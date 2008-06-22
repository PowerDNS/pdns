/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2008  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "utility.hh"
#include "packetcache.hh"
#include "logger.hh"
#include "arguments.hh"
#include "statbag.hh"
#include <map>

extern StatBag S;

PacketCache::PacketCache()
{
  pthread_rwlock_init(&d_mut,0);
  pthread_mutex_init(&d_dellock,0);
  d_hit=d_miss=0;

  d_ttl=-1;
  d_recursivettl=-1;

  S.declare("packetcache-hit");
  S.declare("packetcache-miss");
  S.declare("packetcache-size");

  statnumhit=S.getPointer("packetcache-hit");
  statnummiss=S.getPointer("packetcache-miss");
  statnumentries=S.getPointer("packetcache-size");
}

int PacketCache::get(DNSPacket *p, DNSPacket *cached)
{
  extern StatBag S;
  if(!((d_hit+d_miss)%5000)) {
    cleanup();
  }

  if(d_ttl<0) 
    getTTLS();

  if(d_doRecursion && p->d.rd) { // wants recursion
    if(!d_recursivettl) {
      (*statnummiss)++;
      d_miss++;
      return 0;
    }
  }
  else { // does not
    if(!d_ttl) {
      (*statnummiss)++;
      d_miss++;
      return 0;
    }
  }
    
  bool packetMeritsRecursion=d_doRecursion && p->d.rd;

  if(ntohs(p->d.qdcount)!=1) // we get confused by packets with more than one question
    return 0;

  {
    TryReadLock l(&d_mut); // take a readlock here
    if(!l.gotIt()) {
      S.inc("deferred-cache-lookup");
      return 0;
    }

    if(!((d_hit+d_miss)%1000)) {
      *statnumentries=d_map.size(); // needs lock
    }
    string value;

    if(getEntry(p->qdomain, p->qtype, PacketCache::PACKETCACHE, value, -1, packetMeritsRecursion)) {
      //      cerr<<"Packet cache hit!"<<endl;
      (*statnumhit)++;
      d_hit++;
      if(cached->parse(value.c_str(), value.size()) < 0) {
	return -1;
      }
      cached->spoofQuestion(p->qdomain); // for correct case
      return 1;
    }
  }
  //   cerr<<"Packet cache miss"<<endl;
  (*statnummiss)++;
  d_miss++;
  return 0; // bummer
}

void PacketCache::getTTLS()
{
  d_ttl=::arg().asNum("cache-ttl");
  d_recursivettl=::arg().asNum("recursive-cache-ttl");

  d_doRecursion=::arg().mustDo("recursor"); 
}


void PacketCache::insert(DNSPacket *q, DNSPacket *r)
{
  if(d_ttl < 0)
    getTTLS();
  
  if(ntohs(q->d.qdcount)!=1) {
    return; // do not try to cache packets with multiple questions
  }

  bool packetMeritsRecursion=d_doRecursion && q->d.rd;

  insert(q->qdomain, q->qtype, PacketCache::PACKETCACHE, r->getString(), packetMeritsRecursion ? d_recursivettl : d_ttl);  // XXX FIXME forgets meritsRecursion
}

// universal key appears to be: qname, qtype, kind (packet, query cache), optionally zoneid, meritsRecursion
void PacketCache::insert(const string &qname, const QType& qtype, CacheEntryType cet, const string& value, unsigned int ttl, int zoneID, bool meritsRecursion)
{
  if(!ttl)
    return;
  
  //  cerr<<"Inserting, cet: "<<(int)cet<<endl;

  CacheEntry val;
  val.ttd=time(0)+ttl;
  val.qname=qname;
  val.qtype=qtype.getCode();
  val.value=value;
  val.ctype=cet;
  val.meritsRecursion=meritsRecursion;

  TryWriteLock l(&d_mut);
  if(l.gotIt()) { 
    bool success;
    cmap_t::iterator place;
    tie(place, success)=d_map.insert(val);
    //    cerr<<"Insert succeeded: "<<success<<endl;
    //    if(!success)
    //      cerr<<"Replace: "<<d_map.replace(place, val)<<endl;
    
  }
  else 
    S.inc("deferred-cache-inserts"); 
}

/** purges entries from the packetcache. If prefix ends on a $, it is treated as a suffix */
int PacketCache::purge(const string &f_prefix)
{
  Lock pl(&d_dellock);

  string prefix(f_prefix);
  if(prefix.empty()) {
    cmap_t *tmp=new cmap_t;
    {
      DTime dt;
      dt.set();
      WriteLock l(&d_mut);
      tmp->swap(d_map);
      L<<Logger::Error<<"cache clean time: "<<dt.udiff()<<"usec"<<endl;
    }

    int size=tmp->size();
    delete tmp;

    *statnumentries=0;
    return size;
  }

  bool suffix=false;
  if(prefix[prefix.size()-1]=='$') {
    prefix=prefix.substr(0,prefix.size()-1);
    suffix=true;
  }
  string check=prefix+"|";

  vector<cmap_t::iterator> toRemove;

  ReadLock l(&d_mut);

  for(cmap_t::iterator i=d_map.begin();i!=d_map.end();++i) {
    string::size_type pos=i->qname.find(check);

    if(!pos || (suffix && pos!=string::npos)) 
      toRemove.push_back(i);
  }

  l.upgrade();  

  for(vector<cmap_t::iterator>::const_iterator i=toRemove.begin();i!=toRemove.end();++i) 
    d_map.erase(*i);
  *statnumentries=d_map.size();
  return toRemove.size();
}

bool PacketCache::getEntry(const string &qname, const QType& qtype, CacheEntryType cet, string& value, int zoneID, bool meritsRecursion)
{
  TryReadLock l(&d_mut); // take a readlock here
  if(!l.gotIt()) {
    S.inc( "deferred-cache-lookup");
    return false;
  }

  // needs to do ttl check here
  uint16_t qt = qtype.getCode();
  cmap_t::const_iterator i=d_map.find(tie(qname, qt, cet, zoneID, meritsRecursion));
  time_t now=time(0);
  bool ret=(i!=d_map.end() && i->ttd > now);
  if(ret)
    value = i->value;
  
  //  cerr<<"Cache hit: "<<(int)cet<<", "<<ret<<endl;
  
  return ret;
}

// FIXME: must be converted to boost multi index
map<char,int> PacketCache::getCounts()
{
  ReadLock l(&d_mut);

  map<char,int>ret;
  return ret;
}


int PacketCache::size()
{
  ReadLock l(&d_mut);
  return d_map.size();
}

/** readlock for figuring out which iterators to delete, upgrade to writelock when actually cleaning */
void PacketCache::cleanup()
{
  Lock pl(&d_dellock); // ALWAYS ACQUIRE DELLOCK FIRST
  WriteLock l(&d_mut);

  *statnumentries=d_map.size();

  unsigned int maxCached=::arg().asNum("max-cache-entries");
  unsigned int toTrim=0;
  
  unsigned int cacheSize=*statnumentries;

  if(maxCached && cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
  }

  unsigned int lookAt=0;
  // two modes - if toTrim is 0, just look through 10000 records and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  if(toTrim)
    lookAt=5*toTrim;
  else
    lookAt=cacheSize/10;

  //  cerr<<"cacheSize: "<<cacheSize<<", lookAt: "<<lookAt<<", toTrim: "<<toTrim<<endl;
  time_t now=time(0);

  DLOG(L<<"Starting cache clean"<<endl);
  if(d_map.empty())
    return; // clean

  typedef cmap_t::nth_index<1>::type sequence_t;
  sequence_t& sidx=d_map.get<1>();
  unsigned int erased=0;
  for(sequence_t::iterator i=sidx.begin(); i != sidx.end();) {
    if(i->ttd < now) {
      sidx.erase(i++);
      erased++;
    }
    else
      ++i;

    if(toTrim && erased > toTrim)
      break;

  }
  //  cerr<<"erased: "<<erased<<endl;
  *statnumentries=d_map.size();
  DLOG(L<<"Done with cache clean"<<endl);
}
