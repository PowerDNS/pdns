/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

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
#include <boost/algorithm/string.hpp>

extern StatBag S;

PacketCache::PacketCache()
{
  pthread_rwlock_init(&d_mut, 0);
  // d_ops = 0;

  d_ttl=-1;
  d_recursivettl=-1;

  S.declare("packetcache-hit");
  S.declare("packetcache-miss");
  S.declare("packetcache-size");

  d_statnumhit=S.getPointer("packetcache-hit");
  d_statnummiss=S.getPointer("packetcache-miss");
  d_statnumentries=S.getPointer("packetcache-size");
}

PacketCache::~PacketCache()
{
  WriteLock l(&d_mut);
}

int PacketCache::get(DNSPacket *p, DNSPacket *cached, bool recursive)
{
  extern StatBag S;

  if(d_ttl<0) 
    getTTLS();

  if(!((++d_ops) % 300000)) {
    cleanup();
  }

  if(d_doRecursion && p->d.rd) { // wants recursion
    if(!d_recursivettl) {
      (*d_statnummiss)++;
      return 0;
    }
  }
  else { // does not
    if(!d_ttl) {
      (*d_statnummiss)++;
      return 0;
    }
  }
    
  if(ntohs(p->d.qdcount)!=1) // we get confused by packets with more than one question
    return 0;

  unsigned int age=0;
  string value;
  bool haveSomething;
  {
    TryReadLock l(&d_mut); // take a readlock here
    if(!l.gotIt()) {
      S.inc("deferred-cache-lookup");
      return 0;
    }

    uint16_t maxReplyLen = p->d_tcp ? 0xffff : p->getMaxReplyLen();
    haveSomething=getEntryLocked(p->qdomain, p->qtype, PacketCache::PACKETCACHE, value, -1, recursive, maxReplyLen, p->d_dnssecOk, p->hasEDNS(), &age);
  }
  if(haveSomething) {
    (*d_statnumhit)++;
    if (recursive)
      ageDNSPacket(value, age);
    if(cached->noparse(value.c_str(), value.size()) < 0)
      return 0;
    cached->spoofQuestion(p); // for correct case
    cached->qdomain=p->qdomain;
    cached->qtype=p->qtype;
    return 1;
  }

  //  cerr<<"Packet cache miss for '"<<p->qdomain<<"', merits: "<<packetMeritsRecursion<<endl;
  (*d_statnummiss)++;
  return 0; // bummer
}

void PacketCache::getTTLS()
{
  d_ttl=::arg().asNum("cache-ttl");
  d_recursivettl=::arg().asNum("recursive-cache-ttl");

  d_doRecursion=::arg().mustDo("recursor"); 
}


void PacketCache::insert(DNSPacket *q, DNSPacket *r, bool recursive, unsigned int maxttl)
{
  if(d_ttl < 0)
    getTTLS();
  
  if(ntohs(q->d.qdcount)!=1) {
    return; // do not try to cache packets with multiple questions
  }

  if(q->qclass != QClass::IN) // we only cache the INternet
    return;

  uint16_t maxReplyLen = q->d_tcp ? 0xffff : q->getMaxReplyLen();
  unsigned int ourttl = recursive ? d_recursivettl : d_ttl;
  if(!recursive) {
    if(maxttl<ourttl)
      ourttl=maxttl;
  } else {
    unsigned int minttl = r->getMinTTL();
    if(minttl<ourttl)
      ourttl=minttl;
  }
  insert(q->qdomain, q->qtype, PacketCache::PACKETCACHE, r->getString(), ourttl, -1, recursive,
    maxReplyLen, q->d_dnssecOk, q->hasEDNS());
}

// universal key appears to be: qname, qtype, kind (packet, query cache), optionally zoneid, meritsRecursion
void PacketCache::insert(const string &qname, const QType& qtype, CacheEntryType cet, const string& value, unsigned int ttl, int zoneID, 
  bool meritsRecursion, unsigned int maxReplyLen, bool dnssecOk, bool EDNS)
{
  if(!((++d_ops) % 300000)) {
    cleanup();
  }

  if(!ttl)
    return;
  
  //cerr<<"Inserting qname '"<<qname<<"', cet: "<<(int)cet<<", qtype: "<<qtype.getName()<<", ttl: "<<ttl<<", maxreplylen: "<<maxReplyLen<<", hasEDNS: "<<EDNS<<endl;
  CacheEntry val;
  val.created=time(0);
  val.ttd=val.created+ttl;
  val.qname=pcReverse(qname);
  val.qtype=qtype.getCode();
  val.value=value;
  val.ctype=cet;
  val.meritsRecursion=meritsRecursion;
  val.maxReplyLen = maxReplyLen;
  val.dnssecOk = dnssecOk;
  val.zoneID = zoneID;
  val.hasEDNS = EDNS;
  
  TryWriteLock l(&d_mut);
  if(l.gotIt()) { 
    bool success;
    cmap_t::iterator place;
    tie(place, success)=d_map.insert(val);
    //    cerr<<"Insert succeeded: "<<success<<endl;
    if(!success)
      d_map.replace(place, val);
    
  }
  else 
    S.inc("deferred-cache-inserts"); 
}

/* clears the entire packetcache. */
int PacketCache::purge()
{
  WriteLock l(&d_mut);
  int delcount=d_map.size();
  d_map.clear();
  *d_statnumentries=0;
  return delcount;
}

/* purges entries from the packetcache. If match ends on a $, it is treated as a suffix */
int PacketCache::purge(const string &match)
{
  WriteLock l(&d_mut);
  int delcount=0;

  if(ends_with(match, "$")) {
    string prefix(match);
    prefix.resize(prefix.size()-1);

    string zone = pcReverse(prefix);

    cmap_t::const_iterator iter = d_map.lower_bound(tie(zone));
    cmap_t::const_iterator start=iter;

    for(; iter != d_map.end(); ++iter) {
      if(iter->qname.compare(0, zone.size(), zone) != 0) {
        break;
      }
      delcount++;
    }
    d_map.erase(start, iter);
  }
  else {
    string qname = pcReverse(match);

    delcount=d_map.count(tie(qname));
    pair<cmap_t::iterator, cmap_t::iterator> range = d_map.equal_range(tie(qname));
    d_map.erase(range.first, range.second);
  }
  *d_statnumentries=d_map.size();
  return delcount;
}
// called from ueberbackend
bool PacketCache::getEntry(const string &qname, const QType& qtype, CacheEntryType cet, string& value, int zoneID, bool meritsRecursion, 
  unsigned int maxReplyLen, bool dnssecOk, bool hasEDNS, unsigned int *age)
{
  if(d_ttl<0) 
    getTTLS();

  if(!((++d_ops) % 300000)) {
    cleanup();
  }

  TryReadLock l(&d_mut); // take a readlock here
  if(!l.gotIt()) {
    S.inc( "deferred-cache-lookup");
    return false;
  }

  return getEntryLocked(qname, qtype, cet, value, zoneID, meritsRecursion, maxReplyLen, dnssecOk, hasEDNS, age);
}


bool PacketCache::getEntryLocked(const string &qname, const QType& qtype, CacheEntryType cet, string& value, int zoneID, bool meritsRecursion,
  unsigned int maxReplyLen, bool dnssecOK, bool hasEDNS, unsigned int *age)
{
  uint16_t qt = qtype.getCode();
  //cerr<<"Lookup for maxReplyLen: "<<maxReplyLen<<endl;
  string pcqname = pcReverse(qname);
  cmap_t::const_iterator i=d_map.find(tie(pcqname, qt, cet, zoneID, meritsRecursion, maxReplyLen, dnssecOK, hasEDNS, *age));
  time_t now=time(0);
  bool ret=(i!=d_map.end() && i->ttd > now);
  if(ret) {
    if (age)
      *age = now - i->created;
    value = i->value;
  }

  return ret;
}


string PacketCache::pcReverse(const string &content)
{
  string tmp;
  tmp.reserve(content.size());
  for(std::string::const_reverse_iterator i = content.rbegin(); i < content.rend(); i++)
    tmp.push_back((*i == '.' ? '\t' : dns_tolower(*i)));
  tmp.push_back('\t');
  return tmp;
}


map<char,int> PacketCache::getCounts()
{
  ReadLock l(&d_mut);

  map<char,int>ret;
  int recursivePackets=0, nonRecursivePackets=0, queryCacheEntries=0, negQueryCacheEntries=0;

  for(cmap_t::const_iterator iter = d_map.begin() ; iter != d_map.end(); ++iter) {
    if(iter->ctype == PACKETCACHE)
      if(iter->meritsRecursion)
        recursivePackets++;
      else
        nonRecursivePackets++;
    else if(iter->ctype == QUERYCACHE) {
      if(iter->value.empty())
        negQueryCacheEntries++;
      else
        queryCacheEntries++;
    }
  }
  ret['!']=negQueryCacheEntries;
  ret['Q']=queryCacheEntries;
  ret['n']=nonRecursivePackets;
  ret['r']=recursivePackets;
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
  WriteLock l(&d_mut);

  *d_statnumentries=d_map.size();

  unsigned int maxCached=::arg().asNum("max-cache-entries");
  unsigned int toTrim=0;
  
  unsigned int cacheSize=*d_statnumentries;

  if(maxCached && cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
  }

  unsigned int lookAt=0;
  // two modes - if toTrim is 0, just look through 10%  of the cache and nuke everything that is expired
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
  unsigned int erased=0, lookedAt=0;
  for(sequence_t::iterator i=sidx.begin(); i != sidx.end(); lookedAt++) {
    if(i->ttd < now) {
      sidx.erase(i++);
      erased++;
    }
    else
      ++i;

    if(toTrim && erased > toTrim)
      break;

    if(lookedAt > lookAt)
      break;
  }
  //  cerr<<"erased: "<<erased<<endl;
  *d_statnumentries=d_map.size();
  DLOG(L<<"Done with cache clean"<<endl);
}
