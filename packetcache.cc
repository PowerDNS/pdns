/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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
  d_deferred_lookups=S.getPointer("deferred-cache-lookup");
  d_deferred_inserts=S.getPointer("deferred-cache-inserts");
}


void PacketCache::insert(DNSPacket *q, DNSPacket *r)
{
  
  if(ntohs(q->d.qdcount)!=1) {
    L<<"Warning - tried to cache a packet with wrong number of questions: "<<ntohs(q->d.qdcount)<<endl;
    return; // do not try to cache packets with multiple questions
  }

  bool packetMeritsRecursion=d_doRecursion && q->d.rd;

  char ckey[512];
  int len=q->qdomain.length();
  memcpy(ckey,q->qdomain.c_str(),len); // add TOLOWER HERE FIXME XXX
  ckey[len]='|';
  ckey[len+1]=packetMeritsRecursion ? 'r' : 'n';
  ckey[len+2]=(q->qtype.getCode()>>8) & 0xff;
  ckey[len+3]=(q->qtype.getCode()) & 0xff;
  string key;
  key.assign(ckey,q->qdomain.length()+4);

  insert(key,r->getString(), packetMeritsRecursion ? d_recursivettl : d_ttl);
}

void PacketCache::getTTLS()
{
  d_ttl=arg().asNum("cache-ttl");
  d_recursivettl=arg().asNum("recursive-cache-ttl");

  d_doRecursion=arg().mustDo("recursor"); 
}

void PacketCache::insert(const char *packet, int length) 
{
  if(d_ttl<0)
    getTTLS();

  DNSPacket p;
  p.parse(packet,length);

  bool packetMeritsRecursion=d_doRecursion && p.d.rd;

  char ckey[512];
  int len=p.qdomain.length();
  memcpy(ckey,p.qdomain.c_str(),len); // add TOLOWER HERE FIXME XXX
  ckey[len]='|';
  ckey[len+1]=packetMeritsRecursion ? 'r' : 'n';
  ckey[len+2]=(p.qtype.getCode()>>8) & 0xff;
  ckey[len+3]=(p.qtype.getCode()) & 0xff;
  string key;
  key.assign(ckey,p.qdomain.length()+4);
  //  string key=toLower(p.qdomain+"|"+(packetMeritsRecursion ? "R" : "N")+"|"+p.qtype.getName());

  string buffer;
  buffer.assign(packet,length);
  insert(key,buffer, packetMeritsRecursion ? d_recursivettl : d_ttl);
}

void PacketCache::insert(const string &key, const string &packet, unsigned int ttl)
{
  if(!ttl)
    return;

  cvalue_t val;
  val.ttd=time(0)+ttl;
  val.value=packet;

  TryWriteLock l(&d_mut);
  if(l.gotIt())  
    d_map[key]=val;
  else 
    (*d_deferred_inserts)++;
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
    string::size_type pos=i->first.find(check);

    if(!pos || (suffix && pos!=string::npos)) 
      toRemove.push_back(i);
  }

  l.upgrade();  

  for(vector<cmap_t::iterator>::const_iterator i=toRemove.begin();i!=toRemove.end();++i) 
    d_map.erase(*i);
  *statnumentries=d_map.size();
  return toRemove.size();
}

bool PacketCache::getKey(const string &key, string &content)
{
  TryReadLock l(&d_mut); // take a readlock here
  if(!l.gotIt()) {
    (*d_deferred_lookups)++;
    return false;
  }

  // needs to do ttl check here
  cmap_t::const_iterator i=d_map.find(key);
  time_t now=time(0);
  bool ret=(i!=d_map.end() && i->second.ttd>now);
  if(ret)
    content=i->second.value;
  return ret;
}

map<char,int> PacketCache::getCounts()
{
  ReadLock l(&d_mut);
  int counts[256];
  string::size_type offset;
  memset(counts,0,256*sizeof(counts[0]));
  char key;
  for(cmap_t::const_iterator i=d_map.begin();i!=d_map.end();++i) {
    if((offset=i->first.find_first_of("|"))==string::npos || offset+1>i->first.size())
      continue;
    
    key=i->first[offset+1];
    if((key=='Q' || key=='q') && !i->second.value.empty())
      key='!';
    counts[(int)key]++;
  }

  map<char,int>ret;
  for(int i=0;i<256;++i)
    if(counts[i])
      ret[i]=counts[i];
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
  ReadLock l(&d_mut);

  *statnumentries=d_map.size();

  time_t now=time(0);

  DLOG(L<<"Starting cache clean"<<endl);
  if(d_map.begin()==d_map.end()) {
    return; // clean
  }

  vector<cmap_t::iterator> toRemove;

  for(cmap_t::iterator i=d_map.begin();i!=d_map.end();++i) {
    if(now>i->second.ttd)
      toRemove.push_back(i);
  }

  l.upgrade(); 

  for(vector<cmap_t::iterator>::const_iterator i=toRemove.begin();i!=toRemove.end();++i) 
    d_map.erase(*i);
    
  *statnumentries=d_map.size();
  DLOG(L<<"Done with cache clean"<<endl);
}
