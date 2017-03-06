/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include "packetcache.hh"
#include "logger.hh"
#include "arguments.hh"
#include "statbag.hh"
#include <map>
#include <boost/algorithm/string.hpp>

const unsigned int PacketCache::s_mincleaninterval, PacketCache::s_maxcleaninterval;

extern StatBag S;

PacketCache::PacketCache()
{
  d_ops=0;
  d_maps.resize(1024);
  for(auto& mc : d_maps) {
    pthread_rwlock_init(&mc.d_mut, 0);
  }

  d_ttl=-1;

  d_lastclean=time(0);
  d_cleanskipped=false;
  d_nextclean=d_cleaninterval=4096;

  S.declare("packetcache-hit");
  S.declare("packetcache-miss");
  S.declare("packetcache-size");

  d_statnumhit=S.getPointer("packetcache-hit");
  d_statnummiss=S.getPointer("packetcache-miss");
  d_statnumentries=S.getPointer("packetcache-size");
}

PacketCache::~PacketCache()
{
  try {
    //  WriteLock l(&d_mut);
    vector<WriteLock*> locks;
    for(auto& mc : d_maps) {
      locks.push_back(new WriteLock(&mc.d_mut));
    }
    for(auto wl : locks) {
      delete wl;
    }
  }
  catch(...) {
  }
}



int PacketCache::get(DNSPacket *p, DNSPacket *cached)
{
  extern StatBag S;

  if(d_ttl<0) 
    getTTLS();

  cleanupIfNeeded();

  if(!d_ttl) {
    (*d_statnummiss)++;
    return 0;
  }
    
  if(ntohs(p->d.qdcount)!=1) // we get confused by packets with more than one question
    return 0;

  string value;
  bool haveSomething;
  {
    auto& mc=getMap(p->qdomain);
    TryReadLock l(&mc.d_mut); // take a readlock here
    if(!l.gotIt()) {
      S.inc("deferred-cache-lookup");
      return 0;
    }

    uint16_t maxReplyLen = p->d_tcp ? 0xffff : p->getMaxReplyLen();
    haveSomething=getEntryLocked(p->qdomain, p->qtype, PacketCache::PACKETCACHE, value, -1, maxReplyLen, p->d_dnssecOk, p->hasEDNS());
  }
  if(haveSomething) {
    (*d_statnumhit)++;
    if(cached->noparse(value.c_str(), value.size()) < 0)
      return 0;
    cached->spoofQuestion(p); // for correct case
    cached->qdomain=p->qdomain;
    cached->qtype=p->qtype;
    return 1;
  }

  //  cerr<<"Packet cache miss for '"<<p->qdomain<<"'"<<endl;
  (*d_statnummiss)++;
  return 0; // bummer
}

void PacketCache::getTTLS()
{
  d_ttl=::arg().asNum("cache-ttl");
}


void PacketCache::insert(DNSPacket *q, DNSPacket *r, unsigned int maxttl)
{
  if(d_ttl < 0)
    getTTLS();
  
  if(ntohs(q->d.qdcount)!=1) {
    return; // do not try to cache packets with multiple questions
  }

  if(q->qclass != QClass::IN) // we only cache the INternet
    return;

  uint16_t maxReplyLen = q->d_tcp ? 0xffff : q->getMaxReplyLen();
  unsigned int ourttl = d_ttl;
  if(maxttl<ourttl)
    ourttl=maxttl;
  insert(q->qdomain, q->qtype, PacketCache::PACKETCACHE, r->getString(), ourttl, -1,
    maxReplyLen, q->d_dnssecOk, q->hasEDNS());
}

// universal key appears to be: qname, qtype, kind (packet, query cache), optionally zoneid
void PacketCache::insert(const DNSName &qname, const QType& qtype, CacheEntryType cet, const string& value, unsigned int ttl, int zoneID, 
  unsigned int maxReplyLen, bool dnssecOk, bool EDNS)
{
  cleanupIfNeeded();

  if(!ttl)
    return;
  
  //cerr<<"Inserting qname '"<<qname<<"', cet: "<<(int)cet<<", qtype: "<<qtype.getName()<<", ttl: "<<ttl<<", maxreplylen: "<<maxReplyLen<<", hasEDNS: "<<EDNS<<endl;
  CacheEntry val;
  val.created=time(0);
  val.ttd=val.created+ttl;
  val.qname=qname;
  val.qtype=qtype.getCode();
  val.value=value;
  val.ctype=cet;
  val.maxReplyLen = maxReplyLen;
  val.dnssecOk = dnssecOk;
  val.zoneID = zoneID;
  val.hasEDNS = EDNS;
  
  auto& mc = getMap(val.qname);

  TryWriteLock l(&mc.d_mut);
  if(l.gotIt()) { 
    bool success;
    cmap_t::iterator place;
    tie(place, success)=mc.d_map.insert(val);

    if(!success)
      mc.d_map.replace(place, val);
    else
      (*d_statnumentries)++;
  }
  else 
    S.inc("deferred-cache-inserts"); 
}

void PacketCache::insert(const DNSName &qname, const QType& qtype, CacheEntryType cet, const vector<DNSZoneRecord>& value, unsigned int ttl, int zoneID)
{
  cleanupIfNeeded();

  if(!ttl)
    return;
  
  //cerr<<"Inserting qname '"<<qname<<"', cet: "<<(int)cet<<", qtype: "<<qtype.getName()<<", ttl: "<<ttl<<", maxreplylen: "<<maxReplyLen<<", hasEDNS: "<<EDNS<<endl;
  CacheEntry val;
  val.created=time(0);
  val.ttd=val.created+ttl;
  val.qname=qname;
  val.qtype=qtype.getCode();
  val.drs=value;
  val.ctype=cet;
  val.maxReplyLen = 0;
  val.dnssecOk = false;
  val.zoneID = zoneID;
  val.hasEDNS = false;
  
  auto& mc = getMap(val.qname);

  TryWriteLock l(&mc.d_mut);
  if(l.gotIt()) { 
    bool success;
    cmap_t::iterator place;
    tie(place, success)=mc.d_map.insert(val);

    if(!success)
      mc.d_map.replace(place, val);
    else
      (*d_statnumentries)++;
  }
  else 
    S.inc("deferred-cache-inserts"); 
}


/* clears the entire packetcache. */
int PacketCache::purge()
{
  int delcount=0;
  for(auto& mc : d_maps) {
    WriteLock l(&mc.d_mut);
    delcount+=mc.d_map.size();
    mc.d_map.clear();
  }
  d_statnumentries->store(0);
  return delcount;
}

int PacketCache::purgeExact(const DNSName& qname)
{
  int delcount=0;
  auto& mc = getMap(qname);

  WriteLock l(&mc.d_mut);
  auto range = mc.d_map.equal_range(tie(qname));
  if(range.first != range.second) {
    delcount+=distance(range.first, range.second);
    mc.d_map.erase(range.first, range.second);
  }
  *d_statnumentries-=delcount;
  return delcount;
}

/* purges entries from the packetcache. If match ends on a $, it is treated as a suffix */
int PacketCache::purge(const string &match)
{
  if(ends_with(match, "$")) {
    int delcount=0;
    string prefix(match);
    prefix.resize(prefix.size()-1);
    DNSName dprefix(prefix);
    for(auto& mc : d_maps) {
      WriteLock l(&mc.d_mut);
      cmap_t::const_iterator iter = mc.d_map.lower_bound(tie(dprefix));
      auto start=iter;

      for(; iter != mc.d_map.end(); ++iter) {
	if(!iter->qname.isPartOf(dprefix)) {
	  break;
	}
	delcount++;
      }
      mc.d_map.erase(start, iter);
    }
    *d_statnumentries-=delcount;
    return delcount;
  }
  else {
    return purgeExact(DNSName(match));
  }
}
// called from ueberbackend
bool PacketCache::getEntry(const DNSName &qname, const QType& qtype, CacheEntryType cet, vector<DNSZoneRecord>& value, int zoneID)
{
  if(d_ttl<0) 
    getTTLS();

  cleanupIfNeeded();

  auto& mc=getMap(qname);

  TryReadLock l(&mc.d_mut); // take a readlock here
  if(!l.gotIt()) {
    S.inc( "deferred-cache-lookup");
    return false;
  }

  return getEntryLocked(qname, qtype, cet, value, zoneID);
}


bool PacketCache::getEntryLocked(const DNSName &qname, const QType& qtype, CacheEntryType cet, string& value, int zoneID,
  unsigned int maxReplyLen, bool dnssecOK, bool hasEDNS)
{
  uint16_t qt = qtype.getCode();
  //cerr<<"Lookup for maxReplyLen: "<<maxReplyLen<<endl;
  auto& mc=getMap(qname);
  //  cmap_t::const_iterator i=mc.d_map.find(tie(qname, qt, cet, zoneID, maxReplyLen, dnssecOK, hasEDNS));

  auto& idx = boost::multi_index::get<UnorderedNameTag>(mc.d_map);
  auto range=idx.equal_range(tie(qname, qt, cet, zoneID));

  if(range.first == range.second)
    return false;
  time_t now=time(0);
  for(auto iter = range.first ; iter != range.second; ++iter) {
    if(maxReplyLen == iter->maxReplyLen && dnssecOK == iter->dnssecOk && hasEDNS == iter->hasEDNS ) {
      if(iter->ttd > now) {
        value = iter->value;
        return true;
      }
    }
  }
  
  return false;
}
			   
bool PacketCache::getEntryLocked(const DNSName &qname, const QType& qtype, CacheEntryType cet, vector<DNSZoneRecord>& value, int zoneID)
{
  uint16_t qt = qtype.getCode();
  //cerr<<"Lookup for maxReplyLen: "<<maxReplyLen<<endl;
  auto& mc=getMap(qname);
  auto& idx = boost::multi_index::get<UnorderedNameTag>(mc.d_map);
  auto i=idx.find(tie(qname, qt, cet, zoneID));
  if(i==idx.end())
    return false;

  time_t now=time(0);
  if(i->ttd > now) {
    value = i->drs;
    return true;
  }
  return false;
}


map<char,int> PacketCache::getCounts()
{
  int packets=0, queryCacheEntries=0, negQueryCacheEntries=0;

  for(auto& mc : d_maps) {
    ReadLock l(&mc.d_mut);
    
    for(cmap_t::const_iterator iter = mc.d_map.begin() ; iter != mc.d_map.end(); ++iter) {
      if(iter->ctype == PACKETCACHE)
	  packets++;
      else if(iter->ctype == QUERYCACHE) {
	if(iter->value.empty())
	  negQueryCacheEntries++;
	else
	  queryCacheEntries++;
      }
    }
  }
  map<char,int> ret;

  ret['!']=negQueryCacheEntries;
  ret['Q']=queryCacheEntries;
  ret['p']=packets;
  return ret;
}


void PacketCache::cleanup()
{
  unsigned int maxCached = ::arg().asNum("max-cache-entries");
  unsigned long cacheSize = *d_statnumentries;

  // two modes - if toTrim is 0, just look through 10%  of the cache and nuke everything that is expired
  // otherwise, scan first 5*toTrim records, and stop once we've nuked enough
  unsigned int toTrim = 0, lookAt = 0;
  if(maxCached && cacheSize > maxCached) {
    toTrim = cacheSize - maxCached;
    lookAt = 5 * toTrim;
  } else {
    lookAt = cacheSize / 10;
  }

  DLOG(L<<"Starting cache clean, cacheSize: "<<cacheSize<<", lookAt: "<<lookAt<<", toTrim: "<<toTrim<<endl);

  time_t now = time(0);
  unsigned int totErased = 0;
  for(auto& mc : d_maps) {
    WriteLock wl(&mc.d_mut);
    auto& sidx = boost::multi_index::get<SequenceTag>(mc.d_map);
    unsigned int erased = 0, lookedAt = 0;
    for(auto i = sidx.begin(); i != sidx.end(); lookedAt++) {
      if(i->ttd < now) {
        i = sidx.erase(i);
        erased++;
      } else {
        ++i;
      }

      if(toTrim && erased > toTrim / d_maps.size())
        break;

      if(lookedAt > lookAt / d_maps.size())
        break;
    }
    totErased += erased;
  }
  *d_statnumentries -= totErased;

  DLOG(L<<"Done with cache clean, cacheSize: "<<*d_statnumentries<<", totErased"<<totErased<<endl);
}

/* the logic:
   after d_nextclean operations, we clean. We also adjust the cleaninterval
   a bit so we slowly move it to a value where we clean roughly every 30 seconds.

   If d_nextclean has reached its maximum value, we also test if we were called
   within 30 seconds, and if so, we skip cleaning. This means that under high load,
   we will not clean more often than every 30 seconds anyhow.
*/

void PacketCache::cleanupIfNeeded()
{
  if (d_ops++ == d_nextclean) {
    int timediff = max((int)(time(0) - d_lastclean), 1);

    DLOG(L<<"cleaninterval: "<<d_cleaninterval<<", timediff: "<<timediff<<endl);

    if (d_cleaninterval == s_maxcleaninterval && timediff < 30) {
      d_cleanskipped = true;
      d_nextclean += d_cleaninterval;

      DLOG(L<<"cleaning skipped, timediff: "<<timediff<<endl);

      return;
    }

    if(!d_cleanskipped) {
      d_cleaninterval=(int)(0.6*d_cleaninterval)+(0.4*d_cleaninterval*(30.0/timediff));
      d_cleaninterval=std::max(d_cleaninterval, s_mincleaninterval);
      d_cleaninterval=std::min(d_cleaninterval, s_maxcleaninterval);

      DLOG(L<<"new cleaninterval: "<<d_cleaninterval<<endl);
    } else {
      d_cleanskipped = false;
    }

    d_nextclean += d_cleaninterval;
    d_lastclean=time(0);
    cleanup();
  }
}
