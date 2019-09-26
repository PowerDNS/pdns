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
#include "auth-packetcache.hh"
#include "logger.hh"
#include "statbag.hh"
#include "cachecleaner.hh"
extern StatBag S;

const unsigned int AuthPacketCache::s_mincleaninterval, AuthPacketCache::s_maxcleaninterval;

AuthPacketCache::AuthPacketCache(size_t mapsCount): d_lastclean(time(nullptr))
{
  d_maps.resize(mapsCount);
  for(auto& mc : d_maps) {
    pthread_rwlock_init(&mc.d_mut, 0);
  }

  S.declare("packetcache-hit", "Number of hits on the packet cache");
  S.declare("packetcache-miss", "Number of misses on the packet cache");
  S.declare("packetcache-size", "Number of entries in the packet cache");
  S.declare("deferred-packetcache-inserts","Amount of packet cache inserts that were deferred because of maintenance");
  S.declare("deferred-packetcache-lookup","Amount of packet cache lookups that were deferred because of maintenance");

  d_statnumhit=S.getPointer("packetcache-hit");
  d_statnummiss=S.getPointer("packetcache-miss");
  d_statnumentries=S.getPointer("packetcache-size");
}

AuthPacketCache::~AuthPacketCache()
{
  try {
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

bool AuthPacketCache::get(DNSPacket& p, DNSPacket& cached)
{
  if(!d_ttl) {
    return false;
  }

  cleanupIfNeeded();

  uint32_t hash = canHashPacket(p.getString());
  p.setHash(hash);

  string value;
  bool haveSomething;
  time_t now = time(nullptr);
  auto& mc = getMap(p.qdomain);
  {
    TryReadLock rl(&mc.d_mut);
    if(!rl.gotIt()) {
      S.inc("deferred-packetcache-lookup");
      return false;
    }

    haveSomething = getEntryLocked(mc.d_map, p.getString(), hash, p.qdomain, p.qtype.getCode(), p.d_tcp, now, value);
  }

  if (!haveSomething) {
    (*d_statnummiss)++;
    return false;
  }

  if(cached.noparse(value.c_str(), value.size()) < 0) {
    return false;
  }

  (*d_statnumhit)++;
  cached.spoofQuestion(p); // for correct case
  cached.qdomain = p.qdomain;
  cached.qtype = p.qtype;

  return true;
}

bool AuthPacketCache::entryMatches(cmap_t::index<HashTag>::type::iterator& iter, const std::string& query, const DNSName& qname, uint16_t qtype, bool tcp)
{
  return iter->tcp == tcp && iter->qtype == qtype && iter->qname == qname && queryMatches(iter->query, query, qname);
}

void AuthPacketCache::insert(DNSPacket& q, DNSPacket& r, unsigned int maxTTL)
{
  if(!d_ttl) {
    return;
  }

  cleanupIfNeeded();

  if (ntohs(q.d.qdcount) != 1) {
    return; // do not try to cache packets with multiple questions
  }

  if (q.qclass != QClass::IN) // we only cache the INternet
    return;

  uint32_t ourttl = std::min(d_ttl, maxTTL);
  if (ourttl == 0) {
    return;
  }  

  uint32_t hash = q.getHash();
  time_t now = time(nullptr);
  CacheEntry entry;
  entry.hash = hash;
  entry.created = now;
  entry.ttd = now + ourttl;
  entry.qname = q.qdomain;
  entry.qtype = q.qtype.getCode();
  entry.value = r.getString();
  entry.tcp = r.d_tcp;
  entry.query = q.getString();
  
  auto& mc = getMap(entry.qname);
  {
    TryWriteLock l(&mc.d_mut);
    if (!l.gotIt()) {
      S.inc("deferred-packetcache-inserts");
      return;
    }

    auto& idx = mc.d_map.get<HashTag>();
    auto range = idx.equal_range(hash);
    auto iter = range.first;

    for( ; iter != range.second ; ++iter)  {
      if (!entryMatches(iter, entry.query, entry.qname, entry.qtype, entry.tcp)) {
        continue;
      }

      iter->value = entry.value;
      iter->ttd = now + ourttl;
      iter->created = now;
      return;
    }

    /* no existing entry found to refresh */
    mc.d_map.insert(entry);
    (*d_statnumentries)++;
  }
}

bool AuthPacketCache::getEntryLocked(cmap_t& map, const std::string& query, uint32_t hash, const DNSName &qname, uint16_t qtype, bool tcp, time_t now, string& value)
{
  auto& idx = map.get<HashTag>();
  auto range = idx.equal_range(hash);

  for(auto iter = range.first; iter != range.second ; ++iter)  {
    if (iter->ttd < now) {
      continue;
    }

    if (!entryMatches(iter, query, qname, qtype, tcp)) {
      continue;
    }

    value = iter->value;
    return true;
  }

  return false;
}

/* clears the entire cache. */
uint64_t AuthPacketCache::purge()
{
  if(!d_ttl) {
    return 0;
  }

  d_statnumentries->store(0);

  return purgeLockedCollectionsVector(d_maps);
}

uint64_t AuthPacketCache::purgeExact(const DNSName& qname)
{
  auto& mc = getMap(qname);
  uint64_t delcount = purgeExactLockedCollection(mc, qname);

  *d_statnumentries -= delcount;

  return delcount;
}

/* purges entries from the packetcache. If match ends on a $, it is treated as a suffix */
uint64_t AuthPacketCache::purge(const string &match)
{
  if(!d_ttl) {
    return 0;
  }

  uint64_t delcount = 0;

  if(ends_with(match, "$")) {
    delcount = purgeLockedCollectionsVector(d_maps, match);
    *d_statnumentries -= delcount;
  }
  else {
    delcount = purgeExact(DNSName(match));
  }

  return delcount;
}
			   
void AuthPacketCache::cleanup()
{
  uint64_t maxCached = d_maxEntries;
  uint64_t cacheSize = *d_statnumentries;
  uint64_t totErased = 0;

  totErased = pruneLockedCollectionsVector(d_maps, maxCached, cacheSize);
  *d_statnumentries -= totErased;

  DLOG(g_log<<"Done with cache clean, cacheSize: "<<(*d_statnumentries)<<", totErased"<<totErased<<endl);
}

/* the logic:
   after d_nextclean operations, we clean. We also adjust the cleaninterval
   a bit so we slowly move it to a value where we clean roughly every 30 seconds.

   If d_nextclean has reached its maximum value, we also test if we were called
   within 30 seconds, and if so, we skip cleaning. This means that under high load,
   we will not clean more often than every 30 seconds anyhow.
*/

void AuthPacketCache::cleanupIfNeeded()
{
  if (d_ops++ == d_nextclean) {
    time_t now = time(nullptr);
    int timediff = max((int)(now - d_lastclean), 1);

    DLOG(g_log<<"cleaninterval: "<<d_cleaninterval<<", timediff: "<<timediff<<endl);

    if (d_cleaninterval == s_maxcleaninterval && timediff < 30) {
      d_cleanskipped = true;
      d_nextclean += d_cleaninterval;

      DLOG(g_log<<"cleaning skipped, timediff: "<<timediff<<endl);

      return;
    }

    if(!d_cleanskipped) {
      d_cleaninterval=(int)(0.6*d_cleaninterval)+(0.4*d_cleaninterval*(30.0/timediff));
      d_cleaninterval=std::max(d_cleaninterval, s_mincleaninterval);
      d_cleaninterval=std::min(d_cleaninterval, s_maxcleaninterval);

      DLOG(g_log<<"new cleaninterval: "<<d_cleaninterval<<endl);
    } else {
      d_cleanskipped = false;
    }

    d_nextclean += d_cleaninterval;
    d_lastclean=now;
    cleanup();
  }
}
