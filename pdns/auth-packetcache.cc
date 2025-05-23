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

AuthPacketCache::AuthPacketCache(size_t mapsCount): d_mapscount(mapsCount), d_lastclean(time(nullptr))
{
  S.declare("packetcache-hit", "Number of hits on the packet cache");
  S.declare("packetcache-miss", "Number of misses on the packet cache");
  S.declare("packetcache-size", "Number of entries in the packet cache", StatType::gauge);
  S.declare("deferred-packetcache-inserts","Amount of packet cache inserts that were deferred because of maintenance");
  S.declare("deferred-packetcache-lookup","Amount of packet cache lookups that were deferred because of maintenance");

  d_statnumhit=S.getPointer("packetcache-hit");
  d_statnummiss=S.getPointer("packetcache-miss");
  d_statnumentries=S.getPointer("packetcache-size");

  // Create the MapCombo for the default view
  std::string defaultview{};
  createViewMap(defaultview);
}

// Create the vector<MapCombo> for the given view.
// Assumes there is no existing data for the view. Callers are expected to
// know what they are doing.
std::unordered_map<std::string, std::unique_ptr<vector<AuthPacketCache::MapCombo>>>::iterator AuthPacketCache::createViewMap(const std::string& view)
{
  auto iter = d_cache.emplace(view, std::make_unique<vector<MapCombo>>(d_mapscount));
  auto retval = iter.first;
  auto* map = retval->second.get();
  // Note that this reserves more than intended, especially if multiple views
  // are used.
  for (auto& shard : *map) {
    shard.reserve(d_maxEntries / map->size());
  }
  return retval;
}

void AuthPacketCache::MapCombo::reserve(size_t numberOfEntries)
{
#if BOOST_VERSION >= 105600
  d_map.write_lock()->get<HashTag>().reserve(numberOfEntries);
#endif /* BOOST_VERSION >= 105600 */
}

bool AuthPacketCache::get(DNSPacket& pkt, DNSPacket& cached, const std::string& view)
{
  if(!d_ttl) {
    return false;
  }

  cleanupIfNeeded();

  static const std::unordered_set<uint16_t> optionsToSkip{ EDNSOptionCode::COOKIE};
  uint32_t hash = canHashPacket(pkt.getString(), /* don't skip ECS */optionsToSkip);
  pkt.setHash(hash);

  string value;
  bool haveSomething;
  time_t now = time(nullptr);
  auto iter = d_cache.find(view);
  if (iter == d_cache.end()) {
    // No data for this view yet.
    (*d_statnummiss)++;
    return false;
  }
  auto& mapcombo = getMap(iter->second, pkt.qdomain);
  {
    auto map = mapcombo.d_map.try_read_lock();
    if (!map.owns_lock()) {
      S.inc("deferred-packetcache-lookup");
      return false;
    }

    haveSomething = AuthPacketCache::getEntryLocked(*map, pkt.getString(), hash, pkt.qdomain, pkt.qtype.getCode(), pkt.d_tcp, now, value);
  }

  if (!haveSomething) {
    (*d_statnummiss)++;
    return false;
  }

  if(cached.noparse(value.c_str(), value.size()) < 0) {
    return false;
  }

  (*d_statnumhit)++;
  cached.spoofQuestion(pkt); // for correct case
  cached.qdomain = pkt.qdomain;
  cached.qtype = pkt.qtype;

  return true;
}

bool AuthPacketCache::entryMatches(cmap_t::index<HashTag>::type::iterator& iter, const std::string& query, const DNSName& qname, uint16_t qtype, bool tcp)
{
  static const std::unordered_set<uint16_t> skippedEDNSTypes{ EDNSOptionCode::COOKIE };
  return iter->tcp == tcp && iter->qtype == qtype && iter->qname == qname && queryMatches(iter->query, query, qname, skippedEDNSTypes);
}

void AuthPacketCache::insert(DNSPacket& query, DNSPacket& response, unsigned int maxTTL, const std::string& view)
{
  if(!d_ttl) {
    return;
  }

  cleanupIfNeeded();

  if (ntohs(query.d.qdcount) != 1) {
    return; // do not try to cache packets with multiple questions
  }

  if (query.qclass != QClass::IN) { // we only cache the INternet
    return;
  }

  uint32_t ourttl = std::min(d_ttl, maxTTL);
  if (ourttl == 0) {
    return;
  }

  uint32_t hash = query.getHash();
  time_t now = time(nullptr);
  CacheEntry entry;
  entry.hash = hash;
  entry.created = now;
  entry.ttd = now + ourttl;
  entry.qname = query.qdomain;
  entry.qtype = query.qtype.getCode();
  entry.value = response.getString();
  entry.tcp = response.d_tcp;
  entry.query = query.getString();

  auto iter = d_cache.find(view);
  if (iter == d_cache.end()) {
    // No data for this view yet, create it.
    iter = createViewMap(view);
  }
  auto& mc = getMap(iter->second, entry.qname); // NOLINT(readability-identifier-length)
  {
    auto map = mc.d_map.try_write_lock();
    if (!map.owns_lock()) {
      S.inc("deferred-packetcache-inserts");
      return;
    }

    auto& idx = map->get<HashTag>();
    auto range = idx.equal_range(hash);
    auto iter2 = range.first;

    for( ; iter2 != range.second ; ++iter2)  {
      if (!entryMatches(iter2, entry.query, entry.qname, entry.qtype, entry.tcp)) {
        continue;
      }

      moveCacheItemToBack<SequencedTag>(*map, iter2);
      iter2->value = entry.value;
      iter2->ttd = now + ourttl;
      iter2->created = now;
      return;
    }

    /* no existing entry found to refresh */
    map->insert(std::move(entry));

    if (*d_statnumentries >= d_maxEntries) {
      /* remove the least recently inserted or replaced entry */
      auto& sidx = map->get<SequencedTag>();
      sidx.pop_front();
    }
    else {
      ++(*d_statnumentries);
    }
  }
}

bool AuthPacketCache::getEntryLocked(const cmap_t& map, const std::string& query, uint32_t hash, const DNSName &qname, uint16_t qtype, bool tcp, time_t now, string& value)
{
  const auto& idx = map.get<HashTag>();
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

  uint64_t delcount = 0;
  for (auto& iter : d_cache) {
    auto* map = iter.second.get();
    delcount += purgeLockedCollectionsVector(*map);
  }
  return delcount;
}

uint64_t AuthPacketCache::purgeExact(const DNSName& qname)
{
  uint64_t delcount = 0;

  for (auto& iter : d_cache) {
    auto& mc = getMap(iter.second, qname); // NOLINT(readability-identifier-length)
    delcount += purgeExactLockedCollection<NameTag>(mc, qname);
  }

  *d_statnumentries -= delcount;

  return delcount;
}

uint64_t AuthPacketCache::purgeExact(const std::string& view, const DNSName& qname)
{
  uint64_t delcount = 0;

  if (auto iter = d_cache.find(view); iter != d_cache.end()) {
    auto& mc = getMap(iter->second, qname); // NOLINT(readability-identifier-length)
    delcount += purgeExactLockedCollection<NameTag>(mc, qname);
  }

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

  if(boost::ends_with(match, "$")) {
    for (auto& iter : d_cache) {
      auto* map = iter.second.get();
      delcount += purgeLockedCollectionsVector<NameTag>(*map, match);
    }
    *d_statnumentries -= delcount;
  }
  else {
    delcount = purgeExact(DNSName(match));
  }

  return delcount;
}

void AuthPacketCache::cleanup()
{
  uint64_t totErased = 0;
  for (auto& iter : d_cache) {
    auto* map = iter.second.get();
    totErased += pruneLockedCollectionsVector<SequencedTag>(*map);
  }
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
