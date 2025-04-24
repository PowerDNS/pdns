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

AuthPacketCache::AuthPacketCache(size_t mapsCount): d_maps(mapsCount), d_lastclean(time(nullptr))
{
  S.declare("packetcache-hit", "Number of hits on the packet cache");
  S.declare("packetcache-miss", "Number of misses on the packet cache");
  S.declare("packetcache-size", "Number of entries in the packet cache", StatType::gauge);
  S.declare("deferred-packetcache-inserts","Amount of packet cache inserts that were deferred because of maintenance");
  S.declare("deferred-packetcache-lookup","Amount of packet cache lookups that were deferred because of maintenance");

  d_statnumhit=S.getPointer("packetcache-hit");
  d_statnummiss=S.getPointer("packetcache-miss");
  d_statnumentries=S.getPointer("packetcache-size");
}

void AuthPacketCache::MapCombo::reserve(size_t numberOfEntries)
{
#if BOOST_VERSION >= 105600
  d_map.write_lock()->get<HashTag>().reserve(numberOfEntries);
#endif /* BOOST_VERSION >= 105600 */
}

bool AuthPacketCache::get(DNSPacket& pkt, DNSPacket& cached, ComboAddress* from)
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
  auto& mapcombo = getMap(pkt.qdomain);
  {
    auto map = mapcombo.d_map.try_read_lock();
    if (!map.owns_lock()) {
      S.inc("deferred-packetcache-lookup");
      return false;
    }

    haveSomething = AuthPacketCache::getEntryLocked(*map, pkt.getString(), hash, pkt.qdomain, pkt.qtype.getCode(), pkt.d_tcp, now, from, value);
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

void AuthPacketCache::insert(DNSPacket& query, DNSPacket& response, unsigned int maxTTL, std::optional<Netmask> netmask)
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
  if (netmask) {
    entry.netmask = netmask->getNormalized();
  }

  auto& mc = getMap(entry.qname);
  {
    auto map = mc.d_map.try_write_lock();
    if (!map.owns_lock()) {
      S.inc("deferred-packetcache-inserts");
      return;
    }

    auto& idx = map->get<HashTag>();
    auto range = idx.equal_range(hash);
    auto iter = range.first;

    for( ; iter != range.second ; ++iter)  {
      if (!entryMatches(iter, entry.query, entry.qname, entry.qtype, entry.tcp) || netmask != iter->netmask) {
        continue;
      }

      moveCacheItemToBack<SequencedTag>(*map, iter);
      iter->value = entry.value;
      iter->ttd = now + ourttl;
      iter->created = now;
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

bool AuthPacketCache::getEntryLocked(const cmap_t& map, const std::string& query, uint32_t hash, const DNSName &qname, uint16_t qtype, bool tcp, time_t now, ComboAddress* from, string& value)
{
  auto& idx = map.get<HashTag>();
  auto range = idx.equal_range(hash);
  const Netmask *lastmask{nullptr};
  bool found{false}; // if set, implies lastmask is not nullptr

  for(auto iter = range.first; iter != range.second ; ++iter)  {
    if (iter->ttd < now) {
      continue;
    }

    if (!entryMatches(iter, query, qname, qtype, tcp)) {
      continue;
    }
    // Check network origin if applicable:
    // - if we don't pass an address, only consider entries with no netmask
    // - if we pass an address, only consider entries with a netmask matching that address
    if (from == nullptr) {
      if (iter->netmask) {
        continue;
      }
      value = iter->value;
      return true;
    }

    if (!iter->netmask || !iter->netmask->match(*from)) {
      continue;
    }
    // If we had a candidate value already, only update it if this netmask
    // is narrower.
    if (found && iter->netmask->getBits() < lastmask->getBits()) {
      continue;
    }
    // When we are searching with an address, we need to loop over all entries
    // in order to pick the narrowest match, so don't return this possible
    // match yet.
    value = iter->value;
    lastmask = &(*iter->netmask);
    found = true;
  }

  return found;
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
  uint64_t delcount = purgeExactLockedCollection<NameTag>(mc, qname);

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
    delcount = purgeLockedCollectionsVector<NameTag>(d_maps, match);
    *d_statnumentries -= delcount;
  }
  else {
    delcount = purgeExact(DNSName(match));
  }

  return delcount;
}

// Arguably belongs to pdns/cachecleaner.hh. But better kept here where we can
// be sure the netmask argument has been normalized.
template <typename S, typename T>
uint64_t pruneNetmask(T& collection, const Netmask& netmask)
{
  uint64_t erased = 0;
  auto& sidx = collection.template get<S>();

  for (auto iter = sidx.begin(); iter != sidx.end();) {
    if (!iter->netmask) {
      ++iter;
      continue;
    }
    // We want to remove all elements which cover the given netmask, even
    // if they have a larger span, so simply check for overlap.
    if (netmask.match(&iter->netmask->getNetwork()) ||
      iter->netmask->match(&netmask.getNetwork())) {
      iter = sidx.erase(iter);
      ++erased;
    }
    else {
      ++iter;
    }
  }

  return erased;
}

uint64_t AuthPacketCache::purgeNetmask(const Netmask& netmask)
{
  uint64_t delcount = 0;
  Netmask normalized = netmask.getNormalized();

  // This is slow because we do not perform an exact Netmask comparison.
  for (auto& shard : d_maps) {
    auto map = shard.d_map.write_lock();
    delcount += pruneNetmask<SequencedTag>(*map, normalized);
  }

  *d_statnumentries -= delcount;
  return delcount;
}

void AuthPacketCache::cleanup()
{
  uint64_t totErased = pruneLockedCollectionsVector<SequencedTag>(d_maps);
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
