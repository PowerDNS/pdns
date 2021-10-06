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
#include <cinttypes>

#include "dnsdist.hh"
#include "dolog.hh"
#include "dnsparser.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-ecs.hh"
#include "ednssubnet.hh"
#include "packetcache.hh"

DNSDistPacketCache::DNSDistPacketCache(size_t maxEntries, uint32_t maxTTL, uint32_t minTTL, uint32_t tempFailureTTL, uint32_t maxNegativeTTL, uint32_t staleTTL, bool dontAge, uint32_t shards, bool deferrableInsertLock, bool parseECS): d_maxEntries(maxEntries), d_shardCount(shards), d_maxTTL(maxTTL), d_tempFailureTTL(tempFailureTTL), d_maxNegativeTTL(maxNegativeTTL), d_minTTL(minTTL), d_staleTTL(staleTTL), d_dontAge(dontAge), d_deferrableInsertLock(deferrableInsertLock), d_parseECS(parseECS)
{
  d_shards.resize(d_shardCount);

  /* we reserve maxEntries + 1 to avoid rehashing from occurring
     when we get to maxEntries, as it means a load factor of 1 */
  for (auto& shard : d_shards) {
    shard.setSize((maxEntries / d_shardCount) + 1);
  }
}

bool DNSDistPacketCache::getClientSubnet(const PacketBuffer& packet, size_t qnameWireLength, boost::optional<Netmask>& subnet)
{
  uint16_t optRDPosition;
  size_t remaining = 0;

  int res = getEDNSOptionsStart(packet, qnameWireLength, &optRDPosition, &remaining);

  if (res == 0) {
    size_t ecsOptionStartPosition = 0;
    size_t ecsOptionSize = 0;

    res = getEDNSOption(reinterpret_cast<const char*>(&packet.at(optRDPosition)), remaining, EDNSOptionCode::ECS, &ecsOptionStartPosition, &ecsOptionSize);

    if (res == 0 && ecsOptionSize > (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) {

      EDNSSubnetOpts eso;
      if (getEDNSSubnetOptsFromString(reinterpret_cast<const char*>(&packet.at(optRDPosition + ecsOptionStartPosition + (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE))), ecsOptionSize - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), &eso) == true) {
        subnet = eso.source;
        return true;
      }
    }
  }

  return false;
}

bool DNSDistPacketCache::cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool receivedOverUDP, bool dnssecOK, const boost::optional<Netmask>& subnet) const
{
  if (cachedValue.queryFlags != queryFlags || cachedValue.dnssecOK != dnssecOK || cachedValue.receivedOverUDP != receivedOverUDP || cachedValue.qtype != qtype || cachedValue.qclass != qclass || cachedValue.qname != qname) {
    return false;
  }

  if (d_parseECS && cachedValue.subnet != subnet) {
    return false;
  }

  return true;
}

void DNSDistPacketCache::insertLocked(CacheShard& shard, std::unordered_map<uint32_t,CacheValue>& map, uint32_t key, CacheValue& newValue)
{
  /* check again now that we hold the lock to prevent a race */
  if (map.size() >= (d_maxEntries / d_shardCount)) {
    return;
  }

  std::unordered_map<uint32_t,CacheValue>::iterator it;
  bool result;
  tie(it, result) = map.insert({key, newValue});

  if (result) {
    ++shard.d_entriesCount;
    return;
  }

  /* in case of collision, don't override the existing entry
     except if it has expired */
  CacheValue& value = it->second;
  bool wasExpired = value.validity <= newValue.added;

  if (!wasExpired && !cachedValueMatches(value, newValue.queryFlags, newValue.qname, newValue.qtype, newValue.qclass, newValue.receivedOverUDP, newValue.dnssecOK, newValue.subnet)) {
    d_insertCollisions++;
    return;
  }

  /* if the existing entry had a longer TTD, keep it */
  if (newValue.validity <= value.validity) {
    return;
  }

  value = newValue;
}

void DNSDistPacketCache::insert(uint32_t key, const boost::optional<Netmask>& subnet, uint16_t queryFlags, bool dnssecOK, const DNSName& qname, uint16_t qtype, uint16_t qclass, const PacketBuffer& response, bool receivedOverUDP, uint8_t rcode, boost::optional<uint32_t> tempFailureTTL)
{
  if (response.size() < sizeof(dnsheader)) {
    return;
  }

  uint32_t minTTL;

  if (rcode == RCode::ServFail || rcode == RCode::Refused) {
    minTTL = tempFailureTTL == boost::none ? d_tempFailureTTL : *tempFailureTTL;
    if (minTTL == 0) {
      return;
    }
  }
  else {
    bool seenAuthSOA = false;
    minTTL = getMinTTL(reinterpret_cast<const char*>(response.data()), response.size(), &seenAuthSOA);

    /* no TTL found, we don't want to cache this */
    if (minTTL == std::numeric_limits<uint32_t>::max()) {
      return;
    }

    if (rcode == RCode::NXDomain || (rcode == RCode::NoError && seenAuthSOA)) {
      minTTL = std::min(minTTL, d_maxNegativeTTL);
    }
    else if (minTTL > d_maxTTL) {
      minTTL = d_maxTTL;
    }

    if (minTTL < d_minTTL) {
      d_ttlTooShorts++;
      return;
    }
  }

  uint32_t shardIndex = getShardIndex(key);

  if (d_shards.at(shardIndex).d_entriesCount >= (d_maxEntries / d_shardCount)) {
    return;
  }

  const time_t now = time(nullptr);
  time_t newValidity = now + minTTL;
  CacheValue newValue;
  newValue.qname = qname;
  newValue.qtype = qtype;
  newValue.qclass = qclass;
  newValue.queryFlags = queryFlags;
  newValue.len = response.size();
  newValue.validity = newValidity;
  newValue.added = now;
  newValue.receivedOverUDP = receivedOverUDP;
  newValue.dnssecOK = dnssecOK;
  newValue.value = std::string(response.begin(), response.end());
  newValue.subnet = subnet;

  auto& shard = d_shards.at(shardIndex);

  if (d_deferrableInsertLock) {
    auto w = shard.d_map.try_write_lock();

    if (!w.owns_lock()) {
      d_deferredInserts++;
      return;
    }
    insertLocked(shard, *w, key, newValue);
  }
  else {
    auto w = shard.d_map.write_lock();

    insertLocked(shard, *w, key, newValue);
  }
}

bool DNSDistPacketCache::get(DNSQuestion& dq, uint16_t queryId, uint32_t* keyOut, boost::optional<Netmask>& subnet, bool dnssecOK, bool receivedOverUDP, uint32_t allowExpired, bool skipAging)
{
  const auto& dnsQName = dq.qname->getStorage();
  uint32_t key = getKey(dnsQName, dq.qname->wirelength(), dq.getData(), receivedOverUDP);

  if (keyOut) {
    *keyOut = key;
  }

  if (d_parseECS) {
    getClientSubnet(dq.getData(), dq.qname->wirelength(), subnet);
  }

  uint32_t shardIndex = getShardIndex(key);
  time_t now = time(nullptr);
  time_t age;
  bool stale = false;
  auto& response = dq.getMutableData();
  auto& shard = d_shards.at(shardIndex);
  {
    auto map = shard.d_map.try_read_lock();
    if (!map.owns_lock()) {
      d_deferredLookups++;
      return false;
    }

    std::unordered_map<uint32_t,CacheValue>::const_iterator it = map->find(key);
    if (it == map->end()) {
      d_misses++;
      return false;
    }

    const CacheValue& value = it->second;
    if (value.validity <= now) {
      if ((now - value.validity) >= static_cast<time_t>(allowExpired)) {
        d_misses++;
        return false;
      }
      else {
        stale = true;
      }
    }

    if (value.len < sizeof(dnsheader)) {
      return false;
    }

    /* check for collision */
    if (!cachedValueMatches(value, *(getFlagsFromDNSHeader(dq.getHeader())), *dq.qname, dq.qtype, dq.qclass, receivedOverUDP, dnssecOK, subnet)) {
      d_lookupCollisions++;
      return false;
    }

    response.resize(value.len);
    memcpy(&response.at(0), &queryId, sizeof(queryId));
    memcpy(&response.at(sizeof(queryId)), &value.value.at(sizeof(queryId)), sizeof(dnsheader) - sizeof(queryId));

    if (value.len == sizeof(dnsheader)) {
      /* DNS header only, our work here is done */
      d_hits++;
      return true;
    }

    const size_t dnsQNameLen = dnsQName.length();
    if (value.len < (sizeof(dnsheader) + dnsQNameLen)) {
      return false;
    }

    memcpy(&response.at(sizeof(dnsheader)), dnsQName.c_str(), dnsQNameLen);
    if (value.len > (sizeof(dnsheader) + dnsQNameLen)) {
      memcpy(&response.at(sizeof(dnsheader) + dnsQNameLen), &value.value.at(sizeof(dnsheader) + dnsQNameLen), value.len - (sizeof(dnsheader) + dnsQNameLen));
    }

    if (!stale) {
      age = now - value.added;
    }
    else {
      age = (value.validity - value.added) - d_staleTTL;
    }
  }

  if (!d_dontAge && !skipAging) {
    if (!stale) {
      ageDNSPacket(reinterpret_cast<char *>(&response[0]), response.size(), age);
    }
    else {
      editDNSPacketTTL(reinterpret_cast<char *>(&response[0]), response.size(),
        [staleTTL = d_staleTTL](uint8_t section, uint16_t class_, uint16_t type, uint32_t ttl) { return staleTTL; });
    }
  }

  d_hits++;
  return true;
}

/* Remove expired entries, until the cache has at most
   upTo entries in it.
   If the cache has more than one shard, we will try hard
   to make sure that every shard has free space remaining.
*/
size_t DNSDistPacketCache::purgeExpired(size_t upTo, const time_t now)
{
  const size_t maxPerShard = upTo / d_shardCount;

  size_t removed = 0;

  for (auto& shard : d_shards) {
    auto map = shard.d_map.write_lock();
    if (map->size() <= maxPerShard) {
      continue;
    }

    size_t toRemove = map->size() - maxPerShard;

    for (auto it = map->begin(); toRemove > 0 && it != map->end(); ) {
      const CacheValue& value = it->second;

      if (value.validity <= now) {
        it = map->erase(it);
        --toRemove;
        --shard.d_entriesCount;
        ++removed;
      } else {
        ++it;
      }
    }
  }

  return removed;
}

/* Remove all entries, keeping only upTo
   entries in the cache.
   If the cache has more than one shard, we will try hard
   to make sure that every shard has free space remaining.
*/
size_t DNSDistPacketCache::expunge(size_t upTo)
{
  const size_t maxPerShard = upTo / d_shardCount;

  size_t removed = 0;

  for (auto& shard : d_shards) {
    auto map = shard.d_map.write_lock();

    if (map->size() <= maxPerShard) {
      continue;
    }

    size_t toRemove = map->size() - maxPerShard;

    auto beginIt = map->begin();
    auto endIt = beginIt;

    if (map->size() >= toRemove) {
      std::advance(endIt, toRemove);
      map->erase(beginIt, endIt);
      shard.d_entriesCount -= toRemove;
      removed += toRemove;
    }
    else {
      removed += map->size();
      map->clear();
      shard.d_entriesCount = 0;
    }
  }

  return removed;
}

size_t DNSDistPacketCache::expungeByName(const DNSName& name, uint16_t qtype, bool suffixMatch)
{
  size_t removed = 0;

  for (auto& shard : d_shards) {
    auto map = shard.d_map.write_lock();

    for(auto it = map->begin(); it != map->end(); ) {
      const CacheValue& value = it->second;

      if ((value.qname == name || (suffixMatch && value.qname.isPartOf(name))) && (qtype == QType::ANY || qtype == value.qtype)) {
        it = map->erase(it);
        --shard.d_entriesCount;
        ++removed;
      } else {
        ++it;
      }
    }
  }

  return removed;
}

bool DNSDistPacketCache::isFull()
{
    return (getSize() >= d_maxEntries);
}

uint64_t DNSDistPacketCache::getSize()
{
  uint64_t count = 0;

  for (auto& shard : d_shards) {
    count += shard.d_entriesCount;
  }

  return count;
}

uint32_t DNSDistPacketCache::getMinTTL(const char* packet, uint16_t length, bool* seenNoDataSOA)
{
  return getDNSPacketMinTTL(packet, length, seenNoDataSOA);
}

uint32_t DNSDistPacketCache::getKey(const DNSName::string_t& qname, size_t qnameWireLength, const PacketBuffer& packet, bool receivedOverUDP)
{
  uint32_t result = 0;
  /* skip the query ID */
  if (packet.size() < sizeof(dnsheader)) {
    throw std::range_error("Computing packet cache key for an invalid packet size (" + std::to_string(packet.size()) +")");
  }

  result = burtle(&packet.at(2), sizeof(dnsheader) - 2, result);
  result = burtleCI((const unsigned char*) qname.c_str(), qname.length(), result);
  if (packet.size() < sizeof(dnsheader) + qnameWireLength) {
    throw std::range_error("Computing packet cache key for an invalid packet (" + std::to_string(packet.size()) + " < " + std::to_string(sizeof(dnsheader) + qnameWireLength) + ")");
  }
  if (packet.size() > ((sizeof(dnsheader) + qnameWireLength))) {
    if (!d_optionsToSkip.empty()) {
      /* skip EDNS options if any */
      result = PacketCache::hashAfterQname(pdns_string_view(reinterpret_cast<const char*>(packet.data()), packet.size()), result, sizeof(dnsheader) + qnameWireLength, d_optionsToSkip);
    }
    else {
      result = burtle(&packet.at(sizeof(dnsheader) + qnameWireLength), packet.size() - (sizeof(dnsheader) + qnameWireLength), result);
    }
  }
  result = burtle((const unsigned char*) &receivedOverUDP, sizeof(receivedOverUDP), result);
  return result;
}

uint32_t DNSDistPacketCache::getShardIndex(uint32_t key) const
{
  return key % d_shardCount;
}

string DNSDistPacketCache::toString()
{
  return std::to_string(getSize()) + "/" + std::to_string(d_maxEntries);
}

uint64_t DNSDistPacketCache::getEntriesCount()
{
  return getSize();
}

uint64_t DNSDistPacketCache::dump(int fd)
{
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(dup(fd), "w"), fclose);
  if (fp == nullptr) {
    return 0;
  }

  fprintf(fp.get(), "; dnsdist's packet cache dump follows\n;\n");

  uint64_t count = 0;
  time_t now = time(nullptr);
  for (auto& shard : d_shards) {
    auto map = shard.d_map.read_lock();

    for (const auto& entry : *map) {
      const CacheValue& value = entry.second;
      count++;

      try {
        uint8_t rcode = 0;
        if (value.len >= sizeof(dnsheader)) {
          dnsheader dh;
          memcpy(&dh, value.value.data(), sizeof(dnsheader));
          rcode = dh.rcode;
        }

        fprintf(fp.get(), "%s %" PRId64 " %s ; rcode %" PRIu8 ", key %" PRIu32 ", length %" PRIu16 ", received over UDP %d, added %" PRId64 "\n", value.qname.toString().c_str(), static_cast<int64_t>(value.validity - now), QType(value.qtype).toString().c_str(), rcode, entry.first, value.len, value.receivedOverUDP, static_cast<int64_t>(value.added));
      }
      catch(...) {
        fprintf(fp.get(), "; error printing '%s'\n", value.qname.empty() ? "EMPTY" : value.qname.toString().c_str());
      }
    }
  }

  return count;
}

void DNSDistPacketCache::setSkippedOptions(const std::unordered_set<uint16_t>& optionsToSkip)
{
  d_optionsToSkip = optionsToSkip;
}
