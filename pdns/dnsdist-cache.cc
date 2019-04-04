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
#include "ednsoptions.hh"
#include "ednssubnet.hh"

DNSDistPacketCache::DNSDistPacketCache(size_t maxEntries, uint32_t maxTTL, uint32_t minTTL, uint32_t tempFailureTTL, uint32_t maxNegativeTTL, uint32_t staleTTL, bool dontAge, uint32_t shards, bool deferrableInsertLock, bool parseECS): d_maxEntries(maxEntries), d_shardCount(shards), d_maxTTL(maxTTL), d_tempFailureTTL(tempFailureTTL), d_maxNegativeTTL(maxNegativeTTL), d_minTTL(minTTL), d_staleTTL(staleTTL), d_dontAge(dontAge), d_deferrableInsertLock(deferrableInsertLock), d_parseECS(parseECS)
{
  d_shards.resize(d_shardCount);

  /* we reserve maxEntries + 1 to avoid rehashing from occurring
     when we get to maxEntries, as it means a load factor of 1 */
  for (auto& shard : d_shards) {
    shard.setSize((maxEntries / d_shardCount) + 1);
  }
}

DNSDistPacketCache::~DNSDistPacketCache()
{
  try {
    vector<std::unique_ptr<WriteLock>> locks;
    for (uint32_t shardIndex = 0; shardIndex < d_shardCount; shardIndex++) {
      locks.push_back(std::unique_ptr<WriteLock>(new WriteLock(&d_shards.at(shardIndex).d_lock)));
    }
  }
  catch(...) {
  }
}

bool DNSDistPacketCache::getClientSubnet(const char* packet, unsigned int consumed, uint16_t len, boost::optional<Netmask>& subnet)
{
  uint16_t optRDPosition;
  size_t remaining = 0;

  int res = getEDNSOptionsStart(const_cast<char*>(packet), consumed, len, &optRDPosition, &remaining);

  if (res == 0) {
    char * ecsOptionStart = nullptr;
    size_t ecsOptionSize = 0;

    res = getEDNSOption(const_cast<char*>(packet) + optRDPosition, remaining, EDNSOptionCode::ECS, &ecsOptionStart, &ecsOptionSize);

    if (res == 0 && ecsOptionSize > (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) {

      EDNSSubnetOpts eso;
      if (getEDNSSubnetOptsFromString(ecsOptionStart + (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), ecsOptionSize - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), &eso) == true) {
        subnet = eso.source;
        return true;
      }
    }
  }

  return false;
}

bool DNSDistPacketCache::cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool tcp, bool dnssecOK, const boost::optional<Netmask>& subnet) const
{
  if (cachedValue.queryFlags != queryFlags || cachedValue.dnssecOK != dnssecOK || cachedValue.tcp != tcp || cachedValue.qtype != qtype || cachedValue.qclass != qclass || cachedValue.qname != qname) {
    return false;
  }

  if (d_parseECS && cachedValue.subnet != subnet) {
    return false;
  }

  return true;
}

void DNSDistPacketCache::insertLocked(CacheShard& shard, uint32_t key, CacheValue& newValue)
{
  auto& map = shard.d_map;
  /* check again now that we hold the lock to prevent a race */
  if (map.size() >= (d_maxEntries / d_shardCount)) {
    return;
  }

  std::unordered_map<uint32_t,CacheValue>::iterator it;
  bool result;
  tie(it, result) = map.insert({key, newValue});

  if (result) {
    shard.d_entriesCount++;
    return;
  }

  /* in case of collision, don't override the existing entry
     except if it has expired */
  CacheValue& value = it->second;
  bool wasExpired = value.validity <= newValue.added;

  if (!wasExpired && !cachedValueMatches(value, newValue.queryFlags, newValue.qname, newValue.qtype, newValue.qclass, newValue.tcp, newValue.dnssecOK, newValue.subnet)) {
    d_insertCollisions++;
    return;
  }

  /* if the existing entry had a longer TTD, keep it */
  if (newValue.validity <= value.validity) {
    return;
  }

  value = newValue;
}

void DNSDistPacketCache::insert(uint32_t key, const boost::optional<Netmask>& subnet, uint16_t queryFlags, bool dnssecOK, const DNSName& qname, uint16_t qtype, uint16_t qclass, const char* response, uint16_t responseLen, bool tcp, uint8_t rcode, boost::optional<uint32_t> tempFailureTTL)
{
  if (responseLen < sizeof(dnsheader)) {
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
    minTTL = getMinTTL(response, responseLen, &seenAuthSOA);

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
  newValue.len = responseLen;
  newValue.validity = newValidity;
  newValue.added = now;
  newValue.tcp = tcp;
  newValue.dnssecOK = dnssecOK;
  newValue.value = std::string(response, responseLen);
  newValue.subnet = subnet;

  auto& shard = d_shards.at(shardIndex);

  if (d_deferrableInsertLock) {
    TryWriteLock w(&shard.d_lock);

    if (!w.gotIt()) {
      d_deferredInserts++;
      return;
    }
    insertLocked(shard, key, newValue);
  }
  else {
    WriteLock w(&shard.d_lock);

    insertLocked(shard, key, newValue);
  }
}

bool DNSDistPacketCache::get(const DNSQuestion& dq, uint16_t consumed, uint16_t queryId, char* response, uint16_t* responseLen, uint32_t* keyOut, boost::optional<Netmask>& subnet, bool dnssecOK, uint32_t allowExpired, bool skipAging)
{
  std::string dnsQName(dq.qname->toDNSString());
  uint32_t key = getKey(dnsQName, consumed, reinterpret_cast<const unsigned char*>(dq.dh), dq.len, dq.tcp);

  if (keyOut)
    *keyOut = key;

  if (d_parseECS) {
    getClientSubnet(reinterpret_cast<const char*>(dq.dh), consumed, dq.len, subnet);
  }

  uint32_t shardIndex = getShardIndex(key);
  time_t now = time(nullptr);
  time_t age;
  bool stale = false;
  auto& shard = d_shards.at(shardIndex);
  auto& map = shard.d_map;
  {
    TryReadLock r(&shard.d_lock);
    if (!r.gotIt()) {
      d_deferredLookups++;
      return false;
    }

    std::unordered_map<uint32_t,CacheValue>::const_iterator it = map.find(key);
    if (it == map.end()) {
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

    if (*responseLen < value.len || value.len < sizeof(dnsheader)) {
      return false;
    }

    /* check for collision */
    if (!cachedValueMatches(value, *(getFlagsFromDNSHeader(dq.dh)), *dq.qname, dq.qtype, dq.qclass, dq.tcp, dnssecOK, subnet)) {
      d_lookupCollisions++;
      return false;
    }

    memcpy(response, &queryId, sizeof(queryId));
    memcpy(response + sizeof(queryId), value.value.c_str() + sizeof(queryId), sizeof(dnsheader) - sizeof(queryId));

    if (value.len == sizeof(dnsheader)) {
      /* DNS header only, our work here is done */
      *responseLen = value.len;
      d_hits++;
      return true;
    }

    const size_t dnsQNameLen = dnsQName.length();
    if (value.len < (sizeof(dnsheader) + dnsQNameLen)) {
      return false;
    }

    memcpy(response + sizeof(dnsheader), dnsQName.c_str(), dnsQNameLen);
    if (value.len > (sizeof(dnsheader) + dnsQNameLen)) {
      memcpy(response + sizeof(dnsheader) + dnsQNameLen, value.value.c_str() + sizeof(dnsheader) + dnsQNameLen, value.len - (sizeof(dnsheader) + dnsQNameLen));
    }
    *responseLen = value.len;
    if (!stale) {
      age = now - value.added;
    }
    else {
      age = (value.validity - value.added) - d_staleTTL;
    }
  }

  if (!d_dontAge && !skipAging) {
    ageDNSPacket(response, *responseLen, age);
  }

  d_hits++;
  return true;
}

/* Remove expired entries, until the cache has at most
   upTo entries in it.
*/
size_t DNSDistPacketCache::purgeExpired(size_t upTo)
{
  size_t removed = 0;
  uint64_t size = getSize();

  if (size == 0 || upTo >= size) {
    return removed;
  }

  size_t toRemove = size - upTo;

  size_t scannedMaps = 0;

  const time_t now = time(nullptr);
  do {
    uint32_t shardIndex = (d_expungeIndex++ % d_shardCount);
    WriteLock w(&d_shards.at(shardIndex).d_lock);
    auto& map = d_shards[shardIndex].d_map;

    for(auto it = map.begin(); toRemove > 0 && it != map.end(); ) {
      const CacheValue& value = it->second;

      if (value.validity <= now) {
        it = map.erase(it);
        --toRemove;
        d_shards[shardIndex].d_entriesCount--;
        ++removed;
      } else {
        ++it;
      }
    }

    scannedMaps++;
  }
  while (toRemove > 0 && scannedMaps < d_shardCount);

  return removed;
}

/* Remove all entries, keeping only upTo
   entries in the cache */
size_t DNSDistPacketCache::expunge(size_t upTo)
{
  size_t removed = 0;
  const uint64_t size = getSize();

  if (upTo >= size) {
    return removed;
  }

  size_t toRemove = size - upTo;

  for (uint32_t shardIndex = 0; shardIndex < d_shardCount; shardIndex++) {
    WriteLock w(&d_shards.at(shardIndex).d_lock);
    auto& map = d_shards[shardIndex].d_map;
    auto beginIt = map.begin();
    auto endIt = beginIt;
    size_t removeFromThisShard = (toRemove - removed) / (d_shardCount - shardIndex);
    if (map.size() >= removeFromThisShard) {
      std::advance(endIt, removeFromThisShard);
      map.erase(beginIt, endIt);
      d_shards[shardIndex].d_entriesCount -= removeFromThisShard;
      removed += removeFromThisShard;
    }
    else {
      removed += map.size();
      map.clear();
      d_shards[shardIndex].d_entriesCount = 0;
    }
  }

  return removed;
}

size_t DNSDistPacketCache::expungeByName(const DNSName& name, uint16_t qtype, bool suffixMatch)
{
  size_t removed = 0;

  for (uint32_t shardIndex = 0; shardIndex < d_shardCount; shardIndex++) {
    WriteLock w(&d_shards.at(shardIndex).d_lock);
    auto& map = d_shards[shardIndex].d_map;

    for(auto it = map.begin(); it != map.end(); ) {
      const CacheValue& value = it->second;

      if ((value.qname == name || (suffixMatch && value.qname.isPartOf(name))) && (qtype == QType::ANY || qtype == value.qtype)) {
        it = map.erase(it);
        d_shards[shardIndex].d_entriesCount--;
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

  for (uint32_t shardIndex = 0; shardIndex < d_shardCount; shardIndex++) {
    count += d_shards.at(shardIndex).d_entriesCount;
  }

  return count;
}

uint32_t DNSDistPacketCache::getMinTTL(const char* packet, uint16_t length, bool* seenNoDataSOA)
{
  return getDNSPacketMinTTL(packet, length, seenNoDataSOA);
}

uint32_t DNSDistPacketCache::getKey(const std::string& qname, uint16_t consumed, const unsigned char* packet, uint16_t packetLen, bool tcp)
{
  uint32_t result = 0;
  /* skip the query ID */
  if (packetLen < sizeof(dnsheader))
    throw std::range_error("Computing packet cache key for an invalid packet size");
  result = burtle(packet + 2, sizeof(dnsheader) - 2, result);
  string lc(toLower(qname));
  result = burtle((const unsigned char*) lc.c_str(), lc.length(), result);
  if (packetLen < sizeof(dnsheader) + consumed) {
    throw std::range_error("Computing packet cache key for an invalid packet");
  }
  if (packetLen > ((sizeof(dnsheader) + consumed))) {
    result = burtle(packet + sizeof(dnsheader) + consumed, packetLen - (sizeof(dnsheader) + consumed), result);
  }
  result = burtle((const unsigned char*) &tcp, sizeof(tcp), result);
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
  FILE * fp = fdopen(dup(fd), "w");
  if (fp == nullptr) {
    return 0;
  }

  fprintf(fp, "; dnsdist's packet cache dump follows\n;\n");

  uint64_t count = 0;
  time_t now = time(nullptr);
  for (uint32_t shardIndex = 0; shardIndex < d_shardCount; shardIndex++) {
    ReadLock w(&d_shards.at(shardIndex).d_lock);
    auto& map = d_shards[shardIndex].d_map;

    for(const auto entry : map) {
      const CacheValue& value = entry.second;
      count++;

      try {
        fprintf(fp, "%s %" PRId64 " %s ; key %" PRIu32 ", length %" PRIu16 ", tcp %d, added %" PRId64 "\n", value.qname.toString().c_str(), static_cast<int64_t>(value.validity - now), QType(value.qtype).getName().c_str(), entry.first, value.len, value.tcp, static_cast<int64_t>(value.added));
      }
      catch(...) {
        fprintf(fp, "; error printing '%s'\n", value.qname.empty() ? "EMPTY" : value.qname.toString().c_str());
      }
    }
  }

  fclose(fp);
  return count;
}
