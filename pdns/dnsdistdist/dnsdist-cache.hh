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
#pragma once

#include <atomic>
#include <unordered_map>

#include "iputils.hh"
#include "lock.hh"
#include "noinitvector.hh"
#include "stat_t.hh"
#include "ednsoptions.hh"

struct DNSQuestion;

// lru cache is NOT locked; we need to use shared lock
template <typename K, typename V>
class MaybeLruCache
{
public:
  MaybeLruCache() {}

  void init(size_t t, bool isLRU)
  {
    // we reserve maxEntries + 1 to avoid rehashing from occurring
    // when we get to maxEntries, as it means a load factor of 1
    d_maxSize = t;
    d_baseMap.reserve(t + 1);
    if (d_isLru) {
      d_lruMap.reserve(t + 1);
    }
    d_isLru = isLRU;
  }

  const typename std::unordered_map<K, V>::const_iterator find(const K& key) const
  {
    // this is const; without putFront
    return d_baseMap.find(key);
  }

  const typename std::unordered_map<K, V>::iterator findAndPutFront(const K& key)
  {
    if (!d_isLru) {
      // should not happen? but return something anyway
      return d_baseMap.find(key);
    }

    auto f = d_baseMap.find(key);
    if (f == d_baseMap.end()) {
      return f;
    }
    putFront(key);
    return f;
  }

  size_t size() const
  {
    return d_baseMap.size();
  }

  const std::pair<typename std::unordered_map<K, V>::iterator, bool> insert(const K& key, const V& value, bool& lru_removed)
  {
    if (!d_isLru) {
      lru_removed = false;
      return d_baseMap.insert({key, value});
    }

    auto mapIt = d_baseMap.find(key);
    if (mapIt != d_baseMap.end()) {
      // it's there, we return iterator; but we will need to putFront it later
      return std::pair<typename std::unordered_map<K, V>::iterator, bool>(mapIt, false);
    }

    // we would insert; but first we need to check the sizes
    if (d_baseMap.size() == d_maxSize) {
      lru_removed = true;
      // we need to throw out last
      auto& k = d_lruList.back();
      d_baseMap.erase(k);
      d_lruMap.erase(k);
      d_lruList.pop_back();
    }
    else {
      lru_removed = false;
    }

    // we can insert now
    auto res = d_baseMap.insert({key, value});
    d_lruList.push_front(key);
    d_lruMap.insert({key, d_lruList.begin()});

    return res;
  }

  const typename std::unordered_map<K, V>::const_iterator begin() const
  {
    return d_baseMap.begin();
  }

  const typename std::unordered_map<K, V>::const_iterator end() const
  {
    return d_baseMap.end();
  }

  typename std::unordered_map<K, V>::iterator erase(typename std::unordered_map<K, V>::const_iterator it)
  {
    if (d_isLru) {
      auto lruIt = d_lruMap.find(it->first);
      d_lruList.erase(lruIt->second);
      d_lruMap.erase(lruIt);
    }

    return d_baseMap.erase(it);
  }

  void erase(typename std::unordered_map<K, V>::const_iterator start, typename std::unordered_map<K, V>::const_iterator end)
  {
    for (auto it = start; it != end;) {
      it = erase(it);
    }
  }

  void putFront(const K& key)
  {
    if (!d_isLru) {
      return; // noop
    }
    auto lruIt = d_lruMap.find(key);
    if (lruIt == d_lruMap.end()) {
      // should not happen...?
      return;
    }

    d_lruList.splice(d_lruList.begin(), d_lruList, lruIt->second);
  }

  void clear()
  {
    d_baseMap.clear();
    if (d_isLru) {
      d_lruList.clear();
      d_lruMap.clear();
    }
  }

private:
  bool d_isLru;
  size_t d_maxSize;

  std::unordered_map<K, V> d_baseMap;
  std::list<K> d_lruList;
  std::unordered_map<K, typename std::list<K>::iterator> d_lruMap;
};

class DNSDistPacketCache : boost::noncopyable
{
public:
  struct CacheSettings
  {
    std::unordered_set<uint16_t> d_optionsToSkip{EDNSOptionCode::COOKIE, EDNSOptionCode::PADDING};
    std::vector<uint16_t> d_payloadRanks{};
    size_t d_maxEntries{0};
    size_t d_maximumEntrySize{4096};
    uint32_t d_maxTTL{86400};
    uint32_t d_minTTL{0};
    uint32_t d_tempFailureTTL{60};
    uint32_t d_maxNegativeTTL{3600};
    uint32_t d_truncatedTTL{0};
    uint32_t d_staleTTL{60};
    uint32_t d_shardCount{1};
    bool d_dontAge{false};
    bool d_deferrableInsertLock{true};
    bool d_parseECS{false};
    bool d_keepStaleData{false};
    bool d_shuffle{false};
    bool d_alwaysKeepStaleData{false};
  };

  DNSDistPacketCache(CacheSettings settings);

  void insert(uint32_t key, const std::optional<Netmask>& subnet, uint16_t queryFlags, bool dnssecOK, const DNSName& qname, uint16_t qtype, uint16_t qclass, const PacketBuffer& response, bool receivedOverUDP, uint8_t rcode, std::optional<uint32_t> tempFailureTTL);
  bool get(DNSQuestion& dnsQuestion, uint16_t queryId, uint32_t* keyOut, std::optional<Netmask>& subnet, bool dnssecOK, bool receivedOverUDP, uint32_t allowExpired = 0, bool skipAging = false, bool truncatedOK = true, bool recordMiss = true);
  size_t purgeExpired(size_t upTo, time_t now);
  size_t expunge(size_t upTo = 0);
  size_t expungeByName(const DNSName& name, uint16_t qtype = QType::ANY, bool suffixMatch = false);
  [[nodiscard]] bool isFull();
  [[nodiscard]] string toString();
  [[nodiscard]] uint64_t getSize();
  [[nodiscard]] uint64_t getHits() const { return d_hits.load(); }
  [[nodiscard]] uint64_t getMisses() const { return d_misses.load(); }
  [[nodiscard]] uint64_t getDeferredLookups() const { return d_deferredLookups.load(); }
  [[nodiscard]] uint64_t getDeferredInserts() const { return d_deferredInserts.load(); }
  [[nodiscard]] uint64_t getLookupCollisions() const { return d_lookupCollisions.load(); }
  [[nodiscard]] uint64_t getInsertCollisions() const { return d_insertCollisions.load(); }
  [[nodiscard]] uint64_t getMaxEntries() const { return d_settings.d_maxEntries; }
  [[nodiscard]] uint64_t getTTLTooShorts() const { return d_ttlTooShorts.load(); }
  [[nodiscard]] uint64_t getCleanupCount() const { return d_cleanupCount.load(); }
  [[nodiscard]] uint64_t getEntriesCount();
  uint64_t dump(int fileDesc, bool rawResponse = false);

  /* get the list of domains (qnames) that contains the given address in an A or AAAA record */
  [[nodiscard]] std::set<DNSName> getDomainsContainingRecords(const ComboAddress& addr);
  /* get the list of IP addresses contained in A or AAAA for a given domains (qname) */
  [[nodiscard]] std::set<ComboAddress> getRecordsForDomain(const DNSName& domain);

  [[nodiscard]] bool isECSParsingEnabled() const { return d_settings.d_parseECS; }

  [[nodiscard]] bool keepStaleData() const
  {
    return d_settings.d_keepStaleData;
  }

  [[nodiscard]] bool alwaysKeepStaleData() const
  {
    return d_settings.d_alwaysKeepStaleData;
  }

  [[nodiscard]] size_t getMaximumEntrySize() const { return d_settings.d_maximumEntrySize; }

  uint32_t getKey(const DNSName::string_t& qname, size_t qnameWireLength, const PacketBuffer& packet, bool receivedOverUDP) const;

  static uint32_t getMinTTL(const char* packet, uint16_t length, bool* seenNoDataSOA);
  static bool getClientSubnet(const PacketBuffer& packet, size_t qnameWireLength, std::optional<Netmask>& subnet);

private:
  struct CacheValue
  {
    [[nodiscard]] time_t getTTD() const { return validity; }
    std::string value;
    DNSName qname;
    std::optional<Netmask> subnet;
    uint16_t qtype{0};
    uint16_t qclass{0};
    uint16_t queryFlags{0};
    time_t added{0};
    time_t validity{0};
    uint16_t len{0};
    bool receivedOverUDP{false};
    bool dnssecOK{false};
  };

  class CacheShard
  {
  public:
    CacheShard() = default;
    CacheShard(CacheShard&& /* old */) noexcept
    {
    }
    CacheShard(const CacheShard& /* old */)
    {
    }
    CacheShard& operator=(CacheShard&& /* old */) noexcept
    {
      return *this;
    }
    CacheShard& operator=(const CacheShard& /* old */)
    {
      return *this;
    }
    ~CacheShard() = default;

    void init(size_t maxSize, bool isLRU)
    {
      d_map.write_lock()->init(maxSize, isLRU);
    }

    SharedLockGuarded<MaybeLruCache<uint32_t, CacheValue>> d_map{};
    std::atomic<uint64_t> d_entriesCount{0};
  };

  [[nodiscard]] bool cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool receivedOverUDP, bool dnssecOK, const std::optional<Netmask>& subnet) const;
  [[nodiscard]] uint32_t getShardIndex(uint32_t key) const;
  bool insertLocked(MaybeLruCache<uint32_t, CacheValue>& map, uint32_t key, CacheValue& newValue, bool checkSize);

  [[nodiscard]] std::pair<bool, bool> getWriteLocked(MaybeLruCache<uint32_t, CacheValue>& map, DNSQuestion& dnsQuestion, bool& stale, PacketBuffer& response, time_t& age, uint32_t key, bool recordMiss, time_t now, uint32_t allowExpired, bool receivedOverUDP, bool dnssecOK, const std::optional<Netmask>& subnet, bool truncatedOK, uint16_t queryId, const DNSName::string_t& dnsQName);
  [[nodiscard]] std::pair<bool, bool> getReadLocked(const MaybeLruCache<uint32_t, CacheValue>& map, DNSQuestion& dnsQuestion, bool& stale, PacketBuffer& response, time_t& age, uint32_t key, bool recordMiss, time_t now, uint32_t allowExpired, bool receivedOverUDP, bool dnssecOK, const std::optional<Netmask>& subnet, bool truncatedOK, uint16_t queryId, const DNSName::string_t& dnsQName);
  [[nodiscard]] std::pair<bool, bool> getLocked(const CacheValue& value, DNSQuestion& dnsQuestion, bool& stale, PacketBuffer& response, time_t& age, bool recordMiss, time_t now, uint32_t allowExpired, bool receivedOverUDP, bool dnssecOK, const std::optional<Netmask>& subnet, bool truncatedOK, uint16_t queryId, const DNSName::string_t& dnsQName);

  std::vector<CacheShard> d_shards{};

  pdns::stat_t d_deferredLookups{0};
  pdns::stat_t d_deferredInserts{0};
  pdns::stat_t d_hits{0};
  pdns::stat_t d_misses{0};
  pdns::stat_t d_insertCollisions{0};
  pdns::stat_t d_lookupCollisions{0};
  pdns::stat_t d_ttlTooShorts{0};
  pdns::stat_t d_cleanupCount{0};

  CacheSettings d_settings;
};
