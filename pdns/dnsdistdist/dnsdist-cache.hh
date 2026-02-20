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

#include "iputils.hh"
#include "dnsdist-cache-containers.hh"
#include "lock.hh"
#include "noinitvector.hh"
#include "stat_t.hh"
#include "ednsoptions.hh"

struct DNSQuestion;

class DNSDistPacketCache : boost::noncopyable
{
public:
  enum class EvictionType : uint8_t
  {
    NoEviction,
    Lru,
    Sieve,
  };

  static bool parseEvictionType(const std::string& type, EvictionType& ev)
  {
    if (type == "none") {
      ev = EvictionType::NoEviction;
      return true;
    }
    if (type == "lru") {
      ev = EvictionType::Lru;
      return true;
    }
    if (type == "sieve") {
      ev = EvictionType::Sieve;
      return true;
    }
    return false;
  }

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
    EvictionType d_eviction{EvictionType::NoEviction};
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

  [[nodiscard]] EvictionType eviction() const
  {
    return d_settings.d_eviction;
  }

  [[nodiscard]] bool keepStaleEntriesOnUpServers() const
  {
    return d_settings.d_eviction != EvictionType::NoEviction;
  }

  [[nodiscard]] bool checkSizeBeforeInsert() const
  {
    return d_settings.d_eviction == EvictionType::NoEviction;
  }

  [[nodiscard]] bool getNeedsWriteLock() const
  {
    return d_settings.d_eviction == EvictionType::Lru;
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

    void init(size_t maxSize, EvictionType eviction)
    {
      auto lock = d_container.write_lock();
      switch (eviction) {
      case EvictionType::NoEviction:
        *lock = std::make_unique<NoEvictionCache<CacheValue>>(maxSize);
        break;
      case EvictionType::Lru:
        *lock = std::make_unique<LruCache<CacheValue>>(maxSize);
        break;
      case EvictionType::Sieve:
        *lock = std::make_unique<SieveCache<CacheValue>>(maxSize);
        break;
      default:
        throw std::logic_error("eviction type not known");
      }
    }

    SharedLockGuarded<std::unique_ptr<CacheContainer<CacheValue>>> d_container{};

    std::atomic<uint64_t> d_entriesCount{0};
  };

  [[nodiscard]] bool cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool receivedOverUDP, bool dnssecOK, const std::optional<Netmask>& subnet) const;
  [[nodiscard]] uint32_t getShardIndex(uint32_t key) const;
  bool insertLocked(CacheContainer<CacheValue>& map, uint32_t key, CacheValue& newValue);

  [[nodiscard]] std::pair<bool, bool> getReadLocked(const CacheContainer<CacheValue>& map, DNSQuestion& dnsQuestion, bool& stale, PacketBuffer& response, time_t& age, uint32_t key, bool recordMiss, time_t now, uint32_t allowExpired, bool receivedOverUDP, bool dnssecOK, const std::optional<Netmask>& subnet, bool truncatedOK, uint16_t queryId, const DNSName::string_t& dnsQName);
  [[nodiscard]] std::pair<bool, bool> getWriteLocked(CacheContainer<CacheValue>& map, DNSQuestion& dnsQuestion, bool& stale, PacketBuffer& response, time_t& age, uint32_t key, bool recordMiss, time_t now, uint32_t allowExpired, bool receivedOverUDP, bool dnssecOK, const std::optional<Netmask>& subnet, bool truncatedOK, uint16_t queryId, const DNSName::string_t& dnsQName);
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
