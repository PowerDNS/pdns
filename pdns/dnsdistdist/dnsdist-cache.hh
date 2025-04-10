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

class DNSDistPacketCache : boost::noncopyable
{
public:
  struct CacheSettings
  {
    std::unordered_set<uint16_t> d_optionsToSkip{EDNSOptionCode::COOKIE};
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
  };

  DNSDistPacketCache(CacheSettings settings);

  void insert(uint32_t key, const boost::optional<Netmask>& subnet, uint16_t queryFlags, bool dnssecOK, const DNSName& qname, uint16_t qtype, uint16_t qclass, const PacketBuffer& response, bool receivedOverUDP, uint8_t rcode, boost::optional<uint32_t> tempFailureTTL);
  bool get(DNSQuestion& dnsQuestion, uint16_t queryId, uint32_t* keyOut, boost::optional<Netmask>& subnet, bool dnssecOK, bool receivedOverUDP, uint32_t allowExpired = 0, bool skipAging = false, bool truncatedOK = true, bool recordMiss = true);
  size_t purgeExpired(size_t upTo, const time_t now);
  size_t expunge(size_t upTo = 0);
  size_t expungeByName(const DNSName& name, uint16_t qtype = QType::ANY, bool suffixMatch = false);
  bool isFull();
  string toString();
  uint64_t getSize();
  uint64_t getHits() const { return d_hits.load(); }
  uint64_t getMisses() const { return d_misses.load(); }
  uint64_t getDeferredLookups() const { return d_deferredLookups.load(); }
  uint64_t getDeferredInserts() const { return d_deferredInserts.load(); }
  uint64_t getLookupCollisions() const { return d_lookupCollisions.load(); }
  uint64_t getInsertCollisions() const { return d_insertCollisions.load(); }
  uint64_t getMaxEntries() const { return d_settings.d_maxEntries; }
  uint64_t getTTLTooShorts() const { return d_ttlTooShorts.load(); }
  uint64_t getCleanupCount() const { return d_cleanupCount.load(); }
  uint64_t getEntriesCount();
  uint64_t dump(int fileDesc, bool rawResponse = false);

  /* get the list of domains (qnames) that contains the given address in an A or AAAA record */
  std::set<DNSName> getDomainsContainingRecords(const ComboAddress& addr);
  /* get the list of IP addresses contained in A or AAAA for a given domains (qname) */
  std::set<ComboAddress> getRecordsForDomain(const DNSName& domain);

  bool isECSParsingEnabled() const { return d_settings.d_parseECS; }

  bool keepStaleData() const
  {
    return d_settings.d_keepStaleData;
  }

  size_t getMaximumEntrySize() const { return d_settings.d_maximumEntrySize; }

  uint32_t getKey(const DNSName::string_t& qname, size_t qnameWireLength, const PacketBuffer& packet, bool receivedOverUDP);

  static uint32_t getMinTTL(const char* packet, uint16_t length, bool* seenNoDataSOA);
  static bool getClientSubnet(const PacketBuffer& packet, size_t qnameWireLength, boost::optional<Netmask>& subnet);

private:
  struct CacheValue
  {
    time_t getTTD() const { return validity; }
    std::string value;
    DNSName qname;
    boost::optional<Netmask> subnet;
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
    CacheShard()
    {
    }
    CacheShard(const CacheShard& /* old */)
    {
    }

    void setSize(size_t maxSize)
    {
      d_map.write_lock()->reserve(maxSize);
    }

    SharedLockGuarded<std::unordered_map<uint32_t, CacheValue>> d_map;
    std::atomic<uint64_t> d_entriesCount{0};
  };

  bool cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool receivedOverUDP, bool dnssecOK, const boost::optional<Netmask>& subnet) const;
  uint32_t getShardIndex(uint32_t key) const;
  void insertLocked(CacheShard& shard, std::unordered_map<uint32_t, CacheValue>& map, uint32_t key, CacheValue& newValue);

  std::vector<CacheShard> d_shards;

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
