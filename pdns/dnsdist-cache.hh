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

struct DNSQuestion;

class DNSDistPacketCache : boost::noncopyable
{
public:
  DNSDistPacketCache(size_t maxEntries, uint32_t maxTTL=86400, uint32_t minTTL=0, uint32_t tempFailureTTL=60, uint32_t maxNegativeTTL=3600, uint32_t staleTTL=60, bool dontAge=false, uint32_t shards=1, bool deferrableInsertLock=true, bool parseECS=false);
  ~DNSDistPacketCache();

  void insert(uint32_t key, const boost::optional<Netmask>& subnet, uint16_t queryFlags, bool dnssecOK, const DNSName& qname, uint16_t qtype, uint16_t qclass, const char* response, uint16_t responseLen, bool tcp, uint8_t rcode, boost::optional<uint32_t> tempFailureTTL);
  bool get(const DNSQuestion& dq, uint16_t consumed, uint16_t queryId, char* response, uint16_t* responseLen, uint32_t* keyOut, boost::optional<Netmask>& subnetOut, bool dnssecOK, uint32_t allowExpired=0, bool skipAging=false);
  size_t purgeExpired(size_t upTo=0);
  size_t expunge(size_t upTo=0);
  size_t expungeByName(const DNSName& name, uint16_t qtype=QType::ANY, bool suffixMatch=false);
  bool isFull();
  string toString();
  uint64_t getSize();
  uint64_t getHits() const { return d_hits; }
  uint64_t getMisses() const { return d_misses; }
  uint64_t getDeferredLookups() const { return d_deferredLookups; }
  uint64_t getDeferredInserts() const { return d_deferredInserts; }
  uint64_t getLookupCollisions() const { return d_lookupCollisions; }
  uint64_t getInsertCollisions() const { return d_insertCollisions; }
  uint64_t getMaxEntries() const { return d_maxEntries; }
  uint64_t getTTLTooShorts() const { return d_ttlTooShorts; }
  uint64_t getEntriesCount();
  uint64_t dump(int fd);

  bool isECSParsingEnabled() const { return d_parseECS; }

  bool keepStaleData() const
  {
    return d_keepStaleData;
  }
  void setKeepStaleData(bool keep)
  {
    d_keepStaleData = keep;
  }

  static uint32_t getMinTTL(const char* packet, uint16_t length, bool* seenNoDataSOA);
  static uint32_t getKey(const std::string& qname, uint16_t consumed, const unsigned char* packet, uint16_t packetLen, bool tcp);
  static bool getClientSubnet(const char* packet, unsigned int consumed, uint16_t len, boost::optional<Netmask>& subnet);

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
    bool tcp{false};
    bool dnssecOK{false};
  };

  class CacheShard
  {
  public:
    CacheShard(): d_entriesCount(0)
    {
      pthread_rwlock_init(&d_lock, 0);
    }
    CacheShard(const CacheShard& old): d_entriesCount(0)
    {
      pthread_rwlock_init(&d_lock, 0);
    }

    void setSize(size_t maxSize)
    {
      d_map.reserve(maxSize);
    }

    std::unordered_map<uint32_t,CacheValue> d_map;
    pthread_rwlock_t d_lock;
    std::atomic<uint64_t> d_entriesCount;
  };

  bool cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool tcp, bool dnssecOK, const boost::optional<Netmask>& subnet) const;
  uint32_t getShardIndex(uint32_t key) const;
  void insertLocked(CacheShard& shard, uint32_t key, CacheValue& newValue);

  std::vector<CacheShard> d_shards;

  std::atomic<uint64_t> d_deferredLookups{0};
  std::atomic<uint64_t> d_deferredInserts{0};
  std::atomic<uint64_t> d_hits{0};
  std::atomic<uint64_t> d_misses{0};
  std::atomic<uint64_t> d_insertCollisions{0};
  std::atomic<uint64_t> d_lookupCollisions{0};
  std::atomic<uint64_t> d_ttlTooShorts{0};

  size_t d_maxEntries;
  uint32_t d_expungeIndex{0};
  uint32_t d_shardCount;
  uint32_t d_maxTTL;
  uint32_t d_tempFailureTTL;
  uint32_t d_maxNegativeTTL;
  uint32_t d_minTTL;
  uint32_t d_staleTTL;
  bool d_dontAge;
  bool d_deferrableInsertLock;
  bool d_parseECS;
  bool d_keepStaleData{false};
};
