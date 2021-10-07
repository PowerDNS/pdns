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
  DNSDistPacketCache(size_t maxEntries, uint32_t maxTTL=86400, uint32_t minTTL=0, uint32_t tempFailureTTL=60, uint32_t maxNegativeTTL=3600, uint32_t staleTTL=60, bool dontAge=false, uint32_t shards=1, bool deferrableInsertLock=true, bool parseECS=false);

  void insert(uint32_t key, const boost::optional<Netmask>& subnet, uint16_t queryFlags, bool dnssecOK, const DNSName& qname, uint16_t qtype, uint16_t qclass, const PacketBuffer& response, bool receivedOverUDP, uint8_t rcode, boost::optional<uint32_t> tempFailureTTL);
  bool get(DNSQuestion& dq, uint16_t queryId, uint32_t* keyOut, boost::optional<Netmask>& subnet, bool dnssecOK, bool receivedOverUDP, uint32_t allowExpired = 0, bool skipAging = false);
  size_t purgeExpired(size_t upTo, const time_t now);
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
  void setSkippedOptions(const std::unordered_set<uint16_t>& optionsToSkip);

  bool isECSParsingEnabled() const { return d_parseECS; }

  bool keepStaleData() const
  {
    return d_keepStaleData;
  }
  void setKeepStaleData(bool keep)
  {
    d_keepStaleData = keep;
  }


  void setECSParsingEnabled(bool enabled)
  {
    d_parseECS = enabled;
  }

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
    CacheShard(const CacheShard& old)
    {
    }

    void setSize(size_t maxSize)
    {
      d_map.write_lock()->reserve(maxSize);
    }

    SharedLockGuarded<std::unordered_map<uint32_t,CacheValue>> d_map;
    std::atomic<uint64_t> d_entriesCount{0};
  };

  bool cachedValueMatches(const CacheValue& cachedValue, uint16_t queryFlags, const DNSName& qname, uint16_t qtype, uint16_t qclass, bool receivedOverUDP, bool dnssecOK, const boost::optional<Netmask>& subnet) const;
  uint32_t getShardIndex(uint32_t key) const;
  void insertLocked(CacheShard& shard, std::unordered_map<uint32_t,CacheValue>& map, uint32_t key, CacheValue& newValue);

  std::vector<CacheShard> d_shards;
  std::unordered_set<uint16_t> d_optionsToSkip{EDNSOptionCode::COOKIE};

  pdns::stat_t d_deferredLookups{0};
  pdns::stat_t d_deferredInserts{0};
  pdns::stat_t d_hits{0};
  pdns::stat_t d_misses{0};
  pdns::stat_t d_insertCollisions{0};
  pdns::stat_t d_lookupCollisions{0};
  pdns::stat_t d_ttlTooShorts{0};

  size_t d_maxEntries;
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
