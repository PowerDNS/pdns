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

#include <time.h>
#include <unordered_map>

#include <boost/variant.hpp>

#include "circular_buffer.hh"
#include "dnsname.hh"
#include "iputils.hh"
#include "lock.hh"
#include "stat_t.hh"
#include "dnsdist-protocols.hh"
#include "dnsdist-mac-address.hh"

struct Rings
{
  struct Query
  {
    ComboAddress requestor;
    DNSName name;
    struct timespec when;
    struct dnsheader dh;
    uint16_t size;
    uint16_t qtype;
    // incoming protocol
    dnsdist::Protocol protocol;
#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
    dnsdist::MacAddress macaddress;
    bool hasmac{false};
#endif
  };
  struct Response
  {
    ComboAddress requestor;
    ComboAddress ds; // who handled it
    DNSName name;
    struct timespec when;
    struct dnsheader dh;
    unsigned int usec;
    uint16_t size;
    uint16_t qtype;
    // outgoing protocol
    dnsdist::Protocol protocol;

    bool isACacheHit() const;
  };

  struct Shard
  {
    LockGuarded<boost::circular_buffer<Query>> queryRing;
    LockGuarded<boost::circular_buffer<Response>> respRing;
  };

  std::unordered_map<int, vector<boost::variant<string, double>>> getTopBandwidth(unsigned int numentries);
  size_t numDistinctRequestors();

  struct RingsConfiguration
  {
    size_t capacity{0};
    size_t numberOfShards{1};
    size_t nbLockTries{5};
    size_t samplingRate{0};
    bool recordQueries{true};
    bool recordResponses{true};
  };

  /* This function should only be called at configuration time before any query or response has been inserted */
  void init(const RingsConfiguration& config);

  size_t getNumberOfShards() const
  {
    return d_numberOfShards;
  }

  size_t getNumberOfQueryEntries() const
  {
    return d_nbQueryEntries;
  }

  size_t getNumberOfResponseEntries() const
  {
    return d_nbResponseEntries;
  }

  void insertQuery(const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, uint16_t size, const struct dnsheader& dh, dnsdist::Protocol protocol)
  {
    if (shouldSkipDueToSampling()) {
      return;
    }
    auto ourName = DNSName(name);
#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
    dnsdist::MacAddress macaddress;
    bool hasmac{false};
    if (dnsdist::MacAddressesCache::get(requestor, macaddress.data(), macaddress.size()) == 0) {
      hasmac = true;
    }
#endif
    for (size_t idx = 0; idx < d_nbLockTries; idx++) {
      auto& shard = getOneShard();
      bool wasFull = false;
      {
        auto lock = shard->queryRing.try_lock();
        if (!lock.owns_lock()) {
          if (s_keepLockingStats) {
            ++d_deferredQueryInserts;
          }
          continue;
        }
#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
        wasFull = insertQueryLocked(*lock, when, requestor, std::move(ourName), qtype, size, dh, protocol, macaddress, hasmac);
#else
        wasFull = insertQueryLocked(*lock, when, requestor, std::move(ourName), qtype, size, dh, protocol);
#endif
      }

      if (!wasFull) {
        d_nbQueryEntries++;
      }
      return;
    }

    /* out of luck, let's just wait */
    if (s_keepLockingStats) {
      ++d_blockingResponseInserts;
    }
    auto& shard = getOneShard();
    bool wasFull = false;
    {
      auto lock = shard->queryRing.lock();
#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
      wasFull = insertQueryLocked(*lock, when, requestor, std::move(ourName), qtype, size, dh, protocol, macaddress, hasmac);
#else
      wasFull = insertQueryLocked(*lock, when, requestor, std::move(ourName), qtype, size, dh, protocol);
#endif
    }
    if (!wasFull) {
      d_nbQueryEntries++;
    }
  }

  void insertResponse(const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, unsigned int usec, unsigned int size, const struct dnsheader& dh, const ComboAddress& backend, dnsdist::Protocol protocol)
  {
    if (shouldSkipDueToSampling()) {
      return;
    }
    auto ourName = DNSName(name);
    for (size_t idx = 0; idx < d_nbLockTries; idx++) {
      auto& shard = getOneShard();
      bool wasFull = false;
      {
        auto lock = shard->respRing.try_lock();
        if (!lock.owns_lock()) {
          if (s_keepLockingStats) {
            ++d_deferredResponseInserts;
          }
          continue;
        }
        wasFull = insertResponseLocked(*lock, when, requestor, std::move(ourName), qtype, usec, size, dh, backend, protocol);
      }
      if (!wasFull) {
        d_nbResponseEntries++;
      }
      return;
    }

    /* out of luck, let's just wait */
    if (s_keepLockingStats) {
      ++d_blockingResponseInserts;
    }
    auto& shard = getOneShard();
    bool wasFull = false;
    {
      auto lock = shard->respRing.lock();
      wasFull = insertResponseLocked(*lock, when, requestor, std::move(ourName), qtype, usec, size, dh, backend, protocol);
    }
    if (!wasFull) {
      d_nbResponseEntries++;
    }
  }

  void clear()
  {
    for (auto& shard : d_shards) {
      shard->queryRing.lock()->clear();
      shard->respRing.lock()->clear();
    }

    d_nbQueryEntries.store(0);
    d_nbResponseEntries.store(0);
    d_currentShardId.store(0);
    d_blockingQueryInserts.store(0);
    d_blockingResponseInserts.store(0);
    d_deferredQueryInserts.store(0);
    d_deferredResponseInserts.store(0);
  }

  /* this should be called in the unit tests, and never at runtime */
  void reset()
  {
    clear();
    d_initialized = false;
  }

  /* load the content of the ring buffer from a file in the format emitted by grepq(),
     only useful for debugging purposes */
  size_t loadFromFile(const std::string& filepath, const struct timespec& now);

  bool shouldRecordQueries() const
  {
    return d_recordQueries;
  }

  bool shouldRecordResponses() const
  {
    return d_recordResponses;
  }

  size_t getSamplingRate() const
  {
    return d_samplingRate;
  }

  uint32_t adjustForSamplingRate(uint32_t count) const;

  std::vector<std::unique_ptr<Shard>> d_shards;
  pdns::stat_t d_blockingQueryInserts{0};
  pdns::stat_t d_blockingResponseInserts{0};
  pdns::stat_t d_deferredQueryInserts{0};
  pdns::stat_t d_deferredResponseInserts{0};

private:
  size_t getShardId()
  {
    return (d_currentShardId++ % d_numberOfShards);
  }

  std::unique_ptr<Shard>& getOneShard()
  {
    return d_shards[getShardId()];
  }

#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
  bool insertQueryLocked(boost::circular_buffer<Query>& ring, const struct timespec& when, const ComboAddress& requestor, DNSName&& name, uint16_t qtype, uint16_t size, const struct dnsheader& dh, dnsdist::Protocol protocol, const dnsdist::MacAddress& macaddress, const bool hasmac)
#else
  bool insertQueryLocked(boost::circular_buffer<Query>& ring, const struct timespec& when, const ComboAddress& requestor, DNSName&& name, uint16_t qtype, uint16_t size, const struct dnsheader& dh, dnsdist::Protocol protocol)
#endif
  {
    bool wasFull = ring.full();
#if defined(DNSDIST_RINGS_WITH_MACADDRESS)
    Rings::Query query{requestor, std::move(name), when, dh, size, qtype, protocol, dnsdist::MacAddress{""}, hasmac};
    if (hasmac) {
      memcpy(query.macaddress.data(), macaddress.data(), macaddress.size());
    }
    ring.push_back(std::move(query));
#else
    ring.push_back({requestor, std::move(name), when, dh, size, qtype, protocol});
#endif
    return wasFull;
  }

  bool insertResponseLocked(boost::circular_buffer<Response>& ring, const struct timespec& when, const ComboAddress& requestor, DNSName&& name, uint16_t qtype, unsigned int usec, uint16_t size, const struct dnsheader& dh, const ComboAddress& backend, dnsdist::Protocol protocol)
  {
    bool wasFull = ring.full();
    ring.push_back({requestor, backend, std::move(name), when, dh, usec, size, qtype, protocol});
    return wasFull;
  }

  bool shouldSkipDueToSampling();

  static constexpr bool s_keepLockingStats{false};
  // small hack to reduce contention: this only works because we have a single Rings object in DNSdist
  static thread_local size_t t_samplingCounter;


  std::atomic<size_t> d_nbQueryEntries{0};
  std::atomic<size_t> d_nbResponseEntries{0};
  std::atomic<size_t> d_currentShardId{0};
  std::atomic<bool> d_initialized{false};

  size_t d_capacity{10000};
  size_t d_numberOfShards{10};
  size_t d_nbLockTries{5};
  size_t d_samplingRate{0};
  bool d_recordQueries{true};
  bool d_recordResponses{true};
};

extern Rings g_rings;
