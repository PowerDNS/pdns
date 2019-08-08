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

#include <mutex>
#include <time.h>
#include <unordered_map>

#include <boost/variant.hpp>

#include "circular_buffer.hh"
#include "dnsname.hh"
#include "iputils.hh"


struct Rings {
  struct Query
  {
    struct timespec when;
    ComboAddress requestor;
    DNSName name;
    uint16_t size;
    uint16_t qtype;
    struct dnsheader dh;
  };
  struct Response
  {
    struct timespec when;
    ComboAddress requestor;
    DNSName name;
    uint16_t qtype;
    unsigned int usec;
    unsigned int size;
    struct dnsheader dh;
    ComboAddress ds; // who handled it
  };

  struct Shard
  {
    boost::circular_buffer<Query> queryRing;
    boost::circular_buffer<Response> respRing;
    std::mutex queryLock;
    std::mutex respLock;
  };

  Rings(size_t capacity=10000, size_t numberOfShards=1, size_t nbLockTries=5, bool keepLockingStats=false): d_blockingQueryInserts(0), d_blockingResponseInserts(0), d_deferredQueryInserts(0), d_deferredResponseInserts(0), d_nbQueryEntries(0), d_nbResponseEntries(0), d_currentShardId(0), d_numberOfShards(numberOfShards), d_nbLockTries(nbLockTries), d_keepLockingStats(keepLockingStats)
  {
    setCapacity(capacity, numberOfShards);
    if (numberOfShards <= 1) {
      d_nbLockTries = 0;
    }
  }
  std::unordered_map<int, vector<boost::variant<string,double> > > getTopBandwidth(unsigned int numentries);
  size_t numDistinctRequestors();
  /* This function should only be called at configuration time before any query or response has been inserted */
  void setCapacity(size_t newCapacity, size_t numberOfShards)
  {
    if (numberOfShards < d_numberOfShards) {
      throw std::runtime_error("Decreasing the number of shards in the query and response rings is not supported");
    }

    d_shards.resize(numberOfShards);
    d_numberOfShards = numberOfShards;

    /* resize all the rings */
    for (auto& shard : d_shards) {
      shard = std::unique_ptr<Shard>(new Shard());
      {
        std::lock_guard<std::mutex> wl(shard->queryLock);
        shard->queryRing.set_capacity(newCapacity / numberOfShards);
      }
      {
        std::lock_guard<std::mutex> wl(shard->respLock);
        shard->respRing.set_capacity(newCapacity / numberOfShards);
      }
    }

    /* we just recreated the shards so they are now empty */
    d_nbQueryEntries = 0;
    d_nbResponseEntries = 0;
  }

  void setNumberOfLockRetries(size_t retries)
  {
    if (d_numberOfShards <= 1) {
      d_nbLockTries = 0;
    } else {
      d_nbLockTries = retries;
    }
  }

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

  void insertQuery(const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, uint16_t size, const struct dnsheader& dh)
  {
    for (size_t idx = 0; idx < d_nbLockTries; idx++) {
      auto& shard = getOneShard();
      std::unique_lock<std::mutex> wl(shard->queryLock, std::try_to_lock);
      if (wl.owns_lock()) {
        insertQueryLocked(shard, when, requestor, name, qtype, size, dh);
        return;
      }
      if (d_keepLockingStats) {
        d_deferredQueryInserts++;
      }
    }

    /* out of luck, let's just wait */
    if (d_keepLockingStats) {
      d_blockingResponseInserts++;
    }
    auto& shard = getOneShard();
    std::lock_guard<std::mutex> wl(shard->queryLock);
    insertQueryLocked(shard, when, requestor, name, qtype, size, dh);
  }

  void insertResponse(const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, unsigned int usec, unsigned int size, const struct dnsheader& dh, const ComboAddress& backend)
  {
    for (size_t idx = 0; idx < d_nbLockTries; idx++) {
      auto& shard = getOneShard();
      std::unique_lock<std::mutex> wl(shard->respLock, std::try_to_lock);
      if (wl.owns_lock()) {
        insertResponseLocked(shard, when, requestor, name, qtype, usec, size, dh, backend);
        return;
      }
      if (d_keepLockingStats) {
        d_deferredResponseInserts++;
      }
    }

    /* out of luck, let's just wait */
    if (d_keepLockingStats) {
      d_blockingResponseInserts++;
    }
    auto& shard = getOneShard();
    std::lock_guard<std::mutex> wl(shard->respLock);
    insertResponseLocked(shard, when, requestor, name, qtype, usec, size, dh, backend);
  }

  void clear()
  {
    for (auto& shard : d_shards) {
      {
        std::lock_guard<std::mutex> wl(shard->queryLock);
        shard->queryRing.clear();
      }
      {
        std::lock_guard<std::mutex> wl(shard->respLock);
        shard->respRing.clear();
      }
    }

    d_nbQueryEntries.store(0);
    d_nbResponseEntries.store(0);
    d_currentShardId.store(0);
    d_blockingQueryInserts.store(0);
    d_blockingResponseInserts.store(0);
    d_deferredQueryInserts.store(0);
    d_deferredResponseInserts.store(0);
  }

  std::vector<std::unique_ptr<Shard> > d_shards;
  std::atomic<uint64_t> d_blockingQueryInserts;
  std::atomic<uint64_t> d_blockingResponseInserts;
  std::atomic<uint64_t> d_deferredQueryInserts;
  std::atomic<uint64_t> d_deferredResponseInserts;

private:
  size_t getShardId()
  {
    return (d_currentShardId++ % d_numberOfShards);
  }

  std::unique_ptr<Shard>& getOneShard()
  {
    return d_shards[getShardId()];
  }

  void insertQueryLocked(std::unique_ptr<Shard>& shard, const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, uint16_t size, const struct dnsheader& dh)
  {
    if (!shard->queryRing.full()) {
      d_nbQueryEntries++;
    }
    shard->queryRing.push_back({when, requestor, name, size, qtype, dh});
  }

  void insertResponseLocked(std::unique_ptr<Shard>& shard, const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, unsigned int usec, unsigned int size, const struct dnsheader& dh, const ComboAddress& backend)
  {
    if (!shard->respRing.full()) {
      d_nbResponseEntries++;
    }
    shard->respRing.push_back({when, requestor, name, qtype, usec, size, dh, backend});
  }

  std::atomic<size_t> d_nbQueryEntries;
  std::atomic<size_t> d_nbResponseEntries;
  std::atomic<size_t> d_currentShardId;

  size_t d_numberOfShards;
  size_t d_nbLockTries = 5;
  bool d_keepLockingStats{false};
};

extern Rings g_rings;
