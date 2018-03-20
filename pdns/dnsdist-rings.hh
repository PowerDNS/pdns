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

#include <boost/circular_buffer.hpp>
#include <boost/variant.hpp>

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

  Rings(size_t capacity=10000, size_t numberOfShards=1, size_t nbLockTries=5): d_numberOfShards(numberOfShards), d_nbLockTries(nbLockTries)
  {
    setCapacity(capacity, numberOfShards);
    if (numberOfShards <= 1) {
      d_nbLockTries = 0;
    }
  }
  std::unordered_map<int, vector<boost::variant<string,double> > > getTopBandwidth(unsigned int numentries);
  size_t numDistinctRequestors();
  void setCapacity(size_t newCapacity, size_t numberOfShards)
  {
    if (numberOfShards < d_numberOfShards) {
      throw std::runtime_error("Decreasing the number of shards in the query and response rings is not supported");
    }

    d_shards.resize(numberOfShards);
    d_numberOfShards = numberOfShards;

    /* resize all the rings */
    for (size_t idx = 0; idx < numberOfShards; idx++) {
      d_shards[idx] = std::unique_ptr<Shard>(new Shard());
      {
        std::lock_guard<std::mutex> wl(d_shards[idx]->queryLock);
        d_shards[idx]->queryRing.set_capacity(newCapacity / numberOfShards);
      }
      {
        std::lock_guard<std::mutex> wl(d_shards[idx]->respLock);
        d_shards[idx]->respRing.set_capacity(newCapacity / numberOfShards);
      }
    }
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

  void insertQuery(const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, uint16_t size, const struct dnsheader& dh)
  {
    for (size_t idx = 0; idx < d_nbLockTries; idx++) {
      auto shardId = getShardId();
      std::unique_lock<std::mutex> wl(d_shards[shardId]->queryLock, std::try_to_lock);
      if (wl.owns_lock()) {
        d_shards[shardId]->queryRing.push_back({when, requestor, name, size, qtype, dh});
        return;
      }
    }

    /* out of luck, let's just wait */
    auto shardId = getShardId();
    std::lock_guard<std::mutex> wl(d_shards[shardId]->queryLock);
    d_shards[shardId]->queryRing.push_back({when, requestor, name, size, qtype, dh});
  }

  void insertResponse(const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, unsigned int usec, unsigned int size, const struct dnsheader& dh, const ComboAddress& backend)
  {
    for (size_t idx = 0; idx < d_nbLockTries; idx++) {
      auto shardId = getShardId();
      std::unique_lock<std::mutex> wl(d_shards[shardId]->respLock, std::try_to_lock);
      if (wl.owns_lock()) {
        d_shards[shardId]->respRing.push_back({when, requestor, name, qtype, usec, size, dh, backend});
        return;
      }
    }

    /* out of luck, let's just wait */
    auto shardId = getShardId();
    std::lock_guard<std::mutex> wl(d_shards[shardId]->respLock);
    d_shards[shardId]->respRing.push_back({when, requestor, name, qtype, usec, size, dh, backend});
  }

  std::vector<std::unique_ptr<Shard> > d_shards;

private:
  size_t getShardId()
  {
    return (d_currentShardId++ % d_numberOfShards);
  }

  std::atomic<size_t> d_currentShardId;

  size_t d_numberOfShards;
  size_t d_nbLockTries = 5;

};

extern Rings g_rings;
