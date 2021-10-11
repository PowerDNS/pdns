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

struct Rings {
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
  };
  struct Response
  {
    ComboAddress requestor;
    ComboAddress ds; // who handled it
    DNSName name;
    struct timespec when;
    struct dnsheader dh;
    unsigned int usec;
    unsigned int size;
    uint16_t qtype;
    // outgoing protocol
    dnsdist::Protocol protocol;
  };

  struct Shard
  {
    LockGuarded<boost::circular_buffer<Query>> queryRing{boost::circular_buffer<Query>()};
    LockGuarded<boost::circular_buffer<Response>> respRing{boost::circular_buffer<Response>()};
  };

  Rings(size_t capacity=10000, size_t numberOfShards=10, size_t nbLockTries=5, bool keepLockingStats=false): d_blockingQueryInserts(0), d_blockingResponseInserts(0), d_deferredQueryInserts(0), d_deferredResponseInserts(0), d_nbQueryEntries(0), d_nbResponseEntries(0), d_currentShardId(0), d_numberOfShards(numberOfShards), d_nbLockTries(nbLockTries), d_keepLockingStats(keepLockingStats)
  {
    setCapacity(capacity, numberOfShards);
  }

  std::unordered_map<int, vector<boost::variant<string,double> > > getTopBandwidth(unsigned int numentries);
  size_t numDistinctRequestors();
  /* This function should only be called at configuration time before any query or response has been inserted */
  void setCapacity(size_t newCapacity, size_t numberOfShards)
  {
    if (numberOfShards <= 1) {
      d_nbLockTries = 0;
    }

    d_shards.resize(numberOfShards);
    d_numberOfShards = numberOfShards;

    /* resize all the rings */
    for (auto& shard : d_shards) {
      shard = std::unique_ptr<Shard>(new Shard());
      shard->queryRing.lock()->set_capacity(newCapacity / numberOfShards);
      shard->respRing.lock()->set_capacity(newCapacity / numberOfShards);
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

  void insertQuery(const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, uint16_t size, const struct dnsheader& dh, dnsdist::Protocol protocol)
  {
    for (size_t idx = 0; idx < d_nbLockTries; idx++) {
      auto& shard = getOneShard();
      auto lock = shard->queryRing.try_lock();
      if (lock.owns_lock()) {
        insertQueryLocked(*lock, when, requestor, name, qtype, size, dh, protocol);
        return;
      }
      if (d_keepLockingStats) {
        ++d_deferredQueryInserts;
      }
    }

    /* out of luck, let's just wait */
    if (d_keepLockingStats) {
      ++d_blockingResponseInserts;
    }
    auto& shard = getOneShard();
    auto lock = shard->queryRing.lock();
    insertQueryLocked(*lock, when, requestor, name, qtype, size, dh, protocol);
  }

  void insertResponse(const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, unsigned int usec, unsigned int size, const struct dnsheader& dh, const ComboAddress& backend, dnsdist::Protocol protocol)
  {
    for (size_t idx = 0; idx < d_nbLockTries; idx++) {
      auto& shard = getOneShard();
      auto lock = shard->respRing.try_lock();
      if (lock.owns_lock()) {
        insertResponseLocked(*lock, when, requestor, name, qtype, usec, size, dh, backend, protocol);
        return;
      }
      if (d_keepLockingStats) {
        ++d_deferredResponseInserts;
      }
    }

    /* out of luck, let's just wait */
    if (d_keepLockingStats) {
      ++d_blockingResponseInserts;
    }
    auto& shard = getOneShard();
    auto lock = shard->respRing.lock();
    insertResponseLocked(*lock, when, requestor, name, qtype, usec, size, dh, backend, protocol);
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

  /* load the content of the ring buffer from a file in the format emitted by grepq(),
     only useful for debugging purposes */
  size_t loadFromFile(const std::string& filepath, const struct timespec& now);

  std::vector<std::unique_ptr<Shard> > d_shards;
  pdns::stat_t d_blockingQueryInserts;
  pdns::stat_t d_blockingResponseInserts;
  pdns::stat_t d_deferredQueryInserts;
  pdns::stat_t d_deferredResponseInserts;

private:
  size_t getShardId()
  {
    return (d_currentShardId++ % d_numberOfShards);
  }

  std::unique_ptr<Shard>& getOneShard()
  {
    return d_shards[getShardId()];
  }

  void insertQueryLocked(boost::circular_buffer<Query>& ring, const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, uint16_t size, const struct dnsheader& dh, dnsdist::Protocol protocol)
  {
    if (!ring.full()) {
      d_nbQueryEntries++;
    }
    ring.push_back({requestor, name, when, dh, size, qtype, protocol});
  }

  void insertResponseLocked(boost::circular_buffer<Response>& ring, const struct timespec& when, const ComboAddress& requestor, const DNSName& name, uint16_t qtype, unsigned int usec, unsigned int size, const struct dnsheader& dh, const ComboAddress& backend, dnsdist::Protocol protocol)
  {
    if (!ring.full()) {
      d_nbResponseEntries++;
    }
    ring.push_back({requestor, backend, name, when, dh, usec, size, qtype, protocol});
  }

  std::atomic<size_t> d_nbQueryEntries;
  std::atomic<size_t> d_nbResponseEntries;
  std::atomic<size_t> d_currentShardId;

  size_t d_numberOfShards;
  size_t d_nbLockTries = 5;
  bool d_keepLockingStats{false};
};

extern Rings g_rings;
