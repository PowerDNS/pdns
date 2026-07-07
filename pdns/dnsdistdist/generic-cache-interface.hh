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

#include "stat_t.hh"
#include <cstddef>
#include <ctime>
#include <functional>
#include <string>
#include <utility>

class GenericExpiringCacheInterface
{
public:
  GenericExpiringCacheInterface() = default;
  virtual ~GenericExpiringCacheInterface() = default;
  virtual size_t purgeExpired(size_t upTo, time_t now) = 0;
  virtual size_t expunge(size_t upTo = 0) = 0;
  [[nodiscard]] virtual uint64_t getSize() const = 0;

  GenericExpiringCacheInterface(const GenericExpiringCacheInterface&) = default;
  GenericExpiringCacheInterface(GenericExpiringCacheInterface&&) = delete;
  GenericExpiringCacheInterface& operator=(const GenericExpiringCacheInterface&) = default;
  GenericExpiringCacheInterface& operator=(GenericExpiringCacheInterface&&) = delete;
};

template <typename K>
class GenericFilterInterface : public GenericExpiringCacheInterface
{
public:
  GenericFilterInterface() = default;
  ~GenericFilterInterface() override = default;
  virtual void insertKey(const K& key) = 0;
  virtual bool contains(const K& key, bool recordMiss = true) = 0;
  virtual bool remove(const K& key) = 0;

  GenericFilterInterface(const GenericFilterInterface&) = delete;
  GenericFilterInterface(GenericFilterInterface&&) = delete;
  GenericFilterInterface& operator=(const GenericFilterInterface&) = delete;
  GenericFilterInterface& operator=(GenericFilterInterface&&) = delete;
};

template <typename K, typename V>
class GenericCacheInterface : public GenericFilterInterface<K>
{
protected:
  struct Stats
  {
    Stats() = default;
    explicit Stats(std::string labels) :
      d_labels(std::move(labels)) { }

    pdns::stat_t d_memoryUsed{0};
    pdns::stat_t d_hits{0};
    pdns::stat_t d_misses{0};
    pdns::stat_t d_entriesCount{0};
    pdns::stat_t d_kickedItems{0};
    pdns::stat_t d_expiredItems{0};
    pdns::stat_t d_deferredLookups{0};
    pdns::stat_t d_deferredInserts{0};
    std::string d_labels;

    Stats& operator+=(const Stats& rhs)
    {
      d_memoryUsed += rhs.d_memoryUsed;
      d_hits += rhs.d_hits;
      d_misses += rhs.d_misses;
      d_entriesCount += rhs.d_entriesCount;
      d_kickedItems += rhs.d_kickedItems;
      d_expiredItems += rhs.d_expiredItems;
      d_deferredLookups += rhs.d_deferredLookups;
      d_deferredInserts += rhs.d_deferredInserts;
      return *this;
    }
  };

public:
  GenericCacheInterface() = default;
  virtual ~GenericCacheInterface() = default;
  virtual void insert(const K& key, V value) = 0;
  virtual bool getValue(const K& key, V& value, bool recordMiss = true) = 0;
  virtual bool hasCapacityFor(const K& key) = 0;
  [[nodiscard]] virtual const Stats& getStats() const = 0;
  virtual size_t expungeByCondition(const std::function<bool(const V&)>& condition, size_t upTo = 0) = 0;

  GenericCacheInterface(const GenericCacheInterface&) = delete;
  GenericCacheInterface(GenericCacheInterface&&) = delete;
  GenericCacheInterface& operator=(const GenericCacheInterface&) = delete;
  GenericCacheInterface& operator=(GenericCacheInterface&&) = delete;
};
