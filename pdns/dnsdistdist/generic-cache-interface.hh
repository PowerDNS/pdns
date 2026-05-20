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
#include <string>

class GenericExpiringCacheInterface
{
public:
  virtual ~GenericExpiringCacheInterface() {};
  virtual size_t purgeExpired(size_t upTo, time_t now) = 0;
  virtual size_t expunge(size_t upTo = 0) = 0;
};

template <typename K>
class GenericFilterInterface : public GenericExpiringCacheInterface
{
public:
  virtual ~GenericFilterInterface() {};
  virtual void insertKey(const K& key) = 0;
  virtual bool contains(const K& key) = 0;
  virtual bool remove(const K& key) = 0;
};

template <typename K, typename V>
class GenericCacheInterface : public GenericFilterInterface<K>
{
protected:
  struct Stats
  {
    Stats() {}
    explicit Stats(std::string labels) :
      d_labels(labels) {}

    pdns::stat_t d_memoryUsed{0};
    pdns::stat_t d_cacheHits{0};
    pdns::stat_t d_cacheMisses{0};
    pdns::stat_t d_entriesCount{0};
    pdns::stat_t d_kickedItems{0};
    pdns::stat_t d_expiredItems{0};
    std::string d_labels{};

    Stats& operator+=(const Stats& rhs)
    {
      d_memoryUsed += rhs.d_memoryUsed;
      d_cacheHits += d_cacheHits;
      d_cacheMisses += d_cacheMisses;
      d_entriesCount += d_entriesCount;
      d_kickedItems += d_kickedItems;
      d_expiredItems += d_expiredItems;
      return *this;
    }
  };

public:
  virtual ~GenericCacheInterface() {};
  virtual void insert(const K& key, V value) = 0;
  virtual bool getValue(const K& key, V& value) = 0;
  [[nodiscard]] virtual const Stats& getStats() const = 0;
};
