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
#include <boost/dynamic_bitset.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <cassert>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "cachecleaner.hh"
#include "generic-cache-interface.hh"
#include "gettime.hh"
#include "lock.hh"

using namespace ::boost::multi_index;

template <typename K, typename V, typename Hash = std::hash<K>>
class GenericCache : public GenericCacheInterface<K, V>, boost::noncopyable
{
private:
  struct CacheValue
  {
    K key;
    V value;
    time_t validity;
  };

public:
  struct CacheSettings
  {
    bool d_ttlEnabled;
    unsigned int d_ttl;
    bool d_lruEnabled;
    uint32_t d_shardCount{1};
    uint32_t d_maxEntries{0};
    uint32_t d_lruDeleteUpTo{0};
  };

  GenericCache(CacheSettings settings) :
    d_settings(settings), d_shards(settings.d_shardCount)
  {
    d_stats.d_memoryUsed = sizeof(*this) + d_shards.size() * sizeof(CacheShard);
  }
  virtual ~GenericCache() = default;

  void insert(const K& key, V value) override
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;

    if (d_settings.d_maxEntries > 0 && d_shards.at(shardIndex).d_entriesCount >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
      if (d_settings.d_ttlEnabled) {
        timespec now;
        gettime(&now);
        purgeExpired(0, now.tv_sec);
      }
      if (d_settings.d_lruEnabled) {
        expunge(d_settings.d_lruDeleteUpTo == 0 ? d_settings.d_maxEntries - 1 : d_settings.d_lruDeleteUpTo);
      }

      if (d_shards.at(shardIndex).d_entriesCount >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
        return;
      }
    }

    time_t validity;
    if (d_settings.d_ttlEnabled) {
      timespec now;
      gettime(&now);
      validity = now.tv_sec + d_settings.d_ttl;
    }
    else {
      validity = time_t();
    }
    CacheValue cacheValue{
      .key = key,
      .value = value,
      .validity = validity};

    auto& shard = d_shards.at(shardIndex);

    auto map = shard.d_map.write_lock();

    // check again now that we hold the lock to prevent a race
    if (d_settings.d_maxEntries > 0 && map->size() >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
      return;
    }

    auto result = map->insert(cacheValue);

    if (!result.second) {
      // This key already exists - replace it
      if (map->replace(result.first, cacheValue)) {
        d_stats.d_memoryUsed += sizeof(cacheValue) - sizeof(result.first);
      }
    }
    else {
      ++d_stats.d_entriesCount;
      ++shard.d_entriesCount;
      d_stats.d_memoryUsed += sizeof(cacheValue);
    }
  }

  void insertKey(const K& key) override
  {
    if constexpr (std::is_default_constructible<V>()) {
      insert(key, V());
    }
    else {
      throw new std::runtime_error("Unsupported insertKey operation.");
    }
  }

  bool getValue(const K& key, V& value) override
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;
    auto result = false;
    auto& shard = d_shards.at(shardIndex);
    {
      auto map = shard.d_map.read_lock();

      auto mapIt = map->find(key);
      if (mapIt == map->end()) {
        d_stats.d_cacheMisses += 1;
        return false;
      }

      if (d_settings.d_ttlEnabled) {
        timespec now;
        gettime(&now);
        if (mapIt->validity > now.tv_sec) {
          value = mapIt->value;
          result = true;
        }
      }
      else {
        value = mapIt->value;
        result = true;
      }
    }

    if (result) {
      d_stats.d_cacheHits += 1;
    }
    else {
      d_stats.d_cacheMisses += 1;
    }

    if (d_settings.d_lruEnabled || (!result && d_settings.d_ttlEnabled)) {
      auto map = shard.d_map.write_lock();
      auto mapIt = map->find(key);
      if (mapIt == map->end()) {
        return result;
      }
      if (d_settings.d_lruEnabled) {
        moveCacheItemToBack<SequencedTag>(*map, mapIt);
      }
      if (!result && d_settings.d_ttlEnabled) {
        shard.d_entriesCount -= 1;
        d_stats.d_entriesCount -= 1;
        d_stats.d_expiredItems += 1;
        d_stats.d_memoryUsed -= sizeof(*mapIt);
        map->erase(mapIt);
      }
    }

    return result;
  }

  bool contains(const K& key) override
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;
    auto result = false;
    auto& shard = d_shards.at(shardIndex);
    {
      auto map = shard.d_map.read_lock();

      auto mapIt = map->find(key);

      if (mapIt == map->end()) {
        d_stats.d_cacheMisses += 1;
        return false;
      }

      if (d_settings.d_ttlEnabled) {
        timespec now;
        gettime(&now);
        if (mapIt->validity > now.tv_sec) {
          result = true;
        }
      }
      else {
        result = true;
      }
    }

    if (result) {
      d_stats.d_cacheHits += 1;
    }
    else {
      d_stats.d_cacheMisses += 1;
    }

    if (d_settings.d_lruEnabled || (!result && d_settings.d_ttlEnabled)) {
      auto map = shard.d_map.write_lock();
      auto mapIt = map->find(key);
      if (mapIt == map->end()) {
        return result;
      }
      if (d_settings.d_lruEnabled) {
        moveCacheItemToBack<SequencedTag>(*map, mapIt);
      }
      if (!result && d_settings.d_ttlEnabled) {
        shard.d_entriesCount -= 1;
        d_stats.d_entriesCount -= 1;
        d_stats.d_expiredItems += 1;
        d_stats.d_memoryUsed -= sizeof(*mapIt);
        map->erase(mapIt);
      }
    }

    return result;
  }

  bool remove(const K& key) override
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;
    auto& shard = d_shards.at(shardIndex);
    auto map = shard.d_map.write_lock();

    auto mapIt = map->find(key);
    if (mapIt == map->end()) {
      return false;
    }

    shard.d_entriesCount -= 1;
    d_stats.d_entriesCount -= 1;
    d_stats.d_memoryUsed -= sizeof(*mapIt);
    map->erase(mapIt);
    return true;
  }

  size_t purgeExpired(size_t upTo, const time_t now) override
  {
    if (d_settings.d_ttlEnabled) {
      const size_t maxPerShard = upTo / d_settings.d_shardCount;

      size_t removed = 0;
      for (auto& shard : d_shards) {
        auto map = shard.d_map.write_lock();
        if (map->size() <= maxPerShard) {
          continue;
        }

        size_t toRemove = map->size() - maxPerShard;

        for (auto it = map->begin(); toRemove > 0 && it != map->end();) {
          if (it->validity <= now) {
            d_stats.d_memoryUsed -= sizeof(*it);
            it = map->erase(it);
            --toRemove;
            --shard.d_entriesCount;
            ++removed;
          }
          else {
            ++it;
          }
        }
      }

      d_stats.d_entriesCount -= removed;
      d_stats.d_expiredItems += removed;

      return removed;
    }
    else {
      return expunge(upTo);
    }
  }

  size_t expunge(size_t upTo = 0) override
  {
    const size_t maxPerShard = upTo / d_settings.d_shardCount;

    size_t removed = 0;

    for (auto& shard : d_shards) {
      auto map = shard.d_map.write_lock();

      if (map->size() <= maxPerShard) {
        continue;
      }

      size_t toRemove = map->size() - maxPerShard;

      if (map->size() >= toRemove) {
        auto& sequence = map->template get<SequencedTag>();
        auto beginIt = sequence.begin();
        auto endIt = beginIt;

        std::advance(endIt, toRemove);
        sequence.erase(beginIt, endIt);
        shard.d_entriesCount -= toRemove;
        for (auto it = beginIt; it != endIt; ++it) {
          d_stats.d_memoryUsed -= sizeof(*it);
        }
        removed += toRemove;
      }
      else {
        removed += map->size();
        map->clear();
        shard.d_entriesCount = 0;
      }
    }

    d_stats.d_entriesCount -= removed;
    d_stats.d_kickedItems += removed;

    return removed;
  }

  [[nodiscard]] virtual const typename GenericCacheInterface<K, V>::Stats& getStats() const override
  {
    return d_stats;
  }

private:
  struct HashedTag
  {
  };
  struct SequencedTag
  {
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

    using cache_t = multi_index_container<
      CacheValue,
      indexed_by<
        hashed_unique<tag<HashedTag>, member<CacheValue, K, &CacheValue::key>, Hash>,
        sequenced<tag<SequencedTag>>>>;

    SharedLockGuarded<cache_t> d_map;
    std::atomic<uint64_t> d_entriesCount{0};
  };

  CacheSettings d_settings;
  std::vector<CacheShard> d_shards;
  typename GenericCacheInterface<K, V>::Stats d_stats{"filter=\"none\""};
};
