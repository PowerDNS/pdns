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
#include <functional>
#include <iterator>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "cachecleaner.hh"
#include "generic-cache-interface.hh"
#include "gettime.hh"
#include "lock.hh"

using namespace ::boost::multi_index;

template <typename K, typename V, typename Hash = std::hash<K>, time_t V::* Ttl = nullptr>
class GenericCache : public GenericCacheInterface<K, V>, boost::noncopyable
{
private:
  class CacheShard;
  struct HashedTag;
  struct SequencedTag;

public:
  struct CacheValue
  {
    K key;
    V value;
    time_t validity;
  };
  struct CacheSettings
  {
    bool d_ttlEnabled{false};
    unsigned int d_ttl{0};
    bool d_lruEnabled{false};
    uint32_t d_shardCount{1};
    size_t d_maxEntries{0};
    uint32_t d_lruDeleteUpTo{0};
    bool d_deferrableInsertLock{false};
  };

  struct Iterator
  {
    using iterator_category = std::forward_iterator_tag;
    using difference_type = std::ptrdiff_t;
    using value_type = CacheValue;
    using pointer = const CacheValue*;
    using reference = const CacheValue&;

    Iterator(std::vector<CacheShard>& shards, bool end = false) :
      d_shard_it(end ? shards.end() : shards.begin()), d_shard_it_end(shards.end()), d_map_lock(std::make_unique<SharedLockGuardedNonExclusiveHolder<typename CacheShard::cache_t>>(d_shard_it->d_map.read_lock())), d_map_it(std::make_unique<typename CacheShard::cache_t::iterator>((**d_map_lock).begin())), d_map_it_end(std::make_unique<typename CacheShard::cache_t::iterator>((**d_map_lock).end()))
    {
    }

    reference operator*() const { return **d_map_it; }
    pointer operator->() { return **d_map_it; }

    Iterator& operator++()
    {
      ++*d_map_it;
      if (*d_map_it == *d_map_it_end) {
        ++d_shard_it;
        if (d_shard_it != d_shard_it_end) {
          d_map_lock = std::make_unique<SharedLockGuardedNonExclusiveHolder<typename CacheShard::cache_t>>(d_shard_it->d_map.read_lock());
          d_map_it = std::make_unique<typename CacheShard::cache_t::iterator>((**d_map_lock).begin());
          d_map_it_end = std::make_unique<typename CacheShard::cache_t::iterator>((**d_map_lock).end());
        }
        else {
          d_map_lock.release();
          d_map_it.release();
          d_map_it_end.release();
        }
      }
      return *this;
    }

    Iterator operator++(int)
    {
      Iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    friend bool operator==(const Iterator& left, const Iterator& right)
    {
      return left.d_shard_it == right.d_shard_it && left.d_map_it == right.d_map_it;
    };
    friend bool operator!=(const Iterator& left, const Iterator& right)
    {
      return left.d_shard_it != right.d_shard_it || left.d_map_it != right.d_map_it;
    };

  private:
    typename std::vector<CacheShard>::iterator d_shard_it;
    typename std::vector<CacheShard>::iterator d_shard_it_end;
    std::unique_ptr<SharedLockGuardedNonExclusiveHolder<typename CacheShard::cache_t>> d_map_lock;
    std::unique_ptr<typename CacheShard::cache_t::iterator> d_map_it;
    std::unique_ptr<typename CacheShard::cache_t::iterator> d_map_it_end;
  };

  GenericCache(const GenericCache&) = delete;
  GenericCache(GenericCache&&) = delete;
  GenericCache& operator=(const GenericCache&) = delete;
  GenericCache& operator=(GenericCache&&) = delete;

  GenericCache(CacheSettings settings) :
    d_settings(std::move(settings))
  {
    if (d_settings.d_maxEntries == 0) {
      throw std::runtime_error("Trying to create a 0-sized cache");
    }
    if (d_settings.d_ttlEnabled && Ttl != nullptr) {
      throw std::runtime_error("TTL can't be enabled because validity is provided externally");
    }

    if (d_settings.d_shardCount == 0) {
      d_settings.d_shardCount = 1;
    }

    d_shards.resize(d_settings.d_shardCount);

    /* we reserve maxEntries + 1 to avoid rehashing from occurring
     when we get to maxEntries, as it means a load factor of 1 */
    for (auto& shard : d_shards) {
      shard.setSize((d_settings.d_maxEntries / d_settings.d_shardCount) + 1);
    }
    d_stats.d_memoryUsed = sizeof(*this) + d_shards.size() * sizeof(CacheShard);
  }
  virtual ~GenericCache() = default;

  void insert(const K& key, V value) override
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;

    if (d_shards.at(shardIndex).d_entriesCount >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
      if (d_settings.d_ttlEnabled) {
        timespec now{};
        gettime(&now);
        purgeExpired(0, now.tv_sec);
      }
      if (d_settings.d_lruEnabled) {
        expunge(d_settings.d_lruDeleteUpTo == 0 ? d_settings.d_maxEntries - 1 : d_settings.d_lruDeleteUpTo);
      }

      return;
    }

    time_t validity = 0;
    if (d_settings.d_ttlEnabled) {
      timespec now{};
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

    if (d_settings.d_deferrableInsertLock) {
      auto lock = shard.d_map.try_write_lock();

      if (!lock.owns_lock()) {
        ++d_stats.d_deferredInserts;
        return;
      }
      insertLocked(shard, *lock, cacheValue);
    }
    else {
      auto lock = shard.d_map.write_lock();

      insertLocked(shard, *lock, cacheValue);
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

  void insertLocked(CacheShard& shard, typename CacheShard::cache_t& map, const CacheValue& cacheValue)
  {
    // check again now that we hold the lock to prevent a race
    if (map.size() >= (d_settings.d_maxEntries / d_settings.d_shardCount)) {
      return;
    }

    auto result = map.insert(cacheValue);

    if (!result.second) {
      // This key already exists - replace it
      if (map.replace(result.first, cacheValue)) {
        d_stats.d_memoryUsed += sizeof(cacheValue) - sizeof(result.first);
      }
    }
    else {
      ++d_stats.d_entriesCount;
      ++shard.d_entriesCount;
      d_stats.d_memoryUsed += sizeof(cacheValue);
    }
  }

  bool getValue(const K& key, V& value, bool recordMiss) override
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;
    auto result = false;
    auto& shard = d_shards.at(shardIndex);
    {
      auto map = shard.d_map.try_read_lock();
      if (!map.owns_lock()) {
        ++d_stats.d_deferredLookups;
        return false;
      }

      auto mapIt = map->find(key);
      if (mapIt == map->end()) {
        if (recordMiss) {
          d_stats.d_misses += 1;
        }
        return false;
      }

      if (d_settings.d_ttlEnabled || Ttl != nullptr) {
        timespec now{};
        gettime(&now);
        if constexpr (Ttl == nullptr) {
          if (mapIt->validity > now.tv_sec) {
            value = mapIt->value;
            result = true;
          }
        }
        else {
          if (mapIt->value.*Ttl > now.tv_sec) {
            value = mapIt->value;
            result = true;
          }
        }
      }
      else {
        value = mapIt->value;
        result = true;
      }
    }

    if (result) {
      d_stats.d_hits += 1;
    }
    else {
      if (recordMiss) {
        d_stats.d_misses += 1;
      }
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

  bool hasCapacityFor(const K& key) override
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;

    return static_cast<bool>(d_shards.at(shardIndex).d_entriesCount < (d_settings.d_maxEntries / d_settings.d_shardCount));
  }

  bool contains(const K& key, bool recordMiss) override
  {
    size_t hash = Hash{}(key);
    size_t shardIndex = hash % d_settings.d_shardCount;
    auto result = false;
    auto& shard = d_shards.at(shardIndex);
    {
      auto map = shard.d_map.try_read_lock();
      if (!map.owns_lock()) {
        ++d_stats.d_deferredLookups;
        return false;
      }

      auto mapIt = map->find(key);

      if (mapIt == map->end()) {
        if (recordMiss) {
          d_stats.d_misses += 1;
        }
        return false;
      }

      if (d_settings.d_ttlEnabled || Ttl != nullptr) {
        timespec now{};
        gettime(&now);
        if constexpr (Ttl == nullptr) {
          if (mapIt->validity > now.tv_sec) {
            result = true;
          }
        }
        else {
          if (mapIt->value.*Ttl > now.tv_sec) {
            result = true;
          }
        }
      }
      else {
        result = true;
      }
    }

    if (result) {
      d_stats.d_hits += 1;
    }
    else {
      if (recordMiss) {
        d_stats.d_misses += 1;
      }
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
    if (d_settings.d_ttlEnabled || Ttl != nullptr) {
      const size_t maxPerShard = upTo / d_settings.d_shardCount;

      size_t removed = 0;
      for (auto& shard : d_shards) {
        auto map = shard.d_map.write_lock();
        if (map->size() <= maxPerShard) {
          continue;
        }

        size_t toRemove = map->size() - maxPerShard;

        for (auto it = map->begin(); toRemove > 0 && it != map->end();) {
          auto validity = it->validity;
          if constexpr (Ttl != nullptr) {
            validity = it->value.*Ttl;
          }
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

    return expunge(upTo);
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

  size_t expungeByCondition(const std::function<bool(const V&)>& condition, size_t upTo = 0) override
  {
    const size_t maxPerShard = upTo / d_settings.d_shardCount;

    size_t removed = 0;

    for (auto& shard : d_shards) {
      auto map = shard.d_map.write_lock();

      if (map->size() <= maxPerShard) {
        continue;
      }

      size_t toRemove = map->size() - maxPerShard;

      for (auto it = map->begin(); it != map->end();) {
        if (toRemove == 0) {
          break;
        }

        const V& value = it->value;

        if (condition(value)) {
          it = map->erase(it);
          --shard.d_entriesCount;
          ++removed;
          --toRemove;
          d_stats.d_memoryUsed -= sizeof(*it);
        }
        else {
          ++it;
        }
      }
    }

    d_stats.d_entriesCount -= removed;
    d_stats.d_kickedItems += removed;

    return removed;
  }

  [[nodiscard]] uint64_t getSize() const override
  {
    uint64_t count = 0;

    for (auto& shard : d_shards) {
      count += shard.d_entriesCount;
    }

    return count;
  }

  Iterator begin()
  {
    return Iterator(d_shards);
  }

  Iterator end()
  {
    return Iterator(d_shards, true);
  }

  [[nodiscard]] const typename GenericCacheInterface<K, V>::Stats& getStats() const override
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
    using cache_t = multi_index_container<
      CacheValue,
      indexed_by<
        hashed_unique<tag<HashedTag>, member<CacheValue, K, &CacheValue::key>, Hash>,
        sequenced<tag<SequencedTag>>>>;

    CacheShard() = default;
    CacheShard(CacheShard&& /* old */) noexcept
    {
    }
    CacheShard(const CacheShard& /* old */)
    {
    }
    CacheShard& operator=(CacheShard&& /* old */) noexcept
    {
      return *this;
    }
    CacheShard& operator=(const CacheShard& /* old */)
    {
      return *this;
    }
    ~CacheShard() = default;

    void setSize(size_t maxSize)
    {
      d_map.write_lock()->reserve(maxSize);
    }

    SharedLockGuarded<cache_t> d_map;
    std::atomic<uint64_t> d_entriesCount{0};
  };

  CacheSettings d_settings;
  std::vector<CacheShard> d_shards;
  typename GenericCacheInterface<K, V>::Stats d_stats{"filter=\"none\""};
};
