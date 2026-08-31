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
#include <optional>
#include <functional>
#include <list>
#include <stdexcept>
#include <cstdint>
#include <iterator>

enum class CacheInsertState : uint8_t
{
  Inserted,
  Replaced,
  Full,
  Existing,
};

template <typename V>
class CacheContainer
{
public:
  // container should have only one implemented
  virtual std::optional<std::reference_wrapper<const V>> find(uint32_t key) const = 0;
  virtual std::optional<std::reference_wrapper<const V>> find(uint32_t key) = 0;

  // note - after successful insertion, V is moved out
  virtual std::pair<CacheInsertState, std::optional<std::reference_wrapper<V>>> insert(uint32_t key, V& value) = 0;
  virtual size_t remove(const std::function<bool(const V&)>& pred, size_t toRemove) = 0;
  virtual void visit(uint32_t key) = 0;

  virtual size_t size() const = 0;
  virtual void walk(const std::function<void(uint32_t, const V&)>& fun) const = 0;

  virtual ~CacheContainer() = default;
};

template <typename V>
class SieveCache : public CacheContainer<V>
{
public:
  SieveCache(size_t t)
  {
    if (t == 0) {
      throw std::logic_error("try to create 0-sized SieveCache");
    }
    // we reserve maxEntries + 1 to avoid rehashing from occurring
    // when we get to maxEntries, as it means a load factor of 1
    d_maxSize = t;
    d_map.reserve(t + 1);
    d_sieveHand = d_list.end();
  };

  std::optional<std::reference_wrapper<const V>> find(uint32_t key) const override
  {
    auto mapIt = d_map.find(key);
    if (mapIt == d_map.end()) {
      return std::nullopt;
    }

    mapIt->second->d_eraseable.clear(std::memory_order_relaxed);
    return mapIt->second->d_value;
  };

  [[noreturn]] std::optional<std::reference_wrapper<const V>> find(uint32_t) override
  {
    throw std::logic_error("SieveCache does not need lock on reading");
  };

  std::pair<CacheInsertState, std::optional<std::reference_wrapper<V>>> insert(uint32_t key, V& value) override
  {
    auto mapIt = d_map.find(key);
    if (mapIt != d_map.end()) {
      return {CacheInsertState::Existing, mapIt->second->d_value};
    }

    auto state = CacheInsertState::Inserted;

    if (d_map.size() == d_maxSize) {
      state = CacheInsertState::Replaced;

      while (!d_sieveHand->d_eraseable.test_and_set(std::memory_order_relaxed)) {
        d_sieveHand++;
        if (d_sieveHand == d_list.end()) {
          d_sieveHand = d_list.begin();
        }
      }

      d_map.erase(d_sieveHand->d_key);
      d_sieveHand = d_list.erase(d_sieveHand);
      if (d_sieveHand == d_list.end()) {
        d_sieveHand = d_list.begin();
      }
    }

    d_list.emplace_back(key, std::move(value));
    d_map.insert({key, std::prev(d_list.end())});

    if (d_sieveHand == d_list.end()) {
      d_sieveHand = d_list.begin();
    }
    return {state, std::nullopt};
  }

  size_t size() const override
  {
    return d_map.size();
  }

  void walk(const std::function<void(uint32_t, const V&)>& fun) const override
  {
    for (auto it = d_list.begin(); it != d_list.end(); ++it) {
      fun(it->d_key, it->d_value);
    }
  }

  size_t remove(const std::function<bool(const V&)>& pred, size_t toRemove) override
  {
    size_t removed = 0;

    if (toRemove == d_map.size()) {
      // faster case, that doesn't check visited and just removes
      for (auto it = d_list.begin(); it != d_list.end();) {
        if (pred(it->d_value)) {
          bool moveSieve = (d_sieveHand == it);
          ++removed;
          d_map.erase(it->d_key);
          it = d_list.erase(it);
          if (moveSieve) {
            d_sieveHand = it;
            if (d_sieveHand == d_list.end()) {
              d_sieveHand = d_list.begin();
            }
          }
          if (removed >= toRemove) {
            return removed;
          }
        }
        else {
          ++it;
        }
      }
      return removed;
    }

    // we prefer to remove unvisited things right to the sieve hand; and visit them first.
    // however, we should not move the sieve hand itself.

    size_t walked = 0;
    size_t origsize = d_map.size();

    auto expungeHand = d_sieveHand;
    while (d_map.size() > 0 && removed != toRemove && walked != origsize) {
      bool rem = pred(expungeHand->d_value);
      bool moveSieve = false;
      if (!rem) {
        ++expungeHand;
        ++walked;
      }
      else {
        if (!expungeHand->d_eraseable.test_and_set(std::memory_order_relaxed)) {
          ++expungeHand;
        }
        else {
          moveSieve = (d_sieveHand == expungeHand);
          d_map.erase(expungeHand->d_key);
          expungeHand = d_list.erase(expungeHand);
          ++removed;
          ++walked;
        }
      }
      if (expungeHand == d_list.end()) {
        expungeHand = d_list.begin();
      }
      if (moveSieve) {
        d_sieveHand = expungeHand;
      }
    }
    return removed;
  };

  void visit(uint32_t key) override
  {
    auto mapIt = d_map.find(key);
    if (mapIt == d_map.end()) {
      // should not happen?
      return;
    }
    mapIt->second->d_eraseable.clear(std::memory_order_relaxed);
  };

private:
  size_t d_maxSize;

  struct SieveNode
  {
    uint32_t d_key;
    V d_value;
    // inversion of visited in sieve
    std::atomic_flag d_eraseable;

    SieveNode(uint32_t key, V value) :
      d_key(key), d_value(std::move(value))
    {
      d_eraseable.test_and_set(std::memory_order_relaxed);
    }
  };

  using sieve_list = std::list<SieveNode>;
  using sieve_iter = typename sieve_list::iterator;

  // front: oldest; back: newest; bool - visited (starts at false)
  sieve_list d_list;
  std::unordered_map<uint32_t, sieve_iter> d_map;

  // if std::list is empty - std::list::end; otherwise - always pointing at list item, never at end()
  // hand moves from front to back
  sieve_iter d_sieveHand;
};

template <typename V>
class LruCache : public CacheContainer<V>
{
public:
  LruCache(size_t t)
  {
    if (t == 0) {
      throw std::logic_error("try to create 0-sized LruCache");
    }
    // we reserve maxEntries + 1 to avoid rehashing from occurring
    // when we get to maxEntries, as it means a load factor of 1
    d_maxSize = t;
    d_map.reserve(t + 1);
  };

  [[noreturn]] std::optional<std::reference_wrapper<const V>> find(uint32_t) const override
  {
    throw std::logic_error("LruCache needs lock on reading");
  };

  std::optional<std::reference_wrapper<const V>> find(uint32_t key) override
  {
    auto mapIt = d_map.find(key);
    if (mapIt == d_map.end()) {
      return std::nullopt;
    }

    d_list.splice(d_list.end(), d_list, mapIt->second);
    return mapIt->second->second;
  };

  std::pair<CacheInsertState, std::optional<std::reference_wrapper<V>>> insert(uint32_t key, V& value) override
  {
    auto mapIt = d_map.find(key);
    if (mapIt != d_map.end()) {
      return {CacheInsertState::Existing, mapIt->second->second};
    }

    auto state = CacheInsertState::Inserted;

    if (d_map.size() == d_maxSize) {
      state = CacheInsertState::Replaced;
      auto& newest = d_list.front();
      d_map.erase(newest.first);
      d_list.pop_front();
    }

    d_list.emplace_back(key, std::move(value));
    d_map.insert({key, std::prev(d_list.end())});
    return {state, std::nullopt};
  }

  size_t size() const override
  {
    return d_map.size();
  }

  void walk(const std::function<void(uint32_t, const V&)>& fun) const override
  {
    for (auto it = d_list.begin(); it != d_list.end(); ++it) {
      fun(it->first, it->second);
    }
  }

  size_t remove(const std::function<bool(const V&)>& pred, size_t toRemove) override
  {
    size_t removed = 0;
    for (auto it = d_list.begin(); it != d_list.end();) {
      if (pred(it->second)) {
        ++removed;
        d_map.erase(it->first);
        it = d_list.erase(it);
        if (removed >= toRemove) {
          return removed;
        }
      }
      else {
        ++it;
      }
    }
    return removed;
  };

  void visit(uint32_t key) override
  {
    auto mapIt = d_map.find(key);
    if (mapIt == d_map.end()) {
      // should not happen?
      return;
    }
    d_list.splice(d_list.end(), d_list, mapIt->second);
  };

private:
  size_t d_maxSize;

  // front: oldest; back: newest
  std::list<std::pair<uint32_t, V>> d_list;
  std::unordered_map<uint32_t, typename std::list<std::pair<uint32_t, V>>::iterator> d_map;
};

template <typename V>
class NoEvictionCache : public CacheContainer<V>
{
public:
  NoEvictionCache(size_t t)
  {
    if (t == 0) {
      throw std::logic_error("try to create 0-sized NoEvictionCache");
    }
    // we reserve maxEntries + 1 to avoid rehashing from occurring
    // when we get to maxEntries, as it means a load factor of 1
    d_maxSize = t;
    d_map.reserve(t + 1);
  };

  std::optional<std::reference_wrapper<const V>> find(uint32_t key) const override
  {
    auto it = d_map.find(key);
    if (it == d_map.end()) {
      return std::nullopt;
    }
    return it->second;
  };

  [[noreturn]] std::optional<std::reference_wrapper<const V>> find(uint32_t) override
  {
    throw std::logic_error("NoEvictionCache does not lock on reading");
  };

  std::pair<CacheInsertState, std::optional<std::reference_wrapper<V>>> insert(uint32_t key, V& value) override
  {
    if (d_map.size() == d_maxSize) {
      return {CacheInsertState::Full, std::nullopt};
    }

    // value is moved only if emplacing worked
    auto [it, result] = d_map.try_emplace(key, std::move(value));
    if (result) {
      return {CacheInsertState::Inserted, std::nullopt};
    }

    return {CacheInsertState::Existing, it->second};
  };

  size_t size() const override
  {
    return d_map.size();
  }

  void walk(const std::function<void(uint32_t, const V&)>& fun) const override
  {
    for (auto it = d_map.begin(); it != d_map.end(); ++it) {
      fun(it->first, it->second);
    }
  }

  size_t remove(const std::function<bool(const V&)>& pred, size_t toRemove) override
  {
    size_t removed = 0;
    for (auto it = d_map.begin(); it != d_map.end();) {
      if (pred(it->second)) {
        ++removed;
        it = d_map.erase(it);
        if (removed >= toRemove) {
          return removed;
        }
      }
      else {
        ++it;
      }
    }
    return removed;
  };

  void visit(uint32_t) override {
    // noop
  };

private:
  size_t d_maxSize;
  std::unordered_map<uint32_t, V> d_map;
};
