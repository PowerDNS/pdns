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
  // Full, // FIXME(kb): add option to NOT evict?
  Existing,
};

template <typename V>
class SieveCache
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

  std::optional<std::reference_wrapper<const V>> find(uint32_t key) const
  {
    auto mapIt = d_map.find(key);
    if (mapIt == d_map.end()) {
      return std::nullopt;
    }

    mapIt->second->visit();
    return mapIt->second->d_value;
  };

  [[noreturn]] std::optional<std::reference_wrapper<const V>> find(uint32_t)
  {
    throw std::logic_error("SieveCache does not need lock on reading");
  };

  std::pair<CacheInsertState, std::optional<std::reference_wrapper<V>>> insert(uint32_t key, V& value)
  {
    auto mapIt = d_map.find(key);
    if (mapIt != d_map.end()) {
      return {CacheInsertState::Existing, mapIt->second->d_value};
    }

    auto state = CacheInsertState::Inserted;

    if (d_map.size() == d_maxSize) {
      state = CacheInsertState::Replaced;

      while (d_sieveHand->unvisit()) {
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

  size_t size() const
  {
    return d_map.size();
  }

  void walk(const std::function<void(uint32_t, const V&)>& fun) const
  {
    for (auto it = d_list.begin(); it != d_list.end(); ++it) {
      fun(it->d_key, it->d_value);
    }
  }

  size_t remove(const std::function<bool(const V&)>& pred, size_t toRemove)
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
        if (expungeHand->unvisit()) {
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

  void visit(uint32_t key)
  {
    auto mapIt = d_map.find(key);
    if (mapIt == d_map.end()) {
      // should not happen?
      return;
    }
    mapIt->second->visit();
  };

private:
  size_t d_maxSize;

  struct SieveNode
  {
  public:
    uint32_t d_key;
    V d_value;

    bool unvisit()
    {
      // unvisit returns previous visited state
      return d_visited.exchange(false, std::memory_order_relaxed);
    }

    void visit()
    {
      // this load is here to not do unnecessary atomic write;
      // it's not necessary for correctness.
      // That's why it's load+store, not exchange.
      if (!d_visited.load(std::memory_order_relaxed)) {
        d_visited.store(true, std::memory_order_relaxed);
      }
    }

    SieveNode(uint32_t key, V value) :
      d_key(key), d_value(std::move(value)) {}

  private:
    std::atomic<bool> d_visited{false};
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
