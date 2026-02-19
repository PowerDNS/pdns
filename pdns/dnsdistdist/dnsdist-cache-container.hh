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
#include <stdexcept>
#include <cstdint>
#include <iterator>
#include "gettime.hh"

#include <boost/intrusive/list.hpp>

// DNSDistPacketCacheContainer is a cache container that implements low-level
// cache logic of dnsdist. It is responsible for expiry and eviction.
//
// It uses combination of SIEVE algorithm to track evictions,
// and hierarchical timer wheel to track expiries.
// Internally, it holds values in a map, while SIEVE and timer wheel slots are
// intrusive linked lists.
//
// DNSDistPacketCacheContainer is generic, but it needs to get expiries on insert in
// monotonic clock.
//
// The timer wheel code was partially derived from Linux kernel code
// kernel/time/timer.c
// commit 9b87fdc9af2fbfcdb5c24a64139685ef80f6573f
// Copyright (C) 1991, 1992 Linus Torvalds
// Copyright (C) 1998 Andrea Arcangeli
// Copyright (C) 2000, 2001, 2002 Ingo Molnar
//
// SIEVE was based on original SIEVE paper
// https://junchengyang.com/publication/nsdi24-SIEVE.pdf
// Yazhuo Zhang, Juncheng Yang, Yao Yue, Ymir Vigfusson, K. V. Rashmi

template <typename V>
class DNSDistPacketCacheContainer : boost::noncopyable
{
public:
  enum class InsertState : uint8_t
  {
    Inserted,
    Replaced,
    Existing,
  }; // we can never return "Full" on insert; that is guarded by the cache above

  DNSDistPacketCacheContainer(const DNSDistPacketCacheContainer&) = delete;
  DNSDistPacketCacheContainer(DNSDistPacketCacheContainer&&) = delete;
  DNSDistPacketCacheContainer& operator=(const DNSDistPacketCacheContainer&) = delete;
  DNSDistPacketCacheContainer& operator=(DNSDistPacketCacheContainer&&) = delete;

private:
  // three constants that give us the size of the wheel
  //
  // wheel_bits is how big is each level
  // wheel_clockShift is how much we shift each level
  // wheel_depth is number of levels
  //
  // considerations:
  // * wheel_bits+(wheel_depth-1)*wheel_clockShift must be >= than 32
  // * each container will get fixed-size array with wheel_depth*2^{wheel_bits} pointers
  // * smaller wheel_clockShift gives us smaller bursts/lower latency spikes
  //
  // current constants are copied from kernel, but interpreted as seconds, not ms
  // however we have one more level (s_timerwheel_depth is 10)
  //
  // level 0 - granularity 2^0
  // used for delta 0 .. (2^wheel_bits)-1 = 63
  // 0     | 1     | 2 | .. | (2^wheel_bits)-1 = 63
  //
  // level 1 - granularity 2^(wheel_clockShift) = 8s
  // used for delta 2^wheel_bits=64..2^(wheel_bits+wheel_clockShift)-1=511
  // 0..7  | 8..15 | .. | 63*8 = 504 .. 64*8-1 = 511
  //
  // level 2 - granularity 2^(wheel_clockShift*2) = 64s
  // used for delta 2^(wheel_bits+wheel_clockShift)=512..2^(wheel_bits+2*wheel_clockShift)-1=4095s
  // 0..63 | 64..127 | ... |... 64*64-1 = 4095s
  // ...
  // level 9 - granularity 2^(wheel_clockShift*9) = 2^27
  // used for delta 2^(wheel_bits+8*wheel_clockShift)=64..2^(wheel_bits+9*wheel_clockShift)-1
  // == 2^(30)..2^(33)-1
  // we need this to support all possible 32 bits of DNS TTL
  // (it's very unlikely we will run for 100+ years, but, it doesn't cost us much here and we
  // get to support all possible values)
  //
  // overall:
  // Level Offset      Granularity           Range (of deltas)
  //  0       0            1 s                  0 s -         63 s
  //  1      64            8 s                 64 s -        511 s (~1m - ~9m)
  //  2     128           64 s (~1m)          512 s -       4095 s (~9m - ~1h)
  //  3     192          512 s (~9m)         4096 s -      32767 s (~1h - ~9h)
  //  4     256         4096 s (~1h)        32768 s -     262143 s (~9h - ~3d)
  //  5     320        32768 s (~9h)       262144 s -    2097151 s (~3d - ~24d)
  //  6     384       262144 s (~3d)      2097152 s -   16777215 s (~24d - ~194d)
  //  7     448      2097152 s (~24d)    16777216 s -  134217727 s (~194d - ~4y)
  //  8     512     16777216 s (~194d)  134217728 s - 1073741823 s (~4y - ~34y)
  //  9     576    134217728 s (~4y)   1073741824 s - 4294967295 s (~34y - ~136y)

  // how big is each level (bits)
  static constexpr unsigned int s_timerwheel_bits = 6;
  // how much we shift each level
  static constexpr unsigned int s_timerwheel_clockShift = 3;
  // number of levels
  static constexpr unsigned int s_timerwheel_depth = 10;

  // how much we shift for level N
  static constexpr unsigned int s_timerwheel_clockShiftForLevel(unsigned int lvl)
  {
    return lvl * s_timerwheel_clockShift;
  }

  // what is granularity for level N
  static constexpr time_t s_timerwheel_granularityForLevel(unsigned int lvl)
  {
    return time_t{1} << s_timerwheel_clockShiftForLevel(lvl);
  }

  // the min delta for level N
  static constexpr time_t s_timerwheel_minDeltaForLevel(unsigned int lvl)
  {
    return (s_timerwheel_arrayLenLevel) << ((lvl - 1) * s_timerwheel_clockShift);
  }

  // how big is each level (indexes of the fixed array)
  static constexpr size_t s_timerwheel_arrayLenLevel = size_t{1} << s_timerwheel_bits;
  static constexpr size_t s_timerwheel_arrayIndexForLevel(unsigned int n)
  {
    return n * s_timerwheel_arrayLenLevel;
  }

  // wheels should handle all TTLs
  // s_timerwheel_minDeltaForLevel(s_timerwheel_depth) is one bigger than biggest level
  static_assert(s_timerwheel_minDeltaForLevel(s_timerwheel_depth) > std::numeric_limits<uint32_t>::max());

  static constexpr size_t s_timerwheel_arrayIndexForExpiryOnLevel(time_t expires, unsigned int lvl)
  {
    auto granTime = (expires / s_timerwheel_granularityForLevel(lvl));
    size_t indexOnLevel = granTime % s_timerwheel_arrayLenLevel;
    return s_timerwheel_arrayIndexForLevel(lvl) + indexOnLevel;
  }

  static constexpr unsigned int s_levelForDelta(time_t delta)
  {
    // kernel has this loop unrolled for speed, we are fine like this?
    for (unsigned int lvl = 1; lvl < s_timerwheel_depth; lvl++) {
      if (delta < s_timerwheel_minDeltaForLevel(lvl)) {
        return lvl - 1;
      }
    }
    return s_timerwheel_depth - 1;
  }

  // note that timerwheel_arrayIndexForExpiry is not static, because
  // it depends on delta, which depends on current wheel clock state
  size_t timerwheel_arrayIndexForExpiry(time_t expires)
  {
    // this can be happen if something arrives with TTL=0
    if (expires < d_timerwheel_lastProcessed) {
      expires = d_timerwheel_lastProcessed;
    }

    time_t delta = expires - d_timerwheel_lastProcessed;
    return s_timerwheel_arrayIndexForExpiryOnLevel(expires, s_levelForDelta(delta));
  }

  using IntrusiveListHook = boost::intrusive::list_member_hook<
    boost::intrusive::link_mode<boost::intrusive::auto_unlink>>;

  struct Node
  {
  public:
    uint32_t d_key;

  private:
    // d_sieve_visited is changed in const sieve_visit(), so mutable
    mutable std::atomic<bool> d_sieve_visited{false};

  public:
    V d_value;
    time_t d_timerwheel_expiry;

    // the atomic loads/writes all use relaxed order
    // because the SharedLock in cache will force ordering.
    // counterintutively - inside shared read lock, caches set bool to true;
    // in single write lock, they later read it.
    // that's also why it's mutable - the const correctness is reversed.
    // std::atomic<bool> is used so we don't have UB from multiple
    // concurrent writes.

    bool sieve_unvisit() const
    {
      // we don't need atomic exchange; we are under a unique lock
      bool prev = d_sieve_visited.load(std::memory_order_relaxed);
      if (prev) {
        d_sieve_visited.store(false, std::memory_order_relaxed);
      }
      return prev;
    }

    void sieve_visit() const
    {
      // this load is here to not do unnecessary atomic write;
      // it's not necessary for correctness.
      // That's why it's separate load+store, not more expensive exchange.
      if (!d_sieve_visited.load(std::memory_order_relaxed)) {
        d_sieve_visited.store(true, std::memory_order_relaxed);
      }
    }

    Node(uint32_t key, time_t timerwheel_expiry, V value) :
      d_key(key), d_value(std::move(value)), d_timerwheel_expiry(timerwheel_expiry) {}

    // it's too annoying making these private
    IntrusiveListHook d_sieve_hook;
    IntrusiveListHook d_timerwheel_hook;
  };

  template <IntrusiveListHook Node::* member>
  using IntrusiveList = boost::intrusive::list<
    Node,
    boost::intrusive::member_hook<Node, IntrusiveListHook, member>,
    boost::intrusive::constant_time_size<false>>;

  using SieveList = IntrusiveList<&Node::d_sieve_hook>;
  using TimerWheelList = IntrusiveList<&Node::d_timerwheel_hook>;
  using SieveIterator = typename SieveList::iterator;

  std::array<TimerWheelList, s_timerwheel_arrayLenLevel * s_timerwheel_depth> d_timerwheel_lists;

  // front: oldest; back: newest; bool - sieve_visited (starts at false)
  SieveList d_sieve_list;

  // if SieveList is empty - SieveList::end(); otherwise -
  // always pointing at list item, never at end()
  // hand moves from front to back
  SieveIterator d_sieve_hand{d_sieve_list.end()};

  time_t d_timerwheel_lastProcessed{0};

  size_t d_maxSize{0};

  std::unordered_map<uint32_t, Node> d_map;

public:
  DNSDistPacketCacheContainer()
  {
    // we need a valid empty constructor for cache's SharedLockGuarded
  }

  void init(size_t t, time_t now)
  {
    // we reserve maxEntries + 1 to avoid rehashing from occurring
    // when we get to maxEntries, as it means a load factor of 1
    d_maxSize = t;
    d_map.reserve(t + 1);

    d_timerwheel_lastProcessed = now;
  };

  std::optional<std::reference_wrapper<const V>> find(uint32_t key) const
  {
    auto mapIt = d_map.find(key);
    if (mapIt == d_map.end()) {
      return std::nullopt;
    }

    mapIt->second.sieve_visit();
    return mapIt->second.d_value;
  };

  std::pair<InsertState, std::optional<std::reference_wrapper<V>>> insert(uint32_t key, time_t expires, V& value)
  {
    auto mapIt = d_map.find(key);
    if (mapIt != d_map.end()) {
      return {InsertState::Existing, mapIt->second.d_value};
    }

    auto state = InsertState::Inserted;

    if (d_map.size() == d_maxSize) {
      // we never get here if d_dontevict is set in the main cache object
      state = InsertState::Replaced;

      evict();
    }

    assert(d_map.size() < d_maxSize);

    auto wheel_index = timerwheel_arrayIndexForExpiry(expires);

    // we don't need to use try_emplace here, but it has a nicer syntax
    auto [it, inserted] = d_map.try_emplace(key, key, expires, std::move(value));
    assert(inserted);
    d_sieve_list.push_back(it->second);
    d_timerwheel_lists[wheel_index].push_back(it->second);

    // this needs to exist for the case when we were empty; that means
    // we started at end()
    if (d_sieve_hand == d_sieve_list.end()) {
      d_sieve_hand = d_sieve_list.begin();
    }
    return {state, std::nullopt};
  }

  size_t size() const
  {
    return d_map.size();
  }

  void walk(const std::function<void(uint32_t, const V&)>& fun) const
  {
    for (auto it = d_map.begin(); it != d_map.end(); ++it) {
      fun(it->first, it->second.d_value);
    }
  }

  size_t purgeExpired(size_t maxRemove, time_t now)
  {
    size_t removed = 0;

    for (; d_timerwheel_lastProcessed <= now; d_timerwheel_lastProcessed++) {
      // the loop is same for cascading and actual purges.
      // we only do the levels where we are dividing the granularity,
      // but level 0 always divides
      for (unsigned int lvl = 0; (lvl < s_timerwheel_depth) && (d_timerwheel_lastProcessed % s_timerwheel_granularityForLevel(lvl) == 0); lvl++) {
        auto index = s_timerwheel_arrayIndexForExpiryOnLevel(d_timerwheel_lastProcessed, lvl);
        auto& list = d_timerwheel_lists[index];

        while (!list.empty()) {
          auto& it = list.front();
          if (it.d_timerwheel_expiry <= d_timerwheel_lastProcessed) {
            // expired - delete from SIEVE too
            deleteNode(it);
            removed++;
            if (removed == maxRemove) {
              return removed;
            }
          }
          else {
            assert(lvl != 0);
            // relink in wheel list, don't touch SIEVE
            it.d_timerwheel_hook.unlink();
            auto newi = timerwheel_arrayIndexForExpiry(it.d_timerwheel_expiry);
            assert(newi != index);
            d_timerwheel_lists[newi].push_back(it);
          }
        }
      }
    }
    return removed;
  }

  size_t expunge(size_t maxRemove)
  {
    size_t removed = 0;

    while (d_map.size() != 0 && removed != maxRemove) {
      evict();
      removed++;
    }
    return removed;
  }

  size_t removeByPred(const std::function<bool(const V&)>& pred)
  {
    size_t removed = 0;

    for (auto it = d_map.begin(); it != d_map.end();) {
      bool rem = pred(it->second.d_value);
      if (!rem) {
        ++it;
      }
      else {
        auto next = it;
        next++;
        deleteNode(it->second);
        it = next;
        removed++;
      }
    }

    return removed;
  };

  void bump(uint32_t key, time_t expires)
  {
    auto mapIt = d_map.find(key);
    if (mapIt == d_map.end()) {
      // should not happen?
      return;
    }
    mapIt->second.sieve_visit();
    // we need to put to correct timer wheel
    mapIt->second.d_timerwheel_hook.unlink();
    auto wheel_index = timerwheel_arrayIndexForExpiry(expires);
    d_timerwheel_lists[wheel_index].push_back(mapIt->second);
    mapIt->second.d_timerwheel_expiry = expires;
  };

private:
  bool evict()
  {
    if (d_map.size() == 0) {
      return false;
    }

    assert(d_sieve_hand != d_sieve_list.end());

    while (d_sieve_hand->sieve_unvisit()) {
      d_sieve_hand++;
      if (d_sieve_hand == d_sieve_list.end()) {
        d_sieve_hand = d_sieve_list.begin();
      }
    }

    deleteNode(*d_sieve_hand);
    return true;
  }

  void deleteNode(Node& node)
  {
    auto key = node.d_key;

    auto it = SieveList::s_iterator_to(node);
    auto isHand = (it == d_sieve_hand);
    auto next = d_sieve_list.erase(it);
    if (isHand) {
      d_sieve_hand = next;
      if (d_sieve_hand == d_sieve_list.end()) {
        d_sieve_hand = d_sieve_list.begin();
      }
    }

    node.d_timerwheel_hook.unlink();

    d_map.erase(key);
  }
};
