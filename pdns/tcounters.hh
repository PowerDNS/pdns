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

#include <sys/time.h>
#include <array>
#include <set>
#include <unistd.h>

#include "lock.hh"

namespace pdns
{
// We keep three sets of related counters:
//
// 1. The current counters (thread local, updated individually by thread code very often)
// 2. The snapshot counters (thread local, updated by thread code in one single mutex protected copy)
// 3. The history counters (global) to keep track of the counters of deleted threads

// We have two main classes: one that holds the thread local counters
// (both current and snapshot ones) and one that aggregates the
// values for all threads and keeps the history counters.

// The thread local current counters are the ones updated by
// performance critical code.  Every once in a while, all values in the
// current counters are copied to the snapshot thread local copies in
// a thread safe way.

// The snapshot counters are aggregated by the GlobalCounters
// class, as these can be accessed safely from multiple threads.

// Make sure to call the thread local tlocal.updatesAtomics() once
// in a while. This will fill the snapshot values for that thread if some
// time has passed since the last snap update.

// To fetch aggregate values, call globals.sum(counter1) or
// globals.avg(counter2), or any aggreggation function.  If multiple
// counters need to be collected in a consistent way:
// auto data = globals.aggregatedSnap();
//
// Note that the aggregate values can mix somewhat older thread-local
// with newer thread-local info from another thread. So it is possible
// to see the following:
//
// If thread T1 increments "received" and then passes the packet to
// thread T2 that increments "processed", it may happen that the value
// of "processed" observed by sum() is higher than "received", as T1
// might not have called updateSnap() yet while T2 did.  To avoid this
// inconsistency, be careful to update related counters in a single
// thread only.

// For an example of the use of these templates, see rec-tcounters.hh

template <typename Counters>
class TLocalCounters;

template <typename Counters>
class GlobalCounters
{
public:
  // Register a thread local set of values
  void subscribe(TLocalCounters<Counters>* ptr)
  {
    auto lock = d_guarded.lock();
    lock->d_instances.emplace(ptr);
  }

  // Unregister, typically done when a thread exits
  void unsubscribe(TLocalCounters<Counters>* ptr, const Counters& data)
  {
    auto lock = d_guarded.lock();
    lock->d_instances.erase(ptr);
    lock->d_history.merge(data);
  }

  // Two ways of computing aggregated values for a specific counter: simple additions of all thread data, or taking weighted averages into account
  template <typename Enum>
  auto sum(Enum index);
  template <typename Enum>
  auto avg(Enum index);
  template <typename Enum>
  auto max(Enum index);

  // Aggregate all counter data for all threads
  Counters aggregatedSnap();

  // Reset history
  void reset()
  {
    auto lock = d_guarded.lock();
    lock->d_history = Counters();
  }

private:
  struct Guarded
  {
    // We have x instances, normally one per thread
    std::set<TLocalCounters<Counters>*> d_instances;
    // If an instance gets deleted because its thread is cleaned up, the values
    // are accumulated in d_history
    Counters d_history;
  };
  LockGuarded<Guarded> d_guarded;
};

template <typename Counters>
class TLocalCounters
{
public:
  static constexpr suseconds_t defaultSnapUpdatePeriodus = 100000;
  TLocalCounters(GlobalCounters<Counters>& collector, timeval interval = timeval{0, defaultSnapUpdatePeriodus}) :
    d_collector(collector), d_interval(interval)
  {
    collector.subscribe(this);
  }

  ~TLocalCounters()
  {
    d_collector.unsubscribe(this, d_current);
  }

  TLocalCounters(const TLocalCounters&) = delete;
  TLocalCounters(TLocalCounters&&) = delete;
  TLocalCounters& operator=(const TLocalCounters&) = delete;
  TLocalCounters& operator=(TLocalCounters&&) = delete;

  template <typename Enum>
  auto& at(Enum index)
  {
    return d_current.at(index);
  }

  template <typename Enum>
  // coverity[auto_causes_copy]
  auto snapAt(Enum index)
  {
    return d_snapshot.lock()->at(index);
  }

  [[nodiscard]] Counters getSnap()
  {
    return *(d_snapshot.lock());
  }

  bool updateSnap(const timeval& tv_now, bool force = false)
  {
    timeval tv_diff{};

    if (!force) {
      timersub(&tv_now, &d_last, &tv_diff);
    }
    if (force || timercmp(&tv_diff, &d_interval, >=)) {
      // It's a copy
      *(d_snapshot.lock()) = d_current;
      d_last = tv_now;
      return true;
    }
    return false;
  }

  bool updateSnap(bool force = false)
  {
    timeval tv_now{};

    if (!force) {
      gettimeofday(&tv_now, nullptr);
    }
    return updateSnap(tv_now, force);
  }

private:
  GlobalCounters<Counters>& d_collector;
  Counters d_current;
  LockGuarded<Counters> d_snapshot;
  timeval d_last{0, 0};
  const timeval d_interval;
};

// Sum for a specific index
// In the future we might want to move the specifics of computing an aggregated value to the
// app specific Counters class
template <typename Counters>
template <typename Enum>
auto GlobalCounters<Counters>::sum(Enum index)
{
  auto lock = d_guarded.lock();
  auto sum = lock->d_history.at(index);
  for (const auto& instance : lock->d_instances) {
    sum += instance->snapAt(index);
  }
  return sum;
}

// Average for a specific index
// In the future we might want to move the specifics of computing an aggregated value to the
// app specific Counters class
template <typename Counters>
template <typename Enum>
auto GlobalCounters<Counters>::avg(Enum index)
{
  auto lock = d_guarded.lock();
  auto wavg = lock->d_history.at(index);
  auto sum = wavg.avg * wavg.weight;
  auto count = wavg.weight;
  for (const auto& instance : lock->d_instances) {
    auto val = instance->snapAt(index);
    count += val.weight;
    sum += val.avg * val.weight;
  }
  return count > 0 ? sum / count : 0;
}

// Max for a specific  index
// In the future we might want to move the specifics of computing an aggregated value to the
// app specific Counters class
template <typename Counters>
template <typename Enum>
auto GlobalCounters<Counters>::max(Enum index)
{
  auto lock = d_guarded.lock();
  uint64_t max = 0; // ignore history
  for (const auto& instance : lock->d_instances) {
    max = std::max(instance->snapAt(index), max);
  }
  return max;
}

// Get a consistent snap of *all* aggregated values
template <typename Counters>
Counters GlobalCounters<Counters>::aggregatedSnap()
{
  auto lock = d_guarded.lock();
  Counters ret = lock->d_history;
  for (const auto& instance : lock->d_instances) {
    auto snap = instance->getSnap();
    ret.merge(snap);
  }
  return ret;
}

}
