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

#include "config.h"
#include "dnsname.hh"
#include "dnsdist-protocols.hh"
#include "gettime.hh"
#include "iputils.hh"
#include "uuid-utils.hh"

struct ClientState;
struct DOHUnit;
class DNSCryptQuery;
class DNSDistPacketCache;

using QTag = std::unordered_map<string, string>;

struct StopWatch
{
  StopWatch(bool realTime = false) :
    d_needRealTime(realTime)
  {
  }

  void start()
  {
    d_start = getCurrentTime();
  }

  void set(const struct timespec& from)
  {
    d_start = from;
  }

  double udiff() const
  {
    struct timespec now = getCurrentTime();
    return 1000000.0 * (now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec) / 1000.0;
  }

  double udiffAndSet()
  {
    struct timespec now = getCurrentTime();
    auto ret = 1000000.0 * (now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec) / 1000.0;
    d_start = now;
    return ret;
  }

  struct timespec getCurrentTime() const
  {
    struct timespec now;
    if (gettime(&now, d_needRealTime) < 0) {
      unixDie("Getting timestamp");
    }
    return now;
  }

  struct timespec d_start
  {
    0, 0
  };

private:
  bool d_needRealTime;
};

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#endif

struct InternalQueryState
{
  static void DeleterPlaceHolder(DOHUnit*)
  {
  }

  InternalQueryState() :
    du(std::unique_ptr<DOHUnit, void (*)(DOHUnit*)>(nullptr, DeleterPlaceHolder))
  {
    origDest.sin4.sin_family = 0;
  }

  InternalQueryState(InternalQueryState&& rhs) = default;
  InternalQueryState& operator=(InternalQueryState&& rhs) = default;

  InternalQueryState(const InternalQueryState& orig) = delete;
  InternalQueryState& operator=(const InternalQueryState& orig) = delete;

  boost::optional<Netmask> subnet{boost::none}; // 40
  ComboAddress origRemote; // 28
  ComboAddress origDest; // 28
  ComboAddress hopRemote;
  ComboAddress hopLocal;
  DNSName qname; // 24
  std::string poolName; // 24
  StopWatch sentTime; // 16
  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr}; // 16
  std::unique_ptr<DNSCryptQuery> dnsCryptQuery{nullptr}; // 8
  std::unique_ptr<QTag> qTag{nullptr}; // 8
  boost::optional<uint32_t> tempFailureTTL; // 8
  ClientState* cs{nullptr}; // 8
  std::unique_ptr<DOHUnit, void (*)(DOHUnit*)> du; // 8
  uint32_t cacheKey{0}; // 4
  uint32_t cacheKeyNoECS{0}; // 4
  // DoH-only */
  uint32_t cacheKeyUDP{0}; // 4
  int backendFD{-1}; // 4
  int delayMsec{0};
  uint16_t qtype{0}; // 2
  uint16_t qclass{0}; // 2
  // origID is in network-byte order
  uint16_t origID{0}; // 2
  uint16_t origFlags{0}; // 2
  uint16_t cacheFlags{0}; // DNS flags as sent to the backend // 2
  dnsdist::Protocol protocol; // 1
  boost::optional<boost::uuids::uuid> uniqueId{boost::none}; // 17 (placed here to reduce the space lost to padding)
  bool ednsAdded{false};
  bool ecsAdded{false};
  bool skipCache{false};
  bool dnssecOK{false};
  bool useZeroScope{false};
  bool forwardedOverUDP{false};
};

struct IDState
{
  IDState()
  {
  }

  IDState(const IDState& orig) = delete;
  IDState(IDState&& rhs)
  {
    if (rhs.isInUse()) {
      throw std::runtime_error("Trying to move an in-use IDState");
    }

#ifdef __SANITIZE_THREAD__
    age.store(rhs.age.load());
#else
    age = rhs.age;
#endif
    internal = std::move(rhs.internal);
  }

  IDState& operator=(IDState&& rhs)
  {
    if (isInUse()) {
      throw std::runtime_error("Trying to overwrite an in-use IDState");
    }

    if (rhs.isInUse()) {
      throw std::runtime_error("Trying to move an in-use IDState");
    }
#ifdef __SANITIZE_THREAD__
    age.store(rhs.age.load());
#else
    age = rhs.age;
#endif

    internal = std::move(rhs.internal);

    return *this;
  }

  static const int64_t unusedIndicator = -1;

  static bool isInUse(int64_t usageIndicator)
  {
    return usageIndicator != unusedIndicator;
  }

  bool isInUse() const
  {
    return usageIndicator != unusedIndicator;
  }

  /* return true if the value has been successfully replaced meaning that
     no-one updated the usage indicator in the meantime */
  bool tryMarkUnused(int64_t expectedUsageIndicator)
  {
    return usageIndicator.compare_exchange_strong(expectedUsageIndicator, unusedIndicator);
  }

  /* mark as used no matter what, return true if the state was in use before */
  bool markAsUsed()
  {
    auto currentGeneration = generation++;
    return markAsUsed(currentGeneration);
  }

  /* mark as used no matter what, return true if the state was in use before */
  bool markAsUsed(int64_t currentGeneration)
  {
    int64_t oldUsage = usageIndicator.exchange(currentGeneration);
    return oldUsage != unusedIndicator;
  }

  /* We use this value to detect whether this state is in use.
     For performance reasons we don't want to use a lock here, but that means
     we need to be very careful when modifying this value. Modifications happen
     from:
     - one of the UDP or DoH 'client' threads receiving a query, selecting a backend
       then picking one of the states associated to this backend (via the idOffset).
       Most of the time this state should not be in use and usageIndicator is -1, but we
       might not yet have received a response for the query previously associated to this
       state, meaning that we will 'reuse' this state and erase the existing state.
       If we ever receive a response for this state, it will be discarded. This is
       mostly fine for UDP except that we still need to be careful in order to miss
       the 'outstanding' counters, which should only be increased when we are picking
       an empty state, and not when reusing ;
       For DoH, though, we have dynamically allocated a DOHUnit object that needs to
       be freed, as well as internal objects internals to libh2o.
     - one of the UDP receiver threads receiving a response from a backend, picking
       the corresponding state and sending the response to the client ;
     - the 'healthcheck' thread scanning the states to actively discover timeouts,
       mostly to keep some counters like the 'outstanding' one sane.
     We previously based that logic on the origFD (FD on which the query was received,
     and therefore from where the response should be sent) but this suffered from an
     ABA problem since it was quite likely that a UDP 'client thread' would reset it to the
     same value since we only have so much incoming sockets:
     - 1/ 'client' thread gets a query and set origFD to its FD, say 5 ;
     - 2/ 'receiver' thread gets a response, read the value of origFD to 5, check that the qname,
       qtype and qclass match
     - 3/ during that time the 'client' thread reuses the state, setting again origFD to 5 ;
     - 4/ the 'receiver' thread uses compare_exchange_strong() to only replace the value if it's still
       5, except it's not the same 5 anymore and it overrides a fresh state.
     We now use a 32-bit unsigned counter instead, which is incremented every time the state is set,
     wrapping around if necessary, and we set an atomic signed 64-bit value, so that we still have -1
     when the state is unused and the value of our counter otherwise.
  */
  InternalQueryState internal;
  std::atomic<int64_t> usageIndicator{unusedIndicator}; // set to unusedIndicator to indicate this state is empty   // 8
  std::atomic<uint32_t> generation{0}; // increased every time a state is used, to be able to detect an ABA issue    // 4
#ifdef __SANITIZE_THREAD__
  std::atomic<uint16_t> age{0};
#else
  uint16_t age{0}; // 2
#endif
};
