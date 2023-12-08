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

#include <unordered_map>

#include "config.h"
#include "dnscrypt.hh"
#include "dnsname.hh"
#include "dnsdist-protocols.hh"
#include "ednsextendederror.hh"
#include "gettime.hh"
#include "iputils.hh"
#include "noinitvector.hh"
#include "uuid-utils.hh"

struct ClientState;
struct DOHUnitInterface;
struct DOQUnit;
struct DOH3Unit;
class DNSCryptQuery;
class DNSDistPacketCache;

using QTag = std::unordered_map<string, string>;
using HeadersMap = std::unordered_map<std::string, std::string>;

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

  struct timespec getStartTime() const
  {
    return d_start;
  }

  struct timespec d_start
  {
    0, 0
  };

private:
  struct timespec getCurrentTime() const
  {
    struct timespec now;
    if (gettime(&now, d_needRealTime) < 0) {
      unixDie("Getting timestamp");
    }
    return now;
  }

  bool d_needRealTime;
};

class CrossProtocolContext;

struct InternalQueryState
{
  struct ProtoBufData
  {
    std::optional<boost::uuids::uuid> uniqueId{std::nullopt}; // 17
    std::string d_deviceName;
    std::string d_deviceID;
    std::string d_requestorID;
  };

  InternalQueryState()
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
  StopWatch queryRealTime{true}; // 24
  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr}; // 16
  std::unique_ptr<DNSCryptQuery> dnsCryptQuery{nullptr}; // 8
  std::unique_ptr<QTag> qTag{nullptr}; // 8
  std::unique_ptr<PacketBuffer> d_packet{nullptr}; // Initial packet, so we can restart the query from the response path if needed // 8
  std::unique_ptr<ProtoBufData> d_protoBufData{nullptr};
  std::unique_ptr<EDNSExtendedError> d_extendedError{nullptr};
  boost::optional<uint32_t> tempFailureTTL{boost::none}; // 8
  ClientState* cs{nullptr}; // 8
  std::unique_ptr<DOHUnitInterface> du; // 8
  size_t d_proxyProtocolPayloadSize{0}; // 8
  int32_t d_streamID{-1}; // 4
  std::unique_ptr<DOQUnit> doqu{nullptr}; // 8
  std::unique_ptr<DOH3Unit> doh3u{nullptr}; // 8
  uint32_t cacheKey{0}; // 4
  uint32_t cacheKeyNoECS{0}; // 4
  // DoH-only */
  uint32_t cacheKeyUDP{0}; // 4
  uint32_t ttlCap{0}; // cap the TTL _after_ inserting into the packet cache // 4
  int backendFD{-1}; // 4
  int delayMsec{0};
  uint16_t qtype{0}; // 2
  uint16_t qclass{0}; // 2
  // origID is in network-byte order
  uint16_t origID{0}; // 2
  uint16_t origFlags{0}; // 2
  uint16_t cacheFlags{0}; // DNS flags as sent to the backend // 2
  uint16_t udpPayloadSize{0}; // Max UDP payload size from the query // 2
  dnsdist::Protocol protocol; // 1
  bool ednsAdded{false};
  bool ecsAdded{false};
  bool skipCache{false};
  bool dnssecOK{false};
  bool useZeroScope{false};
  bool forwardedOverUDP{false};
  bool selfGenerated{false};
};

struct IDState
{
  IDState()
  {
  }

  IDState(const IDState& orig) = delete;
  IDState(IDState&& rhs) noexcept :
    internal(std::move(rhs.internal))
  {
    inUse.store(rhs.inUse.load());
    age.store(rhs.age.load());
  }

  IDState& operator=(IDState&& rhs) noexcept
  {
    inUse.store(rhs.inUse.load());
    age.store(rhs.age.load());
    internal = std::move(rhs.internal);
    return *this;
  }

  bool isInUse() const
  {
    return inUse;
  }

  /* For performance reasons we don't want to use a lock here, but that means
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

     We have two flags:
     - inUse tells us if there currently is a in-flight query whose state is stored
       in this state
     - locked tells us whether someone currently owns the state, so no-one else can touch
       it
  */
  InternalQueryState internal;
  std::atomic<uint16_t> age{0};

  class StateGuard
  {
  public:
    StateGuard(IDState& ids) :
      d_ids(ids)
    {
    }
    ~StateGuard()
    {
      d_ids.release();
    }
    StateGuard(const StateGuard&) = delete;
    StateGuard(StateGuard&&) = delete;
    StateGuard& operator=(const StateGuard&) = delete;
    StateGuard& operator=(StateGuard&&) = delete;

  private:
    IDState& d_ids;
  };

  [[nodiscard]] std::optional<StateGuard> acquire()
  {
    bool expected = false;
    if (locked.compare_exchange_strong(expected, true)) {
      return std::optional<StateGuard>(*this);
    }
    return std::nullopt;
  }

  void release()
  {
    locked.store(false);
  }

  std::atomic<bool> inUse{false}; // 1

private:
  std::atomic<bool> locked{false}; // 1
};
