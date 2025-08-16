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

// for OpenBSD, sys/socket.h needs to come before net/if.h
#include <sys/socket.h>
#include <net/if.h>

#include <boost/format.hpp>

#include "config.h"
#include "dnsdist.hh"
#include "dnsdist-backend.hh"
#include "dnsdist-backoff.hh"
#include "dnsdist-metrics.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-random.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-snmp.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-xsk.hh"
#include "dolog.hh"
#include "xsk.hh"

bool DownstreamState::passCrossProtocolQuery(std::unique_ptr<CrossProtocolQuery>&& cpq)
{
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  if (!d_config.d_dohPath.empty()) {
    return g_dohClientThreads && g_dohClientThreads->passCrossProtocolQueryToThread(std::move(cpq));
  }
#endif
  return g_tcpclientthreads && g_tcpclientthreads->passCrossProtocolQueryToThread(std::move(cpq));
}

#ifdef HAVE_XSK
void DownstreamState::addXSKDestination(int fd)
{
  auto socklen = d_config.remote.getSocklen();
  ComboAddress local;
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &socklen)) {
    return;
  }

  {
    auto addresses = d_socketSourceAddresses.write_lock();
    addresses->push_back(local);
  }
  dnsdist::xsk::addDestinationAddress(local);
  for (size_t idx = 0; idx < d_xskSockets.size(); idx++) {
    d_xskSockets.at(idx)->addWorkerRoute(d_xskInfos.at(idx), local);
  }
}

void DownstreamState::removeXSKDestination(int fd)
{
  auto socklen = d_config.remote.getSocklen();
  ComboAddress local;
  if (getsockname(fd, reinterpret_cast<sockaddr*>(&local), &socklen)) {
    return;
  }

  dnsdist::xsk::removeDestinationAddress(local);
  for (auto& xskSocket : d_xskSockets) {
    xskSocket->removeWorkerRoute(local);
  }
}
#endif /* HAVE_XSK */

bool DownstreamState::reconnect(bool initialAttempt)
{
  std::unique_lock<std::mutex> tl(connectLock, std::try_to_lock);
  if (!tl.owns_lock() || isStopped()) {
    /* we are already reconnecting or stopped anyway */
    return false;
  }

  if (IsAnyAddress(d_config.remote)) {
    return true;
  }

  connected = false;
#ifdef HAVE_XSK
  if (!d_xskInfos.empty()) {
    auto addresses = d_socketSourceAddresses.write_lock();
    addresses->clear();
  }
#endif /* HAVE_XSK */

  for (auto& fd : sockets) {
    if (fd != -1) {
      if (sockets.size() > 1) {
        (*mplexer.lock())->removeReadFD(fd);
      }
#ifdef HAVE_XSK
      if (!d_xskInfos.empty()) {
        removeXSKDestination(fd);
      }
#endif /* HAVE_XSK */
      /* shutdown() is needed to wake up recv() in the responderThread */
      shutdown(fd, SHUT_RDWR);
      close(fd);
      fd = -1;
    }
    fd = SSocket(d_config.remote.sin4.sin_family, SOCK_DGRAM, 0);

#ifdef SO_BINDTODEVICE
    if (!d_config.sourceItfName.empty()) {
      int res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, d_config.sourceItfName.c_str(), d_config.sourceItfName.length());
      if (res != 0) {
        infolog("Error setting up the interface on backend socket '%s': %s", d_config.remote.toStringWithPort(), stringerror());
      }
    }
#endif

    if (!IsAnyAddress(d_config.sourceAddr)) {
#ifdef IP_BIND_ADDRESS_NO_PORT
      if (d_config.ipBindAddrNoPort) {
        SSetsockopt(fd, SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
      }
#endif
      SBind(fd, d_config.sourceAddr);
    }

    try {
      setDscp(fd, d_config.remote.sin4.sin_family, d_config.dscp);
      SConnect(fd, d_config.remote);
      if (sockets.size() > 1) {
        (*mplexer.lock())->addReadFD(fd, [](int, boost::any) {});
      }
#ifdef HAVE_XSK
      if (!d_xskInfos.empty()) {
        addXSKDestination(fd);
      }
#endif /* HAVE_XSK */
      connected = true;
    }
    catch (const std::runtime_error& error) {
      if (initialAttempt || dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose) {
        if (!IsAnyAddress(d_config.sourceAddr) || !d_config.sourceItfName.empty()) {
            infolog("Error connecting to new server with address %s (source address: %s, source interface: %s): %s", d_config.remote.toStringWithPort(), IsAnyAddress(d_config.sourceAddr) ? "not set" : d_config.sourceAddr.toString(), d_config.sourceItfName.empty() ? "not set" : d_config.sourceItfName, error.what());
          }
        else {
          infolog("Error connecting to new server with address %s: %s", d_config.remote.toStringWithPort(), error.what());
        }
      }
      connected = false;
      break;
    }
  }

  /* if at least one (re-)connection failed, close all sockets */
  if (!connected) {
#ifdef HAVE_XSK
    if (!d_xskInfos.empty()) {
      auto addresses = d_socketSourceAddresses.write_lock();
      addresses->clear();
    }
#endif /* HAVE_XSK */
    for (auto& fd : sockets) {
      if (fd != -1) {
#ifdef HAVE_XSK
        if (!d_xskInfos.empty()) {
          removeXSKDestination(fd);
        }
#endif /* HAVE_XSK */
        if (sockets.size() > 1) {
          try {
            (*mplexer.lock())->removeReadFD(fd);
          }
          catch (const FDMultiplexerException& e) {
            /* some sockets might not have been added to the multiplexer
               yet, that's fine */
          }
        }
        /* shutdown() is needed to wake up recv() in the responderThread */
        shutdown(fd, SHUT_RDWR);
        close(fd);
        fd = -1;
      }
    }
  }

  if (connected) {
    tl.unlock();
    d_connectedWait.notify_all();
    if (!initialAttempt) {
      /* we need to be careful not to start this
         thread too soon, as the creation should only
         happen after the configuration has been parsed */
      start();
    }
  }

  return connected;
}

void DownstreamState::waitUntilConnected()
{
  if (d_stopped) {
    return;
  }
  if (connected) {
    return;
  }
  {
    std::unique_lock<std::mutex> lock(connectLock);
    d_connectedWait.wait(lock, [this]{
      return connected.load();
    });
  }
}

void DownstreamState::stop()
{
  if (d_stopped) {
    return;
  }
  d_stopped = true;

  {
    auto tlock = std::scoped_lock(connectLock);
    auto slock = mplexer.lock();

    for (auto& fd : sockets) {
      if (fd != -1) {
        /* shutdown() is needed to wake up recv() in the responderThread */
        shutdown(fd, SHUT_RDWR);
      }
    }
  }
}

void DownstreamState::hash()
{
  vinfolog("Computing hashes for id=%s and weight=%d", *d_config.id, d_config.d_weight);
  const auto hashPerturbation = dnsdist::configuration::getImmutableConfiguration().d_hashPerturbation;
  auto w = d_config.d_weight;
  auto idStr = boost::str(boost::format("%s") % *d_config.id);
  auto lockedHashes = hashes.write_lock();
  lockedHashes->clear();
  lockedHashes->reserve(w);
  while (w > 0) {
    std::string uuid = boost::str(boost::format("%s-%d") % idStr % w);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): sorry, it's the burtle API
    unsigned int wshash = burtleCI(reinterpret_cast<const unsigned char*>(uuid.c_str()), uuid.size(), hashPerturbation);
    lockedHashes->push_back(wshash);
    --w;
  }
  std::sort(lockedHashes->begin(), lockedHashes->end());
  hashesComputed = true;
}

void DownstreamState::setId(const boost::uuids::uuid& newId)
{
  d_config.id = newId;
  // compute hashes only if already done
  if (hashesComputed) {
    hash();
  }
}

void DownstreamState::setWeight(int newWeight)
{
  if (newWeight < 1) {
    errlog("Error setting server's weight: downstream weight value must be greater than 0.");
    return ;
  }

  d_config.d_weight = newWeight;

  if (hashesComputed) {
    hash();
  }
}

DownstreamState::DownstreamState(DownstreamState::Config&& config, std::shared_ptr<TLSCtx> tlsCtx, bool connect): d_config(std::move(config)), d_tlsCtx(std::move(tlsCtx))
{
  threadStarted.clear();

  if (d_config.d_qpsLimit > 0) {
    d_qpsLimiter = QPSLimiter(d_config.d_qpsLimit, d_config.d_qpsLimit);
  }

  if (d_config.id) {
    setId(*d_config.id);
  }
  else {
    d_config.id = getUniqueID();
  }

  if (d_config.d_weight > 0) {
    setWeight(d_config.d_weight);
  }

  if (d_config.d_availability == Availability::Auto && d_config.d_healthCheckMode == HealthCheckMode::Lazy && d_config.d_lazyHealthCheckSampleSize > 0) {
    d_lazyHealthCheckStats.lock()->d_lastResults.set_capacity(d_config.d_lazyHealthCheckSampleSize);
    setUpStatus(true);
  }

  setName(d_config.name);

  if (d_tlsCtx && !d_config.d_dohPath.empty()) {
#ifdef HAVE_NGHTTP2
    auto outgoingDoHWorkerThreads = dnsdist::configuration::getImmutableConfiguration().d_outgoingDoHWorkers;
    if (dnsdist::configuration::isImmutableConfigurationDone() && outgoingDoHWorkerThreads && *outgoingDoHWorkerThreads == 0) {
      throw std::runtime_error("Error: setOutgoingDoHWorkerThreads() is set to 0 so no outgoing DoH worker thread is available to serve queries");
    }

    if (!dnsdist::configuration::isImmutableConfigurationDone() && (!outgoingDoHWorkerThreads || *outgoingDoHWorkerThreads == 0)) {
      dnsdist::configuration::updateImmutableConfiguration([](dnsdist::configuration::ImmutableConfiguration& immutableConfig) {
        immutableConfig.d_outgoingDoHWorkers = 1;
      });
    }
#endif /* HAVE_NGHTTP2 */
  }

  if (connect && !isTCPOnly()) {
    if (!IsAnyAddress(d_config.remote)) {
      connectUDPSockets();
    }
  }

  sw.start();
}


void DownstreamState::start()
{
  if (connected && !threadStarted.test_and_set()) {
#ifdef HAVE_XSK
    for (auto& xskInfo : d_xskInfos) {
      auto xskResponderThread = std::thread(dnsdist::xsk::XskResponderThread, shared_from_this(), xskInfo);
      if (!d_config.d_cpus.empty()) {
        mapThreadToCPUList(xskResponderThread.native_handle(), d_config.d_cpus);
      }
      xskResponderThread.detach();
    }
#endif /* HAVE_XSK */

    auto tid = std::thread(responderThread, shared_from_this());
    if (!d_config.d_cpus.empty()) {
      mapThreadToCPUList(tid.native_handle(), d_config.d_cpus);
    }
    tid.detach();
  }
}

void DownstreamState::connectUDPSockets()
{
  const auto& config = dnsdist::configuration::getImmutableConfiguration();
  if (config.d_randomizeIDsToBackend) {
    idStates.clear();
  }
  else {
    idStates.resize(config.d_maxUDPOutstanding);
  }
  sockets.resize(d_config.d_numberOfSockets);

  if (sockets.size() > 1) {
    *(mplexer.lock()) = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(sockets.size()));
  }

  for (auto& fd : sockets) {
    fd = -1;
  }

  reconnect(true);
}

DownstreamState::~DownstreamState()
{
  for (auto& fd : sockets) {
    if (fd >= 0) {
      close(fd);
      fd = -1;
    }
  }
}

void DownstreamState::incCurrentConnectionsCount()
{
  auto currentConnectionsCount = ++tcpCurrentConnections;
  if (currentConnectionsCount > tcpMaxConcurrentConnections) {
    tcpMaxConcurrentConnections.store(currentConnectionsCount);
  }
}

int DownstreamState::pickSocketForSending()
{
  size_t numberOfSockets = sockets.size();
  if (numberOfSockets == 1) {
    return sockets[0];
  }

  size_t idx{0};
  if (dnsdist::configuration::getImmutableConfiguration().d_randomizeUDPSocketsToBackend) {
    idx = dnsdist::getRandomValue(numberOfSockets);
  }
  else {
    idx = socketsOffset++;
  }

  return sockets[idx % numberOfSockets];
}

void DownstreamState::pickSocketsReadyForReceiving(std::vector<int>& ready)
{
  ready.clear();

  if (sockets.size() == 1) {
    ready.push_back(sockets[0]);
    return ;
  }

  (*mplexer.lock())->getAvailableFDs(ready, 1000);
}

static bool isIDSExpired(const IDState& ids, uint8_t udpTimeout)
{
  auto age = ids.age.load();
  return age > udpTimeout;
}

void DownstreamState::handleUDPTimeout(IDState& ids)
{
  ids.age = 0;
  ids.inUse = false;
  ++reuseds;
  --outstanding;
  ++dnsdist::metrics::g_stats.downstreamTimeouts; // this is an 'actively' discovered timeout
  vinfolog("Had a downstream timeout from %s (%s) for query for %s|%s from %s",
           d_config.remote.toStringWithPort(), getName(),
           ids.internal.qname.toLogString(), QType(ids.internal.qtype).toString(), ids.internal.origRemote.toStringWithPort());

  const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
  const auto& timeoutRespRules = dnsdist::rules::getResponseRuleChain(chains, dnsdist::rules::ResponseRuleChain::TimeoutResponseRules);
  auto sender = ids.internal.du == nullptr ? nullptr : ids.internal.du->getQuerySender();
  if (!handleTimeoutResponseRules(timeoutRespRules, ids.internal, shared_from_this(), sender)) {
    DOHUnitInterface::handleTimeout(std::move(ids.internal.du));
  }

  if (g_rings.shouldRecordResponses()) {
    struct timespec ts;
    gettime(&ts);

    struct dnsheader fake;
    memset(&fake, 0, sizeof(fake));
    fake.id = ids.internal.origID;
    uint16_t* flags = getFlagsFromDNSHeader(&fake);
    *flags = ids.internal.origFlags;

    g_rings.insertResponse(ts, ids.internal.origRemote, ids.internal.qname, ids.internal.qtype, std::numeric_limits<unsigned int>::max(), 0, fake, d_config.remote, getProtocol());
  }

  reportTimeoutOrError();
}

void DownstreamState::reportResponse(uint8_t rcode)
{
  if (d_config.d_availability == Availability::Auto && d_config.d_healthCheckMode == HealthCheckMode::Lazy && d_config.d_lazyHealthCheckSampleSize > 0) {
    bool failure = d_config.d_lazyHealthCheckMode == LazyHealthCheckMode::TimeoutOrServFail ? rcode == RCode::ServFail : false;
    d_lazyHealthCheckStats.lock()->d_lastResults.push_back(failure);
  }
}

void DownstreamState::reportTimeoutOrError()
{
  if (d_config.d_availability == Availability::Auto && d_config.d_healthCheckMode == HealthCheckMode::Lazy && d_config.d_lazyHealthCheckSampleSize > 0) {
    d_lazyHealthCheckStats.lock()->d_lastResults.push_back(true);
  }
}

void DownstreamState::handleUDPTimeouts()
{
  if (getProtocol() != dnsdist::Protocol::DoUDP) {
    return;
  }

  const auto& config = dnsdist::configuration::getImmutableConfiguration();
  const auto udpTimeout = d_config.udpTimeout > 0 ? d_config.udpTimeout : config.d_udpTimeout;
  if (config.d_randomizeIDsToBackend) {
    auto map = d_idStatesMap.lock();
    for (auto it = map->begin(); it != map->end(); ) {
      auto& ids = it->second;
      if (isIDSExpired(ids, udpTimeout)) {
        handleUDPTimeout(ids);
        it = map->erase(it);
        continue;
      }
      ++ids.age;
      ++it;
    }
  }
  else {
    if (outstanding.load() > 0) {
      for (IDState& ids : idStates) {
        if (!ids.isInUse()) {
          continue;
        }
        if (!isIDSExpired(ids, udpTimeout)) {
          ++ids.age;
          continue;
        }
        auto guard = ids.acquire();
        if (!guard) {
          continue;
        }
        /* check again, now that we have locked this state */
        if (ids.isInUse() && isIDSExpired(ids, udpTimeout)) {
          handleUDPTimeout(ids);
        }
      }
    }
  }
}

uint16_t DownstreamState::saveState(InternalQueryState&& state)
{
  const auto& config = dnsdist::configuration::getImmutableConfiguration();
  if (config.d_randomizeIDsToBackend) {
    /* if the state is already in use we will retry,
       up to 5 five times. The last selected one is used
       even if it was already in use */
    size_t remainingAttempts = 5;
    auto map = d_idStatesMap.lock();

    do {
      uint16_t selectedID = dnsdist::getRandomValue(std::numeric_limits<uint16_t>::max());
      auto [it, inserted] = map->emplace(selectedID, IDState());

      if (!inserted) {
        remainingAttempts--;
        if (remainingAttempts > 0) {
          continue;
        }

        auto oldDU = std::move(it->second.internal.du);
        ++reuseds;
        ++dnsdist::metrics::g_stats.downstreamTimeouts;
        DOHUnitInterface::handleTimeout(std::move(oldDU));
      }
      else {
        ++outstanding;
      }

      it->second.internal = std::move(state);
      it->second.age.store(0);

      return it->first;
    }
    while (true);
  }

  do {
    uint16_t selectedID = (idOffset++) % idStates.size();
    IDState& ids = idStates[selectedID];
    auto guard = ids.acquire();
    if (!guard) {
      continue;
    }
    if (ids.isInUse()) {
      /* we are reusing a state, no change in outstanding but if there was an existing DOHUnit we need
         to handle it because it's about to be overwritten. */
      auto oldDU = std::move(ids.internal.du);
      ++reuseds;
      ++dnsdist::metrics::g_stats.downstreamTimeouts;
      DOHUnitInterface::handleTimeout(std::move(oldDU));
    }
    else {
      ++outstanding;
    }
    ids.internal = std::move(state);
    ids.age.store(0);
    ids.inUse = true;
    return selectedID;
  }
  while (true);
}

void DownstreamState::restoreState(uint16_t id, InternalQueryState&& state)
{
  const auto& config = dnsdist::configuration::getImmutableConfiguration();
  if (config.d_randomizeIDsToBackend) {
    auto map = d_idStatesMap.lock();

    auto [it, inserted] = map->emplace(id, IDState());
    if (!inserted) {
      /* already used */
      ++reuseds;
      ++dnsdist::metrics::g_stats.downstreamTimeouts;
      DOHUnitInterface::handleTimeout(std::move(state.du));
    }
    else {
      it->second.internal = std::move(state);
      ++outstanding;
    }
    return;
  }

  auto& ids = idStates[id];
  auto guard = ids.acquire();
  if (!guard) {
    /* already used */
    ++reuseds;
    ++dnsdist::metrics::g_stats.downstreamTimeouts;
    DOHUnitInterface::handleTimeout(std::move(state.du));
    return;
  }
  if (ids.isInUse()) {
    /* already used */
    ++reuseds;
    ++dnsdist::metrics::g_stats.downstreamTimeouts;
    DOHUnitInterface::handleTimeout(std::move(state.du));
    return;
  }
  ids.internal = std::move(state);
  ids.inUse = true;
  ++outstanding;
}

std::optional<InternalQueryState> DownstreamState::getState(uint16_t id)
{
  std::optional<InternalQueryState> result = std::nullopt;
  const auto& config = dnsdist::configuration::getImmutableConfiguration();
  if (config.d_randomizeIDsToBackend) {
    auto map = d_idStatesMap.lock();

    auto it = map->find(id);
    if (it == map->end()) {
      return result;
    }

    result = std::move(it->second.internal);
    map->erase(it);
    --outstanding;
    return result;
  }

  if (id > idStates.size()) {
    return result;
  }

  auto& ids = idStates[id];
  auto guard = ids.acquire();
  if (!guard) {
    return result;
  }

  if (ids.isInUse()) {
    result = std::move(ids.internal);
    --outstanding;
  }
  ids.inUse = false;
  return result;
}

bool DownstreamState::healthCheckRequired(std::optional<time_t> currentTime)
{
  if (d_config.d_availability != DownstreamState::Availability::Auto) {
    return false;
  }

  if (d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Lazy) {
    auto stats = d_lazyHealthCheckStats.lock();
    if (stats->d_status == LazyHealthCheckStats::LazyStatus::PotentialFailure) {
      vinfolog("Sending health-check query for %s which is still in the Potential Failure state", getNameWithAddr());
      return true;
    }
    if (stats->d_status == LazyHealthCheckStats::LazyStatus::Failed) {
      auto now = currentTime ? *currentTime : time(nullptr);
      if (stats->d_nextCheck <= now) {
        /* we update the next check time here because the check might time out,
           and we do not want to send a second check during that time unless
           the timer is actually very short */
        vinfolog("Sending health-check query for %s which is still in the Failed state", getNameWithAddr());
        updateNextLazyHealthCheck(*stats, true, now);
        return true;
      }
      return false;
    }
    if (stats->d_status == LazyHealthCheckStats::LazyStatus::Healthy) {
      auto& lastResults = stats->d_lastResults;
      size_t totalCount = lastResults.size();
      if (totalCount < d_config.d_lazyHealthCheckMinSampleCount) {
        return false;
      }

      size_t failures = 0;
      for (const auto& result : lastResults) {
        if (result) {
          ++failures;
        }
      }

      const auto maxFailureRate = static_cast<float>(d_config.d_lazyHealthCheckThreshold);
      auto current = (100.0 * failures) / totalCount;
      if (current >= maxFailureRate) {
        lastResults.clear();
        vinfolog("Backend %s reached the lazy health-check threshold (%f%% out of %f%%, looking at sample of %d items with %d failures), moving to Potential Failure state", getNameWithAddr(), current, maxFailureRate, totalCount, failures);
        stats->d_status = LazyHealthCheckStats::LazyStatus::PotentialFailure;
        consecutiveSuccessfulChecks = 0;
        /* we update the next check time here because the check might time out,
           and we do not want to send a second check during that time unless
           the timer is actually very short */
        updateNextLazyHealthCheck(*stats, true);
        return true;
      }
    }

    return false;
  }
  if (d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active) {

    if (d_nextCheck > 1) {
      --d_nextCheck;
      return false;
    }

    d_nextCheck = d_config.checkInterval;
    return true;
  }

  return false;
}

time_t DownstreamState::getNextLazyHealthCheck()
{
  auto stats = d_lazyHealthCheckStats.lock();
  return stats->d_nextCheck;
}

void DownstreamState::updateNextLazyHealthCheck(LazyHealthCheckStats& stats, bool checkScheduled, std::optional<time_t> currentTime)
{
  auto now = currentTime ? * currentTime : time(nullptr);
  if (d_config.d_lazyHealthCheckUseExponentialBackOff) {
    if (stats.d_status == DownstreamState::LazyHealthCheckStats::LazyStatus::PotentialFailure) {
      /* we are still in the "up" state, we need to send the next query quickly to
         determine if the backend is really down */
      stats.d_nextCheck = now + d_config.checkInterval;
      vinfolog("Backend %s is in potential failure state, next check in %d seconds", getNameWithAddr(), d_config.checkInterval.load());
    }
    else if (consecutiveSuccessfulChecks > 0) {
      /* we are in 'Failed' state, but just had one (or more) successful check,
         so we want the next one to happen quite quickly as the backend might
         be available again. */
      stats.d_nextCheck = now + d_config.d_lazyHealthCheckFailedInterval;
      if (!checkScheduled) {
        vinfolog("Backend %s is in failed state but had %d consecutive successful checks, next check in %d seconds", getNameWithAddr(), std::to_string(consecutiveSuccessfulChecks), d_config.d_lazyHealthCheckFailedInterval);
      }
    }
    else {
      uint16_t failedTests = currentCheckFailures;
      if (checkScheduled) {
        /* we are planning the check after that one, which will only
           occur if there is a failure */
        failedTests++;
      }

      time_t backOff = d_config.d_lazyHealthCheckMaxBackOff;
      const ExponentialBackOffTimer backOffTimer(d_config.d_lazyHealthCheckMaxBackOff);
      auto backOffCoeffTmp = backOffTimer.get(failedTests - 1);
      /* backOffCoeffTmp cannot be higher than d_config.d_lazyHealthCheckMaxBackOff */
      const auto backOffCoeff = static_cast<time_t>(backOffCoeffTmp);
      if ((std::numeric_limits<time_t>::max() / d_config.d_lazyHealthCheckFailedInterval) >= backOffCoeff) {
        backOff = d_config.d_lazyHealthCheckFailedInterval * backOffCoeff;
        if (backOff > d_config.d_lazyHealthCheckMaxBackOff || (std::numeric_limits<time_t>::max() - now) <= backOff) {
          backOff = d_config.d_lazyHealthCheckMaxBackOff;
        }
      }

      stats.d_nextCheck = now + backOff;
      vinfolog("Backend %s is in failed state and has failed %d consecutive checks, next check in %d seconds", getNameWithAddr(), failedTests, backOff);
    }
  }
  else {
    stats.d_nextCheck = now + d_config.d_lazyHealthCheckFailedInterval;
    vinfolog("Backend %s is in %s state, next check in %d seconds", getNameWithAddr(), (stats.d_status == DownstreamState::LazyHealthCheckStats::LazyStatus::PotentialFailure ? "potential failure" : "failed"), d_config.d_lazyHealthCheckFailedInterval);
  }
}

void DownstreamState::submitHealthCheckResult(bool initial, bool newResult)
{
  if (!newResult) {
    ++d_healthCheckMetrics.d_failures;
  }

  if (initial) {
    /* if this is the initial health-check, at startup, we do not care
       about the minimum number of failed/successful health-checks */
    if (!IsAnyAddress(d_config.remote)) {
      infolog("Marking downstream %s as '%s'", getNameWithAddr(), newResult ? "up" : "down");
    }
    setUpStatus(newResult);
    if (newResult == false) {
      currentCheckFailures++;
      if (d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Lazy) {
        auto stats = d_lazyHealthCheckStats.lock();
        stats->d_status = LazyHealthCheckStats::LazyStatus::Failed;
        updateNextLazyHealthCheck(*stats, false);
      }
    }
    handleServerStateChange(getNameWithAddr(), newResult);
    return;
  }

  bool newState = newResult;

  if (newResult) {
    /* check succeeded */
    currentCheckFailures = 0;
    consecutiveSuccessfulChecks++;

    if (!upStatus.load(std::memory_order_relaxed)) {
      /* we were previously marked as "down" and had a successful health-check,
         let's see if this is enough to move to the "up" state or if we need
         more successful health-checks for that */
      if (consecutiveSuccessfulChecks < d_config.minRiseSuccesses) {
        /* we need more than one successful check to rise
           and we didn't reach the threshold yet, let's stay down */
        newState = false;

        if (d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Lazy) {
          auto stats = d_lazyHealthCheckStats.lock();
          updateNextLazyHealthCheck(*stats, false);
        }
      }
    }

    if (newState) {
      if (d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Lazy) {
        auto stats = d_lazyHealthCheckStats.lock();
        vinfolog("Backend %s had %d successful checks, moving to Healthy", getNameWithAddr(), std::to_string(consecutiveSuccessfulChecks));
        stats->d_status = LazyHealthCheckStats::LazyStatus::Healthy;
        stats->d_lastResults.clear();
      }
    }
  }
  else {
    /* check failed */
    consecutiveSuccessfulChecks = 0;

    currentCheckFailures++;

    if (upStatus.load(std::memory_order_relaxed)) {
      /* we were previously marked as "up" and failed a health-check,
         let's see if this is enough to move to the "down" state or if
         need more failed checks for that */
      if (currentCheckFailures < d_config.maxCheckFailures) {
        /* we need more than one failure to be marked as down,
           and we did not reach the threshold yet, let's stay up */
        newState = true;
      }
      else if (d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Lazy) {
        auto stats = d_lazyHealthCheckStats.lock();
        vinfolog("Backend %s failed its health-check, moving from Potential failure to Failed", getNameWithAddr());
        stats->d_status = LazyHealthCheckStats::LazyStatus::Failed;
        currentCheckFailures = 1;
        updateNextLazyHealthCheck(*stats, false);
      }
    }
  }

  if (newState != upStatus.load(std::memory_order_relaxed)) {
    /* we are actually moving to a new state */
    if (!IsAnyAddress(d_config.remote)) {
      infolog("Marking downstream %s as '%s'", getNameWithAddr(), newState ? "up" : "down");
    }

    if (newState && !isTCPOnly() && (!connected || d_config.reconnectOnUp)) {
      newState = reconnect();
    }

    setUpStatus(newState);
    if (g_snmpAgent != nullptr && dnsdist::configuration::getImmutableConfiguration().d_snmpTrapsEnabled) {
      g_snmpAgent->sendBackendStatusChangeTrap(*this);
    }
    handleServerStateChange(getNameWithAddr(), newResult);
  }
}

#ifdef HAVE_XSK
[[nodiscard]] ComboAddress DownstreamState::pickSourceAddressForSending()
{
  if (!connected) {
    waitUntilConnected();
  }

  auto addresses = d_socketSourceAddresses.read_lock();
  auto numberOfAddresses = addresses->size();
  if (numberOfAddresses == 0) {
    throw std::runtime_error("No source address available for sending XSK data to backend " + getNameWithAddr());
  }
  size_t idx = dnsdist::getRandomValue(numberOfAddresses);
  return (*addresses)[idx % numberOfAddresses];
}

void DownstreamState::registerXsk(std::vector<std::shared_ptr<XskSocket>>& xsks)
{
  d_xskSockets = xsks;

  if (d_config.sourceAddr.sin4.sin_family == 0 || (IsAnyAddress(d_config.sourceAddr))) {
    const auto& ifName = xsks.at(0)->getInterfaceName();
    auto addresses = getListOfAddressesOfNetworkInterface(ifName);
    if (addresses.empty()) {
      throw std::runtime_error("Unable to get source address from interface " + ifName);
    }

    if (addresses.size() > 1) {
      warnlog("More than one address configured on interface %s, picking the first one (%s) for XSK. Set the 'source' parameter on 'newServer' if you want to use a different address.", ifName, addresses.at(0).toString());
    }
    d_config.sourceAddr = addresses.at(0);
  }
  d_config.sourceMACAddr = d_xskSockets.at(0)->getSourceMACAddress();

  for (auto& xsk : d_xskSockets) {
    auto xskInfo = XskWorker::create(XskWorker::Type::Bidirectional, xsk->sharedEmptyFrameOffset);
    d_xskInfos.push_back(xskInfo);
    xsk->addWorker(xskInfo);
  }
  reconnect(false);
}
#endif /* HAVE_XSK */

bool DownstreamState::parseSourceParameter(const std::string& source, DownstreamState::Config& config)
{
  /* handle source in the following forms:
     - v4 address ("192.0.2.1")
     - v6 address ("2001:DB8::1")
     - interface name ("eth0")
     - v4 address and interface name ("192.0.2.1@eth0")
     - v6 address and interface name ("2001:DB8::1@eth0")
  */
  std::string::size_type pos = source.find('@');
  if (pos == std::string::npos) {
    /* no '@', try to parse that as a valid v4/v6 address */
    try {
      config.sourceAddr = ComboAddress(source);
      return true;
    }
    catch (...) {
    }
  }

  /* try to parse as interface name, or v4/v6@itf */
  config.sourceItfName = source.substr(pos == std::string::npos ? 0 : pos + 1);
  unsigned int itfIdx = if_nametoindex(config.sourceItfName.c_str());
  if (itfIdx != 0) {
    if (pos == 0 || pos == std::string::npos) {
      /* "eth0" or "@eth0" */
      config.sourceItf = itfIdx;
    }
    else {
      /* "192.0.2.1@eth0" */
      config.sourceAddr = ComboAddress(source.substr(0, pos));
      config.sourceItf = itfIdx;
    }
#ifdef SO_BINDTODEVICE
    if (!dnsdist::configuration::isImmutableConfigurationDone()) {
      /* we need to retain CAP_NET_RAW to be able to set SO_BINDTODEVICE in the health checks */
      dnsdist::configuration::updateImmutableConfiguration([](dnsdist::configuration::ImmutableConfiguration& currentConfig) {
        currentConfig.d_capabilitiesToRetain.insert("CAP_NET_RAW");
      });
    }
#endif
    return true;
  }

  warnlog("Dismissing source %s because '%s' is not a valid interface name", source, config.sourceItfName);
  return false;
}

bool DownstreamState::parseAvailabilityConfigFromStr(DownstreamState::Config& config, const std::string& str)
{
  if (pdns_iequals(str, "auto")) {
    config.d_availability = DownstreamState::Availability::Auto;
    config.d_healthCheckMode = DownstreamState::HealthCheckMode::Active;
    return true;
  }
  if (pdns_iequals(str, "lazy")) {
    config.d_availability = DownstreamState::Availability::Auto;
    config.d_healthCheckMode = DownstreamState::HealthCheckMode::Lazy;
    return true;
  }
  if (pdns_iequals(str, "up")) {
    config.d_availability = DownstreamState::Availability::Up;
    return true;
  }
  if (pdns_iequals(str, "down")) {
    config.d_availability = DownstreamState::Availability::Down;
    return true;
  }
  return false;
}

unsigned int DownstreamState::getQPSLimit() const
{
  return d_qpsLimiter ? d_qpsLimiter->getRate() : 0U;
}

size_t ServerPool::countServers(bool upOnly)
{
  std::shared_ptr<const ServerPolicy::NumberedServerVector> servers = nullptr;
  {
    auto lock = d_servers.read_lock();
    servers = *lock;
  }

  size_t count = 0;
  for (const auto& server : *servers) {
    if (!upOnly || std::get<1>(server)->isUp() ) {
      count++;
    }
  }

  return count;
}

size_t ServerPool::poolLoad()
{
  std::shared_ptr<const ServerPolicy::NumberedServerVector> servers = nullptr;
  {
    auto lock = d_servers.read_lock();
    servers = *lock;
  }

  size_t load = 0;
  for (const auto& server : *servers) {
    size_t serverOutstanding = std::get<1>(server)->outstanding.load();
    load += serverOutstanding;
  }
  return load;
}

const std::shared_ptr<const ServerPolicy::NumberedServerVector> ServerPool::getServers()
{
  std::shared_ptr<const ServerPolicy::NumberedServerVector> result;
  {
    result = *(d_servers.read_lock());
  }
  return result;
}

void ServerPool::addServer(shared_ptr<DownstreamState>& server)
{
  auto servers = d_servers.write_lock();
  /* we can't update the content of the shared pointer directly even when holding the lock,
     as other threads might hold a copy. We can however update the pointer as long as we hold the lock. */
  unsigned int count = static_cast<unsigned int>((*servers)->size());
  auto newServers = ServerPolicy::NumberedServerVector(*(*servers));
  newServers.emplace_back(++count, server);
  /* we need to reorder based on the server 'order' */
  std::stable_sort(newServers.begin(), newServers.end(), [](const std::pair<unsigned int,std::shared_ptr<DownstreamState> >& a, const std::pair<unsigned int,std::shared_ptr<DownstreamState> >& b) {
      return a.second->d_config.order < b.second->d_config.order;
    });
  /* and now we need to renumber for Lua (custom policies) */
  size_t idx = 1;
  for (auto& serv : newServers) {
    serv.first = idx++;
  }
  *servers = std::make_shared<const ServerPolicy::NumberedServerVector>(std::move(newServers));

  if ((*servers)->size() == 1) {
    d_tcpOnly = server->isTCPOnly();
  }
  else if (!server->isTCPOnly()) {
    d_tcpOnly = false;
  }
}

void ServerPool::removeServer(shared_ptr<DownstreamState>& server)
{
  auto servers = d_servers.write_lock();
  /* we can't update the content of the shared pointer directly even when holding the lock,
     as other threads might hold a copy. We can however update the pointer as long as we hold the lock. */
  auto newServers = std::make_shared<ServerPolicy::NumberedServerVector>(*(*servers));
  size_t idx = 1;
  bool found = false;
  bool tcpOnly = true;
  for (auto it = newServers->begin(); it != newServers->end();) {
    if (found) {
      tcpOnly = tcpOnly && it->second->isTCPOnly();
      /* we need to renumber the servers placed
         after the removed one, for Lua (custom policies) */
      it->first = idx++;
      it++;
    }
    else if (it->second == server) {
      it = newServers->erase(it);
      found = true;
    } else {
      tcpOnly = tcpOnly && it->second->isTCPOnly();
      idx++;
      it++;
    }
  }
  d_tcpOnly = tcpOnly;
  *servers = std::move(newServers);
}

namespace dnsdist::backend
{
void registerNewBackend(std::shared_ptr<DownstreamState>& backend)
{
  dnsdist::configuration::updateRuntimeConfiguration([&backend](dnsdist::configuration::RuntimeConfiguration& config) {
    auto& backends = config.d_backends;
    backends.push_back(backend);
    std::stable_sort(backends.begin(), backends.end(), [](const std::shared_ptr<DownstreamState>& lhs, const std::shared_ptr<DownstreamState>& rhs) {
      return lhs->d_config.order < rhs->d_config.order;
    });
  });
}
}
