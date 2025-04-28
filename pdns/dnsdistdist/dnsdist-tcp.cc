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

#include <thread>
#include <netinet/tcp.h>
#include <queue>
#include <boost/format.hpp>

#include "dnsdist.hh"
#include "dnsdist-concurrent-connections.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-edns.hh"
#include "dnsdist-nghttp2-in.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-downstream-connection.hh"
#include "dnsdist-tcp-upstream.hh"
#include "dnsparser.hh"
#include "dolog.hh"
#include "gettime.hh"
#include "lock.hh"
#include "sstuff.hh"
#include "tcpiohandler.hh"
#include "tcpiohandler-mplexer.hh"
#include "threadname.hh"

/* TCP: the grand design.
   We forward 'messages' between clients and downstream servers. Messages are 65k bytes large, tops.
   An answer might theoretically consist of multiple messages (for example, in the case of AXFR), initially
   we will not go there.

   In a sense there is a strong symmetry between UDP and TCP, once a connection to a downstream has been setup.
   This symmetry is broken because of head-of-line blocking within TCP though, necessitating additional connections
   to guarantee performance.

   So the idea is to have a 'pool' of available downstream connections, and forward messages to/from them and never queue.
   So whenever an answer comes in, we know where it needs to go.

   Let's start naively.
*/

std::atomic<uint64_t> g_tcpStatesDumpRequested{0};

IncomingTCPConnectionState::~IncomingTCPConnectionState()
{
  dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(d_ci.remote);

  if (d_ci.cs != nullptr) {
    timeval now{};
    gettimeofday(&now, nullptr);

    auto diff = now - d_connectionStartTime;
    d_ci.cs->updateTCPMetrics(d_queriesCount, diff.tv_sec * 1000 + diff.tv_usec / 1000, d_queriesCount > 0 ? d_readIOsTotal / d_queriesCount : d_readIOsTotal);
  }

  // would have been done when the object is destroyed anyway,
  // but that way we make sure it's done before the ConnectionInfo is destroyed,
  // closing the descriptor, instead of relying on the declaration order of the objects in the class
  d_handler.close();
}

dnsdist::Protocol IncomingTCPConnectionState::getProtocol() const
{
  if (d_ci.cs->dohFrontend) {
    return dnsdist::Protocol::DoH;
  }
  if (d_handler.isTLS()) {
    return dnsdist::Protocol::DoT;
  }
  return dnsdist::Protocol::DoTCP;
}

size_t IncomingTCPConnectionState::clearAllDownstreamConnections()
{
  return t_downstreamTCPConnectionsManager.clear();
}

static std::pair<std::shared_ptr<TCPConnectionToBackend>, bool> getOwnedDownstreamConnection(std::map<std::shared_ptr<DownstreamState>, std::deque<std::shared_ptr<TCPConnectionToBackend>>>& ownedConnectionsToBackend, const std::shared_ptr<DownstreamState>& backend, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs)
{
  bool tlvsMismatch = false;
  auto connIt = ownedConnectionsToBackend.find(backend);
  if (connIt == ownedConnectionsToBackend.end()) {
    DEBUGLOG("no owned connection found for " << backend->getName());
    return {nullptr, tlvsMismatch};
  }

  for (auto& conn : connIt->second) {
    if (conn->canBeReused(true)) {
      if (conn->matchesTLVs(tlvs)) {
        DEBUGLOG("Got one owned connection accepting more for " << backend->getName());
        conn->setReused();
        ++backend->tcpReusedConnections;
        return {conn, tlvsMismatch};
      }
      DEBUGLOG("Found one connection to " << backend->getName() << " but with different TLV values");
      tlvsMismatch = true;
    }
    DEBUGLOG("not accepting more for " << backend->getName());
  }

  return {nullptr, tlvsMismatch};
}

bool IncomingTCPConnectionState::isNearTCPLimits() const
{
  if (d_ci.d_restricted) {
    return true;
  }

  const auto tcpConnectionsOverloadThreshold = dnsdist::configuration::getImmutableConfiguration().d_tcpConnectionsOverloadThreshold;
  if (tcpConnectionsOverloadThreshold == 0) {
    return false;
  }

  const auto& clientState = d_ci.cs;
  if (clientState->d_tcpConcurrentConnectionsLimit > 0) {
    auto concurrentConnections = clientState->tcpCurrentConnections.load();
    auto current = (100 * concurrentConnections) / clientState->d_tcpConcurrentConnectionsLimit;
    if (current >= tcpConnectionsOverloadThreshold) {
      return true;
    }
  }

  return dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(d_ci.remote);
}

std::shared_ptr<TCPConnectionToBackend> IncomingTCPConnectionState::getDownstreamConnection(std::shared_ptr<DownstreamState>& backend, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs, const struct timeval& now)
{
  auto [downstream, tlvsMismatch] = getOwnedDownstreamConnection(d_ownedConnectionsToBackend, backend, tlvs);

  if (!downstream) {
    if (backend->d_config.useProxyProtocol && tlvsMismatch) {
      clearOwnedDownstreamConnections(backend);
    }

    /* we don't have a connection to this backend owned yet, let's get one (it might not be a fresh one, though) */
    downstream = t_downstreamTCPConnectionsManager.getConnectionToDownstream(d_threadData.mplexer, backend, now, std::string());
    // if we had an existing connection but the TLVs are different, they are likely unique per query so do not bother keeping the connection
    // around
    if (backend->d_config.useProxyProtocol && !tlvsMismatch) {
      registerOwnedDownstreamConnection(downstream);
    }
  }

  return downstream;
}

static void tcpClientThread(pdns::channel::Receiver<ConnectionInfo>&& queryReceiver, pdns::channel::Receiver<CrossProtocolQuery>&& crossProtocolQueryReceiver, pdns::channel::Receiver<TCPCrossProtocolResponse>&& crossProtocolResponseReceiver, pdns::channel::Sender<TCPCrossProtocolResponse>&& crossProtocolResponseSender, std::vector<ClientState*> tcpAcceptStates);

TCPClientCollection::TCPClientCollection(size_t maxThreads, std::vector<ClientState*> tcpAcceptStates) :
  d_tcpclientthreads(maxThreads), d_maxthreads(maxThreads)
{
  for (size_t idx = 0; idx < maxThreads; idx++) {
    addTCPClientThread(tcpAcceptStates);
  }
}

void TCPClientCollection::addTCPClientThread(std::vector<ClientState*>& tcpAcceptStates)
{
  try {
    const auto internalPipeBufferSize = dnsdist::configuration::getImmutableConfiguration().d_tcpInternalPipeBufferSize;

    auto [queryChannelSender, queryChannelReceiver] = pdns::channel::createObjectQueue<ConnectionInfo>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, internalPipeBufferSize);

    auto [crossProtocolQueryChannelSender, crossProtocolQueryChannelReceiver] = pdns::channel::createObjectQueue<CrossProtocolQuery>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, internalPipeBufferSize);

    auto [crossProtocolResponseChannelSender, crossProtocolResponseChannelReceiver] = pdns::channel::createObjectQueue<TCPCrossProtocolResponse>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, internalPipeBufferSize);

    vinfolog("Adding TCP Client thread");

    if (d_numthreads >= d_tcpclientthreads.size()) {
      vinfolog("Adding a new TCP client thread would exceed the vector size (%d/%d), skipping. Consider increasing the maximum amount of TCP client threads with setMaxTCPClientThreads() in the configuration.", d_numthreads.load(), d_tcpclientthreads.size());
      return;
    }

    TCPWorkerThread worker(std::move(queryChannelSender), std::move(crossProtocolQueryChannelSender));

    try {
      std::thread clientThread(tcpClientThread, std::move(queryChannelReceiver), std::move(crossProtocolQueryChannelReceiver), std::move(crossProtocolResponseChannelReceiver), std::move(crossProtocolResponseChannelSender), tcpAcceptStates);
      clientThread.detach();
    }
    catch (const std::runtime_error& e) {
      errlog("Error creating a TCP thread: %s", e.what());
      return;
    }

    d_tcpclientthreads.at(d_numthreads) = std::move(worker);
    ++d_numthreads;
  }
  catch (const std::exception& e) {
    errlog("Error creating TCP worker: %s", e.what());
  }
}

std::unique_ptr<TCPClientCollection> g_tcpclientthreads;

static IOState sendQueuedResponses(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now)
{
  IOState result = IOState::Done;

  while (state->active() && !state->d_queuedResponses.empty()) {
    DEBUGLOG("queue size is " << state->d_queuedResponses.size() << ", sending the next one");
    TCPResponse resp = std::move(state->d_queuedResponses.front());
    state->d_queuedResponses.pop_front();
    state->d_state = IncomingTCPConnectionState::State::idle;
    result = state->sendResponse(now, std::move(resp));
    if (result != IOState::Done) {
      return result;
    }
  }

  state->d_state = IncomingTCPConnectionState::State::idle;
  return IOState::Done;
}

void IncomingTCPConnectionState::handleResponseSent(TCPResponse& currentResponse, size_t sentBytes)
{
  if (currentResponse.d_idstate.qtype == QType::AXFR || currentResponse.d_idstate.qtype == QType::IXFR) {
    return;
  }

  --d_currentQueriesCount;

  const auto& backend = currentResponse.d_connection ? currentResponse.d_connection->getDS() : currentResponse.d_ds;
  if (!currentResponse.d_idstate.selfGenerated && backend) {
    const auto& ids = currentResponse.d_idstate;
    double udiff = ids.queryRealTime.udiff();
    vinfolog("Got answer from %s, relayed to %s (%s, %d bytes), took %f us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), getProtocol().toString(), sentBytes, udiff);

    auto backendProtocol = backend->getProtocol();
    if (backendProtocol == dnsdist::Protocol::DoUDP && !currentResponse.d_idstate.forwardedOverUDP) {
      backendProtocol = dnsdist::Protocol::DoTCP;
    }
    ::handleResponseSent(ids, udiff, d_ci.remote, backend->d_config.remote, static_cast<unsigned int>(sentBytes), currentResponse.d_cleartextDH, backendProtocol, true);
  }
  else {
    const auto& ids = currentResponse.d_idstate;
    ::handleResponseSent(ids, 0., d_ci.remote, ComboAddress(), static_cast<unsigned int>(currentResponse.d_buffer.size()), currentResponse.d_cleartextDH, ids.protocol, false);
  }

  currentResponse.d_buffer.clear();
  currentResponse.d_connection.reset();
}

static void prependSizeToTCPQuery(PacketBuffer& buffer, size_t proxyProtocolPayloadSize)
{
  if (buffer.size() <= proxyProtocolPayloadSize) {
    throw std::runtime_error("The payload size is smaller or equal to the buffer size");
  }

  uint16_t queryLen = proxyProtocolPayloadSize > 0 ? (buffer.size() - proxyProtocolPayloadSize) : buffer.size();
  const std::array<uint8_t, 2> sizeBytes{static_cast<uint8_t>(queryLen / 256), static_cast<uint8_t>(queryLen % 256)};
  /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
     that could occur if we had to deal with the size during the processing,
     especially alignment issues */
  buffer.insert(buffer.begin() + static_cast<PacketBuffer::iterator::difference_type>(proxyProtocolPayloadSize), sizeBytes.begin(), sizeBytes.end());
}

bool IncomingTCPConnectionState::canAcceptNewQueries(const struct timeval& now)
{
  if (d_hadErrors) {
    DEBUGLOG("not accepting new queries because we encountered some error during the processing already");
    return false;
  }

  if (isNearTCPLimits()) {
    d_ci.d_restricted = true;
    DEBUGLOG("not accepting new queries because we already near our TCP limits");
    return false;
  }

  // for DoH, this is already handled by the underlying library
  if (!d_ci.cs->dohFrontend && d_currentQueriesCount >= d_ci.cs->d_maxInFlightQueriesPerConn) {
    DEBUGLOG("not accepting new queries because we already have " << d_currentQueriesCount << " out of " << d_ci.cs->d_maxInFlightQueriesPerConn);
    return false;
  }

  const auto& currentConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (currentConfig.d_maxTCPQueriesPerConn != 0 && d_queriesCount > currentConfig.d_maxTCPQueriesPerConn) {
    vinfolog("not accepting new queries from %s because it reached the maximum number of queries per conn (%d / %d)", d_ci.remote.toStringWithPort(), d_queriesCount, currentConfig.d_maxTCPQueriesPerConn);
    return false;
  }

  if (maxConnectionDurationReached(currentConfig.d_maxTCPConnectionDuration, now)) {
    vinfolog("not accepting new queries from %s because it reached the maximum TCP connection duration", d_ci.remote.toStringWithPort());
    return false;
  }

  return true;
}

void IncomingTCPConnectionState::resetForNewQuery()
{
  d_buffer.clear();
  d_currentPos = 0;
  d_querySize = 0;
  d_state = State::waitingForQuery;
  d_readIOsTotal += d_readIOsCurrentQuery;
  d_readIOsCurrentQuery = 0;
}

boost::optional<timeval> IncomingTCPConnectionState::getClientReadTTD(timeval now) const
{
  const auto& runtimeConfiguration = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (!isNearTCPLimits() && runtimeConfiguration.d_maxTCPConnectionDuration == 0 && runtimeConfiguration.d_tcpRecvTimeout == 0) {
    return boost::none;
  }

  size_t maxTCPConnectionDuration = runtimeConfiguration.d_maxTCPConnectionDuration;
  uint16_t tcpRecvTimeout = runtimeConfiguration.d_tcpRecvTimeout;
  uint32_t tcpRecvTimeoutUsec = 0U;
  if (isNearTCPLimits()) {
    constexpr size_t maxTCPConnectionDurationNearLimits = 5U;
    constexpr uint32_t tcpRecvTimeoutUsecNearLimits = 500U * 1000U;
    maxTCPConnectionDuration = runtimeConfiguration.d_maxTCPConnectionDuration != 0 ? std::min(runtimeConfiguration.d_maxTCPConnectionDuration, maxTCPConnectionDurationNearLimits) : maxTCPConnectionDurationNearLimits;
    tcpRecvTimeout = 0;
    tcpRecvTimeoutUsec = tcpRecvTimeoutUsecNearLimits;
  }

  if (maxTCPConnectionDuration > 0) {
    auto elapsed = now.tv_sec - d_connectionStartTime.tv_sec;
    if (elapsed < 0 || (static_cast<size_t>(elapsed) >= maxTCPConnectionDuration)) {
      return now;
    }
    auto remaining = maxTCPConnectionDuration - elapsed;
    if (!isNearTCPLimits() && (runtimeConfiguration.d_tcpRecvTimeout == 0 || remaining <= static_cast<size_t>(runtimeConfiguration.d_tcpRecvTimeout))) {
      now.tv_sec += static_cast<time_t>(remaining);
      return now;
    }
  }

  now.tv_sec += static_cast<time_t>(tcpRecvTimeout);
  now.tv_usec += tcpRecvTimeoutUsec;
  normalizeTV(now);
  return now;
}

boost::optional<timeval> IncomingTCPConnectionState::getClientWriteTTD(const timeval& now) const
{
  const auto& runtimeConfiguration = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (runtimeConfiguration.d_maxTCPConnectionDuration == 0 && runtimeConfiguration.d_tcpSendTimeout == 0) {
    return boost::none;
  }

  timeval res(now);

  if (runtimeConfiguration.d_maxTCPConnectionDuration > 0) {
    auto elapsed = res.tv_sec - d_connectionStartTime.tv_sec;
    if (elapsed < 0 || static_cast<size_t>(elapsed) >= runtimeConfiguration.d_maxTCPConnectionDuration) {
      return res;
    }
    auto remaining = runtimeConfiguration.d_maxTCPConnectionDuration - elapsed;
    if (runtimeConfiguration.d_tcpSendTimeout == 0 || remaining <= static_cast<size_t>(runtimeConfiguration.d_tcpSendTimeout)) {
      res.tv_sec += static_cast<time_t>(remaining);
      return res;
    }
  }

  res.tv_sec += static_cast<time_t>(runtimeConfiguration.d_tcpSendTimeout);
  return res;
}

bool IncomingTCPConnectionState::maxConnectionDurationReached(unsigned int maxConnectionDuration, const timeval& now) const
{
  if (maxConnectionDuration > 0) {
    time_t curtime = now.tv_sec;
    unsigned int elapsed = 0;
    if (curtime > d_connectionStartTime.tv_sec) { // To prevent issues when time goes backward
      elapsed = curtime - d_connectionStartTime.tv_sec;
    }
    if (elapsed >= maxConnectionDuration) {
      return true;
    }
  }

  return false;
}

void IncomingTCPConnectionState::registerOwnedDownstreamConnection(std::shared_ptr<TCPConnectionToBackend>& conn)
{
  const auto& downstream = conn->getDS();
  auto& queue = d_ownedConnectionsToBackend[downstream];
  // how many proxy-protocol enabled connections do we want to keep around?
  // - they are only usable for this incoming connection because of the proxy protocol header containing the source and destination addresses and ports
  // - if we have TLV values, and they are unique per query, keeping these is useless
  // - if there is no, or identical, TLV values, a single outgoing connection is enough if maxInFlight == 1, or if incoming maxInFlight == outgoing maxInFlight
  // so it makes sense to keep a few of them around if incoming maxInFlight is greater than outgoing maxInFlight

  auto incomingMaxInFlightQueriesPerConn = d_ci.cs->d_maxInFlightQueriesPerConn;
  incomingMaxInFlightQueriesPerConn = std::max(incomingMaxInFlightQueriesPerConn, static_cast<size_t>(1U));
  auto outgoingMaxInFlightQueriesPerConn = downstream->d_config.d_maxInFlightQueriesPerConn;
  outgoingMaxInFlightQueriesPerConn = std::max(outgoingMaxInFlightQueriesPerConn, static_cast<size_t>(1U));
  size_t maxCachedOutgoingConnections = std::min(static_cast<size_t>(incomingMaxInFlightQueriesPerConn / outgoingMaxInFlightQueriesPerConn), static_cast<size_t>(5U));

  queue.push_front(conn);
  if (queue.size() > maxCachedOutgoingConnections) {
    queue.pop_back();
  }
}

void IncomingTCPConnectionState::clearOwnedDownstreamConnections(const std::shared_ptr<DownstreamState>& downstream)
{
  d_ownedConnectionsToBackend.erase(downstream);
}

/* called when the buffer has been set and the rules have been processed, and only from handleIO (sometimes indirectly via handleQuery) */
IOState IncomingTCPConnectionState::sendResponse(const struct timeval& now, TCPResponse&& response)
{
  (void)now;
  d_state = State::sendingResponse;

  const auto responseSize = static_cast<uint16_t>(response.d_buffer.size());
  const std::array<uint8_t, 2> sizeBytes{static_cast<uint8_t>(responseSize / 256), static_cast<uint8_t>(responseSize % 256)};
  /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
     that could occur if we had to deal with the size during the processing,
     especially alignment issues */
  response.d_buffer.insert(response.d_buffer.begin(), sizeBytes.begin(), sizeBytes.end());
  d_currentPos = 0;
  d_currentResponse = std::move(response);

  try {
    auto iostate = d_handler.tryWrite(d_currentResponse.d_buffer, d_currentPos, d_currentResponse.d_buffer.size());
    if (iostate == IOState::Done) {
      DEBUGLOG("response sent from " << __PRETTY_FUNCTION__);
      handleResponseSent(d_currentResponse, d_currentResponse.d_buffer.size());
      return iostate;
    }
    d_lastIOBlocked = true;
    DEBUGLOG("partial write");
    return iostate;
  }
  catch (const std::exception& e) {
    vinfolog("Closing TCP client connection with %s: %s", d_ci.remote.toStringWithPort(), e.what());
    DEBUGLOG("Closing TCP client connection: " << e.what());
    ++d_ci.cs->tcpDiedSendingResponse;

    terminateClientConnection();

    return IOState::Done;
  }
}

void IncomingTCPConnectionState::terminateClientConnection()
{
  DEBUGLOG("terminating client connection");
  d_queuedResponses.clear();
  /* we have already released idle connections that could be reused,
     we don't care about the ones still waiting for responses */
  for (auto& backend : d_ownedConnectionsToBackend) {
    for (auto& conn : backend.second) {
      conn->release(true);
    }
  }
  d_ownedConnectionsToBackend.clear();

  /* meaning we will no longer be 'active' when the backend
     response or timeout comes in */
  d_ioState.reset();

  /* if we do have remaining async descriptors associated with this TLS
     connection, we need to defer the destruction of the TLS object until
     the engine has reported back, otherwise we have a use-after-free.. */
  auto afds = d_handler.getAsyncFDs();
  if (afds.empty()) {
    d_handler.close();
  }
  else {
    /* we might already be waiting, but we might also not because sometimes we have already been
       notified via the descriptor, not received Async again, but the async job still exists.. */
    auto state = shared_from_this();
    for (const auto desc : afds) {
      try {
        state->d_threadData.mplexer->addReadFD(desc, handleAsyncReady, state);
      }
      catch (...) {
      }
    }
  }
}

void IncomingTCPConnectionState::queueResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response, bool fromBackend)
{
  // queue response
  state->d_queuedResponses.emplace_back(std::move(response));
  DEBUGLOG("queueing response, state is " << (int)state->d_state << ", queue size is now " << state->d_queuedResponses.size());

  // when the response comes from a backend, there is a real possibility that we are currently
  // idle, and thus not trying to send the response right away would make our ref count go to 0.
  // Even if we are waiting for a query, we will not wake up before the new query arrives or a
  // timeout occurs
  if (state->d_state == State::idle || state->d_state == State::waitingForQuery) {
    auto iostate = sendQueuedResponses(state, now);

    if (iostate == IOState::Done && state->active()) {
      if (state->canAcceptNewQueries(now)) {
        state->resetForNewQuery();
        state->d_state = State::waitingForQuery;
        iostate = IOState::NeedRead;
      }
      else {
        state->d_state = State::idle;
      }
    }

    // for the same reason we need to update the state right away, nobody will do that for us
    if (state->active()) {
      state->updateIO(iostate, now);
      // if we have not finished reading every available byte, we _need_ to do an actual read
      // attempt before waiting for the socket to become readable again, because if there is
      // buffered data available the socket might never become readable again.
      // This is true as soon as we deal with TLS because TLS records are processed one by
      // one and might not match what we see at the application layer, so data might already
      // be available in the TLS library's buffers. This is especially true when OpenSSL's
      // read-ahead mode is enabled because then it buffers even more than one SSL record
      // for performance reasons.
      if (fromBackend && !state->d_lastIOBlocked) {
        state->handleIO();
      }
    }
  }
}

void IncomingTCPConnectionState::handleAsyncReady([[maybe_unused]] int desc, FDMultiplexer::funcparam_t& param)
{
  auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);

  /* If we are here, the async jobs for this SSL* are finished
     so we should be able to remove all FDs */
  auto afds = state->d_handler.getAsyncFDs();
  for (const auto afd : afds) {
    try {
      state->d_threadData.mplexer->removeReadFD(afd);
    }
    catch (...) {
    }
  }

  if (state->active()) {
    /* and now we restart our own I/O state machine */
    state->handleIO();
  }
  else {
    /* we were only waiting for the engine to come back,
       to prevent a use-after-free */
    state->d_handler.close();
  }
}

void IncomingTCPConnectionState::updateIOForAsync(std::shared_ptr<IncomingTCPConnectionState>& conn)
{
  auto fds = conn->d_handler.getAsyncFDs();
  for (const auto desc : fds) {
    conn->d_threadData.mplexer->addReadFD(desc, handleAsyncReady, conn);
  }
  conn->d_ioState->update(IOState::Done, handleIOCallback, conn);
}

void IncomingTCPConnectionState::updateIO(IOState newState, const struct timeval& now)
{
  auto sharedPtrToConn = shared_from_this();
  if (newState == IOState::Async) {
    updateIOForAsync(sharedPtrToConn);
    return;
  }

  d_ioState->update(newState, handleIOCallback, sharedPtrToConn, newState == IOState::NeedWrite ? getClientWriteTTD(now) : getClientReadTTD(now));
}

/* called from the backend code when a new response has been received */
void IncomingTCPConnectionState::handleResponse(const struct timeval& now, TCPResponse&& response)
{
  if (std::this_thread::get_id() != d_creatorThreadID) {
    handleCrossProtocolResponse(now, std::move(response));
    return;
  }

  std::shared_ptr<IncomingTCPConnectionState> state = shared_from_this();

  if (!response.isAsync() && response.d_connection && response.d_connection->getDS() && response.d_connection->getDS()->d_config.useProxyProtocol) {
    // if we have added a TCP Proxy Protocol payload to a connection, don't release it to the general pool as no one else will be able to use it anyway
    if (!response.d_connection->willBeReusable(true)) {
      // if it can't be reused even by us, well
      const auto connIt = state->d_ownedConnectionsToBackend.find(response.d_connection->getDS());
      if (connIt != state->d_ownedConnectionsToBackend.end()) {
        auto& list = connIt->second;

        for (auto it = list.begin(); it != list.end(); ++it) {
          if (*it == response.d_connection) {
            try {
              response.d_connection->release(true);
            }
            catch (const std::exception& e) {
              vinfolog("Error releasing connection: %s", e.what());
            }
            list.erase(it);
            break;
          }
        }
      }
    }
  }

  if (response.d_buffer.size() < sizeof(dnsheader)) {
    state->terminateClientConnection();
    return;
  }

  if (!response.isAsync()) {
    try {
      auto& ids = response.d_idstate;
      std::shared_ptr<DownstreamState> backend = response.d_ds ? response.d_ds : (response.d_connection ? response.d_connection->getDS() : nullptr);
      if (backend == nullptr || !responseContentMatches(response.d_buffer, ids.qname, ids.qtype, ids.qclass, backend, dnsdist::configuration::getCurrentRuntimeConfiguration().d_allowEmptyResponse)) {
        state->terminateClientConnection();
        return;
      }

      if (backend != nullptr) {
        ++backend->responses;
      }

      DNSResponse dnsResponse(ids, response.d_buffer, backend);
      dnsResponse.d_incomingTCPState = state;

      memcpy(&response.d_cleartextDH, dnsResponse.getHeader().get(), sizeof(response.d_cleartextDH));

      if (!processResponse(response.d_buffer, dnsResponse, false)) {
        state->terminateClientConnection();
        return;
      }

      if (dnsResponse.isAsynchronous()) {
        /* we are done for now */
        return;
      }
    }
    catch (const std::exception& e) {
      vinfolog("Unexpected exception while handling response from backend: %s", e.what());
      state->terminateClientConnection();
      return;
    }
  }

  ++dnsdist::metrics::g_stats.responses;
  ++state->d_ci.cs->responses;

  queueResponse(state, now, std::move(response), true);
}

struct TCPCrossProtocolResponse
{
  TCPCrossProtocolResponse(TCPResponse&& response, std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now) :
    d_response(std::move(response)), d_state(state), d_now(now)
  {
  }
  TCPCrossProtocolResponse(const TCPCrossProtocolResponse&) = delete;
  TCPCrossProtocolResponse& operator=(const TCPCrossProtocolResponse&) = delete;
  TCPCrossProtocolResponse(TCPCrossProtocolResponse&&) = delete;
  TCPCrossProtocolResponse& operator=(TCPCrossProtocolResponse&&) = delete;
  ~TCPCrossProtocolResponse() = default;

  TCPResponse d_response;
  std::shared_ptr<IncomingTCPConnectionState> d_state;
  struct timeval d_now;
};

class TCPCrossProtocolQuery : public CrossProtocolQuery
{
public:
  TCPCrossProtocolQuery(PacketBuffer&& buffer, InternalQueryState&& ids, std::shared_ptr<DownstreamState> backend, std::shared_ptr<IncomingTCPConnectionState> sender) :
    CrossProtocolQuery(InternalQuery(std::move(buffer), std::move(ids)), backend), d_sender(std::move(sender))
  {
  }
  TCPCrossProtocolQuery(const TCPCrossProtocolQuery&) = delete;
  TCPCrossProtocolQuery& operator=(const TCPCrossProtocolQuery&) = delete;
  TCPCrossProtocolQuery(TCPCrossProtocolQuery&&) = delete;
  TCPCrossProtocolQuery& operator=(TCPCrossProtocolQuery&&) = delete;
  ~TCPCrossProtocolQuery() override = default;

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    return d_sender;
  }

  DNSQuestion getDQ() override
  {
    auto& ids = query.d_idstate;
    DNSQuestion dnsQuestion(ids, query.d_buffer);
    dnsQuestion.d_incomingTCPState = d_sender;
    return dnsQuestion;
  }

  DNSResponse getDR() override
  {
    auto& ids = query.d_idstate;
    DNSResponse dnsResponse(ids, query.d_buffer, downstream);
    dnsResponse.d_incomingTCPState = d_sender;
    return dnsResponse;
  }

private:
  std::shared_ptr<IncomingTCPConnectionState> d_sender;
};

std::unique_ptr<CrossProtocolQuery> IncomingTCPConnectionState::getCrossProtocolQuery(PacketBuffer&& query, InternalQueryState&& state, const std::shared_ptr<DownstreamState>& backend)
{
  return std::make_unique<TCPCrossProtocolQuery>(std::move(query), std::move(state), backend, shared_from_this());
}

std::unique_ptr<CrossProtocolQuery> getTCPCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion)
{
  auto state = dnsQuestion.getIncomingTCPState();
  if (!state) {
    throw std::runtime_error("Trying to create a TCP cross protocol query without a valid TCP state");
  }

  dnsQuestion.ids.origID = dnsQuestion.getHeader()->id;
  return std::make_unique<TCPCrossProtocolQuery>(std::move(dnsQuestion.getMutableData()), std::move(dnsQuestion.ids), nullptr, std::move(state));
}

void IncomingTCPConnectionState::handleCrossProtocolResponse(const struct timeval& now, TCPResponse&& response)
{
  std::shared_ptr<IncomingTCPConnectionState> state = shared_from_this();
  try {
    auto ptr = std::make_unique<TCPCrossProtocolResponse>(std::move(response), state, now);
    if (!state->d_threadData.crossProtocolResponseSender.send(std::move(ptr))) {
      ++dnsdist::metrics::g_stats.tcpCrossProtocolResponsePipeFull;
      vinfolog("Unable to pass a cross-protocol response to the TCP worker thread because the pipe is full");
    }
  }
  catch (const std::exception& e) {
    vinfolog("Unable to pass a cross-protocol response to the TCP worker thread because we couldn't write to the pipe: %s", stringerror());
  }
}

IncomingTCPConnectionState::QueryProcessingResult IncomingTCPConnectionState::handleQuery(PacketBuffer&& queryIn, const struct timeval& now, std::optional<int32_t> streamID)
{
  auto query = std::move(queryIn);
  if (query.size() < sizeof(dnsheader)) {
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    ++d_ci.cs->nonCompliantQueries;
    return QueryProcessingResult::TooSmall;
  }

  ++d_queriesCount;
  ++d_ci.cs->queries;
  ++dnsdist::metrics::g_stats.queries;

  if (d_handler.isTLS()) {
    auto tlsVersion = d_handler.getTLSVersion();
    switch (tlsVersion) {
    case LibsslTLSVersion::TLS10:
      ++d_ci.cs->tls10queries;
      break;
    case LibsslTLSVersion::TLS11:
      ++d_ci.cs->tls11queries;
      break;
    case LibsslTLSVersion::TLS12:
      ++d_ci.cs->tls12queries;
      break;
    case LibsslTLSVersion::TLS13:
      ++d_ci.cs->tls13queries;
      break;
    default:
      ++d_ci.cs->tlsUnknownqueries;
    }
  }

  auto state = shared_from_this();
  InternalQueryState ids;
  ids.origDest = d_proxiedDestination;
  ids.origRemote = d_proxiedRemote;
  ids.cs = d_ci.cs;
  ids.queryRealTime.start();
  if (streamID) {
    ids.d_streamID = *streamID;
  }

  auto dnsCryptResponse = checkDNSCryptQuery(*d_ci.cs, query, ids.dnsCryptQuery, ids.queryRealTime.d_start.tv_sec, true);
  if (dnsCryptResponse) {
    TCPResponse response;
    d_state = State::idle;
    ++d_currentQueriesCount;
    queueResponse(state, now, std::move(response), false);
    return QueryProcessingResult::SelfAnswered;
  }

  {
    /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
    const dnsheader_aligned dnsHeader(query.data());
    if (!checkQueryHeaders(*dnsHeader, *d_ci.cs)) {
      return QueryProcessingResult::InvalidHeaders;
    }

    if (dnsHeader->qdcount == 0) {
      TCPResponse response;
      auto queryID = dnsHeader->id;
      dnsdist::PacketMangling::editDNSHeaderFromPacket(query, [](dnsheader& header) {
        header.rcode = RCode::NotImp;
        header.qr = true;
        return true;
      });
      response.d_idstate = std::move(ids);
      response.d_idstate.origID = queryID;
      response.d_idstate.selfGenerated = true;
      response.d_buffer = std::move(query);
      d_state = State::idle;
      ++d_currentQueriesCount;
      queueResponse(state, now, std::move(response), false);
      return QueryProcessingResult::SelfAnswered;
    }
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast
  ids.qname = DNSName(reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
  ids.protocol = getProtocol();
  if (ids.dnsCryptQuery) {
    ids.protocol = dnsdist::Protocol::DNSCryptTCP;
  }

  DNSQuestion dnsQuestion(ids, query);
  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [&ids](dnsheader& header) {
    const uint16_t* flags = getFlagsFromDNSHeader(&header);
    ids.origFlags = *flags;
    return true;
  });
  dnsQuestion.d_incomingTCPState = state;
  dnsQuestion.sni = d_handler.getServerNameIndication();

  if (d_proxyProtocolValues) {
    /* we need to copy them, because the next queries received on that connection will
       need to get the _unaltered_ values */
    dnsQuestion.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(*d_proxyProtocolValues);
  }

  if (dnsQuestion.ids.qtype == QType::AXFR || dnsQuestion.ids.qtype == QType::IXFR) {
    dnsQuestion.ids.skipCache = true;
  }

  if (forwardViaUDPFirst()) {
    // if there was no EDNS, we add it with a large buffer size
    // so we can use UDP to talk to the backend.
    const dnsheader_aligned dnsHeader(query.data());
    if (dnsHeader->arcount == 0U) {
      if (addEDNS(query, 4096, false, 4096, 0)) {
        dnsQuestion.ids.ednsAdded = true;
      }
    }
  }

  if (streamID) {
    auto unit = getDOHUnit(*streamID);
    if (unit) {
      dnsQuestion.ids.du = std::move(unit);
    }
  }

  std::shared_ptr<DownstreamState> backend;
  auto result = processQuery(dnsQuestion, backend);

  if (result == ProcessQueryResult::Asynchronous) {
    /* we are done for now */
    ++d_currentQueriesCount;
    return QueryProcessingResult::Asynchronous;
  }

  if (streamID) {
    restoreDOHUnit(std::move(dnsQuestion.ids.du));
  }

  if (result == ProcessQueryResult::Drop) {
    return QueryProcessingResult::Dropped;
  }

  // the buffer might have been invalidated by now
  uint16_t queryID{0};
  {
    const auto dnsHeader = dnsQuestion.getHeader();
    queryID = dnsHeader->id;
  }

  if (result == ProcessQueryResult::SendAnswer) {
    TCPResponse response;
    {
      const auto dnsHeader = dnsQuestion.getHeader();
      memcpy(&response.d_cleartextDH, dnsHeader.get(), sizeof(response.d_cleartextDH));
    }
    response.d_idstate = std::move(ids);
    response.d_idstate.origID = queryID;
    response.d_idstate.selfGenerated = true;
    response.d_idstate.cs = d_ci.cs;
    response.d_buffer = std::move(query);

    d_state = State::idle;
    ++d_currentQueriesCount;
    queueResponse(state, now, std::move(response), false);
    return QueryProcessingResult::SelfAnswered;
  }

  if (result != ProcessQueryResult::PassToBackend || backend == nullptr) {
    return QueryProcessingResult::NoBackend;
  }

  dnsQuestion.ids.origID = queryID;

  ++d_currentQueriesCount;

  std::string proxyProtocolPayload;
  if (backend->isDoH()) {
    vinfolog("Got query for %s|%s from %s (%s, %d bytes), relayed to %s", ids.qname.toLogString(), QType(ids.qtype).toString(), d_proxiedRemote.toStringWithPort(), getProtocol().toString(), query.size(), backend->getNameWithAddr());

    /* we need to do this _before_ creating the cross protocol query because
       after that the buffer will have been moved */
    if (backend->d_config.useProxyProtocol) {
      proxyProtocolPayload = getProxyProtocolPayload(dnsQuestion);
    }

    auto cpq = std::make_unique<TCPCrossProtocolQuery>(std::move(query), std::move(ids), backend, state);
    cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

    backend->passCrossProtocolQuery(std::move(cpq));
    return QueryProcessingResult::Forwarded;
  }
  if (!backend->isTCPOnly() && forwardViaUDPFirst()) {
    if (streamID) {
      auto unit = getDOHUnit(*streamID);
      if (unit) {
        dnsQuestion.ids.du = std::move(unit);
      }
    }
    if (assignOutgoingUDPQueryToBackend(backend, queryID, dnsQuestion, query)) {
      return QueryProcessingResult::Forwarded;
    }
    restoreDOHUnit(std::move(dnsQuestion.ids.du));
    // fallback to the normal flow
  }

  prependSizeToTCPQuery(query, 0);

  auto downstreamConnection = getDownstreamConnection(backend, dnsQuestion.proxyProtocolValues, now);

  if (backend->d_config.useProxyProtocol) {
    /* if we ever sent a TLV over a connection, we can never go back */
    if (!d_proxyProtocolPayloadHasTLV) {
      d_proxyProtocolPayloadHasTLV = dnsQuestion.proxyProtocolValues && !dnsQuestion.proxyProtocolValues->empty();
    }

    proxyProtocolPayload = getProxyProtocolPayload(dnsQuestion);
  }

  if (dnsQuestion.proxyProtocolValues) {
    downstreamConnection->setProxyProtocolValuesSent(std::move(dnsQuestion.proxyProtocolValues));
  }

  TCPQuery tcpquery(std::move(query), std::move(ids));
  tcpquery.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

  vinfolog("Got query for %s|%s from %s (%s, %d bytes), relayed to %s", tcpquery.d_idstate.qname.toLogString(), QType(tcpquery.d_idstate.qtype).toString(), d_proxiedRemote.toStringWithPort(), getProtocol().toString(), tcpquery.d_buffer.size(), backend->getNameWithAddr());
  std::shared_ptr<TCPQuerySender> incoming = state;
  downstreamConnection->queueQuery(incoming, std::move(tcpquery));
  return QueryProcessingResult::Forwarded;
}

void IncomingTCPConnectionState::handleIOCallback(int desc, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);
  if (desc != conn->d_handler.getDescriptor()) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay): __PRETTY_FUNCTION__ is fine
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(desc) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->d_handler.getDescriptor()));
  }

  conn->handleIO();
}

void IncomingTCPConnectionState::handleHandshakeDone(const struct timeval& now)
{
  if (d_handler.isTLS()) {
    if (!d_handler.hasTLSSessionBeenResumed()) {
      ++d_ci.cs->tlsNewSessions;
      dnsdist::IncomingConcurrentTCPConnectionsManager::accountTLSNewSession(d_ci.remote);
    }
    else {
      ++d_ci.cs->tlsResumptions;
      dnsdist::IncomingConcurrentTCPConnectionsManager::accountTLSResumedSession(d_ci.remote);
    }
    if (d_handler.getResumedFromInactiveTicketKey()) {
      ++d_ci.cs->tlsInactiveTicketKey;
    }
    if (d_handler.getUnknownTicketKey()) {
      ++d_ci.cs->tlsUnknownTicketKey;
    }
  }

  d_handshakeDoneTime = now;
}

IncomingTCPConnectionState::ProxyProtocolResult IncomingTCPConnectionState::handleProxyProtocolPayload()
{
  do {
    DEBUGLOG("reading proxy protocol header");
    auto iostate = d_handler.tryRead(d_buffer, d_currentPos, d_proxyProtocolNeed, false, isProxyPayloadOutsideTLS());
    if (iostate == IOState::Done) {
      d_buffer.resize(d_currentPos);
      ssize_t remaining = isProxyHeaderComplete(d_buffer);
      if (remaining == 0) {
        vinfolog("Unable to consume proxy protocol header in packet from TCP client %s", d_ci.remote.toStringWithPort());
        ++dnsdist::metrics::g_stats.proxyProtocolInvalid;
        return ProxyProtocolResult::Error;
      }
      if (remaining < 0) {
        d_proxyProtocolNeed += -remaining;
        d_buffer.resize(d_currentPos + d_proxyProtocolNeed);
        /* we need to keep reading, since we might have buffered data */
      }
      else {
        /* proxy header received */
        std::vector<ProxyProtocolValue> proxyProtocolValues;
        if (!handleProxyProtocol(d_ci.remote, true, dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL, d_buffer, d_proxiedRemote, d_proxiedDestination, proxyProtocolValues)) {
          vinfolog("Error handling the Proxy Protocol received from TCP client %s", d_ci.remote.toStringWithPort());
          return ProxyProtocolResult::Error;
        }

        if (!proxyProtocolValues.empty()) {
          d_proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
        }

        d_currentPos = 0;
        d_proxyProtocolNeed = 0;
        d_buffer.clear();
        return ProxyProtocolResult::Done;
      }
    }
    else {
      d_lastIOBlocked = true;
    }
  } while (active() && !d_lastIOBlocked);

  return ProxyProtocolResult::Reading;
}

IOState IncomingTCPConnectionState::handleHandshake(const struct timeval& now)
{
  DEBUGLOG("doing handshake");
  auto iostate = d_handler.tryHandshake();
  if (iostate == IOState::Done) {
    DEBUGLOG("handshake done");
    handleHandshakeDone(now);

    if (d_ci.cs != nullptr && d_ci.cs->d_enableProxyProtocol && !isProxyPayloadOutsideTLS() && expectProxyProtocolFrom(d_ci.remote)) {
      d_state = State::readingProxyProtocolHeader;
      d_buffer.resize(s_proxyProtocolMinimumHeaderSize);
      d_proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
    }
    else {
      d_state = State::readingQuerySize;
    }
  }
  else {
    d_lastIOBlocked = true;
  }

  return iostate;
}

IOState IncomingTCPConnectionState::handleIncomingQueryReceived(const struct timeval& now)
{
  DEBUGLOG("query received");
  d_buffer.resize(d_querySize);

  d_state = State::idle;
  auto processingResult = handleQuery(std::move(d_buffer), now, std::nullopt);
  switch (processingResult) {
  case QueryProcessingResult::TooSmall:
    /* fall-through */
  case QueryProcessingResult::InvalidHeaders:
    /* fall-through */
  case QueryProcessingResult::Dropped:
    /* fall-through */
  case QueryProcessingResult::NoBackend:
    terminateClientConnection();
    ;
  default:
    break;
  }

  /* the state might have been updated in the meantime, we don't want to override it
     in that case */
  if (active() && d_state != State::idle) {
    if (d_ioState->isWaitingForRead()) {
      return IOState::NeedRead;
    }
    if (d_ioState->isWaitingForWrite()) {
      return IOState::NeedWrite;
    }
    return IOState::Done;
  }
  return IOState::Done;
};

void IncomingTCPConnectionState::handleExceptionDuringIO(const std::exception& exp)
{
  if (d_state == State::idle || d_state == State::waitingForQuery) {
    /* no need to increase any counters in that case, the client is simply done with us */
  }
  else if (d_state == State::doingHandshake || d_state == State::readingProxyProtocolHeader || d_state == State::waitingForQuery || d_state == State::readingQuerySize || d_state == State::readingQuery) {
    ++d_ci.cs->tcpDiedReadingQuery;
  }
  else if (d_state == State::sendingResponse) {
    /* unlikely to happen here, the exception should be handled in sendResponse() */
    ++d_ci.cs->tcpDiedSendingResponse;
  }

  if (d_ioState->isWaitingForWrite() || d_queriesCount == 0) {
    DEBUGLOG("Got an exception while handling TCP query: " << exp.what());
    vinfolog("Got an exception while handling (%s) TCP query from %s: %s", (d_ioState->isWaitingForRead() ? "reading" : "writing"), d_ci.remote.toStringWithPort(), exp.what());
  }
  else {
    vinfolog("Closing TCP client connection with %s: %s", d_ci.remote.toStringWithPort(), exp.what());
    DEBUGLOG("Closing TCP client connection: " << exp.what());
  }
  /* remove this FD from the IO multiplexer */
  terminateClientConnection();
}

bool IncomingTCPConnectionState::readIncomingQuery(const timeval& now, IOState& iostate)
{
  if (!d_lastIOBlocked && (d_state == State::waitingForQuery || d_state == State::readingQuerySize)) {
    DEBUGLOG("reading query size");
    d_buffer.resize(sizeof(uint16_t));
    d_readIOsCurrentQuery++;
    iostate = d_handler.tryRead(d_buffer, d_currentPos, sizeof(uint16_t));
    if (d_currentPos > 0) {
      /* if we got at least one byte, we can't go around sending responses */
      d_state = State::readingQuerySize;
    }

    if (iostate == IOState::Done) {
      DEBUGLOG("query size received");
      d_state = State::readingQuery;
      d_querySizeReadTime = now;
      if (d_queriesCount == 0) {
        d_firstQuerySizeReadTime = now;
      }
      d_querySize = d_buffer.at(0) * 256 + d_buffer.at(1);
      if (d_querySize < sizeof(dnsheader)) {
        /* go away */
        terminateClientConnection();
        return true;
      }

      d_buffer.resize(d_querySize);
      d_currentPos = 0;
    }
    else {
      d_lastIOBlocked = true;
    }
  }

  if (!d_lastIOBlocked && d_state == State::readingQuery) {
    DEBUGLOG("reading query");
    d_readIOsCurrentQuery++;
    iostate = d_handler.tryRead(d_buffer, d_currentPos, d_querySize);
    if (iostate == IOState::Done) {
      iostate = handleIncomingQueryReceived(now);
    }
    else {
      d_lastIOBlocked = true;
    }
  }

  return false;
}

void IncomingTCPConnectionState::handleIO()
{
  // why do we loop? Because the TLS layer does buffering, and thus can have data ready to read
  // even though the underlying socket is not ready, so we need to actually ask for the data first
  IOState iostate = IOState::Done;
  timeval now{};
  gettimeofday(&now, nullptr);

  do {
    iostate = IOState::Done;
    IOStateGuard ioGuard(d_ioState);

    if (maxConnectionDurationReached(dnsdist::configuration::getCurrentRuntimeConfiguration().d_maxTCPConnectionDuration, now)) {
      vinfolog("Terminating TCP connection from %s because it reached the maximum TCP connection duration", d_ci.remote.toStringWithPort());
      // will be handled by the ioGuard
      // handleNewIOState(state, IOState::Done, fd, handleIOCallback);
      return;
    }

    const auto& immutable = dnsdist::configuration::getImmutableConfiguration();
    if (immutable.d_maxTCPReadIOsPerQuery > 0 && d_readIOsCurrentQuery >= immutable.d_maxTCPReadIOsPerQuery) {
      vinfolog("Terminating TCP connection from %s for reaching the maximum number of read IO events per query (%d)", d_ci.remote.toStringWithPort(), immutable.d_maxTCPReadIOsPerQuery);
      dnsdist::IncomingConcurrentTCPConnectionsManager::banClientFor(d_ci.remote, time(nullptr), immutable.d_tcpBanDurationForExceedingMaxReadIOsPerQuery);
      return;
    }

    d_lastIOBlocked = false;

    try {
      if (d_state == State::starting) {
        if (d_ci.cs != nullptr && d_ci.cs->d_enableProxyProtocol && isProxyPayloadOutsideTLS() && expectProxyProtocolFrom(d_ci.remote)) {
          d_state = State::readingProxyProtocolHeader;
          d_buffer.resize(s_proxyProtocolMinimumHeaderSize);
          d_proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
        }
        else {
          d_state = State::doingHandshake;
        }
      }

      if (d_state == State::doingHandshake) {
        iostate = handleHandshake(now);
      }

      if (!d_lastIOBlocked && d_state == State::readingProxyProtocolHeader) {
        auto status = handleProxyProtocolPayload();
        if (status == ProxyProtocolResult::Done) {
          d_buffer.resize(sizeof(uint16_t));

          if (isProxyPayloadOutsideTLS()) {
            d_state = State::doingHandshake;
            iostate = handleHandshake(now);
          }
          else {
            d_state = State::readingQuerySize;
          }
        }
        else if (status == ProxyProtocolResult::Error) {
          iostate = IOState::Done;
        }
        else {
          iostate = IOState::NeedRead;
        }
      }

      if (!d_lastIOBlocked && (d_state == State::waitingForQuery || d_state == State::readingQuerySize || d_state == State::readingQuery)) {
        if (readIncomingQuery(now, iostate)) {
          return;
        }
      }

      if (!d_lastIOBlocked && d_state == State::sendingResponse) {
        DEBUGLOG("sending response");
        iostate = d_handler.tryWrite(d_currentResponse.d_buffer, d_currentPos, d_currentResponse.d_buffer.size());
        if (iostate == IOState::Done) {
          DEBUGLOG("response sent from " << __PRETTY_FUNCTION__);
          handleResponseSent(d_currentResponse, d_currentResponse.d_buffer.size());
          d_state = State::idle;
        }
        else {
          d_lastIOBlocked = true;
        }
      }

      if (active() && !d_lastIOBlocked && iostate == IOState::Done && (d_state == State::idle || d_state == State::waitingForQuery)) {
        // try sending queued responses
        DEBUGLOG("send responses, if any");
        auto state = shared_from_this();
        iostate = sendQueuedResponses(state, now);

        if (!d_lastIOBlocked && active() && iostate == IOState::Done) {
          // if the query has been passed to a backend, or dropped, and the responses have been sent,
          // we can start reading again
          if (canAcceptNewQueries(now)) {
            resetForNewQuery();
            iostate = IOState::NeedRead;
          }
          else {
            d_state = State::idle;
            iostate = IOState::Done;
          }
        }
      }

      if (d_state != State::idle && d_state != State::doingHandshake && d_state != State::readingProxyProtocolHeader && d_state != State::waitingForQuery && d_state != State::readingQuerySize && d_state != State::readingQuery && d_state != State::sendingResponse) {
        vinfolog("Unexpected state %d in handleIOCallback", static_cast<int>(d_state));
      }
    }
    catch (const std::exception& exp) {
      /* most likely an EOF because the other end closed the connection,
         but it might also be a real IO error or something else.
         Let's just drop the connection
      */
      handleExceptionDuringIO(exp);
    }

    if (!active()) {
      DEBUGLOG("state is no longer active");
      return;
    }

    auto sharedPtrToConn = shared_from_this();
    if (iostate == IOState::Done) {
      d_ioState->update(iostate, handleIOCallback, sharedPtrToConn);
    }
    else {
      updateIO(iostate, now);
    }
    ioGuard.release();
  } while ((iostate == IOState::NeedRead || iostate == IOState::NeedWrite) && !d_lastIOBlocked);
}

void IncomingTCPConnectionState::notifyIOError(const struct timeval& now, TCPResponse&& response)
{
  if (std::this_thread::get_id() != d_creatorThreadID) {
    /* empty buffer will signal an IO error */
    response.d_buffer.clear();
    handleCrossProtocolResponse(now, std::move(response));
    return;
  }

  auto sharedPtrToConn = shared_from_this();
  --sharedPtrToConn->d_currentQueriesCount;
  sharedPtrToConn->d_hadErrors = true;

  if (sharedPtrToConn->d_state == State::sendingResponse) {
    /* if we have responses to send, let's do that first */
  }
  else if (!sharedPtrToConn->d_queuedResponses.empty()) {
    /* stop reading and send what we have */
    try {
      auto iostate = sendQueuedResponses(sharedPtrToConn, now);

      if (sharedPtrToConn->active() && iostate != IOState::Done) {
        // we need to update the state right away, nobody will do that for us
        updateIO(iostate, now);
      }
    }
    catch (const std::exception& e) {
      vinfolog("Exception in notifyIOError: %s", e.what());
    }
  }
  else {
    // the backend code already tried to reconnect if it was possible
    sharedPtrToConn->terminateClientConnection();
  }
}

static bool processXFRResponse(DNSResponse& dnsResponse)
{
  const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
  const auto& xfrRespRuleActions = dnsdist::rules::getResponseRuleChain(chains, dnsdist::rules::ResponseRuleChain::XFRResponseRules);

  if (!applyRulesToResponse(xfrRespRuleActions, dnsResponse)) {
    return false;
  }

  if (dnsResponse.isAsynchronous()) {
    return true;
  }

  if (dnsResponse.ids.d_extendedError) {
    dnsdist::edns::addExtendedDNSError(dnsResponse.getMutableData(), dnsResponse.getMaximumSize(), dnsResponse.ids.d_extendedError->infoCode, dnsResponse.ids.d_extendedError->extraText);
  }

  return true;
}

void IncomingTCPConnectionState::handleXFRResponse(const struct timeval& now, TCPResponse&& response)
{
  if (std::this_thread::get_id() != d_creatorThreadID) {
    handleCrossProtocolResponse(now, std::move(response));
    return;
  }

  std::shared_ptr<IncomingTCPConnectionState> state = shared_from_this();
  auto& ids = response.d_idstate;
  std::shared_ptr<DownstreamState> backend = response.d_ds ? response.d_ds : (response.d_connection ? response.d_connection->getDS() : nullptr);
  DNSResponse dnsResponse(ids, response.d_buffer, backend);
  dnsResponse.d_incomingTCPState = state;
  memcpy(&response.d_cleartextDH, dnsResponse.getHeader().get(), sizeof(response.d_cleartextDH));

  if (!processXFRResponse(dnsResponse)) {
    state->terminateClientConnection();
    return;
  }

  queueResponse(state, now, std::move(response), true);
}

void IncomingTCPConnectionState::handleTimeout(std::shared_ptr<IncomingTCPConnectionState>& state, bool write)
{
  vinfolog("Timeout while %s TCP client %s", (write ? "writing to" : "reading from"), state->d_ci.remote.toStringWithPort());
  DEBUGLOG("client timeout");
  DEBUGLOG("Processed " << state->d_queriesCount << " queries, current count is " << state->d_currentQueriesCount << ", " << state->d_ownedConnectionsToBackend.size() << " owned connections, " << state->d_queuedResponses.size() << " response queued");

  if (write || state->d_currentQueriesCount == 0) {
    ++state->d_ci.cs->tcpClientTimeouts;
    state->d_ioState.reset();
  }
  else {
    DEBUGLOG("Going idle");
    /* we still have some queries in flight, let's just stop reading for now */
    state->d_state = State::idle;
    state->d_ioState->update(IOState::Done, handleIOCallback, state);
  }
}

static void handleIncomingTCPQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  (void)pipefd;
  auto* threadData = boost::any_cast<TCPClientThreadData*>(param);

  std::unique_ptr<ConnectionInfo> citmp{nullptr};
  try {
    auto tmp = threadData->queryReceiver.receive();
    if (!tmp) {
      return;
    }
    citmp = std::move(*tmp);
  }
  catch (const std::exception& e) {
    throw std::runtime_error("Error while reading from the TCP query channel: " + std::string(e.what()));
  }

  g_tcpclientthreads->decrementQueuedCount();

  timeval now{};
  gettimeofday(&now, nullptr);

  if (citmp->cs->dohFrontend) {
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    auto state = std::make_shared<IncomingHTTP2Connection>(std::move(*citmp), *threadData, now);
    state->handleIO();
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
  }
  else {
    auto state = std::make_shared<IncomingTCPConnectionState>(std::move(*citmp), *threadData, now);
    state->handleIO();
  }
}

static void handleCrossProtocolQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  (void)pipefd;
  auto* threadData = boost::any_cast<TCPClientThreadData*>(param);

  std::unique_ptr<CrossProtocolQuery> cpq{nullptr};
  try {
    auto tmp = threadData->crossProtocolQueryReceiver.receive();
    if (!tmp) {
      return;
    }
    cpq = std::move(*tmp);
  }
  catch (const std::exception& e) {
    throw std::runtime_error("Error while reading from the TCP cross-protocol channel: " + std::string(e.what()));
  }

  timeval now{};
  gettimeofday(&now, nullptr);

  std::shared_ptr<TCPQuerySender> tqs = cpq->getTCPQuerySender();
  auto query = std::move(cpq->query);
  auto downstreamServer = std::move(cpq->downstream);

  try {
    auto downstream = t_downstreamTCPConnectionsManager.getConnectionToDownstream(threadData->mplexer, downstreamServer, now, std::string());

    prependSizeToTCPQuery(query.d_buffer, query.d_idstate.d_proxyProtocolPayloadSize);

    vinfolog("Got query for %s|%s from %s (%s, %d bytes), relayed to %s", query.d_idstate.qname.toLogString(), QType(query.d_idstate.qtype).toString(), query.d_idstate.origRemote.toStringWithPort(), query.d_idstate.protocol.toString(), query.d_buffer.size(), downstreamServer->getNameWithAddr());

    downstream->queueQuery(tqs, std::move(query));
  }
  catch (...) {
    tqs->notifyIOError(now, std::move(query));
  }
}

static void handleCrossProtocolResponse(int pipefd, FDMultiplexer::funcparam_t& param)
{
  (void)pipefd;
  auto* threadData = boost::any_cast<TCPClientThreadData*>(param);

  std::unique_ptr<TCPCrossProtocolResponse> cpr{nullptr};
  try {
    auto tmp = threadData->crossProtocolResponseReceiver.receive();
    if (!tmp) {
      return;
    }
    cpr = std::move(*tmp);
  }
  catch (const std::exception& e) {
    throw std::runtime_error("Error while reading from the TCP cross-protocol response: " + std::string(e.what()));
  }

  auto& response = *cpr;

  try {
    if (response.d_response.d_buffer.empty()) {
      response.d_state->notifyIOError(response.d_now, std::move(response.d_response));
    }
    else if (response.d_response.d_idstate.qtype == QType::AXFR || response.d_response.d_idstate.qtype == QType::IXFR) {
      response.d_state->handleXFRResponse(response.d_now, std::move(response.d_response));
    }
    else {
      response.d_state->handleResponse(response.d_now, std::move(response.d_response));
    }
  }
  catch (...) {
    /* no point bubbling up from there */
  }
}

struct TCPAcceptorParam
{
  // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
  ClientState& clientState;
  ComboAddress local;
  int socket{-1};
};

static void acceptNewConnection(const TCPAcceptorParam& param, TCPClientThreadData* threadData);

static void scanForTimeouts(const TCPClientThreadData& data, const timeval& now)
{
  auto expiredReadConns = data.mplexer->getTimeouts(now, false);
  for (const auto& cbData : expiredReadConns) {
    if (cbData.second.type() == typeid(std::shared_ptr<IncomingTCPConnectionState>)) {
      auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(cbData.second);
      if (cbData.first == state->d_handler.getDescriptor()) {
        vinfolog("Timeout (read) from remote TCP client %s", state->d_ci.remote.toStringWithPort());
        state->handleTimeout(state, false);
      }
    }
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    else if (cbData.second.type() == typeid(std::shared_ptr<IncomingHTTP2Connection>)) {
      auto state = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(cbData.second);
      if (cbData.first == state->d_handler.getDescriptor()) {
        vinfolog("Timeout (read) from remote H2 client %s", state->d_ci.remote.toStringWithPort());
        std::shared_ptr<IncomingTCPConnectionState> parentState = state;
        state->handleTimeout(parentState, false);
      }
    }
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
    else if (cbData.second.type() == typeid(std::shared_ptr<TCPConnectionToBackend>)) {
      auto conn = boost::any_cast<std::shared_ptr<TCPConnectionToBackend>>(cbData.second);
      vinfolog("Timeout (read) from remote backend %s", conn->getBackendName());
      conn->handleTimeout(now, false);
    }
  }

  auto expiredWriteConns = data.mplexer->getTimeouts(now, true);
  for (const auto& cbData : expiredWriteConns) {
    if (cbData.second.type() == typeid(std::shared_ptr<IncomingTCPConnectionState>)) {
      auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(cbData.second);
      if (cbData.first == state->d_handler.getDescriptor()) {
        vinfolog("Timeout (write) from remote TCP client %s", state->d_ci.remote.toStringWithPort());
        state->handleTimeout(state, true);
      }
    }
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    else if (cbData.second.type() == typeid(std::shared_ptr<IncomingHTTP2Connection>)) {
      auto state = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(cbData.second);
      if (cbData.first == state->d_handler.getDescriptor()) {
        vinfolog("Timeout (write) from remote H2 client %s", state->d_ci.remote.toStringWithPort());
        std::shared_ptr<IncomingTCPConnectionState> parentState = state;
        state->handleTimeout(parentState, true);
      }
    }
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
    else if (cbData.second.type() == typeid(std::shared_ptr<TCPConnectionToBackend>)) {
      auto conn = boost::any_cast<std::shared_ptr<TCPConnectionToBackend>>(cbData.second);
      vinfolog("Timeout (write) from remote backend %s", conn->getBackendName());
      conn->handleTimeout(now, true);
    }
  }
}

static void dumpTCPStates(const TCPClientThreadData& data)
{
  /* just to keep things clean in the output, debug only */
  static std::mutex s_lock;
  std::lock_guard<decltype(s_lock)> lck(s_lock);
  if (g_tcpStatesDumpRequested > 0) {
    /* no race here, we took the lock so it can only be increased in the meantime */
    --g_tcpStatesDumpRequested;
    infolog("Dumping the TCP states, as requested:");
    data.mplexer->runForAllWatchedFDs([](bool isRead, int desc, const FDMultiplexer::funcparam_t& param, struct timeval ttd) {
      timeval lnow{};
      gettimeofday(&lnow, nullptr);
      if (ttd.tv_sec > 0) {
        infolog("- Descriptor %d is in %s state, TTD in %d", desc, (isRead ? "read" : "write"), (ttd.tv_sec - lnow.tv_sec));
      }
      else {
        infolog("- Descriptor %d is in %s state, no TTD set", desc, (isRead ? "read" : "write"));
      }

      if (param.type() == typeid(std::shared_ptr<IncomingTCPConnectionState>)) {
        auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);
        infolog(" - %s", state->toString());
      }
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
      else if (param.type() == typeid(std::shared_ptr<IncomingHTTP2Connection>)) {
        auto state = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
        infolog(" - %s", state->toString());
      }
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
      else if (param.type() == typeid(std::shared_ptr<TCPConnectionToBackend>)) {
        auto conn = boost::any_cast<std::shared_ptr<TCPConnectionToBackend>>(param);
        infolog(" - %s", conn->toString());
      }
      else if (param.type() == typeid(TCPClientThreadData*)) {
        infolog(" - Worker thread pipe");
      }
    });
    infolog("The TCP/DoT client cache has %d active and %d idle outgoing connections cached", t_downstreamTCPConnectionsManager.getActiveCount(), t_downstreamTCPConnectionsManager.getIdleCount());
  }
}

// NOLINTNEXTLINE(performance-unnecessary-value-param): you are wrong, clang-tidy, go home
static void tcpClientThread(pdns::channel::Receiver<ConnectionInfo>&& queryReceiver, pdns::channel::Receiver<CrossProtocolQuery>&& crossProtocolQueryReceiver, pdns::channel::Receiver<TCPCrossProtocolResponse>&& crossProtocolResponseReceiver, pdns::channel::Sender<TCPCrossProtocolResponse>&& crossProtocolResponseSender, std::vector<ClientState*> tcpAcceptStates)
{
  /* we get launched with a pipe on which we receive file descriptors from clients that we own
     from that point on */

  setThreadName("dnsdist/tcpClie");

  try {
    TCPClientThreadData data;
    data.crossProtocolResponseSender = std::move(crossProtocolResponseSender);
    data.queryReceiver = std::move(queryReceiver);
    data.crossProtocolQueryReceiver = std::move(crossProtocolQueryReceiver);
    data.crossProtocolResponseReceiver = std::move(crossProtocolResponseReceiver);

    data.mplexer->addReadFD(data.queryReceiver.getDescriptor(), handleIncomingTCPQuery, &data);
    data.mplexer->addReadFD(data.crossProtocolQueryReceiver.getDescriptor(), handleCrossProtocolQuery, &data);
    data.mplexer->addReadFD(data.crossProtocolResponseReceiver.getDescriptor(), handleCrossProtocolResponse, &data);

    /* only used in single acceptor mode for now */
    std::vector<TCPAcceptorParam> acceptParams;
    acceptParams.reserve(tcpAcceptStates.size());

    for (auto& state : tcpAcceptStates) {
      acceptParams.emplace_back(TCPAcceptorParam{*state, state->local, state->tcpFD});
      for (const auto& [addr, socket] : state->d_additionalAddresses) {
        acceptParams.emplace_back(TCPAcceptorParam{*state, addr, socket});
      }
    }

    auto acceptCallback = [&data](int socket, FDMultiplexer::funcparam_t& funcparam) {
      (void)socket;
      const auto* acceptorParam = boost::any_cast<const TCPAcceptorParam*>(funcparam);
      acceptNewConnection(*acceptorParam, &data);
    };

    for (const auto& param : acceptParams) {
      setNonBlocking(param.socket);
      data.mplexer->addReadFD(param.socket, acceptCallback, &param);
    }

    timeval now{};
    gettimeofday(&now, nullptr);
    time_t lastTimeoutScan = now.tv_sec;

    for (;;) {
      data.mplexer->run(&now);

      try {
        t_downstreamTCPConnectionsManager.cleanupClosedConnections(now);
        dnsdist::IncomingConcurrentTCPConnectionsManager::cleanup(time(nullptr));

        if (now.tv_sec > lastTimeoutScan) {
          lastTimeoutScan = now.tv_sec;
          scanForTimeouts(data, now);

          if (g_tcpStatesDumpRequested > 0) {
            dumpTCPStates(data);
          }
        }
      }
      catch (const std::exception& e) {
        warnlog("Error in TCP worker thread: %s", e.what());
      }
    }
  }
  catch (const std::exception& e) {
    errlog("Fatal error in TCP worker thread: %s", e.what());
  }
}

static void acceptNewConnection(const TCPAcceptorParam& param, TCPClientThreadData* threadData)
{
  auto& clientState = param.clientState;
  const bool checkACL = clientState.dohFrontend == nullptr || (!clientState.dohFrontend->d_trustForwardedForHeader && clientState.dohFrontend->d_earlyACLDrop);
  const int socket = param.socket;
  bool tcpClientCountIncremented = false;
  ComboAddress remote;
  remote.sin4.sin_family = param.local.sin4.sin_family;

  tcpClientCountIncremented = false;
  try {
    socklen_t remlen = remote.getSocklen();
    ConnectionInfo connInfo(&clientState);
#ifdef HAVE_ACCEPT4
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    connInfo.fd = accept4(socket, reinterpret_cast<struct sockaddr*>(&remote), &remlen, SOCK_NONBLOCK);
#else
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    connInfo.fd = accept(socket, reinterpret_cast<struct sockaddr*>(&remote), &remlen);
#endif
    // will be decremented when the ConnectionInfo object is destroyed, no matter the reason
    auto concurrentConnections = ++clientState.tcpCurrentConnections;

    if (connInfo.fd < 0) {
      throw std::runtime_error((boost::format("accepting new connection on socket: %s") % stringerror()).str());
    }

    if (checkACL && !dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.match(remote)) {
      ++dnsdist::metrics::g_stats.aclDrops;
      vinfolog("Dropped TCP connection from %s because of ACL", remote.toStringWithPort());
      return;
    }

    if (clientState.d_tcpConcurrentConnectionsLimit > 0 && concurrentConnections > clientState.d_tcpConcurrentConnectionsLimit) {
      vinfolog("Dropped TCP connection from %s because of concurrent connections limit", remote.toStringWithPort());
      return;
    }

    if (concurrentConnections > clientState.tcpMaxConcurrentConnections.load()) {
      clientState.tcpMaxConcurrentConnections.store(concurrentConnections);
    }

#ifndef HAVE_ACCEPT4
    if (!setNonBlocking(connInfo.fd)) {
      return;
    }
#endif

    setTCPNoDelay(connInfo.fd); // disable NAGLE

    const auto maxTCPQueuedConnections = dnsdist::configuration::getImmutableConfiguration().d_maxTCPQueuedConnections;
    if (maxTCPQueuedConnections > 0 && g_tcpclientthreads->getQueuedCount() >= maxTCPQueuedConnections) {
      vinfolog("Dropping TCP connection from %s because we have too many queued already", remote.toStringWithPort());
      return;
    }

    auto connectionResult = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(remote, connInfo.cs->hasTLS());
    if (connectionResult == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Denied) {
      return;
    }
    tcpClientCountIncremented = true;
    if (connectionResult == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Restricted) {
      connInfo.d_restricted = true;
    }

    vinfolog("Got TCP connection from %s", remote.toStringWithPort());

    connInfo.remote = remote;

    if (threadData == nullptr) {
      if (!g_tcpclientthreads->passConnectionToThread(std::make_unique<ConnectionInfo>(std::move(connInfo)))) {
        if (tcpClientCountIncremented) {
          dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(remote);
        }
      }
    }
    else {
      timeval now{};
      gettimeofday(&now, nullptr);

      if (connInfo.cs->dohFrontend) {
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
        auto state = std::make_shared<IncomingHTTP2Connection>(std::move(connInfo), *threadData, now);
        state->handleIO();
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
      }
      else {
        auto state = std::make_shared<IncomingTCPConnectionState>(std::move(connInfo), *threadData, now);
        state->handleIO();
      }
    }
  }
  catch (const std::exception& e) {
    errlog("While reading a TCP question: %s", e.what());
    if (tcpClientCountIncremented) {
      dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(remote);
    }
  }
  catch (...) {
  }
}

/* spawn as many of these as required, they call Accept on a socket on which they will accept queries, and
   they will hand off to worker threads & spawn more of them if required
*/
#ifndef USE_SINGLE_ACCEPTOR_THREAD
void tcpAcceptorThread(const std::vector<ClientState*>& states)
{
  setThreadName("dnsdist/tcpAcce");

  std::vector<TCPAcceptorParam> params;
  params.reserve(states.size());

  for (const auto& state : states) {
    params.emplace_back(TCPAcceptorParam{*state, state->local, state->tcpFD});
    for (const auto& [addr, socket] : state->d_additionalAddresses) {
      params.emplace_back(TCPAcceptorParam{*state, addr, socket});
    }
  }

  if (params.size() == 1) {
    while (true) {
      acceptNewConnection(params.at(0), nullptr);
    }
  }
  else {
    auto acceptCallback = [](int socket, FDMultiplexer::funcparam_t& funcparam) {
      (void)socket;
      const auto* acceptorParam = boost::any_cast<const TCPAcceptorParam*>(funcparam);
      acceptNewConnection(*acceptorParam, nullptr);
    };

    auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(params.size()));
    for (const auto& param : params) {
      mplexer->addReadFD(param.socket, acceptCallback, &param);
    }

    timeval now{};
    while (true) {
      mplexer->run(&now, -1);
    }
  }
}
#endif
