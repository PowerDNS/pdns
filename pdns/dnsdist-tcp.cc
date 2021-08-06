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

#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-tcp-upstream.hh"
#include "dnsdist-xpf.hh"
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

static LockGuarded<std::map<ComboAddress,size_t,ComboAddress::addressOnlyLessThan>> s_tcpClientsCount;

size_t g_maxTCPQueriesPerConn{0};
size_t g_maxTCPConnectionDuration{0};
size_t g_maxTCPConnectionsPerClient{0};
#ifdef __linux__
// On Linux this gives us 128k pending queries (default is 8192 queries),
// which should be enough to deal with huge spikes
size_t g_tcpInternalPipeBufferSize{1024*1024};
uint64_t g_maxTCPQueuedConnections{10000};
#else
size_t g_tcpInternalPipeBufferSize{0};
uint64_t g_maxTCPQueuedConnections{1000};
#endif

int g_tcpRecvTimeout{2};
int g_tcpSendTimeout{2};
std::atomic<uint64_t> g_tcpStatesDumpRequested{0};

static void decrementTCPClientCount(const ComboAddress& client)
{
  if (g_maxTCPConnectionsPerClient) {
    auto tcpClientsCount = s_tcpClientsCount.lock();
    tcpClientsCount->at(client)--;
    if (tcpClientsCount->at(client) == 0) {
      tcpClientsCount->erase(client);
    }
  }
}

IncomingTCPConnectionState::~IncomingTCPConnectionState()
{
  decrementTCPClientCount(d_ci.remote);

  if (d_ci.cs != nullptr) {
    struct timeval now;
    gettimeofday(&now, nullptr);

    auto diff = now - d_connectionStartTime;
    d_ci.cs->updateTCPMetrics(d_queriesCount, diff.tv_sec * 1000.0 + diff.tv_usec / 1000.0);
  }

  // would have been done when the object is destroyed anyway,
  // but that way we make sure it's done before the ConnectionInfo is destroyed,
  // closing the descriptor, instead of relying on the declaration order of the objects in the class
  d_handler.close();
}

size_t IncomingTCPConnectionState::clearAllDownstreamConnections()
{
  return DownstreamConnectionsManager::clear();
}

std::shared_ptr<TCPConnectionToBackend> IncomingTCPConnectionState::getDownstreamConnection(std::shared_ptr<DownstreamState>& ds, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs, const struct timeval& now)
{
  std::shared_ptr<TCPConnectionToBackend> downstream{nullptr};

  downstream = getActiveDownstreamConnection(ds, tlvs);

  if (!downstream) {
    /* we don't have a connection to this backend active yet, let's get one (it might not be a fresh one, though) */
    downstream = DownstreamConnectionsManager::getConnectionToDownstream(d_threadData.mplexer, ds, now);
    registerActiveDownstreamConnection(downstream);
  }

  return downstream;
}

static void tcpClientThread(int pipefd, int crossProtocolPipeFD);

TCPClientCollection::TCPClientCollection(size_t maxThreads): d_tcpclientthreads(maxThreads), d_maxthreads(maxThreads)
{
}

void TCPClientCollection::addTCPClientThread()
{
  auto preparePipe = [](int fds[2], const std::string& type) -> bool {
    if (pipe(fds) < 0) {
      errlog("Error creating the TCP thread %s pipe: %s", type, stringerror());
      return false;
    }

    if (!setNonBlocking(fds[0])) {
      int err = errno;
      close(fds[0]);
      close(fds[1]);
      errlog("Error setting the TCP thread %s pipe non-blocking: %s", type, stringerror(err));
      return false;
    }

    if (!setNonBlocking(fds[1])) {
      int err = errno;
      close(fds[0]);
      close(fds[1]);
      errlog("Error setting the TCP thread %s pipe non-blocking: %s", type, stringerror(err));
      return false;
    }

    if (g_tcpInternalPipeBufferSize > 0 && getPipeBufferSize(fds[0]) < g_tcpInternalPipeBufferSize) {
      setPipeBufferSize(fds[0], g_tcpInternalPipeBufferSize);
    }

    return true;
  };

  int pipefds[2] = { -1, -1};
  if (!preparePipe(pipefds, "communication")) {
    return;
  }

  int crossProtocolFDs[2] = { -1, -1};
  if (!preparePipe(crossProtocolFDs, "cross-protocol")) {
    return;
  }

  vinfolog("Adding TCP Client thread");

  {
    std::lock_guard<std::mutex> lock(d_mutex);

    if (d_numthreads >= d_tcpclientthreads.size()) {
      vinfolog("Adding a new TCP client thread would exceed the vector size (%d/%d), skipping. Consider increasing the maximum amount of TCP client threads with setMaxTCPClientThreads() in the configuration.", d_numthreads.load(), d_tcpclientthreads.size());
      close(crossProtocolFDs[0]);
      close(crossProtocolFDs[1]);
      close(pipefds[0]);
      close(pipefds[1]);
      return;
    }

    /* from now on this side of the pipe will be managed by that object,
       no need to worry about it */
    TCPWorkerThread worker(pipefds[1], crossProtocolFDs[1]);
    try {
      std::thread t1(tcpClientThread, pipefds[0], crossProtocolFDs[0]);
      t1.detach();
    }
    catch (const std::runtime_error& e) {
      /* the thread creation failed, don't leak */
      errlog("Error creating a TCP thread: %s", e.what());
      close(pipefds[0]);
      return;
    }

    d_tcpclientthreads.at(d_numthreads) = std::move(worker);
    ++d_numthreads;
  }
}

std::unique_ptr<TCPClientCollection> g_tcpclientthreads;

static IOState sendQueuedResponses(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now)
{
  IOState result = IOState::Done;

  while (state->active() && !state->d_queuedResponses.empty()) {
    DEBUGLOG("queue size is "<<state->d_queuedResponses.size()<<", sending the next one");
    TCPResponse resp = std::move(state->d_queuedResponses.front());
    state->d_queuedResponses.pop_front();
    state->d_state = IncomingTCPConnectionState::State::idle;
    result = state->sendResponse(state, now, std::move(resp));
    if (result != IOState::Done) {
      return result;
    }
  }

  state->d_state = IncomingTCPConnectionState::State::idle;
  return IOState::Done;
}

static void updateTCPLatency(const std::shared_ptr<DownstreamState>& ds, double udiff)
{
  ds->latencyUsecTCP = (127.0 * ds->latencyUsecTCP / 128.0) + udiff/128.0;
}

static void handleResponseSent(std::shared_ptr<IncomingTCPConnectionState>& state, const TCPResponse& currentResponse)
{
  if (currentResponse.d_idstate.qtype == QType::AXFR || currentResponse.d_idstate.qtype == QType::IXFR) {
    return;
  }

  --state->d_currentQueriesCount;

  if (currentResponse.d_selfGenerated == false && currentResponse.d_connection && currentResponse.d_connection->getDS()) {
    const auto& ds = currentResponse.d_connection->getDS();
    const auto& ids = currentResponse.d_idstate;
    double udiff = ids.sentTime.udiff();
    vinfolog("Got answer from %s, relayed to %s (%s, %d bytes), took %f usec", ds->remote.toStringWithPort(), ids.origRemote.toStringWithPort(), (state->d_handler.isTLS() ? "DoT" : "TCP"), currentResponse.d_buffer.size(), udiff);

    ::handleResponseSent(ids, udiff, state->d_ci.remote, ds->remote, static_cast<unsigned int>(currentResponse.d_buffer.size()), currentResponse.d_cleartextDH);

    updateTCPLatency(ds, udiff);
  }
}

static void prependSizeToTCPQuery(PacketBuffer& buffer, size_t proxyProtocolPayloadSize)
{
  if (buffer.size() <= proxyProtocolPayloadSize) {
    throw std::runtime_error("The payload size is smaller or equal to the buffer size");
  }

  uint16_t queryLen = proxyProtocolPayloadSize > 0 ? (buffer.size() - proxyProtocolPayloadSize) : buffer.size();
  const uint8_t sizeBytes[] = { static_cast<uint8_t>(queryLen / 256), static_cast<uint8_t>(queryLen % 256) };
  /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
     that could occur if we had to deal with the size during the processing,
     especially alignment issues */
  buffer.insert(buffer.begin() + proxyProtocolPayloadSize, sizeBytes, sizeBytes + 2);
}

bool IncomingTCPConnectionState::canAcceptNewQueries(const struct timeval& now)
{
  if (d_hadErrors) {
    DEBUGLOG("not accepting new queries because we encountered some error during the processing already");
    return false;
  }

  if (d_currentQueriesCount >= d_ci.cs->d_maxInFlightQueriesPerConn) {
    DEBUGLOG("not accepting new queries because we already have "<<d_currentQueriesCount<<" out of "<<d_ci.cs->d_maxInFlightQueriesPerConn);
    return false;
  }

  if (g_maxTCPQueriesPerConn && d_queriesCount > g_maxTCPQueriesPerConn) {
    vinfolog("not accepting new queries from %s because it reached the maximum number of queries per conn (%d / %d)", d_ci.remote.toStringWithPort(), d_queriesCount, g_maxTCPQueriesPerConn);
    return false;
  }

  if (maxConnectionDurationReached(g_maxTCPConnectionDuration, now)) {
    vinfolog("not accepting new queries from %s because it reached the maximum TCP connection duration", d_ci.remote.toStringWithPort());
    return false;
  }

  return true;
}

void IncomingTCPConnectionState::resetForNewQuery()
{
  d_buffer.resize(sizeof(uint16_t));
  d_currentPos = 0;
  d_querySize = 0;
  d_state = State::waitingForQuery;
}

std::shared_ptr<TCPConnectionToBackend> IncomingTCPConnectionState::getActiveDownstreamConnection(const std::shared_ptr<DownstreamState>& ds, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs)
{
  auto it = d_activeConnectionsToBackend.find(ds);
  if (it == d_activeConnectionsToBackend.end()) {
    DEBUGLOG("no active connection found for "<<ds->getName());
    return nullptr;
  }

  for (auto& conn : it->second) {
    if (conn->canAcceptNewQueries() && conn->matchesTLVs(tlvs)) {
      DEBUGLOG("Got one active connection accepting more for "<<ds->getName());
      conn->setReused();
      return conn;
    }
    DEBUGLOG("not accepting more for "<<ds->getName());
  }

  return nullptr;
}

void IncomingTCPConnectionState::registerActiveDownstreamConnection(std::shared_ptr<TCPConnectionToBackend>& conn)
{
  d_activeConnectionsToBackend[conn->getDS()].push_front(conn);
}

/* called when the buffer has been set and the rules have been processed, and only from handleIO (sometimes indirectly via handleQuery) */
IOState IncomingTCPConnectionState::sendResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response)
{
  state->d_state = IncomingTCPConnectionState::State::sendingResponse;

  uint16_t responseSize = static_cast<uint16_t>(response.d_buffer.size());
  const uint8_t sizeBytes[] = { static_cast<uint8_t>(responseSize / 256), static_cast<uint8_t>(responseSize % 256) };
  /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
     that could occur if we had to deal with the size during the processing,
     especially alignment issues */
  response.d_buffer.insert(response.d_buffer.begin(), sizeBytes, sizeBytes + 2);
  state->d_currentPos = 0;
  state->d_currentResponse = std::move(response);

  try {
    auto iostate = state->d_handler.tryWrite(state->d_currentResponse.d_buffer, state->d_currentPos, state->d_currentResponse.d_buffer.size());
    if (iostate == IOState::Done) {
      DEBUGLOG("response sent from "<<__PRETTY_FUNCTION__);
      handleResponseSent(state, state->d_currentResponse);
      return iostate;
    } else {
      state->d_lastIOBlocked = true;
      DEBUGLOG("partial write");
      return iostate;
    }
  }
  catch (const std::exception& e) {
    vinfolog("Closing TCP client connection with %s: %s", state->d_ci.remote.toStringWithPort(), e.what());
    DEBUGLOG("Closing TCP client connection: "<<e.what());
    ++state->d_ci.cs->tcpDiedSendingResponse;

    state->terminateClientConnection();

    return IOState::Done;
  }
}

void IncomingTCPConnectionState::terminateClientConnection()
{
  DEBUGLOG("terminating client connection");
  d_queuedResponses.clear();
  /* we have already released idle connections that could be reused,
     we don't care about the ones still waiting for responses */
  d_activeConnectionsToBackend.clear();
  /* meaning we will no longer be 'active' when the backend
     response or timeout comes in */
  d_ioState.reset();
  d_handler.close();
}

void IncomingTCPConnectionState::queueResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response)
{
  // queue response
  state->d_queuedResponses.push_back(std::move(response));
  DEBUGLOG("queueing response, state is "<<(int)state->d_state<<", queue size is now "<<state->d_queuedResponses.size());

  // when the response comes from a backend, there is a real possibility that we are currently
  // idle, and thus not trying to send the response right away would make our ref count go to 0.
  // Even if we are waiting for a query, we will not wake up before the new query arrives or a
  // timeout occurs
  if (state->d_state == IncomingTCPConnectionState::State::idle ||
      state->d_state == IncomingTCPConnectionState::State::waitingForQuery) {
    auto iostate = sendQueuedResponses(state, now);

    if (iostate == IOState::Done && state->active()) {
      if (state->canAcceptNewQueries(now)) {
        state->resetForNewQuery();
        state->d_state = IncomingTCPConnectionState::State::waitingForQuery;
        iostate = IOState::NeedRead;
      }
      else {
        state->d_state = IncomingTCPConnectionState::State::idle;
      }
    }

    // for the same reason we need to update the state right away, nobody will do that for us
    if (state->active()) {
      state->d_ioState->update(iostate, handleIOCallback, state, iostate == IOState::NeedWrite ? state->getClientWriteTTD(now) : state->getClientReadTTD(now));
    }
  }
}

/* called from the backend code when a new response has been received */
void IncomingTCPConnectionState::handleResponse(const struct timeval& now, TCPResponse&& response)
{
  std::shared_ptr<IncomingTCPConnectionState> state = shared_from_this();

  if (response.d_connection && response.d_connection->isIdle()) {
    // if we have added a TCP Proxy Protocol payload to a connection, don't release it to the general pool yet, no one else will be able to use it anyway
    if (response.d_connection->canBeReused()) {
      auto& list = state->d_activeConnectionsToBackend.at(response.d_connection->getDS());

      for (auto it = list.begin(); it != list.end(); ++it) {
        if (*it == response.d_connection) {
          try {
            response.d_connection->release();
            DownstreamConnectionsManager::releaseDownstreamConnection(std::move(*it));
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

  if (response.d_buffer.size() < sizeof(dnsheader)) {
    state->terminateClientConnection();
    return;
  }

  try {
    auto& ids = response.d_idstate;
    unsigned int qnameWireLength;
    if (!responseContentMatches(response.d_buffer, ids.qname, ids.qtype, ids.qclass, response.d_connection->getRemote(), qnameWireLength)) {
      state->terminateClientConnection();
      return;
    }

    if (response.d_connection->getDS()) {
      ++response.d_connection->getDS()->responses;
    }

    DNSResponse dr = makeDNSResponseFromIDState(ids, response.d_buffer);

    memcpy(&response.d_cleartextDH, dr.getHeader(), sizeof(response.d_cleartextDH));

    if (!processResponse(response.d_buffer, state->d_threadData.localRespRuleActions, dr, false, false)) {
      state->terminateClientConnection();
      return;
    }
  }
  catch (const std::exception& e) {
    vinfolog("Unexpected exception while handling response from backend: %s", e.what());
    state->terminateClientConnection();
    return;
  }

  ++g_stats.responses;
  ++state->d_ci.cs->responses;

  queueResponse(state, now, std::move(response));
}

static void handleQuery(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now)
{
  if (state->d_querySize < sizeof(dnsheader)) {
    ++g_stats.nonCompliantQueries;
    state->terminateClientConnection();
    return;
  }

  ++state->d_queriesCount;
  ++state->d_ci.cs->queries;
  ++g_stats.queries;

  if (state->d_handler.isTLS()) {
    auto tlsVersion = state->d_handler.getTLSVersion();
    switch (tlsVersion) {
    case LibsslTLSVersion::TLS10:
      ++state->d_ci.cs->tls10queries;
      break;
    case LibsslTLSVersion::TLS11:
      ++state->d_ci.cs->tls11queries;
      break;
    case LibsslTLSVersion::TLS12:
      ++state->d_ci.cs->tls12queries;
      break;
    case LibsslTLSVersion::TLS13:
      ++state->d_ci.cs->tls13queries;
      break;
    default:
      ++state->d_ci.cs->tlsUnknownqueries;
    }
  }

  /* we need an accurate ("real") value for the response and
     to store into the IDS, but not for insertion into the
     rings for example */
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);

  std::shared_ptr<DNSCryptQuery> dnsCryptQuery{nullptr};
  auto dnsCryptResponse = checkDNSCryptQuery(*state->d_ci.cs, state->d_buffer, dnsCryptQuery, queryRealTime.tv_sec, true);
  if (dnsCryptResponse) {
    TCPResponse response;
    state->d_state = IncomingTCPConnectionState::State::idle;
    ++state->d_currentQueriesCount;
    state->queueResponse(state, now, std::move(response));
    return;
  }

  {
    /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
    auto* dh = reinterpret_cast<dnsheader*>(state->d_buffer.data());
    if (!checkQueryHeaders(dh)) {
      state->terminateClientConnection();
      return;
    }

    if (dh->qdcount == 0) {
      TCPResponse response;
      dh->rcode = RCode::NotImp;
      dh->qr = true;
      response.d_selfGenerated = true;
      response.d_buffer = std::move(state->d_buffer);
      state->d_state = IncomingTCPConnectionState::State::idle;
      ++state->d_currentQueriesCount;
      state->queueResponse(state, now, std::move(response));
      return;
    }
  }

  uint16_t qtype, qclass;
  unsigned int qnameWireLength = 0;
  DNSName qname(reinterpret_cast<const char*>(state->d_buffer.data()), state->d_buffer.size(), sizeof(dnsheader), false, &qtype, &qclass, &qnameWireLength);
  dnsdist::Protocol protocol = dnsdist::Protocol::DoTCP;
  if (dnsCryptQuery) {
    protocol = dnsdist::Protocol::DNSCryptTCP;
  }
  else if (state->d_handler.isTLS()) {
    protocol = dnsdist::Protocol::DoT;
  }

  DNSQuestion dq(&qname, qtype, qclass, &state->d_proxiedDestination, &state->d_proxiedRemote, state->d_buffer, protocol, &queryRealTime);
  dq.dnsCryptQuery = std::move(dnsCryptQuery);
  dq.sni = state->d_handler.getServerNameIndication();
  if (state->d_proxyProtocolValues) {
    /* we need to copy them, because the next queries received on that connection will
       need to get the _unaltered_ values */
    dq.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(*state->d_proxyProtocolValues);
  }

  if (dq.qtype == QType::AXFR || dq.qtype == QType::IXFR) {
    dq.skipCache = true;
  }

  std::shared_ptr<DownstreamState> ds;
  auto result = processQuery(dq, *state->d_ci.cs, state->d_threadData.holders, ds);

  if (result == ProcessQueryResult::Drop) {
    state->terminateClientConnection();
    return;
  }

  // the buffer might have been invalidated by now
  const dnsheader* dh = dq.getHeader();
  if (result == ProcessQueryResult::SendAnswer) {
    TCPResponse response;
    response.d_selfGenerated = true;
    response.d_buffer = std::move(state->d_buffer);
    state->d_state = IncomingTCPConnectionState::State::idle;
    ++state->d_currentQueriesCount;
    state->queueResponse(state, now, std::move(response));
    return;
  }

  if (result != ProcessQueryResult::PassToBackend || ds == nullptr) {
    state->terminateClientConnection();
    return;
  }

  IDState ids;
  setIDStateFromDNSQuestion(ids, dq, std::move(qname));
  ids.origID = dh->id;

  prependSizeToTCPQuery(state->d_buffer, 0);

#warning FIXME: handle DoH backends here
  auto downstreamConnection = state->getDownstreamConnection(ds, dq.proxyProtocolValues, now);

  bool proxyProtocolPayloadAdded = false;
  std::string proxyProtocolPayload;

  if (ds->useProxyProtocol) {
    /* if we ever sent a TLV over a connection, we can never go back */
    if (!state->d_proxyProtocolPayloadHasTLV) {
      state->d_proxyProtocolPayloadHasTLV = dq.proxyProtocolValues && !dq.proxyProtocolValues->empty();
    }

    proxyProtocolPayload = getProxyProtocolPayload(dq);
    if (state->d_proxyProtocolPayloadHasTLV && downstreamConnection->isFresh()) {
      /* we will not be able to reuse an existing connection anyway so let's add the payload right now */
      addProxyProtocol(state->d_buffer, proxyProtocolPayload);
      proxyProtocolPayloadAdded = true;
    }
  }

  if (dq.proxyProtocolValues) {
    downstreamConnection->setProxyProtocolValuesSent(std::move(dq.proxyProtocolValues));
  }

  TCPQuery query(std::move(state->d_buffer), std::move(ids));
  if (proxyProtocolPayloadAdded) {
    query.d_proxyProtocolPayloadAdded = true;
  }
  else {
    query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);
  }

  ++state->d_currentQueriesCount;
  vinfolog("Got query for %s|%s from %s (%s, %d bytes), relayed to %s", query.d_idstate.qname.toLogString(), QType(query.d_idstate.qtype).toString(), state->d_proxiedRemote.toStringWithPort(), (state->d_handler.isTLS() ? "DoT" : "TCP"), query.d_buffer.size(), ds->getName());
  std::shared_ptr<TCPQuerySender> incoming = state;
  downstreamConnection->queueQuery(incoming, std::move(query));
}

void IncomingTCPConnectionState::handleIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);
  if (fd != conn->d_handler.getDescriptor()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->d_handler.getDescriptor()));
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  handleIO(conn, now);
}

void IncomingTCPConnectionState::handleIO(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now)
{
  // why do we loop? Because the TLS layer does buffering, and thus can have data ready to read
  // even though the underlying socket is not ready, so we need to actually ask for the data first
  IOState iostate = IOState::Done;
  do {
    iostate = IOState::Done;
    IOStateGuard ioGuard(state->d_ioState);

    if (state->maxConnectionDurationReached(g_maxTCPConnectionDuration, now)) {
      vinfolog("Terminating TCP connection from %s because it reached the maximum TCP connection duration", state->d_ci.remote.toStringWithPort());
      // will be handled by the ioGuard
      //handleNewIOState(state, IOState::Done, fd, handleIOCallback);
      return;
    }

    state->d_lastIOBlocked = false;

    try {
      if (state->d_state == IncomingTCPConnectionState::State::doingHandshake) {
        DEBUGLOG("doing handshake");
        iostate = state->d_handler.tryHandshake();
        if (iostate == IOState::Done) {
          DEBUGLOG("handshake done");
          if (state->d_handler.isTLS()) {
            if (!state->d_handler.hasTLSSessionBeenResumed()) {
              ++state->d_ci.cs->tlsNewSessions;
            }
            else {
              ++state->d_ci.cs->tlsResumptions;
            }
            if (state->d_handler.getResumedFromInactiveTicketKey()) {
              ++state->d_ci.cs->tlsInactiveTicketKey;
            }
            if (state->d_handler.getUnknownTicketKey()) {
              ++state->d_ci.cs->tlsUnknownTicketKey;
            }
          }

          state->d_handshakeDoneTime = now;
          if (expectProxyProtocolFrom(state->d_ci.remote)) {
            state->d_state = IncomingTCPConnectionState::State::readingProxyProtocolHeader;
            state->d_buffer.resize(s_proxyProtocolMinimumHeaderSize);
            state->d_proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
          }
          else {
            state->d_state = IncomingTCPConnectionState::State::readingQuerySize;
          }
        }
        else {
          state->d_lastIOBlocked = true;
        }
      }

      if (!state->d_lastIOBlocked && state->d_state == IncomingTCPConnectionState::State::readingProxyProtocolHeader) {
        do {
          DEBUGLOG("reading proxy protocol header");
          iostate = state->d_handler.tryRead(state->d_buffer, state->d_currentPos, state->d_proxyProtocolNeed);
          if (iostate == IOState::Done) {
            state->d_buffer.resize(state->d_currentPos);
            ssize_t remaining = isProxyHeaderComplete(state->d_buffer);
            if (remaining == 0) {
              vinfolog("Unable to consume proxy protocol header in packet from TCP client %s", state->d_ci.remote.toStringWithPort());
              ++g_stats.proxyProtocolInvalid;
              break;
            }
            else if (remaining < 0) {
              state->d_proxyProtocolNeed += -remaining;
              state->d_buffer.resize(state->d_currentPos + state->d_proxyProtocolNeed);
              /* we need to keep reading, since we might have buffered data */
              iostate = IOState::NeedRead;
            }
            else {
              /* proxy header received */
              std::vector<ProxyProtocolValue> proxyProtocolValues;
              if (!handleProxyProtocol(state->d_ci.remote, true, *state->d_threadData.holders.acl, state->d_buffer, state->d_proxiedRemote, state->d_proxiedDestination, proxyProtocolValues)) {
                vinfolog("Error handling the Proxy Protocol received from TCP client %s", state->d_ci.remote.toStringWithPort());
                break;
              }

              if (!proxyProtocolValues.empty()) {
                state->d_proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
              }

              state->d_state = IncomingTCPConnectionState::State::readingQuerySize;
              state->d_buffer.resize(sizeof(uint16_t));
              state->d_currentPos = 0;
              state->d_proxyProtocolNeed = 0;
              break;
            }
          }
          else {
            state->d_lastIOBlocked = true;
          }
        }
        while (state->active() && !state->d_lastIOBlocked);
      }

      if (!state->d_lastIOBlocked && (state->d_state == IncomingTCPConnectionState::State::waitingForQuery ||
                                      state->d_state == IncomingTCPConnectionState::State::readingQuerySize)) {
        DEBUGLOG("reading query size");
        iostate = state->d_handler.tryRead(state->d_buffer, state->d_currentPos, sizeof(uint16_t));
        if (state->d_currentPos > 0) {
          /* if we got at least one byte, we can't go around sending responses */
          state->d_state = IncomingTCPConnectionState::State::readingQuerySize;
        }

        if (iostate == IOState::Done) {
          DEBUGLOG("query size received");
          state->d_state = IncomingTCPConnectionState::State::readingQuery;
          state->d_querySizeReadTime = now;
          if (state->d_queriesCount == 0) {
            state->d_firstQuerySizeReadTime = now;
          }
          state->d_querySize = state->d_buffer.at(0) * 256 + state->d_buffer.at(1);
          if (state->d_querySize < sizeof(dnsheader)) {
            /* go away */
            state->terminateClientConnection();
            return;
          }

          /* allocate a bit more memory to be able to spoof the content, get an answer from the cache
             or to add ECS without allocating a new buffer */
          state->d_buffer.resize(std::max(state->d_querySize + static_cast<size_t>(512), s_maxPacketCacheEntrySize));
          state->d_currentPos = 0;
        }
        else {
          state->d_lastIOBlocked = true;
        }
      }

      if (!state->d_lastIOBlocked && state->d_state == IncomingTCPConnectionState::State::readingQuery) {
        DEBUGLOG("reading query");
        iostate = state->d_handler.tryRead(state->d_buffer, state->d_currentPos, state->d_querySize);
        if (iostate == IOState::Done) {
          DEBUGLOG("query received");
          state->d_buffer.resize(state->d_querySize);

          state->d_state = IncomingTCPConnectionState::State::idle;
          handleQuery(state, now);
          /* the state might have been updated in the meantime, we don't want to override it
             in that case */
          if (state->active() && state->d_state != IncomingTCPConnectionState::State::idle) {
            if (state->d_ioState->isWaitingForRead()) {
              iostate = IOState::NeedRead;
            }
            else if (state->d_ioState->isWaitingForWrite()) {
              iostate = IOState::NeedWrite;
            }
            else {
              iostate = IOState::Done;
            }
          }
        }
        else {
          state->d_lastIOBlocked = true;
        }
      }

      if (!state->d_lastIOBlocked && state->d_state == IncomingTCPConnectionState::State::sendingResponse) {
        DEBUGLOG("sending response");
        iostate = state->d_handler.tryWrite(state->d_currentResponse.d_buffer, state->d_currentPos, state->d_currentResponse.d_buffer.size());
        if (iostate == IOState::Done) {
          DEBUGLOG("response sent from "<<__PRETTY_FUNCTION__);
          handleResponseSent(state, state->d_currentResponse);
          state->d_state = IncomingTCPConnectionState::State::idle;
        }
        else {
          state->d_lastIOBlocked = true;
        }
      }

      if (state->active() &&
          !state->d_lastIOBlocked &&
          iostate == IOState::Done &&
          (state->d_state == IncomingTCPConnectionState::State::idle ||
           state->d_state == IncomingTCPConnectionState::State::waitingForQuery))
      {
        // try sending queued responses
        DEBUGLOG("send responses, if any");
        iostate = sendQueuedResponses(state, now);

        if (!state->d_lastIOBlocked && state->active() && iostate == IOState::Done) {
          // if the query has been passed to a backend, or dropped, and the responses have been sent,
          // we can start reading again
          if (state->canAcceptNewQueries(now)) {
            state->resetForNewQuery();
            iostate = IOState::NeedRead;
          }
          else {
            state->d_state = IncomingTCPConnectionState::State::idle;
            iostate = IOState::Done;
          }
        }
      }

      if (state->d_state != IncomingTCPConnectionState::State::idle &&
          state->d_state != IncomingTCPConnectionState::State::doingHandshake &&
          state->d_state != IncomingTCPConnectionState::State::readingProxyProtocolHeader &&
          state->d_state != IncomingTCPConnectionState::State::waitingForQuery &&
          state->d_state != IncomingTCPConnectionState::State::readingQuerySize &&
          state->d_state != IncomingTCPConnectionState::State::readingQuery &&
          state->d_state != IncomingTCPConnectionState::State::sendingResponse) {
        vinfolog("Unexpected state %d in handleIOCallback", static_cast<int>(state->d_state));
      }
    }
    catch (const std::exception& e) {
      /* most likely an EOF because the other end closed the connection,
         but it might also be a real IO error or something else.
         Let's just drop the connection
      */
      if (state->d_state == IncomingTCPConnectionState::State::idle ||
          state->d_state == IncomingTCPConnectionState::State::waitingForQuery) {
        /* no need to increase any counters in that case, the client is simply done with us */
      }
      else if (state->d_state == IncomingTCPConnectionState::State::doingHandshake ||
               state->d_state != IncomingTCPConnectionState::State::readingProxyProtocolHeader ||
               state->d_state == IncomingTCPConnectionState::State::waitingForQuery ||
               state->d_state == IncomingTCPConnectionState::State::readingQuerySize ||
               state->d_state == IncomingTCPConnectionState::State::readingQuery) {
        ++state->d_ci.cs->tcpDiedReadingQuery;
      }
      else if (state->d_state == IncomingTCPConnectionState::State::sendingResponse) {
        /* unlikely to happen here, the exception should be handled in sendResponse() */
        ++state->d_ci.cs->tcpDiedSendingResponse;
      }

      if (state->d_ioState->isWaitingForWrite() || state->d_queriesCount == 0) {
        DEBUGLOG("Got an exception while handling TCP query: "<<e.what());
        vinfolog("Got an exception while handling (%s) TCP query from %s: %s", (state->d_ioState->isWaitingForRead() ? "reading" : "writing"), state->d_ci.remote.toStringWithPort(), e.what());
      }
      else {
        vinfolog("Closing TCP client connection with %s: %s", state->d_ci.remote.toStringWithPort(), e.what());
        DEBUGLOG("Closing TCP client connection: "<<e.what());
      }
      /* remove this FD from the IO multiplexer */
      state->terminateClientConnection();
    }

    if (!state->active()) {
      DEBUGLOG("state is no longer active");
      return;
    }

    if (iostate == IOState::Done) {
      state->d_ioState->update(iostate, handleIOCallback, state);
    }
    else {
      state->d_ioState->update(iostate, handleIOCallback, state, iostate == IOState::NeedRead ? state->getClientReadTTD(now) : state->getClientWriteTTD(now));
    }
    ioGuard.release();
  }
  while ((iostate == IOState::NeedRead || iostate == IOState::NeedWrite) && !state->d_lastIOBlocked);
}

void IncomingTCPConnectionState::notifyIOError(IDState&& query, const struct timeval& now)
{
  std::shared_ptr<IncomingTCPConnectionState> state = shared_from_this();

  --state->d_currentQueriesCount;
  state->d_hadErrors = true;

  if (state->d_state == State::sendingResponse) {
    /* if we have responses to send, let's do that first */
  }
  else if (!state->d_queuedResponses.empty()) {
    /* stop reading and send what we have */
    try {
      auto iostate = sendQueuedResponses(state, now);

      if (state->active() && iostate != IOState::Done) {
        // we need to update the state right away, nobody will do that for us
        state->d_ioState->update(iostate, handleIOCallback, state, iostate == IOState::NeedWrite ? state->getClientWriteTTD(now) : state->getClientReadTTD(now));
      }
    }
    catch (const std::exception& e) {
      vinfolog("Exception in notifyIOError: %s", e.what());
    }
  }
  else {
    // the backend code already tried to reconnect if it was possible
    state->terminateClientConnection();
  }
}

void IncomingTCPConnectionState::handleXFRResponse(const struct timeval& now, TCPResponse&& response)
{
  std::shared_ptr<IncomingTCPConnectionState> state = shared_from_this();
  queueResponse(state, now, std::move(response));
}

void IncomingTCPConnectionState::handleTimeout(std::shared_ptr<IncomingTCPConnectionState>& state, bool write)
{
  vinfolog("Timeout while %s TCP client %s", (write ? "writing to" : "reading from"), state->d_ci.remote.toStringWithPort());
  DEBUGLOG("client timeout");
  DEBUGLOG("Processed "<<state->d_queriesCount<<" queries, current count is "<<state->d_currentQueriesCount<<", "<<state->d_activeConnectionsToBackend.size()<<" active connections, "<<state->d_queuedResponses.size()<<" response queued");

  if (write || state->d_currentQueriesCount == 0) {
    ++state->d_ci.cs->tcpClientTimeouts;
    state->d_ioState.reset();
  }
  else {
    DEBUGLOG("Going idle");
    /* we still have some queries in flight, let's just stop reading for now */
    state->d_state = IncomingTCPConnectionState::State::idle;
    state->d_ioState->update(IOState::Done, handleIOCallback, state);

#ifdef DEBUGLOG_ENABLED
    for (const auto& active : state->d_activeConnectionsToBackend) {
      for (const auto& conn: active.second) {
        DEBUGLOG("Connection to "<<active.first->getName()<<" is "<<(conn->isIdle() ? "idle" : "not idle"));
      }
    }
#endif
  }
}

static void handleIncomingTCPQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  auto threadData = boost::any_cast<TCPClientThreadData*>(param);

  ConnectionInfo* citmp{nullptr};

  ssize_t got = read(pipefd, &citmp, sizeof(citmp));
  if (got == 0) {
    throw std::runtime_error("EOF while reading from the TCP acceptor pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode");
  }
  else if (got == -1) {
    if (errno == EAGAIN || errno == EINTR) {
      return;
    }
    throw std::runtime_error("Error while reading from the TCP acceptor pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode:" + stringerror());
  }
  else if (got != sizeof(citmp)) {
    throw std::runtime_error("Partial read while reading from the TCP acceptor pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode");
  }

  try {
    g_tcpclientthreads->decrementQueuedCount();

    struct timeval now;
    gettimeofday(&now, nullptr);
    auto state = std::make_shared<IncomingTCPConnectionState>(std::move(*citmp), *threadData, now);
    delete citmp;
    citmp = nullptr;

    IncomingTCPConnectionState::handleIO(state, now);
  }
  catch (...) {
    delete citmp;
    citmp = nullptr;
    throw;
  }
}

static void handleCrossProtocolQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  auto threadData = boost::any_cast<TCPClientThreadData*>(param);
  CrossProtocolQuery* tmp{nullptr};

  ssize_t got = read(pipefd, &tmp, sizeof(tmp));
  if (got == 0) {
    throw std::runtime_error("EOF while reading from the TCP cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode");
  }
  else if (got == -1) {
    if (errno == EAGAIN || errno == EINTR) {
      return;
    }
    throw std::runtime_error("Error while reading from the TCP cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode:" + stringerror());
  }
  else if (got != sizeof(tmp)) {
    throw std::runtime_error("Partial read while reading from the TCP cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode");
  }

  try {
    struct timeval now;
    gettimeofday(&now, nullptr);

    std::shared_ptr<TCPQuerySender> tqs = tmp->getTCPQuerySender();
    auto query = std::move(tmp->query);
    auto downstreamServer = std::move(tmp->downstream);
    auto proxyProtocolPayloadSize = tmp->proxyProtocolPayloadSize;
    delete tmp;
    tmp = nullptr;

    try {
      auto downstream = DownstreamConnectionsManager::getConnectionToDownstream(threadData->mplexer, downstreamServer, now);

      prependSizeToTCPQuery(query.d_buffer, proxyProtocolPayloadSize);
      downstream->queueQuery(tqs, std::move(query));
    }
    catch (...) {
      tqs->notifyIOError(std::move(query.d_idstate), now);
    }
  }
  catch (...) {
    delete tmp;
    tmp = nullptr;
  }
}

static void tcpClientThread(int pipefd, int crossProtocolPipeFD)
{
  /* we get launched with a pipe on which we receive file descriptors from clients that we own
     from that point on */

  setThreadName("dnsdist/tcpClie");

  TCPClientThreadData data;

  data.mplexer->addReadFD(pipefd, handleIncomingTCPQuery, &data);
  data.mplexer->addReadFD(crossProtocolPipeFD, handleCrossProtocolQuery, &data);

  struct timeval now;
  gettimeofday(&now, nullptr);
  time_t lastTimeoutScan = now.tv_sec;

  for (;;) {
    data.mplexer->run(&now);

    if (now.tv_sec > lastTimeoutScan) {
      lastTimeoutScan = now.tv_sec;
      auto expiredReadConns = data.mplexer->getTimeouts(now, false);
      for (const auto& cbData : expiredReadConns) {
        if (cbData.second.type() == typeid(std::shared_ptr<IncomingTCPConnectionState>)) {
          auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(cbData.second);
          if (cbData.first == state->d_handler.getDescriptor()) {
            vinfolog("Timeout (read) from remote TCP client %s", state->d_ci.remote.toStringWithPort());
            state->handleTimeout(state, false);
          }
        }
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
        else if (cbData.second.type() == typeid(std::shared_ptr<TCPConnectionToBackend>)) {
          auto conn = boost::any_cast<std::shared_ptr<TCPConnectionToBackend>>(cbData.second);
          vinfolog("Timeout (write) from remote backend %s", conn->getBackendName());
          conn->handleTimeout(now, true);
        }
      }

      if (g_tcpStatesDumpRequested > 0) {
        /* just to keep things clean in the output, debug only */
        static std::mutex s_lock;
        std::lock_guard<decltype(s_lock)> lck(s_lock);
        if (g_tcpStatesDumpRequested > 0) {
          /* no race here, we took the lock so it can only be increased in the meantime */
          --g_tcpStatesDumpRequested;
          errlog("Dumping the TCP states, as requested:");
          data.mplexer->runForAllWatchedFDs([](bool isRead, int fd, const FDMultiplexer::funcparam_t& param, struct timeval ttd)
          {
            struct timeval lnow;
            gettimeofday(&lnow, nullptr);
            if (ttd.tv_sec > 0) {
            errlog("- Descriptor %d is in %s state, TTD in %d", fd, (isRead ? "read" : "write"), (ttd.tv_sec-lnow.tv_sec));
            }
            else {
              errlog("- Descriptor %d is in %s state, no TTD set", fd, (isRead ? "read" : "write"));
            }

            if (param.type() == typeid(std::shared_ptr<IncomingTCPConnectionState>)) {
              auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);
              errlog(" - %s", state->toString());
            }
            else if (param.type() == typeid(std::shared_ptr<TCPConnectionToBackend>)) {
              auto conn = boost::any_cast<std::shared_ptr<TCPConnectionToBackend>>(param);
              errlog(" - %s", conn->toString());
            }
            else if (param.type() == typeid(TCPClientThreadData*)) {
              errlog(" - Worker thread pipe");
            }
          });
        }
      }
    }
  }
}

/* spawn as many of these as required, they call Accept on a socket on which they will accept queries, and
   they will hand off to worker threads & spawn more of them if required
*/
void tcpAcceptorThread(ClientState* cs)
{
  setThreadName("dnsdist/tcpAcce");

  bool tcpClientCountIncremented = false;
  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;

  auto acl = g_ACL.getLocal();
  for(;;) {
    std::unique_ptr<ConnectionInfo> ci;
    tcpClientCountIncremented = false;
    try {
      socklen_t remlen = remote.getSocklen();
      ci = std::make_unique<ConnectionInfo>(cs);
#ifdef HAVE_ACCEPT4
      ci->fd = accept4(cs->tcpFD, reinterpret_cast<struct sockaddr*>(&remote), &remlen, SOCK_NONBLOCK);
#else
      ci->fd = accept(cs->tcpFD, reinterpret_cast<struct sockaddr*>(&remote), &remlen);
#endif
      // will be decremented when the ConnectionInfo object is destroyed, no matter the reason
      auto concurrentConnections = ++cs->tcpCurrentConnections;
      if (cs->d_tcpConcurrentConnectionsLimit > 0 && concurrentConnections > cs->d_tcpConcurrentConnectionsLimit) {
        continue;
      }

      if (concurrentConnections > cs->tcpMaxConcurrentConnections) {
        cs->tcpMaxConcurrentConnections = concurrentConnections;
      }

      if (ci->fd < 0) {
        throw std::runtime_error((boost::format("accepting new connection on socket: %s") % stringerror()).str());
      }

      if (!acl->match(remote)) {
	++g_stats.aclDrops;
	vinfolog("Dropped TCP connection from %s because of ACL", remote.toStringWithPort());
	continue;
      }

#ifndef HAVE_ACCEPT4
      if (!setNonBlocking(ci->fd)) {
        continue;
      }
#endif
      setTCPNoDelay(ci->fd);  // disable NAGLE
      if (g_maxTCPQueuedConnections > 0 && g_tcpclientthreads->getQueuedCount() >= g_maxTCPQueuedConnections) {
        vinfolog("Dropping TCP connection from %s because we have too many queued already", remote.toStringWithPort());
        continue;
      }

      if (g_maxTCPConnectionsPerClient) {
        auto tcpClientsCount = s_tcpClientsCount.lock();

        if ((*tcpClientsCount)[remote] >= g_maxTCPConnectionsPerClient) {
          vinfolog("Dropping TCP connection from %s because we have too many from this client already", remote.toStringWithPort());
          continue;
        }
        (*tcpClientsCount)[remote]++;
        tcpClientCountIncremented = true;
      }

      vinfolog("Got TCP connection from %s", remote.toStringWithPort());

      ci->remote = remote;
      if (!g_tcpclientthreads->passConnectionToThread(std::move(ci))) {
        if (tcpClientCountIncremented) {
          decrementTCPClientCount(remote);
        }
      }
    }
    catch (const std::exception& e) {
      errlog("While reading a TCP question: %s", e.what());
      if (tcpClientCountIncremented) {
        decrementTCPClientCount(remote);
      }
    }
    catch (...){}
  }
}
