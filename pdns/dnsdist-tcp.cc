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

static std::mutex tcpClientsCountMutex;
static std::map<ComboAddress,size_t,ComboAddress::addressOnlyLessThan> tcpClientsCount;

uint64_t g_maxTCPQueuedConnections{1000};
size_t g_maxTCPQueriesPerConn{0};
size_t g_maxTCPConnectionDuration{0};
size_t g_maxTCPConnectionsPerClient{0};
uint16_t g_downstreamTCPCleanupInterval{60};
bool g_useTCPSinglePipe{false};

class DownstreamConnectionsManager
{
public:

  static std::shared_ptr<TCPConnectionToBackend> getConnectionToDownstream(std::unique_ptr<FDMultiplexer>& mplexer, std::shared_ptr<DownstreamState>& ds, const struct timeval& now)
  {
    std::shared_ptr<TCPConnectionToBackend> result;

    const auto& it = t_downstreamConnections.find(ds);
    if (it != t_downstreamConnections.end()) {
      auto& list = it->second;
      if (!list.empty()) {
        result = std::move(list.front());
        list.pop_front();
        result->setReused();
        return result;
      }
    }

    return std::make_shared<TCPConnectionToBackend>(ds, now);
  }

  static void releaseDownstreamConnection(std::shared_ptr<TCPConnectionToBackend>&& conn)
  {
    if (conn == nullptr) {
      return;
    }

    if (!conn->canBeReused()) {
      conn.reset();
      return;
    }

    const auto& ds = conn->getDS();
    const auto& it = t_downstreamConnections.find(ds);
    if (it != t_downstreamConnections.end()) {
      auto& list = it->second;
      if (list.size() >= s_maxCachedConnectionsPerDownstream) {
        /* too many connections queued already */
        conn.reset();
        return;
      }

      list.push_back(std::move(conn));
    }
    else {
      t_downstreamConnections[ds].push_back(std::move(conn));
    }
  }

  static void cleanupClosedTCPConnections()
  {
    for(auto dsIt = t_downstreamConnections.begin(); dsIt != t_downstreamConnections.end(); ) {
      for (auto connIt = dsIt->second.begin(); connIt != dsIt->second.end(); ) {
        if (*connIt && isTCPSocketUsable((*connIt)->getHandle())) {
          ++connIt;
        }
        else {
          connIt = dsIt->second.erase(connIt);
        }
      }

      if (!dsIt->second.empty()) {
        ++dsIt;
      }
      else {
        dsIt = t_downstreamConnections.erase(dsIt);
      }
    }
  }

private:
  static thread_local map<std::shared_ptr<DownstreamState>, std::deque<std::shared_ptr<TCPConnectionToBackend>>> t_downstreamConnections;
  static const size_t s_maxCachedConnectionsPerDownstream;
};

thread_local map<std::shared_ptr<DownstreamState>, std::deque<std::shared_ptr<TCPConnectionToBackend>>> DownstreamConnectionsManager::t_downstreamConnections;
const size_t DownstreamConnectionsManager::s_maxCachedConnectionsPerDownstream{20};

static void decrementTCPClientCount(const ComboAddress& client)
{
  if (g_maxTCPConnectionsPerClient) {
    std::lock_guard<std::mutex> lock(tcpClientsCountMutex);
    tcpClientsCount.at(client)--;
    if (tcpClientsCount[client] == 0) {
      tcpClientsCount.erase(client);
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
}

std::shared_ptr<TCPConnectionToBackend> IncomingTCPConnectionState::getDownstreamConnection(std::shared_ptr<DownstreamState>& ds, const struct timeval& now)
{
  std::shared_ptr<TCPConnectionToBackend> downstream{nullptr};

  if (!ds->useProxyProtocol || !d_proxyProtocolPayloadHasTLV) {
    downstream = getActiveDownstreamConnection(ds);
  }

  if (!downstream) {
    /* we don't have a connection to this backend active yet, let's ask one (it might not be a fresh one, though) */
    downstream = DownstreamConnectionsManager::getConnectionToDownstream(d_threadData.mplexer, ds, now);
    registerActiveDownstreamConnection(downstream);
  }

  return downstream;
}

static void tcpClientThread(int pipefd);

void TCPClientCollection::addTCPClientThread()
{
  int pipefds[2] = { -1, -1};

  vinfolog("Adding TCP Client thread");

  if (d_useSinglePipe) {
    pipefds[0] = d_singlePipe[0];
    pipefds[1] = d_singlePipe[1];
  }
  else {
    if (pipe(pipefds) < 0) {
      errlog("Error creating the TCP thread communication pipe: %s", stringerror());
      return;
    }

    if (!setNonBlocking(pipefds[0])) {
      int err = errno;
      close(pipefds[0]);
      close(pipefds[1]);
      errlog("Error setting the TCP thread communication pipe non-blocking: %s", stringerror(err));
      return;
    }

    if (!setNonBlocking(pipefds[1])) {
      int err = errno;
      close(pipefds[0]);
      close(pipefds[1]);
      errlog("Error setting the TCP thread communication pipe non-blocking: %s", stringerror(err));
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(d_mutex);

    if (d_numthreads >= d_tcpclientthreads.capacity()) {
      warnlog("Adding a new TCP client thread would exceed the vector capacity (%d/%d), skipping", d_numthreads.load(), d_tcpclientthreads.capacity());
      if (!d_useSinglePipe) {
        close(pipefds[0]);
        close(pipefds[1]);
      }
      return;
    }

    try {
      std::thread t1(tcpClientThread, pipefds[0]);
      t1.detach();
    }
    catch(const std::runtime_error& e) {
      /* the thread creation failed, don't leak */
      errlog("Error creating a TCP thread: %s", e.what());
      if (!d_useSinglePipe) {
        close(pipefds[0]);
        close(pipefds[1]);
      }
      return;
    }

    d_tcpclientthreads.push_back(pipefds[1]);
    ++d_numthreads;
  }
}

std::unique_ptr<TCPClientCollection> g_tcpclientthreads;

static IOState handleResponseSent(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now)
{
  --state->d_currentQueriesCount;

  if (!state->d_isXFR) {
    const auto& currentResponse = state->d_currentResponse;
    if (state->d_selfGeneratedResponse == false && currentResponse.d_connection && currentResponse.d_connection->getDS()) {
      const auto& ds = currentResponse.d_connection->getDS();
      struct timespec answertime;
      gettime(&answertime);
      const auto& ids = currentResponse.d_idstate;
      double udiff = ids.sentTime.udiff();
      g_rings.insertResponse(answertime, state->d_ci.remote, ids.qname, ids.qtype, static_cast<unsigned int>(udiff), static_cast<unsigned int>(currentResponse.d_buffer.size()), currentResponse.d_cleartextDH, ds->remote);
      vinfolog("Got answer from %s, relayed to %s (%s), took %f usec", ds->remote.toStringWithPort(), ids.origRemote.toStringWithPort(), (state->d_ci.cs->tlsFrontend ? "DoT" : "TCP"), udiff);
    }

    switch (currentResponse.d_cleartextDH.rcode) {
    case RCode::NXDomain:
      ++g_stats.frontendNXDomain;
      break;
    case RCode::ServFail:
      ++g_stats.servfailResponses;
      ++g_stats.frontendServFail;
      break;
    case RCode::NoError:
      ++g_stats.frontendNoError;
      break;
    }

    if (g_maxTCPQueriesPerConn && state->d_queriesCount > g_maxTCPQueriesPerConn) {
      vinfolog("Terminating TCP connection from %s because it reached the maximum number of queries per conn (%d / %d)", state->d_ci.remote.toStringWithPort(), state->d_queriesCount, g_maxTCPQueriesPerConn);
      return IOState::Done;
    }

    if (state->maxConnectionDurationReached(g_maxTCPConnectionDuration, now)) {
      vinfolog("Terminating TCP connection from %s because it reached the maximum TCP connection duration", state->d_ci.remote.toStringWithPort());
      return IOState::Done;
    }
  }

  if (state->d_queuedResponses.empty()) {
    if (state->d_isXFR) {
      /* we should still be reading from the backend, and we don't want to read from the client */
      state->d_state = IncomingTCPConnectionState::State::idle;
      state->d_currentPos = 0;
      DEBUGLOG("idling for XFR completion");
      return IOState::Done;
    } else {
      if (state->canAcceptNewQueries()) {
        DEBUGLOG("waiting for new queries");
        state->resetForNewQuery();
        return IOState::NeedRead;
      }
      else {
        DEBUGLOG("idling");
        state->d_state = IncomingTCPConnectionState::State::idle;
        return IOState::Done;
      }
    }
  }
  else {
    DEBUGLOG("queue size is "<<state->d_queuedResponses.size()<<", sending the next one");
    TCPResponse resp = std::move(state->d_queuedResponses.front());
    state->d_queuedResponses.pop_front();
    state->d_state = IncomingTCPConnectionState::State::idle;
    state->sendResponse(state, now, std::move(resp));
    return IOState::NeedWrite;
  }
}


bool IncomingTCPConnectionState::canAcceptNewQueries() const
{
  if (d_isXFR) {
    DEBUGLOG("not accepting new queries because used for XFR");
    return false;
  }

  if (d_currentQueriesCount >= d_ci.cs->d_maxInFlightQueriesPerConn) {
    DEBUGLOG("not accepting new queries because we already have "<<d_currentQueriesCount<<" out of "<<d_ci.cs->d_maxInFlightQueriesPerConn);
    return false;
  }

  return true;
}

void IncomingTCPConnectionState::resetForNewQuery()
{
  d_buffer.resize(sizeof(uint16_t));
  d_currentPos = 0;
  d_querySize = 0;
  d_downstreamFailures = 0;
  d_state = State::readingQuerySize;
  d_selfGeneratedResponse = false;
}

std::shared_ptr<TCPConnectionToBackend> IncomingTCPConnectionState::getActiveDownstreamConnection(const std::shared_ptr<DownstreamState>& ds)
{
  auto it = d_activeConnectionsToBackend.find(ds);
  if (it == d_activeConnectionsToBackend.end()) {
    DEBUGLOG("no active connection found for "<<ds->getName());
    return nullptr;
  }

  for (auto& conn : it->second) {
    if (conn->canAcceptNewQueries()) {
      DEBUGLOG("Got one active connection accepting more for "<<ds->getName());
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

/* this version is called when the buffer has been set and the rules have been processed */
void IncomingTCPConnectionState::sendResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response)
{
  // if we already reading a query (not the query size, mind you), or sending a response we need to either queue the response
  // otherwise we can start sending it right away
  if (state->d_state == IncomingTCPConnectionState::State::idle ||
      state->d_state == IncomingTCPConnectionState::State::readingQuerySize) {

    state->d_state = IncomingTCPConnectionState::State::sendingResponse;

    uint16_t responseSize = static_cast<uint16_t>(response.d_buffer.size());
    const uint8_t sizeBytes[] = { static_cast<uint8_t>(responseSize / 256), static_cast<uint8_t>(responseSize % 256) };
    /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
       that could occur if we had to deal with the size during the processing,
       especially alignment issues */
    response.d_buffer.insert(response.d_buffer.begin(), sizeBytes, sizeBytes + 2);
    state->d_currentPos = 0;
    state->d_currentResponse = std::move(response);

    state->d_ioState->update(IOState::NeedWrite, handleIOCallback, state, state->getClientWriteTTD(now));
  }
  else {
    // queue response
    state->d_queuedResponses.push_back(std::move(response));
    DEBUGLOG("queueing response because state is "<<(int)state->d_state<<", queue size is now "<<state->d_queuedResponses.size());
  }
}

/* this version is called from the backend code when a new response has been received */
void IncomingTCPConnectionState::handleResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response)
{
  // if we have added a TCP Proxy Protocol payload to a connection, don't release it yet, no one else will be able to use it anyway
  if (!state->d_isXFR && response.d_connection && response.d_connection->isIdle() && response.d_connection->canBeReused()) {
    auto& list = state->d_activeConnectionsToBackend.at(response.d_connection->getDS());
    for (auto it = list.begin(); it != list.end(); ++it) {
      if (*it == response.d_connection) {
        DownstreamConnectionsManager::releaseDownstreamConnection(std::move(*it));
        list.erase(it);
        break;
      }
    }
  }

  if (response.d_buffer.size() < sizeof(dnsheader)) {
    return;
  }

  uint16_t responseSize = response.d_buffer.size();
  response.d_buffer.resize(responseSize + static_cast<size_t>(512));
  size_t responseCapacity = response.d_buffer.size();
  auto responseAsCharArray = reinterpret_cast<char*>(&response.d_buffer.at(0));

  auto& ids = response.d_idstate;
  unsigned int consumed;
  if (!responseContentMatches(responseAsCharArray, responseSize, ids.qname, ids.qtype, ids.qclass, response.d_connection->getRemote(), consumed)) {
    return;
  }

  auto dh = reinterpret_cast<struct dnsheader*>(responseAsCharArray);
  uint16_t addRoom = 0;
  DNSResponse dr = makeDNSResponseFromIDState(ids, dh, responseCapacity, responseSize, true);
  if (dr.dnsCryptQuery) {
    addRoom = DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
  }

  memcpy(&response.d_cleartextDH, dr.dh, sizeof(response.d_cleartextDH));

  std::vector<uint8_t> rewrittenResponse;
  if (!processResponse(&responseAsCharArray, &responseSize, &responseCapacity, state->d_threadData.localRespRulactions, dr, addRoom, rewrittenResponse, false)) {
    return;
  }

  if (!rewrittenResponse.empty()) {
    /* responseSize has been updated as well but we don't really care since it will match
       the capacity of rewrittenResponse anyway */
    response.d_buffer = std::move(rewrittenResponse);
  } else {
    /* the size might have been updated (shrinked) if we removed the whole OPT RR, for example) */
    response.d_buffer.resize(responseSize);
  }

  if (state->d_isXFR && !state->d_xfrStarted) {
    /* don't bother parsing the content of the response for now */
    state->d_xfrStarted = true;
    ++g_stats.responses;
    ++state->d_ci.cs->responses;
    if (response.d_connection->getDS()) {
      ++response.d_connection->getDS()->responses;
    }
  }

  if (!state->d_isXFR) {
    ++g_stats.responses;
    ++state->d_ci.cs->responses;
    if (response.d_connection->getDS()) {
      ++response.d_connection->getDS()->responses;
    }
  }

  sendResponse(state, now, std::move(response));
}

static bool handleQuery(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now)
{
  if (state->d_querySize < sizeof(dnsheader)) {
    ++g_stats.nonCompliantQueries;
    return true;
  }

  state->d_readingFirstQuery = false;
  state->d_proxyProtocolPayloadAdded = false;
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

  auto query = reinterpret_cast<char*>(&state->d_buffer.at(0));
  std::shared_ptr<DNSCryptQuery> dnsCryptQuery{nullptr};
  auto dnsCryptResponse = checkDNSCryptQuery(*state->d_ci.cs, query, state->d_querySize, dnsCryptQuery, queryRealTime.tv_sec, true);
  if (dnsCryptResponse) {
    TCPResponse response;
    response.d_buffer = std::move(*dnsCryptResponse);
    state->d_state = IncomingTCPConnectionState::State::idle;
    ++state->d_currentQueriesCount;
    state->sendResponse(state, now, std::move(response));
    return false;
  }

  const auto& dh = reinterpret_cast<dnsheader*>(query);
  if (!checkQueryHeaders(dh)) {
    return true;
  }

  uint16_t qtype, qclass;
  unsigned int consumed = 0;
  DNSName qname(query, state->d_querySize, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  DNSQuestion dq(&qname, qtype, qclass, consumed, &state->d_origDest, &state->d_ci.remote, reinterpret_cast<dnsheader*>(query), state->d_buffer.size(), state->d_querySize, true, &queryRealTime);
  dq.dnsCryptQuery = std::move(dnsCryptQuery);
  dq.sni = state->d_handler.getServerNameIndication();

  state->d_isXFR = (dq.qtype == QType::AXFR || dq.qtype == QType::IXFR);
  if (state->d_isXFR) {
    dq.skipCache = true;
  }

  std::shared_ptr<DownstreamState> ds;
  auto result = processQuery(dq, *state->d_ci.cs, state->d_threadData.holders, ds);

  if (result == ProcessQueryResult::Drop) {
    return true;
  }

  if (result == ProcessQueryResult::SendAnswer) {
    state->d_selfGeneratedResponse = true;
    state->d_buffer.resize(dq.len);
    TCPResponse response;
    response.d_buffer = std::move(state->d_buffer);
    state->d_state = IncomingTCPConnectionState::State::idle;
    ++state->d_currentQueriesCount;
    state->sendResponse(state, now, std::move(response));
    return false;
  }

  if (result != ProcessQueryResult::PassToBackend || ds == nullptr) {
    return true;
  }

  IDState ids;
  setIDStateFromDNSQuestion(ids, dq, std::move(qname));
  ids.origID = ntohs(dh->id);

  const uint8_t sizeBytes[] = { static_cast<uint8_t>(dq.len / 256), static_cast<uint8_t>(dq.len % 256) };
  /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
     that could occur if we had to deal with the size during the processing,
     especially alignment issues */
  state->d_buffer.insert(state->d_buffer.begin(), sizeBytes, sizeBytes + 2);
  dq.len = dq.len + 2;
  dq.dh = reinterpret_cast<dnsheader*>(&state->d_buffer.at(0));
  dq.size = state->d_buffer.size();
  state->d_buffer.resize(dq.len);

  bool proxyProtocolPayloadAdded = false;
  std::string proxyProtocolPayload;

  if (ds->useProxyProtocol) {
    /* if we ever sent a TLV over a connection, we can never go back */
    if (!state->d_proxyProtocolPayloadHasTLV) {
      state->d_proxyProtocolPayloadHasTLV = dq.proxyProtocolValues && !dq.proxyProtocolValues->empty();
    }

    proxyProtocolPayload = getProxyProtocolPayload(dq);

    if (state->d_proxyProtocolPayloadHasTLV) {
      /* we will not be able to reuse an existing connection anyway so let's add the payload right now */
      addProxyProtocol(state->d_buffer, proxyProtocolPayload);
      proxyProtocolPayloadAdded = true;
    }
  }

  auto downstreamConnection = state->getDownstreamConnection(ds, now);
  downstreamConnection->assignToClientConnection(state, state->d_isXFR);

  if (proxyProtocolPayloadAdded) {
    downstreamConnection->setProxyProtocolPayloadAdded(true);
  }
  else {
    downstreamConnection->setProxyProtocolPayload(std::move(proxyProtocolPayload));
  }

  ++state->d_currentQueriesCount;
  vinfolog("Got query for %s|%s from %s (%s, %d bytes), relayed to %s", ids.qname.toLogString(), QType(ids.qtype).getName(), state->d_ci.remote.toStringWithPort(), (state->d_ci.cs->tlsFrontend ? "DoT" : "TCP"), state->d_buffer.size(), ds->getName());
  downstreamConnection->queueQuery(TCPQuery(std::move(state->d_buffer), std::move(ids)), downstreamConnection);

  return true;
}

void IncomingTCPConnectionState::handleIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);
  if (fd != conn->d_ci.fd) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->d_ci.fd));
  }

  struct timeval now;
  gettimeofday(&now, 0);
  handleIO(conn, now);
}

void IncomingTCPConnectionState::handleIO(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now)
{
  // why do we loop? Because the TLS layer does buffering, and thus can have data ready to read
  // even though the underlying socket is not ready, so we need to actually ask for the data first
  bool wouldBlock = false;
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
          state->d_state = IncomingTCPConnectionState::State::readingQuerySize;
        }
        else {
          wouldBlock = true;
        }
      }

      if (state->d_state == IncomingTCPConnectionState::State::readingQuerySize) {
        DEBUGLOG("reading query size");
        iostate = state->d_handler.tryRead(state->d_buffer, state->d_currentPos, sizeof(uint16_t));
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
            return;
          }

          /* allocate a bit more memory to be able to spoof the content, get an answer from the cache
             or to add ECS without allocating a new buffer */
          state->d_buffer.resize(std::max(state->d_querySize + static_cast<size_t>(512), s_maxPacketCacheEntrySize));
          state->d_currentPos = 0;
        }
        else {
          wouldBlock = true;
        }
      }

      if (state->d_state == IncomingTCPConnectionState::State::readingQuery) {
        DEBUGLOG("reading query");
        iostate = state->d_handler.tryRead(state->d_buffer, state->d_currentPos, state->d_querySize);
        if (iostate == IOState::Done) {
          DEBUGLOG("query received");

          if (handleQuery(state, now)) {
            // if the query has been passed to a backend, or dropped, we can start
            // reading again, or sending queued responses
            if (state->d_queuedResponses.empty()) {
              if (state->canAcceptNewQueries()) {
                state->resetForNewQuery();
                iostate = IOState::NeedRead;
              }
              else {
                state->d_state = IncomingTCPConnectionState::State::idle;
                iostate = IOState::Done;
              }
            }
            else {
              TCPResponse resp = std::move(state->d_queuedResponses.front());
              state->d_queuedResponses.pop_front();
              ioGuard.release();
              state->d_state = IncomingTCPConnectionState::State::idle;
              state->sendResponse(state, now, std::move(resp));
              return;
            }
          }
          else {
            /* otherwise the state should already be waiting for
               the socket to be writable */
            ioGuard.release();
            return;
          }
        }
        else {
          wouldBlock = true;
        }
      }

      if (state->d_state == IncomingTCPConnectionState::State::sendingResponse) {
        DEBUGLOG("sending response");
        iostate = state->d_handler.tryWrite(state->d_currentResponse.d_buffer, state->d_currentPos, state->d_currentResponse.d_buffer.size());
        if (iostate == IOState::Done) {
          DEBUGLOG("response sent");
          iostate = handleResponseSent(state, now);
        } else {
          wouldBlock = true;
          DEBUGLOG("partial write");
        }
      }

      if (state->d_state != IncomingTCPConnectionState::State::idle &&
          state->d_state != IncomingTCPConnectionState::State::doingHandshake &&
          state->d_state != IncomingTCPConnectionState::State::readingQuerySize &&
          state->d_state != IncomingTCPConnectionState::State::readingQuery &&
          state->d_state != IncomingTCPConnectionState::State::sendingResponse) {
        vinfolog("Unexpected state %d in handleIOCallback", static_cast<int>(state->d_state));
      }
    }
    catch(const std::exception& e) {
      /* most likely an EOF because the other end closed the connection,
         but it might also be a real IO error or something else.
         Let's just drop the connection
      */
      if (state->d_state == IncomingTCPConnectionState::State::idle ||
          state->d_state == IncomingTCPConnectionState::State::doingHandshake ||
          state->d_state == IncomingTCPConnectionState::State::readingQuerySize ||
          state->d_state == IncomingTCPConnectionState::State::readingQuery) {
        ++state->d_ci.cs->tcpDiedReadingQuery;
      }
      else if (state->d_state == IncomingTCPConnectionState::State::sendingResponse) {
        ++state->d_ci.cs->tcpDiedSendingResponse;
      }

      if (state->d_ioState->getState() == IOState::NeedWrite || state->d_readingFirstQuery) {
        DEBUGLOG("Got an exception while handling TCP query: "<<e.what());
        vinfolog("Got an exception while handling (%s) TCP query from %s: %s", (state->d_ioState->getState() == IOState::NeedRead ? "reading" : "writing"), state->d_ci.remote.toStringWithPort(), e.what());
      }
      else {
        vinfolog("Closing TCP client connection with %s: %s", state->d_ci.remote.toStringWithPort(), e.what());
        DEBUGLOG("Closing TCP client connection: "<<e.what());
      }
      /* remove this FD from the IO multiplexer */
      iostate = IOState::Done;
    }

    if (iostate == IOState::Done) {
      state->d_ioState->update(iostate, handleIOCallback, state);
    }
    else {
      state->d_ioState->update(iostate, handleIOCallback, state, iostate == IOState::NeedRead ? state->getClientReadTTD(now) : state->getClientWriteTTD(now));
    }
    ioGuard.release();
  }
  while (state->d_state == IncomingTCPConnectionState::State::readingQuerySize && iostate == IOState::NeedRead && !wouldBlock);
}

void IncomingTCPConnectionState::notifyIOError(std::shared_ptr<IncomingTCPConnectionState>& state, IDState&& query, const struct timeval& now)
{
  if (state->d_state == State::sendingResponse) {
    /* if we have responses to send, let's do that first */
  }
  else if (!state->d_queuedResponses.empty()) {
    /* stop reading and send what we have */
    TCPResponse resp = std::move(state->d_queuedResponses.front());
    state->d_queuedResponses.pop_front();
    state->d_state = IncomingTCPConnectionState::State::idle;
    sendResponse(state, now, std::move(resp));
  }
  else {
    // the backend code already tried to reconnect if it was possible
    state->d_ioState->reset();
  }
}

void IncomingTCPConnectionState::handleXFRResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response)
{
  sendResponse(state, now, std::move(response));
}

void IncomingTCPConnectionState::handleTimeout(std::shared_ptr<IncomingTCPConnectionState>& state, bool write)
{
  DEBUGLOG("client timeout");
  DEBUGLOG("Processed "<<state->d_queriesCount<<" queries, current count is "<<state->d_currentQueriesCount<<", "<<state->d_activeConnectionsToBackend.size()<<" active connections, "<<state->d_queuedResponses.size()<<" response queued");

  if (write || state->d_currentQueriesCount == 0) {
    ++state->d_ci.cs->tcpClientTimeouts;
    state->d_ioState->reset();
  }
  else {
    DEBUGLOG("Going idle");
    /* we still have some queries in flight, let's just stop reading for now */
    state->d_state = IncomingTCPConnectionState::State::idle;
    state->d_ioState->update(IOState::Done, handleIOCallback, state);
    for (const auto& active : state->d_activeConnectionsToBackend) {
      for (const auto& conn: active.second) {
        DEBUGLOG("Connection to "<<active.first->getName()<<" is "<<(conn->isIdle() ? "idle" : "not idle"));
      }
    }
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
    gettimeofday(&now, 0);
    auto state = std::make_shared<IncomingTCPConnectionState>(std::move(*citmp), *threadData, now);
    delete citmp;
    citmp = nullptr;

    /* let's update the remaining time */
    state->d_remainingTime = g_maxTCPConnectionDuration;

    IncomingTCPConnectionState::handleIO(state, now);
  }
  catch(...) {
    delete citmp;
    citmp = nullptr;
    throw;
  }
}

static void tcpClientThread(int pipefd)
{
  /* we get launched with a pipe on which we receive file descriptors from clients that we own
     from that point on */

  setThreadName("dnsdist/tcpClie");

  TCPClientThreadData data;

  data.mplexer->addReadFD(pipefd, handleIncomingTCPQuery, &data);
  struct timeval now;
  gettimeofday(&now, 0);
  time_t lastTCPCleanup = now.tv_sec;
  time_t lastTimeoutScan = now.tv_sec;

  for (;;) {
    data.mplexer->run(&now);

    if (g_downstreamTCPCleanupInterval > 0 && (now.tv_sec > (lastTCPCleanup + g_downstreamTCPCleanupInterval))) {
      DownstreamConnectionsManager::cleanupClosedTCPConnections();
      lastTCPCleanup = now.tv_sec;
    }

    if (now.tv_sec > lastTimeoutScan) {
      lastTimeoutScan = now.tv_sec;
      auto expiredReadConns = data.mplexer->getTimeouts(now, false);
      for (const auto& cbData : expiredReadConns) {
        if (cbData.second.type() == typeid(std::shared_ptr<IncomingTCPConnectionState>)) {
          auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(cbData.second);
          if (cbData.first == state->d_ci.fd) {
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
          if (cbData.first == state->d_ci.fd) {
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

  if(!g_tcpclientthreads->hasReachedMaxThreads()) {
    g_tcpclientthreads->addTCPClientThread();
  }

  auto acl = g_ACL.getLocal();
  for(;;) {
    bool queuedCounterIncremented = false;
    std::unique_ptr<ConnectionInfo> ci;
    tcpClientCountIncremented = false;
    try {
      socklen_t remlen = remote.getSocklen();
      ci = std::unique_ptr<ConnectionInfo>(new ConnectionInfo(cs));
#ifdef HAVE_ACCEPT4
      ci->fd = accept4(cs->tcpFD, reinterpret_cast<struct sockaddr*>(&remote), &remlen, SOCK_NONBLOCK);
#else
      ci->fd = accept(cs->tcpFD, reinterpret_cast<struct sockaddr*>(&remote), &remlen);
#endif
      ++cs->tcpCurrentConnections;

      if(ci->fd < 0) {
        throw std::runtime_error((boost::format("accepting new connection on socket: %s") % stringerror()).str());
      }

      if(!acl->match(remote)) {
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
      if(g_maxTCPQueuedConnections > 0 && g_tcpclientthreads->getQueuedCount() >= g_maxTCPQueuedConnections) {
        vinfolog("Dropping TCP connection from %s because we have too many queued already", remote.toStringWithPort());
        continue;
      }

      if (g_maxTCPConnectionsPerClient) {
        std::lock_guard<std::mutex> lock(tcpClientsCountMutex);

        if (tcpClientsCount[remote] >= g_maxTCPConnectionsPerClient) {
          vinfolog("Dropping TCP connection from %s because we have too many from this client already", remote.toStringWithPort());
          continue;
        }
        tcpClientsCount[remote]++;
        tcpClientCountIncremented = true;
      }

      vinfolog("Got TCP connection from %s", remote.toStringWithPort());

      ci->remote = remote;
      int pipe = g_tcpclientthreads->getThread();
      if (pipe >= 0) {
        queuedCounterIncremented = true;
        auto tmp = ci.release();
        try {
          writen2WithTimeout(pipe, &tmp, sizeof(tmp), 0);
        }
        catch(...) {
          delete tmp;
          tmp = nullptr;
          throw;
        }
      }
      else {
        g_tcpclientthreads->decrementQueuedCount();
        queuedCounterIncremented = false;
        if(tcpClientCountIncremented) {
          decrementTCPClientCount(remote);
        }
      }
    }
    catch(const std::exception& e) {
      errlog("While reading a TCP question: %s", e.what());
      if(tcpClientCountIncremented) {
        decrementTCPClientCount(remote);
      }
      if (queuedCounterIncremented) {
        g_tcpclientthreads->decrementQueuedCount();
      }
    }
    catch(...){}
  }
}
