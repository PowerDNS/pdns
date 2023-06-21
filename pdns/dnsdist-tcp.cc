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
#include "dnsdist-concurrent-connections.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-nghttp2-in.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-downstream-connection.hh"
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

size_t g_maxTCPQueriesPerConn{0};
size_t g_maxTCPConnectionDuration{0};

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

LockGuarded<std::map<ComboAddress, size_t, ComboAddress::addressOnlyLessThan>> dnsdist::IncomingConcurrentTCPConnectionsManager::s_tcpClientsConcurrentConnectionsCount;
size_t dnsdist::IncomingConcurrentTCPConnectionsManager::s_maxTCPConnectionsPerClient = 0;

IncomingTCPConnectionState::~IncomingTCPConnectionState()
{
  dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(d_ci.remote);

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

std::shared_ptr<TCPConnectionToBackend> IncomingTCPConnectionState::getDownstreamConnection(std::shared_ptr<DownstreamState>& ds, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs, const struct timeval& now)
{
  std::shared_ptr<TCPConnectionToBackend> downstream{nullptr};

  downstream = getOwnedDownstreamConnection(ds, tlvs);

  if (!downstream) {
    /* we don't have a connection to this backend owned yet, let's get one (it might not be a fresh one, though) */
    downstream = t_downstreamTCPConnectionsManager.getConnectionToDownstream(d_threadData.mplexer, ds, now, std::string());
    if (ds->d_config.useProxyProtocol) {
      registerOwnedDownstreamConnection(downstream);
    }
  }

  return downstream;
}

static void tcpClientThread(pdns::channel::Receiver<ConnectionInfo>&& queryReceiver, pdns::channel::Receiver<CrossProtocolQuery>&& crossProtocolQueryReceiver, pdns::channel::Receiver<TCPCrossProtocolResponse>&& crossProtocolResponseReceiver, pdns::channel::Sender<TCPCrossProtocolResponse>&& crossProtocolResponseSender, std::vector<ClientState*> tcpAcceptStates);

TCPClientCollection::TCPClientCollection(size_t maxThreads, std::vector<ClientState*> tcpAcceptStates): d_tcpclientthreads(maxThreads), d_maxthreads(maxThreads)
{
  for (size_t idx = 0; idx < maxThreads; idx++) {
    addTCPClientThread(tcpAcceptStates);
  }
}

void TCPClientCollection::addTCPClientThread(std::vector<ClientState*>& tcpAcceptStates)
{
  try {
    auto [queryChannelSender, queryChannelReceiver] = pdns::channel::createObjectQueue<ConnectionInfo>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, g_tcpInternalPipeBufferSize);

    auto [crossProtocolQueryChannelSender, crossProtocolQueryChannelReceiver] = pdns::channel::createObjectQueue<CrossProtocolQuery>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, g_tcpInternalPipeBufferSize);

    auto [crossProtocolResponseChannelSender, crossProtocolResponseChannelReceiver] = pdns::channel::createObjectQueue<TCPCrossProtocolResponse>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, g_tcpInternalPipeBufferSize);

    vinfolog("Adding TCP Client thread");

    if (d_numthreads >= d_tcpclientthreads.size()) {
      vinfolog("Adding a new TCP client thread would exceed the vector size (%d/%d), skipping. Consider increasing the maximum amount of TCP client threads with setMaxTCPClientThreads() in the configuration.", d_numthreads.load(), d_tcpclientthreads.size());
      return;
    }

    TCPWorkerThread worker(std::move(queryChannelSender), std::move(crossProtocolQueryChannelSender));

    try {
      std::thread t1(tcpClientThread, std::move(queryChannelReceiver), std::move(crossProtocolQueryChannelReceiver), std::move(crossProtocolResponseChannelReceiver), std::move(crossProtocolResponseChannelSender), tcpAcceptStates);
      t1.detach();
    }
    catch (const std::runtime_error& e) {
      errlog("Error creating a TCP thread: %s", e.what());
      return;
    }

    d_tcpclientthreads.at(d_numthreads) = std::move(worker);
    ++d_numthreads;
  }
  catch (const std::exception& e) {
    errlog("Error creating TCP worker: %", e.what());
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
    result = state->sendResponse(now, std::move(resp));
    if (result != IOState::Done) {
      return result;
    }
  }

  state->d_state = IncomingTCPConnectionState::State::idle;
  return IOState::Done;
}

void IncomingTCPConnectionState::handleResponseSent(TCPResponse& currentResponse)
{
  if (currentResponse.d_idstate.qtype == QType::AXFR || currentResponse.d_idstate.qtype == QType::IXFR) {
    return;
  }

  --d_currentQueriesCount;

  const auto& ds = currentResponse.d_connection ? currentResponse.d_connection->getDS() : currentResponse.d_ds;
  if (currentResponse.d_idstate.selfGenerated == false && ds) {
    const auto& ids = currentResponse.d_idstate;
    double udiff = ids.queryRealTime.udiff();
    vinfolog("Got answer from %s, relayed to %s (%s, %d bytes), took %f us", ds->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), getProtocol().toString(), currentResponse.d_buffer.size(), udiff);

    auto backendProtocol = ds->getProtocol();
    if (backendProtocol == dnsdist::Protocol::DoUDP && !currentResponse.d_idstate.forwardedOverUDP) {
      backendProtocol = dnsdist::Protocol::DoTCP;
    }
    ::handleResponseSent(ids, udiff, d_ci.remote, ds->d_config.remote, static_cast<unsigned int>(currentResponse.d_buffer.size()), currentResponse.d_cleartextDH, backendProtocol, true);
  } else {
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

  // for DoH, this is already handled by the underlying library
  if (!d_ci.cs->dohFrontend && d_currentQueriesCount >= d_ci.cs->d_maxInFlightQueriesPerConn) {
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
  d_buffer.clear();
  d_currentPos = 0;
  d_querySize = 0;
  d_state = State::waitingForQuery;
}

std::shared_ptr<TCPConnectionToBackend> IncomingTCPConnectionState::getOwnedDownstreamConnection(const std::shared_ptr<DownstreamState>& ds, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs)
{
  auto it = d_ownedConnectionsToBackend.find(ds);
  if (it == d_ownedConnectionsToBackend.end()) {
    DEBUGLOG("no owned connection found for "<<ds->getName());
    return nullptr;
  }

  for (auto& conn : it->second) {
    if (conn->canBeReused(true) && conn->matchesTLVs(tlvs)) {
      DEBUGLOG("Got one owned connection accepting more for "<<ds->getName());
      conn->setReused();
      return conn;
    }
    DEBUGLOG("not accepting more for "<<ds->getName());
  }

  return nullptr;
}

void IncomingTCPConnectionState::registerOwnedDownstreamConnection(std::shared_ptr<TCPConnectionToBackend>& conn)
{
  d_ownedConnectionsToBackend[conn->getDS()].push_front(conn);
}

/* called when the buffer has been set and the rules have been processed, and only from handleIO (sometimes indirectly via handleQuery) */
IOState IncomingTCPConnectionState::sendResponse(const struct timeval& now, TCPResponse&& response)
{
  d_state = IncomingTCPConnectionState::State::sendingResponse;

  uint16_t responseSize = static_cast<uint16_t>(response.d_buffer.size());
  const uint8_t sizeBytes[] = { static_cast<uint8_t>(responseSize / 256), static_cast<uint8_t>(responseSize % 256) };
  /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
     that could occur if we had to deal with the size during the processing,
     especially alignment issues */
  response.d_buffer.insert(response.d_buffer.begin(), sizeBytes, sizeBytes + 2);
  d_currentPos = 0;
  d_currentResponse = std::move(response);

  try {
    auto iostate = d_handler.tryWrite(d_currentResponse.d_buffer, d_currentPos, d_currentResponse.d_buffer.size());
    if (iostate == IOState::Done) {
      DEBUGLOG("response sent from "<<__PRETTY_FUNCTION__);
      handleResponseSent(d_currentResponse);
      return iostate;
    } else {
      d_lastIOBlocked = true;
      DEBUGLOG("partial write");
      return iostate;
    }
  }
  catch (const std::exception& e) {
    vinfolog("Closing TCP client connection with %s: %s", d_ci.remote.toStringWithPort(), e.what());
    DEBUGLOG("Closing TCP client connection: "<<e.what());
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
      conn->release();
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
    for (const auto fd : afds) {
      try {
        state->d_threadData.mplexer->addReadFD(fd, handleAsyncReady, state);
      }
      catch (...) {
      }
    }

  }
}

void IncomingTCPConnectionState::queueResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response)
{
  // queue response
  state->d_queuedResponses.emplace_back(std::move(response));
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
      updateIO(state, iostate, now);
    }
  }
}

void IncomingTCPConnectionState::handleAsyncReady(int fd, FDMultiplexer::funcparam_t& param)
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

void IncomingTCPConnectionState::updateIO(std::shared_ptr<IncomingTCPConnectionState>& state, IOState newState, const struct timeval& now)
{
  if (newState == IOState::Async) {
    auto fds = state->d_handler.getAsyncFDs();
    for (const auto fd : fds) {
      state->d_threadData.mplexer->addReadFD(fd, handleAsyncReady, state);
    }
    state->d_ioState->update(IOState::Done, handleIOCallback, state);
  }
  else {
    state->d_ioState->update(newState, handleIOCallback, state, newState == IOState::NeedWrite ? state->getClientWriteTTD(now) : state->getClientReadTTD(now));
  }
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
              response.d_connection->release();
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
      unsigned int qnameWireLength;
      std::shared_ptr<DownstreamState> ds = response.d_ds ? response.d_ds : (response.d_connection ? response.d_connection->getDS() : nullptr);
      if (!ds || !responseContentMatches(response.d_buffer, ids.qname, ids.qtype, ids.qclass, ds, qnameWireLength)) {
        state->terminateClientConnection();
        return;
      }

      if (ds) {
        ++ds->responses;
      }

      DNSResponse dr(ids, response.d_buffer, ds);
      dr.d_incomingTCPState = state;

      memcpy(&response.d_cleartextDH, dr.getHeader(), sizeof(response.d_cleartextDH));

      if (!processResponse(response.d_buffer, *state->d_threadData.localRespRuleActions, *state->d_threadData.localCacheInsertedRespRuleActions, dr, false)) {
        state->terminateClientConnection();
        return;
      }

      if (dr.isAsynchronous()) {
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

  queueResponse(state, now, std::move(response));
}

struct TCPCrossProtocolResponse
{
  TCPCrossProtocolResponse(TCPResponse&& response, std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now): d_response(std::move(response)), d_state(state), d_now(now)
  {
  }

  TCPResponse d_response;
  std::shared_ptr<IncomingTCPConnectionState> d_state;
  struct timeval d_now;
};

class TCPCrossProtocolQuery : public CrossProtocolQuery
{
public:
  TCPCrossProtocolQuery(PacketBuffer&& buffer, InternalQueryState&& ids, std::shared_ptr<DownstreamState> ds, std::shared_ptr<IncomingTCPConnectionState> sender): CrossProtocolQuery(InternalQuery(std::move(buffer), std::move(ids)), ds), d_sender(std::move(sender))
  {
  }

  ~TCPCrossProtocolQuery()
  {
  }

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    return d_sender;
  }

  DNSQuestion getDQ() override
  {
    auto& ids = query.d_idstate;
    DNSQuestion dq(ids, query.d_buffer);
    dq.d_incomingTCPState = d_sender;
    return dq;
  }

  DNSResponse getDR() override
  {
    auto& ids = query.d_idstate;
    DNSResponse dr(ids, query.d_buffer, downstream);
    dr.d_incomingTCPState = d_sender;
    return dr;
  }

private:
  std::shared_ptr<IncomingTCPConnectionState> d_sender;
};

std::unique_ptr<CrossProtocolQuery> IncomingTCPConnectionState::getCrossProtocolQuery(PacketBuffer&& query, InternalQueryState&& state, const std::shared_ptr<DownstreamState>& ds)
{
  return std::make_unique<TCPCrossProtocolQuery>(std::move(query), std::move(state), ds, shared_from_this());
}

std::unique_ptr<CrossProtocolQuery> getTCPCrossProtocolQueryFromDQ(DNSQuestion& dq)
{
  auto state = dq.getIncomingTCPState();
  if (!state) {
    throw std::runtime_error("Trying to create a TCP cross protocol query without a valid TCP state");
  }

  dq.ids.origID = dq.getHeader()->id;
  return std::make_unique<TCPCrossProtocolQuery>(std::move(dq.getMutableData()), std::move(dq.ids), nullptr, std::move(state));
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
    d_state = IncomingTCPConnectionState::State::idle;
    ++d_currentQueriesCount;
    queueResponse(state, now, std::move(response));
    return QueryProcessingResult::SelfAnswered;
  }

  {
    /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
    auto* dh = reinterpret_cast<dnsheader*>(query.data());
    if (!checkQueryHeaders(dh, *d_ci.cs)) {
      return QueryProcessingResult::InvalidHeaders;
    }

    if (dh->qdcount == 0) {
      TCPResponse response;
      dh->rcode = RCode::NotImp;
      dh->qr = true;
      response.d_idstate.selfGenerated = true;
      response.d_buffer = std::move(query);
      d_state = IncomingTCPConnectionState::State::idle;
      ++d_currentQueriesCount;
      queueResponse(state, now, std::move(response));
      return QueryProcessingResult::Empty;
    }
  }

  ids.qname = DNSName(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
  ids.protocol = getProtocol();
  if (ids.dnsCryptQuery) {
    ids.protocol = dnsdist::Protocol::DNSCryptTCP;
  }

  DNSQuestion dq(ids, query);
  const uint16_t* flags = getFlagsFromDNSHeader(dq.getHeader());
  ids.origFlags = *flags;
  dq.d_incomingTCPState = state;
  dq.sni = d_handler.getServerNameIndication();

  if (d_proxyProtocolValues) {
    /* we need to copy them, because the next queries received on that connection will
       need to get the _unaltered_ values */
    dq.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(*d_proxyProtocolValues);
  }

  if (dq.ids.qtype == QType::AXFR || dq.ids.qtype == QType::IXFR) {
    dq.ids.skipCache = true;
  }

  if (forwardViaUDPFirst()) {
    // if there was no EDNS, we add it with a large buffer size
    // so we can use UDP to talk to the backend.
    auto dh = const_cast<struct dnsheader*>(reinterpret_cast<const struct dnsheader*>(query.data()));
    if (!dh->arcount) {
      if (addEDNS(query, 4096, false, 4096, 0)) {
        dq.ids.ednsAdded = true;
      }
    }
  }

  if (streamID) {
    auto unit = getDOHUnit(*streamID);
    dq.ids.du = std::move(unit);
  }

  std::shared_ptr<DownstreamState> ds;
  auto result = processQuery(dq, d_threadData.holders, ds);

  if (result == ProcessQueryResult::Asynchronous) {
    /* we are done for now */
    ++d_currentQueriesCount;
    return QueryProcessingResult::Asynchronous;
  }

  if (streamID) {
    restoreDOHUnit(std::move(dq.ids.du));
  }

  if (result == ProcessQueryResult::Drop) {
    return QueryProcessingResult::Dropped;
  }

  // the buffer might have been invalidated by now
  uint16_t queryID;
  {
    const dnsheader* dh = dq.getHeader();
    queryID = dh->id;
  }

  if (result == ProcessQueryResult::SendAnswer) {
    TCPResponse response;
    {
      const dnsheader* dh = dq.getHeader();
      memcpy(&response.d_cleartextDH, dh, sizeof(response.d_cleartextDH));
    }
    response.d_idstate = std::move(ids);
    response.d_idstate.origID = queryID;
    response.d_idstate.selfGenerated = true;
    response.d_idstate.cs = d_ci.cs;
    response.d_buffer = std::move(query);

    d_state = IncomingTCPConnectionState::State::idle;
    ++d_currentQueriesCount;
    queueResponse(state, now, std::move(response));
    return QueryProcessingResult::SelfAnswered;
  }

  if (result != ProcessQueryResult::PassToBackend || ds == nullptr) {
    return QueryProcessingResult::NoBackend;
  }

  dq.ids.origID = queryID;

  ++d_currentQueriesCount;

  std::string proxyProtocolPayload;
  if (ds->isDoH()) {
    vinfolog("Got query for %s|%s from %s (%s, %d bytes), relayed to %s", ids.qname.toLogString(), QType(ids.qtype).toString(), d_proxiedRemote.toStringWithPort(), getProtocol().toString(), query.size(), ds->getNameWithAddr());

    /* we need to do this _before_ creating the cross protocol query because
       after that the buffer will have been moved */
    if (ds->d_config.useProxyProtocol) {
      proxyProtocolPayload = getProxyProtocolPayload(dq);
    }

    auto cpq = std::make_unique<TCPCrossProtocolQuery>(std::move(query), std::move(ids), ds, state);
    cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

    ds->passCrossProtocolQuery(std::move(cpq));
    return QueryProcessingResult::Forwarded;
  }
  else if (!ds->isTCPOnly() && forwardViaUDPFirst()) {
    auto unit = getDOHUnit(*streamID);
    dq.ids.du = std::move(unit);
    if (assignOutgoingUDPQueryToBackend(ds, queryID, dq, query)) {
      return QueryProcessingResult::Forwarded;
    }
    restoreDOHUnit(std::move(dq.ids.du));
    // fallback to the normal flow
  }

  prependSizeToTCPQuery(query, 0);

  auto downstreamConnection = getDownstreamConnection(ds, dq.proxyProtocolValues, now);

  if (ds->d_config.useProxyProtocol) {
    /* if we ever sent a TLV over a connection, we can never go back */
    if (!d_proxyProtocolPayloadHasTLV) {
      d_proxyProtocolPayloadHasTLV = dq.proxyProtocolValues && !dq.proxyProtocolValues->empty();
    }

    proxyProtocolPayload = getProxyProtocolPayload(dq);
  }

  if (dq.proxyProtocolValues) {
    downstreamConnection->setProxyProtocolValuesSent(std::move(dq.proxyProtocolValues));
  }

  TCPQuery tcpquery(std::move(query), std::move(ids));
  tcpquery.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

  vinfolog("Got query for %s|%s from %s (%s, %d bytes), relayed to %s", tcpquery.d_idstate.qname.toLogString(), QType(tcpquery.d_idstate.qtype).toString(), d_proxiedRemote.toStringWithPort(), getProtocol().toString(), tcpquery.d_buffer.size(), ds->getNameWithAddr());
  std::shared_ptr<TCPQuerySender> incoming = state;
  downstreamConnection->queueQuery(incoming, std::move(tcpquery));
  return QueryProcessingResult::Forwarded;
}

void IncomingTCPConnectionState::handleIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);
  if (fd != conn->d_handler.getDescriptor()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->d_handler.getDescriptor()));
  }

  conn->handleIO();
}

void IncomingTCPConnectionState::handleHandshakeDone(const struct timeval& now)
{
  if (d_handler.isTLS()) {
    if (!d_handler.hasTLSSessionBeenResumed()) {
      ++d_ci.cs->tlsNewSessions;
    }
    else {
      ++d_ci.cs->tlsResumptions;
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
    auto iostate = d_handler.tryRead(d_buffer, d_currentPos, d_proxyProtocolNeed);
    if (iostate == IOState::Done) {
      d_buffer.resize(d_currentPos);
      ssize_t remaining = isProxyHeaderComplete(d_buffer);
      if (remaining == 0) {
        vinfolog("Unable to consume proxy protocol header in packet from TCP client %s", d_ci.remote.toStringWithPort());
        ++dnsdist::metrics::g_stats.proxyProtocolInvalid;
        return ProxyProtocolResult::Error;
      }
      else if (remaining < 0) {
        d_proxyProtocolNeed += -remaining;
        d_buffer.resize(d_currentPos + d_proxyProtocolNeed);
        /* we need to keep reading, since we might have buffered data */
      }
      else {
        /* proxy header received */
        std::vector<ProxyProtocolValue> proxyProtocolValues;
        if (!handleProxyProtocol(d_ci.remote, true, *d_threadData.holders.acl, d_buffer, d_proxiedRemote, d_proxiedDestination, proxyProtocolValues)) {
          vinfolog("Error handling the Proxy Protocol received from TCP client %s", d_ci.remote.toStringWithPort());
          return ProxyProtocolResult::Error;
        }

        if (!proxyProtocolValues.empty()) {
          d_proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
        }

        return ProxyProtocolResult::Done;
      }
    }
    else {
      d_lastIOBlocked = true;
    }
  }
  while (active() && !d_lastIOBlocked);

  return ProxyProtocolResult::Reading;
}

void IncomingTCPConnectionState::handleIO()
{
  // why do we loop? Because the TLS layer does buffering, and thus can have data ready to read
  // even though the underlying socket is not ready, so we need to actually ask for the data first
  IOState iostate = IOState::Done;
  struct timeval now;
  gettimeofday(&now, nullptr);

  do {
    iostate = IOState::Done;
    IOStateGuard ioGuard(d_ioState);

    if (maxConnectionDurationReached(g_maxTCPConnectionDuration, now)) {
      vinfolog("Terminating TCP connection from %s because it reached the maximum TCP connection duration", d_ci.remote.toStringWithPort());
      // will be handled by the ioGuard
      //handleNewIOState(state, IOState::Done, fd, handleIOCallback);
      return;
    }

    d_lastIOBlocked = false;

    try {
      if (d_state == IncomingTCPConnectionState::State::doingHandshake) {
        DEBUGLOG("doing handshake");
        iostate = d_handler.tryHandshake();
        if (iostate == IOState::Done) {
          DEBUGLOG("handshake done");
          handleHandshakeDone(now);

          if (expectProxyProtocolFrom(d_ci.remote)) {
            d_state = IncomingTCPConnectionState::State::readingProxyProtocolHeader;
            d_buffer.resize(s_proxyProtocolMinimumHeaderSize);
            d_proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
          }
          else {
            d_state = IncomingTCPConnectionState::State::readingQuerySize;
          }
        }
        else {
          d_lastIOBlocked = true;
        }
      }

      if (!d_lastIOBlocked && d_state == IncomingTCPConnectionState::State::readingProxyProtocolHeader) {
        auto status = handleProxyProtocolPayload();
        if (status == ProxyProtocolResult::Done) {
          d_state = IncomingTCPConnectionState::State::readingQuerySize;
          d_buffer.resize(sizeof(uint16_t));
          d_currentPos = 0;
          d_proxyProtocolNeed = 0;
        }
        else if (status == ProxyProtocolResult::Error) {
          iostate = IOState::Done;
        }
        else {
          iostate = IOState::NeedRead;
        }
      }

      if (!d_lastIOBlocked && (d_state == IncomingTCPConnectionState::State::waitingForQuery ||
                                      d_state == IncomingTCPConnectionState::State::readingQuerySize)) {
        DEBUGLOG("reading query size");
        d_buffer.resize(sizeof(uint16_t));
        iostate = d_handler.tryRead(d_buffer, d_currentPos, sizeof(uint16_t));
        if (d_currentPos > 0) {
          /* if we got at least one byte, we can't go around sending responses */
          d_state = IncomingTCPConnectionState::State::readingQuerySize;
        }

        if (iostate == IOState::Done) {
          DEBUGLOG("query size received");
          d_state = IncomingTCPConnectionState::State::readingQuery;
          d_querySizeReadTime = now;
          if (d_queriesCount == 0) {
            d_firstQuerySizeReadTime = now;
          }
          d_querySize = d_buffer.at(0) * 256 + d_buffer.at(1);
          if (d_querySize < sizeof(dnsheader)) {
            /* go away */
            terminateClientConnection();
            return;
          }

          /* allocate a bit more memory to be able to spoof the content, get an answer from the cache
             or to add ECS without allocating a new buffer */
          d_buffer.resize(std::max(d_querySize + static_cast<size_t>(512), s_maxPacketCacheEntrySize));
          d_currentPos = 0;
        }
        else {
          d_lastIOBlocked = true;
        }
      }

      if (!d_lastIOBlocked && d_state == IncomingTCPConnectionState::State::readingQuery) {
        DEBUGLOG("reading query");
        iostate = d_handler.tryRead(d_buffer, d_currentPos, d_querySize);
        if (iostate == IOState::Done) {
          DEBUGLOG("query received");
          d_buffer.resize(d_querySize);

          d_state = IncomingTCPConnectionState::State::idle;
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
            break;
          default:
            break;
          }

          /* the state might have been updated in the meantime, we don't want to override it
             in that case */
          if (active() && d_state != IncomingTCPConnectionState::State::idle) {
            if (d_ioState->isWaitingForRead()) {
              iostate = IOState::NeedRead;
            }
            else if (d_ioState->isWaitingForWrite()) {
              iostate = IOState::NeedWrite;
            }
            else {
              iostate = IOState::Done;
            }
          }
        }
        else {
          d_lastIOBlocked = true;
        }
      }

      if (!d_lastIOBlocked && d_state == IncomingTCPConnectionState::State::sendingResponse) {
        DEBUGLOG("sending response");
        iostate = d_handler.tryWrite(d_currentResponse.d_buffer, d_currentPos, d_currentResponse.d_buffer.size());
        if (iostate == IOState::Done) {
          DEBUGLOG("response sent from "<<__PRETTY_FUNCTION__);
          handleResponseSent(d_currentResponse);
          d_state = IncomingTCPConnectionState::State::idle;
        }
        else {
          d_lastIOBlocked = true;
        }
      }

      if (active() &&
          !d_lastIOBlocked &&
          iostate == IOState::Done &&
          (d_state == IncomingTCPConnectionState::State::idle ||
           d_state == IncomingTCPConnectionState::State::waitingForQuery))
      {
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
            d_state = IncomingTCPConnectionState::State::idle;
            iostate = IOState::Done;
          }
        }
      }

      if (d_state != IncomingTCPConnectionState::State::idle &&
          d_state != IncomingTCPConnectionState::State::doingHandshake &&
          d_state != IncomingTCPConnectionState::State::readingProxyProtocolHeader &&
          d_state != IncomingTCPConnectionState::State::waitingForQuery &&
          d_state != IncomingTCPConnectionState::State::readingQuerySize &&
          d_state != IncomingTCPConnectionState::State::readingQuery &&
          d_state != IncomingTCPConnectionState::State::sendingResponse) {
        vinfolog("Unexpected state %d in handleIOCallback", static_cast<int>(d_state));
      }
    }
    catch (const std::exception& e) {
      /* most likely an EOF because the other end closed the connection,
         but it might also be a real IO error or something else.
         Let's just drop the connection
      */
      if (d_state == IncomingTCPConnectionState::State::idle ||
          d_state == IncomingTCPConnectionState::State::waitingForQuery) {
        /* no need to increase any counters in that case, the client is simply done with us */
      }
      else if (d_state == IncomingTCPConnectionState::State::doingHandshake ||
               d_state != IncomingTCPConnectionState::State::readingProxyProtocolHeader ||
               d_state == IncomingTCPConnectionState::State::waitingForQuery ||
               d_state == IncomingTCPConnectionState::State::readingQuerySize ||
               d_state == IncomingTCPConnectionState::State::readingQuery) {
        ++d_ci.cs->tcpDiedReadingQuery;
      }
      else if (d_state == IncomingTCPConnectionState::State::sendingResponse) {
        /* unlikely to happen here, the exception should be handled in sendResponse() */
        ++d_ci.cs->tcpDiedSendingResponse;
      }

      if (d_ioState->isWaitingForWrite() || d_queriesCount == 0) {
        DEBUGLOG("Got an exception while handling TCP query: "<<e.what());
        vinfolog("Got an exception while handling (%s) TCP query from %s: %s", (d_ioState->isWaitingForRead() ? "reading" : "writing"), d_ci.remote.toStringWithPort(), e.what());
      }
      else {
        vinfolog("Closing TCP client connection with %s: %s", d_ci.remote.toStringWithPort(), e.what());
        DEBUGLOG("Closing TCP client connection: "<<e.what());
      }
      /* remove this FD from the IO multiplexer */
      terminateClientConnection();
    }

    if (!active()) {
      DEBUGLOG("state is no longer active");
      return;
    }

    auto state = shared_from_this();
    if (iostate == IOState::Done) {
      d_ioState->update(iostate, handleIOCallback, state);
    }
    else {
      updateIO(state, iostate, now);
    }
    ioGuard.release();
  }
  while ((iostate == IOState::NeedRead || iostate == IOState::NeedWrite) && !d_lastIOBlocked);
}

void IncomingTCPConnectionState::notifyIOError(const struct timeval& now, TCPResponse&& response)
{
  if (std::this_thread::get_id() != d_creatorThreadID) {
    /* empty buffer will signal an IO error */
    response.d_buffer.clear();
    handleCrossProtocolResponse(now, std::move(response));
    return;
  }

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
	updateIO(state, iostate, now);
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
  if (std::this_thread::get_id() != d_creatorThreadID) {
    handleCrossProtocolResponse(now, std::move(response));
    return;
  }

  std::shared_ptr<IncomingTCPConnectionState> state = shared_from_this();
  queueResponse(state, now, std::move(response));
}

void IncomingTCPConnectionState::handleTimeout(std::shared_ptr<IncomingTCPConnectionState>& state, bool write)
{
  vinfolog("Timeout while %s TCP client %s", (write ? "writing to" : "reading from"), state->d_ci.remote.toStringWithPort());
  DEBUGLOG("client timeout");
  DEBUGLOG("Processed "<<state->d_queriesCount<<" queries, current count is "<<state->d_currentQueriesCount<<", "<<state->d_ownedConnectionsToBackend.size()<<" owned connections, "<<state->d_queuedResponses.size()<<" response queued");

  if (write || state->d_currentQueriesCount == 0) {
    ++state->d_ci.cs->tcpClientTimeouts;
    state->d_ioState.reset();
  }
  else {
    DEBUGLOG("Going idle");
    /* we still have some queries in flight, let's just stop reading for now */
    state->d_state = IncomingTCPConnectionState::State::idle;
    state->d_ioState->update(IOState::Done, handleIOCallback, state);
  }
}

static void handleIncomingTCPQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  auto threadData = boost::any_cast<TCPClientThreadData*>(param);

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

  struct timeval now;
  gettimeofday(&now, nullptr);

  if (citmp->cs->dohFrontend) {
#ifdef HAVE_NGHTTP2
    auto state = std::make_shared<IncomingHTTP2Connection>(std::move(*citmp), *threadData, now);
    state->handleIO();
#endif /* HAVE_NGHTTP2 */
  }
  else {
    auto state = std::make_shared<IncomingTCPConnectionState>(std::move(*citmp), *threadData, now);
    state->handleIO();
  }
}

static void handleCrossProtocolQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  auto threadData = boost::any_cast<TCPClientThreadData*>(param);

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

  struct timeval now;
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
  auto threadData = boost::any_cast<TCPClientThreadData*>(param);

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

  auto response = std::move(*cpr);

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
  ClientState& cs;
  ComboAddress local;
  LocalStateHolder<NetmaskGroup>& acl;
  int socket{-1};
};

static void acceptNewConnection(const TCPAcceptorParam& param, TCPClientThreadData* threadData);

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
    auto acl = g_ACL.getLocal();
    std::vector<TCPAcceptorParam> acceptParams;
    acceptParams.reserve(tcpAcceptStates.size());

    for (auto& state : tcpAcceptStates) {
      acceptParams.emplace_back(TCPAcceptorParam{*state, state->local, acl, state->tcpFD});
      for (const auto& [addr, socket] : state->d_additionalAddresses) {
        acceptParams.emplace_back(TCPAcceptorParam{*state, addr, acl, socket});
      }
    }

    auto acceptCallback = [&data](int socket, FDMultiplexer::funcparam_t& funcparam) {
      auto acceptorParam = boost::any_cast<const TCPAcceptorParam*>(funcparam);
      acceptNewConnection(*acceptorParam, &data);
    };

    for (size_t idx = 0; idx < acceptParams.size(); idx++) {
      const auto& param = acceptParams.at(idx);
      setNonBlocking(param.socket);
      data.mplexer->addReadFD(param.socket, acceptCallback, &param);
    }

    struct timeval now;
    gettimeofday(&now, nullptr);
    time_t lastTimeoutScan = now.tv_sec;

    for (;;) {
      data.mplexer->run(&now);

      try {
        t_downstreamTCPConnectionsManager.cleanupClosedConnections(now);

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
              errlog("The TCP/DoT client cache has %d active and %d idle outgoing connections cached", t_downstreamTCPConnectionsManager.getActiveCount(), t_downstreamTCPConnectionsManager.getIdleCount());
            }
          }
        }
      }
      catch (const std::exception& e) {
        errlog("Error in TCP worker thread: %s", e.what());
      }
    }
  }
  catch (const std::exception& e) {
    errlog("Fatal error in TCP worker thread: %s", e.what());
  }
}

static void acceptNewConnection(const TCPAcceptorParam& param, TCPClientThreadData* threadData)
{
  auto& cs = param.cs;
  auto& acl = param.acl;
  const bool checkACL = !cs.dohFrontend || (!cs.dohFrontend->d_trustForwardedForHeader && cs.dohFrontend->d_earlyACLDrop);
  const int socket = param.socket;
  bool tcpClientCountIncremented = false;
  ComboAddress remote;
  remote.sin4.sin_family = param.local.sin4.sin_family;

  tcpClientCountIncremented = false;
  try {
    socklen_t remlen = remote.getSocklen();
    ConnectionInfo ci(&cs);
#ifdef HAVE_ACCEPT4
    ci.fd = accept4(socket, reinterpret_cast<struct sockaddr*>(&remote), &remlen, SOCK_NONBLOCK);
#else
    ci.fd = accept(socket, reinterpret_cast<struct sockaddr*>(&remote), &remlen);
#endif
    // will be decremented when the ConnectionInfo object is destroyed, no matter the reason
    auto concurrentConnections = ++cs.tcpCurrentConnections;

    if (ci.fd < 0) {
      throw std::runtime_error((boost::format("accepting new connection on socket: %s") % stringerror()).str());
    }

    if (checkACL && !acl->match(remote)) {
      ++dnsdist::metrics::g_stats.aclDrops;
      vinfolog("Dropped TCP connection from %s because of ACL", remote.toStringWithPort());
      return;
    }

    if (cs.d_tcpConcurrentConnectionsLimit > 0 && concurrentConnections > cs.d_tcpConcurrentConnectionsLimit) {
      vinfolog("Dropped TCP connection from %s because of concurrent connections limit", remote.toStringWithPort());
      return;
    }

    if (concurrentConnections > cs.tcpMaxConcurrentConnections.load()) {
      cs.tcpMaxConcurrentConnections.store(concurrentConnections);
    }

#ifndef HAVE_ACCEPT4
    if (!setNonBlocking(ci.fd)) {
      return;
    }
#endif

    setTCPNoDelay(ci.fd);  // disable NAGLE

    if (g_maxTCPQueuedConnections > 0 && g_tcpclientthreads->getQueuedCount() >= g_maxTCPQueuedConnections) {
      vinfolog("Dropping TCP connection from %s because we have too many queued already", remote.toStringWithPort());
      return;
    }

    if (!dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(remote)) {
      vinfolog("Dropping TCP connection from %s because we have too many from this client already", remote.toStringWithPort());
      return;
    }
    tcpClientCountIncremented = true;

    vinfolog("Got TCP connection from %s", remote.toStringWithPort());

    ci.remote = remote;

    if (threadData == nullptr) {
      if (!g_tcpclientthreads->passConnectionToThread(std::make_unique<ConnectionInfo>(std::move(ci)))) {
        if (tcpClientCountIncremented) {
          dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(remote);
        }
      }
    }
    else {
      struct timeval now;
      gettimeofday(&now, nullptr);

      if (ci.cs->dohFrontend) {
#ifdef HAVE_NGHTTP2        
        auto state = std::make_shared<IncomingHTTP2Connection>(std::move(ci), *threadData, now);
        state->handleIO();
#endif /* HAVE_NGHTTP2 */
      }
      else {
        auto state = std::make_shared<IncomingTCPConnectionState>(std::move(ci), *threadData, now);
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
  catch (...){}
}

/* spawn as many of these as required, they call Accept on a socket on which they will accept queries, and
   they will hand off to worker threads & spawn more of them if required
*/
#ifndef USE_SINGLE_ACCEPTOR_THREAD
void tcpAcceptorThread(std::vector<ClientState*> states)
{
  setThreadName("dnsdist/tcpAcce");

  auto acl = g_ACL.getLocal();
  std::vector<TCPAcceptorParam> params;
  params.reserve(states.size());

  for (auto& state : states) {
    params.emplace_back(TCPAcceptorParam{*state, state->local, acl, state->tcpFD});
    for (const auto& [addr, socket] : state->d_additionalAddresses) {
      params.emplace_back(TCPAcceptorParam{*state, addr, acl, socket});
    }
  }

  if (params.size() == 1) {
    while (true) {
      acceptNewConnection(params.at(0), nullptr);
    }
  }
  else {
    auto acceptCallback = [](int socket, FDMultiplexer::funcparam_t& funcparam) {
      auto acceptorParam = boost::any_cast<const TCPAcceptorParam*>(funcparam);
      acceptNewConnection(*acceptorParam, nullptr);
    };

    auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(params.size()));
    for (size_t idx = 0; idx < params.size(); idx++) {
      const auto& param = params.at(idx);
      mplexer->addReadFD(param.socket, acceptCallback, &param);
    }

    struct timeval tv;
    while (true) {
      mplexer->run(&tv, -1);
    }
  }
}
#endif
