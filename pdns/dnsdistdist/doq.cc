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

#include "doq.hh"

#ifdef HAVE_DNS_OVER_QUIC
#include <quiche.h>

#include "dolog.hh"
#include "iputils.hh"
#include "misc.hh"
#include "sodcrypto.hh"
#include "sstuff.hh"
#include "threadname.hh"

#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-random.hh"

#include "doq-common.hh"

using namespace dnsdist::doq;

#if 0
#define DEBUGLOG_ENABLED
#define DEBUGLOG(x) std::cerr << x << std::endl;
#else
#define DEBUGLOG(x)
#endif

class Connection
{
public:
  Connection(const ComboAddress& peer, QuicheConnection&& conn) :
    d_peer(peer), d_conn(std::move(conn))
  {
  }
  Connection(const Connection&) = delete;
  Connection(Connection&&) = default;
  Connection& operator=(const Connection&) = delete;
  Connection& operator=(Connection&&) = default;
  ~Connection() = default;

  ComboAddress d_peer;
  QuicheConnection d_conn;
  std::unordered_map<uint64_t, PacketBuffer> d_streamBuffers;
  std::unordered_map<uint64_t, PacketBuffer> d_streamOutBuffers;
};

static void sendBackDOQUnit(DOQUnitUniquePtr&& unit, const char* description);

struct DOQServerConfig
{
  DOQServerConfig(QuicheConfig&& config_, uint32_t internalPipeBufferSize) :
    config(std::move(config_))
  {
    {
      auto [sender, receiver] = pdns::channel::createObjectQueue<DOQUnit>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, internalPipeBufferSize);
      d_responseSender = std::move(sender);
      d_responseReceiver = std::move(receiver);
    }
  }
  DOQServerConfig(const DOQServerConfig&) = delete;
  DOQServerConfig(DOQServerConfig&&) = default;
  DOQServerConfig& operator=(const DOQServerConfig&) = delete;
  DOQServerConfig& operator=(DOQServerConfig&&) = default;
  ~DOQServerConfig() = default;

  using ConnectionsMap = std::map<PacketBuffer, Connection>;

  LocalHolders holders;
  ConnectionsMap d_connections;
  QuicheConfig config;
  ClientState* clientState{nullptr};
  std::shared_ptr<DOQFrontend> df{nullptr};
  pdns::channel::Sender<DOQUnit> d_responseSender;
  pdns::channel::Receiver<DOQUnit> d_responseReceiver;
};

/* these might seem useless, but they are needed because
   they need to be declared _after_ the definition of DOQServerConfig
   so that we can use a unique_ptr in DOQFrontend */
DOQFrontend::DOQFrontend() = default;
DOQFrontend::~DOQFrontend() = default;

class DOQTCPCrossQuerySender final : public TCPQuerySender
{
public:
  DOQTCPCrossQuerySender() = default;

  [[nodiscard]] bool active() const override
  {
    return true;
  }

  void handleResponse([[maybe_unused]] const struct timeval& now, TCPResponse&& response) override
  {
    if (!response.d_idstate.doqu) {
      return;
    }

    auto unit = std::move(response.d_idstate.doqu);
    if (unit->dsc == nullptr) {
      return;
    }

    unit->response = std::move(response.d_buffer);
    unit->ids = std::move(response.d_idstate);
    DNSResponse dnsResponse(unit->ids, unit->response, unit->downstream);

    dnsheader cleartextDH{};
    memcpy(&cleartextDH, dnsResponse.getHeader().get(), sizeof(cleartextDH));

    if (!response.isAsync()) {

      static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localRespRuleActions = g_respruleactions.getLocal();
      static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localCacheInsertedRespRuleActions = g_cacheInsertedRespRuleActions.getLocal();

      dnsResponse.ids.doqu = std::move(unit);

      if (!processResponse(dnsResponse.ids.doqu->response, *localRespRuleActions, *localCacheInsertedRespRuleActions, dnsResponse, false)) {
        if (dnsResponse.ids.doqu) {

          sendBackDOQUnit(std::move(dnsResponse.ids.doqu), "Response dropped by rules");
        }
        return;
      }

      if (dnsResponse.isAsynchronous()) {
        return;
      }

      unit = std::move(dnsResponse.ids.doqu);
    }

    if (!unit->ids.selfGenerated) {
      double udiff = unit->ids.queryRealTime.udiff();
      vinfolog("Got answer from %s, relayed to %s (quic, %d bytes), took %f us", unit->downstream->d_config.remote.toStringWithPort(), unit->ids.origRemote.toStringWithPort(), unit->response.size(), udiff);

      auto backendProtocol = unit->downstream->getProtocol();
      if (backendProtocol == dnsdist::Protocol::DoUDP && unit->tcp) {
        backendProtocol = dnsdist::Protocol::DoTCP;
      }
      handleResponseSent(unit->ids, udiff, unit->ids.origRemote, unit->downstream->d_config.remote, unit->response.size(), cleartextDH, backendProtocol, true);
    }

    ++dnsdist::metrics::g_stats.responses;
    if (unit->ids.cs != nullptr) {
      ++unit->ids.cs->responses;
    }

    sendBackDOQUnit(std::move(unit), "Cross-protocol response");
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    return handleResponse(now, std::move(response));
  }

  void notifyIOError([[maybe_unused]] const struct timeval& now, TCPResponse&& response) override
  {
    if (!response.d_idstate.doqu) {
      return;
    }

    auto unit = std::move(response.d_idstate.doqu);
    if (unit->dsc == nullptr) {
      return;
    }

    /* this will signal an error */
    unit->response.clear();
    unit->ids = std::move(response.d_idstate);
    sendBackDOQUnit(std::move(unit), "Cross-protocol error");
  }
};

class DOQCrossProtocolQuery : public CrossProtocolQuery
{
public:
  DOQCrossProtocolQuery(DOQUnitUniquePtr&& unit, bool isResponse)
  {
    if (isResponse) {
      /* happens when a response becomes async */
      query = InternalQuery(std::move(unit->response), std::move(unit->ids));
    }
    else {
      /* we need to duplicate the query here because we might need
         the existing query later if we get a truncated answer */
      query = InternalQuery(PacketBuffer(unit->query), std::move(unit->ids));
    }

    /* it might have been moved when we moved unit->ids */
    if (unit) {
      query.d_idstate.doqu = std::move(unit);
    }

    /* we _could_ remove it from the query buffer and put in query's d_proxyProtocolPayload,
       clearing query.d_proxyProtocolPayloadAdded and unit->proxyProtocolPayloadSize.
       Leave it for now because we know that the onky case where the payload has been
       added is when we tried over UDP, got a TC=1 answer and retried over TCP/DoT,
       and we know the TCP/DoT code can handle it. */
    query.d_proxyProtocolPayloadAdded = query.d_idstate.doqu->proxyProtocolPayloadSize > 0;
    downstream = query.d_idstate.doqu->downstream;
  }

  void handleInternalError()
  {
    sendBackDOQUnit(std::move(query.d_idstate.doqu), "DOQ internal error");
  }

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    query.d_idstate.doqu->downstream = downstream;
    return s_sender;
  }

  DNSQuestion getDQ() override
  {
    auto& ids = query.d_idstate;
    DNSQuestion dnsQuestion(ids, query.d_buffer);
    return dnsQuestion;
  }

  DNSResponse getDR() override
  {
    auto& ids = query.d_idstate;
    DNSResponse dnsResponse(ids, query.d_buffer, downstream);
    return dnsResponse;
  }

  DOQUnitUniquePtr&& releaseDU()
  {
    return std::move(query.d_idstate.doqu);
  }

private:
  static std::shared_ptr<DOQTCPCrossQuerySender> s_sender;
};

std::shared_ptr<DOQTCPCrossQuerySender> DOQCrossProtocolQuery::s_sender = std::make_shared<DOQTCPCrossQuerySender>();

static bool tryWriteResponse(Connection& conn, const uint64_t streamID, PacketBuffer& response)
{
  size_t pos = 0;
  while (pos < response.size()) {
    auto res = quiche_conn_stream_send(conn.d_conn.get(), streamID, &response.at(pos), response.size() - pos, true);
    if (res == QUICHE_ERR_DONE) {
      response.erase(response.begin(), response.begin() + static_cast<ssize_t>(pos));
      return false;
    }
    if (res < 0) {
      quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(DOQ_Error_Codes::DOQ_INTERNAL_ERROR));
      return true;
    }
    pos += res;
  }

  return true;
}

static void handleResponse(DOQFrontend& frontend, Connection& conn, const uint64_t streamID, PacketBuffer& response)
{
  if (response.empty()) {
    ++frontend.d_errorResponses;
    quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(DOQ_Error_Codes::DOQ_UNSPECIFIED_ERROR));
    return;
  }
  ++frontend.d_validResponses;
  auto responseSize = static_cast<uint16_t>(response.size());
  const std::array<uint8_t, 2> sizeBytes = {static_cast<uint8_t>(responseSize / 256), static_cast<uint8_t>(responseSize % 256)};
  response.insert(response.begin(), sizeBytes.begin(), sizeBytes.end());
  if (!tryWriteResponse(conn, streamID, response)) {
    conn.d_streamOutBuffers[streamID] = std::move(response);
  }
}

void DOQFrontend::setup()
{
  auto config = QuicheConfig(quiche_config_new(QUICHE_PROTOCOL_VERSION), quiche_config_free);
  d_quicheParams.d_alpn = std::string(DOQ_ALPN.begin(), DOQ_ALPN.end());
  configureQuiche(config, d_quicheParams, false);
  d_server_config = std::make_unique<DOQServerConfig>(std::move(config), d_internalPipeBufferSize);
}

static std::optional<std::reference_wrapper<Connection>> getConnection(DOQServerConfig::ConnectionsMap& connMap, const PacketBuffer& connID)
{
  auto iter = connMap.find(connID);
  if (iter == connMap.end()) {
    return std::nullopt;
  }
  return iter->second;
}

static void sendBackDOQUnit(DOQUnitUniquePtr&& unit, const char* description)
{
  if (unit->dsc == nullptr) {
    return;
  }
  try {
    if (!unit->dsc->d_responseSender.send(std::move(unit))) {
      ++dnsdist::metrics::g_stats.doqResponsePipeFull;
      vinfolog("Unable to pass a %s to the DoQ worker thread because the pipe is full", description);
    }
  }
  catch (const std::exception& e) {
    vinfolog("Unable to pass a %s to the DoQ worker thread because we couldn't write to the pipe: %s", description, e.what());
  }
}

static std::optional<std::reference_wrapper<Connection>> createConnection(DOQServerConfig& config, const PacketBuffer& serverSideID, const PacketBuffer& originalDestinationID, const ComboAddress& local, const ComboAddress& peer)
{
  auto quicheConn = QuicheConnection(quiche_accept(serverSideID.data(), serverSideID.size(),
                                                   originalDestinationID.data(), originalDestinationID.size(),
                                                   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                                   reinterpret_cast<const struct sockaddr*>(&local),
                                                   local.getSocklen(),
                                                   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                                   reinterpret_cast<const struct sockaddr*>(&peer),
                                                   peer.getSocklen(),
                                                   config.config.get()),
                                     quiche_conn_free);

  if (config.df && !config.df->d_quicheParams.d_keyLogFile.empty()) {
    quiche_conn_set_keylog_path(quicheConn.get(), config.df->d_quicheParams.d_keyLogFile.c_str());
  }

  auto conn = Connection(peer, std::move(quicheConn));
  auto pair = config.d_connections.emplace(serverSideID, std::move(conn));
  return pair.first->second;
}

std::unique_ptr<CrossProtocolQuery> getDOQCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion, bool isResponse)
{
  if (!dnsQuestion.ids.doqu) {
    throw std::runtime_error("Trying to create a DoQ cross protocol query without a valid DoQ unit");
  }

  auto unit = std::move(dnsQuestion.ids.doqu);
  if (&dnsQuestion.ids != &unit->ids) {
    unit->ids = std::move(dnsQuestion.ids);
  }

  unit->ids.origID = dnsQuestion.getHeader()->id;

  if (!isResponse) {
    if (unit->query.data() != dnsQuestion.getMutableData().data()) {
      unit->query = std::move(dnsQuestion.getMutableData());
    }
  }
  else {
    if (unit->response.data() != dnsQuestion.getMutableData().data()) {
      unit->response = std::move(dnsQuestion.getMutableData());
    }
  }

  return std::make_unique<DOQCrossProtocolQuery>(std::move(unit), isResponse);
}

static void processDOQQuery(DOQUnitUniquePtr&& doqUnit)
{
  const auto handleImmediateResponse = [](DOQUnitUniquePtr&& unit, [[maybe_unused]] const char* reason) {
    DEBUGLOG("handleImmediateResponse() reason=" << reason);
    auto conn = getConnection(unit->dsc->df->d_server_config->d_connections, unit->serverConnID);
    handleResponse(*unit->dsc->df, *conn, unit->streamID, unit->response);
    unit->ids.doqu.reset();
  };

  auto& ids = doqUnit->ids;
  ids.doqu = std::move(doqUnit);
  auto& unit = ids.doqu;
  uint16_t queryId = 0;
  ComboAddress remote;

  try {

    remote = unit->ids.origRemote;
    DOQServerConfig* dsc = unit->dsc;
    auto& holders = dsc->holders;
    ClientState& clientState = *dsc->clientState;

    if (!holders.acl->match(remote)) {
      vinfolog("Query from %s (DoQ) dropped because of ACL", remote.toStringWithPort());
      ++dnsdist::metrics::g_stats.aclDrops;
      unit->response.clear();

      handleImmediateResponse(std::move(unit), "DoQ query dropped because of ACL");
      return;
    }

    if (unit->query.size() < sizeof(dnsheader)) {
      ++dnsdist::metrics::g_stats.nonCompliantQueries;
      ++clientState.nonCompliantQueries;
      unit->response.clear();

      handleImmediateResponse(std::move(unit), "DoQ non-compliant query");
      return;
    }

    ++clientState.queries;
    ++dnsdist::metrics::g_stats.queries;
    unit->ids.queryRealTime.start();

    {
      /* don't keep that pointer around, it will be invalidated if the buffer is ever resized */
      dnsheader_aligned dnsHeader(unit->query.data());

      if (!checkQueryHeaders(dnsHeader.get(), clientState)) {
        dnsdist::PacketMangling::editDNSHeaderFromPacket(unit->query, [](dnsheader& header) {
          header.rcode = RCode::ServFail;
          header.qr = true;
          return true;
        });
        unit->response = std::move(unit->query);

        handleImmediateResponse(std::move(unit), "DoQ invalid headers");
        return;
      }

      if (dnsHeader->qdcount == 0) {
        dnsdist::PacketMangling::editDNSHeaderFromPacket(unit->query, [](dnsheader& header) {
          header.rcode = RCode::NotImp;
          header.qr = true;
          return true;
        });
        unit->response = std::move(unit->query);

        handleImmediateResponse(std::move(unit), "DoQ empty query");
        return;
      }

      queryId = ntohs(dnsHeader->id);
    }

    auto downstream = unit->downstream;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    unit->ids.qname = DNSName(reinterpret_cast<const char*>(unit->query.data()), static_cast<int>(unit->query.size()), sizeof(dnsheader), false, &unit->ids.qtype, &unit->ids.qclass);
    DNSQuestion dnsQuestion(unit->ids, unit->query);
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [&ids](dnsheader& header) {
      const uint16_t* flags = getFlagsFromDNSHeader(&header);
      ids.origFlags = *flags;
      return true;
    });
    unit->ids.cs = &clientState;

    auto result = processQuery(dnsQuestion, holders, downstream);
    if (result == ProcessQueryResult::Drop) {
      handleImmediateResponse(std::move(unit), "DoQ dropped query");
      return;
    }
    if (result == ProcessQueryResult::Asynchronous) {
      return;
    }
    if (result == ProcessQueryResult::SendAnswer) {
      if (unit->response.empty()) {
        unit->response = std::move(unit->query);
      }
      if (unit->response.size() >= sizeof(dnsheader)) {
        const dnsheader_aligned dnsHeader(unit->response.data());

        handleResponseSent(unit->ids.qname, QType(unit->ids.qtype), 0., unit->ids.origDest, ComboAddress(), unit->response.size(), *dnsHeader, dnsdist::Protocol::DoQ, dnsdist::Protocol::DoQ, false);
      }
      handleImmediateResponse(std::move(unit), "DoQ self-answered response");
      return;
    }

    ++dnsdist::metrics::g_stats.responses;
    if (unit->ids.cs != nullptr) {
      ++unit->ids.cs->responses;
    }

    if (result != ProcessQueryResult::PassToBackend) {
      handleImmediateResponse(std::move(unit), "DoQ no backend available");
      return;
    }

    if (downstream == nullptr) {
      handleImmediateResponse(std::move(unit), "DoQ no backend available");
      return;
    }

    unit->downstream = downstream;

    std::string proxyProtocolPayload;
    /* we need to do this _before_ creating the cross protocol query because
       after that the buffer will have been moved */
    if (downstream->d_config.useProxyProtocol) {
      proxyProtocolPayload = getProxyProtocolPayload(dnsQuestion);
    }

    unit->ids.origID = htons(queryId);
    unit->tcp = true;

    /* this moves unit->ids, careful! */
    auto cpq = std::make_unique<DOQCrossProtocolQuery>(std::move(unit), false);
    cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

    if (downstream->passCrossProtocolQuery(std::move(cpq))) {
      return;
    }
    // NOLINTNEXTLINE(bugprone-use-after-move): it was only moved if the call succeeded
    unit = cpq->releaseDU();
    handleImmediateResponse(std::move(unit), "DoQ internal error");
    return;
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in DOQ question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
    handleImmediateResponse(std::move(unit), "DoQ internal error");
    return;
  }
}

static void doq_dispatch_query(DOQServerConfig& dsc, PacketBuffer&& query, const ComboAddress& local, const ComboAddress& remote, const PacketBuffer& serverConnID, const uint64_t streamID)
{
  try {
    auto unit = std::make_unique<DOQUnit>(std::move(query));
    unit->dsc = &dsc;
    unit->ids.origDest = local;
    unit->ids.origRemote = remote;
    unit->ids.protocol = dnsdist::Protocol::DoQ;
    unit->serverConnID = serverConnID;
    unit->streamID = streamID;

    processDOQQuery(std::move(unit));
  }
  catch (const std::exception& exp) {
    vinfolog("Had error handling DoQ DNS packet from %s: %s", remote.toStringWithPort(), exp.what());
  }
}

static void flushResponses(pdns::channel::Receiver<DOQUnit>& receiver)
{
  for (;;) {
    try {
      auto tmp = receiver.receive();
      if (!tmp) {
        return;
      }

      auto unit = std::move(*tmp);
      auto conn = getConnection(unit->dsc->df->d_server_config->d_connections, unit->serverConnID);
      if (conn) {
        handleResponse(*unit->dsc->df, *conn, unit->streamID, unit->response);
      }
    }
    catch (const std::exception& e) {
      errlog("Error while processing response received over DoQ: %s", e.what());
    }
    catch (...) {
      errlog("Unspecified error while processing response received over DoQ");
    }
  }
}

static void flushStalledResponses(Connection& conn)
{
  for (auto streamIt = conn.d_streamOutBuffers.begin(); streamIt != conn.d_streamOutBuffers.end();) {
    const auto& streamID = streamIt->first;
    auto& response = streamIt->second;
    if (quiche_conn_stream_writable(conn.d_conn.get(), streamID, response.size()) == 1) {
      if (tryWriteResponse(conn, streamID, response)) {
        streamIt = conn.d_streamOutBuffers.erase(streamIt);
        continue;
      }
    }
    ++streamIt;
  }
}

static void handleReadableStream(DOQFrontend& frontend, ClientState& clientState, Connection& conn, uint64_t streamID, const ComboAddress& client, const PacketBuffer& serverConnID)
{
  auto& streamBuffer = conn.d_streamBuffers[streamID];
  while (true) {
    bool fin = false;
    auto existingLength = streamBuffer.size();
    streamBuffer.resize(existingLength + 512);
    auto received = quiche_conn_stream_recv(conn.d_conn.get(), streamID,
                                            &streamBuffer.at(existingLength), 512,
                                            &fin);
    if (received == 0 || received == QUICHE_ERR_DONE) {
      streamBuffer.resize(existingLength);
      return;
    }
    if (received < 0) {
      ++dnsdist::metrics::g_stats.nonCompliantQueries;
      ++clientState.nonCompliantQueries;
      quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(DOQ_Error_Codes::DOQ_PROTOCOL_ERROR));
      return;
    }

    streamBuffer.resize(existingLength + received);
    if (fin) {
      break;
    }
  }

  if (streamBuffer.size() < (sizeof(uint16_t) + sizeof(dnsheader))) {
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    ++clientState.nonCompliantQueries;
    quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(DOQ_Error_Codes::DOQ_PROTOCOL_ERROR));
    return;
  }

  uint16_t payloadLength = streamBuffer.at(0) * 256 + streamBuffer.at(1);
  streamBuffer.erase(streamBuffer.begin(), streamBuffer.begin() + 2);
  if (payloadLength != streamBuffer.size()) {
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    ++clientState.nonCompliantQueries;
    quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(DOQ_Error_Codes::DOQ_PROTOCOL_ERROR));
    return;
  }
  DEBUGLOG("Dispatching query");
  doq_dispatch_query(*(frontend.d_server_config), std::move(streamBuffer), clientState.local, client, serverConnID, streamID);
  conn.d_streamBuffers.erase(streamID);
}

static void handleSocketReadable(DOQFrontend& frontend, ClientState& clientState, Socket& sock, PacketBuffer& buffer)
{
  // destination connection ID, will have to be sent as original destination connection ID
  PacketBuffer serverConnID;
  // source connection ID, will have to be sent as destination connection ID
  PacketBuffer clientConnID;
  PacketBuffer tokenBuf;
  while (true) {
    ComboAddress client;
    buffer.resize(4096);
    if (!sock.recvFromAsync(buffer, client) || buffer.empty()) {
      return;
    }
    DEBUGLOG("Received DoQ datagram of size " << buffer.size() << " from " << client.toStringWithPort());

    uint32_t version{0};
    uint8_t type{0};
    std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> scid{};
    size_t scid_len = scid.size();
    std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> dcid{};
    size_t dcid_len = dcid.size();
    std::array<uint8_t, MAX_TOKEN_LEN> token{};
    size_t token_len = token.size();

    auto res = quiche_header_info(buffer.data(), buffer.size(), LOCAL_CONN_ID_LEN,
                                  &version, &type,
                                  scid.data(), &scid_len,
                                  dcid.data(), &dcid_len,
                                  token.data(), &token_len);
    if (res != 0) {
      DEBUGLOG("Error in quiche_header_info: " << res);
      continue;
    }

    serverConnID.assign(dcid.begin(), dcid.begin() + dcid_len);
    clientConnID.assign(scid.begin(), scid.begin() + scid_len);
    auto conn = getConnection(frontend.d_server_config->d_connections, serverConnID);

    if (!conn) {
      DEBUGLOG("Connection not found");
      if (!quiche_version_is_supported(version)) {
        DEBUGLOG("Unsupported version");
        ++frontend.d_doqUnsupportedVersionErrors;
        handleVersionNegociation(sock, clientConnID, serverConnID, client, buffer);
        continue;
      }

      if (token_len == 0) {
        /* stateless retry */
        DEBUGLOG("No token received");
        handleStatelessRetry(sock, clientConnID, serverConnID, client, version, buffer);
        continue;
      }

      tokenBuf.assign(token.begin(), token.begin() + token_len);
      auto originalDestinationID = validateToken(tokenBuf, client);
      if (!originalDestinationID) {
        ++frontend.d_doqInvalidTokensReceived;
        DEBUGLOG("Discarding invalid token");
        continue;
      }

      DEBUGLOG("Creating a new connection");
      conn = createConnection(*frontend.d_server_config, serverConnID, *originalDestinationID, clientState.local, client);
      if (!conn) {
        continue;
      }
    }
    DEBUGLOG("Connection found");
    quiche_recv_info recv_info = {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      reinterpret_cast<struct sockaddr*>(&client),
      client.getSocklen(),
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      reinterpret_cast<struct sockaddr*>(&clientState.local),
      clientState.local.getSocklen(),
    };

    auto done = quiche_conn_recv(conn->get().d_conn.get(), buffer.data(), buffer.size(), &recv_info);
    if (done < 0) {
      continue;
    }

    if (quiche_conn_is_established(conn->get().d_conn.get()) || quiche_conn_is_in_early_data(conn->get().d_conn.get())) {
      auto readable = std::unique_ptr<quiche_stream_iter, decltype(&quiche_stream_iter_free)>(quiche_conn_readable(conn->get().d_conn.get()), quiche_stream_iter_free);

      uint64_t streamID = 0;
      while (quiche_stream_iter_next(readable.get(), &streamID)) {
        handleReadableStream(frontend, clientState, *conn, streamID, client, serverConnID);
      }

      flushEgress(sock, conn->get().d_conn, client, buffer);
    }
    else {
      DEBUGLOG("Connection not established");
    }
  }
}

// this is the entrypoint from dnsdist.cc
void doqThread(ClientState* clientState)
{
  try {
    std::shared_ptr<DOQFrontend>& frontend = clientState->doqFrontend;

    frontend->d_server_config->clientState = clientState;
    frontend->d_server_config->df = clientState->doqFrontend;

    setThreadName("dnsdist/doq");

    Socket sock(clientState->udpFD);
    sock.setNonBlocking();

    auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());

    auto responseReceiverFD = frontend->d_server_config->d_responseReceiver.getDescriptor();
    mplexer->addReadFD(sock.getHandle(), [](int, FDMultiplexer::funcparam_t&) {});
    mplexer->addReadFD(responseReceiverFD, [](int, FDMultiplexer::funcparam_t&) {});
    std::vector<int> readyFDs;
    PacketBuffer buffer(4096);
    while (true) {
      readyFDs.clear();
      mplexer->getAvailableFDs(readyFDs, 500);

      try {
        if (std::find(readyFDs.begin(), readyFDs.end(), sock.getHandle()) != readyFDs.end()) {
          handleSocketReadable(*frontend, *clientState, sock, buffer);
        }

        if (std::find(readyFDs.begin(), readyFDs.end(), responseReceiverFD) != readyFDs.end()) {
          flushResponses(frontend->d_server_config->d_responseReceiver);
        }

        for (auto conn = frontend->d_server_config->d_connections.begin(); conn != frontend->d_server_config->d_connections.end();) {
          quiche_conn_on_timeout(conn->second.d_conn.get());

          flushEgress(sock, conn->second.d_conn, conn->second.d_peer, buffer);

          if (quiche_conn_is_closed(conn->second.d_conn.get())) {
#ifdef DEBUGLOG_ENABLED
            quiche_stats stats;
            quiche_path_stats path_stats;

            quiche_conn_stats(conn->second.d_conn.get(), &stats);
            quiche_conn_path_stats(conn->second.d_conn.get(), 0, &path_stats);

            DEBUGLOG("Connection (DoQ) closed, recv=" << stats.recv << " sent=" << stats.sent << " lost=" << stats.lost << " rtt=" << path_stats.rtt << "ns cwnd=" << path_stats.cwnd);
#endif
            conn = frontend->d_server_config->d_connections.erase(conn);
          }
          else {
            flushStalledResponses(conn->second);
            ++conn;
          }
        }
      }
      catch (const std::exception& exp) {
        vinfolog("Caught exception in the main DoQ thread: %s", exp.what());
      }
      catch (...) {
        vinfolog("Unknown exception in the main DoQ thread");
      }
    }
  }
  catch (const std::exception& e) {
    DEBUGLOG("Caught fatal error in the main DoQ thread: " << e.what());
  }
}

#endif /* HAVE_DNS_OVER_QUIC */
