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

#include "dnsdist-tcp.hh"
#include "dolog.hh"
#include "iputils.hh"
#include "misc.hh"
#include "sstuff.hh"
#include "dnsparser.hh"
#include "threadname.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-proxy-protocol.hh"

static void sendBackDOQUnit(DOQUnitUniquePtr&& du, const char* description);
class DOQServerConfig
{
public:
  DOQServerConfig(std::unique_ptr<quiche_config, decltype(&quiche_config_free)>&& config_) :
    config(std::move(config_))
  {
  }
  DOQServerConfig(const DOQServerConfig&) = delete;
  DOQServerConfig(DOQServerConfig&&) = default;
  DOQServerConfig& operator=(const DOQServerConfig&) = delete;
  DOQServerConfig& operator=(DOQServerConfig&&) = default;
  ~DOQServerConfig() = default;

  LocalHolders holders;
  QuicheConfig config;
  ClientState* cs{nullptr};
  std::shared_ptr<DOQFrontend> df{nullptr};
};

#if 0
#define DEBUGLOG_ENABLED
#define DEBUGLOG(x) std::cerr << x << std::endl;
#else
#define DEBUGLOG(x)
#endif

static constexpr size_t MAX_DATAGRAM_SIZE = 1350;
static constexpr size_t LOCAL_CONN_ID_LEN = 16;
static constexpr size_t TOKEN_LEN = 32; /* check if this needs to be authenticated, via HMAC-SHA256, for example, see rfc9000 section 8.1.1 */

static std::map<PacketBuffer, Connection> s_connections;

class DOQTCPCrossQuerySender final : public TCPQuerySender
{
public:
  DOQTCPCrossQuerySender()
  {
  }

  bool active() const override
  {
    return true;
  }

  void handleResponse(const struct timeval& now, TCPResponse&& response) override
  {
    if (!response.d_idstate.doqu) {
      return;
    }

    auto du = std::move(response.d_idstate.doqu);

    du->response = std::move(response.d_buffer);
    du->ids = std::move(response.d_idstate);
    DNSResponse dr(du->ids, du->response, du->downstream);

    dnsheader cleartextDH;
    memcpy(&cleartextDH, dr.getHeader(), sizeof(cleartextDH));

    if (!response.isAsync()) {

      static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localRespRuleActions = g_respruleactions.getLocal();
      static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localCacheInsertedRespRuleActions = g_cacheInsertedRespRuleActions.getLocal();

      dr.ids.doqu = std::move(du);

      if (!processResponse(dr.ids.doqu->response, *localRespRuleActions, *localCacheInsertedRespRuleActions, dr, false)) {
        if (dr.ids.doqu) {

          sendBackDOQUnit(std::move(dr.ids.doqu), "Response dropped by rules");
        }
        return;
      }

      if (dr.isAsynchronous()) {
        return;
      }

      du = std::move(dr.ids.doqu);
    }

    if (!du->ids.selfGenerated) {
      double udiff = du->ids.queryRealTime.udiff();
      vinfolog("Got answer from %s, relayed to %s (quic), took %f us", du->downstream->d_config.remote.toStringWithPort(), du->ids.origRemote.toStringWithPort(), udiff);

      auto backendProtocol = du->downstream->getProtocol();
      if (backendProtocol == dnsdist::Protocol::DoUDP && du->tcp) {
        backendProtocol = dnsdist::Protocol::DoTCP;
      }
      handleResponseSent(du->ids, udiff, du->ids.origRemote, du->downstream->d_config.remote, du->response.size(), cleartextDH, backendProtocol, true);
    }

    ++dnsdist::metrics::g_stats.responses;
    if (du->ids.cs) {
      ++du->ids.cs->responses;
    }

    sendBackDOQUnit(std::move(du), "Cross-protocol response");
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    return handleResponse(now, std::move(response));
  }

  void notifyIOError(const struct timeval& now, TCPResponse&& response) override
  {
  }
};

class DOQCrossProtocolQuery : public CrossProtocolQuery
{
public:
  DOQCrossProtocolQuery(DOQUnitUniquePtr&& du, bool isResponse)
  {
    if (isResponse) {
      /* happens when a response becomes async */
      query = InternalQuery(std::move(du->response), std::move(du->ids));
    }
    else {
      /* we need to duplicate the query here because we might need
         the existing query later if we get a truncated answer */
      query = InternalQuery(PacketBuffer(du->query), std::move(du->ids));
    }

    /* it might have been moved when we moved du->ids */
    if (du) {
      query.d_idstate.doqu = std::move(du);
    }

    /* we _could_ remove it from the query buffer and put in query's d_proxyProtocolPayload,
       clearing query.d_proxyProtocolPayloadAdded and du->proxyProtocolPayloadSize.
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
    DNSQuestion dq(ids, query.d_buffer);
    return dq;
  }

  DNSResponse getDR() override
  {
    auto& ids = query.d_idstate;
    DNSResponse dr(ids, query.d_buffer, downstream);
    return dr;
  }

  DOQUnitUniquePtr&& releaseDU()
  {
    return std::move(query.d_idstate.doqu);
  }

private:
  static std::shared_ptr<DOQTCPCrossQuerySender> s_sender;
};

std::shared_ptr<DOQTCPCrossQuerySender> DOQCrossProtocolQuery::s_sender = std::make_shared<DOQTCPCrossQuerySender>();

static void handleResponse(DOQFrontend& df, Connection& conn, const uint64_t streamID, const PacketBuffer& response)
{
  if (response.size() == 0) {
    quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, 0x5);
  }
  else {
    uint16_t responseSize = static_cast<uint16_t>(response.size());
    const uint8_t sizeBytes[] = {static_cast<uint8_t>(responseSize / 256), static_cast<uint8_t>(responseSize % 256)};
    auto res = quiche_conn_stream_send(conn.d_conn.get(), streamID, sizeBytes, sizeof(sizeBytes), false);
    if (res == sizeof(sizeBytes)) {
      res = quiche_conn_stream_send(conn.d_conn.get(), streamID, response.data(), response.size(), true);
    }
  }
}

void DOQFrontend::setup()
{
  auto config = QuicheConfig(quiche_config_new(QUICHE_PROTOCOL_VERSION), quiche_config_free);
  for (const auto& pair : d_tlsConfig.d_certKeyPairs) {
    auto res = quiche_config_load_cert_chain_from_pem_file(config.get(), pair.d_cert.c_str());
    if (res != 0) {
      throw std::runtime_error("Error loading the server certificate: " + std::to_string(res));
    }
    if (pair.d_key) {
      res = quiche_config_load_priv_key_from_pem_file(config.get(), pair.d_key->c_str());
      if (res != 0) {
        throw std::runtime_error("Error loading the server key: " + std::to_string(res));
      }
    }
  }

  {
    const std::array<uint8_t, 4> alpn{'\x03', 'd', 'o', 'q'};
    auto res = quiche_config_set_application_protos(config.get(),
                                                    alpn.data(),
                                                    alpn.size());
    if (res != 0) {
      throw std::runtime_error("Error setting ALPN: " + std::to_string(res));
    }
  }

  quiche_config_set_max_idle_timeout(config.get(), 5000);
  quiche_config_set_max_recv_udp_payload_size(config.get(), MAX_DATAGRAM_SIZE);
  quiche_config_set_max_send_udp_payload_size(config.get(), MAX_DATAGRAM_SIZE);
  quiche_config_set_initial_max_data(config.get(), 10000000);
  quiche_config_set_initial_max_stream_data_bidi_local(config.get(), 1000000);
  quiche_config_set_initial_max_stream_data_bidi_remote(config.get(), 1000000);
  quiche_config_set_initial_max_streams_bidi(config.get(), 100);
  quiche_config_set_cc_algorithm(config.get(), QUICHE_CC_RENO);
  // quiche_config_log_keys(config.get());

  d_server_config = std::make_shared<DOQServerConfig>(std::move(config));
}

static std::optional<PacketBuffer> getCID()
{
  // FIXME replace it
  int rng = open("/dev/urandom", O_RDONLY);
  if (rng < 0) {
    return std::nullopt;
  }
  PacketBuffer buffer;
  buffer.resize(LOCAL_CONN_ID_LEN);
  auto got = read(rng, buffer.data(), LOCAL_CONN_ID_LEN);
  if (got < 0) {
    return std::nullopt;
  }

  return buffer;
}

static PacketBuffer mintToken(const PacketBuffer& dcid, const ComboAddress& peer)
{
  // FIXME: really check whether this needs to be authenticated, via HMAC for example
  const std::array keyword = {'q', 'u', 'i', 'c', 'h', 'e'};
  auto addrBytes = peer.toByteString();
  PacketBuffer token;
  token.reserve(keyword.size() + addrBytes.size() + dcid.size());
  token.insert(token.end(), keyword.begin(), keyword.end());
  token.insert(token.end(), addrBytes.begin(), addrBytes.end());
  token.insert(token.end(), dcid.begin(), dcid.end());
  return token;
}

// returns the original destination ID if the token is valid, nothing otherwise
static std::optional<PacketBuffer> validateToken(const PacketBuffer& token, const PacketBuffer& dcid, const ComboAddress& peer)
{
  const std::array keyword = {'q', 'u', 'i', 'c', 'h', 'e'};
  auto addrBytes = peer.toByteString();
  auto minimumSize = keyword.size() + addrBytes.size();
  if (token.size() <= minimumSize) {
    return std::nullopt;
  }
  if (std::memcmp(&*keyword.begin(), &*token.begin(), keyword.size()) != 0) {
    return std::nullopt;
  }
  if (std::memcmp(&token.at(keyword.size()), &*addrBytes.begin(), addrBytes.size()) != 0) {
    return std::nullopt;
  }
  return PacketBuffer(token.begin() + keyword.size() + addrBytes.size(), token.end());
}

static void handleStatelessRetry(Socket& sock, const PacketBuffer& clientConnID, const PacketBuffer& serverConnID, const ComboAddress& peer, uint32_t version)
{
  auto newServerConnID = getCID();
  if (!newServerConnID) {
    return;
  }

  auto token = mintToken(serverConnID, peer);

  PacketBuffer out(MAX_DATAGRAM_SIZE);
  auto written = quiche_retry(clientConnID.data(), clientConnID.size(),
                              serverConnID.data(), serverConnID.size(),
                              newServerConnID->data(), newServerConnID->size(),
                              token.data(), token.size(),
                              version,
                              out.data(), out.size());

  if (written < 0) {
    DEBUGLOG("failed to create retry packet " << written);
    return;
  }

  out.resize(written);
  sock.sendTo(std::string(out.begin(), out.end()), peer);
}

static void handleVersionNegociation(Socket& sock, const PacketBuffer& clientConnID, const PacketBuffer& serverConnID, const ComboAddress& peer)
{
  PacketBuffer out(MAX_DATAGRAM_SIZE);

  auto written = quiche_negotiate_version(clientConnID.data(), clientConnID.size(),
                                          serverConnID.data(), serverConnID.size(),
                                          out.data(), out.size());

  if (written < 0) {
    DEBUGLOG("failed to create vneg packet " << written);
    return;
  }
  sock.sendTo(reinterpret_cast<const char*>(out.data()), written, peer);
}

static std::optional<std::reference_wrapper<Connection>> getConnection(const PacketBuffer& id)
{
  auto it = s_connections.find(id);
  if (it == s_connections.end()) {
    return std::nullopt;
  }
  return it->second;
}

static void sendBackDOQUnit(DOQUnitUniquePtr&& du, const char* description)
{
  DEBUGLOG("Handling back a " << description);
  auto conn = getConnection(du->serverConnID);
  handleResponse(*du->dsc->df, *conn, du->streamID, du->response);
}

static std::optional<std::reference_wrapper<Connection>> createConnection(QuicheConfig& config, const PacketBuffer& serverSideID, const PacketBuffer& originalDestinationID, const PacketBuffer& token, const ComboAddress& local, const ComboAddress& peer)
{
  auto quicheConn = QuicheConnection(quiche_accept(serverSideID.data(), serverSideID.size(),
                                                   originalDestinationID.data(), originalDestinationID.size(),
                                                   (struct sockaddr*)&local,
                                                   local.getSocklen(),
                                                   (struct sockaddr*)&peer,
                                                   peer.getSocklen(),
                                                   config.get()),
                                     quiche_conn_free);
  auto conn = Connection(peer, std::move(quicheConn));
  auto pair = s_connections.emplace(serverSideID, std::move(conn));
  return pair.first->second;
}

static void flushEgress(Socket& sock, Connection& conn)
{
  std::array<uint8_t, MAX_DATAGRAM_SIZE> out;
  quiche_send_info send_info;

  while (true) {
    auto written = quiche_conn_send(conn.d_conn.get(), out.data(), out.size(), &send_info);

    if (written == QUICHE_ERR_DONE) {
      return;
    }

    if (written < 0) {
      return;
    }
    // FIXME pacing (as send_info.at should tell us when to send the packet) ?
    sock.sendTo(reinterpret_cast<const char*>(out.data()), written, conn.d_peer);
  }
}

std::unique_ptr<CrossProtocolQuery> getDOQCrossProtocolQueryFromDQ(DNSQuestion& dq, bool isResponse)
{
  if (!dq.ids.doqu) {
    throw std::runtime_error("Trying to create a DoQ cross protocol query without a valid DoQ unit");
  }

  auto du = std::move(dq.ids.doqu);
  if (&dq.ids != &du->ids) {
    du->ids = std::move(dq.ids);
  }

  du->ids.origID = dq.getHeader()->id;

  if (!isResponse) {
    if (du->query.data() != dq.getMutableData().data()) {
      du->query = std::move(dq.getMutableData());
    }
  }
  else {
    if (du->response.data() != dq.getMutableData().data()) {
      du->response = std::move(dq.getMutableData());
    }
  }

  return std::make_unique<DOQCrossProtocolQuery>(std::move(du), isResponse);
}

/*
   We are not in the main DoQ thread but in the DoQ 'client' thread.
*/
static void processDOQQuery(DOQUnitUniquePtr&& unit)
{
  const auto handleImmediateResponse = [](DOQUnitUniquePtr&& du, const char* reason) {
    DEBUGLOG("handleImmediateResponse() reason=" << reason);
    auto conn = getConnection(du->serverConnID);
    handleResponse(*du->dsc->df, *conn, du->streamID, du->response);
    du->ids.doqu.reset();
  };

  auto& ids = unit->ids;
  ids.doqu = std::move(unit);
  auto& du = ids.doqu;
  uint16_t queryId = 0;
  ComboAddress remote;

  try {

    remote = du->ids.origRemote;
    DOQServerConfig* dsc = du->dsc;
    auto& holders = dsc->holders;
    ClientState& cs = *dsc->cs;

    if (du->query.size() < sizeof(dnsheader)) {
      ++dnsdist::metrics::g_stats.nonCompliantQueries;
      ++cs.nonCompliantQueries;
      struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(du->query.data());
      dh->rcode = RCode::ServFail;
      dh->qr = true;
      du->response = std::move(du->query);

      handleImmediateResponse(std::move(du), "DoQ non-compliant query");
      return;
    }

    ++cs.queries;
    ++dnsdist::metrics::g_stats.queries;
    du->ids.queryRealTime.start();

    {
      /* don't keep that pointer around, it will be invalidated if the buffer is ever resized */
      struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(du->query.data());

      if (!checkQueryHeaders(dh, cs)) {
        dh->rcode = RCode::ServFail;
        dh->qr = true;
        du->response = std::move(du->query);

        handleImmediateResponse(std::move(du), "DoQ invalid headers");
        return;
      }

      if (dh->qdcount == 0) {
        dh->rcode = RCode::NotImp;
        dh->qr = true;
        du->response = std::move(du->query);

        handleImmediateResponse(std::move(du), "DoQ empty query");
        return;
      }

      queryId = ntohs(dh->id);
    }

    auto downstream = du->downstream;
    du->ids.qname = DNSName(reinterpret_cast<const char*>(du->query.data()), du->query.size(), sizeof(dnsheader), false, &du->ids.qtype, &du->ids.qclass);
    DNSQuestion dq(du->ids, du->query);
    const uint16_t* flags = getFlagsFromDNSHeader(dq.getHeader());
    ids.origFlags = *flags;
    du->ids.cs = &cs;

    auto result = processQuery(dq, holders, downstream);
    if (result == ProcessQueryResult::Drop) {
      handleImmediateResponse(std::move(du), "DoQ dropped query");
      return;
    }
    else if (result == ProcessQueryResult::Asynchronous) {
      return;
    }
    else if (result == ProcessQueryResult::SendAnswer) {
      if (du->response.empty()) {
        du->response = std::move(du->query);
      }
      if (du->response.size() >= sizeof(dnsheader)) {
        auto dh = reinterpret_cast<const struct dnsheader*>(du->response.data());

        handleResponseSent(du->ids.qname, QType(du->ids.qtype), 0., du->ids.origDest, ComboAddress(), du->response.size(), *dh, dnsdist::Protocol::DoQ, dnsdist::Protocol::DoQ, false);
      }
      handleImmediateResponse(std::move(du), "DoQ self-answered response");
      return;
    }

    ++dnsdist::metrics::g_stats.responses;
    if (du->ids.cs != nullptr) {
      ++du->ids.cs->responses;
    }

    if (result != ProcessQueryResult::PassToBackend) {
      handleImmediateResponse(std::move(du), "DoQ no backend available");
      return;
    }

    if (downstream == nullptr) {
      handleImmediateResponse(std::move(du), "DoQ no backend available");
      return;
    }

    du->downstream = downstream;

    std::string proxyProtocolPayload;
    /* we need to do this _before_ creating the cross protocol query because
       after that the buffer will have been moved */
    if (downstream->d_config.useProxyProtocol) {
      proxyProtocolPayload = getProxyProtocolPayload(dq);
    }

    du->ids.origID = htons(queryId);
    du->tcp = true;

    /* this moves du->ids, careful! */
    auto cpq = std::make_unique<DOQCrossProtocolQuery>(std::move(du), false);
    cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

    if (downstream->passCrossProtocolQuery(std::move(cpq))) {
      return;
    }
    else {
      du = cpq->releaseDU();
      handleImmediateResponse(std::move(du), "DoQ internal error");
      return;
    }
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in DOQ question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
    handleImmediateResponse(std::move(du), "DoQ internal error");
    return;
  }

  return;
}

static void doq_dispatch_query(DOQServerConfig& dsc, PacketBuffer&& query, const ComboAddress& local, const ComboAddress& remote, const PacketBuffer& serverConnID, const uint64_t streamID)
{
  try {
    /* we only parse it there as a sanity check, we will parse it again later */
    DNSPacketMangler mangler(reinterpret_cast<char*>(query.data()), query.size());
    mangler.skipDomainName();
    mangler.skipBytes(4);
    // Should we ensure message id is 0 ?

    auto du = std::make_unique<DOQUnit>(std::move(query));
    du->dsc = &dsc;
    du->ids.origDest = local;
    du->ids.origRemote = remote;
    du->ids.protocol = dnsdist::Protocol::DoQ;
    du->serverConnID = serverConnID;
    du->streamID = streamID;

    processDOQQuery(std::move(du));
  }
  catch (const std::exception& e) {
    vinfolog("Had error parsing DoQ DNS packet from %s: %s", remote.toStringWithPort(), e.what());
  }
}

// this is the entrypoint from dnsdist.cc
void doqThread(ClientState* cs)
{
  try {
    std::shared_ptr<DOQFrontend>& frontend = cs->doqFrontend;

    frontend->d_server_config->cs = cs;
    frontend->d_server_config->df = cs->doqFrontend;

    setThreadName("dnsdist/doq");

    Socket sock(cs->udpFD);

    PacketBuffer buffer(std::numeric_limits<unsigned short>::max());

    while (true) {
      std::string bufferStr;
      ComboAddress client;
      if (waitForData(sock.getHandle(), 1, 0) > 0) {
        sock.recvFrom(bufferStr, client);

        uint32_t version{0};
        uint8_t type;
        std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> scid;
        size_t scid_len = scid.size();
        std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> dcid;
        size_t dcid_len = dcid.size();
        std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> odcid;
        size_t odcid_len = odcid.size();
        std::array<uint8_t, TOKEN_LEN> token;
        size_t token_len = token.size();

        auto res = quiche_header_info(reinterpret_cast<const uint8_t*>(bufferStr.data()), bufferStr.size(), LOCAL_CONN_ID_LEN,
                                      &version, &type,
                                      scid.data(), &scid_len,
                                      dcid.data(), &dcid_len,
                                      token.data(), &token_len);
        if (res != 0) {
          continue;
        }

        // destination connection ID, will have to be sent as original destination connection ID
        PacketBuffer serverConnID(dcid.begin(), dcid.begin() + dcid_len);
        // source connection ID, will have to be sent as destination connection ID
        PacketBuffer clientConnID(scid.begin(), scid.begin() + scid_len);
        auto conn = getConnection(serverConnID);

        if (!conn) {
          DEBUGLOG("Connection not found");
          if (!quiche_version_is_supported(version)) {
            DEBUGLOG("Unsupported version");
            handleVersionNegociation(sock, clientConnID, serverConnID, client);
            continue;
          }

          if (token_len == 0) {
            /* stateless retry */
            DEBUGLOG("No token received");
            handleStatelessRetry(sock, clientConnID, serverConnID, client, version);
            continue;
          }

          PacketBuffer tokenBuf(token.begin(), token.begin() + token_len);
          auto originalDestinationID = validateToken(tokenBuf, serverConnID, client);
          if (!originalDestinationID) {
            DEBUGLOG("Discarding invalid token");
            continue;
          }

          DEBUGLOG("Creating a new connection");
          conn = createConnection(frontend->d_server_config->config, serverConnID, *originalDestinationID, tokenBuf, cs->local, client);
          if (!conn) {
            continue;
          }
        }
        quiche_recv_info recv_info = {
          (struct sockaddr*)&client,
          client.getSocklen(),

          (struct sockaddr*)&cs->local,
          cs->local.getSocklen(),
        };

        auto done = quiche_conn_recv(conn->get().d_conn.get(), reinterpret_cast<uint8_t*>(bufferStr.data()), bufferStr.size(), &recv_info);
        if (done < 0) {
          continue;
        }

        if (quiche_conn_is_established(conn->get().d_conn.get())) {
          auto readable = std::unique_ptr<quiche_stream_iter, decltype(&quiche_stream_iter_free)>(quiche_conn_readable(conn->get().d_conn.get()), quiche_stream_iter_free);

          uint64_t streamID = 0;
          while (quiche_stream_iter_next(readable.get(), &streamID)) {
            bool fin = false;
            buffer.resize(std::numeric_limits<unsigned short>::max());
            auto received = quiche_conn_stream_recv(conn->get().d_conn.get(), streamID,
                                                    buffer.data(), buffer.size(),
                                                    &fin);
            if (received < 2) {
              break;
            }
            buffer.resize(received);

            if (fin) {
              // we skip message length, should we verify ?
              buffer.erase(buffer.begin(), buffer.begin() + 2);
              if (buffer.size() >= sizeof(dnsheader)) {
                doq_dispatch_query(*(frontend->d_server_config), std::move(buffer), cs->local, client, serverConnID, streamID);
              }
            }
          }
        }
        else {
          DEBUGLOG("Connection not established");
        }
      }

      for (auto conn = s_connections.begin(); conn != s_connections.end();) {
        quiche_conn_on_timeout(conn->second.d_conn.get());

        flushEgress(sock, conn->second);

        if (quiche_conn_is_closed(conn->second.d_conn.get())) {
#ifdef DEBUGLOG_ENABLED
          quiche_stats stats;
          quiche_path_stats path_stats;

          quiche_conn_stats(conn->second.d_conn.get(), &stats);
          quiche_conn_path_stats(conn->second.d_conn.get(), 0, &path_stats);

          DEBUGLOG("Connection closed, recv=" << stats.recv << " sent=" << stats.sent << " lost=" << stats.lost << " rtt=" << path_stats.rtt << "ns cwnd=" << path_stats.cwnd);
#endif
          conn = s_connections.erase(conn);
        }
        else {
          ++conn;
        }
      }
    }
  }
  catch (const std::exception& e) {
    DEBUGLOG("Caught fatal error: " << e.what());
  }
}
