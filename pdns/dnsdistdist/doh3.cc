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

#include "doh3.hh"

#ifdef HAVE_DNS_OVER_HTTP3
#include <quiche.h>

#include "dnsparser.hh"
#include "dolog.hh"
#include "iputils.hh"
#include "misc.hh"
#include "sodcrypto.hh"
#include "sstuff.hh"
#include "threadname.hh"
#include "base64.hh"

#include "dnsdist-ecs.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-random.hh"

// FIXME : to be renamed ?
static std::string s_quicRetryTokenKey = newKey(false);

std::map<const string, int> DOH3Frontend::s_available_cc_algorithms = {
  {"reno", QUICHE_CC_RENO},
  {"cubic", QUICHE_CC_CUBIC},
  {"bbr", QUICHE_CC_BBR},
};

using QuicheConnection = std::unique_ptr<quiche_conn, decltype(&quiche_conn_free)>;
using QuicheHTTP3Connection = std::unique_ptr<quiche_h3_conn, decltype(&quiche_h3_conn_free)>;
using QuicheConfig = std::unique_ptr<quiche_config, decltype(&quiche_config_free)>;
using QuicheHTTP3Config = std::unique_ptr<quiche_h3_config, decltype(&quiche_h3_config_free)>;

class H3Connection
{
public:
  H3Connection(const ComboAddress& peer, QuicheConnection&& conn) :
    d_peer(peer), d_conn(std::move(conn))
  {
  }
  H3Connection(const H3Connection&) = delete;
  H3Connection(H3Connection&&) = default;
  H3Connection& operator=(const H3Connection&) = delete;
  H3Connection& operator=(H3Connection&&) = default;
  ~H3Connection() = default;

  ComboAddress d_peer;
  QuicheConnection d_conn;
  QuicheHTTP3Connection d_http3{nullptr, quiche_h3_conn_free};
  std::unordered_map<uint64_t, PacketBuffer> d_streamBuffers;
};

static void sendBackDOH3Unit(DOH3UnitUniquePtr&& unit, const char* description);

struct DOH3ServerConfig
{
  DOH3ServerConfig(QuicheConfig&& config_, QuicheHTTP3Config&& http3config_, uint32_t internalPipeBufferSize) :
    config(std::move(config_)), http3config(std::move(http3config_))
  {
    {
      auto [sender, receiver] = pdns::channel::createObjectQueue<DOH3Unit>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, internalPipeBufferSize);
      d_responseSender = std::move(sender);
      d_responseReceiver = std::move(receiver);
    }
  }
  DOH3ServerConfig(const DOH3ServerConfig&) = delete;
  DOH3ServerConfig(DOH3ServerConfig&&) = default;
  DOH3ServerConfig& operator=(const DOH3ServerConfig&) = delete;
  DOH3ServerConfig& operator=(DOH3ServerConfig&&) = default;
  ~DOH3ServerConfig() = default;

  using ConnectionsMap = std::map<PacketBuffer, H3Connection>;

  LocalHolders holders;
  ConnectionsMap d_connections;
  QuicheConfig config;
  QuicheHTTP3Config http3config;
  ClientState* clientState{nullptr};
  std::shared_ptr<DOH3Frontend> df{nullptr};
  pdns::channel::Sender<DOH3Unit> d_responseSender;
  pdns::channel::Receiver<DOH3Unit> d_responseReceiver;
};

/* these might seem useless, but they are needed because
   they need to be declared _after_ the definition of DOH3ServerConfig
   so that we can use a unique_ptr in DOH3Frontend */
DOH3Frontend::DOH3Frontend() = default;
DOH3Frontend::~DOH3Frontend() = default;

#if 0
#define DEBUGLOG_ENABLED
#define DEBUGLOG(x) std::cerr << x << std::endl;
#else
#define DEBUGLOG(x)
#endif

static constexpr size_t MAX_DATAGRAM_SIZE = 1200;
static constexpr size_t LOCAL_CONN_ID_LEN = 16;

class DOH3TCPCrossQuerySender final : public TCPQuerySender
{
public:
  DOH3TCPCrossQuerySender() = default;

  [[nodiscard]] bool active() const override
  {
    return true;
  }

  void handleResponse([[maybe_unused]] const struct timeval& now, TCPResponse&& response) override
  {
    if (!response.d_idstate.doh3u) {
      return;
    }

    auto unit = std::move(response.d_idstate.doh3u);
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

      dnsResponse.ids.doh3u = std::move(unit);

      if (!processResponse(dnsResponse.ids.doh3u->response, *localRespRuleActions, *localCacheInsertedRespRuleActions, dnsResponse, false)) {
        if (dnsResponse.ids.doh3u) {

          sendBackDOH3Unit(std::move(dnsResponse.ids.doh3u), "Response dropped by rules");
        }
        return;
      }

      if (dnsResponse.isAsynchronous()) {
        return;
      }

      unit = std::move(dnsResponse.ids.doh3u);
    }

    if (!unit->ids.selfGenerated) {
      double udiff = unit->ids.queryRealTime.udiff();
      vinfolog("Got answer from %s, relayed to %s (http/3), took %f us", unit->downstream->d_config.remote.toStringWithPort(), unit->ids.origRemote.toStringWithPort(), udiff);

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

    sendBackDOH3Unit(std::move(unit), "Cross-protocol response");
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    return handleResponse(now, std::move(response));
  }

  void notifyIOError([[maybe_unused]] const struct timeval& now, TCPResponse&& response) override
  {
    if (!response.d_idstate.doh3u) {
      return;
    }

    auto unit = std::move(response.d_idstate.doh3u);
    if (unit->dsc == nullptr) {
      return;
    }

    /* this will signal an error */
    unit->response.clear();
    unit->ids = std::move(response.d_idstate);
    sendBackDOH3Unit(std::move(unit), "Cross-protocol error");
  }
};

class DOH3CrossProtocolQuery : public CrossProtocolQuery
{
public:
  DOH3CrossProtocolQuery(DOH3UnitUniquePtr&& unit, bool isResponse)
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
      query.d_idstate.doh3u = std::move(unit);
    }

    /* we _could_ remove it from the query buffer and put in query's d_proxyProtocolPayload,
       clearing query.d_proxyProtocolPayloadAdded and unit->proxyProtocolPayloadSize.
       Leave it for now because we know that the onky case where the payload has been
       added is when we tried over UDP, got a TC=1 answer and retried over TCP/DoT,
       and we know the TCP/DoT code can handle it. */
    query.d_proxyProtocolPayloadAdded = query.d_idstate.doh3u->proxyProtocolPayloadSize > 0;
    downstream = query.d_idstate.doh3u->downstream;
  }

  void handleInternalError()
  {
    sendBackDOH3Unit(std::move(query.d_idstate.doh3u), "DOH3 internal error");
  }

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    query.d_idstate.doh3u->downstream = downstream;
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

  DOH3UnitUniquePtr&& releaseDU()
  {
    return std::move(query.d_idstate.doh3u);
  }

private:
  static std::shared_ptr<DOH3TCPCrossQuerySender> s_sender;
};

std::shared_ptr<DOH3TCPCrossQuerySender> DOH3CrossProtocolQuery::s_sender = std::make_shared<DOH3TCPCrossQuerySender>();

static void h3_send_response(quiche_conn* quic_conn, quiche_h3_conn* conn, const uint64_t streamID, uint16_t statusCode, const uint8_t* body, size_t len)
{
  std::string status = std::to_string(statusCode);
  std::string lenStr = std::to_string(len);
  quiche_h3_header headers[] = {
    {
      .name = reinterpret_cast<const uint8_t*>(":status"),
      .name_len = sizeof(":status") - 1,

      .value = reinterpret_cast<const uint8_t*>(status.data()),
      .value_len = status.size(),
    },
    {
      .name = reinterpret_cast<const uint8_t*>("content-length"),
      .name_len = sizeof("content-length") - 1,

      .value = reinterpret_cast<const uint8_t*>(lenStr.data()),
      .value_len = lenStr.size(),
    },
  };
  quiche_h3_send_response(conn, quic_conn,
                          streamID, headers, 2, len == 0);

  if (len == 0) {
    return;
  }

  size_t pos = 0;
  while (pos < len) {
    auto res = quiche_h3_send_body(conn, quic_conn,
                                   streamID, const_cast<uint8_t*>(body) + pos, len - pos, true);
    if (res < 0) {
      // Shutdown with internal error code
      quiche_conn_stream_shutdown(quic_conn, streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(1));
      return;
    }
    pos += res;
  }
}

static void h3_send_response(quiche_conn* quic_conn, quiche_h3_conn* conn, const uint64_t streamID, uint16_t statusCode, const std::string& content)
{
  h3_send_response(quic_conn, conn, streamID, statusCode, reinterpret_cast<const uint8_t*>(content.data()), content.size());
}
static void h3_send_response(H3Connection& conn, const uint64_t streamID, uint16_t statusCode, const uint8_t* body, size_t len)
{
  h3_send_response(conn.d_conn.get(), conn.d_http3.get(), streamID, statusCode, body, len);
}

static void handleResponse(DOH3Frontend& frontend, H3Connection& conn, const uint64_t streamID, uint16_t statusCode, const PacketBuffer& response)
{
  if (statusCode == 200) {
    ++frontend.d_validResponses;
  }
  else {
    ++frontend.d_errorResponses;
  }
  if (response.empty()) {
    quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(DOQ_Error_Codes::DOQ_UNSPECIFIED_ERROR));
  }
  else {
    h3_send_response(conn, streamID, statusCode, &response.at(0), response.size());
  }
}

static void fillRandom(PacketBuffer& buffer, size_t size)
{
  buffer.reserve(size);
  while (size > 0) {
    buffer.insert(buffer.end(), dnsdist::getRandomValue(std::numeric_limits<uint8_t>::max()));
    --size;
  }
}

void DOH3Frontend::setup()
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
    auto res = quiche_config_set_application_protos(config.get(),
                                                    (uint8_t*)QUICHE_H3_APPLICATION_PROTOCOL,
                                                    sizeof(QUICHE_H3_APPLICATION_PROTOCOL) - 1);
    if (res != 0) {
      throw std::runtime_error("Error setting ALPN: " + std::to_string(res));
    }
  }

  quiche_config_set_max_idle_timeout(config.get(), d_idleTimeout * 1000);
  /* maximum size of an outgoing packet, which means the buffer we pass to quiche_conn_send() should be at least that big */
  quiche_config_set_max_send_udp_payload_size(config.get(), MAX_DATAGRAM_SIZE);
  quiche_config_set_max_recv_udp_payload_size(config.get(), MAX_DATAGRAM_SIZE);

  // The number of concurrent remotely-initiated bidirectional streams to be open at any given time
  // https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_streams_bidi
  // 0 means none will get accepted, that's why we have a default value of 65535
  quiche_config_set_initial_max_streams_bidi(config.get(), d_maxInFlight);
  quiche_config_set_initial_max_streams_uni(config.get(), d_maxInFlight);

  // The number of bytes of incoming stream data to be buffered for each localy or remotely-initiated bidirectional stream
  quiche_config_set_initial_max_stream_data_bidi_local(config.get(), 1000000);
  quiche_config_set_initial_max_stream_data_bidi_remote(config.get(), 1000000);
  quiche_config_set_initial_max_stream_data_uni(config.get(), 1000000);

  quiche_config_set_disable_active_migration(config.get(), true);

  // The number of total bytes of incoming stream data to be buffered for the whole connection
  // https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_data
  quiche_config_set_initial_max_data(config.get(), 8192 * d_maxInFlight);
  if (!d_keyLogFile.empty()) {
    quiche_config_log_keys(config.get());
  }

  auto algo = DOH3Frontend::s_available_cc_algorithms.find(d_ccAlgo);
  if (algo != DOH3Frontend::s_available_cc_algorithms.end()) {
    quiche_config_set_cc_algorithm(config.get(), static_cast<enum quiche_cc_algorithm>(algo->second));
  }

  {
    PacketBuffer resetToken;
    fillRandom(resetToken, 16);
    quiche_config_set_stateless_reset_token(config.get(), resetToken.data());
  }

  // quiche_h3_config_new
  auto http3config = QuicheHTTP3Config(quiche_h3_config_new(), quiche_h3_config_free);

  d_server_config = std::make_unique<DOH3ServerConfig>(std::move(config), std::move(http3config), d_internalPipeBufferSize);
}

static std::optional<PacketBuffer> getCID()
{
  PacketBuffer buffer;

  fillRandom(buffer, LOCAL_CONN_ID_LEN);

  return buffer;
}

static constexpr size_t MAX_TOKEN_LEN = dnsdist::crypto::authenticated::getEncryptedSize(std::tuple_size<decltype(SodiumNonce::value)>{} /* nonce */ + sizeof(uint64_t) /* TTD */ + 16 /* IPv6 */ + QUICHE_MAX_CONN_ID_LEN);

static PacketBuffer mintToken(const PacketBuffer& dcid, const ComboAddress& peer)
{
  try {
    SodiumNonce nonce;
    nonce.init();

    const auto addrBytes = peer.toByteString();
    // this token will be valid for 60s
    const uint64_t ttd = time(nullptr) + 60U;
    PacketBuffer plainTextToken;
    plainTextToken.reserve(sizeof(ttd) + addrBytes.size() + dcid.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    plainTextToken.insert(plainTextToken.end(), reinterpret_cast<const uint8_t*>(&ttd), reinterpret_cast<const uint8_t*>(&ttd) + sizeof(ttd));
    plainTextToken.insert(plainTextToken.end(), addrBytes.begin(), addrBytes.end());
    plainTextToken.insert(plainTextToken.end(), dcid.begin(), dcid.end());
    //	NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto encryptedToken = sodEncryptSym(std::string_view(reinterpret_cast<const char*>(plainTextToken.data()), plainTextToken.size()), s_quicRetryTokenKey, nonce, false);
    // a bit sad, let's see if we can do better later
    auto encryptedTokenPacket = PacketBuffer(encryptedToken.begin(), encryptedToken.end());
    encryptedTokenPacket.insert(encryptedTokenPacket.begin(), nonce.value.begin(), nonce.value.end());
    return encryptedTokenPacket;
  }
  catch (const std::exception& exp) {
    vinfolog("Error while minting DoH3 token: %s", exp.what());
    throw;
  }
}

// returns the original destination ID if the token is valid, nothing otherwise
static std::optional<PacketBuffer> validateToken(const PacketBuffer& token, const ComboAddress& peer)
{
  try {
    SodiumNonce nonce;
    auto addrBytes = peer.toByteString();
    const uint64_t now = time(nullptr);
    const auto minimumSize = nonce.value.size() + sizeof(now) + addrBytes.size();
    if (token.size() <= minimumSize) {
      return std::nullopt;
    }

    memcpy(nonce.value.data(), token.data(), nonce.value.size());

    //	NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto cipher = std::string_view(reinterpret_cast<const char*>(&token.at(nonce.value.size())), token.size() - nonce.value.size());
    auto plainText = sodDecryptSym(cipher, s_quicRetryTokenKey, nonce, false);

    if (plainText.size() <= sizeof(now) + addrBytes.size()) {
      return std::nullopt;
    }

    uint64_t ttd{0};
    memcpy(&ttd, plainText.data(), sizeof(ttd));
    if (ttd < now) {
      return std::nullopt;
    }

    if (std::memcmp(&plainText.at(sizeof(ttd)), &*addrBytes.begin(), addrBytes.size()) != 0) {
      return std::nullopt;
    }
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    return PacketBuffer(plainText.begin() + (sizeof(ttd) + addrBytes.size()), plainText.end());
  }
  catch (const std::exception& exp) {
    vinfolog("Error while validating DoH3 token: %s", exp.what());
    return std::nullopt;
  }
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
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  sock.sendTo(reinterpret_cast<const char*>(out.data()), written, peer);
}

static std::optional<std::reference_wrapper<H3Connection>> getConnection(DOH3ServerConfig::ConnectionsMap& connMap, const PacketBuffer& connID)
{
  auto iter = connMap.find(connID);
  if (iter == connMap.end()) {
    return std::nullopt;
  }
  return iter->second;
}

static void sendBackDOH3Unit(DOH3UnitUniquePtr&& unit, const char* description)
{
  if (unit->dsc == nullptr) {
    return;
  }
  try {
    if (!unit->dsc->d_responseSender.send(std::move(unit))) {
      ++dnsdist::metrics::g_stats.doh3ResponsePipeFull;
      vinfolog("Unable to pass a %s to the DoH3 worker thread because the pipe is full", description);
    }
  }
  catch (const std::exception& e) {
    vinfolog("Unable to pass a %s to the DoH3 worker thread because we couldn't write to the pipe: %s", description, e.what());
  }
}

static std::optional<std::reference_wrapper<H3Connection>> createConnection(DOH3ServerConfig& config, const PacketBuffer& serverSideID, const PacketBuffer& originalDestinationID, const ComboAddress& local, const ComboAddress& peer)
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

  if (config.df && !config.df->d_keyLogFile.empty()) {
    quiche_conn_set_keylog_path(quicheConn.get(), config.df->d_keyLogFile.c_str());
  }

  auto conn = H3Connection(peer, std::move(quicheConn));
  auto pair = config.d_connections.emplace(serverSideID, std::move(conn));
  return pair.first->second;
}

static void flushEgress(Socket& sock, H3Connection& conn)
{
  std::array<uint8_t, MAX_DATAGRAM_SIZE> out{};
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
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    sock.sendTo(reinterpret_cast<const char*>(out.data()), written, conn.d_peer);
  }
}

std::unique_ptr<CrossProtocolQuery> getDOH3CrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion, bool isResponse)
{
  if (!dnsQuestion.ids.doh3u) {
    throw std::runtime_error("Trying to create a DoH3 cross protocol query without a valid DoH3 unit");
  }

  auto unit = std::move(dnsQuestion.ids.doh3u);
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

  return std::make_unique<DOH3CrossProtocolQuery>(std::move(unit), isResponse);
}

/*
   We are not in the main DoH3 thread but in the DoH3 'client' thread.
*/
static void processDOH3Query(DOH3UnitUniquePtr&& doh3Unit)
{
  const auto handleImmediateResponse = [](DOH3UnitUniquePtr&& unit, [[maybe_unused]] const char* reason) {
    DEBUGLOG("handleImmediateResponse() reason=" << reason);
    auto conn = getConnection(unit->dsc->df->d_server_config->d_connections, unit->serverConnID);
    handleResponse(*unit->dsc->df, *conn, unit->streamID, unit->status_code, unit->response);
    unit->ids.doh3u.reset();
  };

  auto& ids = doh3Unit->ids;
  ids.doh3u = std::move(doh3Unit);
  auto& unit = ids.doh3u;
  uint16_t queryId = 0;
  ComboAddress remote;

  try {

    remote = unit->ids.origRemote;
    DOH3ServerConfig* dsc = unit->dsc;
    auto& holders = dsc->holders;
    ClientState& clientState = *dsc->clientState;

    if (unit->query.size() < sizeof(dnsheader)) {
      ++dnsdist::metrics::g_stats.nonCompliantQueries;
      ++clientState.nonCompliantQueries;
      unit->response.clear();

      unit->status_code = 400;
      handleImmediateResponse(std::move(unit), "DoH3 non-compliant query");
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

        unit->status_code = 400;
        handleImmediateResponse(std::move(unit), "DoH3 invalid headers");
        return;
      }

      if (dnsHeader->qdcount == 0) {
        dnsdist::PacketMangling::editDNSHeaderFromPacket(unit->query, [](dnsheader& header) {
          header.rcode = RCode::NotImp;
          header.qr = true;
          return true;
        });
        unit->response = std::move(unit->query);

        unit->status_code = 400;
        handleImmediateResponse(std::move(unit), "DoH3 empty query");
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
      unit->status_code = 403;
      handleImmediateResponse(std::move(unit), "DoH3 dropped query");
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

        handleResponseSent(unit->ids.qname, QType(unit->ids.qtype), 0., unit->ids.origDest, ComboAddress(), unit->response.size(), *dnsHeader, dnsdist::Protocol::DoH3, dnsdist::Protocol::DoH3, false);
      }
      handleImmediateResponse(std::move(unit), "DoH3 self-answered response");
      return;
    }

    ++dnsdist::metrics::g_stats.responses;
    if (unit->ids.cs != nullptr) {
      ++unit->ids.cs->responses;
    }

    if (result != ProcessQueryResult::PassToBackend) {
      unit->status_code = 500;
      handleImmediateResponse(std::move(unit), "DoH3 no backend available");
      return;
    }

    if (downstream == nullptr) {
      unit->status_code = 502;
      handleImmediateResponse(std::move(unit), "DoH3 no backend available");
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
    auto cpq = std::make_unique<DOH3CrossProtocolQuery>(std::move(unit), false);
    cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

    if (downstream->passCrossProtocolQuery(std::move(cpq))) {
      return;
    }
    // NOLINTNEXTLINE(bugprone-use-after-move): it was only moved if the call succeeded
    unit = cpq->releaseDU();
    unit->status_code = 500;
    handleImmediateResponse(std::move(unit), "DoH3 internal error");
    return;
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in DOH3 question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
    unit->status_code = 500;
    handleImmediateResponse(std::move(unit), "DoH3 internal error");
    return;
  }
}

static void doh3_dispatch_query(DOH3ServerConfig& dsc, PacketBuffer&& query, const ComboAddress& local, const ComboAddress& remote, const PacketBuffer& serverConnID, const uint64_t streamID)
{
  try {
    /* we only parse it there as a sanity check, we will parse it again later */
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DNSPacketMangler mangler(reinterpret_cast<char*>(query.data()), query.size());
    mangler.skipDomainName();
    mangler.skipBytes(4);

    auto unit = std::make_unique<DOH3Unit>(std::move(query));
    unit->dsc = &dsc;
    unit->ids.origDest = local;
    unit->ids.origRemote = remote;
    unit->ids.protocol = dnsdist::Protocol::DoH3;
    unit->serverConnID = serverConnID;
    unit->streamID = streamID;

    processDOH3Query(std::move(unit));
  }
  catch (const std::exception& exp) {
    vinfolog("Had error parsing DoH3 DNS packet from %s: %s", remote.toStringWithPort(), exp.what());
  }
}

static void flushResponses(pdns::channel::Receiver<DOH3Unit>& receiver)
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
        handleResponse(*unit->dsc->df, *conn, unit->streamID, unit->status_code, unit->response);
      }
    }
    catch (const std::exception& e) {
      errlog("Error while processing response received over DoH3: %s", e.what());
    }
    catch (...) {
      errlog("Unspecified error while processing response received over DoH3");
    }
  }
}

// this is the entrypoint from dnsdist.cc
void doh3Thread(ClientState* clientState)
{
  try {
    std::shared_ptr<DOH3Frontend>& frontend = clientState->doh3Frontend;

    frontend->d_server_config->clientState = clientState;
    frontend->d_server_config->df = clientState->doh3Frontend;

    setThreadName("dnsdist/doh3");

    Socket sock(clientState->udpFD);

    PacketBuffer buffer(std::numeric_limits<uint16_t>::max());
    auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());

    auto responseReceiverFD = frontend->d_server_config->d_responseReceiver.getDescriptor();
    mplexer->addReadFD(sock.getHandle(), [](int, FDMultiplexer::funcparam_t&) {});
    mplexer->addReadFD(responseReceiverFD, [](int, FDMultiplexer::funcparam_t&) {});
    while (true) {
      std::vector<int> readyFDs;
      mplexer->getAvailableFDs(readyFDs, 500);

      if (std::find(readyFDs.begin(), readyFDs.end(), sock.getHandle()) != readyFDs.end()) {
        DEBUGLOG("Received datagram");
        std::string bufferStr;
        ComboAddress client;
        sock.recvFrom(bufferStr, client);

        uint32_t version{0};
        uint8_t type{0};
        std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> scid{};
        size_t scid_len = scid.size();
        std::array<uint8_t, QUICHE_MAX_CONN_ID_LEN> dcid{};
        size_t dcid_len = dcid.size();
        std::array<uint8_t, MAX_TOKEN_LEN> token{};
        size_t token_len = token.size();

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto res = quiche_header_info(reinterpret_cast<const uint8_t*>(bufferStr.data()), bufferStr.size(), LOCAL_CONN_ID_LEN,
                                      &version, &type,
                                      scid.data(), &scid_len,
                                      dcid.data(), &dcid_len,
                                      token.data(), &token_len);
        if (res != 0) {
          DEBUGLOG("Error in quiche_header_info: " << res);
          continue;
        }

        // destination connection ID, will have to be sent as original destination connection ID
        PacketBuffer serverConnID(dcid.begin(), dcid.begin() + dcid_len);
        // source connection ID, will have to be sent as destination connection ID
        PacketBuffer clientConnID(scid.begin(), scid.begin() + scid_len);
        auto conn = getConnection(frontend->d_server_config->d_connections, serverConnID);

        if (!conn) {
          DEBUGLOG("Connection not found");
          if (!quiche_version_is_supported(version)) {
            DEBUGLOG("Unsupported version");
            ++frontend->d_doh3UnsupportedVersionErrors;
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
          auto originalDestinationID = validateToken(tokenBuf, client);
          if (!originalDestinationID) {
            ++frontend->d_doh3InvalidTokensReceived;
            DEBUGLOG("Discarding invalid token");
            continue;
          }

          DEBUGLOG("Creating a new connection");
          conn = createConnection(*frontend->d_server_config, serverConnID, *originalDestinationID, clientState->local, client);
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
          reinterpret_cast<struct sockaddr*>(&clientState->local),
          clientState->local.getSocklen(),
        };

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto done = quiche_conn_recv(conn->get().d_conn.get(), reinterpret_cast<uint8_t*>(bufferStr.data()), bufferStr.size(), &recv_info);
        if (done < 0) {
          continue;
        }

        if (quiche_conn_is_established(conn->get().d_conn.get())) {
          DEBUGLOG("Connection is established");

          if (!conn->get().d_http3) {
            conn->get().d_http3 = QuicheHTTP3Connection(quiche_h3_conn_new_with_transport(conn->get().d_conn.get(), frontend->d_server_config->http3config.get()),
                                                        quiche_h3_conn_free);
            if (!conn->get().d_http3) {
              continue;
            }
            DEBUGLOG("Successfully created HTTP/3 connection");
          }

          while (1) {
            quiche_h3_event* ev;
            // Processes HTTP/3 data received from the peer
            int64_t streamID = quiche_h3_conn_poll(conn->get().d_http3.get(),
                                                   conn->get().d_conn.get(),
                                                   &ev);

            if (streamID < 0) {
              break;
            }

            switch (quiche_h3_event_type(ev)) {
            case QUICHE_H3_EVENT_HEADERS: {
              std::string path;
              int rc = quiche_h3_event_for_each_header(
                ev,
                [](uint8_t* name, size_t name_len, uint8_t* value, size_t value_len, void* argp) -> int {
                  std::string_view key(reinterpret_cast<char*>(name), name_len);
                  std::string_view content(reinterpret_cast<char*>(value), value_len);
                  if (key == ":path") {
                    auto pathptr = reinterpret_cast<std::string*>(argp);
                    *pathptr = content;
                  }
                  return 0;
                },
                &path);
              if (rc != 0) {
                DEBUGLOG("Failed to process headers");
                ++dnsdist::metrics::g_stats.nonCompliantQueries;
                ++clientState->nonCompliantQueries;
                ++frontend->d_errorResponses;
                h3_send_response(conn->get().d_conn.get(), conn->get().d_http3.get(), streamID, 400, "Unable to process query headers");
                break;
              }
              if (path.empty()) {
                DEBUGLOG("Path not found");
                ++dnsdist::metrics::g_stats.nonCompliantQueries;
                ++clientState->nonCompliantQueries;
                ++frontend->d_errorResponses;
                h3_send_response(conn->get().d_conn.get(), conn->get().d_http3.get(), streamID, 400, "Path not found");
                break;
              }
              {
                auto pos = path.find("?dns=");
                if (pos == string::npos) {
                  pos = path.find("&dns=");
                }
                if (pos != string::npos) {
                  // need to base64url decode this
                  string sdns(path.substr(pos + 5));
                  boost::replace_all(sdns, "-", "+");
                  boost::replace_all(sdns, "_", "/");
                  // re-add padding that may have been missing
                  switch (sdns.size() % 4) {
                  case 2:
                    sdns.append(2, '=');
                    break;
                  case 3:
                    sdns.append(1, '=');
                    break;
                  }

                  PacketBuffer decoded;

                  /* 1 byte for the root label, 2 type, 2 class, 4 TTL (fake), 2 record length, 2 option length, 2 option code, 2 family, 1 source, 1 scope, 16 max for a full v6 */
                  const size_t maxAdditionalSizeForEDNS = 35U;
                  /* rough estimate so we hopefully don't need a new allocation later */
                  /* We reserve at few additional bytes to be able to add EDNS later */
                  const size_t estimate = ((sdns.size() * 3) / 4);
                  decoded.reserve(estimate + maxAdditionalSizeForEDNS);
                  if (B64Decode(sdns, decoded) < 0) {
                    DEBUGLOG("Unable to base64 decode()");
                    ++dnsdist::metrics::g_stats.nonCompliantQueries;
                    ++clientState->nonCompliantQueries;
                    ++frontend->d_errorResponses;
                    h3_send_response(conn->get().d_conn.get(), conn->get().d_http3.get(), streamID, 400, "Unable to decode BASE64-URL");
                    break;
                  }

                  if (decoded.size() < sizeof(dnsheader)) {
                    ++dnsdist::metrics::g_stats.nonCompliantQueries;
                    ++clientState->nonCompliantQueries;
                    ++frontend->d_errorResponses;
                    h3_send_response(conn->get().d_conn.get(), conn->get().d_http3.get(), streamID, 400, "DoH3 non-compliant query");
                    break;
                  }
                  DEBUGLOG("Dispatching query");
                  doh3_dispatch_query(*(frontend->d_server_config), std::move(decoded), clientState->local, client, serverConnID, streamID);
                  conn->get().d_streamBuffers.erase(streamID);
                }
                else {
                  DEBUGLOG("User error, unable to find the DNS parameter");
                  ++dnsdist::metrics::g_stats.nonCompliantQueries;
                  ++clientState->nonCompliantQueries;
                  ++frontend->d_errorResponses;
                  h3_send_response(conn->get().d_conn.get(), conn->get().d_http3.get(), streamID, 400, "Unable to find the DNS parameter");
                  break;
                }
              }
              break;
            }

            case QUICHE_H3_EVENT_DATA:
            case QUICHE_H3_EVENT_FINISHED:
            case QUICHE_H3_EVENT_RESET:
            case QUICHE_H3_EVENT_PRIORITY_UPDATE:
            case QUICHE_H3_EVENT_GOAWAY:
              break;
            }

            quiche_h3_event_free(ev);
          }
        }
        else {
          DEBUGLOG("Connection not established");
        }
      }

      if (std::find(readyFDs.begin(), readyFDs.end(), responseReceiverFD) != readyFDs.end()) {
        flushResponses(frontend->d_server_config->d_responseReceiver);
      }

      for (auto conn = frontend->d_server_config->d_connections.begin(); conn != frontend->d_server_config->d_connections.end();) {
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
          conn = frontend->d_server_config->d_connections.erase(conn);
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

#endif /* HAVE_DNS_OVER_HTTP3 */
