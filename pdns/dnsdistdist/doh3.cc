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

#include "dolog.hh"
#include "iputils.hh"
#include "misc.hh"
#include "sstuff.hh"
#include "threadname.hh"
#include "base64.hh"

#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-random.hh"

#include "doq-common.hh"

#if 0
#define DEBUGLOG_ENABLED
#define DEBUGLOG(x) std::cerr << x << std::endl;
#else
#define DEBUGLOG(x)
#endif

using namespace dnsdist::doq;

class H3Connection
{
public:
  H3Connection(const ComboAddress& peer, const ComboAddress& localAddr, QuicheConfig config, QuicheConnection&& conn) :
    d_peer(peer), d_localAddr(localAddr), d_conn(std::move(conn)), d_config(std::move(config))
  {
  }
  H3Connection(const H3Connection&) = delete;
  H3Connection(H3Connection&&) = default;
  H3Connection& operator=(const H3Connection&) = delete;
  H3Connection& operator=(H3Connection&&) = default;
  ~H3Connection() = default;

  std::shared_ptr<const std::string> getSNI()
  {
    if (!d_sni) {
      d_sni = std::make_shared<const std::string>(getSNIFromQuicheConnection(d_conn));
    }
    return d_sni;
  }

  ComboAddress d_peer;
  ComboAddress d_localAddr;
  QuicheConnection d_conn;
  QuicheConfig d_config;
  QuicheHTTP3Connection d_http3{nullptr, quiche_h3_conn_free};
  // buffer request headers by streamID
  std::unordered_map<uint64_t, dnsdist::doh3::h3_headers_t> d_headersBuffers;
  std::unordered_map<uint64_t, PacketBuffer> d_streamBuffers;
  std::unordered_map<uint64_t, PacketBuffer> d_streamOutBuffers;
  std::shared_ptr<const std::string> d_sni{nullptr};
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

      dnsResponse.ids.doh3u = std::move(unit);

      if (!processResponse(dnsResponse.ids.doh3u->response, dnsResponse, false)) {
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
      auto udiff = unit->ids.queryRealTime.udiff();
      VERBOSESLOG(infolog("Got answer from %s, relayed to %s (DoH3, %d bytes), took %d us", unit->downstream->d_config.remote.toStringWithPort(), unit->ids.origRemote.toStringWithPort(), unit->response.size(), udiff),
                  dnsResponse.getLogger()->info("Got answer from backend, relayed to client"));

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

static bool tryWriteResponse(H3Connection& conn, const uint64_t streamID, PacketBuffer& response)
{
  size_t pos = 0;
  while (pos < response.size()) {
    // send_body takes care of setting fin to false if it cannot send the entire content so we can try again.
    auto res = quiche_h3_send_body(conn.d_http3.get(), conn.d_conn.get(),
                                   streamID, &response.at(pos), response.size() - pos, true);
    if (res == QUICHE_H3_ERR_DONE || res == QUICHE_H3_TRANSPORT_ERR_DONE) {
      response.erase(response.begin(), response.begin() + static_cast<ssize_t>(pos));
      return false;
    }
    if (res < 0) {
      // Shutdown with internal error code
      quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(dnsdist::doq::DOQ_Error_Codes::DOQ_INTERNAL_ERROR));
      return true;
    }
    pos += res;
  }

  return true;
}

static void addHeaderToList(std::vector<quiche_h3_header>& headers, const char* name, size_t nameLen, const char* value, size_t valueLen)
{
  headers.emplace_back((quiche_h3_header){
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): Quiche API
    .name = reinterpret_cast<const uint8_t*>(name),
    .name_len = nameLen,
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): Quiche API
    .value = reinterpret_cast<const uint8_t*>(value),
    .value_len = valueLen,
  });
}

static void h3_send_response(H3Connection& conn, const uint64_t streamID, uint16_t statusCode, const uint8_t* body, size_t len, const std::string& contentType = {})
{
  std::string status = std::to_string(statusCode);
  PacketBuffer location;
  PacketBuffer responseBody;
  std::vector<quiche_h3_header> headers;
  headers.reserve(4);
  addHeaderToList(headers, ":status", sizeof(":status") - 1, status.data(), status.size());

  if (statusCode >= 300 && statusCode < 400) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): Quiche API
    addHeaderToList(headers, "location", sizeof("location") - 1, reinterpret_cast<const char*>(body), len);
    static const std::string s_redirectStart{"<!DOCTYPE html><TITLE>Moved</TITLE><P>The document has moved <A HREF=\""};
    static const std::string s_redirectEnd{"\">here</A>"};
    static const std::string s_redirectContentType("text/html; charset=utf-8");
    addHeaderToList(headers, "content-type", sizeof("content-type") - 1, s_redirectContentType.data(), s_redirectContentType.size());
    responseBody.reserve(s_redirectStart.size() + len + s_redirectEnd.size());
    responseBody.insert(responseBody.begin(), s_redirectStart.begin(), s_redirectStart.end());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    responseBody.insert(responseBody.end(), body, body + len);
    responseBody.insert(responseBody.end(), s_redirectEnd.begin(), s_redirectEnd.end());
    body = responseBody.data();
    len = responseBody.size();
  }
  else if (len > 0 && (statusCode == 200U || !contentType.empty())) {
    // do not include content-type header info if there is no content
    addHeaderToList(headers, "content-type", sizeof("content-type") - 1, contentType.empty() ? "application/dns-message" : contentType.data(), contentType.empty() ? sizeof("application/dns-message") - 1 : contentType.size());
  }

  const std::string lenStr = std::to_string(len);
  addHeaderToList(headers, "content-length", sizeof("content-length") - 1, lenStr.data(), lenStr.size());

  auto returnValue = quiche_h3_send_response(conn.d_http3.get(), conn.d_conn.get(),
                                             streamID, headers.data(),
                                             headers.size(),
                                             len == 0);
  if (returnValue != 0) {
    /* in theory it could be QUICHE_H3_ERR_STREAM_BLOCKED if the stream is not writable / congested, but we are not going to handle this case */
    quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(dnsdist::doq::DOQ_Error_Codes::DOQ_INTERNAL_ERROR));
    return;
  }

  if (len == 0) {
    return;
  }

  size_t pos = 0;
  while (pos < len) {
    // send_body takes care of setting fin to false if it cannot send the entire content so we can try again.
    auto res = quiche_h3_send_body(conn.d_http3.get(), conn.d_conn.get(),
                                   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic): Quiche API
                                   streamID, const_cast<uint8_t*>(body) + pos, len - pos, true);
    if (res == QUICHE_H3_ERR_DONE || res == QUICHE_H3_TRANSPORT_ERR_DONE) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic): Quiche API
      conn.d_streamOutBuffers[streamID] = PacketBuffer(body + pos, body + len);
      return;
    }
    if (res < 0) {
      // Shutdown with internal error code
      quiche_conn_stream_shutdown(conn.d_conn.get(), streamID, QUICHE_SHUTDOWN_WRITE, static_cast<uint64_t>(1));
      return;
    }
    pos += res;
  }
}

static void h3_send_response(H3Connection& conn, const uint64_t streamID, uint16_t statusCode, const std::string& content = {})
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): Quiche API
  h3_send_response(conn, streamID, statusCode, reinterpret_cast<const uint8_t*>(content.data()), content.size());
}

static void handleResponse(DOH3Frontend& frontend, H3Connection& conn, const uint64_t streamID, uint16_t statusCode, const PacketBuffer& response, const std::string& contentType)
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
    h3_send_response(conn, streamID, statusCode, &response.at(0), response.size(), contentType);
  }
}

void DOH3Frontend::setup()
{
  auto config = QuicheConfig(quiche_config_new(QUICHE_PROTOCOL_VERSION), quiche_config_free);
  d_quicheParams.d_alpn = std::string(DOH3_ALPN.begin(), DOH3_ALPN.end());
  configureQuiche(config, d_quicheParams, true);

  auto http3config = QuicheHTTP3Config(quiche_h3_config_new(), quiche_h3_config_free);

  d_server_config = std::make_unique<DOH3ServerConfig>(std::move(config), std::move(http3config), d_internalPipeBufferSize);
}

void DOH3Frontend::reloadCertificates()
{
  auto config = QuicheConfig(quiche_config_new(QUICHE_PROTOCOL_VERSION), quiche_config_free);
  d_quicheParams.d_alpn = std::string(DOH3_ALPN.begin(), DOH3_ALPN.end());
  configureQuiche(config, d_quicheParams, true);
  std::atomic_store_explicit(&d_server_config->config, std::move(config), std::memory_order_release);
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
      VERBOSESLOG(infolog("Unable to pass a %s to the DoH3 worker thread because the pipe is full", description),
                  dnsdist::logging::getTopLogger()->info(Logr::Info, std::string("Unable to pass a ") + std::string(description) + " to the DoH3 worker thread because the pipe is full"));
    }
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Unable to pass a %s to the DoH3 worker thread because we couldn't write to the pipe: %s", description, e.what()),
                dnsdist::logging::getTopLogger()->error(Logr::Info, e.what(), std::string("Unable to pass a ") + std::string(description) + " to the DoH3 worker thread because we couldn't write to the pipe"));
  }
}

static std::optional<std::reference_wrapper<H3Connection>> createConnection(DOH3ServerConfig& config, const PacketBuffer& serverSideID, const PacketBuffer& originalDestinationID, const ComboAddress& localAddr, const ComboAddress& peer)
{
  auto quicheConfig = std::atomic_load_explicit(&config.config, std::memory_order_acquire);
  auto quicheConn = QuicheConnection(quiche_accept(serverSideID.data(), serverSideID.size(),
                                                   originalDestinationID.data(), originalDestinationID.size(),
                                                   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                                   reinterpret_cast<const struct sockaddr*>(&localAddr),
                                                   localAddr.getSocklen(),
                                                   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                                                   reinterpret_cast<const struct sockaddr*>(&peer),
                                                   peer.getSocklen(),
                                                   quicheConfig.get()),
                                     quiche_conn_free);

  if (config.df && !config.df->d_quicheParams.d_keyLogFile.empty()) {
    quiche_conn_set_keylog_path(quicheConn.get(), config.df->d_quicheParams.d_keyLogFile.c_str());
  }

  auto conn = H3Connection(peer, localAddr, std::move(quicheConfig), std::move(quicheConn));
  auto pair = config.d_connections.emplace(serverSideID, std::move(conn));
  return pair.first->second;
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

static void processDOH3Query(DOH3UnitUniquePtr&& doh3Unit)
{
  const auto handleImmediateResponse = [](DOH3UnitUniquePtr&& unit, [[maybe_unused]] const char* reason) {
    DEBUGLOG("handleImmediateResponse() reason=" << reason);
    auto conn = getConnection(unit->dsc->df->d_server_config->d_connections, unit->serverConnID);
    handleResponse(*unit->dsc->df, *conn, unit->streamID, unit->status_code, unit->response, unit->d_contentTypeOut);
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
    ClientState& clientState = *dsc->clientState;

    if (!dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.match(remote)) {
      VERBOSESLOG(infolog("Query from %s (DoH3) dropped because of ACL", remote.toStringWithPort()),
                  dsc->df->getLogger().info("DoH3 query dropped because of ACL", "client.address", Logging::Loggable(remote)));
      ++dnsdist::metrics::g_stats.aclDrops;
      unit->response.clear();

      unit->status_code = 403;
      handleImmediateResponse(std::move(unit), "DoH3 query dropped because of ACL");
      return;
    }

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

      if (!checkQueryHeaders(*dnsHeader, clientState)) {
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
    if (unit->sni) {
      dnsQuestion.sni = *unit->sni;
    }
    unit->ids.cs = &clientState;

    auto result = processQuery(dnsQuestion, downstream);
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

        handleResponseSent(unit->ids.qname, QType(unit->ids.qtype), 0, unit->ids.origRemote, ComboAddress(), unit->response.size(), *dnsHeader, dnsdist::Protocol::DoH3, dnsdist::Protocol::DoH3, false);
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
    if (unit) {
      VERBOSESLOG(infolog("Got an error in DOH3 question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what()),
                  unit->dsc->df->getLogger().error(Logr::Info, e.what(), "Got an error in DoH3 question thread while parsing a query", "client.address", Logging::Loggable(remote), "dns.question.id", Logging::Loggable(queryId)));
      unit->status_code = 500;
      handleImmediateResponse(std::move(unit), "DoH3 internal error");
    }
    return;
  }
}

static void doh3_dispatch_query(DOH3ServerConfig& dsc, PacketBuffer&& query, const ComboAddress& local, const ComboAddress& remote, const PacketBuffer& serverConnID, const uint64_t streamID, const std::shared_ptr<const std::string>& sni, dnsdist::doh3::h3_headers_t&& headers)
{
  try {
    auto unit = std::make_unique<DOH3Unit>(std::move(query));
    unit->dsc = &dsc;
    unit->ids.origDest = local;
    unit->ids.origRemote = remote;
    unit->ids.protocol = dnsdist::Protocol::DoH3;
    unit->serverConnID = serverConnID;
    unit->streamID = streamID;
    unit->sni = sni;
    unit->headers = std::move(headers);

    processDOH3Query(std::move(unit));
  }
  catch (const std::exception& exp) {
    VERBOSESLOG(infolog("Had error handling DoH3 DNS packet from %s: %s", remote.toStringWithPort(), exp.what()),
                dsc.df->getLogger().error(Logr::Info, exp.what(), "Had error handling DoH3 DNS packet", "client.address", Logging::Loggable(remote)));
  }
}

static void flushResponses(pdns::channel::Receiver<DOH3Unit>& receiver, const Logr::Logger& frontendLogger)
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
        handleResponse(*unit->dsc->df, *conn, unit->streamID, unit->status_code, unit->response, unit->d_contentTypeOut);
      }
    }
    catch (const std::exception& e) {
      SLOG(errlog("Error while processing response received over DoH3: %s", e.what()),
           frontendLogger.error(e.what(), "Error while processing response received over DoH3"));
    }
    catch (...) {
      SLOG(errlog("Unspecified error while processing response received over DoH3"),
           frontendLogger.info(Logr::Error, "Unspecified error while processing response received over DoH3"));
    }
  }
}

static void flushStalledResponses(H3Connection& conn)
{
  for (auto streamIt = conn.d_streamOutBuffers.begin(); streamIt != conn.d_streamOutBuffers.end();) {
    const auto streamID = streamIt->first;
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

static void processH3HeaderEvent(ClientState& clientState, DOH3Frontend& frontend, H3Connection& conn, const ComboAddress& client, const PacketBuffer& serverConnID, const uint64_t streamID, quiche_h3_event* event)
{
  auto handleImmediateError = [&clientState, &frontend, &conn, streamID](const char* msg) {
    DEBUGLOG(msg);
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    ++clientState.nonCompliantQueries;
    ++frontend.d_errorResponses;
    h3_send_response(conn, streamID, 400, msg);
  };

  auto& headers = conn.d_headersBuffers.at(streamID);
  // Callback result. Any value other than 0 will interrupt further header processing.
  int cbresult = quiche_h3_event_for_each_header(
    event,
    [](uint8_t* name, size_t name_len, uint8_t* value, size_t value_len, void* argp) -> int {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): Quiche API
      std::string_view key(reinterpret_cast<char*>(name), name_len);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): Quiche API
      std::string_view content(reinterpret_cast<char*>(value), value_len);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): Quiche API
      auto* headersptr = reinterpret_cast<dnsdist::doh3::h3_headers_t*>(argp);
      headersptr->emplace(key, content);
      return 0;
    },
    &headers);

#ifdef DEBUGLOG_ENABLED
  DEBUGLOG("Processed headers of stream " << streamID);
  for (const auto& [key, value] : headers) {
    DEBUGLOG(" " << key << ": " << value);
  }
#endif
  if (cbresult != 0 || headers.count(":method") == 0) {
    handleImmediateError("Unable to process query headers");
    return;
  }

  if (headers.at(":method") == "GET") {
    if (headers.count(":path") == 0 || headers.at(":path").empty()) {
      handleImmediateError("Path not found");
      return;
    }
    const auto& path = headers.at(":path");
    auto payload = dnsdist::doh::getPayloadFromPath(path);
    if (!payload) {
      handleImmediateError("Unable to find the DNS parameter");
      return;
    }
    if (payload->size() < sizeof(dnsheader)) {
      handleImmediateError("DoH3 non-compliant query");
      return;
    }
    DEBUGLOG("Dispatching GET query");
    doh3_dispatch_query(*(frontend.d_server_config), std::move(*payload), conn.d_localAddr, client, serverConnID, streamID, conn.getSNI(), std::move(headers));
    conn.d_streamBuffers.erase(streamID);
    conn.d_headersBuffers.erase(streamID);
    return;
  }

  if (headers.at(":method") == "POST") {
#if defined(HAVE_QUICHE_H3_EVENT_HEADERS_HAS_MORE_FRAMES)
    if (!quiche_h3_event_headers_has_more_frames(event)) {
#else
    if (!quiche_h3_event_headers_has_body(event)) {
#endif
      handleImmediateError("Empty POST query");
    }
    return;
  }

  handleImmediateError("Unsupported HTTP method");
}

static void processH3DataEvent(ClientState& clientState, DOH3Frontend& frontend, H3Connection& conn, const ComboAddress& client, const PacketBuffer& serverConnID, const uint64_t streamID, PacketBuffer& buffer)
{
  auto handleImmediateError = [&clientState, &frontend, &conn, streamID](const char* msg) {
    DEBUGLOG(msg);
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    ++clientState.nonCompliantQueries;
    ++frontend.d_errorResponses;
    h3_send_response(conn, streamID, 400, msg);
  };
  auto& headers = conn.d_headersBuffers.at(streamID);

  if (headers.at(":method") != "POST") {
    handleImmediateError("DATA frame for non-POST method");
    return;
  }

  if (headers.count("content-type") == 0 || headers.at("content-type") != "application/dns-message") {
    handleImmediateError("Unsupported content-type");
    return;
  }

  buffer.resize(std::numeric_limits<uint16_t>::max());
  auto& streamBuffer = conn.d_streamBuffers[streamID];

  while (true) {
    buffer.resize(std::numeric_limits<uint16_t>::max());
    ssize_t len = quiche_h3_recv_body(conn.d_http3.get(),
                                      conn.d_conn.get(), streamID,
                                      buffer.data(), buffer.size());

    if (len <= 0) {
      break;
    }

    buffer.resize(static_cast<size_t>(len));
    streamBuffer.insert(streamBuffer.end(), buffer.begin(), buffer.end());
  }

  if (!quiche_conn_stream_finished(conn.d_conn.get(), streamID)) {
    return;
  }

  if (streamBuffer.size() < sizeof(dnsheader)) {
    conn.d_streamBuffers.erase(streamID);
    handleImmediateError("DoH3 non-compliant query");
    return;
  }

  DEBUGLOG("Dispatching POST query");
  doh3_dispatch_query(*(frontend.d_server_config), std::move(streamBuffer), conn.d_localAddr, client, serverConnID, streamID, conn.getSNI(), std::move(headers));
  conn.d_headersBuffers.erase(streamID);
  conn.d_streamBuffers.erase(streamID);
}

static void processH3Events(ClientState& clientState, DOH3Frontend& frontend, H3Connection& conn, const ComboAddress& client, const PacketBuffer& serverConnID, PacketBuffer& buffer)
{
  while (true) {
    quiche_h3_event* event{nullptr};
    // Processes HTTP/3 data received from the peer
    const int64_t streamID = quiche_h3_conn_poll(conn.d_http3.get(),
                                                 conn.d_conn.get(),
                                                 &event);

    if (streamID < 0) {
      break;
    }
    conn.d_headersBuffers.try_emplace(streamID, dnsdist::doh3::h3_headers_t{});

    switch (quiche_h3_event_type(event)) {
    case QUICHE_H3_EVENT_HEADERS: {
      processH3HeaderEvent(clientState, frontend, conn, client, serverConnID, streamID, event);
      break;
    }
    case QUICHE_H3_EVENT_DATA: {
      processH3DataEvent(clientState, frontend, conn, client, serverConnID, streamID, buffer);
      break;
    }
    case QUICHE_H3_EVENT_FINISHED:
    case QUICHE_H3_EVENT_RESET:
    case QUICHE_H3_EVENT_PRIORITY_UPDATE:
    case QUICHE_H3_EVENT_GOAWAY:
      break;
    }

    quiche_h3_event_free(event);
  }
}

static void handleSocketReadable(DOH3Frontend& frontend, ClientState& clientState, Socket& sock, PacketBuffer& buffer)
{
  // destination connection ID, will have to be sent as original destination connection ID
  PacketBuffer serverConnID;
  // source connection ID, will have to be sent as destination connection ID
  PacketBuffer clientConnID;
  PacketBuffer tokenBuf;
  while (true) {
    ComboAddress client;
    ComboAddress localAddr;
    client.sin4.sin_family = clientState.local.sin4.sin_family;
    localAddr.sin4.sin_family = clientState.local.sin4.sin_family;
    buffer.resize(4096);
    if (!dnsdist::doq::recvAsync(sock, buffer, client, localAddr)) {
      return;
    }
    if (localAddr.sin4.sin_family == 0) {
      localAddr = clientState.local;
    }
    else {
      /* we don't get the port, only the address */
      localAddr.sin4.sin_port = clientState.local.sin4.sin_port;
    }

    DEBUGLOG("Received DoH3 datagram of size " << buffer.size() << " from " << client.toStringWithPort());

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
    // source connection ID, will have to be sent as destination connection ID
    clientConnID.assign(scid.begin(), scid.begin() + scid_len);
    auto conn = getConnection(frontend.d_server_config->d_connections, serverConnID);

    if (!conn) {
      DEBUGLOG("Connection not found");
      if (type != static_cast<uint8_t>(DOQ_Packet_Types::QUIC_PACKET_TYPE_INITIAL)) {
        DEBUGLOG("Packet is not initial");
        continue;
      }

      if (!quiche_version_is_supported(version)) {
        DEBUGLOG("Unsupported version");
        ++frontend.d_doh3UnsupportedVersionErrors;
        handleVersionNegotiation(sock, clientConnID, serverConnID, client, localAddr, buffer, clientState.local.isUnspecified());
        continue;
      }

      if (token_len == 0) {
        /* stateless retry */
        DEBUGLOG("No token received");
        handleStatelessRetry(sock, clientConnID, serverConnID, client, localAddr, version, buffer, clientState.local.isUnspecified());
        continue;
      }

      tokenBuf.assign(token.begin(), token.begin() + token_len);
      auto originalDestinationID = validateToken(tokenBuf, client);
      if (!originalDestinationID) {
        ++frontend.d_doh3InvalidTokensReceived;
        DEBUGLOG("Discarding invalid token");
        continue;
      }

      DEBUGLOG("Creating a new connection");
      conn = createConnection(*frontend.d_server_config, serverConnID, *originalDestinationID, localAddr, client);
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
      reinterpret_cast<struct sockaddr*>(&localAddr),
      localAddr.getSocklen(),
    };

    auto done = quiche_conn_recv(conn->get().d_conn.get(), buffer.data(), buffer.size(), &recv_info);
    if (done < 0) {
      continue;
    }

    if (quiche_conn_is_established(conn->get().d_conn.get()) || quiche_conn_is_in_early_data(conn->get().d_conn.get())) {
      DEBUGLOG("Connection is established");

      if (!conn->get().d_http3) {
        conn->get().d_http3 = QuicheHTTP3Connection(quiche_h3_conn_new_with_transport(conn->get().d_conn.get(), frontend.d_server_config->http3config.get()),
                                                    quiche_h3_conn_free);
        if (!conn->get().d_http3) {
          continue;
        }
        DEBUGLOG("Successfully created HTTP/3 connection");
      }

      processH3Events(clientState, frontend, conn->get(), client, serverConnID, buffer);

      flushEgress(sock, conn->get().d_conn, client, localAddr, buffer, clientState.local.isUnspecified());
    }
    else {
      DEBUGLOG("Connection not established");
    }
  }
}

// this is the entrypoint from dnsdist.cc
void doh3Thread(ClientState* clientState)
{
  try {
    std::shared_ptr<DOH3Frontend>& frontend = clientState->doh3Frontend;
    auto frontendLogger = dnsdist::logging::getTopLogger()->withName("doh3-frontend")->withValues("frontend.address", Logging::Loggable(clientState->local));

    frontend->d_server_config->clientState = clientState;
    frontend->d_server_config->df = clientState->doh3Frontend;
    frontend->d_logger = frontendLogger;

    setThreadName("dnsdist/doh3");

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

      dnsdist::configuration::refreshLocalRuntimeConfiguration();

      try {
        if (std::find(readyFDs.begin(), readyFDs.end(), sock.getHandle()) != readyFDs.end()) {
          handleSocketReadable(*frontend, *clientState, sock, buffer);
        }

        if (std::find(readyFDs.begin(), readyFDs.end(), responseReceiverFD) != readyFDs.end()) {
          flushResponses(frontend->d_server_config->d_responseReceiver, *frontendLogger);
        }

        for (auto conn = frontend->d_server_config->d_connections.begin(); conn != frontend->d_server_config->d_connections.end();) {
          quiche_conn_on_timeout(conn->second.d_conn.get());

          flushEgress(sock, conn->second.d_conn, conn->second.d_peer, conn->second.d_localAddr, buffer, clientState->local.isUnspecified());

          if (quiche_conn_is_closed(conn->second.d_conn.get())) {
#ifdef DEBUGLOG_ENABLED
            quiche_stats stats;
            quiche_path_stats path_stats;

            quiche_conn_stats(conn->second.d_conn.get(), &stats);
            quiche_conn_path_stats(conn->second.d_conn.get(), 0, &path_stats);

            DEBUGLOG("Connection (DoH3) closed, recv=" << stats.recv << " sent=" << stats.sent << " lost=" << stats.lost << " rtt=" << path_stats.rtt << "ns cwnd=" << path_stats.cwnd);
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
        VERBOSESLOG(infolog("Caught exception in the main DoH3 thread: %s", exp.what()),
                    frontendLogger->error(Logr::Info, exp.what(), "Caught exception in the main DoH3 thread"));
      }
      catch (...) {
        VERBOSESLOG(infolog("Unknown exception in the main DoH3 thread"),
                    frontendLogger->info(Logr::Info, "Caught unknown exception in the main DoH3 thread"));
      }
    }
  }
  catch (const std::exception& e) {
    DEBUGLOG("Caught fatal error in the main DoH3 thread: " << e.what());
  }
}

std::string DOH3Unit::getHTTPPath() const
{
  const auto& path = headers.at(":path");
  auto pos = path.find('?');
  if (pos == string::npos) {
    return path;
  }
  return path.substr(0, pos);
}

std::string DOH3Unit::getHTTPQueryString() const
{
  const auto& path = headers.at(":path");
  auto pos = path.find('?');
  if (pos == string::npos) {
    return {};
  }

  return path.substr(pos);
}

std::string DOH3Unit::getHTTPHost() const
{
  const auto& host = headers.find(":authority");
  if (host == headers.end()) {
    return {};
  }
  return host->second;
}

std::string DOH3Unit::getHTTPScheme() const
{
  const auto& scheme = headers.find(":scheme");
  if (scheme == headers.end()) {
    return {};
  }
  return scheme->second;
}

const dnsdist::doh3::h3_headers_t& DOH3Unit::getHTTPHeaders() const
{
  return headers;
}

void DOH3Unit::setHTTPResponse(uint16_t statusCode, PacketBuffer&& body, const std::string& contentType)
{
  status_code = statusCode;
  response = std::move(body);
  d_contentTypeOut = contentType;
}

#else /* HAVE_DNS_OVER_HTTP3 */

std::string DOH3Unit::getHTTPPath() const
{
  return {};
}

std::string DOH3Unit::getHTTPQueryString() const
{
  return {};
}

std::string DOH3Unit::getHTTPHost() const
{
  return {};
}

std::string DOH3Unit::getHTTPScheme() const
{
  return {};
}

const dnsdist::doh3::h3_headers_t& DOH3Unit::getHTTPHeaders() const
{
  static const dnsdist::doh3::h3_headers_t headers;
  return headers;
}

void DOH3Unit::setHTTPResponse(uint16_t, PacketBuffer&&, const std::string&)
{
}

#endif /* HAVE_DNS_OVER_HTTP3 */
