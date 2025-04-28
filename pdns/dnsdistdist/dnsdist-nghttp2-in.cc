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
#include "dnsdist-nghttp2-in.hh"

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)

#include "dnsdist-dnsparser.hh"
#include "dnsdist-doh-common.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsparser.hh"

#if 0
class IncomingDoHCrossProtocolContext : public CrossProtocolContext
{
public:
  IncomingDoHCrossProtocolContext(IncomingHTTP2Connection::PendingQuery&& query, std::shared_ptr<IncomingHTTP2Connection> connection, IncomingHTTP2Connection::StreamID streamID): CrossProtocolContext(std::move(query.d_buffer)), d_connection(connection), d_query(std::move(query))
  {
  }

  std::optional<std::string> getHTTPPath() const override
  {
    return d_query.d_path;
  }

  std::optional<std::string> getHTTPScheme() const override
  {
    return d_query.d_scheme;
  }

  std::optional<std::string> getHTTPHost() const override
  {
    return d_query.d_host;
  }

  std::optional<std::string> getHTTPQueryString() const override
  {
    return d_query.d_queryString;
  }

  std::optional<HeadersMap> getHTTPHeaders() const override
  {
    if (!d_query.d_headers) {
      return std::nullopt;
    }
    return *d_query.d_headers;
  }

  void handleResponse(PacketBuffer&& response, InternalQueryState&& state) override
  {
    auto conn = d_connection.lock();
    if (!conn) {
      /* the connection has been closed in the meantime */
      return;
    }
  }

  void handleTimeout() override
  {
    auto conn = d_connection.lock();
    if (!conn) {
      /* the connection has been closed in the meantime */
      return;
    }
  }

  ~IncomingDoHCrossProtocolContext() override
  {
  }

private:
  std::weak_ptr<IncomingHTTP2Connection> d_connection;
  IncomingHTTP2Connection::PendingQuery d_query;
  IncomingHTTP2Connection::StreamID d_streamID{-1};
};
#endif

class IncomingDoHCrossProtocolContext : public DOHUnitInterface
{
public:
  IncomingDoHCrossProtocolContext(IncomingHTTP2Connection::PendingQuery&& query, const std::shared_ptr<IncomingHTTP2Connection>& connection, IncomingHTTP2Connection::StreamID streamID) :
    d_connection(connection), d_query(std::move(query)), d_streamID(streamID)
  {
  }
  IncomingDoHCrossProtocolContext(const IncomingDoHCrossProtocolContext&) = delete;
  IncomingDoHCrossProtocolContext(IncomingDoHCrossProtocolContext&&) = delete;
  IncomingDoHCrossProtocolContext& operator=(const IncomingDoHCrossProtocolContext&) = delete;
  IncomingDoHCrossProtocolContext& operator=(IncomingDoHCrossProtocolContext&&) = delete;

  ~IncomingDoHCrossProtocolContext() override = default;

  [[nodiscard]] std::string getHTTPPath() const override
  {
    return d_query.d_path;
  }

  [[nodiscard]] const std::string& getHTTPScheme() const override
  {
    return d_query.d_scheme;
  }

  [[nodiscard]] const std::string& getHTTPHost() const override
  {
    return d_query.d_host;
  }

  [[nodiscard]] std::string getHTTPQueryString() const override
  {
    return d_query.d_queryString;
  }

  [[nodiscard]] const HeadersMap& getHTTPHeaders() const override
  {
    if (!d_query.d_headers) {
      static const HeadersMap empty{};
      return empty;
    }
    return *d_query.d_headers;
  }

  [[nodiscard]] std::shared_ptr<TCPQuerySender> getQuerySender() const override
  {
    return std::dynamic_pointer_cast<TCPQuerySender>(d_connection.lock());
  }

  void setHTTPResponse(uint16_t statusCode, PacketBuffer&& body, const std::string& contentType = "") override
  {
    d_query.d_statusCode = statusCode;
    d_query.d_response = std::move(body);
    d_query.d_contentTypeOut = contentType;
  }

  void handleUDPResponse(PacketBuffer&& response, InternalQueryState&& state, const std::shared_ptr<DownstreamState>& downstream_) override
  {
    std::unique_ptr<DOHUnitInterface> unit(this);
    auto conn = d_connection.lock();
    if (!conn) {
      /* the connection has been closed in the meantime */
      return;
    }

    state.du = std::move(unit);
    TCPResponse resp(std::move(response), std::move(state), nullptr, nullptr);
    resp.d_ds = downstream_;
    struct timeval now{};
    gettimeofday(&now, nullptr);
    conn->handleResponse(now, std::move(resp));
  }

  void handleTimeout() override
  {
    std::unique_ptr<DOHUnitInterface> unit(this);
    auto conn = d_connection.lock();
    if (!conn) {
      /* the connection has been closed in the meantime */
      return;
    }
    struct timeval now{};
    gettimeofday(&now, nullptr);
    TCPResponse resp;
    resp.d_idstate.d_streamID = d_streamID;
    conn->notifyIOError(now, std::move(resp));
  }

  std::weak_ptr<IncomingHTTP2Connection> d_connection;
  IncomingHTTP2Connection::PendingQuery d_query;
  IncomingHTTP2Connection::StreamID d_streamID{-1};
};

void IncomingHTTP2Connection::handleResponse(const struct timeval& now, TCPResponse&& response)
{
  if (std::this_thread::get_id() != d_creatorThreadID) {
    handleCrossProtocolResponse(now, std::move(response));
    return;
  }

  auto& state = response.d_idstate;
  if (state.forwardedOverUDP) {
    dnsheader_aligned responseDH(response.d_buffer.data());

    if (responseDH.get()->tc && state.d_packet && state.d_packet->size() > state.d_proxyProtocolPayloadSize && state.d_packet->size() - state.d_proxyProtocolPayloadSize > sizeof(dnsheader)) {
      vinfolog("Response received from backend %s via UDP, for query %d received from %s via DoH, is truncated, retrying over TCP", response.d_ds->getNameWithAddr(), state.d_streamID, state.origRemote.toStringWithPort());
      auto& query = *state.d_packet;
      dnsdist::PacketMangling::editDNSHeaderFromRawPacket(&query.at(state.d_proxyProtocolPayloadSize), [origID = state.origID](dnsheader& header) {
        /* restoring the original ID */
        header.id = origID;
        return true;
      });

      state.forwardedOverUDP = false;
      bool proxyProtocolPayloadAdded = state.d_proxyProtocolPayloadSize > 0;
      auto cpq = getCrossProtocolQuery(std::move(query), std::move(state), response.d_ds);
      /* 'd_packet' buffer moved by InternalQuery constructor, need re-association */
      cpq->query.d_idstate.d_packet = std::make_unique<PacketBuffer>(cpq->query.d_buffer);
      cpq->query.d_proxyProtocolPayloadAdded = proxyProtocolPayloadAdded;
      if (g_tcpclientthreads && g_tcpclientthreads->passCrossProtocolQueryToThread(std::move(cpq))) {
        return;
      }
      vinfolog("Unable to pass DoH query to a TCP worker thread after getting a TC response over UDP");
      notifyIOError(now, std::move(response));
      return;
    }
  }

  IncomingTCPConnectionState::handleResponse(now, std::move(response));
}

std::unique_ptr<DOHUnitInterface> IncomingHTTP2Connection::getDOHUnit(uint32_t streamID)
{
  if (streamID > std::numeric_limits<IncomingHTTP2Connection::StreamID>::max()) {
    throw std::runtime_error("Invalid stream ID while retrieving DoH unit");
  }

  // NOLINTNEXTLINE(*-narrowing-conversions): generic interface between DNS and DoH with different types
  auto query = std::move(d_currentStreams.at(static_cast<IncomingHTTP2Connection::StreamID>(streamID)));
  return std::make_unique<IncomingDoHCrossProtocolContext>(std::move(query), std::dynamic_pointer_cast<IncomingHTTP2Connection>(shared_from_this()), streamID);
}

void IncomingHTTP2Connection::restoreDOHUnit(std::unique_ptr<DOHUnitInterface>&& unit)
{
  auto context = std::unique_ptr<IncomingDoHCrossProtocolContext>(dynamic_cast<IncomingDoHCrossProtocolContext*>(unit.release()));
  if (context) {
    d_currentStreams.at(context->d_streamID) = std::move(context->d_query);
  }
}

IncomingHTTP2Connection::IncomingHTTP2Connection(ConnectionInfo&& connectionInfo, TCPClientThreadData& threadData, const struct timeval& now) :
  IncomingTCPConnectionState(std::move(connectionInfo), threadData, now)
{
  nghttp2_session_callbacks* cbs = nullptr;
  if (nghttp2_session_callbacks_new(&cbs) != 0) {
    throw std::runtime_error("Unable to create a callback object for a new incoming HTTP/2 session");
  }
  std::unique_ptr<nghttp2_session_callbacks, void (*)(nghttp2_session_callbacks*)> callbacks(cbs, nghttp2_session_callbacks_del);
  cbs = nullptr;

  nghttp2_session_callbacks_set_send_callback(callbacks.get(), send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), on_stream_close_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks.get(), on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks.get(), on_header_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_error_callback2(callbacks.get(), on_error_callback);

  nghttp2_session* sess = nullptr;
  if (nghttp2_session_server_new(&sess, callbacks.get(), this) != 0) {
    throw std::runtime_error("Coult not allocate a new incoming HTTP/2 session");
  }

  d_session = std::unique_ptr<nghttp2_session, decltype(&nghttp2_session_del)>(sess, nghttp2_session_del);
  sess = nullptr;
}

bool IncomingHTTP2Connection::checkALPN()
{
  constexpr std::array<uint8_t, 2> h2ALPN{'h', '2'};
  const auto protocols = d_handler.getNextProtocol();
  if (protocols.size() == h2ALPN.size() && memcmp(protocols.data(), h2ALPN.data(), h2ALPN.size()) == 0) {
    return true;
  }

  constexpr std::array<uint8_t, 8> http11ALPN{'h', 't', 't', 'p', '/', '1', '.', '1'};
  if (protocols.size() == http11ALPN.size() && memcmp(protocols.data(), http11ALPN.data(), http11ALPN.size()) == 0) {
    ++d_ci.cs->dohFrontend->d_http1Stats.d_nbQueries;
  }

  const std::string data("HTTP/1.1 400 Bad Request\r\nConnection: Close\r\n\r\n<html><body>This server implements RFC 8484 - DNS Queries over HTTP, and requires HTTP/2 in accordance with section 5.2 of the RFC.</body></html>\r\n");
  d_out.insert(d_out.end(), data.begin(), data.end());
  writeToSocket(false);

  vinfolog("DoH connection from %s expected ALPN value 'h2', got '%s'", d_ci.remote.toStringWithPort(), std::string(protocols.begin(), protocols.end()));
  return false;
}

void IncomingHTTP2Connection::handleConnectionReady()
{
  constexpr std::array<nghttp2_settings_entry, 1> settings{{{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100U}}};
  constexpr std::array<nghttp2_settings_entry, 1> nearLimitsSettings{{{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1U}}};
  auto ret = nghttp2_submit_settings(d_session.get(), NGHTTP2_FLAG_NONE, isNearTCPLimits() ? nearLimitsSettings.data() : settings.data(), isNearTCPLimits() ? nearLimitsSettings.size() : settings.size());
  if (ret != 0) {
    throw std::runtime_error("Fatal error: " + std::string(nghttp2_strerror(ret)));
  }
  d_needFlush = true;
  ret = nghttp2_session_send(d_session.get());
  if (ret != 0) {
    throw std::runtime_error("Fatal error: " + std::string(nghttp2_strerror(ret)));
  }
}

bool IncomingHTTP2Connection::hasPendingWrite() const
{
  return d_pendingWrite;
}

IOState IncomingHTTP2Connection::handleHandshake(const struct timeval& now)
{
  auto iostate = d_handler.tryHandshake();
  if (iostate == IOState::Done) {
    handleHandshakeDone(now);
    if (d_handler.isTLS()) {
      if (!checkALPN()) {
        d_connectionDied = true;
        stopIO();
        return iostate;
      }
    }

    if (d_ci.cs != nullptr && d_ci.cs->d_enableProxyProtocol && !isProxyPayloadOutsideTLS() && expectProxyProtocolFrom(d_ci.remote)) {
      d_state = State::readingProxyProtocolHeader;
      d_buffer.resize(s_proxyProtocolMinimumHeaderSize);
      d_proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
    }
    else {
      d_state = State::waitingForQuery;
      handleConnectionReady();
    }
  }
  return iostate;
}

class ReadFunctionGuard
{
public:
  ReadFunctionGuard(bool& inReadFunction) :
    d_inReadFunctionRef(inReadFunction)
  {
    d_inReadFunctionRef = true;
  }
  ReadFunctionGuard(ReadFunctionGuard&&) = delete;
  ReadFunctionGuard(const ReadFunctionGuard&) = delete;
  ReadFunctionGuard& operator=(ReadFunctionGuard&&) = delete;
  ReadFunctionGuard& operator=(const ReadFunctionGuard&) = delete;
  ~ReadFunctionGuard()
  {
    d_inReadFunctionRef = false;
  }

private:
  bool& d_inReadFunctionRef;
};

void IncomingHTTP2Connection::handleIO()
{
  IOState iostate = IOState::Done;
  struct timeval now{};
  gettimeofday(&now, nullptr);

  try {
    if (maxConnectionDurationReached(dnsdist::configuration::getCurrentRuntimeConfiguration().d_maxTCPConnectionDuration, now)) {
      vinfolog("Terminating DoH connection from %s because it reached the maximum TCP connection duration", d_ci.remote.toStringWithPort());
      stopIO();
      d_connectionClosing = true;
      return;
    }

    if (d_state == State::starting) {
      if (d_ci.cs != nullptr && d_ci.cs->dohFrontend != nullptr) {
        ++d_ci.cs->dohFrontend->d_httpconnects;
      }
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
      if (d_connectionDied) {
        return;
      }
    }

    if (d_state == State::readingProxyProtocolHeader) {
      auto status = handleProxyProtocolPayload();
      if (status == ProxyProtocolResult::Done) {
        if (isProxyPayloadOutsideTLS()) {
          d_state = State::doingHandshake;
          iostate = handleHandshake(now);
          if (d_connectionDied) {
            return;
          }
        }
        else {
          d_state = State::waitingForQuery;
          handleConnectionReady();
        }
      }
      else if (status == ProxyProtocolResult::Error) {
        d_connectionDied = true;
        stopIO();
        return;
      }
    }

    if (!d_inReadFunction && active() && !d_connectionClosing && (d_state == State::waitingForQuery || d_state == State::idle)) {
      do {
        iostate = readHTTPData();
      } while (!d_inReadFunction && active() && !d_connectionClosing && iostate == IOState::Done);
    }

    if (!active()) {
      stopIO();
      return;
    }
    /*
      So:
      - if we have a pending write, we need to wait until the socket becomes writable
        and then call handleWritableCallback
      - if we have NeedWrite but no pending write, we need to wait until the socket
        becomes writable but for handleReadableIOCallback
      - if we have NeedRead, or nghttp2_session_want_read, wait until the socket
        becomes readable and call handleReadableIOCallback
    */
    if (hasPendingWrite()) {
      updateIO(IOState::NeedWrite, handleWritableIOCallback);
    }
    else if (iostate == IOState::NeedWrite) {
      updateIO(IOState::NeedWrite, handleReadableIOCallback);
    }
    else if (!d_connectionClosing) {
      if (nghttp2_session_want_read(d_session.get()) != 0) {
        updateIO(IOState::NeedRead, handleReadableIOCallback);
      }
    }
  }
  catch (const std::exception& e) {
    vinfolog("Exception when processing IO for incoming DoH connection from %s: %s", d_ci.remote.toStringWithPort(), e.what());
    d_connectionDied = true;
    stopIO();
  }
}

void IncomingHTTP2Connection::writeToSocket(bool socketReady)
{
  try {
    d_needFlush = false;
    IOState newState = d_handler.tryWrite(d_out, d_outPos, d_out.size());

    if (newState == IOState::Done) {
      d_pendingWrite = false;
      d_out.clear();
      d_outPos = 0;
      if (active() && !d_connectionClosing) {
        updateIO(IOState::NeedRead, handleReadableIOCallback);
      }
      else {
        stopIO();
      }
    }
    else {
      updateIO(newState, handleWritableIOCallback);
      d_pendingWrite = true;
    }
  }
  catch (const std::exception& e) {
    vinfolog("Exception while trying to write (%s) to HTTP client connection to %s: %s", (socketReady ? "ready" : "send"), d_ci.remote.toStringWithPort(), e.what());
    handleIOError();
  }
}

ssize_t IncomingHTTP2Connection::send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
  (void)session;
  (void)flags;
  auto* conn = static_cast<IncomingHTTP2Connection*>(user_data);
  if (conn->d_connectionDied) {
    return static_cast<ssize_t>(length);
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): nghttp2 API
  conn->d_out.insert(conn->d_out.end(), data, data + length);

  if (conn->d_connectionClosing || conn->d_needFlush) {
    conn->writeToSocket(false);
  }

  return static_cast<ssize_t>(length);
}

static const std::array<const std::string, static_cast<size_t>(NGHTTP2Headers::HeaderConstantIndexes::COUNT)> s_headerConstants{
  "200",
  ":method",
  "POST",
  ":scheme",
  "https",
  ":authority",
  "x-forwarded-for",
  ":path",
  "content-length",
  ":status",
  "location",
  "accept",
  "application/dns-message",
  "cache-control",
  "content-type",
  "application/dns-message",
  "user-agent",
  "nghttp2-" NGHTTP2_VERSION "/dnsdist",
  "x-forwarded-port",
  "x-forwarded-proto",
  "dns-over-udp",
  "dns-over-tcp",
  "dns-over-tls",
  "dns-over-http",
  "dns-over-https"};

static const std::string s_authorityHeaderName(":authority");
static const std::string s_pathHeaderName(":path");
static const std::string s_methodHeaderName(":method");
static const std::string s_schemeHeaderName(":scheme");
static const std::string s_xForwardedForHeaderName("x-forwarded-for");

void NGHTTP2Headers::addStaticHeader(std::vector<nghttp2_nv>& headers, NGHTTP2Headers::HeaderConstantIndexes nameKey, NGHTTP2Headers::HeaderConstantIndexes valueKey)
{
  const auto& name = s_headerConstants.at(static_cast<size_t>(nameKey));
  const auto& value = s_headerConstants.at(static_cast<size_t>(valueKey));

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-pro-type-reinterpret-cast): nghttp2 API
  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.c_str())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

void NGHTTP2Headers::addCustomDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& name, const std::string_view& value)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-pro-type-reinterpret-cast): nghttp2 API
  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.data())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.data())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

void NGHTTP2Headers::addDynamicHeader(std::vector<nghttp2_nv>& headers, NGHTTP2Headers::HeaderConstantIndexes nameKey, const std::string_view& value)
{
  const auto& name = s_headerConstants.at(static_cast<size_t>(nameKey));
  NGHTTP2Headers::addCustomDynamicHeader(headers, name, value);
}

IOState IncomingHTTP2Connection::sendResponse(const struct timeval& now, TCPResponse&& response)
{
  (void)now;
  if (response.d_idstate.d_streamID == -1) {
    throw std::runtime_error("Invalid DoH stream ID while sending response");
  }
  auto streamIt = d_currentStreams.find(response.d_idstate.d_streamID);
  if (streamIt == d_currentStreams.end()) {
    /* it might have been closed by the remote end in the meantime */
    return hasPendingWrite() ? IOState::NeedWrite : IOState::Done;
  }
  auto& context = streamIt->second;

  uint32_t statusCode = 200U;
  std::string contentType;
  bool sendContentType = true;
  auto& responseBuffer = context.d_buffer;
  if (context.d_statusCode != 0) {
    responseBuffer = std::move(context.d_response);
    statusCode = context.d_statusCode;
    contentType = std::move(context.d_contentTypeOut);
  }
  else {
    responseBuffer = std::move(response.d_buffer);
  }

  auto sent = responseBuffer.size();
  sendResponse(response.d_idstate.d_streamID, context, statusCode, d_ci.cs->dohFrontend->d_customResponseHeaders, contentType, sendContentType);
  handleResponseSent(response, sent);

  return hasPendingWrite() ? IOState::NeedWrite : IOState::Done;
}

void IncomingHTTP2Connection::notifyIOError(const struct timeval& now, TCPResponse&& response)
{
  if (std::this_thread::get_id() != d_creatorThreadID) {
    /* empty buffer will signal an IO error */
    response.d_buffer.clear();
    handleCrossProtocolResponse(now, std::move(response));
    return;
  }

  if (response.d_idstate.d_streamID == -1) {
    throw std::runtime_error("Invalid DoH stream ID while handling I/O error notification");
  }

  auto streamIt = d_currentStreams.find(response.d_idstate.d_streamID);
  if (streamIt == d_currentStreams.end()) {
    /* it might have been closed by the remote end in the meantime */
    return;
  }
  auto& context = streamIt->second;
  context.d_buffer = std::move(response.d_buffer);
  sendResponse(response.d_idstate.d_streamID, context, 502, d_ci.cs->dohFrontend->d_customResponseHeaders);
}

bool IncomingHTTP2Connection::sendResponse(IncomingHTTP2Connection::StreamID streamID, IncomingHTTP2Connection::PendingQuery& context, uint16_t responseCode, const HeadersMap& customResponseHeaders, const std::string& contentType, bool addContentType)
{
  /* if data_prd is not NULL, it provides data which will be sent in subsequent DATA frames. In this case, a method that allows request message bodies (https://tools.ietf.org/html/rfc7231#section-4) must be specified with :method key (e.g. POST). This function does not take ownership of the data_prd. The function copies the members of the data_prd. If data_prd is NULL, HEADERS have END_STREAM set.
   */
  nghttp2_data_provider data_provider;

  data_provider.source.ptr = this;
  data_provider.read_callback = [](nghttp2_session*, IncomingHTTP2Connection::StreamID stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* cb_data) -> ssize_t {
    (void)source;
    auto* connection = static_cast<IncomingHTTP2Connection*>(cb_data);
    auto& obj = connection->d_currentStreams.at(stream_id);
    size_t toCopy = 0;
    if (obj.d_queryPos < obj.d_buffer.size()) {
      size_t remaining = obj.d_buffer.size() - obj.d_queryPos;
      toCopy = length > remaining ? remaining : length;
      memcpy(buf, &obj.d_buffer.at(obj.d_queryPos), toCopy);
      obj.d_queryPos += toCopy;
    }

    if (obj.d_queryPos >= obj.d_buffer.size()) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      obj.d_buffer.clear();
      connection->d_needFlush = true;
    }
    return static_cast<ssize_t>(toCopy);
  };

  const auto& dohFrontend = d_ci.cs->dohFrontend;
  auto& responseBody = context.d_buffer;

  std::vector<nghttp2_nv> headers;
  std::string responseCodeStr;
  std::string cacheControlValue;
  std::string location;
  /* remember that dynamic header values should be kept alive
     until we have called nghttp2_submit_response(), at least */
  /* status, content-type, cache-control, content-length */
  headers.reserve(4);

  if (responseCode == 200) {
    NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::STATUS_NAME, NGHTTP2Headers::HeaderConstantIndexes::OK_200_VALUE);
    ++dohFrontend->d_validresponses;
    ++dohFrontend->d_http2Stats.d_nb200Responses;

    if (addContentType) {
      if (contentType.empty()) {
        NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_VALUE);
      }
      else {
        NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, contentType);
      }
    }

    if (dohFrontend->d_sendCacheControlHeaders && responseBody.size() > sizeof(dnsheader)) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): API
      uint32_t minTTL = getDNSPacketMinTTL(reinterpret_cast<const char*>(responseBody.data()), responseBody.size());
      if (minTTL != std::numeric_limits<uint32_t>::max()) {
        cacheControlValue = "max-age=" + std::to_string(minTTL);
        NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CACHE_CONTROL_NAME, cacheControlValue);
      }
    }
  }
  else {
    responseCodeStr = std::to_string(responseCode);
    NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::STATUS_NAME, responseCodeStr);

    if (responseCode >= 300 && responseCode < 400) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      location = std::string(reinterpret_cast<const char*>(responseBody.data()), responseBody.size());
      NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, "text/html; charset=utf-8");
      NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::LOCATION_NAME, location);
      static const std::string s_redirectStart{"<!DOCTYPE html><TITLE>Moved</TITLE><P>The document has moved <A HREF=\""};
      static const std::string s_redirectEnd{"\">here</A>"};
      responseBody.reserve(s_redirectStart.size() + responseBody.size() + s_redirectEnd.size());
      responseBody.insert(responseBody.begin(), s_redirectStart.begin(), s_redirectStart.end());
      responseBody.insert(responseBody.end(), s_redirectEnd.begin(), s_redirectEnd.end());
      ++dohFrontend->d_redirectresponses;
    }
    else {
      ++dohFrontend->d_errorresponses;
      switch (responseCode) {
      case 400:
        ++dohFrontend->d_http2Stats.d_nb400Responses;
        break;
      case 403:
        ++dohFrontend->d_http2Stats.d_nb403Responses;
        break;
      case 500:
        ++dohFrontend->d_http2Stats.d_nb500Responses;
        break;
      case 502:
        ++dohFrontend->d_http2Stats.d_nb502Responses;
        break;
      default:
        ++dohFrontend->d_http2Stats.d_nbOtherResponses;
        break;
      }

      if (!responseBody.empty()) {
        NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, "text/plain; charset=utf-8");
      }
      else {
        static const std::string invalid{"invalid DNS query"};
        static const std::string notAllowed{"dns query not allowed"};
        static const std::string noDownstream{"no downstream server available"};
        static const std::string internalServerError{"Internal Server Error"};

        switch (responseCode) {
        case 400:
          responseBody.insert(responseBody.begin(), invalid.begin(), invalid.end());
          break;
        case 403:
          responseBody.insert(responseBody.begin(), notAllowed.begin(), notAllowed.end());
          break;
        case 502:
          responseBody.insert(responseBody.begin(), noDownstream.begin(), noDownstream.end());
          break;
        case 500:
          /* fall-through */
        default:
          responseBody.insert(responseBody.begin(), internalServerError.begin(), internalServerError.end());
          break;
        }
      }
    }
  }

  const std::string contentLength = std::to_string(responseBody.size());
  NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_LENGTH_NAME, contentLength);

  for (const auto& [key, value] : customResponseHeaders) {
    NGHTTP2Headers::addCustomDynamicHeader(headers, key, value);
  }

  auto ret = nghttp2_submit_response(d_session.get(), streamID, headers.data(), headers.size(), &data_provider);
  if (ret != 0) {
    d_currentStreams.erase(streamID);
    vinfolog("Error submitting HTTP response for stream %d: %s", streamID, nghttp2_strerror(ret));
    return false;
  }

  ret = nghttp2_session_send(d_session.get());
  if (ret != 0) {
    d_currentStreams.erase(streamID);
    vinfolog("Error flushing HTTP response for stream %d: %s", streamID, nghttp2_strerror(ret));
    return false;
  }

  return true;
}

static void processForwardedForHeader(const std::unique_ptr<HeadersMap>& headers, ComboAddress& remote)
{
  if (!headers) {
    return;
  }

  auto headerIt = headers->find(s_xForwardedForHeaderName);
  if (headerIt == headers->end()) {
    return;
  }

  std::string_view value = headerIt->second;
  try {
    auto pos = value.rfind(',');
    if (pos != std::string_view::npos) {
      ++pos;
      for (; pos < value.size() && value[pos] == ' '; ++pos) {
      }

      if (pos < value.size()) {
        value = value.substr(pos);
      }
    }
    auto newRemote = ComboAddress(std::string(value));
    remote = newRemote;
  }
  catch (const std::exception& e) {
    vinfolog("Invalid X-Forwarded-For header ('%s') received from %s : %s", std::string(value), remote.toStringWithPort(), e.what());
  }
  catch (const PDNSException& e) {
    vinfolog("Invalid X-Forwarded-For header ('%s') received from %s : %s", std::string(value), remote.toStringWithPort(), e.reason);
  }
}

void IncomingHTTP2Connection::handleIncomingQuery(IncomingHTTP2Connection::PendingQuery&& query, IncomingHTTP2Connection::StreamID streamID)
{
  const auto handleImmediateResponse = [this, &query, streamID](uint16_t code, const std::string& reason, PacketBuffer&& response = PacketBuffer()) {
    if (response.empty()) {
      query.d_buffer.clear();
      query.d_buffer.insert(query.d_buffer.begin(), reason.begin(), reason.end());
    }
    else {
      query.d_buffer = std::move(response);
    }
    vinfolog("Sending an immediate %d response to incoming DoH query: %s", code, reason);
    sendResponse(streamID, query, code, d_ci.cs->dohFrontend->d_customResponseHeaders);
  };

  if (query.d_method == PendingQuery::Method::Unknown || query.d_method == PendingQuery::Method::Unsupported) {
    handleImmediateResponse(400, "DoH query not allowed because of unsupported HTTP method");
    return;
  }

  ++d_ci.cs->dohFrontend->d_http2Stats.d_nbQueries;

  if (d_ci.cs->dohFrontend->d_trustForwardedForHeader) {
    processForwardedForHeader(query.d_headers, d_proxiedRemote);

    /* second ACL lookup based on the updated address */
    if (!dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.match(d_proxiedRemote)) {
      ++dnsdist::metrics::g_stats.aclDrops;
      vinfolog("Query from %s (%s) (DoH) dropped because of ACL", d_ci.remote.toStringWithPort(), d_proxiedRemote.toStringWithPort());
      handleImmediateResponse(403, "DoH query not allowed because of ACL");
      return;
    }

    if (!d_ci.cs->dohFrontend->d_keepIncomingHeaders) {
      query.d_headers.reset();
    }
  }

  if (d_ci.cs->dohFrontend->d_exactPathMatching) {
    if (d_ci.cs->dohFrontend->d_urls.count(query.d_path) == 0) {
      handleImmediateResponse(404, "there is no endpoint configured for this path");
      return;
    }
  }
  else {
    bool found = false;
    for (const auto& path : d_ci.cs->dohFrontend->d_urls) {
      if (boost::starts_with(query.d_path, path)) {
        found = true;
        break;
      }
    }
    if (!found) {
      handleImmediateResponse(404, "there is no endpoint configured for this path");
      return;
    }
  }

  /* the responses map can be updated at runtime, so we need to take a copy of
     the shared pointer, increasing the reference counter */
  auto responsesMap = d_ci.cs->dohFrontend->d_responsesMap;
  if (responsesMap) {
    for (const auto& entry : *responsesMap) {
      if (entry->matches(query.d_path)) {
        const auto& customHeaders = entry->getHeaders();
        query.d_buffer = entry->getContent();
        if (entry->getStatusCode() >= 400 && !query.d_buffer.empty()) {
          // legacy trailing 0 from the h2o era
          query.d_buffer.pop_back();
        }

        sendResponse(streamID, query, entry->getStatusCode(), customHeaders ? *customHeaders : d_ci.cs->dohFrontend->d_customResponseHeaders, std::string(), false);
        return;
      }
    }
  }

  if (query.d_buffer.empty() && query.d_method == PendingQuery::Method::Get && !query.d_queryString.empty()) {
    auto payload = dnsdist::doh::getPayloadFromPath(query.d_queryString);
    if (payload) {
      query.d_buffer = std::move(*payload);
    }
    else {
      ++d_ci.cs->dohFrontend->d_badrequests;
      handleImmediateResponse(400, "DoH unable to decode BASE64-URL");
      return;
    }
  }

  if (query.d_method == PendingQuery::Method::Get) {
    ++d_ci.cs->dohFrontend->d_getqueries;
  }
  else if (query.d_method == PendingQuery::Method::Post) {
    ++d_ci.cs->dohFrontend->d_postqueries;
  }

  try {
    struct timeval now{};
    gettimeofday(&now, nullptr);
    auto processingResult = handleQuery(std::move(query.d_buffer), now, streamID);

    switch (processingResult) {
    case QueryProcessingResult::TooSmall:
      handleImmediateResponse(400, "DoH non-compliant query");
      break;
    case QueryProcessingResult::InvalidHeaders:
      handleImmediateResponse(400, "DoH invalid headers");
      break;
    case QueryProcessingResult::Dropped:
      handleImmediateResponse(403, "DoH dropped query");
      break;
    case QueryProcessingResult::NoBackend:
      handleImmediateResponse(502, "DoH no backend available");
      return;
    case QueryProcessingResult::Forwarded:
    case QueryProcessingResult::Asynchronous:
    case QueryProcessingResult::SelfAnswered:
      break;
    }
  }
  catch (const std::exception& e) {
    vinfolog("Exception while processing DoH query: %s", e.what());
    handleImmediateResponse(400, "DoH non-compliant query");
    return;
  }
}

int IncomingHTTP2Connection::on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
  (void)session;
  auto* conn = static_cast<IncomingHTTP2Connection*>(user_data);
  /* is this the last frame for this stream? */
  if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
    auto streamID = frame->hd.stream_id;
    auto stream = conn->d_currentStreams.find(streamID);
    if (stream != conn->d_currentStreams.end()) {
      conn->handleIncomingQuery(std::move(stream->second), streamID);
    }
    else {
      vinfolog("Stream %d NOT FOUND", streamID);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  else if (frame->hd.type == NGHTTP2_PING) {
    conn->d_needFlush = true;
  }

  return 0;
}

int IncomingHTTP2Connection::on_stream_close_callback(nghttp2_session* session, IncomingHTTP2Connection::StreamID stream_id, uint32_t error_code, void* user_data)
{
  (void)session;
  (void)error_code;
  auto* conn = static_cast<IncomingHTTP2Connection*>(user_data);

  conn->d_currentStreams.erase(stream_id);
  return 0;
}

int IncomingHTTP2Connection::on_begin_headers_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
  (void)session;
  if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  auto* conn = static_cast<IncomingHTTP2Connection*>(user_data);
  auto insertPair = conn->d_currentStreams.emplace(frame->hd.stream_id, PendingQuery());
  if (!insertPair.second) {
    /* there is a stream ID collision, something is very wrong! */
    vinfolog("Stream ID collision (%d) on connection from %d", frame->hd.stream_id, conn->d_ci.remote.toStringWithPort());
    conn->d_connectionClosing = true;
    conn->d_needFlush = true;
    nghttp2_session_terminate_session(conn->d_session.get(), NGHTTP2_NO_ERROR);
    auto ret = nghttp2_session_send(conn->d_session.get());
    if (ret != 0) {
      vinfolog("Error flushing HTTP response for stream %d from %s: %s", frame->hd.stream_id, conn->d_ci.remote.toStringWithPort(), nghttp2_strerror(ret));
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    return 0;
  }

  return 0;
}

static std::string::size_type getLengthOfPathWithoutParameters(const std::string_view& path)
{
  auto pos = path.find('?');
  if (pos == string::npos) {
    return path.size();
  }

  return pos;
}

int IncomingHTTP2Connection::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t nameLen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
  (void)session;
  (void)flags;
  auto* conn = static_cast<IncomingHTTP2Connection*>(user_data);

  if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    if (nghttp2_check_header_name(name, nameLen) == 0) {
      vinfolog("Invalid header name");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

#if defined(HAVE_NGHTTP2_CHECK_HEADER_VALUE_RFC9113)
    if (nghttp2_check_header_value_rfc9113(value, valuelen) == 0) {
      vinfolog("Invalid header value");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
#endif /* HAVE_NGHTTP2_CHECK_HEADER_VALUE_RFC9113 */

    auto headerMatches = [name, nameLen](const std::string& expected) -> bool {
      return nameLen == expected.size() && memcmp(name, expected.data(), expected.size()) == 0;
    };

    auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
    if (stream == conn->d_currentStreams.end()) {
      vinfolog("Unable to match the stream ID %d to a known one!", frame->hd.stream_id);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    auto& query = stream->second;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): nghttp2 API
    auto valueView = std::string_view(reinterpret_cast<const char*>(value), valuelen);
    if (headerMatches(s_pathHeaderName)) {
#if defined(HAVE_NGHTTP2_CHECK_PATH)
      if (nghttp2_check_path(value, valuelen) == 0) {
        vinfolog("Invalid path value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
#endif /* HAVE_NGHTTP2_CHECK_PATH */

      auto pathLen = getLengthOfPathWithoutParameters(valueView);
      query.d_path = valueView.substr(0, pathLen);
      if (pathLen < valueView.size()) {
        query.d_queryString = valueView.substr(pathLen);
      }
    }
    else if (headerMatches(s_authorityHeaderName)) {
      query.d_host = valueView;
    }
    else if (headerMatches(s_schemeHeaderName)) {
      query.d_scheme = valueView;
    }
    else if (headerMatches(s_methodHeaderName)) {
#if defined(HAVE_NGHTTP2_CHECK_METHOD)
      if (nghttp2_check_method(value, valuelen) == 0) {
        vinfolog("Invalid method value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
#endif /* HAVE_NGHTTP2_CHECK_METHOD */

      if (valueView == "GET") {
        query.d_method = PendingQuery::Method::Get;
      }
      else if (valueView == "POST") {
        query.d_method = PendingQuery::Method::Post;
      }
      else {
        query.d_method = PendingQuery::Method::Unsupported;
        vinfolog("Unsupported method value");
        return 0;
      }
    }

    if (conn->d_ci.cs->dohFrontend->d_keepIncomingHeaders || (conn->d_ci.cs->dohFrontend->d_trustForwardedForHeader && headerMatches(s_xForwardedForHeaderName))) {
      if (!query.d_headers) {
        query.d_headers = std::make_unique<HeadersMap>();
      }
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): nghttp2 API
      query.d_headers->insert({std::string(reinterpret_cast<const char*>(name), nameLen), std::string(valueView)});
    }
  }
  return 0;
}

int IncomingHTTP2Connection::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, IncomingHTTP2Connection::StreamID stream_id, const uint8_t* data, size_t len, void* user_data)
{
  (void)session;
  (void)flags;
  auto* conn = static_cast<IncomingHTTP2Connection*>(user_data);
  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    vinfolog("Unable to match the stream ID %d to a known one!", stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if (len > std::numeric_limits<uint16_t>::max() || (std::numeric_limits<uint16_t>::max() - stream->second.d_buffer.size()) < len) {
    vinfolog("Data frame of size %d is too large for a DNS query (we already have %d)", len, stream->second.d_buffer.size());
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): nghttp2 API
  stream->second.d_buffer.insert(stream->second.d_buffer.end(), data, data + len);

  return 0;
}

int IncomingHTTP2Connection::on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data)
{
  (void)session;
  auto* conn = static_cast<IncomingHTTP2Connection*>(user_data);

  vinfolog("Error in HTTP/2 connection from %s: %s (%d)", conn->d_ci.remote.toStringWithPort(), std::string(msg, len), lib_error_code);
  conn->d_connectionClosing = true;
  conn->d_needFlush = true;
  nghttp2_session_terminate_session(conn->d_session.get(), NGHTTP2_NO_ERROR);
  auto ret = nghttp2_session_send(conn->d_session.get());
  if (ret != 0) {
    vinfolog("Error flushing HTTP response on connection from %s: %s", conn->d_ci.remote.toStringWithPort(), nghttp2_strerror(ret));
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

IOState IncomingHTTP2Connection::readHTTPData()
{
  if (d_inReadFunction) {
    return IOState::Done;
  }
  ReadFunctionGuard readGuard(d_inReadFunction);

  IOState newState = IOState::Done;
  size_t got = 0;
  if (d_in.size() < s_initialReceiveBufferSize) {
    d_in.resize(std::max(s_initialReceiveBufferSize, d_in.capacity()));
  }
  try {
    newState = d_handler.tryRead(d_in, got, d_in.size(), true);
    d_in.resize(got);

    if (got > 0) {
      /* we got something */
      auto readlen = nghttp2_session_mem_recv(d_session.get(), d_in.data(), d_in.size());
      /* as long as we don't require a pause by returning nghttp2_error.NGHTTP2_ERR_PAUSE from a CB,
         all data should be consumed before returning */
      if (readlen < 0 || static_cast<size_t>(readlen) < d_in.size()) {
        throw std::runtime_error("Fatal error while passing received data to nghttp2: " + std::string(nghttp2_strerror((int)readlen)));
      }

      nghttp2_session_send(d_session.get());
    }
  }
  catch (const std::exception& e) {
    vinfolog("Exception while trying to read from HTTP client connection to %s: %s", d_ci.remote.toStringWithPort(), e.what());
    handleIOError();
    return IOState::Done;
  }
  return newState;
}

void IncomingHTTP2Connection::handleReadableIOCallback([[maybe_unused]] int descriptor, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
  conn->handleIO();
}

void IncomingHTTP2Connection::handleWritableIOCallback([[maybe_unused]] int descriptor, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
  conn->writeToSocket(true);
}

void IncomingHTTP2Connection::stopIO()
{
  if (d_ioState) {
    d_ioState->reset();
  }
}

uint32_t IncomingHTTP2Connection::getConcurrentStreamsCount() const
{
  return d_currentStreams.size();
}

boost::optional<struct timeval> IncomingHTTP2Connection::getIdleClientReadTTD(struct timeval now) const
{
  const auto& currentConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  auto idleTimeout = d_ci.cs->dohFrontend->d_idleTimeout;
  if (currentConfig.d_maxTCPConnectionDuration == 0 && idleTimeout == 0) {
    return boost::none;
  }

  if (currentConfig.d_maxTCPConnectionDuration > 0) {
    auto elapsed = now.tv_sec - d_connectionStartTime.tv_sec;
    if (elapsed < 0 || (static_cast<size_t>(elapsed) >= currentConfig.d_maxTCPConnectionDuration)) {
      return now;
    }
    auto remaining = currentConfig.d_maxTCPConnectionDuration - elapsed;
    if (idleTimeout == 0 || remaining <= static_cast<size_t>(idleTimeout)) {
      now.tv_sec += static_cast<time_t>(remaining);
      return now;
    }
  }

  now.tv_sec += idleTimeout;
  return now;
}

void IncomingHTTP2Connection::updateIO(IOState newState, const timeval& now)
{
  (void)now;
  updateIO(newState, newState == IOState::NeedWrite ? handleWritableIOCallback : handleReadableIOCallback);
}

void IncomingHTTP2Connection::updateIO(IOState newState, const FDMultiplexer::callbackfunc_t& callback)
{
  boost::optional<struct timeval> ttd{boost::none};

  if (newState == IOState::Async) {
    auto shared = shared_from_this();
    updateIOForAsync(shared);
    return;
  }

  auto shared = std::dynamic_pointer_cast<IncomingHTTP2Connection>(shared_from_this());
  if (!shared || !d_ioState) {
    return;
  }

  timeval now{};
  gettimeofday(&now, nullptr);

  if (newState == IOState::NeedRead) {
    /* use the idle TTL if the handshake has been completed (and proxy protocol payload received, if any),
       and we have processed at least one query, otherwise we use the shorter read TTL  */
    if ((d_state == State::waitingForQuery || d_state == State::idle) && (d_queriesCount > 0 || d_currentQueriesCount > 0)) {
      ttd = getIdleClientReadTTD(now);
    }
    else {
      ttd = getClientReadTTD(now);
    }
    d_ioState->update(newState, callback, shared, ttd);
  }
  else if (newState == IOState::NeedWrite) {
    ttd = getClientWriteTTD(now);
    d_ioState->update(newState, callback, shared, ttd);
  }
}

void IncomingHTTP2Connection::handleIOError()
{
  d_connectionDied = true;
  d_out.clear();
  d_outPos = 0;
  nghttp2_session_terminate_session(d_session.get(), NGHTTP2_PROTOCOL_ERROR);
  d_currentStreams.clear();
  stopIO();
}

bool IncomingHTTP2Connection::active() const
{
  return !d_connectionDied && d_ioState != nullptr;
}

#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
