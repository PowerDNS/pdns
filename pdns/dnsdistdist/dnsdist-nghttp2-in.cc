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

#include "base64.hh"
#include "dnsdist-nghttp2-in.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsparser.hh"

#ifdef HAVE_NGHTTP2

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
  IncomingDoHCrossProtocolContext(IncomingHTTP2Connection::PendingQuery&& query, std::shared_ptr<IncomingHTTP2Connection> connection, IncomingHTTP2Connection::StreamID streamID) :
    d_connection(connection), d_query(std::move(query)), d_streamID(streamID)
  {
  }

  std::string getHTTPPath() const override
  {
    return d_query.d_path;
  }

  const std::string& getHTTPScheme() const override
  {
    return d_query.d_scheme;
  }

  const std::string& getHTTPHost() const override
  {
    return d_query.d_host;
  }

  std::string getHTTPQueryString() const override
  {
    return d_query.d_queryString;
  }

  const HeadersMap& getHTTPHeaders() const override
  {
    if (!d_query.d_headers) {
      static const HeadersMap empty{};
      return empty;
    }
    return *d_query.d_headers;
  }

  void setHTTPResponse(uint16_t statusCode, PacketBuffer&& body, const std::string& contentType = "") override
  {
    d_query.d_statusCode = statusCode;
    d_query.d_response = std::move(body);
    d_query.d_contentTypeOut = contentType;
  }

  void handleUDPResponse(PacketBuffer&& response, InternalQueryState&& state, const std::shared_ptr<DownstreamState>& ds) override
  {
    std::unique_ptr<DOHUnitInterface> unit(this);
    auto conn = d_connection.lock();
    if (!conn) {
      /* the connection has been closed in the meantime */
      return;
    }

    state.du = std::move(unit);
    TCPResponse resp(std::move(response), std::move(state), nullptr, nullptr);
    resp.d_ds = ds;
    struct timeval now;
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
    struct timeval now;
    gettimeofday(&now, nullptr);
    TCPResponse resp;
    resp.d_idstate.d_streamID = d_streamID;
    conn->notifyIOError(now, std::move(resp));
  }

  ~IncomingDoHCrossProtocolContext() override
  {
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
    dnsheader* responseDH = reinterpret_cast<struct dnsheader*>(response.d_buffer.data());

    if (responseDH->tc && state.d_packet && state.d_packet->size() > state.d_proxyProtocolPayloadSize && state.d_packet->size() - state.d_proxyProtocolPayloadSize > sizeof(dnsheader)) {
      vinfolog("Response received from backend %s via UDP, for query %d received from %s via DoH, is truncated, retrying over TCP", response.d_ds->getNameWithAddr(), state.d_streamID, state.origRemote.toStringWithPort());
      auto& query = *state.d_packet;
      dnsheader* queryDH = reinterpret_cast<struct dnsheader*>(query.data() + state.d_proxyProtocolPayloadSize);
      /* restoring the original ID */
      queryDH->id = state.origID;

      state.forwardedOverUDP = false;
      auto cpq = getCrossProtocolQuery(std::move(query), std::move(state), response.d_ds);
      cpq->query.d_proxyProtocolPayloadAdded = state.d_proxyProtocolPayloadSize > 0;
      if (g_tcpclientthreads && g_tcpclientthreads->passCrossProtocolQueryToThread(std::move(cpq))) {
        return;
      }
      else {
        vinfolog("Unable to pass DoH query to a TCP worker thread after getting a TC response over UDP");
        notifyIOError(now, std::move(response));
        return;
      }
    }
  }

  IncomingTCPConnectionState::handleResponse(now, std::move(response));
}

std::unique_ptr<DOHUnitInterface> IncomingHTTP2Connection::getDOHUnit(uint32_t streamID)
{
  auto query = std::move(d_currentStreams.at(streamID));
  return std::make_unique<IncomingDoHCrossProtocolContext>(std::move(query), std::dynamic_pointer_cast<IncomingHTTP2Connection>(shared_from_this()), streamID);
}

void IncomingHTTP2Connection::restoreDOHUnit(std::unique_ptr<DOHUnitInterface>&& unit)
{
  auto context = std::unique_ptr<IncomingDoHCrossProtocolContext>(dynamic_cast<IncomingDoHCrossProtocolContext*>(unit.release()));
  d_currentStreams.at(context->d_streamID) = std::move(context->d_query);
}

void IncomingHTTP2Connection::restoreContext(uint32_t streamID, IncomingHTTP2Connection::PendingQuery&& context)
{
  d_currentStreams.at(streamID) = std::move(context);
}

IncomingHTTP2Connection::IncomingHTTP2Connection(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now) :
  IncomingTCPConnectionState(std::move(ci), threadData, now)
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
  constexpr std::array<uint8_t, 2> h2{'h', '2'};
  auto protocols = d_handler.getNextProtocol();
  if (protocols.size() == h2.size() && memcmp(protocols.data(), h2.data(), h2.size()) == 0) {
    return true;
  }
  vinfolog("DoH connection from %s expected ALPN value 'h2', got '%s'", d_ci.remote.toStringWithPort(), std::string(protocols.begin(), protocols.end()));
  return false;
}

void IncomingHTTP2Connection::handleConnectionReady()
{
  constexpr std::array<nghttp2_settings_entry, 1> iv{{{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100U}}};
  auto ret = nghttp2_submit_settings(d_session.get(), NGHTTP2_FLAG_NONE, iv.data(), iv.size());
  if (ret != 0) {
    throw std::runtime_error("Fatal error: " + std::string(nghttp2_strerror(ret)));
  }
  ret = nghttp2_session_send(d_session.get());
  if (ret != 0) {
    throw std::runtime_error("Fatal error: " + std::string(nghttp2_strerror(ret)));
  }
}

void IncomingHTTP2Connection::handleIO()
{
  IOState iostate = IOState::Done;
  struct timeval now;
  gettimeofday(&now, nullptr);

  try {
    if (maxConnectionDurationReached(g_maxTCPConnectionDuration, now)) {
      vinfolog("Terminating DoH connection from %s because it reached the maximum TCP connection duration", d_ci.remote.toStringWithPort());
      stopIO();
      d_connectionDied = true;
      return;
    }

    if (d_state == State::doingHandshake) {
      iostate = d_handler.tryHandshake();
      if (iostate == IOState::Done) {
        handleHandshakeDone(now);
        if (d_handler.isTLS()) {
          if (!checkALPN()) {
            d_connectionDied = true;
            stopIO();
            return;
          }
        }

        if (expectProxyProtocolFrom(d_ci.remote)) {
          d_state = IncomingTCPConnectionState::State::readingProxyProtocolHeader;
          d_buffer.resize(s_proxyProtocolMinimumHeaderSize);
          d_proxyProtocolNeed = s_proxyProtocolMinimumHeaderSize;
        }
        else {
          d_state = State::waitingForQuery;
          handleConnectionReady();
        }
      }
    }

    if (d_state == IncomingTCPConnectionState::State::readingProxyProtocolHeader) {
      auto status = handleProxyProtocolPayload();
      if (status == ProxyProtocolResult::Done) {
        d_currentPos = 0;
        d_proxyProtocolNeed = 0;
        d_buffer.clear();
        d_state = State::waitingForQuery;
        handleConnectionReady();
      }
      else if (status == ProxyProtocolResult::Error) {
        d_connectionDied = true;
        stopIO();
        return;
      }
    }

    if (d_state == State::waitingForQuery) {
      readHTTPData();
    }

    if (!d_connectionDied) {
      auto shared = std::dynamic_pointer_cast<IncomingHTTP2Connection>(shared_from_this());
      if (nghttp2_session_want_read(d_session.get())) {
        d_ioState->add(IOState::NeedRead, &handleReadableIOCallback, shared, boost::none);
      }
      if (nghttp2_session_want_write(d_session.get())) {
        d_ioState->add(IOState::NeedWrite, &handleWritableIOCallback, shared, boost::none);
      }
    }
  }
  catch (const std::exception& e) {
    vinfolog("Exception when processing IO for incoming DoH connection from %s: %s", d_ci.remote.toStringWithPort(), e.what());
    d_connectionDied = true;
    stopIO();
  }
}

ssize_t IncomingHTTP2Connection::send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  bool bufferWasEmpty = conn->d_out.empty();
  conn->d_out.insert(conn->d_out.end(), data, data + length);

  if (bufferWasEmpty) {
    try {
      auto state = conn->d_handler.tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
      if (state == IOState::Done) {
        conn->d_out.clear();
        conn->d_outPos = 0;
        if (!conn->isIdle()) {
          conn->updateIO(IOState::NeedRead, handleReadableIOCallback);
        }
        else {
          conn->watchForRemoteHostClosingConnection();
        }
      }
      else {
        conn->updateIO(state, handleWritableIOCallback);
      }
    }
    catch (const std::exception& e) {
      vinfolog("Exception while trying to write (send) to incoming HTTP connection: %s", e.what());
      conn->handleIOError();
    }
  }

  return length;
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
  "dns-over-https"
};

static const std::string s_authorityHeaderName(":authority");
static const std::string s_pathHeaderName(":path");
static const std::string s_methodHeaderName(":method");
static const std::string s_schemeHeaderName(":scheme");
static const std::string s_xForwardedForHeaderName("x-forwarded-for");

void NGHTTP2Headers::addStaticHeader(std::vector<nghttp2_nv>& headers, NGHTTP2Headers::HeaderConstantIndexes nameKey, NGHTTP2Headers::HeaderConstantIndexes valueKey)
{
  const auto& name = s_headerConstants.at(static_cast<size_t>(nameKey));
  const auto& value = s_headerConstants.at(static_cast<size_t>(valueKey));

  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.c_str())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

void NGHTTP2Headers::addCustomDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& name, const std::string_view& value)
{
  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.data())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.data())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

void NGHTTP2Headers::addDynamicHeader(std::vector<nghttp2_nv>& headers, NGHTTP2Headers::HeaderConstantIndexes nameKey, const std::string_view& value)
{
  const auto& name = s_headerConstants.at(static_cast<size_t>(nameKey));
  NGHTTP2Headers::addCustomDynamicHeader(headers, name, value);
}

IOState IncomingHTTP2Connection::sendResponse(const struct timeval& now, TCPResponse&& response)
{
  assert(response.d_idstate.d_streamID != -1);
  auto& context = d_currentStreams.at(response.d_idstate.d_streamID);

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

  sendResponse(response.d_idstate.d_streamID, statusCode, d_ci.cs->dohFrontend->d_customResponseHeaders, contentType, sendContentType);
  handleResponseSent(response);

  return IOState::Done;
}

void IncomingHTTP2Connection::notifyIOError(const struct timeval& now, TCPResponse&& response)
{
  if (std::this_thread::get_id() != d_creatorThreadID) {
    /* empty buffer will signal an IO error */
    response.d_buffer.clear();
    handleCrossProtocolResponse(now, std::move(response));
    return;
  }

  assert(response.d_idstate.d_streamID != -1);
  d_currentStreams.at(response.d_idstate.d_streamID).d_buffer = std::move(response.d_buffer);
  sendResponse(response.d_idstate.d_streamID, 502, d_ci.cs->dohFrontend->d_customResponseHeaders);
}

bool IncomingHTTP2Connection::sendResponse(IncomingHTTP2Connection::StreamID streamID, uint16_t responseCode, const HeadersMap& customResponseHeaders, const std::string& contentType, bool addContentType)
{
  /* if data_prd is not NULL, it provides data which will be sent in subsequent DATA frames. In this case, a method that allows request message bodies (https://tools.ietf.org/html/rfc7231#section-4) must be specified with :method key (e.g. POST). This function does not take ownership of the data_prd. The function copies the members of the data_prd. If data_prd is NULL, HEADERS have END_STREAM set.
   */
  nghttp2_data_provider data_provider;

  data_provider.source.ptr = this;
  data_provider.read_callback = [](nghttp2_session*, IncomingHTTP2Connection::StreamID stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* cb_data) -> ssize_t {
    auto connection = reinterpret_cast<IncomingHTTP2Connection*>(cb_data);
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
    }
    return toCopy;
  };

  const auto& df = d_ci.cs->dohFrontend;
  auto& responseBody = d_currentStreams.at(streamID).d_buffer;

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
    ++df->d_validresponses;
    ++df->d_http2Stats.d_nb200Responses;

    if (addContentType) {
      if (contentType.empty()) {
        NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_VALUE);
      }
      else {
        NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, contentType);
      }
    }

    if (df->d_sendCacheControlHeaders && responseBody.size() > sizeof(dnsheader)) {
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
      location = std::string(reinterpret_cast<const char*>(responseBody.data()), responseBody.size());
      NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, "text/html; charset=utf-8");
      NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::LOCATION_NAME, location);
      static const std::string s_redirectStart{"<!DOCTYPE html><TITLE>Moved</TITLE><P>The document has moved <A HREF=\""};
      static const std::string s_redirectEnd{"\">here</A>"};
      responseBody.reserve(s_redirectStart.size() + responseBody.size() + s_redirectEnd.size());
      responseBody.insert(responseBody.begin(), s_redirectStart.begin(), s_redirectStart.end());
      responseBody.insert(responseBody.end(), s_redirectEnd.begin(), s_redirectEnd.end());
      ++df->d_redirectresponses;
    }
    else {
      ++df->d_errorresponses;
      switch (responseCode) {
      case 400:
        ++df->d_http2Stats.d_nb400Responses;
        break;
      case 403:
        ++df->d_http2Stats.d_nb403Responses;
        break;
      case 500:
        ++df->d_http2Stats.d_nb500Responses;
        break;
      case 502:
        ++df->d_http2Stats.d_nb502Responses;
        break;
      default:
        ++df->d_http2Stats.d_nbOtherResponses;
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

  auto it = headers->find(s_xForwardedForHeaderName);
  if (it == headers->end()) {
    return;
  }

  std::string_view value = it->second;
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

static std::optional<PacketBuffer> getPayloadFromPath(const std::string_view& path)
{
  std::optional<PacketBuffer> result{std::nullopt};

  if (path.size() <= 5) {
    return result;
  }

  auto pos = path.find("?dns=");
  if (pos == string::npos) {
    pos = path.find("&dns=");
  }

  if (pos == string::npos) {
    return result;
  }

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
  /* rough estimate so we hopefully don't need a new allocation later */
  /* We reserve at few additional bytes to be able to add EDNS later */
  const size_t estimate = ((sdns.size() * 3) / 4);
  decoded.reserve(estimate);
  if (B64Decode(sdns, decoded) < 0) {
    return result;
  }

  result = std::move(decoded);
  return result;
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
    sendResponse(streamID, code, d_ci.cs->dohFrontend->d_customResponseHeaders);
  };

  ++d_ci.cs->dohFrontend->d_http2Stats.d_nbQueries;

  if (d_ci.cs->dohFrontend->d_trustForwardedForHeader) {
    processForwardedForHeader(query.d_headers, d_proxiedRemote);

    /* second ACL lookup based on the updated address */
    auto& holders = d_threadData.holders;
    if (!holders.acl->match(d_proxiedRemote)) {
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
        if (entry->getStatusCode() >= 400 && query.d_buffer.size() >= 1) {
          // legacy trailing 0 from the h2o era
          query.d_buffer.pop_back();
        }

        sendResponse(streamID, entry->getStatusCode(), customHeaders ? *customHeaders : d_ci.cs->dohFrontend->d_customResponseHeaders, std::string(), false);
        return;
      }
    }
  }

  if (query.d_buffer.empty() && query.d_method == PendingQuery::Method::Get && !query.d_queryString.empty()) {
    auto payload = getPayloadFromPath(query.d_queryString);
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
    struct timeval now;
    gettimeofday(&now, nullptr);
    auto processingResult = handleQuery(std::move(query.d_buffer), now, streamID);

    switch (processingResult) {
    case QueryProcessingResult::TooSmall:
      handleImmediateResponse(400, "DoH non-compliant query");
      break;
    case QueryProcessingResult::InvalidHeaders:
      handleImmediateResponse(400, "DoH invalid headers");
      break;
    case QueryProcessingResult::Empty:
      handleImmediateResponse(200, "DoH empty query", std::move(query.d_buffer));
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
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
#if 0
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    cerr<<"got headers"<<endl;
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      cerr<<"All headers received"<<endl;
    }
    if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
      cerr<<"All headers received - query"<<endl;
    }
    break;
  case NGHTTP2_WINDOW_UPDATE:
    cerr<<"got window update"<<endl;
    break;
  case NGHTTP2_SETTINGS:
    cerr<<"got settings"<<endl;
    cerr<<frame->settings.niv<<endl;
    for (size_t idx = 0; idx < frame->settings.niv; idx++) {
      cerr<<"- "<<frame->settings.iv[idx].settings_id<<" "<<frame->settings.iv[idx].value<<endl;
    }
    break;
  case NGHTTP2_DATA:
    cerr<<"got data"<<endl;
    break;
  }
#endif

  if (frame->hd.type == NGHTTP2_GOAWAY) {
    conn->stopIO();
    if (conn->isIdle()) {
      if (nghttp2_session_want_write(conn->d_session.get())) {
        conn->d_ioState->add(IOState::NeedWrite, &handleWritableIOCallback, conn, boost::none);
      }
    }
  }

  /* is this the last frame for this stream? */
  else if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    auto streamID = frame->hd.stream_id;
    auto stream = conn->d_currentStreams.find(streamID);
    if (stream != conn->d_currentStreams.end()) {
      conn->handleIncomingQuery(std::move(stream->second), streamID);

      if (conn->isIdle()) {
        conn->watchForRemoteHostClosingConnection();
      }
    }
    else {
      vinfolog("Stream %d NOT FOUND", streamID);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

int IncomingHTTP2Connection::on_stream_close_callback(nghttp2_session* session, IncomingHTTP2Connection::StreamID stream_id, uint32_t error_code, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  if (error_code == 0) {
    return 0;
  }

  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    /* we don't care, then */
    return 0;
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  auto request = std::move(stream->second);
  conn->d_currentStreams.erase(stream->first);

  if (conn->isIdle()) {
    conn->watchForRemoteHostClosingConnection();
  }

  return 0;
}

int IncomingHTTP2Connection::on_begin_headers_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
  if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }

  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  auto insertPair = conn->d_currentStreams.emplace(frame->hd.stream_id, PendingQuery());
  if (!insertPair.second) {
    /* there is a stream ID collision, something is very wrong! */
    vinfolog("Stream ID collision (%d) on connection from %d", frame->hd.stream_id, conn->d_ci.remote.toStringWithPort());
    conn->d_connectionDied = true;
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
  auto pos = path.find("?");
  if (pos == string::npos) {
    return path.size();
  }

  return pos;
}

int IncomingHTTP2Connection::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t nameLen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
    if (nghttp2_check_header_name(name, nameLen) == 0) {
      vinfolog("Invalid header name");
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

#if HAVE_NGHTTP2_CHECK_HEADER_VALUE_RFC9113
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
    auto valueView = std::string_view(reinterpret_cast<const char*>(value), valuelen);
    if (headerMatches(s_pathHeaderName)) {
#if HAVE_NGHTTP2_CHECK_PATH
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
#if HAVE_NGHTTP2_CHECK_METHOD
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
        vinfolog("Unsupported method value");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }

    if (conn->d_ci.cs->dohFrontend->d_keepIncomingHeaders || (conn->d_ci.cs->dohFrontend->d_trustForwardedForHeader && headerMatches(s_xForwardedForHeaderName))) {
      if (!query.d_headers) {
        query.d_headers = std::make_unique<HeadersMap>();
      }
      query.d_headers->insert({std::string(reinterpret_cast<const char*>(name), nameLen), std::string(valueView)});
    }
  }
  return 0;
}

int IncomingHTTP2Connection::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, IncomingHTTP2Connection::StreamID stream_id, const uint8_t* data, size_t len, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);
  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    vinfolog("Unable to match the stream ID %d to a known one!", stream_id);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if (len > std::numeric_limits<uint16_t>::max() || (std::numeric_limits<uint16_t>::max() - stream->second.d_buffer.size()) < len) {
    vinfolog("Data frame of size %d is too large for a DNS query (we already have %d)", len, stream->second.d_buffer.size());
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  stream->second.d_buffer.insert(stream->second.d_buffer.end(), data, data + len);

  return 0;
}

int IncomingHTTP2Connection::on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data)
{
  IncomingHTTP2Connection* conn = reinterpret_cast<IncomingHTTP2Connection*>(user_data);

  vinfolog("Error in HTTP/2 connection from %d: %s", conn->d_ci.remote.toStringWithPort(), std::string(msg, len));
  conn->d_connectionDied = true;
  nghttp2_session_terminate_session(conn->d_session.get(), NGHTTP2_NO_ERROR);
  auto ret = nghttp2_session_send(conn->d_session.get());
  if (ret != 0) {
    vinfolog("Error flushing HTTP response on connection from %s: %s", conn->d_ci.remote.toStringWithPort(), nghttp2_strerror(ret));
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  return 0;
}

void IncomingHTTP2Connection::readHTTPData()
{
  IOStateGuard ioGuard(d_ioState);
  do {
    size_t got = 0;
    d_in.resize(d_in.size() + 512);
    try {
      IOState newState = d_handler.tryRead(d_in, got, d_in.size(), true);
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

      if (newState == IOState::Done) {
        if (isIdle()) {
          watchForRemoteHostClosingConnection();
          ioGuard.release();
          break;
        }
      }
      else {
        if (newState == IOState::NeedWrite) {
          updateIO(IOState::NeedWrite, handleReadableIOCallback);
        }
        ioGuard.release();
        break;
      }
    }
    catch (const std::exception& e) {
      vinfolog("Exception while trying to read from HTTP backend connection: %s", e.what());
      handleIOError();
      break;
    }
  } while (getConcurrentStreamsCount() > 0);
}

void IncomingHTTP2Connection::handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
  conn->handleIO();
}

void IncomingHTTP2Connection::handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<IncomingHTTP2Connection>>(param);
  IOStateGuard ioGuard(conn->d_ioState);

  try {
    IOState newState = conn->d_handler.tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
    if (newState == IOState::NeedRead) {
      conn->updateIO(IOState::NeedRead, handleWritableIOCallback);
    }
    else if (newState == IOState::Done) {
      conn->d_out.clear();
      conn->d_outPos = 0;
      if (!conn->isIdle()) {
        conn->updateIO(IOState::NeedRead, handleReadableIOCallback);
      }
      else {
        conn->watchForRemoteHostClosingConnection();
      }
    }
    ioGuard.release();
  }
  catch (const std::exception& e) {
    vinfolog("Exception while trying to write (ready) to HTTP backend connection: %s", e.what());
    conn->handleIOError();
  }
}

bool IncomingHTTP2Connection::isIdle() const
{
  return getConcurrentStreamsCount() == 0;
}

void IncomingHTTP2Connection::stopIO()
{
  d_ioState->reset();
}

uint32_t IncomingHTTP2Connection::getConcurrentStreamsCount() const
{
  return d_currentStreams.size();
}

boost::optional<struct timeval> IncomingHTTP2Connection::getIdleClientReadTTD(struct timeval now) const
{
  auto idleTimeout = d_ci.cs->dohFrontend->d_idleTimeout;
  if (g_maxTCPConnectionDuration == 0 && idleTimeout == 0) {
    return boost::none;
  }

  if (g_maxTCPConnectionDuration > 0) {
    auto elapsed = now.tv_sec - d_connectionStartTime.tv_sec;
    if (elapsed < 0 || (static_cast<size_t>(elapsed) >= g_maxTCPConnectionDuration)) {
      return now;
    }
    auto remaining = g_maxTCPConnectionDuration - elapsed;
    if (idleTimeout == 0 || remaining <= static_cast<size_t>(idleTimeout)) {
      now.tv_sec += remaining;
      return now;
    }
  }

  now.tv_sec += idleTimeout;
  return now;
}

void IncomingHTTP2Connection::updateIO(IOState newState, FDMultiplexer::callbackfunc_t callback)
{
  boost::optional<struct timeval> ttd{boost::none};

  auto shared = std::dynamic_pointer_cast<IncomingHTTP2Connection>(shared_from_this());
  if (shared) {
    struct timeval now;
    gettimeofday(&now, nullptr);

    if (newState == IOState::NeedRead) {
      if (isIdle()) {
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
}

void IncomingHTTP2Connection::watchForRemoteHostClosingConnection()
{
  updateIO(IOState::NeedRead, handleReadableIOCallback);
}

void IncomingHTTP2Connection::handleIOError()
{
  d_connectionDied = true;
  nghttp2_session_terminate_session(d_session.get(), NGHTTP2_PROTOCOL_ERROR);
  d_currentStreams.clear();
  stopIO();
}
#endif /* HAVE_NGHTTP2 */
