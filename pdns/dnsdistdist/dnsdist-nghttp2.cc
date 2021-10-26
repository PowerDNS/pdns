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

#include "config.h"

#ifdef HAVE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif /* HAVE_NGHTTP2 */

#include "dnsdist-nghttp2.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"

#include "dolog.hh"
#include "iputils.hh"
#include "libssl.hh"
#include "noinitvector.hh"
#include "tcpiohandler.hh"
#include "threadname.hh"
#include "sstuff.hh"

std::atomic<uint64_t> g_dohStatesDumpRequested{0};
std::unique_ptr<DoHClientCollection> g_dohClientThreads{nullptr};
std::optional<uint16_t> g_outgoingDoHWorkerThreads{std::nullopt};

#ifdef HAVE_NGHTTP2
class DoHConnectionToBackend : public ConnectionToBackend
{
public:
  DoHConnectionToBackend(std::shared_ptr<DownstreamState> ds, std::unique_ptr<FDMultiplexer>& mplexer, const struct timeval& now, std::string&& proxyProtocolPayload);

  void handleTimeout(const struct timeval& now, bool write) override;
  void queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query) override;

  std::string toString() const override
  {
    ostringstream o;
    o << "DoH connection to backend " << (d_ds ? d_ds->getName() : "empty") << " over FD " << (d_handler ? std::to_string(d_handler->getDescriptor()) : "no socket") << ", " << getConcurrentStreamsCount() << " streams";
    return o.str();
  }

  void setHealthCheck(bool h)
  {
    d_healthCheckQuery = h;
  }

  void stopIO();
  bool reachedMaxConcurrentQueries() const override;
  bool reachedMaxStreamID() const override;
  bool isIdle() const override;
  void release() override
  {
  }

private:
  static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data);
  static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data);
  static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data);
  static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data);
  static int on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data);
  static void handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param);
  static void handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param);

  static void addStaticHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string& valueKey);
  static void addDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string& value);

  class PendingRequest
  {
  public:
    std::shared_ptr<TCPQuerySender> d_sender{nullptr};
    TCPQuery d_query;
    PacketBuffer d_buffer;
    size_t d_queryPos{0};
    uint16_t d_responseCode{0};
    bool d_finished{false};
  };
  void addToIOState(IOState state, FDMultiplexer::callbackfunc_t callback);
  void updateIO(IOState newState, FDMultiplexer::callbackfunc_t callback, bool noTTD = false);
  void watchForRemoteHostClosingConnection();
  void handleResponse(PendingRequest&& request);
  void handleResponseError(PendingRequest&& request, const struct timeval& now);
  void handleIOError();
  uint32_t getConcurrentStreamsCount() const;

  size_t getUsageCount() const
  {
    auto ref = shared_from_this();
    return ref.use_count();
  }

  static const std::unordered_map<std::string, std::string> s_constants;

  std::unordered_map<int32_t, PendingRequest> d_currentStreams;
  std::string d_proxyProtocolPayload;
  PacketBuffer d_out;
  PacketBuffer d_in;
  std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)> d_session{nullptr, nghttp2_session_del};
  size_t d_outPos{0};
  size_t d_inPos{0};
  bool d_healthCheckQuery{false};
  bool d_firstWrite{true};
};

class DownstreamDoHConnectionsManager
{
public:
  static std::shared_ptr<DoHConnectionToBackend> getConnectionToDownstream(std::unique_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& ds, const struct timeval& now, std::string&& proxyProtocolPayload);
  static void releaseDownstreamConnection(std::shared_ptr<DoHConnectionToBackend>&& conn);
  static bool removeDownstreamConnection(std::shared_ptr<DoHConnectionToBackend>& conn);
  static void cleanupClosedConnections(struct timeval now);
  static size_t clear();

  static void setMaxCachedConnectionsPerDownstream(size_t max)
  {
    s_maxCachedConnectionsPerDownstream = max;
  }

  static void setCleanupInterval(uint16_t interval)
  {
    s_cleanupInterval = interval;
  }

  static void setMaxIdleTime(uint16_t max)
  {
    s_maxIdleTime = max;
  }

private:
  static thread_local map<boost::uuids::uuid, std::deque<std::shared_ptr<DoHConnectionToBackend>>> t_downstreamConnections;
  static thread_local time_t t_nextCleanup;
  static size_t s_maxCachedConnectionsPerDownstream;
  static uint16_t s_cleanupInterval;
  static uint16_t s_maxIdleTime;
};

uint32_t DoHConnectionToBackend::getConcurrentStreamsCount() const
{
  return d_currentStreams.size();
}

void DoHConnectionToBackend::handleResponse(PendingRequest&& request)
{
  struct timeval now;
  gettimeofday(&now, nullptr);
  try {
    request.d_sender->handleResponse(now, TCPResponse(std::move(request.d_buffer), std::move(request.d_query.d_idstate), shared_from_this()));
  }
  catch (const std::exception& e) {
    vinfolog("Got exception while handling response for cross-protocol DoH: %s", e.what());
  }
}

void DoHConnectionToBackend::handleResponseError(PendingRequest&& request, const struct timeval& now)
{
  try {
    request.d_sender->notifyIOError(std::move(request.d_query.d_idstate), now);
  }
  catch (const std::exception& e) {
    vinfolog("Got exception while handling response for cross-protocol DoH: %s", e.what());
  }
}

void DoHConnectionToBackend::handleIOError()
{
  d_connectionDied = true;
  nghttp2_session_terminate_session(d_session.get(), NGHTTP2_PROTOCOL_ERROR);

  struct timeval now;
  gettimeofday(&now, nullptr);
  for (auto& request : d_currentStreams) {
    handleResponseError(std::move(request.second), now);
  }

  d_currentStreams.clear();
  stopIO();
}

void DoHConnectionToBackend::handleTimeout(const struct timeval& now, bool write)
{
  if (write) {
    if (d_firstWrite) {
      ++d_ds->tcpConnectTimeouts;
    }
    else {
      ++d_ds->tcpWriteTimeouts;
    }
  }
  else {
    ++d_ds->tcpReadTimeouts;
  }

  handleIOError();
}

bool DoHConnectionToBackend::reachedMaxStreamID() const
{
  const uint32_t maximumStreamID = (static_cast<uint32_t>(1) << 31) - 1;
  return d_highestStreamID == maximumStreamID;
}

bool DoHConnectionToBackend::reachedMaxConcurrentQueries() const
{
  //cerr<<"Got "<<getConcurrentStreamsCount()<<" concurrent streams, max is "<<nghttp2_session_get_remote_settings(d_session.get(), NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)<<endl;
  if (nghttp2_session_get_remote_settings(d_session.get(), NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) <= getConcurrentStreamsCount()) {
    return true;
  }
  return false;
}

bool DoHConnectionToBackend::isIdle() const
{
  return getConcurrentStreamsCount() == 0;
}

const std::unordered_map<std::string, std::string> DoHConnectionToBackend::s_constants = {
  {"method-name", ":method"},
  {"method-value", "POST"},
  {"scheme-name", ":scheme"},
  {"scheme-value", "https"},
  {"accept-name", "accept"},
  {"accept-value", "application/dns-message"},
  {"content-type-name", "content-type"},
  {"content-type-value", "application/dns-message"},
  {"user-agent-name", "user-agent"},
  {"user-agent-value", "nghttp2-" NGHTTP2_VERSION "/dnsdist"},
  {"authority-name", ":authority"},
  {"path-name", ":path"},
  {"content-length-name", "content-length"},
  {"x-forwarded-for-name", "x-forwarded-for"},
  {"x-forwarded-port-name", "x-forwarded-port"},
  {"x-forwarded-proto-name", "x-forwarded-proto"},
  {"x-forwarded-proto-value-dns-over-udp", "dns-over-udp"},
  {"x-forwarded-proto-value-dns-over-tcp", "dns-over-tcp"},
  {"x-forwarded-proto-value-dns-over-tls", "dns-over-tls"},
  {"x-forwarded-proto-value-dns-over-http", "dns-over-http"},
  {"x-forwarded-proto-value-dns-over-https", "dns-over-https"},
};

void DoHConnectionToBackend::addStaticHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string& valueKey)
{
  const auto& name = s_constants.at(nameKey);
  const auto& value = s_constants.at(valueKey);

  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.c_str())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

void DoHConnectionToBackend::addDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& nameKey, const std::string& value)
{
  const auto& name = s_constants.at(nameKey);

  headers.push_back({const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(name.c_str())), const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(value.c_str())), name.size(), value.size(), NGHTTP2_NV_FLAG_NO_COPY_NAME | NGHTTP2_NV_FLAG_NO_COPY_VALUE});
}

void DoHConnectionToBackend::queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query)
{
  auto payloadSize = std::to_string(query.d_buffer.size());

  bool addXForwarded = d_ds->d_addXForwardedHeaders;

  /* We use nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_NAME and nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_VALUE
     to avoid a copy and lowercasing but we need to make sure that the data will outlive the request (nghttp2_on_frame_send_callback called), and that it is already lowercased. */
  std::vector<nghttp2_nv> headers;
  // these need to live until after the request headers have been processed
  std::string remote;
  std::string remotePort;
  headers.reserve(8 + (addXForwarded ? 3 : 0));

  /* Pseudo-headers need to come first (rfc7540 8.1.2.1) */
  addStaticHeader(headers, "method-name", "method-value");
  addStaticHeader(headers, "scheme-name", "scheme-value");
  addDynamicHeader(headers, "authority-name", d_ds->d_tlsSubjectName);
  addDynamicHeader(headers, "path-name", d_ds->d_dohPath);
  addStaticHeader(headers, "accept-name", "accept-value");
  addStaticHeader(headers, "content-type-name", "content-type-value");
  addStaticHeader(headers, "user-agent-name", "user-agent-value");
  addDynamicHeader(headers, "content-length-name", payloadSize);
  /* no need to add these headers for health-check queries */
  if (addXForwarded && query.d_idstate.origRemote.getPort() != 0) {
    remote = query.d_idstate.origRemote.toString();
    remotePort = std::to_string(query.d_idstate.origRemote.getPort());
    addDynamicHeader(headers, "x-forwarded-for-name", remote);
    addDynamicHeader(headers, "x-forwarded-port-name", remotePort);
    if (query.d_idstate.cs != nullptr) {
      if (query.d_idstate.cs->isUDP()) {
        addStaticHeader(headers, "x-forwarded-proto-name", "x-forwarded-proto-value-dns-over-udp");
      }
      else if (query.d_idstate.cs->isDoH()) {
        if (query.d_idstate.cs->hasTLS()) {
          addStaticHeader(headers, "x-forwarded-proto-name", "x-forwarded-proto-value-dns-over-https");
        }
        else {
          addStaticHeader(headers, "x-forwarded-proto-name", "x-forwarded-proto-value-dns-over-http");
        }
      }
      else if (query.d_idstate.cs->hasTLS()) {
        addStaticHeader(headers, "x-forwarded-proto-name", "x-forwarded-proto-value-dns-over-tls");
      }
      else {
        addStaticHeader(headers, "x-forwarded-proto-name", "x-forwarded-proto-value-dns-over-tcp");
      }
    }
  }

  PendingRequest pending;
  pending.d_query = std::move(query);
  pending.d_sender = std::move(sender);

  uint32_t streamId = nghttp2_session_get_next_stream_id(d_session.get());
  auto insertPair = d_currentStreams.insert({streamId, std::move(pending)});
  if (!insertPair.second) {
    /* there is a stream ID collision, something is very wrong! */
    d_connectionDied = true;
    nghttp2_session_terminate_session(d_session.get(), NGHTTP2_NO_ERROR);
    throw std::runtime_error("Stream ID collision");
  }

  /* if data_prd is not NULL, it provides data which will be sent in subsequent DATA frames. In this case, a method that allows request message bodies (https://tools.ietf.org/html/rfc7231#section-4) must be specified with :method key (e.g. POST). This function does not take ownership of the data_prd. The function copies the members of the data_prd. If data_prd is NULL, HEADERS have END_STREAM set.
   */
  nghttp2_data_provider data_provider;

  /* we will not use this pointer */
  data_provider.source.ptr = this;
  data_provider.read_callback = [](nghttp2_session* session, int32_t stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* user_data) -> ssize_t {
    auto conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
    auto& request = conn->d_currentStreams.at(stream_id);
    size_t toCopy = 0;
    if (request.d_queryPos < request.d_query.d_buffer.size()) {
      size_t remaining = request.d_query.d_buffer.size() - request.d_queryPos;
      toCopy = length > remaining ? remaining : length;
      memcpy(buf, &request.d_query.d_buffer.at(request.d_queryPos), toCopy);
      request.d_queryPos += toCopy;
    }

    if (request.d_queryPos >= request.d_query.d_buffer.size()) {
      *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return toCopy;
  };

  auto newStreamId = nghttp2_submit_request(d_session.get(), nullptr, headers.data(), headers.size(), &data_provider, this);
  if (newStreamId < 0) {
    d_connectionDied = true;
    ++d_ds->tcpDiedSendingQuery;
    d_currentStreams.erase(streamId);
    throw std::runtime_error("Error submitting HTTP request:" + std::string(nghttp2_strerror(newStreamId)));
  }

  auto rv = nghttp2_session_send(d_session.get());
  if (rv != 0) {
    d_connectionDied = true;
    ++d_ds->tcpDiedSendingQuery;
    d_currentStreams.erase(streamId);
    throw std::runtime_error("Error in nghttp2_session_send:" + std::to_string(rv));
  }

  d_highestStreamID = newStreamId;
}

class DoHClientThreadData
{
public:
  DoHClientThreadData() :
    mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent()))
  {
  }

  std::unique_ptr<FDMultiplexer> mplexer{nullptr};
};

void DoHConnectionToBackend::handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(param);
  if (fd != conn->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->getHandle()));
  }

  IOStateGuard ioGuard(conn->d_ioState);
  do {
    conn->d_inPos = 0;
    conn->d_in.resize(conn->d_in.size() + 512);
    // cerr<<"trying to read "<<conn->d_in.size()<<endl;
    try {
      IOState newState = conn->d_handler->tryRead(conn->d_in, conn->d_inPos, conn->d_in.size(), true);
      // cerr<<"got a "<<(int)newState<<" state and "<<conn->d_inPos<<" bytes"<<endl;
      conn->d_in.resize(conn->d_inPos);

      if (conn->d_inPos > 0) {
        /* we got something */
        auto readlen = nghttp2_session_mem_recv(conn->d_session.get(), conn->d_in.data(), conn->d_inPos);
        // cerr<<"nghttp2_session_mem_recv returned "<<readlen<<endl;
        /* as long as we don't require a pause by returning nghttp2_error.NGHTTP2_ERR_PAUSE from a CB,
           all data should be consumed before returning */
        if (readlen > 0 && static_cast<size_t>(readlen) < conn->d_inPos) {
          throw std::runtime_error("Fatal error while passing received data to nghttp2: " + std::string(nghttp2_strerror((int)readlen)));
        }

        struct timeval now;
        gettimeofday(&now, nullptr);
        conn->d_lastDataReceivedTime = now;

        // cerr<<"after read send"<<endl;
        nghttp2_session_send(conn->d_session.get());
      }

      if (newState == IOState::Done) {
        if (conn->getConcurrentStreamsCount() == 0) {
          conn->stopIO();
          conn->watchForRemoteHostClosingConnection();
          ioGuard.release();
          break;
        }
      }
      else {
        if (newState == IOState::NeedWrite) {
          // cerr<<"need write"<<endl;
          conn->updateIO(IOState::NeedWrite, handleReadableIOCallback);
        }
        ioGuard.release();
        break;
      }
    }
    catch (const std::exception& e) {
      vinfolog("Exception while trying to read from HTTP backend connection: %s", e.what());
      ++conn->d_ds->tcpDiedReadingResponse;
      conn->handleIOError();
      break;
    }
  } while (conn->getConcurrentStreamsCount() > 0);
}

void DoHConnectionToBackend::handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(param);
  if (fd != conn->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->getHandle()));
  }
  IOStateGuard ioGuard(conn->d_ioState);

  // cerr<<"in "<<__PRETTY_FUNCTION__<<" trying to write "<<conn->d_out.size()-conn->d_outPos<<endl;
  try {
    IOState newState = conn->d_handler->tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
    // cerr<<"got a "<<(int)newState<<" state, "<<conn->d_out.size()-conn->d_outPos<<" bytes remaining"<<endl;
    if (newState == IOState::NeedRead) {
      conn->updateIO(IOState::NeedRead, handleWritableIOCallback);
    }
    else if (newState == IOState::Done) {
      // cerr<<"done, buffer size was "<<conn->d_out.size()<<", pos was "<<conn->d_outPos<<endl;
      conn->d_firstWrite = false;
      conn->d_out.clear();
      conn->d_outPos = 0;
      conn->stopIO();
      if (conn->getConcurrentStreamsCount() > 0) {
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
    ++conn->d_ds->tcpDiedSendingQuery;
    conn->handleIOError();
  }
}

void DoHConnectionToBackend::stopIO()
{
  d_ioState->reset();

  if (!willBeReusable(false)) {
    /* remove ourselves from the connection cache, this might mean that our
       reference count drops to zero after that, so we need to be careful */
    auto shared = std::dynamic_pointer_cast<DoHConnectionToBackend>(shared_from_this());
    DownstreamDoHConnectionsManager::removeDownstreamConnection(shared);
  }
}

void DoHConnectionToBackend::updateIO(IOState newState, FDMultiplexer::callbackfunc_t callback, bool noTTD)
{
  struct timeval now;
  gettimeofday(&now, nullptr);
  boost::optional<struct timeval> ttd{boost::none};
  if (!noTTD) {
    if (d_healthCheckQuery) {
      ttd = getBackendHealthCheckTTD(now);
    }
    else if (newState == IOState::NeedRead) {
      ttd = getBackendReadTTD(now);
    }
    else if (isFresh() && d_firstWrite) {
      /* first write just after the non-blocking connect */
      ttd = getBackendConnectTTD(now);
    }
    else {
      ttd = getBackendWriteTTD(now);
    }
  }

  auto shared = std::dynamic_pointer_cast<DoHConnectionToBackend>(shared_from_this());
  if (shared) {
    if (newState == IOState::NeedRead) {
      d_ioState->update(newState, callback, shared, ttd);
    }
    else if (newState == IOState::NeedWrite) {
      d_ioState->update(newState, callback, shared, ttd);
    }
  }
}

void DoHConnectionToBackend::watchForRemoteHostClosingConnection()
{
  if (willBeReusable(false) && !d_healthCheckQuery) {
    updateIO(IOState::NeedRead, handleReadableIOCallback, false);
  }
}

void DoHConnectionToBackend::addToIOState(IOState state, FDMultiplexer::callbackfunc_t callback)
{
  struct timeval now;
  gettimeofday(&now, nullptr);
  boost::optional<struct timeval> ttd{boost::none};
  if (state == IOState::NeedRead) {
    ttd = getBackendReadTTD(now);
  }
  else if (isFresh() && d_firstWrite == 0) {
    /* first write just after the non-blocking connect */
    ttd = getBackendConnectTTD(now);
  }
  else {
    ttd = getBackendWriteTTD(now);
  }

  auto shared = std::dynamic_pointer_cast<DoHConnectionToBackend>(shared_from_this());
  if (shared) {
    if (state == IOState::NeedRead) {
      d_ioState->add(state, callback, shared, ttd);
    }
    else if (state == IOState::NeedWrite) {
      d_ioState->add(state, callback, shared, ttd);
    }
  }
}

ssize_t DoHConnectionToBackend::send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  bool bufferWasEmpty = conn->d_out.empty();
  if (!conn->d_proxyProtocolPayloadSent && !conn->d_proxyProtocolPayload.empty()) {
    conn->d_out.insert(conn->d_out.end(), conn->d_proxyProtocolPayload.begin(), conn->d_proxyProtocolPayload.end());
    conn->d_proxyProtocolPayloadSent = true;
  }

  conn->d_out.insert(conn->d_out.end(), data, data + length);

  if (bufferWasEmpty) {
    try {
      // cerr<<"in "<<__PRETTY_FUNCTION__<<" trying to write "<<conn->d_out.size()-conn->d_outPos<<endl;
      auto state = conn->d_handler->tryWrite(conn->d_out, conn->d_outPos, conn->d_out.size());
      // cerr<<"got a "<<(int)state<<" state, "<<conn->d_out.size()-conn->d_outPos<<" bytes remaining"<<endl;
      if (state == IOState::Done) {
        conn->d_firstWrite = false;
        conn->d_out.clear();
        conn->d_outPos = 0;
        conn->stopIO();
        if (conn->getConcurrentStreamsCount() > 0) {
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
      vinfolog("Exception while trying to write (send) to HTTP backend connection: %s", e.what());
      conn->handleIOError();
      ++conn->d_ds->tcpDiedSendingQuery;
    }
  }

  return length;
}

int DoHConnectionToBackend::on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  // cerr<<"Frame type is "<<std::to_string(frame->hd.type)<<endl;
#if 0
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    cerr<<"got headers"<<endl;
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      cerr<<"All headers received"<<endl;
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
    conn->d_connectionDied = true;
  }

  /* is this the last frame for this stream? */
  else if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
    auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
    if (stream != conn->d_currentStreams.end()) {
      // cerr<<"Stream "<<frame->hd.stream_id<<" is now finished"<<endl;
      stream->second.d_finished = true;
      ++conn->d_queries;

      auto request = std::move(stream->second);
      conn->d_currentStreams.erase(stream->first);
      if (request.d_responseCode == 200U) {
        conn->handleResponse(std::move(request));
      }
      else {
        vinfolog("HTTP response has a non-200 status code: %d", request.d_responseCode);
        struct timeval now;
        gettimeofday(&now, nullptr);

        conn->handleResponseError(std::move(request), now);
      }

      if (conn->getConcurrentStreamsCount() == 0) {
        conn->stopIO();
        conn->watchForRemoteHostClosingConnection();
      }
    }
    else {
      vinfolog("Stream %d NOT FOUND", frame->hd.stream_id);
      conn->d_connectionDied = true;
      ++conn->d_ds->tcpDiedReadingResponse;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

int DoHConnectionToBackend::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data)
{
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  // cerr<<"Got data of size "<<len<<" for stream "<<stream_id<<endl;
  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    vinfolog("Unable to match the stream ID %d to a known one!", stream_id);
    conn->d_connectionDied = true;
    ++conn->d_ds->tcpDiedReadingResponse;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if (len > std::numeric_limits<uint16_t>::max() || (std::numeric_limits<uint16_t>::max() - stream->second.d_buffer.size()) < len) {
    vinfolog("Data frame of size %d is too large for a DNS response (we already have %d)", len, stream->second.d_buffer.size());
    conn->d_connectionDied = true;
    ++conn->d_ds->tcpDiedReadingResponse;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  stream->second.d_buffer.insert(stream->second.d_buffer.end(), data, data + len);
  if (stream->second.d_finished) {
    // cerr<<"we now have the full response!"<<endl;
    // cerr<<std::string(reinterpret_cast<const char*>(data), len)<<endl;

    auto request = std::move(stream->second);
    conn->d_currentStreams.erase(stream->first);
    if (request.d_responseCode == 200U) {
      conn->handleResponse(std::move(request));
    }
    else {
      vinfolog("HTTP response has a non-200 status code: %d", request.d_responseCode);
      struct timeval now;
      gettimeofday(&now, nullptr);

      conn->handleResponseError(std::move(request), now);
    }
    if (conn->getConcurrentStreamsCount() == 0) {
      conn->stopIO();
      conn->watchForRemoteHostClosingConnection();
    }
  }

  return 0;
}

int DoHConnectionToBackend::on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data)
{
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);

  if (error_code == 0) {
    return 0;
  }

  // cerr << "Stream " << stream_id << " closed with error_code=" << error_code << endl;
  conn->d_connectionDied = true;
  ++conn->d_ds->tcpDiedReadingResponse;

  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    /* we don't care, then */
    return 0;
  }

  struct timeval now;
  gettimeofday(&now, nullptr);
  auto request = std::move(stream->second);
  conn->d_currentStreams.erase(stream->first);

  // cerr<<"Query has "<<request.d_query.d_downstreamFailures<<" failures, backend limit is "<<conn->d_ds->d_retries<<endl;
  if (request.d_query.d_downstreamFailures < conn->d_ds->d_retries) {
    // cerr<<"in "<<__PRETTY_FUNCTION__<<", looking for a connection to send a query of size "<<request.d_query.d_buffer.size()<<endl;
    ++request.d_query.d_downstreamFailures;
    auto downstream = DownstreamDoHConnectionsManager::getConnectionToDownstream(conn->d_mplexer, conn->d_ds, now, std::string(conn->d_proxyProtocolPayload));
    downstream->queueQuery(request.d_sender, std::move(request.d_query));
  }
  else {
    conn->handleResponseError(std::move(request), now);
  }

  //cerr<<"we now have "<<conn->getConcurrentStreamsCount()<<" concurrent connections"<<endl;
  if (conn->getConcurrentStreamsCount() == 0) {
    //cerr<<"stopping IO"<<endl;
    conn->stopIO();
    conn->watchForRemoteHostClosingConnection();
  }

  return 0;
}

int DoHConnectionToBackend::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);

  const std::string status(":status");
  if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
    //cerr<<"got header for "<<frame->hd.stream_id<<":"<<endl;
    //cerr<<"- "<<std::string(reinterpret_cast<const char*>(name), namelen)<<endl;
    //cerr<<"- "<<std::string(reinterpret_cast<const char*>(value), valuelen)<<endl;
    if (namelen == status.size() && memcmp(status.data(), name, status.size()) == 0) {
      auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
      if (stream == conn->d_currentStreams.end()) {
        vinfolog("Unable to match the stream ID %d to a known one!", frame->hd.stream_id);
        conn->d_connectionDied = true;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      try {
        stream->second.d_responseCode = pdns_stou(std::string(reinterpret_cast<const char*>(value), valuelen));
      }
      catch (...) {
        vinfolog("Error parsing the status header for stream ID %d", frame->hd.stream_id);
        conn->d_connectionDied = true;
        ++conn->d_ds->tcpDiedReadingResponse;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
    }
  }
  return 0;
}

int DoHConnectionToBackend::on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data)
{
  vinfolog("Error in HTTP/2 connection: %s", std::string(msg, len));

  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  conn->d_connectionDied = true;
  ++conn->d_ds->tcpDiedReadingResponse;

  return 0;
}

DoHConnectionToBackend::DoHConnectionToBackend(std::shared_ptr<DownstreamState> ds, std::unique_ptr<FDMultiplexer>& mplexer, const struct timeval& now, std::string&& proxyProtocolPayload) :
  ConnectionToBackend(ds, mplexer, now), d_proxyProtocolPayload(std::move(proxyProtocolPayload))
{
  // inherit most of the stuff from the ConnectionToBackend()
  d_ioState = make_unique<IOStateHandler>(*d_mplexer, d_handler->getDescriptor());

  nghttp2_session_callbacks* cbs = nullptr;
  if (nghttp2_session_callbacks_new(&cbs) != 0) {
    d_connectionDied = true;
    ++d_ds->tcpDiedSendingQuery;
    vinfolog("Unable to create a callback object for a new HTTP/2 session");
    return;
  }
  std::unique_ptr<nghttp2_session_callbacks, void (*)(nghttp2_session_callbacks*)> callbacks(cbs, nghttp2_session_callbacks_del);
  cbs = nullptr;

  nghttp2_session_callbacks_set_send_callback(callbacks.get(), send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), on_stream_close_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks.get(), on_header_callback);
  nghttp2_session_callbacks_set_error_callback2(callbacks.get(), on_error_callback);

  nghttp2_session* sess = nullptr;
  if (nghttp2_session_client_new(&sess, callbacks.get(), this) != 0) {
    d_connectionDied = true;
    ++d_ds->tcpDiedSendingQuery;
    vinfolog("Coult not allocate a new HTTP/2 session");
    return;
  }

  d_session = std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)>(sess, nghttp2_session_del);
  sess = nullptr;

  callbacks.reset();

  nghttp2_settings_entry iv[] = {
    /* rfc7540 section-8.2.2:
       "Advertising a SETTINGS_MAX_CONCURRENT_STREAMS value of zero disables
       server push by preventing the server from creating the necessary
       streams."
    */
    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 0},
    {NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
    /* we might want to make the initial window size configurable, but 16M is a large enough default */
    {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 16 * 1024 * 1024}};
  /* client 24 bytes magic string will be sent by nghttp2 library */
  int rv = nghttp2_submit_settings(d_session.get(), NGHTTP2_FLAG_NONE, iv, sizeof(iv) / sizeof(*iv));
  if (rv != 0) {
    d_connectionDied = true;
    ++d_ds->tcpDiedSendingQuery;
    vinfolog("Could not submit SETTINGS: %s", nghttp2_strerror(rv));
    return;
  }
}

thread_local map<boost::uuids::uuid, std::deque<std::shared_ptr<DoHConnectionToBackend>>> DownstreamDoHConnectionsManager::t_downstreamConnections;
thread_local time_t DownstreamDoHConnectionsManager::t_nextCleanup{0};
size_t DownstreamDoHConnectionsManager::s_maxCachedConnectionsPerDownstream{10};
uint16_t DownstreamDoHConnectionsManager::s_cleanupInterval{60};
uint16_t DownstreamDoHConnectionsManager::s_maxIdleTime{300};

size_t DownstreamDoHConnectionsManager::clear()
{
  size_t result = 0;
  for (const auto& backend : t_downstreamConnections) {
    result += backend.second.size();
    for (auto& conn : backend.second) {
      conn->stopIO();
    }
  }
  t_downstreamConnections.clear();
  return result;
}

bool DownstreamDoHConnectionsManager::removeDownstreamConnection(std::shared_ptr<DoHConnectionToBackend>& conn)
{
  bool found = false;
  auto backendIt = t_downstreamConnections.find(conn->getDS()->getID());
  if (backendIt == t_downstreamConnections.end()) {
    return found;
  }

  for (auto connIt = backendIt->second.begin(); connIt != backendIt->second.end(); ++connIt) {
    if (*connIt == conn) {
      backendIt->second.erase(connIt);
      found = true;
      break;
    }
  }

  return found;
}

void DownstreamDoHConnectionsManager::cleanupClosedConnections(struct timeval now)
{
  //cerr<<"cleanup interval is "<<s_cleanupInterval<<", next cleanup is "<<t_nextCleanup<<", now is "<<now.tv_sec<<endl;
  if (s_cleanupInterval <= 0 || (t_nextCleanup > 0 && t_nextCleanup > now.tv_sec)) {
    return;
  }

  t_nextCleanup = now.tv_sec + s_cleanupInterval;

  struct timeval freshCutOff = now;
  freshCutOff.tv_sec -= 1;
  struct timeval idleCutOff = now;
  idleCutOff.tv_sec -= s_maxIdleTime;

  for (auto dsIt = t_downstreamConnections.begin(); dsIt != t_downstreamConnections.end();) {
    for (auto connIt = dsIt->second.begin(); connIt != dsIt->second.end();) {
      if (!(*connIt)) {
        connIt = dsIt->second.erase(connIt);
        continue;
      }

      /* don't bother checking freshly used connections */
      if (freshCutOff < (*connIt)->getLastDataReceivedTime()) {
        ++connIt;
        continue;
      }

      if ((*connIt)->isIdle() && (*connIt)->getLastDataReceivedTime() < idleCutOff) {
        /* idle for too long */
        connIt = dsIt->second.erase(connIt);
        continue;
      }

      if ((*connIt)->isUsable()) {
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

std::shared_ptr<DoHConnectionToBackend> DownstreamDoHConnectionsManager::getConnectionToDownstream(std::unique_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& ds, const struct timeval& now, std::string&& proxyProtocolPayload)
{
  std::shared_ptr<DoHConnectionToBackend> result;
  struct timeval freshCutOff = now;
  freshCutOff.tv_sec -= 1;

  auto backendId = ds->getID();

  cleanupClosedConnections(now);

  const bool haveProxyProtocol = !proxyProtocolPayload.empty();
  if (!haveProxyProtocol) {
    //cerr<<"looking for existing connection"<<endl;
    const auto& it = t_downstreamConnections.find(backendId);
    if (it != t_downstreamConnections.end()) {
      auto& list = it->second;
      for (auto listIt = list.begin(); listIt != list.end();) {
        auto& entry = *listIt;
        if (!entry->canBeReused()) {
          if (!entry->willBeReusable(false)) {
            listIt = list.erase(listIt);
          }
          else {
            ++listIt;
          }
          continue;
        }
        entry->setReused();
        /* for connections that have not been used very recently,
           check whether they have been closed in the meantime */
        if (freshCutOff < entry->getLastDataReceivedTime()) {
          /* used recently enough, skip the check */
          ++ds->tcpReusedConnections;
          return entry;
        }

        if (isTCPSocketUsable(entry->getHandle())) {
          ++ds->tcpReusedConnections;
          return entry;
        }

        /* otherwise let's try the next one, if any */
        ++listIt;
      }
    }
  }

  auto newConnection = std::make_shared<DoHConnectionToBackend>(ds, mplexer, now, std::move(proxyProtocolPayload));
  if (!haveProxyProtocol) {
    t_downstreamConnections[backendId].push_front(newConnection);
  }
  return newConnection;
}

static void handleCrossProtocolQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  auto threadData = boost::any_cast<DoHClientThreadData*>(param);
  CrossProtocolQuery* tmp{nullptr};

  ssize_t got = read(pipefd, &tmp, sizeof(tmp));
  if (got == 0) {
    throw std::runtime_error("EOF while reading from the DoH cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode");
  }
  else if (got == -1) {
    if (errno == EAGAIN || errno == EINTR) {
      return;
    }
    throw std::runtime_error("Error while reading from the DoH cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode:" + stringerror());
  }
  else if (got != sizeof(tmp)) {
    throw std::runtime_error("Partial read while reading from the DoH cross-protocol pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode");
  }

  try {
    struct timeval now;
    gettimeofday(&now, nullptr);

    std::shared_ptr<TCPQuerySender> tqs = tmp->getTCPQuerySender();
    auto query = std::move(tmp->query);
    auto downstreamServer = std::move(tmp->downstream);
    delete tmp;
    tmp = nullptr;

    try {
      auto downstream = DownstreamDoHConnectionsManager::getConnectionToDownstream(threadData->mplexer, downstreamServer, now, std::move(query.d_proxyProtocolPayload));
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

static void dohClientThread(int crossProtocolPipeFD)
{
  setThreadName("dnsdist/dohClie");

  try {
    DoHClientThreadData data;
    data.mplexer->addReadFD(crossProtocolPipeFD, handleCrossProtocolQuery, &data);

    struct timeval now;
    gettimeofday(&now, nullptr);
    time_t lastTimeoutScan = now.tv_sec;

    for (;;) {
      data.mplexer->run(&now);

      if (now.tv_sec > lastTimeoutScan) {
        lastTimeoutScan = now.tv_sec;

        try {
          DownstreamDoHConnectionsManager::cleanupClosedConnections(now);
          handleH2Timeouts(*data.mplexer, now);

          if (g_dohStatesDumpRequested > 0) {
            /* just to keep things clean in the output, debug only */
            static std::mutex s_lock;
            std::lock_guard<decltype(s_lock)> lck(s_lock);
            if (g_dohStatesDumpRequested > 0) {
              /* no race here, we took the lock so it can only be increased in the meantime */
              --g_dohStatesDumpRequested;
              errlog("Dumping the DoH client states, as requested:");
              data.mplexer->runForAllWatchedFDs([](bool isRead, int fd, const FDMultiplexer::funcparam_t& param, struct timeval ttd) {
                struct timeval lnow;
                gettimeofday(&lnow, nullptr);
                if (ttd.tv_sec > 0) {
                  errlog("- Descriptor %d is in %s state, TTD in %d", fd, (isRead ? "read" : "write"), (ttd.tv_sec - lnow.tv_sec));
                }
                else {
                  errlog("- Descriptor %d is in %s state, no TTD set", fd, (isRead ? "read" : "write"));
                }

                if (param.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
                  auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(param);
                  errlog(" - %s", conn->toString());
                }
                else if (param.type() == typeid(DoHClientThreadData*)) {
                  errlog(" - Worker thread pipe");
                }
              });
            }
          }
        }
        catch (const std::exception& e) {
          errlog("Error in outgoing DoH thread: %s", e.what());
        }
      }
    }
  }
  catch (const std::exception& e) {
    errlog("Fatal error in outgoing DoH thread: %s", e.what());
  }
}

static bool select_next_proto_callback(unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen)
{
  if (nghttp2_select_next_protocol(out, outlen, in, inlen) <= 0) {
    vinfolog("The remote DoH backend did not advertise " NGHTTP2_PROTO_VERSION_ID);
    return false;
  }
  return true;
}

#endif /* HAVE_NGHTTP2 */

struct DoHClientCollection::DoHWorkerThread
{
  DoHWorkerThread()
  {
  }

  DoHWorkerThread(int crossProtocolPipe) :
    d_crossProtocolQueryPipe(crossProtocolPipe)
  {
  }

  DoHWorkerThread(DoHWorkerThread&& rhs) :
    d_crossProtocolQueryPipe(rhs.d_crossProtocolQueryPipe)
  {
    rhs.d_crossProtocolQueryPipe = -1;
  }

  DoHWorkerThread& operator=(DoHWorkerThread&& rhs)
  {
    if (d_crossProtocolQueryPipe != -1) {
      close(d_crossProtocolQueryPipe);
    }

    d_crossProtocolQueryPipe = rhs.d_crossProtocolQueryPipe;
    rhs.d_crossProtocolQueryPipe = -1;

    return *this;
  }

  DoHWorkerThread(const DoHWorkerThread& rhs) = delete;
  DoHWorkerThread& operator=(const DoHWorkerThread&) = delete;

  ~DoHWorkerThread()
  {
    if (d_crossProtocolQueryPipe != -1) {
      close(d_crossProtocolQueryPipe);
    }
  }

  int d_crossProtocolQueryPipe{-1};
};

DoHClientCollection::DoHClientCollection(size_t numberOfThreads) :
  d_clientThreads(numberOfThreads)
{
}

bool DoHClientCollection::passCrossProtocolQueryToThread(std::unique_ptr<CrossProtocolQuery>&& cpq)
{
  if (d_numberOfThreads == 0) {
    throw std::runtime_error("No DoH worker thread yet");
  }

  uint64_t pos = d_pos++;
  auto pipe = d_clientThreads.at(pos % d_numberOfThreads).d_crossProtocolQueryPipe;
  auto tmp = cpq.release();

  if (write(pipe, &tmp, sizeof(tmp)) != sizeof(tmp)) {
    delete tmp;
    ++g_stats.outgoingDoHQueryPipeFull;
    tmp = nullptr;
    return false;
  }

  return true;
}

void DoHClientCollection::addThread()
{
#ifdef HAVE_NGHTTP2
  auto preparePipe = [](int fds[2], const std::string& type) -> bool {
    if (pipe(fds) < 0) {
      errlog("Error creating the DoH thread %s pipe: %s", type, stringerror());
      return false;
    }

    if (!setNonBlocking(fds[0])) {
      int err = errno;
      close(fds[0]);
      close(fds[1]);
      errlog("Error setting the DoH thread %s pipe non-blocking: %s", type, stringerror(err));
      return false;
    }

    if (!setNonBlocking(fds[1])) {
      int err = errno;
      close(fds[0]);
      close(fds[1]);
      errlog("Error setting the DoH thread %s pipe non-blocking: %s", type, stringerror(err));
      return false;
    }

    if (g_tcpInternalPipeBufferSize > 0 && getPipeBufferSize(fds[0]) < g_tcpInternalPipeBufferSize) {
      setPipeBufferSize(fds[0], g_tcpInternalPipeBufferSize);
    }

    return true;
  };

  int crossProtocolFDs[2] = {-1, -1};
  if (!preparePipe(crossProtocolFDs, "cross-protocol")) {
    return;
  }

  vinfolog("Adding DoH Client thread");

  {
    std::lock_guard<std::mutex> lock(d_mutex);

    if (d_numberOfThreads >= d_clientThreads.size()) {
      vinfolog("Adding a new DoH client thread would exceed the vector size (%d/%d), skipping. Consider increasing the maximum amount of DoH client threads with setMaxDoHClientThreads() in the configuration.", d_numberOfThreads, d_clientThreads.size());
      close(crossProtocolFDs[0]);
      close(crossProtocolFDs[1]);
      return;
    }

    /* from now on this side of the pipe will be managed by that object,
       no need to worry about it */
    DoHWorkerThread worker(crossProtocolFDs[1]);
    try {
      std::thread t1(dohClientThread, crossProtocolFDs[0]);
      t1.detach();
    }
    catch (const std::runtime_error& e) {
      /* the thread creation failed, don't leak */
      errlog("Error creating a DoH thread: %s", e.what());
      close(crossProtocolFDs[0]);
      return;
    }

    d_clientThreads.at(d_numberOfThreads) = std::move(worker);
    ++d_numberOfThreads;
  }
#else /* HAVE_NGHTTP2 */
  throw std::runtime_error("DoHClientCollection::addThread() called but nghttp2 support is not available");
#endif /* HAVE_NGHTTP2 */
}

bool initDoHWorkers()
{
#ifdef HAVE_NGHTTP2
  if (!g_outgoingDoHWorkerThreads) {
    /* Unless the value has been set to 0 explicitly, always start at least one outgoing DoH worker thread, in case a DoH backend
       is added at a later time. */
    g_outgoingDoHWorkerThreads = 1;
  }

  if (g_outgoingDoHWorkerThreads && *g_outgoingDoHWorkerThreads > 0) {
    g_dohClientThreads = std::make_unique<DoHClientCollection>(*g_outgoingDoHWorkerThreads);
    for (size_t idx = 0; idx < *g_outgoingDoHWorkerThreads; idx++) {
      g_dohClientThreads->addThread();
    }
  }
  return true;
#else
  return false;
#endif /* HAVE_NGHTTP2 */
}

bool setupDoHClientProtocolNegotiation(std::shared_ptr<TLSCtx>& ctx)
{
  if (ctx == nullptr) {
    return false;
  }
#ifdef HAVE_NGHTTP2
  /* we want to set the ALPN to h2, if only to mitigate the ALPACA attack */
  const std::vector<std::vector<uint8_t>> h2Alpns = {{'h', '2'}};
  ctx->setALPNProtos(h2Alpns);
  ctx->setNextProtocolSelectCallback(select_next_proto_callback);
  return true;
#else /* HAVE_NGHTTP2 */
  return false;
#endif /* HAVE_NGHTTP2 */
}

bool sendH2Query(const std::shared_ptr<DownstreamState>& ds, std::unique_ptr<FDMultiplexer>& mplexer, std::shared_ptr<TCPQuerySender>& sender, InternalQuery&& query, bool healthCheck)
{
#ifdef HAVE_NGHTTP2
  struct timeval now;
  gettimeofday(&now, nullptr);

  if (healthCheck) {
    /* always do health-checks over a new connection */
    auto newConnection = std::make_shared<DoHConnectionToBackend>(ds, mplexer, now, std::move(query.d_proxyProtocolPayload));
    newConnection->setHealthCheck(healthCheck);
    newConnection->queueQuery(sender, std::move(query));
  }
  else {
    auto connection = DownstreamDoHConnectionsManager::getConnectionToDownstream(mplexer, ds, now, std::move(query.d_proxyProtocolPayload));
    connection->queueQuery(sender, std::move(query));
  }

  return true;
#else /* HAVE_NGHTTP2 */
  return false;
#endif /* HAVE_NGHTTP2 */
}

size_t clearH2Connections()
{
  size_t cleared = 0;
#ifdef HAVE_NGHTTP2
  cleared = DownstreamDoHConnectionsManager::clear();
#endif /* HAVE_NGHTTP2 */
  return cleared;
}

size_t handleH2Timeouts(FDMultiplexer& mplexer, const struct timeval& now)
{
  size_t got = 0;
#ifdef HAVE_NGHTTP2
  auto expiredReadConns = mplexer.getTimeouts(now, false);
  for (const auto& cbData : expiredReadConns) {
    if (cbData.second.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
      auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(cbData.second);
      vinfolog("Timeout (read) from remote DoH backend %s", conn->getBackendName());
      conn->handleTimeout(now, false);
      ++got;
    }
  }

  auto expiredWriteConns = mplexer.getTimeouts(now, true);
  for (const auto& cbData : expiredWriteConns) {
    if (cbData.second.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
      auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(cbData.second);
      vinfolog("Timeout (write) from remote DoH backend %s", conn->getBackendName());
      conn->handleTimeout(now, true);
      ++got;
    }
  }
#endif /* HAVE_NGHTTP2 */
  return got;
}

void setDoHDownstreamCleanupInterval(uint16_t max)
{
  DownstreamDoHConnectionsManager::setCleanupInterval(max);
}

void setDoHDownstreamMaxIdleTime(uint16_t max)
{
  DownstreamDoHConnectionsManager::setMaxIdleTime(max);
}

void setDoHDownstreamMaxConnectionsPerBackend(size_t max)
{
  DownstreamDoHConnectionsManager::setMaxCachedConnectionsPerDownstream(max);
}
