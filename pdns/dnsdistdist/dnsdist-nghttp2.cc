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

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
#include <nghttp2/nghttp2.h>
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */

#include "dnsdist-nghttp2.hh"
#include "dnsdist-nghttp2-in.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-downstream-connection.hh"

#include "dolog.hh"
#include "channel.hh"
#include "iputils.hh"
#include "libssl.hh"
#include "noinitvector.hh"
#include "tcpiohandler.hh"
#include "threadname.hh"
#include "sstuff.hh"

std::atomic<uint64_t> g_dohStatesDumpRequested{0};
std::unique_ptr<DoHClientCollection> g_dohClientThreads{nullptr};

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
class DoHConnectionToBackend : public ConnectionToBackend
{
public:
  using StreamID = int32_t;

  DoHConnectionToBackend(const std::shared_ptr<DownstreamState>& ds, std::unique_ptr<FDMultiplexer>& mplexer, const struct timeval& now, std::string&& proxyProtocolPayload);

  void handleTimeout(const struct timeval& now, bool write) override;
  void queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query) override;

  std::string toString() const override
  {
    ostringstream o;
    o << "DoH connection to backend " << (d_ds ? d_ds->getName() : "empty") << " over FD " << (d_handler ? std::to_string(d_handler->getDescriptor()) : "no socket") << ", " << getConcurrentStreamsCount() << " streams";
    return o.str();
  }

  std::shared_ptr<const Logr::Logger> getLogger() const override
  {
    return ConnectionToBackend::getLogger()->withName("outgoing-doh-connection")->withValues("concurrent_streams", Logging::Loggable(getConcurrentStreamsCount()), "health_check_query", Logging::Loggable(d_healthCheckQuery));
  }

  void setHealthCheck(bool h)
  {
    d_healthCheckQuery = h;
  }

  void stopIO() override;
  bool reachedMaxConcurrentQueries() const override;
  bool reachedMaxStreamID() const override;
  bool isIdle() const override;
  void release(bool removeFromCache) override
  {
    (void)removeFromCache;
  }

private:
  static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data);
  static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, StreamID stream_id, const uint8_t* data, size_t len, void* user_data);
  static int on_stream_close_callback(nghttp2_session* session, StreamID stream_id, uint32_t error_code, void* user_data);
  static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data);
  static int on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data);
  static void handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param);
  static void handleWritableIOCallback(int fd, FDMultiplexer::funcparam_t& param);

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
  void updateIO(IOState newState, const FDMultiplexer::callbackfunc_t& callback, bool noTTD = false);
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

  std::unordered_map<StreamID, PendingRequest> d_currentStreams;
  std::string d_proxyProtocolPayload;
  PacketBuffer d_out;
  PacketBuffer d_in;
  std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)> d_session{nullptr, nghttp2_session_del};
  size_t d_outPos{0};
  size_t d_inPos{0};
  bool d_healthCheckQuery{false};
  bool d_firstWrite{true};
  bool d_inIOCallback{false};
};

using DownstreamDoHConnectionsManager = DownstreamConnectionsManager<DoHConnectionToBackend>;
thread_local DownstreamDoHConnectionsManager t_downstreamDoHConnectionsManager;

uint32_t DoHConnectionToBackend::getConcurrentStreamsCount() const
{
  return d_currentStreams.size();
}

void DoHConnectionToBackend::handleResponse(PendingRequest&& request)
{
  struct timeval now{
    .tv_sec = 0, .tv_usec = 0};

  gettimeofday(&now, nullptr);
  try {
    if (!d_healthCheckQuery) {
      const double udiff = request.d_query.d_idstate.queryRealTime.udiff();
      d_ds->updateTCPLatency(udiff);
      if (request.d_buffer.size() >= sizeof(dnsheader)) {
        dnsheader dh;
        memcpy(&dh, request.d_buffer.data(), sizeof(dh));
        d_ds->reportResponse(dh.rcode);
      }
      else {
        d_ds->reportTimeoutOrError();
      }
    }

    TCPResponse response(std::move(request.d_query));
    response.d_buffer = std::move(request.d_buffer);
    response.d_connection = shared_from_this();
    response.d_ds = d_ds;
    request.d_sender->handleResponse(now, std::move(response));
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Got exception while handling response for cross-protocol DoH: %s", e.what()),
                getLogger()->error(Logr::Info, e.what(), "Got exception while handling response for cross-protocol DoH"));
  }
}

void DoHConnectionToBackend::handleResponseError(PendingRequest&& request, const struct timeval& now)
{
  try {
    if (!d_healthCheckQuery) {
      d_ds->reportTimeoutOrError();
    }

    TCPResponse response(PacketBuffer(), std::move(request.d_query.d_idstate), nullptr, nullptr);
    request.d_sender->notifyIOError(now, std::move(response));
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Got exception while handling response for cross-protocol DoH: %s", e.what()),
                getLogger()->error(Logr::Info, e.what(), "Got exception while handling error for cross-protocol DoH"));
  }
}

void DoHConnectionToBackend::handleIOError()
{
  d_connectionDied = true;
  nghttp2_session_terminate_session(d_session.get(), NGHTTP2_PROTOCOL_ERROR);

  struct timeval now{
    .tv_sec = 0, .tv_usec = 0};

  const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
  const auto& timeoutRespRules = dnsdist::rules::getResponseRuleChain(chains, dnsdist::rules::ResponseRuleChain::TimeoutResponseRules);

  gettimeofday(&now, nullptr);
  for (auto& request : d_currentStreams) {
    if (!d_healthCheckQuery && handleTimeoutResponseRules(timeoutRespRules, request.second.d_query.d_idstate, d_ds, request.second.d_sender)) {
      d_ds->reportTimeoutOrError();
    }
    else {
      handleResponseError(std::move(request.second), now);
    }
  }

  d_currentStreams.clear();
  stopIO();
}

void DoHConnectionToBackend::handleTimeout(const struct timeval& now, bool write)
{
  (void)now;
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
  // cerr<<"Got "<<getConcurrentStreamsCount()<<" concurrent streams, max is "<<nghttp2_session_get_remote_settings(d_session.get(), NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS)<<endl;
  if (nghttp2_session_get_remote_settings(d_session.get(), NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS) <= getConcurrentStreamsCount()) {
    return true;
  }
  return false;
}

bool DoHConnectionToBackend::isIdle() const
{
  return getConcurrentStreamsCount() == 0;
}

void DoHConnectionToBackend::queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query)
{
  auto payloadSize = std::to_string(query.d_buffer.size());

  bool addXForwarded = d_ds->d_config.d_addXForwardedHeaders;

  /* We use nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_NAME and nghttp2_nv_flag.NGHTTP2_NV_FLAG_NO_COPY_VALUE
     to avoid a copy and lowercasing but we need to make sure that the data will outlive the request (nghttp2_on_frame_send_callback called), and that it is already lowercased. */
  std::vector<nghttp2_nv> headers;
  // these need to live until after the request headers have been processed
  std::string remote;
  std::string remotePort;
  headers.reserve(8 + (addXForwarded ? 3 : 0));

  /* Pseudo-headers need to come first (rfc7540 8.1.2.1) */
  NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::METHOD_NAME, NGHTTP2Headers::HeaderConstantIndexes::METHOD_VALUE);
  NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::SCHEME_NAME, NGHTTP2Headers::HeaderConstantIndexes::SCHEME_VALUE);
  NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::AUTHORITY_NAME, d_ds->d_config.d_tlsSubjectName);
  NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::PATH_NAME, d_ds->d_config.d_dohPath);
  NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::ACCEPT_NAME, NGHTTP2Headers::HeaderConstantIndexes::ACCEPT_VALUE);
  NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_VALUE);
  NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::USER_AGENT_NAME, NGHTTP2Headers::HeaderConstantIndexes::USER_AGENT_VALUE);
  NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_LENGTH_NAME, payloadSize);
  /* no need to add these headers for health-check queries */
  if (addXForwarded && query.d_idstate.origRemote.getPort() != 0) {
    remote = query.d_idstate.origRemote.toString();
    remotePort = std::to_string(query.d_idstate.origRemote.getPort());
    NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_FOR_NAME, remote);
    NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PORT_NAME, remotePort);
    if (query.d_idstate.cs != nullptr) {
      if (query.d_idstate.cs->isUDP()) {
        NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_NAME, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_VALUE_DNS_OVER_UDP);
      }
      else if (query.d_idstate.cs->isDoH()) {
        if (query.d_idstate.cs->hasTLS()) {
          NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_NAME, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_VALUE_DNS_OVER_HTTPS);
        }
        else {
          NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_NAME, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_VALUE_DNS_OVER_HTTP);
        }
      }
      else if (query.d_idstate.cs->hasTLS()) {
        NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_NAME, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_VALUE_DNS_OVER_TLS);
      }
      else {
        NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_NAME, NGHTTP2Headers::HeaderConstantIndexes::X_FORWARDED_PROTO_VALUE_DNS_OVER_TCP);
      }
    }
  }

  PendingRequest pending;
  pending.d_query = std::move(query);
  pending.d_sender = std::move(sender);

  uint32_t tentativeStreamId = nghttp2_session_get_next_stream_id(d_session.get());
  if (tentativeStreamId == static_cast<uint32_t>(1 << 31)) {
    /* running out of stream IDs */
    d_connectionDied = true;
    nghttp2_session_terminate_session(d_session.get(), NGHTTP2_NO_ERROR);
    throw std::runtime_error("No more stream IDs");
  }

  auto streamId = static_cast<StreamID>(tentativeStreamId);
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

  data_provider.source.ptr = this;
  data_provider.read_callback = [](nghttp2_session* session, StreamID stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* user_data) -> ssize_t {
    (void)session;
    (void)source;
    auto* conn = static_cast<DoHConnectionToBackend*>(user_data);
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

  if (!d_inIOCallback) {
    auto rtv = nghttp2_session_send(d_session.get());
    if (rtv != 0) {
      d_connectionDied = true;
      ++d_ds->tcpDiedSendingQuery;
      d_currentStreams.erase(streamId);
      throw std::runtime_error("Error in nghttp2_session_send: " + std::to_string(rtv));
    }
  }

  d_highestStreamID = newStreamId;
}

class DoHClientThreadData
{
public:
  DoHClientThreadData(pdns::channel::Receiver<CrossProtocolQuery>&& receiver) :
    mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent())),
    d_receiver(std::move(receiver))
  {
  }

  std::unique_ptr<FDMultiplexer> mplexer{nullptr};
  pdns::channel::Receiver<CrossProtocolQuery> d_receiver;
};

void DoHConnectionToBackend::handleReadableIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(param);
  if (fd != conn->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__PRETTY_FUNCTION__) + ", expected " + std::to_string(conn->getHandle()));
  }

  if (conn->d_inIOCallback) {
    return;
  }
  dnsdist::tcp::HandlingIOGuard handlingIOGuard(conn->d_inIOCallback);
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

        struct timeval now{
          .tv_sec = 0, .tv_usec = 0};

        gettimeofday(&now, nullptr);
        conn->d_lastDataReceivedTime = now;

        // cerr<<"after read send"<<endl;
        nghttp2_session_send(conn->d_session.get());
      }

      if (newState == IOState::Done) {
        if (conn->isIdle()) {
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
      VERBOSESLOG(infolog("Exception while trying to read from HTTP backend connection: %s", e.what()),
                  conn->getLogger()->error(Logr::Info, e.what(), "Exception while trying to read from HTTP backend connection"));
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
    VERBOSESLOG(infolog("Exception while trying to write (ready) to HTTP backend connection: %s", e.what()),
                conn->getLogger()->error(Logr::Info, e.what(), "Exception while trying to write (ready) to HTTP backend connection"));
    ++conn->d_ds->tcpDiedSendingQuery;
    conn->handleIOError();
  }
}

void DoHConnectionToBackend::stopIO()
{
  d_ioState->reset();

  if (isIdle()) {
    auto shared = std::dynamic_pointer_cast<DoHConnectionToBackend>(shared_from_this());
    if (!willBeReusable(false)) {
      /* remove ourselves from the connection cache, this might mean that our
         reference count drops to zero after that, so we need to be careful */
      t_downstreamDoHConnectionsManager.removeDownstreamConnection(shared);
    }
    else {
      t_downstreamDoHConnectionsManager.moveToIdle(shared);
    }
  }
}

void DoHConnectionToBackend::updateIO(IOState newState, const FDMultiplexer::callbackfunc_t& callback, bool noTTD)
{
  struct timeval now{
    .tv_sec = 0, .tv_usec = 0};

  gettimeofday(&now, nullptr);
  std::optional<struct timeval> ttd{std::nullopt};
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
      d_ioState->update(newState, callback, std::move(shared), ttd);
    }
    else if (newState == IOState::NeedWrite) {
      d_ioState->update(newState, callback, std::move(shared), ttd);
    }
  }
}

void DoHConnectionToBackend::watchForRemoteHostClosingConnection()
{
  if (willBeReusable(false) && !d_healthCheckQuery) {
    updateIO(IOState::NeedRead, handleReadableIOCallback, false);
  }
}

ssize_t DoHConnectionToBackend::send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
{
  (void)session;
  (void)flags;
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
      VERBOSESLOG(infolog("Exception while trying to write (send) to HTTP backend connection: %s", e.what()),
                  conn->getLogger()->error(Logr::Info, e.what(), "Exception while trying to write (send) to HTTP backend connection"));
      conn->handleIOError();
      ++conn->d_ds->tcpDiedSendingQuery;
    }
  }

  return length;
}

int DoHConnectionToBackend::on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
{
  (void)session;
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
        VERBOSESLOG(infolog("HTTP response has a non-200 status code: %d", request.d_responseCode),
                    conn->getLogger()->info(Logr::Info, "HTTP response has a non-200 status code", "http.stream_id", Logging::Loggable(frame->hd.stream_id), "http.response.status_code", Logging::Loggable(request.d_responseCode)));
        struct timeval now{
          .tv_sec = 0, .tv_usec = 0};

        gettimeofday(&now, nullptr);

        conn->handleResponseError(std::move(request), now);
      }

      if (conn->isIdle()) {
        conn->stopIO();
        conn->watchForRemoteHostClosingConnection();
      }
    }
    else {
      VERBOSESLOG(infolog("Stream %d NOT FOUND", frame->hd.stream_id),
                  conn->getLogger()->info(Logr::Info, "HTTP stream not found", "http.stream_id", Logging::Loggable(frame->hd.stream_id)));
      conn->d_connectionDied = true;
      ++conn->d_ds->tcpDiedReadingResponse;
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  return 0;
}

int DoHConnectionToBackend::on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, StreamID stream_id, const uint8_t* data, size_t len, void* user_data)
{
  (void)session;
  (void)flags;
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  // cerr<<"Got data of size "<<len<<" for stream "<<stream_id<<endl;
  auto stream = conn->d_currentStreams.find(stream_id);
  if (stream == conn->d_currentStreams.end()) {
    VERBOSESLOG(infolog("Unable to match the stream ID %d to a known one!", stream_id),
                conn->getLogger()->info(Logr::Info, "Unable to match the stream ID to a known one", "http.stream_id", Logging::Loggable(stream_id)));
    conn->d_connectionDied = true;
    ++conn->d_ds->tcpDiedReadingResponse;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  if (len > std::numeric_limits<uint16_t>::max() || (std::numeric_limits<uint16_t>::max() - stream->second.d_buffer.size()) < len) {
    VERBOSESLOG(infolog("Data frame of size %d is too large for a DNS response (we already have %d)", len, stream->second.d_buffer.size()),
                conn->getLogger()->info(Logr::Info, "Data frame is too large for a DNS response", "http.stream_id", Logging::Loggable(stream_id), "frame_size", Logging::Loggable(len), "existing_payload_size", Logging::Loggable(stream->second.d_buffer.size())));
    conn->d_connectionDied = true;
    ++conn->d_ds->tcpDiedReadingResponse;
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  stream->second.d_buffer.insert(stream->second.d_buffer.end(), data, data + len);
  if (stream->second.d_finished) {
    auto request = std::move(stream->second);
    conn->d_currentStreams.erase(stream->first);
    if (request.d_responseCode == 200U) {
      conn->handleResponse(std::move(request));
    }
    else {
      VERBOSESLOG(infolog("HTTP response has a non-200 status code: %d", request.d_responseCode),
                  conn->getLogger()->info(Logr::Info, "HTTP response has a non-200 status code", "http.response.status_code", Logging::Loggable(request.d_responseCode), "http.stream_id", Logging::Loggable(stream_id)));
      struct timeval now{
        .tv_sec = 0, .tv_usec = 0};

      gettimeofday(&now, nullptr);

      conn->handleResponseError(std::move(request), now);
    }
    if (conn->isIdle()) {
      conn->stopIO();
      conn->watchForRemoteHostClosingConnection();
    }
  }

  return 0;
}

int DoHConnectionToBackend::on_stream_close_callback(nghttp2_session* session, StreamID stream_id, uint32_t error_code, void* user_data)
{
  (void)session;
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

  struct timeval now{
    .tv_sec = 0, .tv_usec = 0};

  gettimeofday(&now, nullptr);
  auto request = std::move(stream->second);
  conn->d_currentStreams.erase(stream->first);

  // cerr<<"Query has "<<request.d_query.d_downstreamFailures<<" failures, backend limit is "<<conn->d_ds->d_retries<<endl;
  if (request.d_query.d_downstreamFailures < conn->d_ds->d_config.d_retries) {
    // cerr<<"in "<<__PRETTY_FUNCTION__<<", looking for a connection to send a query of size "<<request.d_query.d_buffer.size()<<endl;
    ++request.d_query.d_downstreamFailures;
    auto downstream = t_downstreamDoHConnectionsManager.getConnectionToDownstream(conn->d_mplexer, conn->d_ds, now, std::string(conn->d_proxyProtocolPayload));
    downstream->queueQuery(request.d_sender, std::move(request.d_query));
  }
  else {
    conn->handleResponseError(std::move(request), now);
  }

  // cerr<<"we now have "<<conn->getConcurrentStreamsCount()<<" concurrent connections"<<endl;
  if (conn->isIdle()) {
    // cerr<<"stopping IO"<<endl;
    conn->stopIO();
    conn->watchForRemoteHostClosingConnection();
  }

  return 0;
}

int DoHConnectionToBackend::on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
{
  (void)session;
  (void)flags;
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);

  const std::string status(":status");
  if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
    // cerr<<"got header for "<<frame->hd.stream_id<<":"<<endl;
    // cerr<<"- "<<std::string(reinterpret_cast<const char*>(name), namelen)<<endl;
    // cerr<<"- "<<std::string(reinterpret_cast<const char*>(value), valuelen)<<endl;
    if (namelen == status.size() && memcmp(status.data(), name, status.size()) == 0) {
      auto stream = conn->d_currentStreams.find(frame->hd.stream_id);
      if (stream == conn->d_currentStreams.end()) {
        VERBOSESLOG(infolog("Unable to match the stream ID %d to a known one!", frame->hd.stream_id),
                    conn->getLogger()->info(Logr::Info, "Unable to match the stream ID %d to a known one", "http.stream_id", Logging::Loggable(frame->hd.stream_id)));
        conn->d_connectionDied = true;
        return NGHTTP2_ERR_CALLBACK_FAILURE;
      }
      try {
        pdns::checked_stoi_into(stream->second.d_responseCode, std::string(reinterpret_cast<const char*>(value), valuelen));
      }
      catch (...) {
        VERBOSESLOG(infolog("Error parsing the status header for stream ID %d", frame->hd.stream_id),
                    conn->getLogger()->info(Logr::Info, "Error parsing the status header", "http.stream_id", Logging::Loggable(frame->hd.stream_id)));
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
  (void)session;
  DoHConnectionToBackend* conn = reinterpret_cast<DoHConnectionToBackend*>(user_data);
  VERBOSESLOG(infolog("Error in HTTP/2 connection: %s (%d)", std::string(msg, len), lib_error_code),
              conn->getLogger()->error(Logr::Info, std::string(msg, len), "Error in HTTP/2 connection", "nghttp2.error_code", Logging::Loggable(lib_error_code)));

  conn->d_connectionDied = true;
  ++conn->d_ds->tcpDiedReadingResponse;

  return 0;
}

DoHConnectionToBackend::DoHConnectionToBackend(const std::shared_ptr<DownstreamState>& ds, std::unique_ptr<FDMultiplexer>& mplexer, const struct timeval& now, std::string&& proxyProtocolPayload) :
  ConnectionToBackend(ds, mplexer, now), d_proxyProtocolPayload(std::move(proxyProtocolPayload))
{
  // inherit most of the stuff from the ConnectionToBackend()
  d_ioState = make_unique<IOStateHandler>(*d_mplexer, d_handler->getDescriptor());

  nghttp2_session_callbacks* cbs = nullptr;
  if (nghttp2_session_callbacks_new(&cbs) != 0) {
    d_connectionDied = true;
    ++d_ds->tcpDiedSendingQuery;
    VERBOSESLOG(infolog("Unable to create a callback object for a new HTTP/2 session"),
                ConnectionToBackend::getLogger()->info(Logr::Info, "Unable to create a callback object for a new HTTP/2 session"));
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
    VERBOSESLOG(infolog("Could not allocate a new HTTP/2 session"),
                ConnectionToBackend::getLogger()->info(Logr::Info, "Could not allocate a new HTTP/2 session"));
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
    VERBOSESLOG(infolog("Could not submit SETTINGS: %s", nghttp2_strerror(rv)),
                ConnectionToBackend::getLogger()->error(Logr::Info, nghttp2_strerror(rv), "Could not submit SETTINGS"));
    return;
  }
}

static void handleCrossProtocolQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  (void)pipefd;
  auto threadData = boost::any_cast<DoHClientThreadData*>(param);

  std::unique_ptr<CrossProtocolQuery> cpq{nullptr};
  try {
    auto tmp = threadData->d_receiver.receive();
    if (!tmp) {
      return;
    }
    cpq = std::move(*tmp);
  }
  catch (const std::exception& e) {
    throw std::runtime_error("Error while reading from the DoH cross-protocol channel:" + std::string(e.what()));
  }

  struct timeval now{
    .tv_sec = 0, .tv_usec = 0};
  gettimeofday(&now, nullptr);

  std::shared_ptr<TCPQuerySender> tqs = cpq->getTCPQuerySender();
  auto query = std::move(cpq->query);
  auto downstreamServer = std::move(cpq->downstream);
  cpq.reset();

  try {
    auto downstream = t_downstreamDoHConnectionsManager.getConnectionToDownstream(threadData->mplexer, downstreamServer, now, std::move(query.d_proxyProtocolPayload));
    downstream->queueQuery(tqs, std::move(query));
  }
  catch (...) {
    TCPResponse response(std::move(query));
    tqs->notifyIOError(now, std::move(response));
  }
}

static void dohClientThread(pdns::channel::Receiver<CrossProtocolQuery>&& receiver)
{
  setThreadName("dnsdist/dohClie");
  auto logger = dnsdist::logging::getTopLogger("outgoing-doh-worker");

  try {
    DoHClientThreadData data(std::move(receiver));
    data.mplexer->addReadFD(data.d_receiver.getDescriptor(), handleCrossProtocolQuery, &data);

    struct timeval now{
      .tv_sec = 0, .tv_usec = 0};

    gettimeofday(&now, nullptr);
    time_t lastTimeoutScan = now.tv_sec;
    time_t lastConfigRefresh = now.tv_sec;

    for (;;) {
      data.mplexer->run(&now, 1000);

      if (now.tv_sec > lastConfigRefresh) {
        lastConfigRefresh = now.tv_sec;
        dnsdist::configuration::refreshLocalRuntimeConfiguration();
      }

      if (now.tv_sec > lastTimeoutScan) {
        lastTimeoutScan = now.tv_sec;

        try {
          t_downstreamDoHConnectionsManager.cleanupClosedConnections(now);
          handleH2Timeouts(*data.mplexer, now);

          if (g_dohStatesDumpRequested > 0) {
            /* just to keep things clean in the output, debug only */
            static std::mutex s_lock;
            auto lock = std::scoped_lock(s_lock);
            if (g_dohStatesDumpRequested > 0) {
              /* no race here, we took the lock so it can only be increased in the meantime */
              --g_dohStatesDumpRequested;
              /* no point dumping these in structured format */
              infolog("Dumping the DoH client states, as requested:");
              data.mplexer->runForAllWatchedFDs([](bool isRead, int fd, const FDMultiplexer::funcparam_t& param, struct timeval ttd) {
                struct timeval lnow;
                gettimeofday(&lnow, nullptr);
                if (ttd.tv_sec > 0) {
                  infolog("- Descriptor %d is in %s state, TTD in %d", fd, (isRead ? "read" : "write"), (ttd.tv_sec - lnow.tv_sec));
                }
                else {
                  infolog("- Descriptor %d is in %s state, no TTD set", fd, (isRead ? "read" : "write"));
                }

                if (param.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
                  auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(param);
                  infolog(" - %s", conn->toString());
                }
                else if (param.type() == typeid(DoHClientThreadData*)) {
                  infolog(" - Worker thread pipe");
                }
              });
              infolog("The DoH client cache has %d active and %d idle outgoing connections cached", t_downstreamDoHConnectionsManager.getActiveCount(), t_downstreamDoHConnectionsManager.getIdleCount());
            }
          }
        }
        catch (const std::exception& e) {
          SLOG(warnlog("Error in outgoing DoH thread: %s", e.what()),
               logger->error(Logr::Warning, e.what(), "Error in outgoing DoH thread"));
        }
      }
    }
  }
  catch (const std::exception& e) {
    SLOG(errlog("Fatal error in outgoing DoH thread: %s", e.what()),
         logger->error(Logr::Error, e.what(), "Fatal error in outgoing DoH thread"));
  }
}
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */

struct DoHClientCollection::DoHWorkerThread
{
  DoHWorkerThread()
  {
  }

  DoHWorkerThread(pdns::channel::Sender<CrossProtocolQuery>&& sender) noexcept :
    d_sender(std::move(sender))
  {
  }

  DoHWorkerThread(DoHWorkerThread&& rhs) noexcept = default;
  DoHWorkerThread& operator=(DoHWorkerThread&& rhs) noexcept = default;
  DoHWorkerThread(const DoHWorkerThread& rhs) = delete;
  DoHWorkerThread& operator=(const DoHWorkerThread&) = delete;

  pdns::channel::Sender<CrossProtocolQuery> d_sender;
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
  if (!d_clientThreads.at(pos % d_numberOfThreads).d_sender.send(std::move(cpq))) {
    ++dnsdist::metrics::g_stats.outgoingDoHQueryPipeFull;
    return false;
  }

  return true;
}

void DoHClientCollection::addThread()
{
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  try {
    const auto internalPipeBufferSize = dnsdist::configuration::getImmutableConfiguration().d_tcpInternalPipeBufferSize;
    auto [sender, receiver] = pdns::channel::createObjectQueue<CrossProtocolQuery>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, internalPipeBufferSize);

    VERBOSESLOG(infolog("Adding DoH Client thread"),
                dnsdist::logging::getTopLogger("outgoing-doh")->info(Logr::Info, "Adding outgoing DoH worker thread"));

    auto lock = std::scoped_lock(d_mutex);
    if (d_numberOfThreads >= d_clientThreads.size()) {
      VERBOSESLOG(infolog("Adding a new DoH client thread would exceed the vector size (%d/%d), skipping. Consider increasing the maximum amount of DoH client threads with setMaxDoHClientThreads() in the configuration.", d_numberOfThreads, d_clientThreads.size()),
                  dnsdist::logging::getTopLogger("outgoing-doh")->info(Logr::Info, "Adding a new outgoing DoH worker thread would exceed the vector size, skipping. Consider increasing the maximum amount of DoH worker threads with setMaxDoHClientThreads() in the configuration.", "workers_count", Logging::Loggable(d_numberOfThreads), "workers_limit", Logging::Loggable(d_clientThreads.size())));
      return;
    }

    DoHWorkerThread worker(std::move(sender));
    try {
      std::thread t1(dohClientThread, std::move(receiver));
      t1.detach();
    }
    catch (const std::runtime_error& e) {
      /* the thread creation failed */
      SLOG(errlog("Error creating a DoH thread: %s", e.what()),
           dnsdist::logging::getTopLogger("outgoing-doh")->error(Logr::Error, e.what(), "Error creating an outgoing DoH worker thread"));
      return;
    }

    d_clientThreads.at(d_numberOfThreads) = std::move(worker);
    ++d_numberOfThreads;
  }
  catch (const std::exception& e) {
    SLOG(errlog("Error creating the DoH channel: %s", e.what()),
         dnsdist::logging::getTopLogger("outgoing-doh")->error(Logr::Error, e.what(), "Error creating a channel for a new outgoing DoH worker"));
    return;
  }
#else /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
  throw std::runtime_error("DoHClientCollection::addThread() called but nghttp2 support is not available");
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
}

bool initDoHWorkers()
{
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  auto outgoingDoHWorkerThreads = dnsdist::configuration::getImmutableConfiguration().d_outgoingDoHWorkers;
  if (!outgoingDoHWorkerThreads) {
    /* Unless the value has been set to 0 explicitly, always start at least one outgoing DoH worker thread, in case a DoH backend
       is added at a later time. */
    outgoingDoHWorkerThreads = 1;
  }

  if (outgoingDoHWorkerThreads && *outgoingDoHWorkerThreads > 0) {
    g_dohClientThreads = std::make_unique<DoHClientCollection>(*outgoingDoHWorkerThreads);
    for (size_t idx = 0; idx < *outgoingDoHWorkerThreads; idx++) {
      g_dohClientThreads->addThread();
    }
  }
  return true;
#else
  return false;
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
}

bool sendH2Query([[maybe_unused]] const std::shared_ptr<DownstreamState>& downstream, [[maybe_unused]] std::unique_ptr<FDMultiplexer>& mplexer, [[maybe_unused]] std::shared_ptr<TCPQuerySender>& sender, [[maybe_unused]] InternalQuery&& query, [[maybe_unused]] bool healthCheck)
{
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  struct timeval now{
    .tv_sec = 0, .tv_usec = 0};
  gettimeofday(&now, nullptr);

  if (healthCheck) {
    /* always do health-checks over a new connection */
    auto newConnection = std::make_shared<DoHConnectionToBackend>(downstream, mplexer, now, std::move(query.d_proxyProtocolPayload));
    newConnection->setHealthCheck(healthCheck);
    newConnection->queueQuery(sender, std::move(query));
  }
  else {
    auto connection = t_downstreamDoHConnectionsManager.getConnectionToDownstream(mplexer, downstream, now, std::move(query.d_proxyProtocolPayload));
    connection->queueQuery(sender, std::move(query));
  }

  return true;
#else /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
  return false;
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
}

size_t clearH2Connections()
{
  size_t cleared = 0;
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  cleared = t_downstreamDoHConnectionsManager.clear();
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
  return cleared;
}

size_t handleH2Timeouts([[maybe_unused]] FDMultiplexer& mplexer, [[maybe_unused]] const struct timeval& now)
{
  size_t got = 0;
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  auto expiredReadConns = mplexer.getTimeouts(now, false);
  for (const auto& cbData : expiredReadConns) {
    if (cbData.second.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
      auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(cbData.second);
      VERBOSESLOG(infolog("Timeout (read) from remote DoH backend %s", conn->getBackendName()),
                  conn->getLogger()->info(Logr::Info, "Timeout (read) from remote DoH backend"));
      conn->handleTimeout(now, false);
      ++got;
    }
  }

  auto expiredWriteConns = mplexer.getTimeouts(now, true);
  for (const auto& cbData : expiredWriteConns) {
    if (cbData.second.type() == typeid(std::shared_ptr<DoHConnectionToBackend>)) {
      auto conn = boost::any_cast<std::shared_ptr<DoHConnectionToBackend>>(cbData.second);
      VERBOSESLOG(infolog("Timeout (write) from remote DoH backend %s", conn->getBackendName()),
                  conn->getLogger()->info(Logr::Info, "Timeout (write) from remote DoH backend"));
      conn->handleTimeout(now, true);
      ++got;
    }
  }
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
  return got;
}

void setDoHDownstreamCleanupInterval([[maybe_unused]] uint16_t max)
{
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  DownstreamDoHConnectionsManager::setCleanupInterval(max);
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
}

void setDoHDownstreamMaxIdleTime([[maybe_unused]] uint16_t max)
{
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  DownstreamDoHConnectionsManager::setMaxIdleTime(max);
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
}

void setDoHDownstreamMaxIdleConnectionsPerBackend([[maybe_unused]] size_t max)
{
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  DownstreamDoHConnectionsManager::setMaxIdleConnectionsPerDownstream(max);
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
}
