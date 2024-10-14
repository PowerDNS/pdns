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
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnswriter.hh"
#include "dnsdist.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-nghttp2.hh"
#include "sstuff.hh"

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
#include <nghttp2/nghttp2.h>

BOOST_AUTO_TEST_SUITE(test_dnsdistnghttp2_cc)

struct ExpectedStep
{
public:
  enum class ExpectedRequest
  {
    handshakeClient,
    readFromClient,
    writeToClient,
    closeClient,
    connectToBackend,
    readFromBackend,
    writeToBackend,
    closeBackend
  };

  ExpectedStep(ExpectedRequest r, IOState n, size_t b = 0, std::function<void(int descriptor)> fn = nullptr) :
    cb(fn), request(r), nextState(n), bytes(b)
  {
  }

  std::function<void(int descriptor)> cb{nullptr};
  ExpectedRequest request;
  IOState nextState;
  size_t bytes{0};
};

struct ExpectedData
{
  PacketBuffer d_query;
  PacketBuffer d_response;
};

static std::deque<ExpectedStep> s_steps;
static std::map<uint16_t, ExpectedData> s_responses;
static std::unique_ptr<FDMultiplexer> s_mplexer;

std::ostream& operator<<(std::ostream& os, const ExpectedStep::ExpectedRequest d);

std::ostream& operator<<(std::ostream& os, const ExpectedStep::ExpectedRequest d)
{
  static const std::vector<std::string> requests = {"handshake with client", "read from client", "write to client", "close connection to client", "connect to the backend", "read from the backend", "write to the backend", "close connection to backend"};
  os << requests.at(static_cast<size_t>(d));
  return os;
}

class DOHConnection
{
public:
  DOHConnection(bool needProxyProtocol) :
    d_session(std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)>(nullptr, nghttp2_session_del)), d_needProxyProtocol(needProxyProtocol)
  {
    nghttp2_session_callbacks* cbs = nullptr;
    nghttp2_session_callbacks_new(&cbs);
    std::unique_ptr<nghttp2_session_callbacks, void (*)(nghttp2_session_callbacks*)> callbacks(cbs, nghttp2_session_callbacks_del);
    cbs = nullptr;
    nghttp2_session_callbacks_set_send_callback(callbacks.get(), send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), on_stream_close_callback);
    nghttp2_session* sess = nullptr;
    nghttp2_session_server_new(&sess, callbacks.get(), this);
    d_session = std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)>(sess, nghttp2_session_del);

    nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
    nghttp2_submit_settings(d_session.get(), NGHTTP2_FLAG_NONE, iv, sizeof(iv) / sizeof(*iv));
  }

  PacketBuffer d_serverOutBuffer;
  PacketBuffer d_proxyProtocolBuffer;
  std::map<uint32_t, PacketBuffer> d_queries;
  std::map<uint32_t, PacketBuffer> d_responses;
  std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)> d_session;
  /* used to replace the stream ID in outgoing frames. Ugly but the library does not let us
     test weird cases without that */
  std::map<uint32_t, uint32_t> d_idMapping;
  bool d_needProxyProtocol;

  size_t submitIncoming(const PacketBuffer& data, size_t pos, size_t toWrite)
  {
    size_t consumed = 0;
    if (d_needProxyProtocol) {
      do {
        auto bytesRemaining = isProxyHeaderComplete(d_proxyProtocolBuffer);
        if (bytesRemaining < 0) {
          size_t toConsume = toWrite > static_cast<size_t>(-bytesRemaining) ? static_cast<size_t>(-bytesRemaining) : toWrite;
          d_proxyProtocolBuffer.insert(d_proxyProtocolBuffer.end(), data.begin() + pos, data.begin() + pos + toConsume);
          pos += toConsume;
          toWrite -= toConsume;
          consumed += toConsume;

          bytesRemaining = isProxyHeaderComplete(d_proxyProtocolBuffer);
          if (bytesRemaining > 0) {
            d_needProxyProtocol = false;
          }
          else if (bytesRemaining == 0) {
            throw("Fatal error while parsing proxy protocol payload");
          }
        }
        else if (bytesRemaining == 0) {
          throw("Fatal error while parsing proxy protocol payload");
        }

        if (toWrite == 0) {
          return consumed;
        }
      } while (d_needProxyProtocol && toWrite > 0);
    }

    ssize_t readlen = nghttp2_session_mem_recv(d_session.get(), &data.at(pos), toWrite);
    if (readlen < 0) {
      throw("Fatal error while submitting: " + std::string(nghttp2_strerror(static_cast<int>(readlen))));
    }

    /* just in case, see if we have anything to send */
    int rv = nghttp2_session_send(d_session.get());
    if (rv != 0) {
      throw("Fatal error while sending: " + std::string(nghttp2_strerror(rv)));
    }

    return readlen;
  }

  void submitResponse(uint32_t streamId, PacketBuffer& data)
  {
    const nghttp2_nv hdrs[] = {{(uint8_t*)":status", (uint8_t*)"200", sizeof(":status") - 1, sizeof("200") - 1, NGHTTP2_NV_FLAG_NONE}};
    nghttp2_data_provider dataProvider;
    dataProvider.source.ptr = &data;
    dataProvider.read_callback = [](nghttp2_session* session, int32_t stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* user_data) -> ssize_t {
      (void)session;
      (void)stream_id;
      (void)user_data;
      auto buffer = reinterpret_cast<PacketBuffer*>(source->ptr);
      size_t toCopy = 0;
      if (buffer->size() > 0) {
        toCopy = length > buffer->size() ? buffer->size() : length;
        memcpy(buf, &buffer->at(0), toCopy);
        buffer->erase(buffer->begin(), buffer->begin() + toCopy);
      }

      if (buffer->size() == 0) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
      }
      // cerr<<"submitting response data of size "<<toCopy<<" for stream "<<stream_id<<endl;
      return toCopy;
    };

    int rv = nghttp2_submit_response(d_session.get(), streamId, hdrs, sizeof(hdrs) / sizeof(*hdrs), &dataProvider);
    // cerr<<"Submitting response for stream ID "<<streamId<<": "<<rv<<endl;
    BOOST_CHECK_EQUAL(rv, 0);
    /* just in case, see if we have anything to send */
    rv = nghttp2_session_send(d_session.get());
    BOOST_CHECK_EQUAL(rv, 0);
  }

  void submitError(uint32_t streamId, uint16_t status, const std::string& msg)
  {
    (void)msg;
    const std::string statusStr = std::to_string(status);
    const nghttp2_nv hdrs[] = {{(uint8_t*)":status", (uint8_t*)statusStr.c_str(), sizeof(":status") - 1, statusStr.size(), NGHTTP2_NV_FLAG_NONE}};

    int rv = nghttp2_submit_response(d_session.get(), streamId, hdrs, sizeof(hdrs) / sizeof(*hdrs), nullptr);
    BOOST_CHECK_EQUAL(rv, 0);
    /* just in case, see if we have anything to send */
    rv = nghttp2_session_send(d_session.get());
    BOOST_CHECK_EQUAL(rv, 0);
  }

  void submitGoAway()
  {
    int rv = nghttp2_submit_goaway(d_session.get(), NGHTTP2_FLAG_NONE, 0, NGHTTP2_INTERNAL_ERROR, nullptr, 0);
    BOOST_CHECK_EQUAL(rv, 0);
    /* just in case, see if we have anything to send */
    rv = nghttp2_session_send(d_session.get());
    BOOST_CHECK_EQUAL(rv, 0);
  }

private:
  static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
  {
    (void)session;
    (void)flags;
    DOHConnection* conn = reinterpret_cast<DOHConnection*>(user_data);
    // cerr<<"inserting "<<length<<" bytes into the server output buffer of size "<<conn->d_serverOutBuffer.size()<<endl;
    if (!conn->d_idMapping.empty() && length > 9) {
      /* frame type == DATA */
      if (data[3] == NGHTTP2_DATA) {
        uint32_t streamId = 0;
        memcpy(&streamId, &data[5], sizeof(streamId));
        const auto it = conn->d_idMapping.find(ntohl(streamId));
        if (it != conn->d_idMapping.end()) {
          streamId = htonl(it->second);
          std::vector<uint8_t> editedData(length);
          std::copy(data, data + length, editedData.begin());
          memcpy(&editedData.at(5), &streamId, sizeof(streamId));
          conn->d_serverOutBuffer.insert(conn->d_serverOutBuffer.end(), editedData.data(), editedData.data() + length);
          return static_cast<ssize_t>(editedData.size());
        }
      }
    }

    conn->d_serverOutBuffer.insert(conn->d_serverOutBuffer.end(), data, data + length);
    return static_cast<ssize_t>(length);
  }

  static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    (void)session;
    DOHConnection* conn = reinterpret_cast<DOHConnection*>(user_data);
    // cerr<<"Frame type is "<<std::to_string(frame->hd.type)<<endl;
    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
#if 0
      auto stream_data = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after on_stream_close_callback. Check that stream still alive. */
      if (stream_data == nullptr) {
        cerr<<"unable to find stream data!"<<endl;
        return 0;
      }
#endif

      auto& query = conn->d_queries.at(frame->hd.stream_id);
      BOOST_REQUIRE_GT(query.size(), sizeof(dnsheader));
      const dnsheader_aligned dh(query.data());
      uint16_t id = ntohs(dh->id);
      // cerr<<"got query ID "<<id<<endl;

      const auto& expected = s_responses.at(id);
      BOOST_REQUIRE_EQUAL(expected.d_query.size(), query.size());
      for (size_t idx = 0; idx < query.size(); idx++) {
        if (expected.d_query.at(idx) != query.at(idx)) {
          cerr << "Mismatch at offset " << idx << ", expected " << std::to_string(query.at(idx)) << " got " << std::to_string(expected.d_query.at(idx)) << endl;
          BOOST_CHECK(false);
        }
      }

      DNSName qname(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false);
      if (qname == DNSName("goaway.powerdns.com.")) {
        conn->submitGoAway();
      }
      else if (qname == DNSName("500.powerdns.com.") && (id % 2) == 0) {
        /* we return a 500 on the first query only */
        conn->submitError(frame->hd.stream_id, 500, "Server failure");
      }
      else if (qname == DNSName("wrong-stream-id.powerdns.com.") && (id % 2) == 0) {
        /* we return a wrong stremad ID on the first query only */
        BOOST_CHECK_EQUAL(frame->hd.stream_id, 1);
        conn->d_responses[frame->hd.stream_id] = expected.d_response;
        /* use an invalid stream ID! */
        conn->d_idMapping[frame->hd.stream_id] = frame->hd.stream_id + 4;
        conn->submitResponse(frame->hd.stream_id, conn->d_responses.at(frame->hd.stream_id));
      }
      else {
        conn->d_responses[frame->hd.stream_id] = expected.d_response;
        conn->submitResponse(frame->hd.stream_id, conn->d_responses.at(frame->hd.stream_id));
      }
      conn->d_queries.erase(frame->hd.stream_id);
    }

    return 0;
  }

  static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data)
  {
    (void)session;
    (void)flags;
    DOHConnection* conn = reinterpret_cast<DOHConnection*>(user_data);
    auto& query = conn->d_queries[stream_id];
    query.insert(query.end(), data, data + len);
    return 0;
  }

  static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data)
  {
    (void)session;
    (void)stream_id;
    (void)user_data;
    if (error_code == 0) {
      return 0;
    }

    return 0;
  }
};

static std::map<int, std::unique_ptr<DOHConnection>> s_connectionBuffers;

class MockupTLSConnection : public TLSConnection
{
public:
  MockupTLSConnection(int descriptor, bool client = false, bool needProxyProtocol = false) :
    d_descriptor(descriptor), d_client(client)
  {
    s_connectionBuffers[d_descriptor] = std::make_unique<DOHConnection>(needProxyProtocol);
  }

  ~MockupTLSConnection() {}

  IOState tryHandshake() override
  {
    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::handshakeClient);

    return step.nextState;
  }

  IOState tryWrite(const PacketBuffer& buffer, size_t& pos, size_t toWrite) override
  {
    auto& conn = s_connectionBuffers.at(d_descriptor);
    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, !d_client ? ExpectedStep::ExpectedRequest::writeToClient : ExpectedStep::ExpectedRequest::writeToBackend);

    if (step.bytes == 0) {
      if (step.nextState == IOState::NeedWrite) {
        return step.nextState;
      }
      throw std::runtime_error("Remote host closed the connection");
    }

    toWrite -= pos;
    BOOST_REQUIRE_GE(buffer.size(), pos + toWrite);

    if (step.bytes < toWrite) {
      toWrite = step.bytes;
    }

    conn->submitIncoming(buffer, pos, toWrite);
    pos += toWrite;

    return step.nextState;
  }

  IOState tryRead(PacketBuffer& buffer, size_t& pos, size_t toRead, bool allowIncomplete = false) override
  {
    auto& conn = s_connectionBuffers.at(d_descriptor);
    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, !d_client ? ExpectedStep::ExpectedRequest::readFromClient : ExpectedStep::ExpectedRequest::readFromBackend);

    if (step.bytes == 0) {
      if (step.nextState == IOState::NeedRead) {
        return step.nextState;
      }
      throw std::runtime_error("Remote host closed the connection");
    }

    auto& externalBuffer = conn->d_serverOutBuffer;
    toRead -= pos;

    if (step.bytes < toRead) {
      toRead = step.bytes;
    }
    if (allowIncomplete) {
      if (toRead > externalBuffer.size()) {
        toRead = externalBuffer.size();
      }
    }
    else {
      BOOST_REQUIRE_GE(externalBuffer.size(), toRead);
    }

    BOOST_REQUIRE_GE(buffer.size(), toRead);

    std::copy(externalBuffer.begin(), externalBuffer.begin() + toRead, buffer.begin() + pos);
    pos += toRead;
    externalBuffer.erase(externalBuffer.begin(), externalBuffer.begin() + toRead);

    return step.nextState;
  }

  IOState tryConnect(bool fastOpen, const ComboAddress& remote) override
  {
    (void)fastOpen;
    (void)remote;
    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::connectToBackend);

    return step.nextState;
  }

  void close() override
  {
    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, !d_client ? ExpectedStep::ExpectedRequest::closeClient : ExpectedStep::ExpectedRequest::closeBackend);
  }

  bool isUsable() const override
  {
    return true;
  }

  std::string getServerNameIndication() const override
  {
    return "";
  }

  std::vector<uint8_t> getNextProtocol() const override
  {
    return std::vector<uint8_t>();
  }

  LibsslTLSVersion getTLSVersion() const override
  {
    return LibsslTLSVersion::TLS13;
  }

  bool hasSessionBeenResumed() const override
  {
    return false;
  }

  std::vector<std::unique_ptr<TLSSession>> getSessions() override
  {
    return {};
  }

  void setSession(std::unique_ptr<TLSSession>& session) override
  {
    (void)session;
  }

  std::vector<int> getAsyncFDs() override
  {
    return {};
  }

  /* unused in that context, don't bother */
  void doHandshake() override
  {
  }

  void connect(bool fastOpen, const ComboAddress& remote, const struct timeval& timeout) override
  {
    (void)fastOpen;
    (void)remote;
    (void)timeout;
  }

  size_t read(void* buffer, size_t bufferSize, const struct timeval& readTimeout, const struct timeval& totalTimeout = {0, 0}, bool allowIncomplete = false) override
  {
    (void)buffer;
    (void)bufferSize;
    (void)readTimeout;
    (void)totalTimeout;
    (void)allowIncomplete;
    return 0;
  }

  size_t write(const void* buffer, size_t bufferSize, const struct timeval& writeTimeout) override
  {
    (void)buffer;
    (void)bufferSize;
    (void)writeTimeout;
    return 0;
  }

private:
  ExpectedStep getStep() const
  {
    BOOST_REQUIRE(!s_steps.empty());
    auto step = s_steps.front();
    s_steps.pop_front();

    if (step.cb) {
      step.cb(d_descriptor);
    }

    return step;
  }

  const int d_descriptor;
  bool d_client{false};
};

#include "test-dnsdistnghttp2_common.hh"

class MockupQuerySender : public TCPQuerySender
{
public:
  bool active() const override
  {
    return true;
  }

  void handleResponse(const struct timeval& now, TCPResponse&& response) override
  {
    if (d_customHandler) {
      d_customHandler(d_id, now, std::move(response));
      return;
    }

    BOOST_REQUIRE_GT(response.d_buffer.size(), sizeof(dnsheader));
    const dnsheader_aligned dh(response.d_buffer.data());
    uint16_t id = ntohs(dh->id);

    BOOST_REQUIRE_EQUAL(id, d_id);
    const auto& expected = s_responses.at(id);
    BOOST_REQUIRE_EQUAL(expected.d_response.size(), response.d_buffer.size());
    for (size_t idx = 0; idx < response.d_buffer.size(); idx++) {
      if (expected.d_response.at(idx) != response.d_buffer.at(idx)) {
        cerr << "Mismatch at offset " << idx << ", expected " << std::to_string(response.d_buffer.at(idx)) << " got " << std::to_string(expected.d_response.at(idx)) << endl;
        BOOST_CHECK(false);
      }
    }

    if (expected.d_response != response.d_buffer) {
      BOOST_REQUIRE(false);
    }
    d_valid = true;
  }

  void handleXFRResponse([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
  }

  void notifyIOError([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
    d_error = true;
  }

  std::function<void(uint16_t id, const struct timeval& now, TCPResponse&& response)> d_customHandler;
  uint16_t d_id{0};
  bool d_valid{false};
  bool d_error{false};
};

struct TestFixture
{
  TestFixture()
  {
    s_steps.clear();
    s_responses.clear();
    s_mplexer = std::make_unique<MockupFDMultiplexer>();
  }
  ~TestFixture()
  {
    clearH2Connections();
    s_steps.clear();
    s_responses.clear();
    s_mplexer.reset();
  }
};

BOOST_FIXTURE_TEST_CASE(test_SingleQuery, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  size_t counter = 1;
  DNSName name("powerdns.com.");
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  pwQ.getHeader()->id = htons(counter);

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
  pwR.getHeader()->qr = 1;
  pwR.getHeader()->rd = 1;
  pwR.getHeader()->ra = 1;
  pwR.getHeader()->id = htons(counter);
  pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
  pwR.xfr32BitInt(0x01020304);
  pwR.commit();

  s_responses[counter] = {query, response};

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  auto sender = std::make_shared<MockupQuerySender>();
  sender->d_id = counter;
  InternalQuery internalQuery(std::move(query), InternalQueryState());

  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and response from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as NOT ready anymore */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setNotReady(desc);
     }},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       s_connectionBuffers.at(desc)->submitGoAway();
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  auto sliced = std::shared_ptr<TCPQuerySender>(sender);
  bool result = sendH2Query(backend, s_mplexer, sliced, std::move(internalQuery), false);
  BOOST_CHECK_EQUAL(result, true);

  while (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0) {
    s_mplexer->run(&now);
  }
  BOOST_CHECK_EQUAL(sender->d_valid, true);
}

BOOST_FIXTURE_TEST_CASE(test_ConcurrentQueries, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       s_connectionBuffers.at(desc)->submitGoAway();
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0) {
    s_mplexer->run(&now);
  }

  for (auto& query : queries) {
    BOOST_CHECK_EQUAL(query.first->d_valid, true);
  }
}

BOOST_FIXTURE_TEST_CASE(test_ConnectionReuse, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  bool firstQueryDone = false;
  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [&firstQueryDone](int desc) {
       (void)desc;
       firstQueryDone = true;
     }},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       (void)desc;
     }},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* later the backend sends a go away frame */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       (void)desc;
       s_connectionBuffers.at(desc)->submitGoAway();
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  {
    auto& query = queries.at(0);
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);

    while (!firstQueryDone && (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0)) {
      s_mplexer->run(&now);
    }

    BOOST_CHECK_EQUAL(query.first->d_valid, true);
    BOOST_CHECK_EQUAL(firstQueryDone, true);
  }

  {
    auto& query = queries.at(1);
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);

    while (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0) {
      s_mplexer->run(&now);
    }

    BOOST_CHECK_EQUAL(query.first->d_valid, true);
  }
}

BOOST_FIXTURE_TEST_CASE(test_InvalidDNSAnswer, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  size_t counter = 1;
  DNSName name("powerdns.com.");
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  pwQ.getHeader()->id = htons(counter);

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
  pwR.getHeader()->qr = 1;
  pwR.getHeader()->rd = 1;
  pwR.getHeader()->ra = 1;
  pwR.getHeader()->id = htons(counter);
  pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
  pwR.xfr32BitInt(0x01020304);
  pwR.commit();

  /* TRUNCATE the answer */
  response.resize(11);
  s_responses[counter] = {query, response};

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  auto sender = std::make_shared<MockupQuerySender>();
  sender->d_id = counter;
  sender->d_customHandler = [](uint16_t id, const struct timeval&, TCPResponse&& resp) {
    (void)id;
    BOOST_CHECK_EQUAL(resp.d_buffer.size(), 11U);
    /* simulate an exception, since DoH and UDP frontends will process the query right away,
       while TCP and DoT will first pass it back to the TCP worker thread */
    throw std::runtime_error("Invalid response");
  };
  InternalQuery internalQuery(std::move(query), InternalQueryState());

  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and response from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* try to read, the backend says to go away */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       s_connectionBuffers.at(desc)->submitGoAway();
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  auto sliced = std::shared_ptr<TCPQuerySender>(sender);
  bool result = sendH2Query(backend, s_mplexer, sliced, std::move(internalQuery), false);
  BOOST_CHECK_EQUAL(result, true);

  while (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0) {
    s_mplexer->run(&now);
  }
  BOOST_CHECK_EQUAL(sender->d_valid, false);
}

BOOST_FIXTURE_TEST_CASE(test_TimeoutWhileWriting, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  bool timeout = false;
  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::NeedWrite, std::numeric_limits<size_t>::max(), [&timeout](int desc) {
       (void)desc;
       timeout = true;
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (!timeout && (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0)) {
    s_mplexer->run(&now);
  }

  struct timeval later = now;
  later.tv_sec += backend->d_config.tcpSendTimeout + 1;

  auto expiredConns = handleH2Timeouts(*s_mplexer, later);
  BOOST_CHECK_EQUAL(expiredConns, 1U);

  for (auto& query : queries) {
    BOOST_CHECK_EQUAL(query.first->d_valid, false);
    BOOST_CHECK_EQUAL(query.first->d_error, true);
  }

  BOOST_CHECK_EQUAL(clearH2Connections(), 0U);
}

BOOST_FIXTURE_TEST_CASE(test_TimeoutWhileReading, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  bool timeout = false;
  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [&timeout](int desc) {
       (void)desc;
       /* set the timeout flag now, since the timeout occurs while waiting for the descriptor to become readable */
       timeout = true;
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (!timeout && (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0)) {
    s_mplexer->run(&now);
  }

  struct timeval later = now;
  later.tv_sec += backend->d_config.tcpRecvTimeout + 1;

  auto expiredConns = handleH2Timeouts(*s_mplexer, later);
  BOOST_CHECK_EQUAL(expiredConns, 1U);

  for (auto& query : queries) {
    BOOST_CHECK_EQUAL(query.first->d_valid, false);
    BOOST_CHECK_EQUAL(query.first->d_error, true);
  }
  BOOST_CHECK_EQUAL(clearH2Connections(), 0U);
}

BOOST_FIXTURE_TEST_CASE(test_ShortWrite, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  bool done = false;
  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::NeedWrite, 2, [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* settings (second attempt) + headers + data + headers (second query) + data */
    {
      ExpectedStep::ExpectedRequest::writeToBackend,
      IOState::Done,
      std::numeric_limits<size_t>::max(),
    },
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [&done](int desc) {
       /* mark backend as not ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setNotReady(desc);
       done = true;
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (!done && (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0)) {
    s_mplexer->run(&now);
  }

  for (auto& query : queries) {
    BOOST_CHECK_EQUAL(query.first->d_valid, true);
  }

  BOOST_CHECK_EQUAL(clearH2Connections(), 1U);
}

BOOST_FIXTURE_TEST_CASE(test_ShortRead, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  bool done = false;
  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::NeedRead, 4},
    /* read settings, headers and responses (second attempt) */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [&done](int desc) {
       /* mark backend as not ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setNotReady(desc);
       done = true;
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (!done && (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0)) {
    s_mplexer->run(&now);
  }

  for (auto& query : queries) {
    BOOST_CHECK_EQUAL(query.first->d_valid, true);
  }

  BOOST_CHECK_EQUAL(clearH2Connections(), 1U);
}

BOOST_FIXTURE_TEST_CASE(test_ConnectionClosedWhileReading, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, 0},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0) {
    s_mplexer->run(&now);
  }

  for (auto& query : queries) {
    BOOST_CHECK_EQUAL(query.first->d_valid, false);
    BOOST_CHECK_EQUAL(query.first->d_error, true);
  }

  BOOST_CHECK_EQUAL(clearH2Connections(), 0U);
}

BOOST_FIXTURE_TEST_CASE(test_ConnectionClosedWhileWriting, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  bool done = false;
  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers, connection is closed by the backend */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, 0},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and response from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [&done](int desc) {
       /* mark backend as not ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setNotReady(desc);
       done = true;
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (!done && (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0)) {
    s_mplexer->run(&now);
  }

  BOOST_CHECK_EQUAL(queries.at(0).first->d_valid, false);
  BOOST_CHECK_EQUAL(queries.at(0).first->d_error, true);
  BOOST_CHECK_EQUAL(queries.at(1).first->d_valid, true);
  BOOST_CHECK_EQUAL(queries.at(1).first->d_error, false);

  BOOST_CHECK_EQUAL(clearH2Connections(), 1U);
}

BOOST_FIXTURE_TEST_CASE(test_GoAwayFromServer, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;
  /* set the number of reconnection attempts to a low value to not waste time */
  backend->d_config.d_retries = 1;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("goaway.powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read GO AWAY from the server (1) */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* close the first connection. It happens now because the new connection was set up first, then that one destroyed */
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
    /* read GO AWAY from the server (1) */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0) {
    s_mplexer->run(&now);
  }

  for (auto& query : queries) {
    BOOST_CHECK_EQUAL(query.first->d_valid, false);
    BOOST_CHECK_EQUAL(query.first->d_error, true);
  }

  BOOST_CHECK_EQUAL(clearH2Connections(), 0U);
}

BOOST_FIXTURE_TEST_CASE(test_HTTP500FromServer, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("500.powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  bool done = false;
  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [&done](int desc) {
       /* mark backend as not ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setNotReady(desc);
       done = true;
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (!done && (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0)) {
    s_mplexer->run(&now);
  }

  BOOST_CHECK_EQUAL(queries.at(0).first->d_valid, false);
  BOOST_CHECK_EQUAL(queries.at(0).first->d_error, true);
  BOOST_CHECK_EQUAL(queries.at(1).first->d_valid, true);
  BOOST_CHECK_EQUAL(queries.at(1).first->d_error, false);

  BOOST_CHECK_EQUAL(clearH2Connections(), 1U);
}

BOOST_FIXTURE_TEST_CASE(test_WrongStreamID, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("wrong-stream-id.powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  bool timeout = false;
  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* read ends up as a time out since nghttp2 filters the frame with the wrong stream ID */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::NeedRead, 0, [&timeout](int desc) {
       (void)desc;
       /* set the timeout flag now, since the timeout occurs while waiting for the descriptor to become readable */
       timeout = true;
     }},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (!timeout && (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0)) {
    s_mplexer->run(&now);
  }

  struct timeval later = now;
  later.tv_sec += backend->d_config.tcpRecvTimeout + 1;

  auto expiredConns = handleH2Timeouts(*s_mplexer, later);
  BOOST_CHECK_EQUAL(expiredConns, 1U);

  BOOST_CHECK_EQUAL(queries.at(0).first->d_valid, false);
  BOOST_CHECK_EQUAL(queries.at(0).first->d_error, true);
  BOOST_CHECK_EQUAL(queries.at(1).first->d_valid, false);
  BOOST_CHECK_EQUAL(queries.at(1).first->d_error, true);

  BOOST_CHECK_EQUAL(clearH2Connections(), 0U);
}

BOOST_FIXTURE_TEST_CASE(test_ProxyProtocol, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  tlsCtx->d_needProxyProtocol = true;
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  struct timeval now;
  gettimeofday(&now, nullptr);

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));
  backend->d_tlsCtx = tlsCtx;
  backend->d_config.d_tlsSubjectName = "backend.powerdns.com";
  backend->d_config.d_dohPath = "/dns-query";
  backend->d_config.d_addXForwardedHeaders = true;
  backend->d_config.useProxyProtocol = true;

  size_t numberOfQueries = 2;
  std::vector<std::pair<std::shared_ptr<MockupQuerySender>, InternalQuery>> queries;
  for (size_t counter = 0; counter < numberOfQueries; counter++) {
    DNSName name("powerdns.com.");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(counter);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(counter);
    pwR.startRecord(name, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    s_responses[counter] = {query, response};

    auto sender = std::make_shared<MockupQuerySender>();
    sender->d_id = counter;
    std::string payload = makeProxyHeader(counter % 2, local, local, {});
    InternalQuery internalQuery(std::move(query), InternalQueryState());
    internalQuery.d_proxyProtocolPayload = std::move(payload);
    queries.push_back({std::move(sender), std::move(internalQuery)});
  }

  s_steps = {
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* proxy protocol data + opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    {ExpectedStep::ExpectedRequest::connectToBackend, IOState::Done},
    /* proxy protocol data + opening */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* headers */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* data */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max(), [](int desc) {
       /* set the outgoing descriptor (backend connection) as ready */
       dynamic_cast<MockupFDMultiplexer*>(s_mplexer.get())->setReady(desc);
     }},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
    /* read settings, headers and responses from the server */
    {ExpectedStep::ExpectedRequest::readFromBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    /* acknowledge settings */
    {ExpectedStep::ExpectedRequest::writeToBackend, IOState::Done, std::numeric_limits<size_t>::max()},
    {ExpectedStep::ExpectedRequest::closeBackend, IOState::Done},
  };

  for (auto& query : queries) {
    auto sliced = std::static_pointer_cast<TCPQuerySender>(query.first);
    bool result = sendH2Query(backend, s_mplexer, sliced, std::move(query.second), false);
    BOOST_CHECK_EQUAL(result, true);
  }

  while (s_mplexer->getWatchedFDCount(false) != 0 || s_mplexer->getWatchedFDCount(true) != 0) {
    s_mplexer->run(&now);
  }

  for (auto& query : queries) {
    BOOST_CHECK_EQUAL(query.first->d_valid, true);
  }

  BOOST_CHECK_EQUAL(clearH2Connections(), 0U);
}

BOOST_AUTO_TEST_SUITE_END();
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
