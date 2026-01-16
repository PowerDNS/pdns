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
#include "dnsdist-nghttp2-in.hh"

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
#include <nghttp2/nghttp2.h>

extern std::function<ProcessQueryResult(DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend)> s_processQuery;

BOOST_AUTO_TEST_SUITE(test_dnsdistnghttp2_in_cc)

struct ExpectedStep
{
public:
  enum class ExpectedRequest
  {
    handshakeClient,
    readFromClient,
    writeToClient,
    closeClient,
  };

  ExpectedStep(ExpectedRequest req, IOState next, size_t bytes_ = 0, std::function<void(int descriptor)> func = nullptr) :
    cb(std::move(func)), request(req), nextState(next), bytes(bytes_)
  {
  }

  std::function<void(int descriptor)> cb{nullptr};
  ExpectedRequest request;
  IOState nextState;
  size_t bytes{0};
};

struct ExpectedData
{
  PacketBuffer d_proxyProtocolPayload;
  std::vector<PacketBuffer> d_queries;
  std::vector<PacketBuffer> d_responses;
  std::vector<uint16_t> d_responseCodes;
};

class DOHConnection;

static std::deque<ExpectedStep> s_steps;
static std::map<uint64_t, ExpectedData> s_connectionContexts;
static std::map<int, std::unique_ptr<DOHConnection>> s_connectionBuffers;
static uint64_t s_connectionID{0};

std::ostream& operator<<(std::ostream& outs, ExpectedStep::ExpectedRequest step);

std::ostream& operator<<(std::ostream& outs, ExpectedStep::ExpectedRequest step)
{
  static const std::vector<std::string> requests = {"handshake with client", "read from client", "write to client", "close connection to client", "connect to the backend", "read from the backend", "write to the backend", "close connection to backend"};
  outs << requests.at(static_cast<size_t>(step));
  return outs;
}

class DOHConnection
{
public:
  DOHConnection(uint64_t connectionID) :
    d_session(std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)>(nullptr, nghttp2_session_del)), d_connectionID(connectionID)
  {
    const auto& context = s_connectionContexts.at(connectionID);
    d_clientOutBuffer.insert(d_clientOutBuffer.begin(), context.d_proxyProtocolPayload.begin(), context.d_proxyProtocolPayload.end());

    nghttp2_session_callbacks* cbs = nullptr;
    nghttp2_session_callbacks_new(&cbs);
    std::unique_ptr<nghttp2_session_callbacks, void (*)(nghttp2_session_callbacks*)> callbacks(cbs, nghttp2_session_callbacks_del);
    cbs = nullptr;
    nghttp2_session_callbacks_set_send_callback(callbacks.get(), send_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(), on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks.get(), on_header_callback);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(), on_data_chunk_recv_callback);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks.get(), on_stream_close_callback);
    nghttp2_session* sess = nullptr;
    nghttp2_session_client_new(&sess, callbacks.get(), this);
    d_session = std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)>(sess, nghttp2_session_del);

    std::array<nghttp2_settings_entry, 3> settings{
      /* rfc7540 section-8.2.2:
         "Advertising a SETTINGS_MAX_CONCURRENT_STREAMS value of zero disables
         server push by preventing the server from creating the necessary
         streams."
      */
      nghttp2_settings_entry{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 0},
      nghttp2_settings_entry{NGHTTP2_SETTINGS_ENABLE_PUSH, 0},
      /* we might want to make the initial window size configurable, but 16M is a large enough default */
      nghttp2_settings_entry{NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 16 * 1024 * 1024}};
    /* client 24 bytes magic string will be sent by nghttp2 library */
    auto result = nghttp2_submit_settings(d_session.get(), NGHTTP2_FLAG_NONE, settings.data(), settings.size());
    if (result != 0) {
      throw std::runtime_error("Error submitting settings:" + std::string(nghttp2_strerror(result)));
    }

    const std::string host("unit-tests");
    const std::string path("/dns-query");
    for (const auto& query : context.d_queries) {
      const auto querySize = std::to_string(query.size());
      std::vector<nghttp2_nv> headers;
      /* Pseudo-headers need to come first (rfc7540 8.1.2.1) */
      NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::METHOD_NAME, NGHTTP2Headers::HeaderConstantIndexes::METHOD_VALUE);
      NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::SCHEME_NAME, NGHTTP2Headers::HeaderConstantIndexes::SCHEME_VALUE);
      NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::AUTHORITY_NAME, host);
      NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::PATH_NAME, path);
      NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::ACCEPT_NAME, NGHTTP2Headers::HeaderConstantIndexes::ACCEPT_VALUE);
      NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_NAME, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_TYPE_VALUE);
      NGHTTP2Headers::addStaticHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::USER_AGENT_NAME, NGHTTP2Headers::HeaderConstantIndexes::USER_AGENT_VALUE);
      NGHTTP2Headers::addDynamicHeader(headers, NGHTTP2Headers::HeaderConstantIndexes::CONTENT_LENGTH_NAME, querySize);

      d_position = 0;
      d_currentQuery = query;
      nghttp2_data_provider data_provider;
      data_provider.source.ptr = this;
      data_provider.read_callback = [](nghttp2_session* session, int32_t stream_id, uint8_t* buf, size_t length, uint32_t* data_flags, nghttp2_data_source* source, void* user_data) -> ssize_t {
        (void)session;
        (void)stream_id;
        (void)source;
        auto* conn = static_cast<DOHConnection*>(user_data);
        auto& pos = conn->d_position;
        const auto& currentQuery = conn->d_currentQuery;
        size_t toCopy = 0;
        if (pos < currentQuery.size()) {
          size_t remaining = currentQuery.size() - pos;
          toCopy = length > remaining ? remaining : length;
          memcpy(buf, &currentQuery.at(pos), toCopy);
          pos += toCopy;
        }

        if (pos >= currentQuery.size()) {
          *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        }
        return static_cast<ssize_t>(toCopy);
      };

      auto newStreamId = nghttp2_submit_request(d_session.get(), nullptr, headers.data(), headers.size(), &data_provider, this);
      if (newStreamId < 0) {
        throw std::runtime_error("Error submitting HTTP request:" + std::string(nghttp2_strerror(newStreamId)));
      }

      result = nghttp2_session_send(d_session.get());
      if (result != 0) {
        throw std::runtime_error("Error in nghttp2_session_send:" + std::to_string(result));
      }
    }
  }

  std::map<int32_t, PacketBuffer> d_responses;
  std::map<int32_t, uint16_t> d_responseCodes;
  std::unique_ptr<nghttp2_session, void (*)(nghttp2_session*)> d_session;
  PacketBuffer d_currentQuery;
  PacketBuffer d_clientOutBuffer;
  uint64_t d_connectionID{0};
  size_t d_position{0};

  void submitIncoming(const PacketBuffer& data, size_t pos, size_t toWrite) const
  {
    ssize_t readlen = nghttp2_session_mem_recv(d_session.get(), &data.at(pos), toWrite);
    if (readlen < 0) {
      throw("Fatal error while submitting line " + std::to_string(__LINE__) + ": " + std::string(nghttp2_strerror(static_cast<int>(readlen))));
    }

    /* just in case, see if we have anything to send */
    int got = nghttp2_session_send(d_session.get());
    if (got != 0) {
      throw("Fatal error while sending: " + std::string(nghttp2_strerror(got)));
    }
  }

private:
  static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data)
  {
    (void)session;
    (void)flags;
    auto* conn = static_cast<DOHConnection*>(user_data);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): nghttp2 API
    conn->d_clientOutBuffer.insert(conn->d_clientOutBuffer.end(), data, data + length);
    return static_cast<ssize_t>(length);
  }

  static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data)
  {
    (void)session;
    auto* conn = static_cast<DOHConnection*>(user_data);
    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) != 0) {
      const auto& response = conn->d_responses.at(frame->hd.stream_id);
      if (conn->d_responseCodes.at(frame->hd.stream_id) != 200U) {
        return 0;
      }

      BOOST_REQUIRE_GT(response.size(), sizeof(dnsheader));
      const dnsheader_aligned dnsHeader(response.data());
      uint16_t queryID = ntohs(dnsHeader.get()->id);

      const auto& expected = s_connectionContexts.at(conn->d_connectionID).d_responses.at(queryID);
      BOOST_REQUIRE_EQUAL(expected.size(), response.size());
      for (size_t idx = 0; idx < response.size(); idx++) {
        if (expected.at(idx) != response.at(idx)) {
          cerr << "Mismatch at offset " << idx << ", expected " << std::to_string(response.at(idx)) << " got " << std::to_string(expected.at(idx)) << endl;
          BOOST_CHECK(false);
        }
      }
    }

    return 0;
  }

  static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, int32_t stream_id, const uint8_t* data, size_t len, void* user_data)
  {
    (void)session;
    (void)flags;
    auto* conn = static_cast<DOHConnection*>(user_data);
    auto& response = conn->d_responses[stream_id];
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): nghttp2 API
    response.insert(response.end(), data, data + len);
    return 0;
  }

  static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data)
  {
    (void)session;
    (void)flags;
    auto* conn = static_cast<DOHConnection*>(user_data);
    const std::string status(":status");
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      if (namelen == status.size() && memcmp(status.data(), name, status.size()) == 0) {
        try {
          uint16_t responseCode{0};
          auto expected = s_connectionContexts.at(conn->d_connectionID).d_responseCodes.at((frame->hd.stream_id - 1) / 2);
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): nghttp2 API
          pdns::checked_stoi_into(responseCode, std::string(reinterpret_cast<const char*>(value), valuelen));
          conn->d_responseCodes[frame->hd.stream_id] = responseCode;
          if (responseCode != expected) {
            cerr << "Mismatch response code, expected " << std::to_string(expected) << " got " << std::to_string(responseCode) << endl;
            BOOST_CHECK(false);
          }
        }
        catch (const std::exception& e) {
          SLOG(infolog("Error parsing the status header for stream ID %d: %s", frame->hd.stream_id, e.what()),
               dnsdist::logging::getTopLogger("nghttp2-incoming-unit-tests")->error(e.what(), "Error parsing the status header for stream", "http.stream_id", Logging::Loggable(frame->hd.stream_id)));
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
    }
    return 0;
  }

  static int on_stream_close_callback(nghttp2_session* session, int32_t stream_id, uint32_t error_code, void* user_data)
  {
    (void)session;
    (void)stream_id;
    (void)error_code;
    (void)user_data;
    return 0;
  }
};

class MockupTLSConnection : public TLSConnection
{
public:
  MockupTLSConnection(int descriptor, [[maybe_unused]] bool client = false, [[maybe_unused]] bool needProxyProtocol = false) :
    d_descriptor(descriptor)
  {
    auto connectionID = s_connectionID++;
    auto conn = std::make_unique<DOHConnection>(connectionID);
    s_connectionBuffers[d_descriptor] = std::move(conn);
  }
  MockupTLSConnection(const MockupTLSConnection&) = delete;
  MockupTLSConnection(MockupTLSConnection&&) = delete;
  MockupTLSConnection& operator=(const MockupTLSConnection&) = delete;
  MockupTLSConnection& operator=(MockupTLSConnection&&) = delete;
  ~MockupTLSConnection() override = default;

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
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::writeToClient);

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
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::readFromClient);

    if (step.bytes == 0) {
      if (step.nextState == IOState::NeedRead) {
        return step.nextState;
      }
      throw std::runtime_error("Remote host closed the connection");
    }

    auto& externalBuffer = conn->d_clientOutBuffer;
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

    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    std::copy(externalBuffer.begin(), externalBuffer.begin() + toRead, buffer.begin() + pos);
    pos += toRead;
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    externalBuffer.erase(externalBuffer.begin(), externalBuffer.begin() + toRead);

    return step.nextState;
  }

  IOState tryConnect(bool fastOpen, const ComboAddress& remote) override
  {
    (void)fastOpen;
    (void)remote;
    throw std::runtime_error("Should not happen");
  }

  void close() override
  {
    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::closeClient);
  }

  [[nodiscard]] bool isUsable() const override
  {
    return true;
  }

  [[nodiscard]] std::string getServerNameIndication() const override
  {
    return "";
  }

  [[nodiscard]] std::vector<uint8_t> getNextProtocol() const override
  {
    return std::vector<uint8_t>{'h', '2'};
  }

  [[nodiscard]] LibsslTLSVersion getTLSVersion() const override
  {
    return LibsslTLSVersion::TLS13;
  }

  [[nodiscard]] std::pair<long, std::string> getVerifyResult() const override
  {
    return {-1, "Not implemented yet"};
  }

  [[nodiscard]] bool hasSessionBeenResumed() const override
  {
    return false;
  }

  [[nodiscard]] std::vector<std::unique_ptr<TLSSession>> getSessions() override
  {
    return {};
  }

  void setSession(std::unique_ptr<TLSSession>& session) override
  {
    (void)session;
  }

  [[nodiscard]] std::vector<int> getAsyncFDs() override
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
  [[nodiscard]] ExpectedStep getStep() const
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
};

#include "test-dnsdistnghttp2_common.hh"

struct TestFixture
{
  TestFixture()
  {
    reset();
  }
  TestFixture(const TestFixture&) = delete;
  TestFixture(TestFixture&&) = delete;
  TestFixture& operator=(const TestFixture&) = delete;
  TestFixture& operator=(TestFixture&&) = delete;
  ~TestFixture()
  {
    reset();
  }

private:
  void reset()
  {
    s_steps.clear();
    s_connectionContexts.clear();
    s_connectionBuffers.clear();
    s_connectionID = 0;
    /* we _NEED_ to set this function to empty otherwise we might get what was set
       by the last test, and we might not like it at all */
    s_processQuery = nullptr;
  }
};

BOOST_FIXTURE_TEST_CASE(test_IncomingConnection_SelfAnswered, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  localCS.dohFrontend = std::make_shared<DOHFrontend>(std::make_shared<MockupTLSCtx>());
  localCS.dohFrontend->d_urls.insert("/dns-query");

  TCPClientThreadData threadData;
  threadData.mplexer = std::make_unique<MockupFDMultiplexer>();

  struct timeval now{};
  gettimeofday(&now, nullptr);

  size_t counter = 0;
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

  {
    /* dnsdist drops the query right away after receiving it, client closes the connection */
    s_connectionContexts[counter++] = ExpectedData{{}, {query}, {response}, {403U}};
    s_steps = {
      /* opening */
      {ExpectedStep::ExpectedRequest::handshakeClient, IOState::Done},
      /* settings server -> client */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 15},
      /* settings + headers + data client -> server.. */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 128},
      /* .. continued */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 60},
      /* headers + data */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, std::numeric_limits<size_t>::max()},
      /* wait for next query, but the client closes the connection */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 0},
      /* server close */
      {ExpectedStep::ExpectedRequest::closeClient, IOState::Done},
    };

    auto state = std::make_shared<IncomingHTTP2Connection>(ConnectionInfo(&localCS, getBackendAddress("84", 4242)), threadData, now);
    state->handleIO();
  }

  {
    /* client closes the connection right in the middle of sending the query */
    s_connectionContexts[counter++] = ExpectedData{{}, {query}, {response}, {403U}};
    s_steps = {
      /* opening */
      {ExpectedStep::ExpectedRequest::handshakeClient, IOState::Done},
      /* settings server -> client */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 15},
      /* client sends one byte */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::NeedRead, 1},
      /* then closes the connection */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 0},
      /* server close */
      {ExpectedStep::ExpectedRequest::closeClient, IOState::Done},
    };

    /* mark the incoming FD as always ready */
    dynamic_cast<MockupFDMultiplexer*>(threadData.mplexer.get())->setReady(-1);

    auto state = std::make_shared<IncomingHTTP2Connection>(ConnectionInfo(&localCS, getBackendAddress("84", 4242)), threadData, now);
    state->handleIO();
    while (threadData.mplexer->getWatchedFDCount(false) != 0 || threadData.mplexer->getWatchedFDCount(true) != 0) {
      threadData.mplexer->run(&now);
    }
  }

  {
    /* dnsdist sends a response right away, client closes the connection after getting the response */
    s_processQuery = [response](DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend) -> ProcessQueryResult {
      (void)selectedBackend;
      /* self answered */
      dnsQuestion.getMutableData() = response;
      return ProcessQueryResult::SendAnswer;
    };

    s_connectionContexts[counter++] = ExpectedData{{}, {query}, {response}, {200U}};

    s_steps = {
      /* opening */
      {ExpectedStep::ExpectedRequest::handshakeClient, IOState::Done},
      /* settings server -> client */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 15},
      /* settings + headers + data client -> server.. */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 128},
      /* .. continued */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 60},
      /* headers + data */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, std::numeric_limits<size_t>::max()},
      /* wait for next query, but the client closes the connection */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 0},
      /* server close */
      {ExpectedStep::ExpectedRequest::closeClient, IOState::Done},
    };

    auto state = std::make_shared<IncomingHTTP2Connection>(ConnectionInfo(&localCS, getBackendAddress("84", 4242)), threadData, now);
    state->handleIO();
  }

  {
    /* dnsdist sends a response right away, but the client closes the connection without even reading the response */
    s_processQuery = [response](DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend) -> ProcessQueryResult {
      (void)selectedBackend;
      /* self answered */
      dnsQuestion.getMutableData() = response;
      return ProcessQueryResult::SendAnswer;
    };

    s_connectionContexts[counter++] = ExpectedData{{}, {query}, {response}, {200U}};

    s_steps = {
      /* opening */
      {ExpectedStep::ExpectedRequest::handshakeClient, IOState::Done},
      /* settings server -> client */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 15},
      /* settings + headers + data client -> server.. */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 128},
      /* .. continued */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 60},
      /* we want to send the response but the client closes the connection */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 0},
      /* server close */
      {ExpectedStep::ExpectedRequest::closeClient, IOState::Done},
    };

    /* mark the incoming FD as always ready */
    dynamic_cast<MockupFDMultiplexer*>(threadData.mplexer.get())->setReady(-1);

    auto state = std::make_shared<IncomingHTTP2Connection>(ConnectionInfo(&localCS, getBackendAddress("84", 4242)), threadData, now);
    state->handleIO();
    while (threadData.mplexer->getWatchedFDCount(false) != 0 || threadData.mplexer->getWatchedFDCount(true) != 0) {
      threadData.mplexer->run(&now);
    }
  }

  {
    /* dnsdist sends a response right away, client closes the connection while getting the response */
    s_processQuery = [response](DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend) -> ProcessQueryResult {
      (void)selectedBackend;
      /* self answered */
      dnsQuestion.getMutableData() = response;
      return ProcessQueryResult::SendAnswer;
    };

    s_connectionContexts[counter++] = ExpectedData{{}, {query}, {response}, {200U}};

    s_steps = {
      /* opening */
      {ExpectedStep::ExpectedRequest::handshakeClient, IOState::Done},
      /* settings server -> client */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 15},
      /* settings + headers + data client -> server.. */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 128},
      /* .. continued */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 60},
      /* headers + data (partial write) */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::NeedWrite, 1},
      /* nothing to read after that */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::NeedRead, 0},
      /* then the client closes the connection before we are done  */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 0},
      /* server close */
      {ExpectedStep::ExpectedRequest::closeClient, IOState::Done},
    };

    /* mark the incoming FD as always ready */
    dynamic_cast<MockupFDMultiplexer*>(threadData.mplexer.get())->setReady(-1);

    auto state = std::make_shared<IncomingHTTP2Connection>(ConnectionInfo(&localCS, getBackendAddress("84", 4242)), threadData, now);
    state->handleIO();
    while (threadData.mplexer->getWatchedFDCount(false) != 0 || threadData.mplexer->getWatchedFDCount(true) != 0) {
      threadData.mplexer->run(&now);
    }
  }
}

BOOST_FIXTURE_TEST_CASE(test_IncomingConnection_BackendTimeout, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  localCS.dohFrontend = std::make_shared<DOHFrontend>(std::make_shared<MockupTLSCtx>());
  localCS.dohFrontend->d_urls.insert("/dns-query");

  TCPClientThreadData threadData;
  threadData.mplexer = std::make_unique<MockupFDMultiplexer>();

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));

  timeval now{};
  gettimeofday(&now, nullptr);

  size_t counter = 0;
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

  {
    /* dnsdist forwards the query to the backend, which does not answer -> timeout */
    s_processQuery = [backend](DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend) -> ProcessQueryResult {
      (void)dnsQuestion;
      selectedBackend = backend;
      return ProcessQueryResult::PassToBackend;
    };
    s_connectionContexts[counter++] = ExpectedData{{}, {query}, {response}, {502U}};
    s_steps = {
      /* opening */
      {ExpectedStep::ExpectedRequest::handshakeClient, IOState::Done},
      /* settings server -> client */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 15},
      /* settings + headers + data client -> server.. */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 128},
      /* .. continued */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 60},
      /* trying to read a new request while processing the first one */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::NeedRead},
      /* headers + data */
      {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, std::numeric_limits<size_t>::max(), [&threadData](int desc) {
         /* set the incoming descriptor as ready */
         dynamic_cast<MockupFDMultiplexer*>(threadData.mplexer.get())->setReady(desc);
       }},
      /* wait for next query, but the client closes the connection */
      {ExpectedStep::ExpectedRequest::readFromClient, IOState::Done, 0},
      /* server close */
      {ExpectedStep::ExpectedRequest::closeClient, IOState::Done},
    };

    auto state = std::make_shared<IncomingHTTP2Connection>(ConnectionInfo(&localCS, getBackendAddress("84", 4242)), threadData, now);
    state->handleIO();
    TCPResponse resp;
    resp.d_idstate.d_streamID = 1;
    state->notifyIOError(now, std::move(resp));
    while (threadData.mplexer->getWatchedFDCount(false) != 0 || threadData.mplexer->getWatchedFDCount(true) != 0) {
      threadData.mplexer->run(&now);
    }
  }
}

BOOST_FIXTURE_TEST_CASE(test_IncomingConnection_ClientTimeout_BackendTimeout, TestFixture)
{
  auto local = getBackendAddress("1", 80);
  ClientState localCS(local, true, false, 0, "", {}, true);
  localCS.dohFrontend = std::make_shared<DOHFrontend>(std::make_shared<MockupTLSCtx>());
  localCS.dohFrontend->d_urls.insert("/dns-query");

  TCPClientThreadData threadData;
  threadData.mplexer = std::make_unique<MockupFDMultiplexer>();

  auto backend = std::make_shared<DownstreamState>(getBackendAddress("42", 53));

  timeval now{};
  gettimeofday(&now, nullptr);

  size_t counter = 0;
  s_connectionContexts[counter++] = ExpectedData{{}, {}, {}, {}};
  s_steps = {
    {ExpectedStep::ExpectedRequest::handshakeClient, IOState::Done},
    /* write to client, but the client closes the connection */
    {ExpectedStep::ExpectedRequest::writeToClient, IOState::Done, 0},
    /* server close */
    {ExpectedStep::ExpectedRequest::closeClient, IOState::Done},
  };

  auto state = std::make_shared<IncomingHTTP2Connection>(ConnectionInfo(&localCS, getBackendAddress("84", 4242)), threadData, now);
  auto base = std::static_pointer_cast<IncomingTCPConnectionState>(state);
  IncomingHTTP2Connection::handleTimeout(base, true);
  state->handleIO();
}

BOOST_AUTO_TEST_SUITE_END();
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
