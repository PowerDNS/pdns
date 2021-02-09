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
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnswriter.hh"
#include "dnsdist.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-tcp-upstream.hh"

struct DNSDistStats g_stats;
GlobalStateHolder<NetmaskGroup> g_ACL;
GlobalStateHolder<vector<DNSDistRuleAction> > g_rulactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_resprulactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_cachehitresprulactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_selfansweredresprulactions;
GlobalStateHolder<servers_t> g_dstates;

QueryCount g_qcount;


bool checkDNSCryptQuery(const ClientState& cs, PacketBuffer& query, std::shared_ptr<DNSCryptQuery>& dnsCryptQuery, time_t now, bool tcp)
{
  return false;
}

bool processResponse(PacketBuffer& response, LocalStateHolder<vector<DNSDistResponseRuleAction> >& localRespRulactions, DNSResponse& dr, bool muted)
{
  return false;
}

bool checkQueryHeaders(const struct dnsheader* dh)
{
  return true;
}

bool responseContentMatches(const PacketBuffer& response, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& remote, unsigned int& qnameWireLength)
{
  return true;
}

uint64_t uptimeOfProcess(const std::string& str)
{
  return 0;
}

uint64_t getLatencyCount(const std::string&)
{
  return 0;
}

static std::function<ProcessQueryResult(DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend)> s_processQuery;

ProcessQueryResult processQuery(DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend)
{
  if (s_processQuery) {
    return s_processQuery(dq, cs, holders, selectedBackend);
  }

  return ProcessQueryResult::Drop;
}

BOOST_AUTO_TEST_SUITE(test_dnsdisttcp_cc)

struct ExpectedStep
{
public:
  enum class ExpectedRequest { handshake, connect, read, write, close };

  ExpectedStep(ExpectedRequest r, IOState n): ExpectedStep(r, n, 0)
  {
  }

  ExpectedStep(ExpectedRequest r, IOState n, size_t b): request(r), nextState(n), bytes(b)
  {
  }

  ExpectedRequest request;
  IOState nextState;
  size_t bytes{0};
};

static std::deque<ExpectedStep> s_steps;
static ExpectedStep getStep()
{
  BOOST_REQUIRE(!s_steps.empty());
  auto res = s_steps.front();
  s_steps.pop_front();
  return res;
}

static boost::optional<PacketBuffer> s_readBuffer;
static PacketBuffer s_writeBuffer;

std::ostream& operator<<(std::ostream &os, const ExpectedStep::ExpectedRequest d);

std::ostream& operator<<(std::ostream &os, const ExpectedStep::ExpectedRequest d)
{
  static const std::vector<std::string> requests = { "handshake", "connect", "read", "write", "close" };
  os<<requests.at(static_cast<size_t>(d));
  return os;
}

class MockupTLSConnection : public TLSConnection
{
private:
public:
  ~MockupTLSConnection() { }

  IOState tryHandshake() override
  {
    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::handshake);
    return step.nextState;
  }

  IOState tryWrite(const PacketBuffer& buffer, size_t& pos, size_t toWrite) override
  {
    if (buffer.size() < toWrite || pos >= toWrite) {
      throw std::out_of_range("Calling tryWrite() with a too small buffer (" + std::to_string(buffer.size()) + ") for a write of " + std::to_string(toWrite - pos) + " bytes starting at " + std::to_string(pos));
    }

    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::write);

    if (step.bytes == 0) {
      throw std::runtime_error("Remote host closed the connection");
    }

    toWrite -= pos;
    BOOST_REQUIRE_GE(buffer.size(), pos + toWrite);

    if (step.bytes < toWrite) {
      toWrite = step.bytes;
    }

    s_writeBuffer.insert(s_writeBuffer.end(), buffer.begin() + pos, buffer.begin() + pos + toWrite);
    pos += toWrite;

    return step.nextState;
  }

  IOState tryRead(PacketBuffer& buffer, size_t& pos, size_t toRead) override
  {
    if (buffer.size() < toRead || pos >= toRead) {
      throw std::out_of_range("Calling tryRead() with a too small buffer (" + std::to_string(buffer.size()) + ") for a read of " + std::to_string(toRead - pos) + " bytes starting at " + std::to_string(pos));
    }

    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::read);

    if (step.bytes == 0) {
      throw std::runtime_error("Remote host closed the connection");
    }

    if (s_readBuffer) {
      toRead -= pos;

      if (step.bytes < toRead) {
        toRead = step.bytes;
      }
      BOOST_REQUIRE_GE(buffer.size(), toRead);
      BOOST_REQUIRE_GE(s_readBuffer->size(), toRead);

      std::copy(s_readBuffer->begin(), s_readBuffer->begin() + toRead, buffer.begin() + pos);
      pos += toRead;
      s_readBuffer->erase(s_readBuffer->begin(), s_readBuffer->begin() + toRead);
    }

    return step.nextState;
  }

  void close() override
  {
    auto step = getStep();
    BOOST_REQUIRE_EQUAL(step.request, ExpectedStep::ExpectedRequest::close);
  }

  bool hasBufferedData() const override
  {
    return false;
  }

  std::string getServerNameIndication() const override
  {
    return "";
  }

  LibsslTLSVersion getTLSVersion() const override
  {
    return LibsslTLSVersion::TLS13;
  }

  bool hasSessionBeenResumed() const override
  {
    return false;
  }

  /* unused in that context, don't bother */
  void doHandshake() override
  {
  }

  void connect(bool fastOpen, const ComboAddress& remote, unsigned int timeout) override
  {
  }

  IOState tryConnect(bool fastOpen, const ComboAddress& remote) override
  {
    return IOState::Done;
  }

  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout, unsigned int totalTimeout=0) override
  {
    return 0;
  }

  size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) override
  {
    return 0;
  }
};

class MockupTLSCtx : public TLSCtx
{
public:
  ~MockupTLSCtx()
  {
  }

  std::unique_ptr<TLSConnection> getConnection(int socket, unsigned int timeout, time_t now) override
  {
    return std::make_unique<MockupTLSConnection>();
  }

  void rotateTicketsKey(time_t now) override
  {
  }

  size_t getTicketsKeysCount() override
  {
    return 0;
  }

  std::unique_ptr<TLSConnection> getClientConnection(const std::string& host, int socket, unsigned int timeout) override
  {
    return nullptr;
  }
};

class MockupFDMultiplexer : public FDMultiplexer
{
public:
  MockupFDMultiplexer()
  {
  }

  ~MockupFDMultiplexer()
  {
  }

  int run(struct timeval* tv, int timeout=500) override
  {
    int ret = 0;

    gettimeofday(tv, nullptr); // MANDATORY

    for (const auto fd : ready) {
      {
        const auto& it = d_readCallbacks.find(fd);

        if (it != d_readCallbacks.end()) {
          it->d_callback(it->d_fd, it->d_parameter);
          continue; // so we don't refind ourselves as writable!
        }
      }

      {
        const auto& it = d_writeCallbacks.find(fd);

        if (it != d_writeCallbacks.end()) {
          it->d_callback(it->d_fd, it->d_parameter);
        }
      }
    }

    return ret;
  }

  void getAvailableFDs(std::vector<int>& fds, int timeout) override
  {
  }

  void addFD(callbackmap_t& cbmap, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd=nullptr) override
  {
    accountingAddFD(cbmap, fd, toDo, parameter, ttd);
  }

  void removeFD(callbackmap_t& cbmap, int fd) override
  {
    accountingRemoveFD(cbmap, fd);
  }

  void alterFD(callbackmap_t& from, callbackmap_t& to, int fd, callbackfunc_t toDo, const funcparam_t& parameter, const struct timeval* ttd) override
  {
    accountingRemoveFD(from, fd);
    accountingAddFD(to, fd, toDo, parameter, ttd);
  }

  string getName() const override
  {
    return "mockup";
  }

  void setReady(int fd)
  {
    ready.insert(fd);
  }

  void setNotdReady(int fd)
  {
    ready.erase(fd);
  }

private:
  std::set<int> ready;
};

BOOST_AUTO_TEST_CASE(test_IncomingConnection)
{
  //int sockets[2];
  //int res = socketpair(AF_UNIX, SOCK_STREAM, 0, sockets);
  //BOOST_REQUIRE_EQUAL(res, 0);
  ComboAddress local("192.0.2.1:80");
  ClientState localCS(local, true, false, false, "", {});
  auto tlsCtx = std::make_shared<MockupTLSCtx>();
  localCS.tlsFrontend = std::make_shared<TLSFrontend>(tlsCtx);

  TCPClientThreadData threadData;
  threadData.mplexer = std::make_unique<MockupFDMultiplexer>();

  struct timeval now;
  gettimeofday(&now, nullptr);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, DNSName("powerdns.com."), QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;

  uint16_t querySize = static_cast<uint16_t>(query.size());
  const uint8_t sizeBytes[] = { static_cast<uint8_t>(querySize / 256), static_cast<uint8_t>(querySize % 256) };
  query.insert(query.begin(), sizeBytes, sizeBytes + 2);

  g_verbose = true;

  {
    /* drop right away */
    s_readBuffer = query;
    s_writeBuffer.clear();
    s_steps = {
      { ExpectedStep::ExpectedRequest::handshake, IOState::Done },
      { ExpectedStep::ExpectedRequest::read, IOState::Done, 2 },
      { ExpectedStep::ExpectedRequest::read, IOState::Done, query.size() - 2 },
      { ExpectedStep::ExpectedRequest::close, IOState::Done },
    };
    s_processQuery = [](DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend) -> ProcessQueryResult {
      return ProcessQueryResult::Drop;
    };

    auto state = std::make_shared<IncomingTCPConnectionState>(ConnectionInfo(&localCS), threadData, now);
    IncomingTCPConnectionState::handleIO(state, now);
    BOOST_CHECK_EQUAL(s_writeBuffer.size(), 0);
  }

  {
    /* self-generated REFUSED, client closes connection right away */
    s_readBuffer = query;
    s_writeBuffer.clear();
    s_steps = {
      { ExpectedStep::ExpectedRequest::handshake, IOState::Done },
      { ExpectedStep::ExpectedRequest::read, IOState::Done, 2 },
      { ExpectedStep::ExpectedRequest::read, IOState::Done, query.size() - 2 },
      { ExpectedStep::ExpectedRequest::write, IOState::Done, 65537 },
      { ExpectedStep::ExpectedRequest::read, IOState::Done, 0 },
      { ExpectedStep::ExpectedRequest::close, IOState::Done },
    };
    s_processQuery = [](DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend) -> ProcessQueryResult {
      // Would be nicer to actually turn it into a response
      return ProcessQueryResult::SendAnswer;
    };

    auto state = std::make_shared<IncomingTCPConnectionState>(ConnectionInfo(&localCS), threadData, now);
    IncomingTCPConnectionState::handleIO(state, now);
    BOOST_CHECK_EQUAL(s_writeBuffer.size(), query.size());
  }

  {
    /* short read on the size, then on the query itself,
       self-generated REFUSED, short write on the response, 
       client closes connection right away */
    s_readBuffer = query;
    s_writeBuffer.clear();
    s_steps = {
      { ExpectedStep::ExpectedRequest::handshake, IOState::Done },
      { ExpectedStep::ExpectedRequest::read, IOState::NeedRead, 1 },
      { ExpectedStep::ExpectedRequest::read, IOState::Done, 1 },
      { ExpectedStep::ExpectedRequest::read, IOState::NeedRead, query.size() - 3 },
      { ExpectedStep::ExpectedRequest::read, IOState::Done, 1 },
      { ExpectedStep::ExpectedRequest::write, IOState::NeedWrite, query.size() - 1},
      { ExpectedStep::ExpectedRequest::write, IOState::Done, 1 },
      { ExpectedStep::ExpectedRequest::read, IOState::Done, 0 },
      { ExpectedStep::ExpectedRequest::close, IOState::Done },
    };
    s_processQuery = [](DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend) -> ProcessQueryResult {
      // Would be nicer to actually turn it into a response
      return ProcessQueryResult::SendAnswer;
    };

    /* mark the incoming FD as always ready */
    dynamic_cast<MockupFDMultiplexer*>(threadData.mplexer.get())->setReady(-1);

    auto state = std::make_shared<IncomingTCPConnectionState>(ConnectionInfo(&localCS), threadData, now);
    IncomingTCPConnectionState::handleIO(state, now);
    while (threadData.mplexer->getWatchedFDCount(false) != 0 || threadData.mplexer->getWatchedFDCount(true) != 0) {
      threadData.mplexer->run(&now);
    }
    BOOST_CHECK_EQUAL(s_writeBuffer.size(), query.size());
  }

  {
#if 0
    /* 10k self-generated REFUSED on the same connection */
    size_t count = 10000;
    s_readBuffer->clear();
    s_writeBuffer.clear();
    s_steps = { { ExpectedStep::ExpectedRequest::handshake, IOState::Done } };

    for (size_t idx = 0; idx < count; idx++) {
      s_readBuffer->insert(s_readBuffer->end(), query.begin(), query.end());
      s_steps.push_back({ ExpectedStep::ExpectedRequest::read, IOState::Done, 2 });
      s_steps.push_back({ ExpectedStep::ExpectedRequest::read, IOState::Done, query.size() - 2 });
      s_steps.push_back({ ExpectedStep::ExpectedRequest::write, IOState::Done, query.size() + 2 });
    };
    s_steps.push_back({ ExpectedStep::ExpectedRequest::read, IOState::Done, 0 });
    s_steps.push_back({ ExpectedStep::ExpectedRequest::close, IOState::Done });

    size_t counter = 0;
    s_processQuery = [&counter](DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend) -> ProcessQueryResult {
      // Would be nicer to actually turn it into a response
      return ProcessQueryResult::SendAnswer;
    };

    auto state = std::make_shared<IncomingTCPConnectionState>(ConnectionInfo(&localCS), threadData, now);
    IncomingTCPConnectionState::handleIO(state, now);
    BOOST_CHECK_EQUAL(s_writeBuffer.size(), query.size() * count);
#endif
  }
}

BOOST_AUTO_TEST_SUITE_END();
