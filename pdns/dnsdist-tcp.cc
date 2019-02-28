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
#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-xpf.hh"

#include "dnsparser.hh"
#include "ednsoptions.hh"
#include "dolog.hh"
#include "lock.hh"
#include "gettime.hh"
#include "tcpiohandler.hh"
#include "threadname.hh"
#include <thread>
#include <atomic>
#include <netinet/tcp.h>

#include "sstuff.hh"

using std::thread;
using std::atomic;

/* TCP: the grand design.
   We forward 'messages' between clients and downstream servers. Messages are 65k bytes large, tops.
   An answer might theoretically consist of multiple messages (for example, in the case of AXFR), initially
   we will not go there.

   In a sense there is a strong symmetry between UDP and TCP, once a connection to a downstream has been setup.
   This symmetry is broken because of head-of-line blocking within TCP though, necessitating additional connections
   to guarantee performance.

   So the idea is to have a 'pool' of available downstream connections, and forward messages to/from them and never queue.
   So whenever an answer comes in, we know where it needs to go.

   Let's start naively.
*/

static thread_local map<ComboAddress, std::deque<std::unique_ptr<Socket>>> t_downstreamSockets;
static std::mutex tcpClientsCountMutex;
static std::map<ComboAddress,size_t,ComboAddress::addressOnlyLessThan> tcpClientsCount;
uint64_t g_maxTCPQueuedConnections{1000};
size_t g_maxTCPQueriesPerConn{0};
size_t g_maxTCPConnectionDuration{0};
size_t g_maxTCPConnectionsPerClient{0};
bool g_useTCPSinglePipe{false};
std::atomic<uint16_t> g_downstreamTCPCleanupInterval{60};

static std::unique_ptr<Socket> setupTCPDownstream(shared_ptr<DownstreamState> ds, uint16_t& downstreamFailures, int timeout)
{
  std::unique_ptr<Socket> result;

  do {
    vinfolog("TCP connecting to downstream %s (%d)", ds->remote.toStringWithPort(), downstreamFailures);
    result = std::unique_ptr<Socket>(new Socket(ds->remote.sin4.sin_family, SOCK_STREAM, 0));
    try {
      if (!IsAnyAddress(ds->sourceAddr)) {
        SSetsockopt(result->getHandle(), SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef IP_BIND_ADDRESS_NO_PORT
        if (ds->ipBindAddrNoPort) {
          SSetsockopt(result->getHandle(), SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
        }
#endif
        result->bind(ds->sourceAddr, false);
      }
      result->setNonBlocking();
#ifdef MSG_FASTOPEN
      if (!ds->tcpFastOpen) {
        SConnectWithTimeout(result->getHandle(), ds->remote, timeout);
      }
#else
      SConnectWithTimeout(result->getHandle(), ds->remote, timeout);
#endif /* MSG_FASTOPEN */
      return result;
    }
    catch(const std::runtime_error& e) {
      vinfolog("Connection to downstream server %s failed: %s", ds->getName(), e.what());
      downstreamFailures++;
      if (downstreamFailures > ds->retries) {
        throw;
      }
    }
  } while(downstreamFailures <= ds->retries);

  return nullptr;
}

static std::unique_ptr<Socket> getConnectionToDownstream(std::shared_ptr<DownstreamState>& ds, uint16_t& downstreamFailures, bool& isFresh)
{
  std::unique_ptr<Socket> result;

  const auto& it = t_downstreamSockets.find(ds->remote);
  if (it != t_downstreamSockets.end()) {
    auto& list = it->second;
    if (!list.empty()) {
      result = std::move(list.front());
      list.pop_front();
      isFresh = false;
      return result;
    }
  }

  isFresh = true;
  return setupTCPDownstream(ds, downstreamFailures, 0);
}

static void releaseDownstreamConnection(std::shared_ptr<DownstreamState>& ds, std::unique_ptr<Socket>&& socket)
{
  const auto& it = t_downstreamSockets.find(ds->remote);
  if (it != t_downstreamSockets.end()) {
    auto& list = it->second;
    if (list.size() >= 20) {
      /* too many connections queued already */
      socket.reset();
      return;
    }
    list.push_back(std::move(socket));
  }
  else {
    t_downstreamSockets[ds->remote].push_back(std::move(socket));
  }
}

struct ConnectionInfo
{
  ConnectionInfo(): cs(nullptr), fd(-1)
  {
  }
  ConnectionInfo(ConnectionInfo&& rhs)
  {
    remote = rhs.remote;
    cs = rhs.cs;
    rhs.cs = nullptr;
    fd = rhs.fd;
    rhs.fd = -1;
  }

  ConnectionInfo(const ConnectionInfo& rhs) = delete;
  ConnectionInfo& operator=(const ConnectionInfo& rhs) = delete;

  ConnectionInfo& operator=(ConnectionInfo&& rhs)
  {
    remote = rhs.remote;
    cs = rhs.cs;
    rhs.cs = nullptr;
    fd = rhs.fd;
    rhs.fd = -1;
    return *this;
  }

  ~ConnectionInfo()
  {
    if (fd != -1) {
      close(fd);
      fd = -1;
    }
  }

  ComboAddress remote;
  ClientState* cs{nullptr};
  int fd{-1};
};

void tcpClientThread(int pipefd);

static void decrementTCPClientCount(const ComboAddress& client)
{
  if (g_maxTCPConnectionsPerClient) {
    std::lock_guard<std::mutex> lock(tcpClientsCountMutex);
    tcpClientsCount[client]--;
    if (tcpClientsCount[client] == 0) {
      tcpClientsCount.erase(client);
    }
  }
}

void TCPClientCollection::addTCPClientThread()
{
  int pipefds[2] = { -1, -1};

  vinfolog("Adding TCP Client thread");

  if (d_useSinglePipe) {
    pipefds[0] = d_singlePipe[0];
    pipefds[1] = d_singlePipe[1];
  }
  else {
    if (pipe(pipefds) < 0) {
      errlog("Error creating the TCP thread communication pipe: %s", strerror(errno));
      return;
    }

    if (!setNonBlocking(pipefds[1])) {
      close(pipefds[0]);
      close(pipefds[1]);
      errlog("Error setting the TCP thread communication pipe non-blocking: %s", strerror(errno));
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(d_mutex);

    if (d_numthreads >= d_tcpclientthreads.capacity()) {
      warnlog("Adding a new TCP client thread would exceed the vector capacity (%d/%d), skipping", d_numthreads.load(), d_tcpclientthreads.capacity());
      if (!d_useSinglePipe) {
        close(pipefds[0]);
        close(pipefds[1]);
      }
      return;
    }

    try {
      thread t1(tcpClientThread, pipefds[0]);
      t1.detach();
    }
    catch(const std::runtime_error& e) {
      /* the thread creation failed, don't leak */
      errlog("Error creating a TCP thread: %s", e.what());
      if (!d_useSinglePipe) {
        close(pipefds[0]);
        close(pipefds[1]);
      }
      return;
    }

    d_tcpclientthreads.push_back(pipefds[1]);
  }

  ++d_numthreads;
}

static void cleanupClosedTCPConnections()
{
  for(auto dsIt = t_downstreamSockets.begin(); dsIt != t_downstreamSockets.end(); ) {
    for (auto socketIt = dsIt->second.begin(); socketIt != dsIt->second.end(); ) {
      if (*socketIt && isTCPSocketUsable((*socketIt)->getHandle())) {
        ++socketIt;
      }
      else {
        socketIt = dsIt->second.erase(socketIt);
      }
    }

    if (!dsIt->second.empty()) {
      ++dsIt;
    }
    else {
      dsIt = t_downstreamSockets.erase(dsIt);
    }
  }
}

/* Tries to read exactly toRead bytes into the buffer, starting at position pos.
   Updates pos everytime a successful read occurs,
   throws an std::runtime_error in case of IO error,
   return Done when toRead bytes have been read, needRead or needWrite if the IO operation
   would block.
*/
// XXX could probably be implemented as a TCPIOHandler
IOState tryRead(int fd, std::vector<uint8_t>& buffer, size_t& pos, size_t toRead)
{
  size_t got = 0;
  do {
    ssize_t res = ::read(fd, reinterpret_cast<char*>(&buffer.at(pos)), toRead - got);
    if (res == 0) {
      throw runtime_error("EOF while reading message");
    }
    if (res < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return IOState::NeedRead;
      }
      else {
        throw std::runtime_error(std::string("Error while reading message: ") + strerror(errno));
      }
    }

    pos += static_cast<size_t>(res);
    got += static_cast<size_t>(res);
  }
  while (got < toRead);

  return IOState::Done;
}

std::shared_ptr<TCPClientCollection> g_tcpclientthreads;

class TCPClientThreadData
{
public:
  TCPClientThreadData(): localRespRulactions(g_resprulactions.getLocal()), mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent()))
  {
  }

  LocalHolders holders;
  LocalStateHolder<vector<DNSDistResponseRuleAction> > localRespRulactions;
  std::unique_ptr<FDMultiplexer> mplexer{nullptr};
};

static void handleDownstreamIOCallback(int fd, FDMultiplexer::funcparam_t& param);

class IncomingTCPConnectionState
{
public:
  IncomingTCPConnectionState(ConnectionInfo&& ci, TCPClientThreadData& threadData, time_t now): d_buffer(4096), d_responseBuffer(4096), d_threadData(threadData), d_ci(std::move(ci)), d_handler(d_ci.fd, g_tcpRecvTimeout, d_ci.cs->tlsFrontend ? d_ci.cs->tlsFrontend->getContext() : nullptr, now), d_connectionStartTime(now)
  {
    d_ids.origDest.reset();
    d_ids.origDest.sin4.sin_family = d_ci.remote.sin4.sin_family;
    socklen_t socklen = d_ids.origDest.getSocklen();
    if (getsockname(d_ci.fd, reinterpret_cast<sockaddr*>(&d_ids.origDest), &socklen)) {
      d_ids.origDest = d_ci.cs->local;
    }
  }

  IncomingTCPConnectionState(const IncomingTCPConnectionState& rhs) = delete;
  IncomingTCPConnectionState& operator=(const IncomingTCPConnectionState& rhs) = delete;

  ~IncomingTCPConnectionState()
  {
    decrementTCPClientCount(d_ci.remote);

    if (d_ds != nullptr) {
      if (d_outstanding) {
        --d_ds->outstanding;
      }

      if (d_downstreamSocket) {
        try {
          if (d_lastIOState == IOState::NeedRead) {
            cerr<<__func__<<": removing leftover backend read FD "<<d_downstreamSocket->getHandle()<<endl;
            d_threadData.mplexer->removeReadFD(d_downstreamSocket->getHandle());
          }
          else if (d_lastIOState == IOState::NeedWrite) {
            cerr<<__func__<<": removing leftover backend write FD "<<d_downstreamSocket->getHandle()<<endl;
            d_threadData.mplexer->removeWriteFD(d_downstreamSocket->getHandle());
          }
        }
        catch(const FDMultiplexerException& e) {
          vinfolog("Got an exception when trying to remove a pending IO operation on the socket to the %s backend: %s", d_ds->getName(), e.what());
        }
      }
    }

    try {
      if (d_lastIOState == IOState::NeedRead) {
        cerr<<__func__<<": removing leftover client read FD "<<d_ci.fd<<endl;
        d_threadData.mplexer->removeReadFD(d_ci.fd);
      }
      else if (d_lastIOState == IOState::NeedWrite) {
        cerr<<__func__<<": removing leftover client write FD "<<d_ci.fd<<endl;
        d_threadData.mplexer->removeWriteFD(d_ci.fd);
      }
    }
    catch(const FDMultiplexerException& e) {
      vinfolog("Got an exception when trying to remove a pending IO operation on an incoming TCP connection from %s: %s", d_ci.remote.toStringWithPort(), e.what());
    }
  }

  void resetForNewQuery()
  {
    d_buffer.resize(sizeof(uint16_t));
    d_currentPos = 0;
    d_querySize = 0;
    d_responseSize = 0;
    d_downstreamFailures = 0;
    d_state = State::readingQuerySize;
    d_lastIOState = IOState::Done;
  }

  boost::optional<struct timeval> getClientReadTTD(struct timeval now) const
  {
    if (g_maxTCPConnectionDuration == 0 && g_tcpRecvTimeout == 0) {
      return boost::none;
    }

    if (g_maxTCPConnectionDuration > 0) {
      auto elapsed = now.tv_sec - d_connectionStartTime;
      if (elapsed < 0 || (static_cast<size_t>(elapsed) >= g_maxTCPConnectionDuration)) {
        return now;
      }
      auto remaining = g_maxTCPConnectionDuration - elapsed;
      if (g_tcpRecvTimeout == 0 || remaining <= static_cast<size_t>(g_tcpRecvTimeout)) {
        now.tv_sec += remaining;
        return now;
      }
    }

    now.tv_sec += g_tcpRecvTimeout;
    return now;
  }

  boost::optional<struct timeval> getBackendReadTTD() const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendReadTTD() without any backend selected");
    }
    if (d_ds->tcpRecvTimeout == 0) {
      return boost::none;
    }

    struct timeval res;
    gettimeofday(&res, 0);

    res.tv_sec += d_ds->tcpRecvTimeout;

    return res;
  }

  boost::optional<struct timeval> getClientWriteTTD(boost::optional<struct timeval> now=boost::none) const
  {
    if (g_maxTCPConnectionDuration == 0 && g_tcpSendTimeout == 0) {
      return boost::none;
    }

    struct timeval res;
    if (now) {
      res = *now;
    }
    else {
      gettimeofday(&res, 0);
    }

    if (g_maxTCPConnectionDuration > 0) {
      auto elapsed = res.tv_sec - d_connectionStartTime;
      if (elapsed < 0 || static_cast<size_t>(elapsed) >= g_maxTCPConnectionDuration) {
        return res;
      }
      auto remaining = g_maxTCPConnectionDuration - elapsed;
      if (g_tcpSendTimeout == 0 || remaining <= static_cast<size_t>(g_tcpSendTimeout)) {
        res.tv_sec += remaining;
        return res;
      }
    }

    res.tv_sec += g_tcpSendTimeout;
    return res;
  }

  boost::optional<struct timeval> getBackendWriteTTD() const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendReadTTD() called without any backend selected");
    }
    if (d_ds->tcpSendTimeout == 0) {
      return boost::none;
    }

    struct timeval res;
    gettimeofday(&res, 0);

    res.tv_sec += d_ds->tcpSendTimeout;

    return res;
  }

  bool maxConnectionDurationReached(unsigned int maxConnectionDuration, const struct timeval now)
  {
    if (maxConnectionDuration) {
      time_t curtime = now.tv_sec;
      unsigned int elapsed = 0;
      if (curtime > d_connectionStartTime) { // To prevent issues when time goes backward
        elapsed = curtime - d_connectionStartTime;
      }
      if (elapsed >= maxConnectionDuration) {
        return true;
      }
      d_remainingTime = maxConnectionDuration - elapsed;
    }

    return false;
  }

  enum class State { doingHandshake, readingQuerySize, readingQuery, sendingQueryToBackend, readingResponseSizeFromBackend, readingResponseFromBackend, sendingResponse };

  std::vector<uint8_t> d_buffer;
  std::vector<uint8_t> d_responseBuffer;
  TCPClientThreadData& d_threadData;
  IDState d_ids;
  ConnectionInfo d_ci;
  TCPIOHandler d_handler;
  std::unique_ptr<Socket> d_downstreamSocket{nullptr};
  std::shared_ptr<DownstreamState> d_ds{nullptr};
  size_t d_currentPos{0};
  size_t d_queriesCount{0};
  time_t d_connectionStartTime;
  unsigned int d_remainingTime{0};
  uint16_t d_querySize{0};
  uint16_t d_responseSize{0};
  uint16_t d_downstreamFailures{0};
  State d_state{State::doingHandshake};
  IOState d_lastIOState{IOState::Done};
  bool d_freshDownstreamConnection{false};
  bool d_readingFirstQuery{true};
  bool d_outstanding{false};
  bool d_firstResponsePacket{true};
  bool d_isXFR{false};
  bool d_xfrStarted{false};
};

static void handleIOCallback(int fd, FDMultiplexer::funcparam_t& param);
static void handleNewIOState(std::shared_ptr<IncomingTCPConnectionState>& state, IOState iostate, const int fd, FDMultiplexer::callbackfunc_t callback, boost::optional<struct timeval> ttd=boost::none);

static void handleResponseSent(std::shared_ptr<IncomingTCPConnectionState>& state)
{
  handleNewIOState(state, IOState::Done, state->d_ci.fd, handleIOCallback);

  if (state->d_isXFR && state->d_downstreamSocket) {
    /* we need to resume reading from the backend! */
    state->d_state = IncomingTCPConnectionState::State::readingResponseSizeFromBackend;
    state->d_currentPos = 0;
    //cerr<<__func__<<": add read client FD "<<state->d_ci.fd<<endl;
    handleNewIOState(state, IOState::NeedRead, state->d_downstreamSocket->getHandle(), handleDownstreamIOCallback, state->getBackendReadTTD());
    return;
  }

  if (g_maxTCPQueriesPerConn && state->d_queriesCount > g_maxTCPQueriesPerConn) {
    vinfolog("Terminating TCP connection from %s because it reached the maximum number of queries per conn (%d / %d)", state->d_ci.remote.toStringWithPort(), state->d_queriesCount, g_maxTCPQueriesPerConn);
    return;
  }

  struct timeval now;
  gettimeofday(&now, 0);
  if (state->maxConnectionDurationReached(g_maxTCPConnectionDuration, now)) {
    vinfolog("Terminating TCP connection from %s because it reached the maximum TCP connection duration", state->d_ci.remote.toStringWithPort());
    return;
  }

  state->resetForNewQuery();
  //cerr<<__func__<<": add read client FD "<<state->d_ci.fd<<endl;
  handleNewIOState(state, IOState::NeedRead, state->d_ci.fd, handleIOCallback, state->getClientReadTTD(now));
}

static void sendResponse(std::shared_ptr<IncomingTCPConnectionState>& state)
{
  state->d_state = IncomingTCPConnectionState::State::sendingResponse;
  const uint8_t sizeBytes[] = { static_cast<uint8_t>(state->d_responseSize / 256), static_cast<uint8_t>(state->d_responseSize % 256) };
  /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
     that could occur if we had to deal with the size during the processing,
     especially alignment issues */
  state->d_responseBuffer.insert(state->d_responseBuffer.begin(), sizeBytes, sizeBytes + 2);

  state->d_currentPos = 0;

  auto iostate = state->d_handler.tryWrite(state->d_responseBuffer, state->d_currentPos, state->d_responseBuffer.size());
  if (iostate == IOState::Done) {

    handleResponseSent(state);
    return;
  }
  else {
    //cerr<<__func__<<": adding client write FD "<<state->d_ci.fd<<endl;
    handleNewIOState(state, IOState::NeedWrite, state->d_ci.fd, handleIOCallback, state->getClientWriteTTD());
  }
}

static void handleResponse(std::shared_ptr<IncomingTCPConnectionState>& state)
{
  if (state->d_responseSize < sizeof(dnsheader)) {
    return;
  }

  auto response = reinterpret_cast<char*>(&state->d_responseBuffer.at(0));
  unsigned int consumed;
  if (state->d_firstResponsePacket && !responseContentMatches(response, state->d_responseSize, state->d_ids.qname, state->d_ids.qtype, state->d_ids.qclass, state->d_ds->remote, consumed)) {
    return;
  }
  state->d_firstResponsePacket = false;

  if (state->d_outstanding) {
    --state->d_ds->outstanding;
    state->d_outstanding = false;
  }

  auto dh = reinterpret_cast<struct dnsheader*>(response);
  uint16_t addRoom = 0;
  DNSResponse dr = makeDNSResponseFromIDState(state->d_ids, dh, state->d_responseBuffer.size(), state->d_responseSize, true);
  if (dr.dnsCryptQuery) {
    addRoom = DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
  }

  dnsheader cleartextDH;
  memcpy(&cleartextDH, dr.dh, sizeof(cleartextDH));

  std::vector<uint8_t> rewrittenResponse;
  size_t responseSize = state->d_responseBuffer.size();
  if (!processResponse(&response, &state->d_responseSize, &responseSize, state->d_threadData.localRespRulactions, dr, addRoom, rewrittenResponse, false)) {
    return;
  }

  if (!rewrittenResponse.empty()) {
    /* responseSize has been updated as well but we don't really care since it will match
       the capacity of rewrittenResponse anyway */
    state->d_responseBuffer = std::move(rewrittenResponse);
    state->d_responseSize = state->d_responseBuffer.size();
  } else {
    /* the size might have been updated (shrinked) if we removed the whole OPT RR, for example) */
    state->d_responseBuffer.resize(state->d_responseSize);
  }

  if (state->d_isXFR && !state->d_xfrStarted) {
    /* don't bother parsing the content of the response for now */
    state->d_xfrStarted = true;
  }

  sendResponse(state);

  ++g_stats.responses;
  struct timespec answertime;
  gettime(&answertime);
  double udiff = state->d_ids.sentTime.udiff();
  g_rings.insertResponse(answertime, state->d_ci.remote, *dr.qname, dr.qtype, static_cast<unsigned int>(udiff), static_cast<unsigned int>(state->d_responseBuffer.size()), cleartextDH, state->d_ds->remote);
}

static void sendQueryToBackend(std::shared_ptr<IncomingTCPConnectionState>& state)
{
  auto ds = state->d_ds;
  state->d_state = IncomingTCPConnectionState::State::sendingQueryToBackend;
  state->d_currentPos = 0;
  state->d_firstResponsePacket = true;
  state->d_downstreamSocket.reset();

  if (state->d_xfrStarted) {
    /* sorry, but we are not going to resume a XFR if we have already sent some packets
       to the client */
    return;
  }

  while (state->d_downstreamFailures < state->d_ds->retries)
  {
    state->d_downstreamSocket = getConnectionToDownstream(ds, state->d_downstreamFailures, state->d_freshDownstreamConnection);

    if (!state->d_downstreamSocket) {
      vinfolog("Downstream connection to %s failed %d times in a row, giving up.", ds->getName(), state->d_downstreamFailures);
      return;
    }

    //cerr<<__func__<<": add write backend FD "<<state->d_downstreamSocket->getHandle()<<endl;
    handleNewIOState(state, IOState::NeedWrite, state->d_downstreamSocket->getHandle(), handleDownstreamIOCallback, state->getBackendWriteTTD());
    return;
  }

  vinfolog("Downstream connection to %s failed %u times in a row, giving up.", ds->getName(), state->d_downstreamFailures);
}

static void handleQuery(std::shared_ptr<IncomingTCPConnectionState>& state)
{
  if (state->d_querySize < sizeof(dnsheader)) {
    ++g_stats.nonCompliantQueries;
    return;
  }

  state->d_readingFirstQuery = false;
  ++state->d_queriesCount;
  ++state->d_ci.cs->queries;
  ++g_stats.queries;

  /* we need an accurate ("real") value for the response and
     to store into the IDS, but not for insertion into the
     rings for example */
  struct timespec now;
  struct timespec queryRealTime;
  gettime(&now);
  gettime(&queryRealTime, true);

  auto query = reinterpret_cast<char*>(&state->d_buffer.at(0));
  std::shared_ptr<DNSCryptQuery> dnsCryptQuery{nullptr};
  auto dnsCryptResponse = checkDNSCryptQuery(*state->d_ci.cs, query, state->d_querySize, dnsCryptQuery, queryRealTime.tv_sec, true);
  if (dnsCryptResponse) {
    state->d_responseBuffer = std::move(*dnsCryptResponse);
    state->d_responseSize = state->d_responseBuffer.size();
    sendResponse(state);
    return;
  }

  const auto& dh = reinterpret_cast<dnsheader*>(query);
  if (!checkQueryHeaders(dh)) {
    return;
  }

  uint16_t qtype, qclass;
  unsigned int consumed = 0;
  DNSName qname(query, state->d_querySize, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  DNSQuestion dq(&qname, qtype, qclass, consumed, &state->d_ids.origDest, &state->d_ci.remote, reinterpret_cast<dnsheader*>(query), state->d_buffer.size(), state->d_querySize, true, &queryRealTime);
  dq.dnsCryptQuery = std::move(dnsCryptQuery);

  state->d_isXFR = (dq.qtype == QType::AXFR || dq.qtype == QType::IXFR);
  if (state->d_isXFR) {
    dq.skipCache = true;
  }

  state->d_ds.reset();
  auto result = processQuery(dq, *state->d_ci.cs, state->d_threadData.holders, state->d_ds);

  if (result == ProcessQueryResult::Drop) {
    return;
  }

  if (result == ProcessQueryResult::SendAnswer) {
    state->d_buffer.resize(dq.len);
    state->d_responseBuffer = std::move(state->d_buffer);
    state->d_responseSize = state->d_responseBuffer.size();
    sendResponse(state);
    return;
  }

  if (result != ProcessQueryResult::PassToBackend || state->d_ds == nullptr) {
    return;
  }

  state->d_buffer.resize(dq.len);
  setIDStateFromDNSQuestion(state->d_ids, dq, std::move(qname));

  const uint8_t sizeBytes[] = { static_cast<uint8_t>(dq.len / 256), static_cast<uint8_t>(dq.len % 256) };
  /* prepend the size. Yes, this is not the most efficient way but it prevents mistakes
     that could occur if we had to deal with the size during the processing,
     especially alignment issues */
  state->d_buffer.insert(state->d_buffer.begin(), sizeBytes, sizeBytes + 2);
  sendQueryToBackend(state);
}

static void handleNewIOState(std::shared_ptr<IncomingTCPConnectionState>& state, IOState iostate, const int fd, FDMultiplexer::callbackfunc_t callback, boost::optional<struct timeval> ttd)
{
  //cerr<<"in "<<__func__<<" for fd "<<fd<<", last state was "<<(int)state->d_lastIOState<<", new state is "<<(int)iostate<<endl;

  if (state->d_lastIOState == IOState::NeedRead && iostate != IOState::NeedRead) {
    state->d_threadData.mplexer->removeReadFD(fd);
    //cerr<<__func__<<": remove read FD "<<fd<<endl;
    state->d_lastIOState = IOState::Done;
  }
  else if (state->d_lastIOState == IOState::NeedWrite && iostate != IOState::NeedWrite) {
    state->d_threadData.mplexer->removeWriteFD(fd);
    //cerr<<__func__<<": remove write FD "<<fd<<endl;
    state->d_lastIOState = IOState::Done;
  }

  if (iostate == IOState::NeedRead) {
    if (state->d_lastIOState == IOState::NeedRead) {
      if (ttd) {
        /* let's update the TTD ! */
        state->d_threadData.mplexer->setReadTTD(fd, *ttd, /* we pass 0 here because we already have a TTD */0);
      }
      return;
    }

    state->d_lastIOState = IOState::NeedRead;
    //cerr<<__func__<<": add read FD "<<fd<<endl;
    state->d_threadData.mplexer->addReadFD(fd, callback, state, ttd ? &*ttd : nullptr);
  }
  else if (iostate == IOState::NeedWrite) {
    if (state->d_lastIOState == IOState::NeedWrite) {
      return;
    }

    state->d_lastIOState = IOState::NeedWrite;
    //cerr<<__func__<<": add write FD "<<fd<<endl;
    state->d_threadData.mplexer->addWriteFD(fd, callback, state, ttd ? &*ttd : nullptr);
  }
  else if (iostate == IOState::Done) {
    state->d_lastIOState = IOState::Done;
  }
}

static void handleDownstreamIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);
  if (state->d_downstreamSocket == nullptr) {
    throw std::runtime_error("No downstream socket in " + std::string(__func__) + "!");
  }
  if (fd != state->d_downstreamSocket->getHandle()) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__func__) + ", expected " + std::to_string(state->d_downstreamSocket->getHandle()));
  }

  IOState iostate = IOState::Done;
  bool connectionDied = false;

  try {
    if (state->d_state == IncomingTCPConnectionState::State::sendingQueryToBackend) {
      int socketFlags = 0;
#ifdef MSG_FASTOPEN
      if (state->d_ds->tcpFastOpen && state->d_freshDownstreamConnection) {
        socketFlags |= MSG_FASTOPEN;
      }
#endif /* MSG_FASTOPEN */

      size_t sent = sendMsgWithTimeout(fd, reinterpret_cast<const char *>(&state->d_buffer.at(state->d_currentPos)), state->d_buffer.size() - state->d_currentPos, 0, &state->d_ds->remote, &state->d_ds->sourceAddr, state->d_ds->sourceItf, 0, socketFlags);
      if (sent == state->d_buffer.size()) {
        /* request sent ! */
        state->d_state = IncomingTCPConnectionState::State::readingResponseSizeFromBackend;
        state->d_currentPos = 0;
        iostate = IOState::NeedRead;
        if (!state->d_isXFR) {
          /* don't bother with the outstanding count for XFR queries */
          ++state->d_ds->outstanding;
          state->d_outstanding = true;
        }
      }
      else {
        state->d_currentPos += sent;
        iostate = IOState::NeedWrite;
        /* disable fast open on partial write */
        state->d_freshDownstreamConnection = false;
      }
    }

    if (state->d_state == IncomingTCPConnectionState::State::readingResponseSizeFromBackend) {
      // then we need to allocate a new buffer (new because we might need to re-send the query if the
      // backend dies on us
      // We also might need to read and send to the client more than one response in case of XFR (yeah!)
      // should very likely be a TCPIOHandler d_downstreamHandler
      iostate = tryRead(fd, state->d_responseBuffer, state->d_currentPos, sizeof(uint16_t) - state->d_currentPos);
      if (iostate == IOState::Done) {
        state->d_state = IncomingTCPConnectionState::State::readingResponseFromBackend;
        state->d_responseSize = state->d_responseBuffer.at(0) * 256 + state->d_responseBuffer.at(1);
        state->d_responseBuffer.resize((state->d_ids.dnsCryptQuery && (UINT16_MAX - state->d_responseSize) > static_cast<uint16_t>(DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE)) ? state->d_responseSize + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE : state->d_responseSize);
        state->d_currentPos = 0;
      }
    }

    if (state->d_state == IncomingTCPConnectionState::State::readingResponseFromBackend) {
      iostate = tryRead(fd, state->d_responseBuffer, state->d_currentPos, state->d_responseSize - state->d_currentPos);
      if (iostate == IOState::Done) {
        handleNewIOState(state, IOState::Done, fd, handleDownstreamIOCallback);

        if (state->d_isXFR) {
          /* Don't reuse the TCP connection after an {A,I}XFR */
          /* but don't reset it either, we will need to read more messages */
        }
        else {
          releaseDownstreamConnection(state->d_ds, std::move(state->d_downstreamSocket));
        }
        fd = -1;

        handleResponse(state);
        return;
      }
    }

    if (state->d_state != IncomingTCPConnectionState::State::sendingQueryToBackend &&
        state->d_state != IncomingTCPConnectionState::State::readingResponseSizeFromBackend &&
        state->d_state != IncomingTCPConnectionState::State::readingResponseFromBackend) {
      vinfolog("Unexpected state %d in handleDownstreamIOCallback", static_cast<int>(state->d_state));
    }
  }
  catch(const std::exception& e) {
    /* most likely an EOF because the other end closed the connection,
       but it might also be a real IO error or something else.
       Let's just drop the connection
    */
    vinfolog("Got an exception while handling (%s backend) TCP query from %s: %s", (state->d_lastIOState == IOState::NeedRead ? "reading from" : "writing to"), state->d_ci.remote.toStringWithPort(), e.what());
    /* remove this FD from the IO multiplexer */
    ++state->d_downstreamFailures;
    if (state->d_outstanding && state->d_ds != nullptr) {
      --state->d_ds->outstanding;
    }
    iostate = IOState::Done;
    connectionDied = true;
  }

  if (iostate == IOState::Done) {
    handleNewIOState(state, iostate, fd, handleDownstreamIOCallback);
  }
  else {
    handleNewIOState(state, iostate, fd, handleDownstreamIOCallback, iostate == IOState::NeedRead ? state->getBackendReadTTD() : state->getBackendWriteTTD());
  }

  if (connectionDied) {
    sendQueryToBackend(state);
  }
}

static void handleIOCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(param);
  if (fd != state->d_ci.fd) {
    throw std::runtime_error("Unexpected socket descriptor " + std::to_string(fd) + " received in " + std::string(__func__) + ", expected " + std::to_string(state->d_ci.fd));
  }

  IOState iostate = IOState::Done;

  struct timeval now;
  gettimeofday(&now, 0);
  if (state->maxConnectionDurationReached(g_maxTCPConnectionDuration, now)) {
    vinfolog("Terminating TCP connection from %s because it reached the maximum TCP connection duration", state->d_ci.remote.toStringWithPort());
    handleNewIOState(state, IOState::Done, fd, handleIOCallback);
    return;
  }

  try {
    if (state->d_state == IncomingTCPConnectionState::State::doingHandshake) {
      iostate = state->d_handler.tryHandshake();
      if (iostate == IOState::Done) {
        state->d_state = IncomingTCPConnectionState::State::readingQuerySize;
      }
    }

    if (state->d_state == IncomingTCPConnectionState::State::readingQuerySize) {
      iostate = state->d_handler.tryRead(state->d_buffer, state->d_currentPos, sizeof(uint16_t) - state->d_currentPos);
      if (iostate == IOState::Done) {
        state->d_state = IncomingTCPConnectionState::State::readingQuery;
        state->d_querySize = state->d_buffer.at(0) * 256 + state->d_buffer.at(1);
        if (state->d_querySize < sizeof(dnsheader)) {
          /* go away */
          handleNewIOState(state, IOState::Done, fd, handleIOCallback);
          return;
        }

        /* allocate a bit more memory to be able to spoof the content,
           or to add ECS without allocating a new buffer */
        state->d_buffer.resize(state->d_querySize + 512);
        state->d_currentPos = 0;
      }
    }

    if (state->d_state == IncomingTCPConnectionState::State::readingQuery) {
      iostate = state->d_handler.tryRead(state->d_buffer, state->d_currentPos, state->d_querySize);
      if (iostate == IOState::Done) {
        handleNewIOState(state, IOState::Done, fd, handleIOCallback);
        handleQuery(state);
        return;
      }
    }

    if (state->d_state == IncomingTCPConnectionState::State::sendingResponse) {
      iostate = state->d_handler.tryWrite(state->d_buffer, state->d_currentPos, state->d_buffer.size());
      if (iostate == IOState::Done) {
        handleResponseSent(state);
        return;
      }
    }

    if (state->d_state != IncomingTCPConnectionState::State::doingHandshake &&
        state->d_state != IncomingTCPConnectionState::State::readingQuerySize &&
        state->d_state != IncomingTCPConnectionState::State::readingQuery &&
        state->d_state != IncomingTCPConnectionState::State::sendingResponse) {
      vinfolog("Unexpected state %d in handleIOCallback", static_cast<int>(state->d_state));
    }
  }
  catch(const std::exception& e) {
    /* most likely an EOF because the other end closed the connection,
       but it might also be a real IO error or something else.
       Let's just drop the connection
    */
    if (state->d_lastIOState == IOState::NeedWrite || state->d_readingFirstQuery) {
      vinfolog("Got an exception while handling (%s) TCP query from %s: %s", (state->d_lastIOState == IOState::NeedRead ? "reading" : "writing"), state->d_ci.remote.toStringWithPort(), e.what());
    }
    else {
      vinfolog("Closing TCP client connection with %s", state->d_ci.remote.toStringWithPort());
    }
    /* remove this FD from the IO multiplexer */
    iostate = IOState::Done;
  }

  if (iostate == IOState::Done) {
    handleNewIOState(state, iostate, fd, handleIOCallback);
  }
  else {
    handleNewIOState(state, iostate, fd, handleIOCallback, iostate == IOState::NeedRead ? state->getClientReadTTD(now) : state->getClientWriteTTD(now));
  }
}

static void handleIncomingTCPQuery(int pipefd, FDMultiplexer::funcparam_t& param)
{
  auto threadData = boost::any_cast<TCPClientThreadData*>(param);

  ConnectionInfo* citmp{nullptr};

  try {
    readn2(pipefd, &citmp, sizeof(citmp));
  }
  catch(const std::runtime_error& e) {
    throw std::runtime_error("Error reading from TCP acceptor pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode: " + e.what());
  }

  g_tcpclientthreads->decrementQueuedCount();
  auto ci = std::move(*citmp);
  delete citmp;
  citmp = nullptr;

  struct timeval now;
  gettimeofday(&now, 0);
  auto state = std::make_shared<IncomingTCPConnectionState>(std::move(ci), *threadData, now.tv_sec);

  /* let's update the remaining time */
  state->d_remainingTime = g_maxTCPConnectionDuration;

  /* we could try reading right away, but let's not for now */
  handleNewIOState(state, IOState::NeedRead, state->d_ci.fd, handleIOCallback, state->getClientReadTTD(now));
}

void tcpClientThread(int pipefd)
{
  /* we get launched with a pipe on which we receive file descriptors from clients that we own
     from that point on */

  setThreadName("dnsdist/tcpClie");

  TCPClientThreadData data;

  data.mplexer->addReadFD(pipefd, handleIncomingTCPQuery, &data);
  time_t lastTCPCleanup = time(nullptr);
  struct timeval now;
  gettimeofday(&now, 0);

  for (;;) {
    data.mplexer->run(&now);

    if (g_downstreamTCPCleanupInterval > 0 && (now.tv_sec > (lastTCPCleanup + g_downstreamTCPCleanupInterval))) {
      cleanupClosedTCPConnections();
      lastTCPCleanup = now.tv_sec;
    }

    auto expiredReadConns = data.mplexer->getTimeouts(now, false);
    for(const auto& conn : expiredReadConns) {
      auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(conn.second);
      if (conn.first == state->d_ci.fd) {
        vinfolog("Timeout (read) from remote TCP client %s", state->d_ci.remote.toStringWithPort());
      }
      else if (state->d_ds) {
        vinfolog("Timeout (read) from remote backend %s", state->d_ds->getName());
      }
      data.mplexer->removeReadFD(conn.first);
      state->d_lastIOState = IOState::Done;
    }

    auto expiredWriteConns = data.mplexer->getTimeouts(now, true);
    for(const auto& conn : expiredWriteConns) {
      auto state = boost::any_cast<std::shared_ptr<IncomingTCPConnectionState>>(conn.second);
      if (conn.first == state->d_ci.fd) {
        vinfolog("Timeout (write) from remote TCP client %s", state->d_ci.remote.toStringWithPort());
      }
      else if (state->d_ds) {
        vinfolog("Timeout (write) from remote backend %s", state->d_ds->getName());
      }
      data.mplexer->removeWriteFD(conn.first);
      state->d_lastIOState = IOState::Done;
    }
  }
}

/* spawn as many of these as required, they call Accept on a socket on which they will accept queries, and
   they will hand off to worker threads & spawn more of them if required
*/
void tcpAcceptorThread(void* p)
{
  setThreadName("dnsdist/tcpAcce");
  ClientState* cs = (ClientState*) p;
  bool tcpClientCountIncremented = false;
  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;

  g_tcpclientthreads->addTCPClientThread();

  auto acl = g_ACL.getLocal();
  for(;;) {
    bool queuedCounterIncremented = false;
    std::unique_ptr<ConnectionInfo> ci;
    tcpClientCountIncremented = false;
    try {
      socklen_t remlen = remote.getSocklen();
      ci = std::unique_ptr<ConnectionInfo>(new ConnectionInfo);
      ci->cs = cs;
#ifdef HAVE_ACCEPT4
      ci->fd = accept4(cs->tcpFD, reinterpret_cast<struct sockaddr*>(&remote), &remlen, SOCK_NONBLOCK);
#else
      ci->fd = accept(cs->tcpFD, reinterpret_cast<struct sockaddr*>(&remote), &remlen);
#endif
      if(ci->fd < 0) {
        throw std::runtime_error((boost::format("accepting new connection on socket: %s") % strerror(errno)).str());
      }

      if(!acl->match(remote)) {
	++g_stats.aclDrops;
	vinfolog("Dropped TCP connection from %s because of ACL", remote.toStringWithPort());
	continue;
      }

#ifndef HAVE_ACCEPT4
      if (!setNonBlocking(ci->fd)) {
        continue;
      }
#endif
      setTCPNoDelay(ci->fd);  // disable NAGLE
      if(g_maxTCPQueuedConnections > 0 && g_tcpclientthreads->getQueuedCount() >= g_maxTCPQueuedConnections) {
        vinfolog("Dropping TCP connection from %s because we have too many queued already", remote.toStringWithPort());
        continue;
      }

      if (g_maxTCPConnectionsPerClient) {
        std::lock_guard<std::mutex> lock(tcpClientsCountMutex);

        if (tcpClientsCount[remote] >= g_maxTCPConnectionsPerClient) {
          vinfolog("Dropping TCP connection from %s because we have too many from this client already", remote.toStringWithPort());
          continue;
        }
        tcpClientsCount[remote]++;
        tcpClientCountIncremented = true;
      }

      vinfolog("Got TCP connection from %s", remote.toStringWithPort());

      ci->remote = remote;
      int pipe = g_tcpclientthreads->getThread();
      if (pipe >= 0) {
        queuedCounterIncremented = true;
        auto tmp = ci.release();
        try {
          writen2WithTimeout(pipe, &tmp, sizeof(tmp), 0);
        }
        catch(...) {
          delete tmp;
          tmp = nullptr;
          throw;
        }
      }
      else {
        g_tcpclientthreads->decrementQueuedCount();
        queuedCounterIncremented = false;
        if(tcpClientCountIncremented) {
          decrementTCPClientCount(remote);
        }
      }
    }
    catch(const std::exception& e) {
      errlog("While reading a TCP question: %s", e.what());
      if(tcpClientCountIncremented) {
        decrementTCPClientCount(remote);
      }
      if (queuedCounterIncremented) {
        g_tcpclientthreads->decrementQueuedCount();
      }
    }
    catch(...){}
  }
}
