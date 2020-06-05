#pragma once

#include "dolog.hh"

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

struct ConnectionInfo
{
  ConnectionInfo(ClientState* cs_): cs(cs_), fd(-1)
  {
  }
  ConnectionInfo(ConnectionInfo&& rhs): remote(rhs.remote), cs(rhs.cs), fd(rhs.fd)
  {
    rhs.cs = nullptr;
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
    if (cs) {
      --cs->tcpCurrentConnections;
    }
  }

  ComboAddress remote;
  ClientState* cs{nullptr};
  int fd{-1};
};

class IncomingTCPConnectionState
{
public:
  //IncomingTCPConnectionState(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now): d_buffer(s_maxPacketCacheEntrySize), d_responseBuffer(s_maxPacketCacheEntrySize), d_threadData(threadData), d_ci(std::move(ci)), d_handler(d_ci.fd, g_tcpRecvTimeout, d_ci.cs->tlsFrontend ? d_ci.cs->tlsFrontend->getContext() : nullptr, now.tv_sec), d_ioState(threadData.mplexer, d_ci.fd), _connectionStartTime(now)
  IncomingTCPConnectionState(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now): d_buffer(s_maxPacketCacheEntrySize), d_threadData(threadData), d_ci(std::move(ci)), d_handler(d_ci.fd, g_tcpRecvTimeout, d_ci.cs->tlsFrontend ? d_ci.cs->tlsFrontend->getContext() : nullptr, now.tv_sec), d_ioState(make_unique<IOStateHandler>(threadData.mplexer, d_ci.fd)), d_connectionStartTime(now)
  {
    d_origDest.reset();
    d_origDest.sin4.sin_family = d_ci.remote.sin4.sin_family;
    socklen_t socklen = d_origDest.getSocklen();
    if (getsockname(d_ci.fd, reinterpret_cast<sockaddr*>(&d_origDest), &socklen)) {
      d_origDest = d_ci.cs->local;
    }
  }

  IncomingTCPConnectionState(const IncomingTCPConnectionState& rhs) = delete;
  IncomingTCPConnectionState& operator=(const IncomingTCPConnectionState& rhs) = delete;

  ~IncomingTCPConnectionState();

  void resetForNewQuery();

  boost::optional<struct timeval> getClientReadTTD(struct timeval now) const
  {
    if (g_maxTCPConnectionDuration == 0 && g_tcpRecvTimeout == 0) {
      return boost::none;
    }

    if (g_maxTCPConnectionDuration > 0) {
      auto elapsed = now.tv_sec - d_connectionStartTime.tv_sec;
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

  boost::optional<struct timeval> getClientWriteTTD(const struct timeval& now) const
  {
    if (g_maxTCPConnectionDuration == 0 && g_tcpSendTimeout == 0) {
      return boost::none;
    }

    struct timeval res = now;

    if (g_maxTCPConnectionDuration > 0) {
      auto elapsed = res.tv_sec - d_connectionStartTime.tv_sec;
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

  bool maxConnectionDurationReached(unsigned int maxConnectionDuration, const struct timeval& now)
  {
    if (maxConnectionDuration) {
      time_t curtime = now.tv_sec;
      unsigned int elapsed = 0;
      if (curtime > d_connectionStartTime.tv_sec) { // To prevent issues when time goes backward
        elapsed = curtime - d_connectionStartTime.tv_sec;
      }
      if (elapsed >= maxConnectionDuration) {
        return true;
      }
      d_remainingTime = maxConnectionDuration - elapsed;
    }

    return false;
  }

  void dump() const
  {
    static std::mutex s_mutex;

    struct timeval now;
    gettimeofday(&now, 0);

    {
      std::lock_guard<std::mutex> lock(s_mutex);
      fprintf(stderr, "State is %p\n", this);
      cerr << "Current state is " << static_cast<int>(d_state) << ", got "<<d_queriesCount<<" queries so far" << endl;
      cerr << "Current time is " << now.tv_sec << " - " << now.tv_usec << endl;
      cerr << "Connection started at " << d_connectionStartTime.tv_sec << " - " << d_connectionStartTime.tv_usec << endl;
      if (d_state > State::doingHandshake) {
        cerr << "Handshake done at " << d_handshakeDoneTime.tv_sec << " - " << d_handshakeDoneTime.tv_usec << endl;
      }
      if (d_state > State::readingQuerySize) {
        cerr << "Got first query size at " << d_firstQuerySizeReadTime.tv_sec << " - " << d_firstQuerySizeReadTime.tv_usec << endl;
      }
      if (d_state > State::readingQuerySize) {
        cerr << "Got query size at " << d_querySizeReadTime.tv_sec << " - " << d_querySizeReadTime.tv_usec << endl;
      }
      if (d_state > State::readingQuery) {
        cerr << "Got query at " << d_queryReadTime.tv_sec << " - " << d_queryReadTime.tv_usec << endl;
      }
    }
  }

  std::shared_ptr<TCPConnectionToBackend> getActiveDownstreamConnection(const std::shared_ptr<DownstreamState>& ds)
  {
#warning TODO: we need to find a connection to this DS, usable (no TLV values sent) and supporting OOR
    return nullptr;
  }

  std::shared_ptr<TCPConnectionToBackend> getDownstreamConnection(std::shared_ptr<DownstreamState>& ds, const struct timeval& now);

  std::unique_ptr<FDMultiplexer>& getIOMPlexer() const
  {
    return d_threadData.mplexer;
  }

  static void handleIO(std::shared_ptr<IncomingTCPConnectionState>& conn, const struct timeval& now);
  static void handleIOCallback(int fd, FDMultiplexer::funcparam_t& param);

  void queueQuery(TCPQuery&& query);
  void notifyIOError(std::shared_ptr<IncomingTCPConnectionState>& state, IDState&& query, const struct timeval& now);
  void sendResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response);
  void handleResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response);
  void handleXFRResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response);
  void handleTimeout(bool write);

  bool active() const
  {
    return d_ioState != nullptr;
  }

  enum class State { doingHandshake, readingQuerySize, readingQuery, sendingResponse, idle /* in case of XFR, we stop processing queries */ };

  std::vector<uint8_t> d_buffer;
  std::deque<TCPResponse> d_queuedResponses;
  TCPClientThreadData& d_threadData;
  TCPResponse d_currentResponse;
  ConnectionInfo d_ci;
  ComboAddress d_origDest;
  TCPIOHandler d_handler;
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  struct timeval d_connectionStartTime;
  struct timeval d_handshakeDoneTime;
  struct timeval d_firstQuerySizeReadTime;
  struct timeval d_querySizeReadTime;
  struct timeval d_queryReadTime;
  size_t d_currentPos{0};
  size_t d_queriesCount{0};
  unsigned int d_remainingTime{0};
  uint16_t d_querySize{0};
  uint16_t d_downstreamFailures{0};
  State d_state{State::doingHandshake};
  IOState d_lastIOState{IOState::Done};
  bool d_readingFirstQuery{true};
  bool d_isXFR{false};
  bool d_xfrStarted{false};
  bool d_xfrDone{false};
  bool d_selfGeneratedResponse{false};
  bool d_proxyProtocolPayloadAdded{false};
  bool d_proxyProtocolPayloadHasTLV{false};
};

IOState tryRead(int fd, std::vector<uint8_t>& buffer, size_t& pos, size_t toRead);
