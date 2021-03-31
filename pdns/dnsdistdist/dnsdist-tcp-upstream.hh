#pragma once

#include "dolog.hh"
#include "dnsdist-tcp.hh"

class TCPClientThreadData
{
public:
  TCPClientThreadData(): localRespRuleActions(g_respruleactions.getLocal()), mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent()))
  {
  }

  LocalHolders holders;
  LocalStateHolder<vector<DNSDistResponseRuleAction> > localRespRuleActions;
  std::unique_ptr<FDMultiplexer> mplexer{nullptr};
};

class IncomingTCPConnectionState : public TCPQuerySender, public std::enable_shared_from_this<IncomingTCPConnectionState>
{
public:
  IncomingTCPConnectionState(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now): d_buffer(s_maxPacketCacheEntrySize), d_threadData(threadData), d_ci(std::move(ci)), d_handler(d_ci.fd, timeval{g_tcpRecvTimeout,0}, d_ci.cs->tlsFrontend ? d_ci.cs->tlsFrontend->getContext() : nullptr, now.tv_sec), d_ioState(make_unique<IOStateHandler>(threadData.mplexer, d_ci.fd)), d_connectionStartTime(now)
  {
    d_origDest.reset();
    d_origDest.sin4.sin_family = d_ci.remote.sin4.sin_family;
    socklen_t socklen = d_origDest.getSocklen();
    if (getsockname(d_ci.fd, reinterpret_cast<sockaddr*>(&d_origDest), &socklen)) {
      d_origDest = d_ci.cs->local;
    }
    /* belongs to the handler now */
    d_ci.fd = -1;
    d_proxiedDestination = d_origDest;
    d_proxiedRemote = d_ci.remote;
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
    }

    return false;
  }

  std::shared_ptr<TCPConnectionToBackend> getActiveDownstreamConnection(const std::shared_ptr<DownstreamState>& ds, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs);
  std::shared_ptr<TCPConnectionToBackend> getDownstreamConnection(std::shared_ptr<DownstreamState>& ds, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs, const struct timeval& now);
  void registerActiveDownstreamConnection(std::shared_ptr<TCPConnectionToBackend>& conn);

  static size_t clearAllDownstreamConnections();

  static void handleIO(std::shared_ptr<IncomingTCPConnectionState>& conn, const struct timeval& now);
  static void handleIOCallback(int fd, FDMultiplexer::funcparam_t& param);

  static IOState sendResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response);
  static void queueResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response);
static void handleTimeout(std::shared_ptr<IncomingTCPConnectionState>& state, bool write);

  /* we take a copy of a shared pointer, not a reference, because the initial shared pointer might be released during the handling of the response */
  void handleResponse(const struct timeval& now, TCPResponse&& response) override;
  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override;
  void notifyIOError(IDState&& query, const struct timeval& now) override;

  void terminateClientConnection();
  void queueQuery(TCPQuery&& query);

  bool canAcceptNewQueries(const struct timeval& now);

  bool active() const override
  {
    return d_ioState != nullptr;
  }

  const ClientState& getClientState() override
  {
    return *d_ci.cs;
  }

  std::string toString() const
  {
    ostringstream o;
    o << "Incoming TCP connection from "<<d_ci.remote.toStringWithPort()<<" over FD "<<d_handler.getDescriptor()<<", state is "<<(int)d_state<<", io state is "<<(d_ioState ? std::to_string((int)d_ioState->getState()) : "empty")<<", queries count is "<<d_queriesCount<<", current queries count is "<<d_currentQueriesCount<<", "<<d_queuedResponses.size()<<" queued responses, "<<d_activeConnectionsToBackend.size()<<" active connections to a backend";
    return o.str();
  }

  enum class State { doingHandshake, readingProxyProtocolHeader, waitingForQuery, readingQuerySize, readingQuery, sendingResponse, idle /* in case of XFR, we stop processing queries */ };

  std::map<std::shared_ptr<DownstreamState>, std::deque<std::shared_ptr<TCPConnectionToBackend>>> d_activeConnectionsToBackend;
  PacketBuffer d_buffer;
  std::deque<TCPResponse> d_queuedResponses;
  TCPClientThreadData& d_threadData;
  TCPResponse d_currentResponse;
  ConnectionInfo d_ci;
  ComboAddress d_origDest;
  ComboAddress d_proxiedRemote;
  ComboAddress d_proxiedDestination;
  TCPIOHandler d_handler;
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  std::unique_ptr<std::vector<ProxyProtocolValue>> d_proxyProtocolValues{nullptr};
  struct timeval d_connectionStartTime;
  struct timeval d_handshakeDoneTime;
  struct timeval d_firstQuerySizeReadTime;
  struct timeval d_querySizeReadTime;
  struct timeval d_queryReadTime;
  size_t d_currentPos{0};
  size_t d_proxyProtocolNeed{0};
  size_t d_queriesCount{0};
  size_t d_currentQueriesCount{0};
  uint16_t d_querySize{0};
  State d_state{State::doingHandshake};
  bool d_isXFR{false};
  bool d_proxyProtocolPayloadHasTLV{false};
  bool d_lastIOBlocked{false};
  bool d_hadErrors{false};
};
