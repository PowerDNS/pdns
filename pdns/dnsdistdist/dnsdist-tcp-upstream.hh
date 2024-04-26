#pragma once

#include "dolog.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"

struct TCPCrossProtocolResponse;

class TCPClientThreadData
{
public:
  TCPClientThreadData():
    localRespRuleActions(dnsdist::rules::getResponseRuleChainHolder(dnsdist::rules::ResponseRuleChain::ResponseRules).getLocal()), localCacheInsertedRespRuleActions(dnsdist::rules::getResponseRuleChainHolder(dnsdist::rules::ResponseRuleChain::CacheInsertedResponseRules).getLocal()), localXFRRespRuleActions(dnsdist::rules::getResponseRuleChainHolder(dnsdist::rules::ResponseRuleChain::XFRResponseRules).getLocal()), mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent()))
  {
  }

  LocalHolders holders;
  LocalStateHolder<vector<dnsdist::rules::ResponseRuleAction>> localRespRuleActions;
  LocalStateHolder<vector<dnsdist::rules::ResponseRuleAction>> localCacheInsertedRespRuleActions;
  LocalStateHolder<vector<dnsdist::rules::ResponseRuleAction>> localXFRRespRuleActions;
  std::unique_ptr<FDMultiplexer> mplexer{nullptr};
  pdns::channel::Receiver<ConnectionInfo> queryReceiver;
  pdns::channel::Receiver<CrossProtocolQuery> crossProtocolQueryReceiver;
  pdns::channel::Receiver<TCPCrossProtocolResponse> crossProtocolResponseReceiver;
  pdns::channel::Sender<TCPCrossProtocolResponse> crossProtocolResponseSender;
};

class IncomingTCPConnectionState : public TCPQuerySender, public std::enable_shared_from_this<IncomingTCPConnectionState>
{
public:
  enum class QueryProcessingResult : uint8_t { Forwarded, TooSmall, InvalidHeaders, Dropped, SelfAnswered, NoBackend, Asynchronous };
  enum class ProxyProtocolResult : uint8_t { Reading, Done, Error };

  IncomingTCPConnectionState(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now): d_buffer(sizeof(uint16_t)), d_ci(std::move(ci)), d_handler(d_ci.fd, timeval{g_tcpRecvTimeout,0}, d_ci.cs->tlsFrontend ? d_ci.cs->tlsFrontend->getContext() : (d_ci.cs->dohFrontend ? d_ci.cs->dohFrontend->d_tlsContext.getContext() : nullptr), now.tv_sec), d_connectionStartTime(now), d_ioState(make_unique<IOStateHandler>(*threadData.mplexer, d_ci.fd)), d_threadData(threadData), d_creatorThreadID(std::this_thread::get_id())
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

    /* we manage the release of the downstream connection ourselves */
    d_releaseConnection = false;
  }

  IncomingTCPConnectionState(const IncomingTCPConnectionState& rhs) = delete;
  IncomingTCPConnectionState& operator=(const IncomingTCPConnectionState& rhs) = delete;

  virtual ~IncomingTCPConnectionState();

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

  std::shared_ptr<TCPConnectionToBackend> getOwnedDownstreamConnection(const std::shared_ptr<DownstreamState>& backend, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs);
  std::shared_ptr<TCPConnectionToBackend> getDownstreamConnection(std::shared_ptr<DownstreamState>& backend, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs, const struct timeval& now);
  void registerOwnedDownstreamConnection(std::shared_ptr<TCPConnectionToBackend>& conn);

  static size_t clearAllDownstreamConnections();

  static void handleIOCallback(int desc, FDMultiplexer::funcparam_t& param);
  static void handleAsyncReady(int desc, FDMultiplexer::funcparam_t& param);
  static void updateIO(std::shared_ptr<IncomingTCPConnectionState>& state, IOState newState, const struct timeval& now);

  static void queueResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response, bool fromBackend);
  static void handleTimeout(std::shared_ptr<IncomingTCPConnectionState>& state, bool write);

  virtual void handleIO();

  QueryProcessingResult handleQuery(PacketBuffer&& query, const struct timeval& now, std::optional<int32_t> streamID);
  virtual void handleResponse(const struct timeval& now, TCPResponse&& response) override;
  virtual void notifyIOError(const struct timeval& now, TCPResponse&& response) override;
  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override;

  virtual IOState sendResponse(const struct timeval& now, TCPResponse&& response);
  void handleResponseSent(TCPResponse& currentResponse);
  virtual IOState handleHandshake(const struct timeval& now);
  void handleHandshakeDone(const struct timeval& now);
  ProxyProtocolResult handleProxyProtocolPayload();
  void handleCrossProtocolResponse(const struct timeval& now, TCPResponse&& response);

  void terminateClientConnection();

  bool canAcceptNewQueries(const struct timeval& now);

  bool active() const override
  {
    return d_ioState != nullptr;
  }
  bool isProxyPayloadOutsideTLS() const
  {
    if (!d_ci.cs->hasTLS()) {
      return false;
    }
    return d_ci.cs->getTLSFrontend().d_proxyProtocolOutsideTLS;
  }

  virtual bool forwardViaUDPFirst() const
  {
    return false;
  }
  virtual std::unique_ptr<DOHUnitInterface> getDOHUnit(uint32_t streamID)
  {
    throw std::runtime_error("Getting a DOHUnit state from a generic TCP/DoT connection is not supported");
  }
  virtual void restoreDOHUnit(std::unique_ptr<DOHUnitInterface>&&)
  {
    throw std::runtime_error("Restoring a DOHUnit state to a generic TCP/DoT connection is not supported");
  }

  std::unique_ptr<CrossProtocolQuery> getCrossProtocolQuery(PacketBuffer&& query, InternalQueryState&& state, const std::shared_ptr<DownstreamState>& backend);

  std::string toString() const
  {
    ostringstream o;
    o << "Incoming TCP connection from "<<d_ci.remote.toStringWithPort()<<" over FD "<<d_handler.getDescriptor()<<", state is "<<(int)d_state<<", io state is "<<(d_ioState ? d_ioState->getState() : "empty")<<", queries count is "<<d_queriesCount<<", current queries count is "<<d_currentQueriesCount<<", "<<d_queuedResponses.size()<<" queued responses, "<<d_ownedConnectionsToBackend.size()<<" owned connections to a backend";
    return o.str();
  }

  dnsdist::Protocol getProtocol() const;
  IOState handleIncomingQueryReceived(const struct timeval& now);
  void handleExceptionDuringIO(const std::exception& exp);
  bool readIncomingQuery(const timeval& now, IOState& iostate);

  enum class State : uint8_t { starting, doingHandshake, readingProxyProtocolHeader, waitingForQuery, readingQuerySize, readingQuery, sendingResponse, idle /* in case of XFR, we stop processing queries */ };

  TCPResponse d_currentResponse;
  std::map<std::shared_ptr<DownstreamState>, std::deque<std::shared_ptr<TCPConnectionToBackend>>> d_ownedConnectionsToBackend;
  std::deque<TCPResponse> d_queuedResponses;
  PacketBuffer d_buffer;
  ConnectionInfo d_ci;
  ComboAddress d_origDest;
  ComboAddress d_proxiedRemote;
  ComboAddress d_proxiedDestination;
  TCPIOHandler d_handler;
  struct timeval d_connectionStartTime;
  struct timeval d_handshakeDoneTime;
  struct timeval d_firstQuerySizeReadTime;
  struct timeval d_querySizeReadTime;
  struct timeval d_queryReadTime;
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  std::unique_ptr<std::vector<ProxyProtocolValue>> d_proxyProtocolValues{nullptr};
  TCPClientThreadData& d_threadData;
  size_t d_currentPos{0};
  size_t d_proxyProtocolNeed{0};
  size_t d_queriesCount{0};
  size_t d_currentQueriesCount{0};
  std::thread::id d_creatorThreadID;
  uint16_t d_querySize{0};
  State d_state{State::starting};
  bool d_isXFR{false};
  bool d_proxyProtocolPayloadHasTLV{false};
  bool d_lastIOBlocked{false};
  bool d_hadErrors{false};
};
