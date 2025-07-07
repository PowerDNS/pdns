#pragma once

#include "dolog.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"

struct TCPCrossProtocolResponse;

class TCPClientThreadData
{
public:
  TCPClientThreadData():
    mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent()))
  {
  }

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

  IncomingTCPConnectionState(ConnectionInfo&& ci, TCPClientThreadData& threadData, const struct timeval& now): d_buffer(sizeof(uint16_t)), d_ci(std::move(ci)), d_handler(d_ci.fd, timeval{dnsdist::configuration::getCurrentRuntimeConfiguration().d_tcpRecvTimeout,0}, d_ci.cs->tlsFrontend ? d_ci.cs->tlsFrontend->getContext() : (d_ci.cs->dohFrontend ? d_ci.cs->dohFrontend->d_tlsContext->getContext() : nullptr), now.tv_sec), d_connectionStartTime(now), d_ioState(make_unique<IOStateHandler>(*threadData.mplexer, d_ci.fd)), d_threadData(threadData), d_creatorThreadID(std::this_thread::get_id())
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

  boost::optional<timeval> getClientReadTTD(timeval now) const;
  boost::optional<timeval> getClientWriteTTD(const timeval& now) const;
  bool maxConnectionDurationReached(unsigned int maxConnectionDuration, const timeval& now) const;

  std::shared_ptr<TCPConnectionToBackend> getDownstreamConnection(std::shared_ptr<DownstreamState>& backend, const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs, const struct timeval& now);
  void registerOwnedDownstreamConnection(std::shared_ptr<TCPConnectionToBackend>& conn);
  void clearOwnedDownstreamConnections(const std::shared_ptr<DownstreamState>& downstream);

  static size_t clearAllDownstreamConnections();

  static void handleIOCallback(int desc, FDMultiplexer::funcparam_t& param);
  static void handleAsyncReady(int desc, FDMultiplexer::funcparam_t& param);

  static void queueResponse(std::shared_ptr<IncomingTCPConnectionState>& state, const struct timeval& now, TCPResponse&& response, bool fromBackend);
  static void handleTimeout(std::shared_ptr<IncomingTCPConnectionState>& state, bool write);
  static void updateIOForAsync(std::shared_ptr<IncomingTCPConnectionState>& conn);

  virtual void handleIO();
  virtual void updateIO(IOState newState, const timeval& now);

  QueryProcessingResult handleQuery(PacketBuffer&& query, const struct timeval& now, std::optional<int32_t> streamID);
  virtual void handleResponse(const struct timeval& now, TCPResponse&& response) override;
  virtual void notifyIOError(const struct timeval& now, TCPResponse&& response) override;
  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override;

  virtual IOState sendResponse(const struct timeval& now, TCPResponse&& response);
  void handleResponseSent(TCPResponse& currentResponse, size_t sentBytes);
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
    return d_ci.cs->getTLSFrontend()->d_proxyProtocolOutsideTLS;
  }

  virtual bool forwardViaUDPFirst() const;

  virtual std::unique_ptr<DOHUnitInterface> getDOHUnit(uint32_t streamID);
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
  bool isNearTCPLimits() const;

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
  uint64_t d_readIOsTotal{0};
  size_t d_currentPos{0};
  size_t d_proxyProtocolNeed{0};
  size_t d_queriesCount{0};
  size_t d_currentQueriesCount{0};
  std::thread::id d_creatorThreadID;
  uint16_t d_querySize{0};
  uint16_t d_readIOsCurrentQuery{0};
  State d_state{State::starting};
  bool d_isXFR{false};
  bool d_proxyProtocolPayloadHasTLV{false};
  bool d_lastIOBlocked{false};
  bool d_hadErrors{false};
  bool d_handlingIO{false};
};
