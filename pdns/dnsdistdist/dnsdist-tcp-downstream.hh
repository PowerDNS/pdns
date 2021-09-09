#pragma once

#include <queue>

#include "sstuff.hh"
#include "tcpiohandler-mplexer.hh"
#include "dnsdist.hh"

struct TCPQuery
{
  TCPQuery()
  {
  }

  TCPQuery(PacketBuffer&& buffer, IDState&& state): d_idstate(std::move(state)), d_buffer(std::move(buffer))
  {
  }

  IDState d_idstate;
  PacketBuffer d_buffer;
  std::string d_proxyProtocolPayload;
  bool d_proxyProtocolPayloadAdded{false};
};

class TCPConnectionToBackend;

struct TCPResponse : public TCPQuery
{
  TCPResponse()
  {
    /* let's make Coverity happy */
    memset(&d_cleartextDH, 0, sizeof(d_cleartextDH));
  }

  TCPResponse(PacketBuffer&& buffer, IDState&& state, std::shared_ptr<TCPConnectionToBackend> conn): TCPQuery(std::move(buffer), std::move(state)), d_connection(conn)
  {
    memset(&d_cleartextDH, 0, sizeof(d_cleartextDH));
  }

  std::shared_ptr<TCPConnectionToBackend> d_connection{nullptr};
  dnsheader d_cleartextDH;
  bool d_selfGenerated{false};
};

class IncomingTCPConnectionState;

class TCPConnectionToBackend
{
public:
  TCPConnectionToBackend(std::shared_ptr<DownstreamState>& ds, const struct timeval& now): d_responseBuffer(s_maxPacketCacheEntrySize), d_ds(ds), d_connectionStartTime(now), d_lastDataReceivedTime(now), d_enableFastOpen(ds->tcpFastOpen)
  {
    reconnect();
  }

  ~TCPConnectionToBackend()
  {
    if (d_ds && !d_usedForXFR && !d_pendingResponses.empty()) {
      d_ds->outstanding -= d_pendingResponses.size();
    }

    if (d_ds && d_handler) {
      --d_ds->tcpCurrentConnections;
      struct timeval now;
      gettimeofday(&now, nullptr);

      auto diff = now - d_connectionStartTime;
      d_ds->updateTCPMetrics(d_queries, diff.tv_sec * 1000 + diff.tv_usec / 1000);
    }
  }

  void assignToClientConnection(std::shared_ptr<IncomingTCPConnectionState>& clientConn, bool isXFR);

  int getHandle() const
  {
    if (!d_handler) {
      throw std::runtime_error("Attempt to get the socket handle from a non-established TCP connection");
    }

    return d_handler->getDescriptor();
  }

  const std::shared_ptr<DownstreamState>& getDS() const
  {
    return d_ds;
  }

  const ComboAddress& getRemote() const
  {
    return d_ds->remote;
  }

  const std::string& getBackendName() const
  {
    return d_ds->getName();
  }

  bool isFresh() const
  {
    return d_fresh;
  }

  void incQueries()
  {
    ++d_queries;
  }

  void setReused()
  {
    d_fresh = false;
  }

  void disableFastOpen()
  {
    d_enableFastOpen = false;
  }

  bool isFastOpenEnabled()
  {
    return d_enableFastOpen;
  }

  /* whether we can accept new queries FOR THE SAME CLIENT */
  bool canAcceptNewQueries() const
  {
    if (d_usedForXFR || d_connectionDied) {
      return false;
      /* Don't reuse the TCP connection after an {A,I}XFR */
      /* but don't reset it either, we will need to read more messages */
    }

    if ((d_pendingQueries.size() + d_pendingResponses.size()) >= d_ds->d_maxInFlightQueriesPerConn) {
      return false;
    }

    return true;
  }

  bool isIdle() const
  {
    return d_state == State::idle && d_pendingQueries.size() == 0 && d_pendingResponses.size() == 0;
  }

  /* whether a connection can be reused for a different client */
  bool canBeReused() const
  {
    if (d_usedForXFR || d_connectionDied) {
      return false;
    }
    /* we can't reuse a connection where a proxy protocol payload has been sent,
       since:
       - it cannot be reused for a different client
       - we might have different TLV values for each query
    */
    if (d_ds && d_ds->useProxyProtocol == true) {
      return false;
    }
    return true;
  }

  bool matchesTLVs(const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs) const;

  bool matches(const std::shared_ptr<DownstreamState>& ds) const
  {
    if (!ds || !d_ds) {
      return false;
    }
    return ds == d_ds;
  }

  void queueQuery(TCPQuery&& query, std::shared_ptr<TCPConnectionToBackend>& sharedSelf);
  void handleTimeout(const struct timeval& now, bool write);
  void release();

  void setProxyProtocolValuesSent(std::unique_ptr<std::vector<ProxyProtocolValue>>&& proxyProtocolValuesSent);

  struct timeval getLastDataReceivedTime() const
  {
    return d_lastDataReceivedTime;
  }

  std::string toString() const
  {
    ostringstream o;
    o << "TCP connection to backend "<<(d_ds ? d_ds->getName() : "empty")<<" over FD "<<(d_handler ? std::to_string(d_handler->getDescriptor()) : "no socket")<<", state is "<<(int)d_state<<", io state is "<<(d_ioState ? std::to_string((int)d_ioState->getState()) : "empty")<<", queries count is "<<d_queries<<", pending queries count is "<<d_pendingQueries.size()<<", "<<d_pendingResponses.size()<<" pending responses, linked to "<<(d_clientConn ? " a client" : "no client");
    return o.str();
  }

private:
  /* waitingForResponseFromBackend is a state where we have not yet started reading the size,
     so we can still switch to sending instead */
  enum class State : uint8_t { idle, doingHandshake, sendingQueryToBackend, waitingForResponseFromBackend, readingResponseSizeFromBackend, readingResponseFromBackend };
  enum class FailureReason : uint8_t { /* too many attempts */ gaveUp, timeout, unexpectedQueryID };

  static void handleIO(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now);
  static void handleIOCallback(int fd, FDMultiplexer::funcparam_t& param);
  static IOState queueNextQuery(std::shared_ptr<TCPConnectionToBackend>& conn);
  static IOState sendQuery(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now);

  IOState handleResponse(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now);
  uint16_t getQueryIdFromResponse();
  bool reconnect();
  void notifyAllQueriesFailed(const struct timeval& now, FailureReason reason);
  bool needProxyProtocolPayload() const
  {
    return !d_proxyProtocolPayloadSent && (d_ds && d_ds->useProxyProtocol);
  }

  boost::optional<struct timeval> getBackendReadTTD(const struct timeval& now) const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendReadTTD() without any backend selected");
    }
    if (d_ds->tcpRecvTimeout == 0) {
      return boost::none;
    }

    struct timeval res = now;
    res.tv_sec += d_ds->tcpRecvTimeout;

    return res;
  }

  boost::optional<struct timeval> getBackendWriteTTD(const struct timeval& now) const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendWriteTTD() called without any backend selected");
    }
    if (d_ds->tcpSendTimeout == 0) {
      return boost::none;
    }

    struct timeval res = now;
    res.tv_sec += d_ds->tcpSendTimeout;

    return res;
  }

  boost::optional<struct timeval> getBackendConnectTTD(const struct timeval& now) const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendConnectTTD() called without any backend selected");
    }
    if (d_ds->tcpConnectTimeout == 0) {
      return boost::none;
    }

    struct timeval res = now;
    res.tv_sec += d_ds->tcpConnectTimeout;

    return res;
  }

  static const uint16_t s_xfrID;

  PacketBuffer d_responseBuffer;
  std::deque<TCPQuery> d_pendingQueries;
  std::unordered_map<uint16_t, TCPQuery> d_pendingResponses;
  std::unique_ptr<std::vector<ProxyProtocolValue>> d_proxyProtocolValuesSent{nullptr};
  std::unique_ptr<TCPIOHandler> d_handler{nullptr};
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  std::shared_ptr<DownstreamState> d_ds{nullptr};
  std::shared_ptr<IncomingTCPConnectionState> d_clientConn;
  TCPQuery d_currentQuery;
  struct timeval d_connectionStartTime;
  struct timeval d_lastDataReceivedTime;
  size_t d_currentPos{0};
  uint64_t d_queries{0};
  uint64_t d_downstreamFailures{0};
  uint16_t d_responseSize{0};
  State d_state{State::idle};
  bool d_fresh{true};
  bool d_enableFastOpen{false};
  bool d_connectionDied{false};
  bool d_usedForXFR{false};
  bool d_proxyProtocolPayloadSent{false};
};
