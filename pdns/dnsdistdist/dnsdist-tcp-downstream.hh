#pragma once

#include "sstuff.hh"
#include "tcpiohandler-mplexer.hh"
#include "dnsdist.hh"
#include "dnsdist-tcp.hh"

class ConnectionToBackend : public std::enable_shared_from_this<ConnectionToBackend>
{
public:
  ConnectionToBackend(const std::shared_ptr<DownstreamState>& ds, std::unique_ptr<FDMultiplexer>& mplexer, const struct timeval& now): d_connectionStartTime(now), d_lastDataReceivedTime(now), d_ds(ds), d_mplexer(mplexer), d_enableFastOpen(ds->d_config.tcpFastOpen)
  {
    reconnect();
  }

  virtual ~ConnectionToBackend();

  int getHandle() const
  {
    if (!d_handler) {
      throw std::runtime_error("Attempt to get the socket handle from a non-established TCP connection");
    }

    return d_handler->getDescriptor();
  }

  /* whether the underlying socket has been closed under our feet, basically */
  bool isUsable()
  {
    if (!d_handler) {
      d_connectionDied = true;
      return false;
    }

    if (d_handler->isUsable()) {
      return true;
    }

    d_connectionDied = true;
    return false;
  }

  const std::shared_ptr<DownstreamState>& getDS() const
  {
    return d_ds;
  }

  const ComboAddress& getRemote() const
  {
    return d_ds->d_config.remote;
  }

  const std::string& getBackendName() const
  {
    return d_ds->getName();
  }

  bool isFresh() const
  {
    return d_fresh;
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

  /* whether a connection can be used now */
  bool canBeReused(bool sameClient = false) const
  {
    if (d_connectionDied) {
      return false;
    }

    /* we can't reuse a connection where a proxy protocol payload has been sent,
       since:
       - it cannot be reused for a different client
       - we might have different TLV values for each query
    */
    if (d_ds && d_ds->d_config.useProxyProtocol == true && !sameClient) {
      return false;
    }

    if (reachedMaxStreamID()) {
      return false;
    }

    if (reachedMaxConcurrentQueries()) {
      return false;
    }

    return true;
  }

  /* full now but will become usable later */
  bool willBeReusable(bool sameClient) const
  {
    if (d_connectionDied || reachedMaxStreamID()) {
      return false;
    }

    if (d_ds && d_ds->d_config.useProxyProtocol == true) {
      return sameClient;
    }

    return true;
  }

  virtual bool reachedMaxStreamID() const = 0;
  virtual bool reachedMaxConcurrentQueries() const = 0;
  virtual bool isIdle() const = 0;
  virtual void release(bool removeFromCache) = 0;
  virtual void stopIO()
  {
  }

  bool matches(const std::shared_ptr<DownstreamState>& ds) const
  {
    if (!ds || !d_ds) {
      return false;
    }
    return ds == d_ds;
  }

  virtual void queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query) = 0;
  virtual void handleTimeout(const struct timeval& now, bool write) = 0;

  struct timeval getLastDataReceivedTime() const
  {
    return d_lastDataReceivedTime;
  }

  virtual std::string toString() const = 0;

protected:
  bool reconnect();

  boost::optional<struct timeval> getBackendHealthCheckTTD(const struct timeval& now) const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendReadTTD() without any backend selected");
    }
    if (d_ds->d_config.checkTimeout == 0) {
      return boost::none;
    }

    struct timeval res = now;
    res.tv_sec += d_ds->d_config.checkTimeout / 1000; /* ms to s */
    res.tv_usec += (d_ds->d_config.checkTimeout % 1000) * 1000; /* remaining ms to µs */
    normalizeTV(res);

    return res;
  }

  boost::optional<struct timeval> getBackendReadTTD(const struct timeval& now) const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendReadTTD() without any backend selected");
    }
    if (d_ds->d_config.tcpRecvTimeout == 0) {
      return boost::none;
    }

    struct timeval res = now;
    res.tv_sec += d_ds->d_config.tcpRecvTimeout;

    return res;
  }

  boost::optional<struct timeval> getBackendWriteTTD(const struct timeval& now) const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendWriteTTD() called without any backend selected");
    }
    if (d_ds->d_config.tcpSendTimeout == 0) {
      return boost::none;
    }

    struct timeval res = now;
    res.tv_sec += d_ds->d_config.tcpSendTimeout;

    return res;
  }

  boost::optional<struct timeval> getBackendConnectTTD(const struct timeval& now) const
  {
    if (d_ds == nullptr) {
      throw std::runtime_error("getBackendConnectTTD() called without any backend selected");
    }
    if (d_ds->d_config.tcpConnectTimeout == 0) {
      return boost::none;
    }

    struct timeval res = now;
    res.tv_sec += d_ds->d_config.tcpConnectTimeout;

    return res;
  }

  struct timeval d_connectionStartTime;
  struct timeval d_lastDataReceivedTime;
  const std::shared_ptr<DownstreamState> d_ds{nullptr};
  std::shared_ptr<TCPQuerySender> d_sender{nullptr};
  std::unique_ptr<FDMultiplexer>& d_mplexer;
  std::unique_ptr<TCPIOHandler> d_handler{nullptr};
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  uint64_t d_queries{0};
  uint32_t d_highestStreamID{0};
  uint16_t d_downstreamFailures{0};
  bool d_proxyProtocolPayloadSent{false};
  bool d_enableFastOpen{false};
  bool d_connectionDied{false};
  bool d_fresh{true};
};

class TCPConnectionToBackend : public ConnectionToBackend
{
public:
  TCPConnectionToBackend(const std::shared_ptr<DownstreamState>& ds, std::unique_ptr<FDMultiplexer>& mplexer, const struct timeval& now, std::string&& /* proxyProtocolPayload*, unused but there to match the HTTP2 connections, so we can use the same templated connections manager class */): ConnectionToBackend(ds, mplexer, now), d_responseBuffer(512)
  {
  }

  virtual ~TCPConnectionToBackend();

  bool isIdle() const override
  {
    return d_state == State::idle && d_pendingQueries.size() == 0 && d_pendingResponses.size() == 0;
  }

  bool reachedMaxStreamID() const override
  {
    /* TCP/DoT has only 2^16 usable identifiers, DoH has 2^32 */
    const uint32_t maximumStreamID = std::numeric_limits<uint16_t>::max() - 1;
    return d_highestStreamID == maximumStreamID;
  }

  bool reachedMaxConcurrentQueries() const override
  {
    const size_t concurrent = d_pendingQueries.size() + d_pendingResponses.size() + (d_state == State::sendingQueryToBackend ? 1 : 0);
    if (concurrent > 0 && concurrent >= d_ds->d_config.d_maxInFlightQueriesPerConn) {
      return true;
    }
    return false;
  }
  bool matchesTLVs(const std::unique_ptr<std::vector<ProxyProtocolValue>>& tlvs) const;

  void queueQuery(std::shared_ptr<TCPQuerySender>& sender, TCPQuery&& query) override;
  void handleTimeout(const struct timeval& now, bool write) override;
  void release(bool removeFromCache) override;

  std::string toString() const override
  {
    ostringstream o;
    o << "TCP connection to backend "<<(d_ds ? d_ds->getName() : "empty")<<" over FD "<<(d_handler ? std::to_string(d_handler->getDescriptor()) : "no socket")<<", state is "<<(int)d_state<<", io state is "<<(d_ioState ? d_ioState->getState() : "empty")<<", queries count is "<<d_queries<<", pending queries count is "<<d_pendingQueries.size()<<", "<<d_pendingResponses.size()<<" pending responses";
    return o.str();
  }

  void setProxyProtocolValuesSent(std::unique_ptr<std::vector<ProxyProtocolValue>>&& proxyProtocolValuesSent);

private:
  /* waitingForResponseFromBackend is a state where we have not yet started reading the size,
     so we can still switch to sending instead */
  enum class State : uint8_t { idle, sendingQueryToBackend, waitingForResponseFromBackend, readingResponseSizeFromBackend, readingResponseFromBackend };
  enum class FailureReason : uint8_t { /* too many attempts */ gaveUp, timeout, unexpectedQueryID };

  static void handleIO(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now);
  static void handleIOCallback(int fd, FDMultiplexer::funcparam_t& param);
  static IOState queueNextQuery(std::shared_ptr<TCPConnectionToBackend>& conn);
  static IOState sendQuery(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now);
  static bool isXFRFinished(const TCPResponse& response, TCPQuery& query);

  IOState handleResponse(std::shared_ptr<TCPConnectionToBackend>& conn, const struct timeval& now);
  uint16_t getQueryIdFromResponse() const;
  void notifyAllQueriesFailed(const struct timeval& now, FailureReason reason);
  bool needProxyProtocolPayload() const
  {
    return !d_proxyProtocolPayloadSent && (d_ds && d_ds->d_config.useProxyProtocol);
  }

  class PendingRequest
  {
  public:
    std::shared_ptr<TCPQuerySender> d_sender{nullptr};
    TCPQuery d_query;
  };

  PacketBuffer d_responseBuffer;
  std::list<PendingRequest> d_pendingQueries;
  std::unordered_map<uint16_t, PendingRequest> d_pendingResponses;
  std::unique_ptr<std::vector<ProxyProtocolValue>> d_proxyProtocolValuesSent{nullptr};
  PendingRequest d_currentQuery;
  size_t d_currentPos{0};
  uint16_t d_responseSize{0};
  State d_state{State::idle};
};

void setTCPDownstreamMaxIdleConnectionsPerBackend(uint64_t max);
void setTCPDownstreamCleanupInterval(uint64_t interval);
void setTCPDownstreamMaxIdleTime(uint64_t max);
