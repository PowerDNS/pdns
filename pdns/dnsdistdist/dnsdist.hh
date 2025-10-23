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
#pragma once

#include "config.h"

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <unordered_map>

#include "bpf-filter.hh"
#include "circular_buffer.hh"
#include "dnsdist-idstate.hh"
#include "dnsdist-lbpolicies.hh"
#include "dnsdist-protocols.hh"
#include "dnsname.hh"
#include "dnsdist-doh-common.hh"
#include "doq.hh"
#include "doh3.hh"
#include "ednsoptions.hh"
#include "iputils.hh"
#include "misc.hh"
#include "mplexer.hh"
#include "noinitvector.hh"
#include "uuid-utils.hh"
#include "proxy-protocol.hh"
#include "stat_t.hh"

uint64_t uptimeOfProcess(const std::string& str);

using QTag = std::unordered_map<string, string>;

class IncomingTCPConnectionState;

class TCPQuerySender;

struct ClientState;

struct DNSQuestion
{
  DNSQuestion(InternalQueryState& ids_, PacketBuffer& data_);
  DNSQuestion(const DNSQuestion&) = delete;
  DNSQuestion& operator=(const DNSQuestion&) = delete;
  DNSQuestion(DNSQuestion&&) = default;
  virtual ~DNSQuestion() = default;

  std::string getTrailingData() const;
  bool setTrailingData(const std::string&);
  const PacketBuffer& getData() const
  {
    return data;
  }
  PacketBuffer& getMutableData()
  {
    return data;
  }

  bool editHeader(const std::function<bool(dnsheader&)>& editFunction);

  const dnsheader_aligned getHeader() const
  {
    if (data.size() < sizeof(dnsheader)) {
      throw std::runtime_error("Trying to access the dnsheader of a too small (" + std::to_string(data.size()) + ") DNSQuestion buffer");
    }
    dnsheader_aligned dh(data.data());
    return dh;
  }

  /* this function is not safe against unaligned access, you should
     use editHeader() instead, but we need it for the Lua bindings */
  dnsheader* getMutableHeader() const
  {
    if (data.size() < sizeof(dnsheader)) {
      throw std::runtime_error("Trying to access the dnsheader of a too small (" + std::to_string(data.size()) + ") DNSQuestion buffer");
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<dnsheader*>(data.data());
  }

  bool hasRoomFor(size_t more) const
  {
    return data.size() <= getMaximumSize() && (getMaximumSize() - data.size()) >= more;
  }

  size_t getMaximumSize() const
  {
    if (overTCP()) {
      return std::numeric_limits<uint16_t>::max();
    }
    return 4096;
  }

  dnsdist::Protocol getProtocol() const
  {
    return ids.protocol;
  }

  bool overTCP() const
  {
    return !(ids.protocol == dnsdist::Protocol::DoUDP || ids.protocol == dnsdist::Protocol::DNSCryptUDP);
  }

  void setTag(std::string&& key, std::string&& value)
  {
    if (!ids.qTag) {
      ids.qTag = std::make_unique<QTag>();
    }
    ids.qTag->insert_or_assign(std::move(key), std::move(value));
  }

  void setTag(const std::string& key, const std::string& value)
  {
    if (!ids.qTag) {
      ids.qTag = std::make_unique<QTag>();
    }
    ids.qTag->insert_or_assign(key, value);
  }

  void setTag(const std::string& key, std::string&& value)
  {
    if (!ids.qTag) {
      ids.qTag = std::make_unique<QTag>();
    }
    ids.qTag->insert_or_assign(key, std::move(value));
  }

  const struct timespec& getQueryRealTime() const
  {
    return ids.queryRealTime.d_start;
  }

  bool isAsynchronous() const
  {
    return asynchronous;
  }

  std::shared_ptr<IncomingTCPConnectionState> getIncomingTCPState() const
  {
    return d_incomingTCPState;
  }

  ClientState* getFrontend() const
  {
    return ids.cs;
  }

protected:
  PacketBuffer& data;

public:
  InternalQueryState& ids;
  std::unique_ptr<Netmask> ecs{nullptr};
  std::string sni; /* Server Name Indication, if any (DoT or DoH) */
  mutable std::unique_ptr<EDNSOptionViewMap> ednsOptions; /* this needs to be mutable because it is parsed just in time, when DNSQuestion is read-only */
  std::shared_ptr<IncomingTCPConnectionState> d_incomingTCPState{nullptr};
  std::unique_ptr<std::vector<ProxyProtocolValue>> proxyProtocolValues{nullptr};
  uint16_t ecsPrefixLength;
  uint8_t ednsRCode{0};
  bool ecsOverride;
  bool useECS{true};
  bool asynchronous{false};
  bool d_selfGeneratedHandledEDNS{false};
};

struct DownstreamState;

struct DNSResponse : DNSQuestion
{
  DNSResponse(InternalQueryState& ids_, PacketBuffer& data_, const std::shared_ptr<DownstreamState>& downstream) :
    DNSQuestion(ids_, data_), d_downstream(downstream) {}
  DNSResponse(const DNSResponse&) = delete;
  DNSResponse& operator=(const DNSResponse&) = delete;
  DNSResponse(DNSResponse&&) = default;

  const std::shared_ptr<DownstreamState>& d_downstream;
};

using pdns::stat_t;

class BasicQPSLimiter
{
public:
  BasicQPSLimiter(unsigned int burst) :
    d_tokens(burst)
  {
    d_prev.start();
  }

  virtual ~BasicQPSLimiter()
  {
  }

  bool check(unsigned int rate, unsigned int burst) const // this is not quite fair
  {
    if (checkOnly(rate, burst)) {
      addHit();
      return true;
    }

    return false;
  }

  bool checkOnly(unsigned int rate, unsigned int burst) const // this is not quite fair
  {
    auto delta = d_prev.udiffAndSet();

    if (delta > 0.0) { // time, frequently, does go backwards..
      d_tokens += 1.0 * rate * (delta / 1000000.0);
    }

    if (d_tokens > burst) {
      d_tokens = burst;
    }

    bool ret = false;
    if (d_tokens >= 1.0) { // we need this because burst=1 is weird otherwise
      ret = true;
    }

    return ret;
  }

  virtual void addHit() const
  {
    --d_tokens;
  }

  bool seenSince(const struct timespec& cutOff) const
  {
    return cutOff < d_prev.d_start;
  }

protected:
  mutable StopWatch d_prev;
  mutable double d_tokens{0.0};
};

class QPSLimiter : public BasicQPSLimiter
{
public:
  QPSLimiter(unsigned int rate, unsigned int burst) :
    BasicQPSLimiter(burst), d_rate(rate), d_burst(burst), d_passthrough(false)
  {
    d_prev.start();
  }

  unsigned int getRate() const
  {
    return d_passthrough ? 0 : d_rate;
  }

  bool check() const // this is not quite fair
  {
    if (d_passthrough) {
      return true;
    }

    return BasicQPSLimiter::check(d_rate, d_burst);
  }

  bool checkOnly() const
  {
    if (d_passthrough) {
      return true;
    }

    return BasicQPSLimiter::checkOnly(d_rate, d_burst);
  }

  void addHit() const override
  {
    if (!d_passthrough) {
      --d_tokens;
    }
  }

private:
  unsigned int d_rate{0};
  unsigned int d_burst{0};
  bool d_passthrough{true};
};

class XskPacket;
class XskSocket;
class XskWorker;

class DNSCryptContext;

struct ClientState
{
  ClientState(const ComboAddress& local_, bool isTCP_, bool doReusePort, int fastOpenQueue, const std::string& itfName, const std::set<int>& cpus_, bool enableProxyProtocol) :
    cpus(cpus_), interface(itfName), local(local_), fastOpenQueueSize(fastOpenQueue), tcp(isTCP_), reuseport(doReusePort), d_enableProxyProtocol(enableProxyProtocol)
  {
  }

  stat_t queries{0};
  stat_t nonCompliantQueries{0};
  mutable stat_t responses{0};
  mutable stat_t tcpDiedReadingQuery{0};
  mutable stat_t tcpDiedSendingResponse{0};
  mutable stat_t tcpGaveUp{0};
  mutable stat_t tcpClientTimeouts{0};
  mutable stat_t tcpDownstreamTimeouts{0};
  /* current number of connections to this frontend */
  mutable stat_t tcpCurrentConnections{0};
  /* maximum number of concurrent connections to this frontend reached */
  mutable stat_t tcpMaxConcurrentConnections{0};
  stat_t tlsNewSessions{0}; // A new TLS session has been negotiated, no resumption
  stat_t tlsResumptions{0}; // A TLS session has been resumed, either via session id or via a TLS ticket
  stat_t tlsUnknownTicketKey{0}; // A TLS ticket has been presented but we don't have the associated key (might have expired)
  stat_t tlsInactiveTicketKey{0}; // A TLS ticket has been successfully resumed but the key is no longer active, we should issue a new one
  stat_t tls10queries{0}; // valid DNS queries received via TLSv1.0
  stat_t tls11queries{0}; // valid DNS queries received via TLSv1.1
  stat_t tls12queries{0}; // valid DNS queries received via TLSv1.2
  stat_t tls13queries{0}; // valid DNS queries received via TLSv1.3
  stat_t tlsUnknownqueries{0}; // valid DNS queries received via unknown TLS version
  pdns::stat_double_t tcpAvgIOsPerConnection{0.0};
  pdns::stat_double_t tcpAvgQueriesPerConnection{0.0};
  /* in ms */
  pdns::stat_double_t tcpAvgConnectionDuration{0.0};
  std::set<int> cpus;
  std::string interface;
  ComboAddress local;
  std::vector<std::pair<ComboAddress, int>> d_additionalAddresses;
  std::shared_ptr<DNSCryptContext> dnscryptCtx{nullptr};
  std::shared_ptr<TLSFrontend> tlsFrontend{nullptr};
  std::shared_ptr<DOHFrontend> dohFrontend{nullptr};
  std::shared_ptr<DOQFrontend> doqFrontend{nullptr};
  std::shared_ptr<DOH3Frontend> doh3Frontend{nullptr};
  std::shared_ptr<BPFFilter> d_filter{nullptr};
  std::shared_ptr<XskWorker> xskInfo{nullptr};
  std::shared_ptr<XskWorker> xskInfoResponder{nullptr};
  size_t d_maxInFlightQueriesPerConn{1};
  size_t d_tcpConcurrentConnectionsLimit{0};
  int udpFD{-1};
  int tcpFD{-1};
  int tcpListenQueueSize{SOMAXCONN};
  int fastOpenQueueSize{0};
  bool muted{false};
  bool tcp;
  bool reuseport;
  bool d_enableProxyProtocol{true}; // the global proxy protocol ACL still applies
  bool ready{false};

  int getSocket() const
  {
    return udpFD != -1 ? udpFD : tcpFD;
  }

  bool isUDP() const
  {
    return udpFD != -1;
  }

  bool isTCP() const
  {
    return udpFD == -1;
  }

  bool isDoH() const
  {
    return dohFrontend != nullptr;
  }

  bool hasTLS() const
  {
    return tlsFrontend != nullptr || (dohFrontend != nullptr && dohFrontend->isHTTPS());
  }

  const std::shared_ptr<const TLSFrontend> getTLSFrontend() const
  {
    if (tlsFrontend != nullptr) {
      return tlsFrontend;
    }
    if (dohFrontend) {
      return dohFrontend->d_tlsContext;
    }
    throw std::runtime_error("Trying to get a TLS frontend from a non-TLS ClientState");
  }

  dnsdist::Protocol getProtocol() const
  {
    if (dnscryptCtx) {
      if (udpFD != -1) {
        return dnsdist::Protocol::DNSCryptUDP;
      }
      return dnsdist::Protocol::DNSCryptTCP;
    }
    if (isDoH()) {
      return dnsdist::Protocol::DoH;
    }
    else if (hasTLS()) {
      return dnsdist::Protocol::DoT;
    }
    else if (doqFrontend != nullptr) {
      return dnsdist::Protocol::DoQ;
    }
    else if (doh3Frontend != nullptr) {
      return dnsdist::Protocol::DoH3;
    }
    else if (udpFD != -1) {
      return dnsdist::Protocol::DoUDP;
    }
    else {
      return dnsdist::Protocol::DoTCP;
    }
  }

  std::string getType() const
  {
    std::string result = udpFD != -1 ? "UDP" : "TCP";

    if (doqFrontend) {
      result += " (DNS over QUIC)";
    }
    else if (doh3Frontend) {
      result += " (DNS over HTTP/3)";
    }
    else if (dohFrontend) {
      if (dohFrontend->isHTTPS()) {
        result += " (DNS over HTTPS)";
      }
      else {
        result += " (DNS over HTTP)";
      }
    }
    else if (tlsFrontend) {
      result += " (DNS over TLS)";
    }
    else if (dnscryptCtx) {
      result += " (DNSCrypt)";
    }

    return result;
  }

  void detachFilter(int socket)
  {
    if (d_filter) {
      d_filter->removeSocket(socket);
      d_filter = nullptr;
    }
  }

  void attachFilter(shared_ptr<BPFFilter>& bpf, int socket)
  {
    detachFilter(socket);

    bpf->addSocket(socket);
    d_filter = bpf;
  }

  void detachFilter()
  {
    if (d_filter) {
      detachFilter(getSocket());
      for (const auto& [addr, socket] : d_additionalAddresses) {
        (void)addr;
        if (socket != -1) {
          detachFilter(socket);
        }
      }

      d_filter = nullptr;
    }
  }

  void attachFilter(shared_ptr<BPFFilter>& bpf)
  {
    detachFilter();

    bpf->addSocket(getSocket());
    for (const auto& [addr, socket] : d_additionalAddresses) {
      (void)addr;
      if (socket != -1) {
        bpf->addSocket(socket);
      }
    }
    d_filter = bpf;
  }

  void updateTCPMetrics(size_t nbQueries, uint64_t durationMs, size_t nbIOs)
  {
    tcpAvgQueriesPerConnection = (99.0 * tcpAvgQueriesPerConnection / 100.0) + (nbQueries / 100.0);
    tcpAvgConnectionDuration = (99.0 * tcpAvgConnectionDuration / 100.0) + (durationMs / 100.0);
    tcpAvgIOsPerConnection = (99.0 * tcpAvgIOsPerConnection / 100.0) + (nbIOs / 100.0);
  }
};

struct CrossProtocolQuery;
class FDMultiplexer;

struct DownstreamState : public std::enable_shared_from_this<DownstreamState>
{
  DownstreamState(const DownstreamState&) = delete;
  DownstreamState(DownstreamState&&) = delete;
  DownstreamState& operator=(const DownstreamState&) = delete;
  DownstreamState& operator=(DownstreamState&&) = delete;

  typedef std::function<std::tuple<DNSName, uint16_t, uint16_t>(const DNSName&, uint16_t, uint16_t, dnsheader*)> checkfunc_t;
  enum class Availability : uint8_t
  {
    Up,
    Down,
    Auto
  };
  enum class HealthCheckMode : uint8_t
  {
    Active,
    Lazy
  };
  enum class LazyHealthCheckMode : uint8_t
  {
    TimeoutOnly,
    TimeoutOrServFail
  };

  struct BaseConfig
  {
    BaseConfig()
    {
    }
    BaseConfig(const ComboAddress& remote_) :
      remote(remote_)
    {
    }

    TLSContextParameters d_tlsParams;
    set<string> pools;
    std::set<int> d_cpus;
    checkfunc_t checkFunction;
    std::optional<boost::uuids::uuid> id;
    DNSName checkName{"a.root-servers.net."};
    ComboAddress remote;
    ComboAddress sourceAddr;
    std::string sourceItfName;
    std::string d_tlsSubjectName;
    std::string d_dohPath;
    std::string name;
    std::string nameWithAddr;
#ifdef HAVE_XSK
    std::array<uint8_t, 6> sourceMACAddr;
    std::array<uint8_t, 6> destMACAddr;
#endif /* HAVE_XSK */
    size_t d_numberOfSockets{1};
    size_t d_maxInFlightQueriesPerConn{1};
    size_t d_tcpConcurrentConnectionsLimit{0};
    int order{1};
    int d_weight{1};
    int tcpConnectTimeout{5};
    int tcpRecvTimeout{30};
    int tcpSendTimeout{30};
    int d_qpsLimit{0};
    unsigned int sourceItf{0};
    QType checkType{QType::A};
    uint16_t checkClass{QClass::IN};
    uint16_t d_retries{5};
    uint16_t d_lazyHealthCheckSampleSize{100};
    uint16_t d_lazyHealthCheckMinSampleCount{1};
    uint16_t d_lazyHealthCheckFailedInterval{30};
    uint16_t d_lazyHealthCheckMaxBackOff{3600};
    uint8_t d_lazyHealthCheckThreshold{20};
    LazyHealthCheckMode d_lazyHealthCheckMode{LazyHealthCheckMode::TimeoutOrServFail};
    uint8_t udpTimeout{0};
    uint8_t dscp{0};
    Availability d_availability{Availability::Auto};
    HealthCheckMode d_healthCheckMode{HealthCheckMode::Active};
    bool d_tlsSubjectIsAddr{false};
    bool mustResolve{false};
    bool useECS{false};
    bool useProxyProtocol{false};
    bool d_proxyProtocolAdvertiseTLS{false};
    bool setCD{false};
    bool disableZeroScope{false};
    bool tcpFastOpen{false};
    bool ipBindAddrNoPort{true};
    bool reconnectOnUp{false};
    bool d_tcpCheck{false};
    bool d_tcpOnly{false};
    bool d_addXForwardedHeaders{false}; // for DoH backends
    bool d_lazyHealthCheckUseExponentialBackOff{false};
    bool d_upgradeToLazyHealthChecks{false};
  };

  struct Config : public BaseConfig
  {
    Config() :
      BaseConfig()
    {
    }
    Config(const ComboAddress& remote_) :
      BaseConfig(remote_)
    {
    }
    Config(const Config& c) :
      BaseConfig(c)
    {
      checkInterval.store(c.checkInterval.load());
      checkTimeout.store(c.checkTimeout.load());
      maxCheckFailures.store(c.maxCheckFailures.load());
      minRiseSuccesses.store(c.minRiseSuccesses.load());
    }

    std::atomic<unsigned int> checkInterval{1};
    std::atomic<uint16_t> checkTimeout{1000}; /* in milliseconds */
    std::atomic<uint8_t> maxCheckFailures{1};
    std::atomic<uint8_t> minRiseSuccesses{1};
  };

  struct HealthCheckMetrics
  {
    stat_t d_failures{0};
    stat_t d_timeOuts{0};
    stat_t d_parseErrors{0};
    stat_t d_networkErrors{0};
    stat_t d_mismatchErrors{0};
    stat_t d_invalidResponseErrors{0};
  };

  DownstreamState(DownstreamState::Config&& config, std::shared_ptr<TLSCtx> tlsCtx, bool connect);
  DownstreamState(const ComboAddress& remote) :
    DownstreamState(DownstreamState::Config(remote), nullptr, false)
  {
  }

  ~DownstreamState();

  Config d_config;
  HealthCheckMetrics d_healthCheckMetrics;
  stat_t sendErrors{0};
  stat_t outstanding{0};
  stat_t reuseds{0};
  stat_t queries{0};
  stat_t responses{0};
  stat_t nonCompliantResponses{0};
  struct
  {
    stat_t sendErrors{0};
    stat_t reuseds{0};
    stat_t queries{0};
  } prev;
  stat_t tcpDiedSendingQuery{0};
  stat_t tcpDiedReadingResponse{0};
  stat_t tcpGaveUp{0};
  stat_t tcpReadTimeouts{0};
  stat_t tcpWriteTimeouts{0};
  stat_t tcpConnectTimeouts{0};
  /* current number of connections to this backend */
  stat_t tcpCurrentConnections{0};
  /* maximum number of concurrent connections to this backend reached */
  stat_t tcpMaxConcurrentConnections{0};
  /* number of times we had to enforce the maximum concurrent connections limit */
  stat_t tcpTooManyConcurrentConnections{0};
  stat_t tcpReusedConnections{0};
  stat_t tcpNewConnections{0};
  stat_t tlsResumptions{0};
  pdns::stat_double_t tcpAvgQueriesPerConnection{0.0};
  /* in ms */
  pdns::stat_double_t tcpAvgConnectionDuration{0.0};
  pdns::stat_double_t queryLoad{0.0};
  pdns::stat_double_t dropRate{0.0};

  SharedLockGuarded<std::vector<unsigned int>> hashes;
  LockGuarded<std::unique_ptr<FDMultiplexer>> mplexer{nullptr};

private:
  LockGuarded<std::map<uint16_t, IDState>> d_idStatesMap;
  vector<IDState> idStates;

  struct LazyHealthCheckStats
  {
    boost::circular_buffer<bool> d_lastResults;
    time_t d_nextCheck{0};
    enum class LazyStatus : uint8_t
    {
      Healthy = 0,
      PotentialFailure,
      Failed
    };
    LazyStatus d_status{LazyStatus::Healthy};
  };
  LockGuarded<LazyHealthCheckStats> d_lazyHealthCheckStats;

public:
  std::shared_ptr<TLSCtx> d_tlsCtx{nullptr};
  std::vector<int> sockets;
  StopWatch sw;
  std::optional<QPSLimiter> d_qpsLimiter;
#ifdef HAVE_XSK
  std::vector<std::shared_ptr<XskWorker>> d_xskInfos;
  std::vector<std::shared_ptr<XskSocket>> d_xskSockets;
#endif
  std::atomic<uint64_t> idOffset{0};
  std::atomic<double> d_healthCheckLatency{0.0};
  size_t socketsOffset{0};
  double latencyUsec{0.0};
  double latencyUsecTCP{0.0};
  unsigned int d_nextCheck{0};
  uint16_t currentCheckFailures{0};
  std::atomic<bool> hashesComputed{false};
  std::atomic<bool> connected{false};
  std::atomic<bool> upStatus{false};

private:
  void handleUDPTimeout(IDState& ids);
  void updateNextLazyHealthCheck(LazyHealthCheckStats& stats, bool checkScheduled, std::optional<time_t> currentTime = std::nullopt);
  void connectUDPSockets();
#ifdef HAVE_XSK
  void addXSKDestination(int fd);
  void removeXSKDestination(int fd);
#endif /* HAVE_XSK */

  std::mutex connectLock;
  std::condition_variable d_connectedWait;
#ifdef HAVE_XSK
  SharedLockGuarded<std::vector<ComboAddress>> d_socketSourceAddresses;
#endif
  std::atomic_flag threadStarted;
  uint8_t consecutiveSuccessfulChecks{0};
  bool d_stopped{false};

public:
  static bool parseSourceParameter(const std::string& source, Config& config);
  static bool parseAvailabilityConfigFromStr(DownstreamState::Config& config, const std::string& str);

  void updateStatisticsInfo()
  {
    auto delta = sw.udiffAndSet() / 1000000.0;
    queryLoad.store(1.0 * (queries.load() - prev.queries.load()) / delta);
    dropRate.store(1.0 * (reuseds.load() - prev.reuseds.load()) / delta);
    prev.queries.store(queries.load());
    prev.reuseds.store(reuseds.load());
  }
  void start();

  bool isUp() const
  {
    if (d_config.d_availability == Availability::Down) {
      return false;
    }
    else if (d_config.d_availability == Availability::Up) {
      return true;
    }
    return upStatus.load(std::memory_order_relaxed);
  }

  void setUp()
  {
    d_config.d_availability = Availability::Up;
  }

  void setUpStatus(bool newStatus)
  {
    upStatus.store(newStatus);
    if (!newStatus) {
      latencyUsec = 0.0;
      latencyUsecTCP = 0.0;
    }
  }
  void setDown()
  {
    d_config.d_availability = Availability::Down;
    latencyUsec = 0.0;
    latencyUsecTCP = 0.0;
  }
  void setAuto()
  {
    d_config.d_availability = Availability::Auto;
  }
  void setActiveAuto()
  {
    d_config.d_availability = Availability::Auto;
    d_config.d_healthCheckMode = HealthCheckMode::Active;
  }
  void setLazyAuto()
  {
    d_config.d_availability = Availability::Auto;
    d_config.d_healthCheckMode = HealthCheckMode::Lazy;
    d_lazyHealthCheckStats.lock()->d_lastResults.set_capacity(d_config.d_lazyHealthCheckSampleSize);
  }
  bool healthCheckRequired(std::optional<time_t> currentTime = std::nullopt);

  const string& getName() const
  {
    return d_config.name;
  }
  const string& getNameWithAddr() const
  {
    return d_config.nameWithAddr;
  }
  void setName(const std::string& newName)
  {
    d_config.name = newName;
    d_config.nameWithAddr = newName.empty() ? d_config.remote.toStringWithPort() : (d_config.name + " (" + d_config.remote.toStringWithPort() + ")");
  }

  string getStatus() const
  {
    string status;
    if (d_config.d_availability == DownstreamState::Availability::Up) {
      status = "UP";
    }
    else if (d_config.d_availability == DownstreamState::Availability::Down) {
      status = "DOWN";
    }
    else {
      status = (upStatus.load(std::memory_order_relaxed) ? "up" : "down");
    }
    return status;
  }

  bool reconnect(bool initialAttempt = false);
  void waitUntilConnected();
  void hash();
  void setId(const boost::uuids::uuid& newId);
  void setWeight(int newWeight);
  void stop();
  bool isStopped() const
  {
    return d_stopped;
  }
  const boost::uuids::uuid& getID() const
  {
    return *d_config.id;
  }

  void updateTCPMetrics(size_t nbQueries, uint64_t durationMs)
  {
    tcpAvgQueriesPerConnection = (99.0 * tcpAvgQueriesPerConnection / 100.0) + (nbQueries / 100.0);
    tcpAvgConnectionDuration = (99.0 * tcpAvgConnectionDuration / 100.0) + (durationMs / 100.0);
  }

  void updateTCPLatency(double udiff)
  {
    latencyUsecTCP = (127.0 * latencyUsecTCP / 128.0) + udiff / 128.0;
  }

  void incQueriesCount()
  {
    ++queries;
    if (d_qpsLimiter) {
      d_qpsLimiter->addHit();
    }
  }

  void incCurrentConnectionsCount();

  bool doHealthcheckOverTCP() const
  {
    return d_config.d_tcpOnly || d_config.d_tcpCheck || d_tlsCtx != nullptr;
  }

  [[nodiscard]] bool isTCPOnly() const
  {
    return d_config.d_tcpOnly || d_tlsCtx != nullptr;
  }

  bool isDoH() const
  {
    return !d_config.d_dohPath.empty();
  }

  bool passCrossProtocolQuery(std::unique_ptr<CrossProtocolQuery>&& cpq);
  int pickSocketForSending();
  void pickSocketsReadyForReceiving(std::vector<int>& ready);
  void handleUDPTimeouts();
  void reportTimeoutOrError();
  void reportResponse(uint8_t rcode);
  void submitHealthCheckResult(bool initial, bool newResult);
  time_t getNextLazyHealthCheck();
  uint16_t saveState(InternalQueryState&&);
  void restoreState(uint16_t id, InternalQueryState&&);
  std::optional<InternalQueryState> getState(uint16_t id);

#ifdef HAVE_XSK
  void registerXsk(std::vector<std::shared_ptr<XskSocket>>& xsks);
  [[nodiscard]] ComboAddress pickSourceAddressForSending();
#endif /* HAVE_XSK */

  dnsdist::Protocol getProtocol() const
  {
    if (isDoH()) {
      return dnsdist::Protocol::DoH;
    }
    if (d_tlsCtx != nullptr) {
      return dnsdist::Protocol::DoT;
    }
    if (isTCPOnly()) {
      return dnsdist::Protocol::DoTCP;
    }
    return dnsdist::Protocol::DoUDP;
  }

  double getRelevantLatencyUsec() const
  {
    if (isTCPOnly()) {
      return latencyUsecTCP;
    }
    return latencyUsec;
  }

  unsigned int getQPSLimit() const;
};

void responderThread(std::shared_ptr<DownstreamState> dss);

enum ednsHeaderFlags
{
  EDNS_HEADER_FLAG_NONE = 0,
  EDNS_HEADER_FLAG_DO = 32768
};

extern shared_ptr<BPFFilter> g_defaultBPFFilter;

void tcpAcceptorThread(const std::vector<ClientState*>& states);

void setLuaNoSideEffect(); // if nothing has been declared, set that there are no side effects
void setLuaSideEffect(); // set to report a side effect, cancelling all _no_ side effect calls
bool getLuaNoSideEffect(); // set if there were only explicit declarations of _no_ side effect
void resetLuaSideEffect(); // reset to indeterminate state

bool responseContentMatches(const PacketBuffer& response, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const std::shared_ptr<DownstreamState>& remote, bool allowEmptyResponse);

bool checkQueryHeaders(const struct dnsheader& dnsHeader, ClientState& clientState);

class DNSCryptQuery;

enum class ProcessQueryResult : uint8_t
{
  Drop,
  SendAnswer,
  PassToBackend,
  Asynchronous
};

#include "dnsdist-actions.hh"
#include "dnsdist-rule-chains.hh"

ProcessQueryResult processQuery(DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend);
ProcessQueryResult processQueryAfterRules(DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& outgoingBackend);
bool processResponse(PacketBuffer& response, DNSResponse& dnsResponse, bool muted);
bool processRulesResult(const DNSAction::Action& action, DNSQuestion& dnsQuestion, std::string& ruleresult, bool& drop);
bool processResponseAfterRules(PacketBuffer& response, DNSResponse& dnsResponse, bool muted);
bool processResponderPacket(std::shared_ptr<DownstreamState>& dss, PacketBuffer& response, InternalQueryState&& ids);
bool applyRulesToResponse(const std::vector<dnsdist::rules::ResponseRuleAction>& respRuleActions, DNSResponse& dnsResponse);

bool assignOutgoingUDPQueryToBackend(std::shared_ptr<DownstreamState>& downstream, uint16_t queryID, DNSQuestion& dnsQuestion, PacketBuffer& query, bool actuallySend = true);

ssize_t udpClientSendRequestToBackend(const std::shared_ptr<DownstreamState>& backend, const int socketDesc, const PacketBuffer& request, bool healthCheck = false);
bool sendUDPResponse(int origFD, const PacketBuffer& response, const int delayMsec, const ComboAddress& origDest, const ComboAddress& origRemote);
void handleResponseSent(const DNSName& qname, const QType& qtype, double udiff, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH, dnsdist::Protocol outgoingProtocol, dnsdist::Protocol incomingProtocol, bool fromBackend);
void handleResponseSent(const InternalQueryState& ids, double udiff, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH, dnsdist::Protocol outgoingProtocol, bool fromBackend);
bool handleTimeoutResponseRules(const std::vector<dnsdist::rules::ResponseRuleAction>& rules, InternalQueryState& ids, const std::shared_ptr<DownstreamState>& ds, const std::shared_ptr<TCPQuerySender>& sender);
void handleServerStateChange(const std::string& nameWithAddr, bool newResult);
