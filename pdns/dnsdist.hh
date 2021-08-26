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
#include "ext/luawrapper/include/LuaContext.hpp"

#include <mutex>
#include <string>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <unordered_map>

#include <boost/variant.hpp>

#include "capabilities.hh"
#include "circular_buffer.hh"
#include "dnscrypt.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-dynbpf.hh"
#include "dnsdist-lbpolicies.hh"
#include "dnsdist-protocols.hh"
#include "dnsname.hh"
#include "doh.hh"
#include "ednsoptions.hh"
#include "iputils.hh"
#include "misc.hh"
#include "mplexer.hh"
#include "noinitvector.hh"
#include "sholder.hh"
#include "tcpiohandler.hh"
#include "uuid-utils.hh"
#include "proxy-protocol.hh"
#include "stat_t.hh"

uint64_t uptimeOfProcess(const std::string& str);

extern uint16_t g_ECSSourcePrefixV4;
extern uint16_t g_ECSSourcePrefixV6;
extern bool g_ECSOverride;

using QTag = std::unordered_map<string, string>;

struct DNSQuestion
{
  DNSQuestion(const DNSName* name, uint16_t type, uint16_t class_, const ComboAddress* lc, const ComboAddress* rem, PacketBuffer& data_, dnsdist::Protocol proto, const struct timespec* queryTime_):
    data(data_), qname(name), local(lc), remote(rem), queryTime(queryTime_), tempFailureTTL(boost::none), qtype(type), qclass(class_), ecsPrefixLength(rem->sin4.sin_family == AF_INET ? g_ECSSourcePrefixV4 : g_ECSSourcePrefixV6), protocol(proto), ecsOverride(g_ECSOverride) {
    const uint16_t* flags = getFlagsFromDNSHeader(getHeader());
    origFlags = *flags;
  }
  DNSQuestion(const DNSQuestion&) = delete;
  DNSQuestion& operator=(const DNSQuestion&) = delete;
  DNSQuestion(DNSQuestion&&) = default;

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

  dnsheader* getHeader()
  {
    if (data.size() < sizeof(dnsheader)) {
      throw std::runtime_error("Trying to access the dnsheader of a too small (" + std::to_string(data.size()) + ") DNSQuestion buffer");
    }
    return reinterpret_cast<dnsheader*>(&data.at(0));
  }

  const dnsheader* getHeader() const
  {
    if (data.size() < sizeof(dnsheader)) {
      throw std::runtime_error("Trying to access the dnsheader of a too small (" + std::to_string(data.size()) + ") DNSQuestion buffer");
    }
    return reinterpret_cast<const dnsheader*>(&data.at(0));
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
    return protocol;
  }

  bool overTCP() const
  {
    return !(protocol == dnsdist::Protocol::DoUDP || protocol == dnsdist::Protocol::DNSCryptUDP);
  }

protected:
  PacketBuffer& data;

public:
  boost::optional<boost::uuids::uuid> uniqueId;
  Netmask ecs;
  boost::optional<Netmask> subnet;
  std::string sni; /* Server Name Indication, if any (DoT or DoH) */
  std::string poolname;
  const DNSName* qname{nullptr};
  const ComboAddress* local{nullptr};
  const ComboAddress* remote{nullptr};
  /* this is the address dnsdist received the packet on,
     which might not match local when support for incoming proxy protocol
     is enabled */
  const ComboAddress* hopLocal{nullptr};  /* the address dnsdist received the packet from, see above */
  const ComboAddress* hopRemote{nullptr};
  std::shared_ptr<QTag> qTag{nullptr};
  std::unique_ptr<std::vector<ProxyProtocolValue>> proxyProtocolValues{nullptr};
  mutable std::shared_ptr<std::map<uint16_t, EDNSOptionView> > ednsOptions;
  std::shared_ptr<DNSCryptQuery> dnsCryptQuery{nullptr};
  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr};
  const struct timespec* queryTime{nullptr};
  struct DOHUnit* du{nullptr};
  int delayMsec{0};
  boost::optional<uint32_t> tempFailureTTL;
  uint32_t cacheKeyNoECS{0};
  uint32_t cacheKey{0};
  /* for DoH */
  uint32_t cacheKeyUDP{0};
  const uint16_t qtype;
  const uint16_t qclass;
  uint16_t ecsPrefixLength;
  uint16_t origFlags;
  uint16_t cacheFlags{0}; /* DNS flags as sent to the backend */
  const dnsdist::Protocol protocol;
  uint8_t ednsRCode{0};
  bool skipCache{false};
  bool ecsOverride;
  bool useECS{true};
  bool addXPF{true};
  bool ecsSet{false};
  bool ecsAdded{false};
  bool ednsAdded{false};
  bool useZeroScope{false};
  bool dnssecOK{false};
};

struct DNSResponse : DNSQuestion
{
  DNSResponse(const DNSName* name, uint16_t type, uint16_t class_, const ComboAddress* lc, const ComboAddress* rem, PacketBuffer& data_, dnsdist::Protocol proto, const struct timespec* queryTime_):
    DNSQuestion(name, type, class_, lc, rem, data_, proto, queryTime_) { }
  DNSResponse(const DNSResponse&) = delete;
  DNSResponse& operator=(const DNSResponse&) = delete;
  DNSResponse(DNSResponse&&) = default;
};

/* so what could you do:
   drop,
   fake up nxdomain,
   provide actual answer,
   allow & and stop processing,
   continue processing,
   modify header:    (servfail|refused|notimp), set TC=1,
   send to pool */

class DNSAction
{
public:
  enum class Action : uint8_t { Drop, Nxdomain, Refused, Spoof, Allow, HeaderModify, Pool, Delay, Truncate, ServFail, None, NoOp, NoRecurse, SpoofRaw };
  static std::string typeToString(const Action& action)
  {
    switch(action) {
    case Action::Drop:
      return "Drop";
    case Action::Nxdomain:
      return "Send NXDomain";
    case Action::Refused:
      return "Send Refused";
    case Action::Spoof:
      return "Spoof an answer";
    case Action::SpoofRaw:
      return "Spoof an answer from raw bytes";
    case Action::Allow:
      return "Allow";
    case Action::HeaderModify:
      return "Modify the header";
    case Action::Pool:
      return "Route to a pool";
    case Action::Delay:
      return "Delay";
    case Action::Truncate:
      return "Truncate over UDP";
    case Action::ServFail:
      return "Send ServFail";
    case Action::None:
    case Action::NoOp:
      return "Do nothing";
    case Action::NoRecurse:
      return "Set rd=0";
    }

    return "Unknown";
  }

  virtual Action operator()(DNSQuestion*, string* ruleresult) const =0;
  virtual ~DNSAction()
  {
  }
  virtual string toString() const = 0;
  virtual std::map<string, double> getStats() const
  {
    return {{}};
  }
  virtual void reload()
  {
  }
};

class DNSResponseAction
{
public:
  enum class Action : uint8_t { Allow, Delay, Drop, HeaderModify, ServFail, None };
  virtual Action operator()(DNSResponse*, string* ruleresult) const =0;
  virtual ~DNSResponseAction()
  {
  }
  virtual string toString() const = 0;
  virtual void reload()
  {
  }
};

struct DynBlock
{
  DynBlock(): action(DNSAction::Action::None), warning(false)
  {
    until.tv_sec = 0;
    until.tv_nsec = 0;
  }

  DynBlock(const std::string& reason_, const struct timespec& until_, const DNSName& domain_, DNSAction::Action action_): reason(reason_), domain(domain_), until(until_), action(action_), warning(false)
  {
  }

  DynBlock(const DynBlock& rhs): reason(rhs.reason), domain(rhs.domain), until(rhs.until), action(rhs.action), warning(rhs.warning), bpf(rhs.bpf)
  {
    blocks.store(rhs.blocks);
  }

  DynBlock(DynBlock&& rhs): reason(std::move(rhs.reason)), domain(std::move(rhs.domain)), until(rhs.until), action(rhs.action), warning(rhs.warning), bpf(rhs.bpf)
  {
    blocks.store(rhs.blocks);
  }

  DynBlock& operator=(const DynBlock& rhs)
  {
    reason = rhs.reason;
    until = rhs.until;
    domain = rhs.domain;
    action = rhs.action;
    blocks.store(rhs.blocks);
    warning = rhs.warning;
    bpf = rhs.bpf;
    return *this;
  }

  DynBlock& operator=(DynBlock&& rhs)
  {
    reason = std::move(rhs.reason);
    until = rhs.until;
    domain = std::move(rhs.domain);
    action = rhs.action;
    blocks.store(rhs.blocks);
    warning = rhs.warning;
    bpf = rhs.bpf;
    return *this;
  }

  string reason;
  DNSName domain;
  struct timespec until;
  mutable std::atomic<unsigned int> blocks;
  DNSAction::Action action{DNSAction::Action::None};
  bool warning{false};
  bool bpf{false};
};

extern GlobalStateHolder<NetmaskTree<DynBlock>> g_dynblockNMG;

extern vector<pair<struct timeval, std::string> > g_confDelta;

extern uint64_t getLatencyCount(const std::string&);

using pdns::stat_t;

struct DNSDistStats
{
  stat_t responses{0};
  stat_t servfailResponses{0};
  stat_t queries{0};
  stat_t frontendNXDomain{0};
  stat_t frontendServFail{0};
  stat_t frontendNoError{0};
  stat_t nonCompliantQueries{0};
  stat_t nonCompliantResponses{0};
  stat_t rdQueries{0};
  stat_t emptyQueries{0};
  stat_t aclDrops{0};
  stat_t dynBlocked{0};
  stat_t ruleDrop{0};
  stat_t ruleNXDomain{0};
  stat_t ruleRefused{0};
  stat_t ruleServFail{0};
  stat_t ruleTruncated{0};
  stat_t selfAnswered{0};
  stat_t downstreamTimeouts{0};
  stat_t downstreamSendErrors{0};
  stat_t truncFail{0};
  stat_t noPolicy{0};
  stat_t cacheHits{0};
  stat_t cacheMisses{0};
  stat_t latency0_1{0}, latency1_10{0}, latency10_50{0}, latency50_100{0}, latency100_1000{0}, latencySlow{0}, latencySum{0};
  stat_t securityStatus{0};
  stat_t dohQueryPipeFull{0};
  stat_t dohResponsePipeFull{0};
  stat_t proxyProtocolInvalid{0};

  double latencyAvg100{0}, latencyAvg1000{0}, latencyAvg10000{0}, latencyAvg1000000{0};
  typedef std::function<uint64_t(const std::string&)> statfunction_t;
  typedef boost::variant<stat_t*, double*, statfunction_t> entry_t;
  std::vector<std::pair<std::string, entry_t>> entries{
    {"responses", &responses},
    {"servfail-responses", &servfailResponses},
    {"queries", &queries},
    {"frontend-nxdomain", &frontendNXDomain},
    {"frontend-servfail", &frontendServFail},
    {"frontend-noerror", &frontendNoError},
    {"acl-drops", &aclDrops},
    {"rule-drop", &ruleDrop},
    {"rule-nxdomain", &ruleNXDomain},
    {"rule-refused", &ruleRefused},
    {"rule-servfail", &ruleServFail},
    {"rule-truncated", &ruleTruncated},
    {"self-answered", &selfAnswered},
    {"downstream-timeouts", &downstreamTimeouts},
    {"downstream-send-errors", &downstreamSendErrors},
    {"trunc-failures", &truncFail},
    {"no-policy", &noPolicy},
    {"latency0-1", &latency0_1},
    {"latency1-10", &latency1_10},
    {"latency10-50", &latency10_50},
    {"latency50-100", &latency50_100},
    {"latency100-1000", &latency100_1000},
    {"latency-slow", &latencySlow},
    {"latency-avg100", &latencyAvg100},
    {"latency-avg1000", &latencyAvg1000},
    {"latency-avg10000", &latencyAvg10000},
    {"latency-avg1000000", &latencyAvg1000000},
    {"uptime", uptimeOfProcess},
    {"real-memory-usage", getRealMemoryUsage},
    {"special-memory-usage", getSpecialMemoryUsage},
    {"udp-in-errors", boost::bind(udpErrorStats, "udp-in-errors")},
    {"udp-noport-errors", boost::bind(udpErrorStats, "udp-noport-errors")},
    {"udp-recvbuf-errors", boost::bind(udpErrorStats, "udp-recvbuf-errors")},
    {"udp-sndbuf-errors", boost::bind(udpErrorStats, "udp-sndbuf-errors")},
    {"tcp-listen-overflows", std::bind(tcpErrorStats, "ListenOverflows")},
    {"noncompliant-queries", &nonCompliantQueries},
    {"noncompliant-responses", &nonCompliantResponses},
    {"proxy-protocol-invalid", &proxyProtocolInvalid},
    {"rdqueries", &rdQueries},
    {"empty-queries", &emptyQueries},
    {"cache-hits", &cacheHits},
    {"cache-misses", &cacheMisses},
    {"cpu-iowait", getCPUIOWait},
    {"cpu-steal", getCPUSteal},
    {"cpu-sys-msec", getCPUTimeSystem},
    {"cpu-user-msec", getCPUTimeUser},
    {"fd-usage", getOpenFileDescriptors},
    {"dyn-blocked", &dynBlocked},
    {"dyn-block-nmg-size", [](const std::string&) { return g_dynblockNMG.getLocal()->size(); }},
    {"security-status", &securityStatus},
    {"doh-query-pipe-full", &dohQueryPipeFull},
    {"doh-response-pipe-full", &dohResponsePipeFull},
    // Latency histogram
    {"latency-sum", &latencySum},
    {"latency-count", getLatencyCount},
  };
};

extern struct DNSDistStats g_stats;
void doLatencyStats(double udiff);

#include "dnsdist-idstate.hh"

class BasicQPSLimiter
{
public:
  BasicQPSLimiter()
  {
  }

  BasicQPSLimiter(unsigned int burst): d_tokens(burst)
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
      d_tokens += 1.0 * rate * (delta/1000000.0);
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
  QPSLimiter(): BasicQPSLimiter()
  {
  }

  QPSLimiter(unsigned int rate, unsigned int burst): BasicQPSLimiter(burst), d_rate(rate), d_burst(burst), d_passthrough(false)
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

typedef std::unordered_map<string, unsigned int> QueryCountRecords;
typedef std::function<std::tuple<bool, string>(const DNSQuestion* dq)> QueryCountFilter;
struct QueryCount {
  QueryCount()
  {
  }
  ~QueryCount()
  {
  }
  SharedLockGuarded<QueryCountRecords> records;
  QueryCountFilter filter;
  bool enabled{false};
};

extern QueryCount g_qcount;

struct ClientState
{
  ClientState(const ComboAddress& local_, bool isTCP_, bool doReusePort, int fastOpenQueue, const std::string& itfName, const std::set<int>& cpus_): cpus(cpus_), local(local_), interface(itfName), fastOpenQueueSize(fastOpenQueue), tcp(isTCP_), reuseport(doReusePort)
  {
  }

  std::set<int> cpus;
  ComboAddress local;
  std::shared_ptr<DNSCryptContext> dnscryptCtx{nullptr};
  std::shared_ptr<TLSFrontend> tlsFrontend{nullptr};
  std::shared_ptr<DOHFrontend> dohFrontend{nullptr};
  std::string interface;
  stat_t queries{0};
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
  stat_t tls10queries{0};   // valid DNS queries received via TLSv1.0
  stat_t tls11queries{0};   // valid DNS queries received via TLSv1.1
  stat_t tls12queries{0};   // valid DNS queries received via TLSv1.2
  stat_t tls13queries{0};   // valid DNS queries received via TLSv1.3
  stat_t tlsUnknownqueries{0};   // valid DNS queries received via unknown TLS version
  pdns::stat_t_trait<double> tcpAvgQueriesPerConnection{0.0};
  /* in ms */
  pdns::stat_t_trait<double> tcpAvgConnectionDuration{0.0};
  size_t d_maxInFlightQueriesPerConn{1};
  size_t d_tcpConcurrentConnectionsLimit{0};
  int udpFD{-1};
  int tcpFD{-1};
  int tcpListenQueueSize{SOMAXCONN};
  int fastOpenQueueSize{0};
  bool muted{false};
  bool tcp;
  bool reuseport;
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

  std::string getType() const
  {
    std::string result = udpFD != -1 ? "UDP" : "TCP";

    if (dohFrontend) {
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

  shared_ptr<BPFFilter> d_filter;

  void detachFilter()
  {
    if (d_filter) {
      d_filter->removeSocket(getSocket());
      d_filter = nullptr;
    }
  }

  void attachFilter(shared_ptr<BPFFilter> bpf)
  {
    detachFilter();

    bpf->addSocket(getSocket());
    d_filter = bpf;
  }

  void updateTCPMetrics(size_t nbQueries, uint64_t durationMs)
  {
    tcpAvgQueriesPerConnection = (99.0 * tcpAvgQueriesPerConnection / 100.0) + (nbQueries / 100.0);
    tcpAvgConnectionDuration = (99.0 * tcpAvgConnectionDuration / 100.0) + (durationMs / 100.0);
  }
};

struct CrossProtocolQuery;

struct DownstreamState
{
   typedef std::function<std::tuple<DNSName, uint16_t, uint16_t>(const DNSName&, uint16_t, uint16_t, dnsheader*)> checkfunc_t;

  DownstreamState(const ComboAddress& remote_, const ComboAddress& sourceAddr_, unsigned int sourceItf, const std::string& sourceItfName, size_t numberOfSockets, bool connect);
  DownstreamState(const ComboAddress& remote_): DownstreamState(remote_, ComboAddress(), 0, std::string(), 1, true) {}
  ~DownstreamState();

  boost::uuids::uuid id;
  SharedLockGuarded<std::vector<unsigned int>> hashes;
  std::vector<int> sockets;
  const std::string sourceItfName;
  std::string d_tlsSubjectName;
  std::string d_dohPath;
  std::mutex connectLock;
  LockGuarded<std::unique_ptr<FDMultiplexer>> mplexer{nullptr};
  std::shared_ptr<TLSCtx> d_tlsCtx{nullptr};
  std::thread tid;
  const ComboAddress remote;
  QPSLimiter qps;
  vector<IDState> idStates;
  const ComboAddress sourceAddr;
  checkfunc_t checkFunction;
  DNSName checkName{"a.root-servers.net."};
  QType checkType{QType::A};
  uint16_t checkClass{QClass::IN};
  std::atomic<uint64_t> idOffset{0};
  std::atomic<bool> hashesComputed{false};
  stat_t sendErrors{0};
  stat_t outstanding{0};
  stat_t reuseds{0};
  stat_t queries{0};
  stat_t responses{0};
  struct {
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
  stat_t tcpReusedConnections{0};
  stat_t tcpNewConnections{0};
  stat_t tlsResumptions{0};
  pdns::stat_t_trait<double> tcpAvgQueriesPerConnection{0.0};
  /* in ms */
  pdns::stat_t_trait<double> tcpAvgConnectionDuration{0.0};
  size_t socketsOffset{0};
  size_t d_maxInFlightQueriesPerConn{1};
  size_t d_tcpConcurrentConnectionsLimit{0};
  pdns::stat_t_trait<double> queryLoad{0.0};
  pdns::stat_t_trait<double> dropRate{0.0};
  double latencyUsec{0.0};
  double latencyUsecTCP{0.0};
  int order{1};
  int weight{1};
  int tcpConnectTimeout{5};
  int tcpRecvTimeout{30};
  int tcpSendTimeout{30};
  unsigned int checkInterval{1};
  unsigned int lastCheck{0};
  const unsigned int sourceItf{0};
  uint16_t retries{5};
  uint16_t xpfRRCode{0};
  uint16_t checkTimeout{1000}; /* in milliseconds */
  uint8_t currentCheckFailures{0};
  uint8_t consecutiveSuccessfulChecks{0};
  uint8_t maxCheckFailures{1};
  uint8_t minRiseSuccesses{1};
  StopWatch sw;
  set<string> pools;
  enum class Availability : uint8_t { Up, Down, Auto} availability{Availability::Auto};
  bool mustResolve{false};
  bool upStatus{false};
  bool useECS{false};
  bool useProxyProtocol{false};
  bool setCD{false};
  bool disableZeroScope{false};
  std::atomic<bool> connected{false};
  std::atomic_flag threadStarted;
  bool tcpFastOpen{false};
  bool ipBindAddrNoPort{true};
  bool reconnectOnUp{false};
  bool d_tcpCheck{false};
  bool d_tcpOnly{false};
  bool d_addXForwardedHeaders{false}; // for DoH backends

  bool isUp() const
  {
    if(availability == Availability::Down)
      return false;
    if(availability == Availability::Up)
      return true;
    return upStatus;
  }
  void setUp() { availability = Availability::Up; }
  void setUpStatus(bool newStatus)
  {
    upStatus = newStatus;
    if (!upStatus)
      latencyUsec = 0.0;
  }
  void setDown()
  {
    availability = Availability::Down;
    latencyUsec = 0.0;
  }
  void setAuto() { availability = Availability::Auto; }
  const string& getName() const {
    return name;
  }
  const string& getNameWithAddr() const {
    return nameWithAddr;
  }
  void setName(const std::string& newName)
  {
    name = newName;
    nameWithAddr = newName.empty() ? remote.toStringWithPort() : (name + " (" + remote.toStringWithPort()+ ")");
  }

  string getStatus() const
  {
    string status;
    if(availability == DownstreamState::Availability::Up)
      status = "UP";
    else if(availability == DownstreamState::Availability::Down)
      status = "DOWN";
    else
      status = (upStatus ? "up" : "down");
    return status;
  }
  bool reconnect();
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
    return id;
  }

  void updateTCPMetrics(size_t nbQueries, uint64_t durationMs)
  {
    tcpAvgQueriesPerConnection = (99.0 * tcpAvgQueriesPerConnection / 100.0) + (nbQueries / 100.0);
    tcpAvgConnectionDuration = (99.0 * tcpAvgConnectionDuration / 100.0) + (durationMs / 100.0);
  }

  void incQueriesCount()
  {
    ++queries;
    qps.addHit();
  }

  void incCurrentConnectionsCount();

  bool doHealthcheckOverTCP() const
  {
    return d_tcpOnly || d_tcpCheck || d_tlsCtx != nullptr;
  }

  bool isTCPOnly() const
  {
    return d_tcpOnly || d_tlsCtx != nullptr;
  }

  bool isDoH() const
  {
    return !d_dohPath.empty();
  }

  bool passCrossProtocolQuery(std::unique_ptr<CrossProtocolQuery>&& cpq);

private:
  std::string name;
  std::string nameWithAddr;
  bool d_stopped{false};
};
using servers_t =vector<std::shared_ptr<DownstreamState>>;

void responderThread(std::shared_ptr<DownstreamState> state);
extern LockGuarded<LuaContext> g_lua;
extern std::string g_outputBuffer; // locking for this is ok, as locked by g_luamutex

class DNSRule
{
public:
  virtual ~DNSRule ()
  {
  }
  virtual bool matches(const DNSQuestion* dq) const =0;
  virtual string toString() const = 0;
  mutable stat_t d_matches{0};
};

struct ServerPool
{
  ServerPool(): d_servers(std::make_shared<ServerPolicy::NumberedServerVector>())
  {
  }

  ~ServerPool()
  {
  }

  const std::shared_ptr<DNSDistPacketCache> getCache() const { return packetCache; };

  bool getECS() const
  {
    return d_useECS;
  }

  void setECS(bool useECS)
  {
    d_useECS = useECS;
  }

  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr};
  std::shared_ptr<ServerPolicy> policy{nullptr};

  size_t countServers(bool upOnly);
  const std::shared_ptr<ServerPolicy::NumberedServerVector> getServers();
  void addServer(shared_ptr<DownstreamState>& server);
  void removeServer(shared_ptr<DownstreamState>& server);

private:
  SharedLockGuarded<std::shared_ptr<ServerPolicy::NumberedServerVector>> d_servers;
  bool d_useECS{false};
};

struct CarbonConfig
{
  ComboAddress server;
  std::string namespace_name;
  std::string ourname;
  std::string instance_name;
  unsigned int interval;
};

enum ednsHeaderFlags {
  EDNS_HEADER_FLAG_NONE = 0,
  EDNS_HEADER_FLAG_DO = 32768
};

struct DNSDistRuleAction
{
  std::shared_ptr<DNSRule> d_rule;
  std::shared_ptr<DNSAction> d_action;
  std::string d_name;
  boost::uuids::uuid d_id;
  uint64_t d_creationOrder;
};

struct DNSDistResponseRuleAction
{
  std::shared_ptr<DNSRule> d_rule;
  std::shared_ptr<DNSResponseAction> d_action;
  std::string d_name;
  boost::uuids::uuid d_id;
  uint64_t d_creationOrder;
};

extern GlobalStateHolder<SuffixMatchTree<DynBlock>> g_dynblockSMT;
extern DNSAction::Action g_dynBlockAction;

extern GlobalStateHolder<vector<CarbonConfig> > g_carbon;
extern GlobalStateHolder<ServerPolicy> g_policy;
extern GlobalStateHolder<servers_t> g_dstates;
extern GlobalStateHolder<pools_t> g_pools;
extern GlobalStateHolder<vector<DNSDistRuleAction> > g_ruleactions;
extern GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_respruleactions;
extern GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_cachehitrespruleactions;
extern GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_selfansweredrespruleactions;
extern GlobalStateHolder<NetmaskGroup> g_ACL;

extern ComboAddress g_serverControl; // not changed during runtime

extern std::vector<shared_ptr<TLSFrontend>> g_tlslocals;
extern std::vector<shared_ptr<DOHFrontend>> g_dohlocals;
extern std::vector<std::unique_ptr<ClientState>> g_frontends;
extern bool g_truncateTC;
extern bool g_fixupCase;
extern int g_tcpRecvTimeout;
extern int g_tcpSendTimeout;
extern int g_udpTimeout;
extern uint16_t g_maxOutstanding;
extern std::atomic<bool> g_configurationDone;
extern boost::optional<uint64_t> g_maxTCPClientThreads;
extern uint64_t g_maxTCPQueuedConnections;
extern size_t g_maxTCPQueriesPerConn;
extern size_t g_maxTCPConnectionDuration;
extern size_t g_maxTCPConnectionsPerClient;
extern size_t g_tcpInternalPipeBufferSize;
extern pdns::stat16_t g_cacheCleaningDelay;
extern pdns::stat16_t g_cacheCleaningPercentage;
extern uint32_t g_staleCacheEntriesTTL;
extern bool g_apiReadWrite;
extern std::string g_apiConfigDirectory;
extern bool g_servFailOnNoPolicy;
extern size_t g_udpVectorSize;
extern bool g_allowEmptyResponse;

extern shared_ptr<BPFFilter> g_defaultBPFFilter;
extern std::vector<std::shared_ptr<DynBPFFilter> > g_dynBPFFilters;

struct LocalHolders
{
  LocalHolders(): acl(g_ACL.getLocal()), policy(g_policy.getLocal()), ruleactions(g_ruleactions.getLocal()), cacheHitRespRuleactions(g_cachehitrespruleactions.getLocal()), selfAnsweredRespRuleactions(g_selfansweredrespruleactions.getLocal()), servers(g_dstates.getLocal()), dynNMGBlock(g_dynblockNMG.getLocal()), dynSMTBlock(g_dynblockSMT.getLocal()), pools(g_pools.getLocal())
  {
  }

  LocalStateHolder<NetmaskGroup> acl;
  LocalStateHolder<ServerPolicy> policy;
  LocalStateHolder<vector<DNSDistRuleAction> > ruleactions;
  LocalStateHolder<vector<DNSDistResponseRuleAction> > cacheHitRespRuleactions;
  LocalStateHolder<vector<DNSDistResponseRuleAction> > selfAnsweredRespRuleactions;
  LocalStateHolder<servers_t> servers;
  LocalStateHolder<NetmaskTree<DynBlock> > dynNMGBlock;
  LocalStateHolder<SuffixMatchTree<DynBlock> > dynSMTBlock;
  LocalStateHolder<pools_t> pools;
};

vector<std::function<void(void)>> setupLua(bool client, const std::string& config);

void tcpAcceptorThread(ClientState* p);
void setMaxCachedTCPConnectionsPerDownstream(size_t max);

#ifdef HAVE_DNS_OVER_HTTPS
void dohThread(ClientState* cs);
#endif /* HAVE_DNS_OVER_HTTPS */

void setLuaNoSideEffect(); // if nothing has been declared, set that there are no side effects
void setLuaSideEffect();   // set to report a side effect, cancelling all _no_ side effect calls
bool getLuaNoSideEffect(); // set if there were only explicit declarations of _no_ side effect
void resetLuaSideEffect(); // reset to indeterminate state

bool responseContentMatches(const PacketBuffer& response, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& remote, unsigned int& qnameWireLength);
bool processResponse(PacketBuffer& response, LocalStateHolder<vector<DNSDistResponseRuleAction> >& localRespRuleActions, DNSResponse& dr, bool muted, bool receivedOverUDP);
bool processRulesResult(const DNSAction::Action& action, DNSQuestion& dq, std::string& ruleresult, bool& drop);

bool checkQueryHeaders(const struct dnsheader* dh);

extern std::vector<std::shared_ptr<DNSCryptContext>> g_dnsCryptLocals;
int handleDNSCryptQuery(PacketBuffer& packet, std::shared_ptr<DNSCryptQuery>& query, bool tcp, time_t now, PacketBuffer& response);
bool checkDNSCryptQuery(const ClientState& cs, PacketBuffer& query, std::shared_ptr<DNSCryptQuery>& dnsCryptQuery, time_t now, bool tcp);

uint16_t getRandomDNSID();

#include "dnsdist-snmp.hh"

extern bool g_snmpEnabled;
extern bool g_snmpTrapsEnabled;
extern DNSDistSNMPAgent* g_snmpAgent;
extern bool g_addEDNSToSelfGeneratedResponses;

extern std::set<std::string> g_capabilitiesToRetain;
static const uint16_t s_udpIncomingBufferSize{1500}; // don't accept UDP queries larger than this value
static const size_t s_maxPacketCacheEntrySize{4096}; // don't cache responses larger than this value

enum class ProcessQueryResult : uint8_t { Drop, SendAnswer, PassToBackend };
ProcessQueryResult processQuery(DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend);

DNSResponse makeDNSResponseFromIDState(IDState& ids, PacketBuffer& data);
void setIDStateFromDNSQuestion(IDState& ids, DNSQuestion& dq, DNSName&& qname);

int pickBackendSocketForSending(std::shared_ptr<DownstreamState>& state);
ssize_t udpClientSendRequestToBackend(const std::shared_ptr<DownstreamState>& ss, const int sd, const PacketBuffer& request, bool healthCheck = false);
void handleResponseSent(const IDState& ids, double udiff, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH);

void carbonDumpThread();
