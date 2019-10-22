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

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <unordered_map>

#include <boost/variant.hpp>

#include "bpf-filter.hh"
#include "capabilities.hh"
#include "circular_buffer.hh"
#include "dnscrypt.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-dynbpf.hh"
#include "dnsname.hh"
#include "doh.hh"
#include "ednsoptions.hh"
#include "gettime.hh"
#include "iputils.hh"
#include "misc.hh"
#include "mplexer.hh"
#include "sholder.hh"
#include "tcpiohandler.hh"
#include "uuid-utils.hh"

void carbonDumpThread();
uint64_t uptimeOfProcess(const std::string& str);

extern uint16_t g_ECSSourcePrefixV4;
extern uint16_t g_ECSSourcePrefixV6;
extern bool g_ECSOverride;

typedef std::unordered_map<string, string> QTag;

struct DNSQuestion
{
  DNSQuestion(const DNSName* name, uint16_t type, uint16_t class_, unsigned int consumed_, const ComboAddress* lc, const ComboAddress* rem, struct dnsheader* header, size_t bufferSize, uint16_t queryLen, bool isTcp, const struct timespec* queryTime_):
    qname(name), local(lc), remote(rem), dh(header), queryTime(queryTime_), size(bufferSize), consumed(consumed_), tempFailureTTL(boost::none), qtype(type), qclass(class_), len(queryLen), ecsPrefixLength(rem->sin4.sin_family == AF_INET ? g_ECSSourcePrefixV4 : g_ECSSourcePrefixV6), tcp(isTcp), ecsOverride(g_ECSOverride) {
    const uint16_t* flags = getFlagsFromDNSHeader(dh);
    origFlags = *flags;
  }
  DNSQuestion(const DNSQuestion&) = delete;
  DNSQuestion& operator=(const DNSQuestion&) = delete;
  DNSQuestion(DNSQuestion&&) = default;

#ifdef HAVE_PROTOBUF
  boost::optional<boost::uuids::uuid> uniqueId;
#endif
  Netmask ecs;
  boost::optional<Netmask> subnet;
  std::string sni; /* Server Name Indication, if any (DoT or DoH) */
  std::string poolname;
  const DNSName* qname{nullptr};
  const ComboAddress* local{nullptr};
  const ComboAddress* remote{nullptr};
  std::shared_ptr<QTag> qTag{nullptr};
  std::shared_ptr<std::map<uint16_t, EDNSOptionView> > ednsOptions;
  std::shared_ptr<DNSCryptQuery> dnsCryptQuery{nullptr};
  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr};
  struct dnsheader* dh{nullptr};
  const struct timespec* queryTime{nullptr};
  struct DOHUnit* du{nullptr};
  size_t size;
  unsigned int consumed{0};
  int delayMsec{0};
  boost::optional<uint32_t> tempFailureTTL;
  uint32_t cacheKeyNoECS;
  uint32_t cacheKey;
  const uint16_t qtype;
  const uint16_t qclass;
  uint16_t len;
  uint16_t ecsPrefixLength;
  uint16_t origFlags;
  uint8_t ednsRCode{0};
  const bool tcp;
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
  DNSResponse(const DNSName* name, uint16_t type, uint16_t class_, unsigned int consumed_, const ComboAddress* lc, const ComboAddress* rem, struct dnsheader* header, size_t bufferSize, uint16_t responseLen, bool isTcp, const struct timespec* queryTime_):
    DNSQuestion(name, type, class_, consumed_, lc, rem, header, bufferSize, responseLen, isTcp, queryTime_) { }
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
  enum class Action { Drop, Nxdomain, Refused, Spoof, Allow, HeaderModify, Pool, Delay, Truncate, ServFail, None, NoOp, NoRecurse };
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
};

class DNSResponseAction
{
public:
  enum class Action { Allow, Delay, Drop, HeaderModify, ServFail, None };
  virtual Action operator()(DNSResponse*, string* ruleresult) const =0;
  virtual ~DNSResponseAction()
  {
  }
  virtual string toString() const = 0;
};

struct DynBlock
{
  DynBlock(): action(DNSAction::Action::None), warning(false)
  {
  }

  DynBlock(const std::string& reason_, const struct timespec& until_, const DNSName& domain_, DNSAction::Action action_): reason(reason_), until(until_), domain(domain_), action(action_), warning(false)
  {
  }

  DynBlock(const DynBlock& rhs): reason(rhs.reason), until(rhs.until), domain(rhs.domain), action(rhs.action), warning(rhs.warning)
  {
    blocks.store(rhs.blocks);
  }

  DynBlock& operator=(const DynBlock& rhs)
  {
    reason=rhs.reason;
    until=rhs.until;
    domain=rhs.domain;
    action=rhs.action;
    blocks.store(rhs.blocks);
    warning=rhs.warning;
    return *this;
  }

  string reason;
  struct timespec until;
  DNSName domain;
  DNSAction::Action action;
  mutable std::atomic<unsigned int> blocks;
  bool warning;
};

extern GlobalStateHolder<NetmaskTree<DynBlock>> g_dynblockNMG;

extern vector<pair<struct timeval, std::string> > g_confDelta;

extern uint64_t getLatencyCount(const std::string&);

struct DNSDistStats
{
  using stat_t=std::atomic<uint64_t>; // aww yiss ;-)
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
  stat_t selfAnswered{0};
  stat_t downstreamTimeouts{0};
  stat_t downstreamSendErrors{0};
  stat_t truncFail{0};
  stat_t noPolicy{0};
  stat_t cacheHits{0};
  stat_t cacheMisses{0};
  stat_t latency0_1{0}, latency1_10{0}, latency10_50{0}, latency50_100{0}, latency100_1000{0}, latencySlow{0}, latencySum{0};
  stat_t securityStatus{0};

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
    {"noncompliant-queries", &nonCompliantQueries},
    {"noncompliant-responses", &nonCompliantResponses},
    {"rdqueries", &rdQueries},
    {"empty-queries", &emptyQueries},
    {"cache-hits", &cacheHits},
    {"cache-misses", &cacheMisses},
    {"cpu-user-msec", getCPUTimeUser},
    {"cpu-sys-msec", getCPUTimeSystem},
    {"fd-usage", getOpenFileDescriptors},
    {"dyn-blocked", &dynBlocked},
    {"dyn-block-nmg-size", [](const std::string&) { return g_dynblockNMG.getLocal()->size(); }},
    {"security-status", &securityStatus},
    // Latency histogram
    {"latency-sum", &latencySum},
    {"latency-count", getLatencyCount},
  };
};

// Metric types for Prometheus
enum class PrometheusMetricType: int {
    counter = 1,
    gauge = 2
};

// Keeps additional information about metrics
struct MetricDefinition {
  MetricDefinition(PrometheusMetricType _prometheusType, const std::string& _description): description(_description), prometheusType(_prometheusType) {
  }
 
  MetricDefinition() = default;

  // Metric description
  std::string description;
  // Metric type for Prometheus
  PrometheusMetricType prometheusType;
};

struct MetricDefinitionStorage {
  // Return metric definition by name
  bool getMetricDetails(std::string metricName, MetricDefinition& metric) {
  auto metricDetailsIter = metrics.find(metricName);

  if (metricDetailsIter == metrics.end()) {
    return false;
  }

  metric = metricDetailsIter->second;
    return true;
  };

  // Return string representation of Prometheus metric type
  std::string getPrometheusStringMetricType(PrometheusMetricType metricType) {
    switch (metricType) { 
      case PrometheusMetricType::counter:
        return "counter";
        break;
      case PrometheusMetricType::gauge:
        return "gauge";
        break;
      default:
        return "";
        break;
    }
  };

  std::map<std::string, MetricDefinition> metrics = {
    { "responses",              MetricDefinition(PrometheusMetricType::counter, "Number of responses received from backends") },
    { "servfail-responses",     MetricDefinition(PrometheusMetricType::counter, "Number of SERVFAIL answers received from backends") },
    { "queries",                MetricDefinition(PrometheusMetricType::counter, "Number of received queries")},
    { "frontend-nxdomain",      MetricDefinition(PrometheusMetricType::counter, "Number of NXDomain answers sent to clients")},
    { "frontend-servfail",      MetricDefinition(PrometheusMetricType::counter, "Number of SERVFAIL answers sent to clients")},
    { "frontend-noerror",       MetricDefinition(PrometheusMetricType::counter, "Number of NoError answers sent to clients")},
    { "acl-drops",              MetricDefinition(PrometheusMetricType::counter, "Number of packets dropped because of the ACL")},
    { "rule-drop",              MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped because of a rule")},
    { "rule-nxdomain",          MetricDefinition(PrometheusMetricType::counter, "Number of NXDomain answers returned because of a rule")},
    { "rule-refused",           MetricDefinition(PrometheusMetricType::counter, "Number of Refused answers returned because of a rule")},
    { "rule-servfail",          MetricDefinition(PrometheusMetricType::counter, "Number of SERVFAIL answers received because of a rule")},
    { "self-answered",          MetricDefinition(PrometheusMetricType::counter, "Number of self-answered responses")},
    { "downstream-timeouts",    MetricDefinition(PrometheusMetricType::counter, "Number of queries not answered in time by a backend")},
    { "downstream-send-errors", MetricDefinition(PrometheusMetricType::counter, "Number of errors when sending a query to a backend")},
    { "trunc-failures",         MetricDefinition(PrometheusMetricType::counter, "Number of errors encountered while truncating an answer")},
    { "no-policy",              MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped because no server was available")},
    { "latency0-1",             MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in less than 1ms")},
    { "latency1-10",            MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in 1-10 ms")},
    { "latency10-50",           MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in 10-50 ms")},
    { "latency50-100",          MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in 50-100 ms")},
    { "latency100-1000",        MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in 100-1000 ms")},
    { "latency-slow",           MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in more than 1 second")},
    { "latency-avg100",         MetricDefinition(PrometheusMetricType::gauge,   "Average response latency in microseconds of the last 100 packets")},
    { "latency-avg1000",        MetricDefinition(PrometheusMetricType::gauge,   "Average response latency in microseconds of the last 1000 packets")},
    { "latency-avg10000",       MetricDefinition(PrometheusMetricType::gauge,   "Average response latency in microseconds of the last 10000 packets")},
    { "latency-avg1000000",     MetricDefinition(PrometheusMetricType::gauge,   "Average response latency in microseconds of the last 1000000 packets")},
    { "uptime",                 MetricDefinition(PrometheusMetricType::gauge,   "Uptime of the dnsdist process in seconds")},
    { "real-memory-usage",      MetricDefinition(PrometheusMetricType::gauge,   "Current memory usage in bytes")},
    { "noncompliant-queries",   MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped as non-compliant")},
    { "noncompliant-responses", MetricDefinition(PrometheusMetricType::counter, "Number of answers from a backend dropped as non-compliant")},
    { "rdqueries",              MetricDefinition(PrometheusMetricType::counter, "Number of received queries with the recursion desired bit set")},
    { "empty-queries",          MetricDefinition(PrometheusMetricType::counter, "Number of empty queries received from clients")},
    { "cache-hits",             MetricDefinition(PrometheusMetricType::counter, "Number of times an answer was retrieved from cache")},
    { "cache-misses",           MetricDefinition(PrometheusMetricType::counter, "Number of times an answer not found in the cache")},
    { "cpu-user-msec",          MetricDefinition(PrometheusMetricType::counter, "Milliseconds spent by dnsdist in the user state")},
    { "cpu-sys-msec",           MetricDefinition(PrometheusMetricType::counter, "Milliseconds spent by dnsdist in the system state")},
    { "fd-usage",               MetricDefinition(PrometheusMetricType::gauge,   "Number of currently used file descriptors")},
    { "dyn-blocked",            MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped because of a dynamic block")},
    { "dyn-block-nmg-size",     MetricDefinition(PrometheusMetricType::gauge,   "Number of dynamic blocks entries") },
    { "security-status",        MetricDefinition(PrometheusMetricType::gauge,   "Security status of this software. 0=unknown, 1=OK, 2=upgrade recommended, 3=upgrade mandatory") },
  };
};

extern MetricDefinitionStorage g_metricDefinitions;
extern struct DNSDistStats g_stats;
void doLatencyStats(double udiff);


struct StopWatch
{
  StopWatch(bool realTime=false): d_needRealTime(realTime)
  {
  }
  struct timespec d_start{0,0};
  bool d_needRealTime{false};

  void start() {
    if(gettime(&d_start, d_needRealTime) < 0)
      unixDie("Getting timestamp");

  }

  void set(const struct timespec& from) {
    d_start = from;
  }

  double udiff() const {
    struct timespec now;
    if(gettime(&now, d_needRealTime) < 0)
      unixDie("Getting timestamp");

    return 1000000.0*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec)/1000.0;
  }

  double udiffAndSet() {
    struct timespec now;
    if(gettime(&now, d_needRealTime) < 0)
      unixDie("Getting timestamp");

    auto ret= 1000000.0*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec)/1000.0;
    d_start = now;
    return ret;
  }

};

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

  bool check(unsigned int rate, unsigned int burst) const // this is not quite fair
  {
    auto delta = d_prev.udiffAndSet();

    if(delta > 0.0) // time, frequently, does go backwards..
      d_tokens += 1.0 * rate * (delta/1000000.0);

    if(d_tokens > burst) {
      d_tokens = burst;
    }

    bool ret=false;
    if(d_tokens >= 1.0) { // we need this because burst=1 is weird otherwise
      ret=true;
      --d_tokens;
    }

    return ret;
  }

  bool seenSince(const struct timespec& cutOff) const
  {
    return cutOff < d_prev.d_start;
  }

protected:
  mutable StopWatch d_prev;
  mutable double d_tokens;
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

  int getPassed() const
  {
    return d_passed;
  }

  int getBlocked() const
  {
    return d_blocked;
  }

  bool check() const // this is not quite fair
  {
    if (d_passthrough) {
      return true;
    }

    bool ret = BasicQPSLimiter::check(d_rate, d_burst);
    if (ret) {
      d_passed++;
    }
    else {
      d_blocked++;
    }

    return ret;
  }
private:
  mutable unsigned int d_passed{0};
  mutable unsigned int d_blocked{0};
  unsigned int d_rate;
  unsigned int d_burst;
  bool d_passthrough{true};
};

struct ClientState;

struct IDState
{
  IDState(): sentTime(true), delayMsec(0), tempFailureTTL(boost::none) { origDest.sin4.sin_family = 0;}
  IDState(const IDState& orig): origRemote(orig.origRemote), origDest(orig.origDest), age(orig.age)
  {
    usageIndicator.store(orig.usageIndicator.load());
    origFD = orig.origFD;
    origID = orig.origID;
    delayMsec = orig.delayMsec;
    tempFailureTTL = orig.tempFailureTTL;
  }

  static const int64_t unusedIndicator = -1;

  static bool isInUse(int64_t usageIndicator)
  {
    return usageIndicator != unusedIndicator;
  }

  bool isInUse() const
  {
    return usageIndicator != unusedIndicator;
  }

  /* return true if the value has been successfully replaced meaning that
     no-one updated the usage indicator in the meantime */
  bool tryMarkUnused(int64_t expectedUsageIndicator)
  {
    return usageIndicator.compare_exchange_strong(expectedUsageIndicator, unusedIndicator);
  }

  /* mark as unused no matter what, return true if the state was in use before */
  bool markAsUsed()
  {
    auto currentGeneration = generation++;
    return markAsUsed(currentGeneration);
  }

  /* mark as unused no matter what, return true if the state was in use before */
  bool markAsUsed(int64_t currentGeneration)
  {
    int64_t oldUsage = usageIndicator.exchange(currentGeneration);
    return oldUsage != unusedIndicator;
  }

  /* We use this value to detect whether this state is in use.
     For performance reasons we don't want to use a lock here, but that means
     we need to be very careful when modifying this value. Modifications happen
     from:
     - one of the UDP or DoH 'client' threads receiving a query, selecting a backend
       then picking one of the states associated to this backend (via the idOffset).
       Most of the time this state should not be in use and usageIndicator is -1, but we
       might not yet have received a response for the query previously associated to this
       state, meaning that we will 'reuse' this state and erase the existing state.
       If we ever receive a response for this state, it will be discarded. This is
       mostly fine for UDP except that we still need to be careful in order to miss
       the 'outstanding' counters, which should only be increased when we are picking
       an empty state, and not when reusing ;
       For DoH, though, we have dynamically allocated a DOHUnit object that needs to
       be freed, as well as internal objects internals to libh2o.
     - one of the UDP receiver threads receiving a response from a backend, picking
       the corresponding state and sending the response to the client ;
     - the 'healthcheck' thread scanning the states to actively discover timeouts,
       mostly to keep some counters like the 'outstanding' one sane.
     We previously based that logic on the origFD (FD on which the query was received,
     and therefore from where the response should be sent) but this suffered from an
     ABA problem since it was quite likely that a UDP 'client thread' would reset it to the
     same value since we only have so much incoming sockets:
     - 1/ 'client' thread gets a query and set origFD to its FD, say 5 ;
     - 2/ 'receiver' thread gets a response, read the value of origFD to 5, check that the qname,
       qtype and qclass match
     - 3/ during that time the 'client' thread reuses the state, setting again origFD to 5 ;
     - 4/ the 'receiver' thread uses compare_exchange_strong() to only replace the value if it's still
       5, except it's not the same 5 anymore and it overrides a fresh state.
     We now use a 32-bit unsigned counter instead, which is incremented every time the state is set,
     wrapping around if necessary, and we set an atomic signed 64-bit value, so that we still have -1
     when the state is unused and the value of our counter otherwise.
  */
  std::atomic<int64_t> usageIndicator{unusedIndicator};  // set to unusedIndicator to indicate this state is empty   // 8
  std::atomic<uint32_t> generation{0}; // increased every time a state is used, to be able to detect an ABA issue    // 4
  ComboAddress origRemote;                                    // 28
  ComboAddress origDest;                                      // 28
  StopWatch sentTime;                                         // 16
  DNSName qname;                                              // 80
  std::shared_ptr<DNSCryptQuery> dnsCryptQuery{nullptr};
#ifdef HAVE_PROTOBUF
  boost::optional<boost::uuids::uuid> uniqueId;
#endif
  boost::optional<Netmask> subnet{boost::none};
  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr};
  std::shared_ptr<QTag> qTag{nullptr};
  const ClientState* cs{nullptr};
  DOHUnit* du{nullptr};
  uint32_t cacheKey;                                          // 4
  uint32_t cacheKeyNoECS;                                     // 4
  uint16_t age;                                               // 4
  uint16_t qtype;                                             // 2
  uint16_t qclass;                                            // 2
  uint16_t origID;                                            // 2
  uint16_t origFlags;                                         // 2
  int origFD{-1};
  int delayMsec;
  boost::optional<uint32_t> tempFailureTTL;
  bool ednsAdded{false};
  bool ecsAdded{false};
  bool skipCache{false};
  bool destHarvested{false}; // if true, origDest holds the original dest addr, otherwise the listening addr
  bool dnssecOK{false};
  bool useZeroScope;
};

typedef std::unordered_map<string, unsigned int> QueryCountRecords;
typedef std::function<std::tuple<bool, string>(const DNSQuestion* dq)> QueryCountFilter;
struct QueryCount {
  QueryCount()
  {
    pthread_rwlock_init(&queryLock, nullptr);
  }
  QueryCountRecords records;
  QueryCountFilter filter;
  pthread_rwlock_t queryLock;
  bool enabled{false};
};

extern QueryCount g_qcount;

struct ClientState
{
  ClientState(const ComboAddress& local_, bool isTCP, bool doReusePort, int fastOpenQueue, const std::string& itfName, const std::set<int>& cpus_): cpus(cpus_), local(local_), interface(itfName), fastOpenQueueSize(fastOpenQueue), tcp(isTCP), reuseport(doReusePort)
  {
  }

  std::set<int> cpus;
  ComboAddress local;
  std::shared_ptr<DNSCryptContext> dnscryptCtx{nullptr};
  std::shared_ptr<TLSFrontend> tlsFrontend{nullptr};
  std::shared_ptr<DOHFrontend> dohFrontend{nullptr};
  std::string interface;
  std::atomic<uint64_t> queries{0};
  mutable std::atomic<uint64_t> responses{0};
  std::atomic<uint64_t> tcpDiedReadingQuery{0};
  std::atomic<uint64_t> tcpDiedSendingResponse{0};
  std::atomic<uint64_t> tcpGaveUp{0};
  std::atomic<uint64_t> tcpClientTimeouts{0};
  std::atomic<uint64_t> tcpDownstreamTimeouts{0};
  std::atomic<uint64_t> tcpCurrentConnections{0};
  std::atomic<uint64_t> tlsNewSessions{0}; // A new TLS session has been negotiated, no resumption
  std::atomic<uint64_t> tlsResumptions{0}; // A TLS session has been resumed, either via session id or via a TLS ticket
  std::atomic<uint64_t> tlsUnknownTicketKey{0}; // A TLS ticket has been presented but we don't have the associated key (might have expired)
  std::atomic<uint64_t> tlsInactiveTicketKey{0}; // A TLS ticket has been successfully resumed but the key is no longer active, we should issue a new one
  std::atomic<uint64_t> tls10queries{0};   // valid DNS queries received via TLSv1.0
  std::atomic<uint64_t> tls11queries{0};   // valid DNS queries received via TLSv1.1
  std::atomic<uint64_t> tls12queries{0};   // valid DNS queries received via TLSv1.2
  std::atomic<uint64_t> tls13queries{0};   // valid DNS queries received via TLSv1.3
  std::atomic<uint64_t> tlsUnknownqueries{0};   // valid DNS queries received via unknown TLS version
  std::atomic<double> tcpAvgQueriesPerConnection{0.0};
  /* in ms */
  std::atomic<double> tcpAvgConnectionDuration{0.0};
  int udpFD{-1};
  int tcpFD{-1};
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

  bool hasTLS() const
  {
    return tlsFrontend != nullptr || dohFrontend != nullptr;
  }

  std::string getType() const
  {
    std::string result = udpFD != -1 ? "UDP" : "TCP";

    if (dohFrontend) {
      result += " (DNS over HTTPS)";
    }
    else if (tlsFrontend) {
      result += " (DNS over TLS)";
    }
    else if (dnscryptCtx) {
      result += " (DNSCrypt)";
    }

    return result;
  }

#ifdef HAVE_EBPF
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
#endif /* HAVE_EBPF */

  void updateTCPMetrics(size_t nbQueries, uint64_t durationMs)
  {
    tcpAvgQueriesPerConnection = (99.0 * tcpAvgQueriesPerConnection / 100.0) + (nbQueries / 100.0);
    tcpAvgConnectionDuration = (99.0 * tcpAvgConnectionDuration / 100.0) + (durationMs / 100.0);
  }
};

class TCPClientCollection {
  std::vector<int> d_tcpclientthreads;
  std::atomic<uint64_t> d_numthreads{0};
  std::atomic<uint64_t> d_pos{0};
  std::atomic<uint64_t> d_queued{0};
  const uint64_t d_maxthreads{0};
  std::mutex d_mutex;
  int d_singlePipe[2];
  const bool d_useSinglePipe;
public:

  TCPClientCollection(size_t maxThreads, bool useSinglePipe=false): d_maxthreads(maxThreads), d_singlePipe{-1,-1}, d_useSinglePipe(useSinglePipe)

  {
    d_tcpclientthreads.reserve(maxThreads);

    if (d_useSinglePipe) {
      if (pipe(d_singlePipe) < 0) {
        int err = errno;
        throw std::runtime_error("Error creating the TCP single communication pipe: " + stringerror(err));
      }

      if (!setNonBlocking(d_singlePipe[0])) {
        int err = errno;
        close(d_singlePipe[0]);
        close(d_singlePipe[1]);
        throw std::runtime_error("Error setting the TCP single communication pipe non-blocking: " + stringerror(err));
      }

      if (!setNonBlocking(d_singlePipe[1])) {
        int err = errno;
        close(d_singlePipe[0]);
        close(d_singlePipe[1]);
        throw std::runtime_error("Error setting the TCP single communication pipe non-blocking: " + stringerror(err));
      }
    }
  }
  int getThread()
  {
    uint64_t pos = d_pos++;
    ++d_queued;
    return d_tcpclientthreads[pos % d_numthreads];
  }
  bool hasReachedMaxThreads() const
  {
    return d_numthreads >= d_maxthreads;
  }
  uint64_t getThreadsCount() const
  {
    return d_numthreads;
  }
  uint64_t getQueuedCount() const
  {
    return d_queued;
  }
  void decrementQueuedCount()
  {
    --d_queued;
  }
  void addTCPClientThread();
};

extern std::unique_ptr<TCPClientCollection> g_tcpclientthreads;

struct DownstreamState
{
   typedef std::function<std::tuple<DNSName, uint16_t, uint16_t>(const DNSName&, uint16_t, uint16_t, dnsheader*)> checkfunc_t;

  DownstreamState(const ComboAddress& remote_, const ComboAddress& sourceAddr_, unsigned int sourceItf, const std::string& sourceItfName, size_t numberOfSockets);
  DownstreamState(const ComboAddress& remote_): DownstreamState(remote_, ComboAddress(), 0, std::string(), 1) {}
  ~DownstreamState()
  {
    for (auto& fd : sockets) {
      if (fd >= 0) {
        close(fd);
        fd = -1;
      }
    }
  }
  boost::uuids::uuid id;
  std::set<unsigned int> hashes;
  mutable pthread_rwlock_t d_lock;
  std::vector<int> sockets;
  const std::string sourceItfName;
  std::mutex socketsLock;
  std::mutex connectLock;
  std::unique_ptr<FDMultiplexer> mplexer{nullptr};
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
  std::atomic<uint64_t> sendErrors{0};
  std::atomic<uint64_t> outstanding{0};
  std::atomic<uint64_t> reuseds{0};
  std::atomic<uint64_t> queries{0};
  std::atomic<uint64_t> responses{0};
  struct {
    std::atomic<uint64_t> sendErrors{0};
    std::atomic<uint64_t> reuseds{0};
    std::atomic<uint64_t> queries{0};
  } prev;
  std::atomic<uint64_t> tcpDiedSendingQuery{0};
  std::atomic<uint64_t> tcpDiedReadingResponse{0};
  std::atomic<uint64_t> tcpGaveUp{0};
  std::atomic<uint64_t> tcpReadTimeouts{0};
  std::atomic<uint64_t> tcpWriteTimeouts{0};
  std::atomic<uint64_t> tcpCurrentConnections{0};
  std::atomic<double> tcpAvgQueriesPerConnection{0.0};
  /* in ms */
  std::atomic<double> tcpAvgConnectionDuration{0.0};
  string name;
  size_t socketsOffset{0};
  double queryLoad{0.0};
  double dropRate{0.0};
  double latencyUsec{0.0};
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
  enum class Availability { Up, Down, Auto} availability{Availability::Auto};
  bool mustResolve{false};
  bool upStatus{false};
  bool useECS{false};
  bool setCD{false};
  bool disableZeroScope{false};
  std::atomic<bool> connected{false};
  std::atomic_flag threadStarted;
  bool tcpFastOpen{false};
  bool ipBindAddrNoPort{true};

  bool isUp() const
  {
    if(availability == Availability::Down)
      return false;
    if(availability == Availability::Up)
      return true;
    return upStatus;
  }
  void setUp() { availability = Availability::Up; }
  void setDown() { availability = Availability::Down; }
  void setAuto() { availability = Availability::Auto; }
  string getName() const {
    if (name.empty()) {
      return remote.toStringWithPort();
    }
    return name;
  }
  string getNameWithAddr() const {
    if (name.empty()) {
      return remote.toStringWithPort();
    }
    return name + " (" + remote.toStringWithPort()+ ")";
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

  void updateTCPMetrics(size_t nbQueries, uint64_t durationMs)
  {
    tcpAvgQueriesPerConnection = (99.0 * tcpAvgQueriesPerConnection / 100.0) + (nbQueries / 100.0);
    tcpAvgConnectionDuration = (99.0 * tcpAvgConnectionDuration / 100.0) + (durationMs / 100.0);
  }
};
using servers_t =vector<std::shared_ptr<DownstreamState>>;

template <class T> using NumberedVector = std::vector<std::pair<unsigned int, T> >;

void responderThread(std::shared_ptr<DownstreamState> state);
extern std::mutex g_luamutex;
extern LuaContext g_lua;
extern std::string g_outputBuffer; // locking for this is ok, as locked by g_luamutex

class DNSRule
{
public:
  virtual ~DNSRule ()
  {
  }
  virtual bool matches(const DNSQuestion* dq) const =0;
  virtual string toString() const = 0;
  mutable std::atomic<uint64_t> d_matches{0};
};

using NumberedServerVector = NumberedVector<shared_ptr<DownstreamState>>;
typedef std::function<shared_ptr<DownstreamState>(const NumberedServerVector& servers, const DNSQuestion*)> policyfunc_t;

struct ServerPolicy
{
  string name;
  policyfunc_t policy;
  bool isLua;
  std::string toString() const {
    return string("ServerPolicy") + (isLua ? " (Lua)" : "") + " \"" + name + "\"";
  }
};

struct ServerPool
{
  ServerPool()
  {
    pthread_rwlock_init(&d_lock, nullptr);
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

  size_t countServers(bool upOnly)
  {
    size_t count = 0;
    ReadLock rl(&d_lock);
    for (const auto& server : d_servers) {
      if (!upOnly || std::get<1>(server)->isUp() ) {
        count++;
      }
    }
    return count;
  }

  NumberedVector<shared_ptr<DownstreamState>> getServers()
  {
    NumberedVector<shared_ptr<DownstreamState>> result;
    {
      ReadLock rl(&d_lock);
      result = d_servers;
    }
    return result;
  }

  void addServer(shared_ptr<DownstreamState>& server)
  {
    WriteLock wl(&d_lock);
    unsigned int count = (unsigned int) d_servers.size();
    d_servers.push_back(make_pair(++count, server));
    /* we need to reorder based on the server 'order' */
    std::stable_sort(d_servers.begin(), d_servers.end(), [](const std::pair<unsigned int,std::shared_ptr<DownstreamState> >& a, const std::pair<unsigned int,std::shared_ptr<DownstreamState> >& b) {
      return a.second->order < b.second->order;
    });
    /* and now we need to renumber for Lua (custom policies) */
    size_t idx = 1;
    for (auto& serv : d_servers) {
      serv.first = idx++;
    }
  }

  void removeServer(shared_ptr<DownstreamState>& server)
  {
    WriteLock wl(&d_lock);
    size_t idx = 1;
    bool found = false;
    for (auto it = d_servers.begin(); it != d_servers.end();) {
      if (found) {
        /* we need to renumber the servers placed
           after the removed one, for Lua (custom policies) */
        it->first = idx++;
        it++;
      }
      else if (it->second == server) {
        it = d_servers.erase(it);
        found = true;
      } else {
        idx++;
        it++;
      }
    }
  }

private:
  NumberedVector<shared_ptr<DownstreamState>> d_servers;
  pthread_rwlock_t d_lock;
  bool d_useECS{false};
};
using pools_t=map<std::string,std::shared_ptr<ServerPool>>;
void setPoolPolicy(pools_t& pools, const string& poolName, std::shared_ptr<ServerPolicy> policy);
void addServerToPool(pools_t& pools, const string& poolName, std::shared_ptr<DownstreamState> server);
void removeServerFromPool(pools_t& pools, const string& poolName, std::shared_ptr<DownstreamState> server);

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
  boost::uuids::uuid d_id;
  uint64_t d_creationOrder;
};

struct DNSDistResponseRuleAction
{
  std::shared_ptr<DNSRule> d_rule;
  std::shared_ptr<DNSResponseAction> d_action;
  boost::uuids::uuid d_id;
  uint64_t d_creationOrder;
};

extern GlobalStateHolder<SuffixMatchTree<DynBlock>> g_dynblockSMT;
extern DNSAction::Action g_dynBlockAction;

extern GlobalStateHolder<vector<CarbonConfig> > g_carbon;
extern GlobalStateHolder<ServerPolicy> g_policy;
extern GlobalStateHolder<servers_t> g_dstates;
extern GlobalStateHolder<pools_t> g_pools;
extern GlobalStateHolder<vector<DNSDistRuleAction> > g_rulactions;
extern GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_resprulactions;
extern GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_cachehitresprulactions;
extern GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_selfansweredresprulactions;
extern GlobalStateHolder<NetmaskGroup> g_ACL;

extern ComboAddress g_serverControl; // not changed during runtime

extern std::vector<std::tuple<ComboAddress, bool, bool, int, std::string, std::set<int>>> g_locals; // not changed at runtime (we hope XXX)
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
extern uint64_t g_maxTCPClientThreads;
extern uint64_t g_maxTCPQueuedConnections;
extern size_t g_maxTCPQueriesPerConn;
extern size_t g_maxTCPConnectionDuration;
extern size_t g_maxTCPConnectionsPerClient;
extern std::atomic<uint16_t> g_cacheCleaningDelay;
extern std::atomic<uint16_t> g_cacheCleaningPercentage;
extern bool g_verboseHealthChecks;
extern uint32_t g_staleCacheEntriesTTL;
extern bool g_apiReadWrite;
extern std::string g_apiConfigDirectory;
extern bool g_servFailOnNoPolicy;
extern uint32_t g_hashperturb;
extern bool g_useTCPSinglePipe;
extern uint16_t g_downstreamTCPCleanupInterval;
extern size_t g_udpVectorSize;
extern bool g_preserveTrailingData;
extern bool g_allowEmptyResponse;
extern bool g_roundrobinFailOnNoServer;

#ifdef HAVE_EBPF
extern shared_ptr<BPFFilter> g_defaultBPFFilter;
extern std::vector<std::shared_ptr<DynBPFFilter> > g_dynBPFFilters;
#endif /* HAVE_EBPF */

struct LocalHolders
{
  LocalHolders(): acl(g_ACL.getLocal()), policy(g_policy.getLocal()), rulactions(g_rulactions.getLocal()), cacheHitRespRulactions(g_cachehitresprulactions.getLocal()), selfAnsweredRespRulactions(g_selfansweredresprulactions.getLocal()), servers(g_dstates.getLocal()), dynNMGBlock(g_dynblockNMG.getLocal()), dynSMTBlock(g_dynblockSMT.getLocal()), pools(g_pools.getLocal())
  {
  }

  LocalStateHolder<NetmaskGroup> acl;
  LocalStateHolder<ServerPolicy> policy;
  LocalStateHolder<vector<DNSDistRuleAction> > rulactions;
  LocalStateHolder<vector<DNSDistResponseRuleAction> > cacheHitRespRulactions;
  LocalStateHolder<vector<DNSDistResponseRuleAction> > selfAnsweredRespRulactions;
  LocalStateHolder<servers_t> servers;
  LocalStateHolder<NetmaskTree<DynBlock> > dynNMGBlock;
  LocalStateHolder<SuffixMatchTree<DynBlock> > dynSMTBlock;
  LocalStateHolder<pools_t> pools;
};

struct dnsheader;

void controlThread(int fd, ComboAddress local);
vector<std::function<void(void)>> setupLua(bool client, const std::string& config);
std::shared_ptr<ServerPool> getPool(const pools_t& pools, const std::string& poolName);
std::shared_ptr<ServerPool> createPoolIfNotExists(pools_t& pools, const string& poolName);
NumberedServerVector getDownstreamCandidates(const pools_t& pools, const std::string& poolName);

std::shared_ptr<DownstreamState> firstAvailable(const NumberedServerVector& servers, const DNSQuestion* dq);

std::shared_ptr<DownstreamState> leastOutstanding(const NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> wrandom(const NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> whashed(const NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> chashed(const NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> roundrobin(const NumberedServerVector& servers, const DNSQuestion* dq);

struct WebserverConfig
{
  std::string password;
  std::string apiKey;
  boost::optional<std::map<std::string, std::string> > customHeaders;
  std::mutex lock;
};

void setWebserverAPIKey(const boost::optional<std::string> apiKey);
void setWebserverPassword(const std::string& password);
void setWebserverCustomHeaders(const boost::optional<std::map<std::string, std::string> > customHeaders);

void dnsdistWebserverThread(int sock, const ComboAddress& local);
void tcpAcceptorThread(void* p);
#ifdef HAVE_DNS_OVER_HTTPS
void dohThread(ClientState* cs);
#endif /* HAVE_DNS_OVER_HTTPS */

void setLuaNoSideEffect(); // if nothing has been declared, set that there are no side effects
void setLuaSideEffect();   // set to report a side effect, cancelling all _no_ side effect calls
bool getLuaNoSideEffect(); // set if there were only explicit declarations of _no_ side effect
void resetLuaSideEffect(); // reset to indeterminate state

bool responseContentMatches(const char* response, const uint16_t responseLen, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& remote, unsigned int& consumed);
bool processResponse(char** response, uint16_t* responseLen, size_t* responseSize, LocalStateHolder<vector<DNSDistResponseRuleAction> >& localRespRulactions, DNSResponse& dr, size_t addRoom, std::vector<uint8_t>& rewrittenResponse, bool muted);
bool processRulesResult(const DNSAction::Action& action, DNSQuestion& dq, std::string& ruleresult, bool& drop);

bool checkQueryHeaders(const struct dnsheader* dh);

extern std::vector<std::shared_ptr<DNSCryptContext>> g_dnsCryptLocals;
int handleDNSCryptQuery(char* packet, uint16_t len, std::shared_ptr<DNSCryptQuery> query, uint16_t* decryptedQueryLen, bool tcp, time_t now, std::vector<uint8_t>& response);
boost::optional<std::vector<uint8_t>> checkDNSCryptQuery(const ClientState& cs, const char* query, uint16_t& len, std::shared_ptr<DNSCryptQuery>& dnsCryptQuery, time_t now, bool tcp);

bool addXPF(DNSQuestion& dq, uint16_t optionCode);

uint16_t getRandomDNSID();

#include "dnsdist-snmp.hh"

extern bool g_snmpEnabled;
extern bool g_snmpTrapsEnabled;
extern DNSDistSNMPAgent* g_snmpAgent;
extern bool g_addEDNSToSelfGeneratedResponses;

extern std::set<std::string> g_capabilitiesToRetain;
static const uint16_t s_udpIncomingBufferSize{1500}; // don't accept UDP queries larger than this value
static const size_t s_maxPacketCacheEntrySize{4096}; // don't cache responses larger than this value

enum class ProcessQueryResult { Drop, SendAnswer, PassToBackend };
ProcessQueryResult processQuery(DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend);

DNSResponse makeDNSResponseFromIDState(IDState& ids, struct dnsheader* dh, size_t bufferSize, uint16_t responseLen, bool isTCP);
void setIDStateFromDNSQuestion(IDState& ids, DNSQuestion& dq, DNSName&& qname);

int pickBackendSocketForSending(std::shared_ptr<DownstreamState>& state);
ssize_t udpClientSendRequestToBackend(const std::shared_ptr<DownstreamState>& ss, const int sd, const char* request, const size_t requestLen, bool healthCheck=false);
