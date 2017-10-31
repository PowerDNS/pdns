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
#include <time.h>
#include "misc.hh"
#include "iputils.hh"
#include "dnsname.hh"
#include <atomic>
#include <boost/circular_buffer.hpp>
#include <boost/variant.hpp>
#include <mutex>
#include <thread>
#include <unistd.h>
#include "sholder.hh"
#include "dnscrypt.hh"
#include "dnsdist-cache.hh"
#include "gettime.hh"
#include "dnsdist-dynbpf.hh"
#include "bpf-filter.hh"
#include <string>
#include <unordered_map>


#ifdef HAVE_PROTOBUF
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#endif

void* carbonDumpThread();
uint64_t uptimeOfProcess(const std::string& str);

extern uint16_t g_ECSSourcePrefixV4;
extern uint16_t g_ECSSourcePrefixV6;
extern bool g_ECSOverride;

class QTag
{
public:
  QTag()
  {
  }

  ~QTag()
  {
  }

  void add(const std::string strLabel, const std::string strValue)
  {
    tagData.insert( {strLabel, strValue});
    return;
  }

  std::string getMatch(const std::string& strLabel)  const
  {
    std::unordered_map<std::string, std::string>::const_iterator got =tagData.find (strLabel);
    if(got == tagData.end()) {
      return "";
    } else {
      return got->second;
    }
  }

  std::string getEntry(size_t iEntry) const
  {
    std::string strEntry;
    size_t iCounter = 0;

    for (const auto& itr : tagData) {
      iCounter++;
      if(iCounter == iEntry) {
        strEntry = itr.first;
        strEntry += strSep;
        strEntry += itr.second;
        break;
      }
    }

    return strEntry;
  }

  size_t count() const
  {
    return tagData.size();
  }

  std::string dumpString() const
  {
    std::string strRet;

    for (const auto& itr : tagData) {
      strRet += itr.first;
      strRet += strSep;
      strRet += itr.second;
      strRet += "\n";
    }
    return strRet;
  }

  std::unordered_map<std::string, std::string>tagData;

private:
  static constexpr char const *strSep = "\t";
};

#ifdef HAVE_PROTOBUF
extern thread_local boost::uuids::random_generator t_uuidGenerator;
#endif

struct DNSQuestion
{
  DNSQuestion(const DNSName* name, uint16_t type, uint16_t class_, const ComboAddress* lc, const ComboAddress* rem, struct dnsheader* header, size_t bufferSize, uint16_t queryLen, bool isTcp): qname(name), qtype(type), qclass(class_), local(lc), remote(rem), dh(header), size(bufferSize), len(queryLen), ecsPrefixLength(rem->sin4.sin_family == AF_INET ? g_ECSSourcePrefixV4 : g_ECSSourcePrefixV6), tcp(isTcp), ecsOverride(g_ECSOverride) { }

#ifdef HAVE_PROTOBUF
  boost::optional<boost::uuids::uuid> uniqueId;
#endif
  const DNSName* qname;
  const uint16_t qtype;
  const uint16_t qclass;
  const ComboAddress* local;
  const ComboAddress* remote;
  std::shared_ptr<QTag> qTag;
  struct dnsheader* dh;
  size_t size;
  uint16_t len;
  uint16_t ecsPrefixLength;
  const bool tcp;
  bool skipCache{false};
  bool ecsOverride;
  bool useECS{true};
};

struct DNSResponse : DNSQuestion
{
  DNSResponse(const DNSName* name, uint16_t type, uint16_t class_, const ComboAddress* lc, const ComboAddress* rem, struct dnsheader* header, size_t bufferSize, uint16_t responseLen, bool isTcp, const struct timespec* queryTime_): DNSQuestion(name, type, class_, lc, rem, header, bufferSize, responseLen, isTcp), queryTime(queryTime_) { }

  const struct timespec* queryTime;
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
  enum class Action { Drop, Nxdomain, Refused, Spoof, Allow, HeaderModify, Pool, Delay, Truncate, None};
  virtual Action operator()(DNSQuestion*, string* ruleresult) const =0;
  virtual ~DNSAction()
  {
  }
  virtual string toString() const = 0;
  virtual std::unordered_map<string, double> getStats() const 
  {
    return {{}};
  }
};

class DNSResponseAction
{
public:
  enum class Action { Allow, Delay, Drop, HeaderModify, None };
  virtual Action operator()(DNSResponse*, string* ruleresult) const =0;
  virtual ~DNSResponseAction()
  {
  }
  virtual string toString() const = 0;
};

struct DynBlock
{
  DynBlock& operator=(const DynBlock& rhs)
  {
    reason=rhs.reason;
    until=rhs.until;
    domain=rhs.domain;
    action=rhs.action;
    blocks.store(rhs.blocks);
    return *this;
  }

  string reason;
  struct timespec until;
  DNSName domain;
  DNSAction::Action action;
  mutable std::atomic<unsigned int> blocks;
};

extern GlobalStateHolder<NetmaskTree<DynBlock>> g_dynblockNMG;

extern vector<pair<struct timeval, std::string> > g_confDelta;

struct DNSDistStats
{
  using stat_t=std::atomic<uint64_t>; // aww yiss ;-)
  stat_t responses{0};
  stat_t servfailResponses{0};
  stat_t queries{0};
  stat_t nonCompliantQueries{0};
  stat_t nonCompliantResponses{0};
  stat_t rdQueries{0};
  stat_t emptyQueries{0};
  stat_t aclDrops{0};
  stat_t dynBlocked{0};
  stat_t ruleDrop{0};
  stat_t ruleNXDomain{0};
  stat_t ruleRefused{0};
  stat_t selfAnswered{0};
  stat_t downstreamTimeouts{0};
  stat_t downstreamSendErrors{0};
  stat_t truncFail{0};
  stat_t noPolicy{0};
  stat_t cacheHits{0};
  stat_t cacheMisses{0};
  stat_t latency0_1{0}, latency1_10{0}, latency10_50{0}, latency50_100{0}, latency100_1000{0}, latencySlow{0};
  
  double latencyAvg100{0}, latencyAvg1000{0}, latencyAvg10000{0}, latencyAvg1000000{0};
  typedef std::function<uint64_t(const std::string&)> statfunction_t;
  typedef boost::variant<stat_t*, double*, statfunction_t> entry_t;
  std::vector<std::pair<std::string, entry_t>> entries{
    {"responses", &responses},
    {"servfail-responses", &servfailResponses},
    {"queries", &queries},
    {"acl-drops", &aclDrops},
    {"rule-drop", &ruleDrop},
    {"rule-nxdomain", &ruleNXDomain},
    {"rule-refused", &ruleRefused},
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
    {"dyn-block-nmg-size", [](const std::string&) { return g_dynblockNMG.getLocal()->size(); }}
  };
};


extern struct DNSDistStats g_stats;


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

class QPSLimiter
{
public:
  QPSLimiter()
  {
  }

  QPSLimiter(unsigned int rate, unsigned int burst) : d_rate(rate), d_burst(burst), d_tokens(burst)
  {
    d_passthrough=false;
    d_prev.start();
  }

  unsigned int getRate() const
  {
    return d_passthrough? 0 : d_rate;
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
    if(d_passthrough)
      return true;
    auto delta = d_prev.udiffAndSet();
  
    d_tokens += 1.0*d_rate * (delta/1000000.0);

    if(d_tokens > d_burst)
      d_tokens = d_burst;

    bool ret=false;
    if(d_tokens >= 1.0) { // we need this because burst=1 is weird otherwise
      ret=true;
      --d_tokens;
      d_passed++;
    }
    else
      d_blocked++;

    return ret; 
  }
private:
  bool d_passthrough{true};
  unsigned int d_rate;
  unsigned int d_burst;
  mutable double d_tokens;
  mutable StopWatch d_prev;
  mutable unsigned int d_passed{0};
  mutable unsigned int d_blocked{0};
};

struct ClientState;

struct IDState
{
  IDState() : origFD(-1), sentTime(true), delayMsec(0) { origDest.sin4.sin_family = 0;}
  IDState(const IDState& orig)
  {
    origFD = orig.origFD;
    origID = orig.origID;
    origRemote = orig.origRemote;
    origDest = orig.origDest;
    delayMsec = orig.delayMsec;
    age.store(orig.age.load());
  }

  int origFD;  // set to <0 to indicate this state is empty   // 4

  ComboAddress origRemote;                                    // 28
  ComboAddress origDest;                                      // 28
  StopWatch sentTime;                                         // 16
  DNSName qname;                                              // 80
#ifdef HAVE_DNSCRYPT
  std::shared_ptr<DnsCryptQuery> dnsCryptQuery{0};
#endif
#ifdef HAVE_PROTOBUF
  boost::optional<boost::uuids::uuid> uniqueId;
#endif
  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr};
  const ClientState* cs{nullptr};
  uint32_t cacheKey;                                          // 8
  std::atomic<uint16_t> age;                                  // 4
  uint16_t qtype;                                             // 2
  uint16_t qclass;                                            // 2
  uint16_t origID;                                            // 2
  uint16_t origFlags;                                         // 2
  int delayMsec;
  bool ednsAdded{false};
  bool ecsAdded{false};
  bool skipCache{false};
  bool destHarvested{false}; // if true, origDest holds the original dest addr, otherwise the listening addr
};

struct Rings {
  Rings(size_t capacity=10000)
  {
    queryRing.set_capacity(capacity);
    respRing.set_capacity(capacity);
    pthread_rwlock_init(&queryLock, 0);
  }
  struct Query
  {
    struct timespec when;
    ComboAddress requestor;
    DNSName name;
    uint16_t size;
    uint16_t qtype;
    struct dnsheader dh;
  };
  boost::circular_buffer<Query> queryRing;
  struct Response
  {
    struct timespec when;
    ComboAddress requestor;
    DNSName name;
    uint16_t qtype;
    unsigned int usec;
    unsigned int size;
    struct dnsheader dh;
    ComboAddress ds; // who handled it
  };
  boost::circular_buffer<Response> respRing;
  std::mutex respMutex;
  pthread_rwlock_t queryLock;

  std::unordered_map<int, vector<boost::variant<string,double> > > getTopBandwidth(unsigned int numentries);
  size_t numDistinctRequestors();
  void setCapacity(size_t newCapacity) 
  {
    {
      WriteLock wl(&queryLock);
      queryRing.set_capacity(newCapacity);
    }
    {
      std::lock_guard<std::mutex> lock(respMutex);
      respRing.set_capacity(newCapacity);
    }
  }
};

extern Rings g_rings;

typedef std::unordered_map<string, unsigned int> QueryCountRecords;
typedef std::function<std::tuple<bool, string>(DNSQuestion dq)> QueryCountFilter;
struct QueryCount {
  QueryCount()
  {
    pthread_rwlock_init(&queryLock, 0);
  }
  QueryCountRecords records;
  QueryCountFilter filter;
  pthread_rwlock_t queryLock;
  bool enabled{false};
};

extern QueryCount g_qcount;

struct ClientState
{
  std::set<int> cpus;
  ComboAddress local;
#ifdef HAVE_DNSCRYPT
  DnsCryptContext* dnscryptCtx{0};
#endif
  std::atomic<uint64_t> queries{0};
  int udpFD{-1};
  int tcpFD{-1};
  bool muted{false};

  int getSocket() const
  {
    return udpFD != -1 ? udpFD : tcpFD;
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
};

class TCPClientCollection {
  std::vector<int> d_tcpclientthreads;
  std::atomic<uint64_t> d_numthreads{0};
  std::atomic<uint64_t> d_pos{0};
  std::atomic<uint64_t> d_queued{0};
  uint64_t d_maxthreads{0};
  std::mutex d_mutex;
  int d_singlePipe[2];
  bool d_useSinglePipe;
public:

  TCPClientCollection(size_t maxThreads, bool useSinglePipe=false): d_maxthreads(maxThreads), d_singlePipe{-1,-1}, d_useSinglePipe(useSinglePipe)

  {
    d_tcpclientthreads.reserve(maxThreads);

    if (d_useSinglePipe) {
      if (pipe(d_singlePipe) < 0) {
        throw std::runtime_error("Error creating the TCP single communication pipe: " + string(strerror(errno)));
      }
      if (!setNonBlocking(d_singlePipe[1])) {
        int err = errno;
        close(d_singlePipe[0]);
        close(d_singlePipe[1]);
        throw std::runtime_error("Error setting the TCP single communication pipe non-blocking: " + string(strerror(err)));
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

extern std::shared_ptr<TCPClientCollection> g_tcpclientthreads;

struct DownstreamState
{
  DownstreamState(const ComboAddress& remote_, const ComboAddress& sourceAddr_, unsigned int sourceItf);
  DownstreamState(const ComboAddress& remote_): DownstreamState(remote_, ComboAddress(), 0) {}
  ~DownstreamState()
  {
    if (fd >= 0)
      close(fd);
  }

  int fd{-1};
  std::thread tid;
  ComboAddress remote;
  QPSLimiter qps;
  vector<IDState> idStates;
  ComboAddress sourceAddr;
  DNSName checkName{"a.root-servers.net."};
  QType checkType{QType::A};
  std::atomic<uint64_t> idOffset{0};
  std::atomic<uint64_t> sendErrors{0};
  std::atomic<uint64_t> outstanding{0};
  std::atomic<uint64_t> reuseds{0};
  std::atomic<uint64_t> queries{0};
  struct {
    std::atomic<uint64_t> sendErrors{0};
    std::atomic<uint64_t> reuseds{0};
    std::atomic<uint64_t> queries{0};
  } prev;
  string name;
  double queryLoad{0.0};
  double dropRate{0.0};
  double latencyUsec{0.0};
  int order{1};
  int weight{1};
  int tcpConnectTimeout{5};
  int tcpRecvTimeout{30};
  int tcpSendTimeout{30};
  unsigned int sourceItf{0};
  uint16_t retries{5};
  uint8_t currentCheckFailures{0};
  uint8_t maxCheckFailures{1};
  StopWatch sw;
  set<string> pools;
  enum class Availability { Up, Down, Auto} availability{Availability::Auto};
  bool mustResolve{false};
  bool upStatus{false};
  bool useECS{false};
  bool setCD{false};
  std::atomic<bool> connected{false};
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
  void reconnect();
};
using servers_t =vector<std::shared_ptr<DownstreamState>>;

template <class T> using NumberedVector = std::vector<std::pair<unsigned int, T> >;

void* responderThread(std::shared_ptr<DownstreamState> state);
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
};

struct ServerPool
{
  const std::shared_ptr<DNSDistPacketCache> getCache() const { return packetCache; };

  NumberedVector<shared_ptr<DownstreamState>> servers;
  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr};
  std::shared_ptr<ServerPolicy> policy{nullptr};
};
using pools_t=map<std::string,std::shared_ptr<ServerPool>>;
void setPoolPolicy(pools_t& pools, const string& poolName, std::shared_ptr<ServerPolicy> policy);
void addServerToPool(pools_t& pools, const string& poolName, std::shared_ptr<DownstreamState> server);
void removeServerFromPool(pools_t& pools, const string& poolName, std::shared_ptr<DownstreamState> server);

struct CarbonConfig
{
  ComboAddress server;
  std::string ourname;
  unsigned int interval;
};

enum ednsHeaderFlags {
  EDNS_HEADER_FLAG_NONE = 0,
  EDNS_HEADER_FLAG_DO = 32768
};

extern GlobalStateHolder<SuffixMatchTree<DynBlock>> g_dynblockSMT;
extern DNSAction::Action g_dynBlockAction;

extern GlobalStateHolder<vector<CarbonConfig> > g_carbon;
extern GlobalStateHolder<ServerPolicy> g_policy;
extern GlobalStateHolder<servers_t> g_dstates;
extern GlobalStateHolder<pools_t> g_pools;
extern GlobalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSAction> > > > g_rulactions;
extern GlobalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSResponseAction> > > > g_resprulactions;
extern GlobalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSResponseAction> > > > g_cachehitresprulactions;
extern GlobalStateHolder<NetmaskGroup> g_ACL;

extern ComboAddress g_serverControl; // not changed during runtime

extern std::vector<std::tuple<ComboAddress, bool, bool, int, std::string, std::set<int>>> g_locals; // not changed at runtime (we hope XXX)
extern vector<ClientState*> g_frontends;
extern std::string g_key; // in theory needs locking
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
extern std::atomic<uint16_t> g_downstreamTCPCleanupInterval;
extern size_t g_udpVectorSize;

struct ConsoleKeyword {
  std::string name;
  bool function;
  std::string parameters;
  std::string description;
  std::string toString() const
  {
    std::string res(name);
    if (function) {
      res += "(" + parameters + ")";
    }
    res += ": ";
    res += description;
    return res;
  }
};
extern const std::vector<ConsoleKeyword> g_consoleKeywords;
extern bool g_logConsoleConnections;

#ifdef HAVE_EBPF
extern shared_ptr<BPFFilter> g_defaultBPFFilter;
extern std::vector<std::shared_ptr<DynBPFFilter> > g_dynBPFFilters;
#endif /* HAVE_EBPF */

struct LocalHolders
{
  LocalHolders(): acl(g_ACL.getLocal()), policy(g_policy.getLocal()), rulactions(g_rulactions.getLocal()), cacheHitRespRulactions(g_cachehitresprulactions.getLocal()), servers(g_dstates.getLocal()), dynNMGBlock(g_dynblockNMG.getLocal()), dynSMTBlock(g_dynblockSMT.getLocal()), pools(g_pools.getLocal())
  {
  }

  LocalStateHolder<NetmaskGroup> acl;
  LocalStateHolder<ServerPolicy> policy;
  LocalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSAction> > > > rulactions;
  LocalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSResponseAction> > > > cacheHitRespRulactions;
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
const NumberedServerVector& getDownstreamCandidates(const pools_t& pools, const std::string& poolName);

std::shared_ptr<DownstreamState> firstAvailable(const NumberedServerVector& servers, const DNSQuestion* dq);

std::shared_ptr<DownstreamState> leastOutstanding(const NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> wrandom(const NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> whashed(const NumberedServerVector& servers, const DNSQuestion* dq);
std::shared_ptr<DownstreamState> roundrobin(const NumberedServerVector& servers, const DNSQuestion* dq);
int getEDNSZ(const char* packet, unsigned int len);
uint16_t getEDNSOptionCode(const char * packet, size_t len);
void dnsdistWebserverThread(int sock, const ComboAddress& local, const string& password, const string& apiKey, const boost::optional<std::map<std::string, std::string> >&);
bool getMsgLen32(int fd, uint32_t* len);
bool putMsgLen32(int fd, uint32_t len);
void* tcpAcceptorThread(void* p);

void moreLua(bool client);
void doClient(ComboAddress server, const std::string& command);
void doConsole();
void controlClientThread(int fd, ComboAddress client);
extern "C" {
char** my_completion( const char * text , int start,  int end);
}
void setLuaNoSideEffect(); // if nothing has been declared, set that there are no side effects
void setLuaSideEffect();   // set to report a side effect, cancelling all _no_ side effect calls
bool getLuaNoSideEffect(); // set if there were only explicit declarations of _no_ side effect
void resetLuaSideEffect(); // reset to indeterminate state

bool responseContentMatches(const char* response, const uint16_t responseLen, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& remote);
bool processQuery(LocalHolders& holders, DNSQuestion& dq, string& poolname, int* delayMsec, const struct timespec& now);
bool processResponse(LocalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSResponseAction> > > >& localRespRulactions, DNSResponse& dr, int* delayMsec);
bool fixUpResponse(char** response, uint16_t* responseLen, size_t* responseSize, const DNSName& qname, uint16_t origFlags, bool ednsAdded, bool ecsAdded, std::vector<uint8_t>& rewrittenResponse, uint16_t addRoom);
void restoreFlags(struct dnsheader* dh, uint16_t origFlags);
bool checkQueryHeaders(const struct dnsheader* dh);

#ifdef HAVE_DNSCRYPT
extern std::vector<std::tuple<ComboAddress,DnsCryptContext,bool,int, std::string, std::set<int>>> g_dnsCryptLocals;

int handleDnsCryptQuery(DnsCryptContext* ctx, char* packet, uint16_t len, std::shared_ptr<DnsCryptQuery>& query, uint16_t* decryptedQueryLen, bool tcp, std::vector<uint8_t>& response);
bool encryptResponse(char* response, uint16_t* responseLen, size_t responseSize, bool tcp, std::shared_ptr<DnsCryptQuery> dnsCryptQuery, dnsheader** dh, dnsheader* dhCopy);
#endif

#include "dnsdist-snmp.hh"

extern bool g_snmpEnabled;
extern bool g_snmpTrapsEnabled;
extern DNSDistSNMPAgent* g_snmpAgent;
