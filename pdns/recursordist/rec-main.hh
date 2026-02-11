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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "logger.hh"
#include "logr.hh"
#include "lua-recursor4.hh"
#include "mplexer.hh"
#include "namespaces.hh"
#include "rec-lua-conf.hh"
#include "rec-protozero.hh"
#include "syncres.hh"
#include "rec-snmp.hh"
#include "rec_channel.hh"
#include "threadname.hh"
#include "recpacketcache.hh"
#include "ratelimitedlog.hh"
#include "protozero-trace.hh"
#include "remote_logger.hh"

#ifdef NOD_ENABLED
#include "nod.hh"
#endif /* NOD_ENABLED */

extern std::shared_ptr<Logr::Logger> g_slogtcpin;
extern std::shared_ptr<Logr::Logger> g_slogudpin;

//! used to send information to a newborn mthread
struct DNSComboWriter
{
  DNSComboWriter(const std::string& query, const struct timeval& now, shared_ptr<RecursorLua4> luaContext) :
    d_mdp(true, query), d_now(now), d_query(query), d_luaContext(std::move(luaContext))
  {
  }

  DNSComboWriter(const std::string& query, const struct timeval& now, std::unordered_set<std::string>&& policyTags, shared_ptr<RecursorLua4> luaContext, LuaContext::LuaObject&& data, std::vector<DNSRecord>&& records) :
    d_mdp(true, query), d_now(now), d_query(query), d_policyTags(std::move(policyTags)), d_gettagPolicyTags(d_policyTags), d_records(std::move(records)), d_luaContext(std::move(luaContext)), d_data(std::move(data))
  {
  }

  // The address the query is coming from
  void setRemote(const ComboAddress& sa)
  {
    d_remote = sa;
  }

  // The address we assume the query is coming from, might be set by proxy protocol
  void setSource(const ComboAddress& sa)
  {
    d_source = sa;
  }

  void setMappedSource(const ComboAddress& sa)
  {
    d_mappedSource = sa;
  }

  void setLocal(const ComboAddress& sa)
  {
    d_local = sa;
  }

  // The address we assume the query is sent to, might be set by proxy protocol
  void setDestination(const ComboAddress& sa)
  {
    d_destination = sa;
  }

  void setSocket(int sock)
  {
    d_socket = sock;
  }

  // get a string representation of the client address, including proxy info if applicable
  string getRemote() const
  {
    if (d_source == d_remote) {
      return d_source.toStringWithPort();
    }
    return d_source.toStringWithPort() + " (proxied by " + d_remote.toStringWithPort() + ")";
  }

  std::vector<ProxyProtocolValue> d_proxyProtocolValues;
  MOADNSParser d_mdp;
  struct timeval d_now;

  ComboAddress d_remote; // the address from which the query is coming
  ComboAddress d_source; // the address we assume the query is coming from, might be set by proxy protocol
  ComboAddress d_local; // the address we received the query on
  ComboAddress d_destination; // the address we assume the query is sent to, might be set by proxy protocol
  ComboAddress d_mappedSource; // the source address after being mapped by table based proxy mapping
  RecEventTrace d_eventTrace;
  pdns::trace::InitialSpanInfo d_otTrace;
  boost::uuids::uuid d_uuid;
  string d_requestorId;
  string d_deviceId;
  string d_deviceName;
  struct timeval d_kernelTimestamp{
    0, 0};
  std::string d_query;
  std::unordered_set<std::string> d_policyTags;
  std::unordered_set<std::string> d_gettagPolicyTags;
  std::string d_routingTag;
  std::vector<DNSRecord> d_records;

  // d_data is tied to this LuaContext so we need to keep it alive and use it, not a newer one, as long as d_data exists
  shared_ptr<RecursorLua4> d_luaContext;
  LuaContext::LuaObject d_data;

  EDNSSubnetOpts d_ednssubnet;
  shared_ptr<TCPConnection> d_tcpConnection;
  std::optional<uint16_t> d_extendedErrorCode{std::nullopt};
  string d_extendedErrorExtra;
  std::optional<int> d_rcode{std::nullopt};
  int d_socket{-1};
  unsigned int d_tag{0};
  uint32_t d_qhash{0};
  uint32_t d_ttlCap{std::numeric_limits<uint32_t>::max()};
  bool d_variable{false};
  bool d_ecsFound{false};
  bool d_ecsParsed{false};
  bool d_followCNAMERecords{false};
  bool d_logResponse{false};
  bool d_tcp{false};
  bool d_responsePaddingDisabled{false};
  std::map<std::string, RecursorLua4::MetaValue> d_meta;
};

extern thread_local unique_ptr<FDMultiplexer> t_fdm;
extern uint16_t g_minUdpSourcePort;
extern uint16_t g_maxUdpSourcePort;
extern bool g_regressionTestMode;
struct DoneRunning
{
  std::mutex mutex;
  std::condition_variable condVar;
  std::atomic<bool> done{false};
};
extern DoneRunning g_doneRunning;

// you can ask this class for a UDP socket to send a query from
// this socket is not yours, don't even think about deleting it
// but after you call 'returnSocket' on it, don't assume anything anymore
class UDPClientSocks
{
  unsigned int d_numsocks;

public:
  UDPClientSocks() :
    d_numsocks(0)
  {
  }

  LWResult::Result getSocket(const ComboAddress& toaddr, const std::optional<ComboAddress>& localAddress, int* fileDesc);

  // return a socket to the pool, or simply erase it
  void returnSocket(int fileDesc);

private:
  // returns -1 for errors which might go away, throws for ones that won't
  static int makeClientSocket(int family, const std::optional<ComboAddress>& localAddress);
};

enum class PaddingMode
{
  Always,
  PaddedQueries
};

typedef MTasker<std::shared_ptr<PacketID>, PacketBuffer, PacketIDCompare> MT_t;
extern thread_local std::unique_ptr<MT_t> g_multiTasker; // the big MTasker
extern std::unique_ptr<RecursorPacketCache> g_packetCache;

using RemoteLoggerStats_t = std::unordered_map<std::string, RemoteLoggerInterface::Stats>;

extern bool g_yamlSettings;
extern string g_yamlSettingsSuffix;
extern LockGuarded<pdns::rust::settings::rec::Recursorsettings> g_yamlStruct;
extern bool g_logCommonErrors;
extern size_t g_proxyProtocolMaximumSize;
extern std::atomic<bool> g_quiet;
extern thread_local std::shared_ptr<RecursorLua4> t_pdl;
extern bool g_gettagNeedsEDNSOptions;
extern NetmaskGroup g_paddingFrom;
extern unsigned int g_paddingTag;
extern PaddingMode g_paddingMode;
extern unsigned int g_maxMThreads;
extern bool g_reusePort;
extern bool g_anyToTcp;
extern size_t g_tcpMaxQueriesPerConn;
extern unsigned int g_maxTCPClients;
extern unsigned int g_maxTCPPerClient;
extern int g_tcpTimeout;
extern uint16_t g_udpTruncationThreshold;
extern double g_balancingFactor;
extern size_t g_maxUDPQueriesPerRound;
extern bool g_useKernelTimestamp;
extern bool g_allowNoRD;
extern unsigned int g_maxChainLength;
extern thread_local std::shared_ptr<NetmaskGroup> t_allowFrom;
extern thread_local std::shared_ptr<NetmaskGroup> t_allowNotifyFrom;
extern thread_local std::shared_ptr<notifyset_t> t_allowNotifyFor;
extern thread_local std::unique_ptr<UDPClientSocks> t_udpclientsocks;
extern thread_local std::shared_ptr<NetmaskGroup> t_proxyProtocolACL;
extern thread_local std::shared_ptr<std::set<ComboAddress>> t_proxyProtocolExceptions;
extern bool g_useIncomingECS;
extern std::optional<ComboAddress> g_dns64Prefix;
extern DNSName g_dns64PrefixReverse;
extern uint64_t g_latencyStatSize;
extern std::atomic<bool> g_statsWanted;
extern uint32_t g_disthashseed;
extern int g_argc;
extern char** g_argv;
extern LockGuarded<std::shared_ptr<SyncRes::domainmap_t>> g_initialDomainMap; // new threads needs this to be setup
extern LockGuarded<std::shared_ptr<NetmaskGroup>> g_initialAllowFrom; // new thread needs to be setup with this
extern LockGuarded<std::shared_ptr<NetmaskGroup>> g_initialAllowNotifyFrom; // new threads need this to be setup
extern LockGuarded<std::shared_ptr<notifyset_t>> g_initialAllowNotifyFor; // new threads need this to be setup
extern LockGuarded<std::shared_ptr<OpenTelemetryTraceConditions>> g_initialOpenTelemetryConditions; // new threads need this to be set
extern thread_local std::shared_ptr<Regex> t_traceRegex;
extern thread_local FDWrapper t_tracefd;
extern string g_programname;
extern string g_pidfname;
extern RecursorControlChannel g_rcc; // only active in the handler thread

extern thread_local std::unique_ptr<ProxyMapping> t_proxyMapping;
using ProxyMappingStats_t = std::unordered_map<Netmask, ProxyMappingCounts>;
extern thread_local std::unique_ptr<OpenTelemetryTraceConditions> t_OTConditions;
extern pdns::RateLimitedLog g_rateLimitedLogger;

#ifdef NOD_ENABLED
extern bool g_nodEnabled;
extern DNSName g_nodLookupDomain;
extern bool g_nodLog;
extern SuffixMatchNode g_nodDomainWL;
extern SuffixMatchNode g_udrDomainWL;
extern std::string g_nod_pbtag;
extern bool g_udrEnabled;
extern bool g_udrLog;
extern std::string g_udr_pbtag;
extern std::unique_ptr<nod::NODDB> g_nodDBp;
extern std::unique_ptr<nod::UniqueResponseDB> g_udrDBp;
#endif

struct ProtobufServersInfo
{
  std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>> servers;
  uint64_t generation;
  ProtobufExportConfig config;
};
extern thread_local ProtobufServersInfo t_protobufServers;
extern thread_local ProtobufServersInfo t_outgoingProtobufServers;

#ifdef HAVE_FSTRM
struct FrameStreamServersInfo
{
  std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>> servers;
  uint64_t generation;
  FrameStreamExportConfig config;
};

extern thread_local FrameStreamServersInfo t_frameStreamServersInfo;
extern thread_local FrameStreamServersInfo t_nodFrameStreamServersInfo;
#endif /* HAVE_FSTRM */

extern std::vector<bool> g_avoidUdpSourcePorts;

/* without reuseport, all listeners share the same sockets */
typedef vector<pair<int, std::function<void(int, boost::any&)>>> deferredAdd_t;

inline MT_t* getMT()
{
  return g_multiTasker ? g_multiTasker.get() : nullptr;
}

/* this function is called with both a string and a vector<uint8_t> representing a packet */
template <class T>
static bool sendResponseOverTCP(const std::unique_ptr<DNSComboWriter>& dc, const T& packet)
{
  uint8_t buf[2];
  buf[0] = packet.size() / 256;
  buf[1] = packet.size() % 256;

  Utility::iovec iov[2];
  iov[0].iov_base = (void*)buf;
  iov[0].iov_len = 2;
  iov[1].iov_base = (void*)&*packet.begin();
  iov[1].iov_len = packet.size();

  int wret = Utility::writev(dc->d_socket, iov, 2);
  bool hadError = true;

  if (wret == 0) {
    g_log << Logger::Warning << "EOF writing TCP answer to " << dc->getRemote() << endl;
  }
  else if (wret < 0) {
    int err = errno;
    g_log << Logger::Warning << "Error writing TCP answer to " << dc->getRemote() << ": " << strerror(err) << endl;
  }
  else if ((unsigned int)wret != 2 + packet.size()) {
    g_log << Logger::Warning << "Oops, partial answer sent to " << dc->getRemote() << " for " << dc->d_mdp.d_qname << " (size=" << (2 + packet.size()) << ", sent " << wret << ")" << endl;
  }
  else {
    hadError = false;
  }

  return hadError;
}

// For communicating with our threads effectively readonly after
// startup.
// First we have the handler thread, t_id == 0  then the
// distributor threads if any and finally the workers
struct RecThreadInfo
{
  struct ThreadPipeSet
  {
    int writeToThread{-1};
    int readToThread{-1};
    int writeFromThread{-1};
    int readFromThread{-1};
    int writeQueriesToThread{-1}; // this one is non-blocking
    int readQueriesToThread{-1};
  };

public:
  static RecThreadInfo& self()
  {
    auto& info = s_threadInfos.at(t_id);
    assert(info.d_myid == t_id); // internal consistency check
    return info;
  }

  static RecThreadInfo& info(unsigned int index)
  {
    auto& info = s_threadInfos.at(index);
    assert(info.d_myid == index);
    return info;
  }

  static vector<RecThreadInfo>& infos()
  {
    return s_threadInfos;
  }

  [[nodiscard]] bool isDistributor() const
  {
    return s_weDistributeQueries && listener;
  }

  [[nodiscard]] bool isHandler() const
  {
    return handler;
  }

  [[nodiscard]] bool isWorker() const
  {
    return worker;
  }

  // UDP or TCP listener?
  [[nodiscard]] bool isListener() const
  {
    return listener;
  }

  // A TCP-only listener?
  [[nodiscard]] bool isTCPListener() const
  {
    return tcplistener;
  }

  [[nodiscard]] bool isTaskThread() const
  {
    return taskThread;
  }

  void setHandler()
  {
    handler = true;
  }

  void setWorker()
  {
    worker = true;
  }

  void setListener(bool flag = true)
  {
    listener = flag;
  }

  void setTCPListener(bool flag = true)
  {
    setListener(flag);
    tcplistener = flag;
  }

  void setTaskThread()
  {
    taskThread = true;
  }

  static unsigned int thread_local_id()
  {
    if (t_id == TID_NOT_INITED) {
      return 0; // backward compatibility
    }
    return t_id;
  }

  static bool is_thread_inited()
  {
    return t_id != TID_NOT_INITED;
  }

  [[nodiscard]] unsigned int id() const
  {
    return d_myid;
  }

  static void setThreadId(unsigned int arg)
  {
    t_id = arg;
  }

  [[nodiscard]] std::string getName() const
  {
    return name;
  }

  static unsigned int numHandlers()
  {
    return 1;
  }

  static unsigned int numTaskThreads()
  {
    return 1;
  }

  static unsigned int numUDPWorkers()
  {
    return s_numUDPWorkerThreads;
  }

  static unsigned int numTCPWorkers()
  {
    return s_numTCPWorkerThreads;
  }

  static unsigned int numDistributors()
  {
    return s_numDistributorThreads;
  }

  static bool weDistributeQueries()
  {
    return s_weDistributeQueries;
  }

  static void setWeDistributeQueries(bool flag)
  {
    s_weDistributeQueries = flag;
  }

  static void setNumUDPWorkerThreads(unsigned int n)
  {
    s_numUDPWorkerThreads = n;
  }

  static void setNumTCPWorkerThreads(unsigned int n)
  {
    s_numTCPWorkerThreads = n;
  }

  static void setNumDistributorThreads(unsigned int n)
  {
    s_numDistributorThreads = n;
  }

  static unsigned int numRecursorThreads()
  {
    return numHandlers() + numDistributors() + numUDPWorkers() + numTCPWorkers() + numTaskThreads();
  }

  static int runThreads(Logr::log_t);
  static void makeThreadPipes(Logr::log_t);

  void setExitCode(int n)
  {
    exitCode = n;
  }

  std::set<int>& getTCPSockets()
  {
    return tcpSockets;
  }

  void setTCPSockets(std::set<int>& socks)
  {
    tcpSockets = socks;
  }

  deferredAdd_t& getDeferredAdds()
  {
    return deferredAdds;
  }

  const ThreadPipeSet& getPipes() const
  {
    return pipes;
  }

  [[nodiscard]] uint64_t getNumberOfDistributedQueries() const
  {
    return numberOfDistributedQueries;
  }

  void incNumberOfDistributedQueries()
  {
    numberOfDistributedQueries++;
  }

  MT_t* getMT()
  {
    return mt;
  }

  void setMT(MT_t* theMT)
  {
    mt = theMT;
  }

  static void joinThread0()
  {
    if (!s_threadInfos.empty()) {
      info(0).thread.join();
    }
  }

  static void resize(size_t size)
  {
    s_threadInfos.resize(size);
    for (unsigned int i = 0; i < size; i++) {
      s_threadInfos.at(i).d_myid = i;
    }
  }
  static constexpr unsigned int TID_NOT_INITED = std::numeric_limits<unsigned int>::max();

private:
  // FD corresponding to TCP sockets this thread is listening on.
  // These FDs are also in deferredAdds when we have one socket per
  // listener, and in g_deferredAdds instead.
  std::set<int> tcpSockets;
  // FD corresponding to listening sockets if we have one socket per
  // listener (with reuseport), otherwise all listeners share the
  // same FD and g_deferredAdds is then used instead
  deferredAdd_t deferredAdds;

  struct ThreadPipeSet pipes;
  MT_t* mt{nullptr};
  uint64_t numberOfDistributedQueries{0};

  void start(unsigned int tid, const string& tname, const std::map<unsigned int, std::set<int>>& cpusMap, Logr::log_t);

  std::string name;
  std::thread thread;
  int exitCode{0};
  unsigned int d_myid{TID_NOT_INITED}; // should always be equal to the thread_local tid;

  // handle the web server, carbon, statistics and the control channel
  bool handler{false};
  // accept incoming queries (and distributes them to the workers if pdns-distributes-queries is set)
  bool listener{false};
  // accept incoming TCP queries (and distributes them to the workers if pdns-distributes-queries is set)
  bool tcplistener{false};
  // process queries
  bool worker{false};
  // run async tasks: from TaskQueue and ZoneToCache
  bool taskThread{false};

  static thread_local unsigned int t_id;
  static std::vector<RecThreadInfo> s_threadInfos;
  static bool s_weDistributeQueries; // if true, 1 or more threads listen on the incoming query sockets and distribute them to workers
  static unsigned int s_numDistributorThreads;
  static unsigned int s_numUDPWorkerThreads;
  static unsigned int s_numTCPWorkerThreads;
};

struct ThreadMSG
{
  pipefunc_t func;
  bool wantAnswer;
};

void parseACLs();
PacketBuffer GenUDPQueryResponse(const ComboAddress& dest, const string& query);
bool checkProtobufExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal);
bool checkOutgoingProtobufExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal);
#ifdef HAVE_FSTRM
bool checkFrameStreamExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal, const FrameStreamExportConfig& config, FrameStreamServersInfo& serverInfos);
#endif
void getQNameAndSubnet(const std::string& question, DNSName* dnsname, uint16_t* qtype, uint16_t* qclass,
                       bool& foundECS, EDNSSubnetOpts* ednssubnet, EDNSOptionViewMap* options, std::optional<uint32_t>& ednsVersion);
void protobufLogQuery(LocalStateHolder<LuaConfigItems>& luaconfsLocal, const boost::uuids::uuid& uniqueId, const ComboAddress& remote, const ComboAddress& local, const ComboAddress& mappedSource, const Netmask& ednssubnet, bool tcp, size_t len, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::unordered_set<std::string>& policyTags, const std::string& requestorId, const std::string& deviceId, const std::string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta, const std::optional<uint32_t>& ednsVersion, const dnsheader& header, const pdns::trace::TraceID& traceID);
bool isAllowNotifyForZone(DNSName qname);
bool checkForCacheHit(bool qnameParsed, unsigned int tag, const string& data,
                      DNSName& qname, uint16_t& qtype, uint16_t& qclass,
                      const struct timeval& now,
                      string& response, uint32_t& qhash,
                      RecursorPacketCache::OptPBData& pbData, bool tcp, const ComboAddress& source, const ComboAddress& mappedSource);
void protobufLogResponse(pdns::ProtoZero::RecMessage& message);
void protobufLogResponse(const DNSName& qname, QType qtype, const struct dnsheader* header, LocalStateHolder<LuaConfigItems>& luaconfsLocal,
                         const RecursorPacketCache::OptPBData& pbData, const struct timeval& tv,
                         bool tcp, const ComboAddress& source, const ComboAddress& destination,
                         const ComboAddress& mappedSource, const EDNSSubnetOpts& ednssubnet,
                         const boost::uuids::uuid& uniqueId, const string& requestorId, const string& deviceId,
                         const string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta,
                         const RecEventTrace& eventTrace,
                         pdns::trace::InitialSpanInfo& otTrace,
                         const std::unordered_set<std::string>& policyTags);
void requestWipeCaches(const DNSName& canon);
void startDoResolve(void*);
bool expectProxyProtocol(const ComboAddress& from, const ComboAddress& listenAddress);
bool matchOTConditions(const std::unique_ptr<OpenTelemetryTraceConditions>& conditions, const ComboAddress& source);
bool matchOTConditions(RecEventTrace& eventTrace, const std::unique_ptr<OpenTelemetryTraceConditions>& conditions, const ComboAddress& source, const DNSName& qname, QType qtype, uint16_t qid, bool edns_option_present);
void finishTCPReply(std::unique_ptr<DNSComboWriter>&, bool hadError, bool updateInFlight);
void checkFastOpenSysctl(bool active, Logr::log_t);
void checkTFOconnect(Logr::log_t);
unsigned int makeTCPServerSockets(deferredAdd_t& deferredAdds, std::set<int>& tcpSockets, Logr::log_t, bool doLog, unsigned int instances);
void handleNewTCPQuestion(int fileDesc, FDMultiplexer::funcparam_t&);

unsigned int makeUDPServerSockets(deferredAdd_t& deferredAdds, Logr::log_t, bool doLog, unsigned int instances);
string doTraceRegex(FDWrapper file, vector<string>::const_iterator begin, vector<string>::const_iterator end);
extern bool g_luaSettingsInYAML;
void startLuaConfigDelayedThreads(const LuaConfigItems& luaConfig, uint64_t generation);
void activateLuaConfig(LuaConfigItems& lci);
unsigned int authWaitTimeMSec(const std::unique_ptr<MT_t>& mtasker);

#define LOCAL_NETS "127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10"
#define LOCAL_NETS_INVERSE "!127.0.0.0/8, !10.0.0.0/8, !100.64.0.0/10, !169.254.0.0/16, !192.168.0.0/16, !172.16.0.0/12, !::1/128, !fc00::/7, !fe80::/10"
// Bad Nets taken from both:
// http://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
// and
// http://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
// where such a network may not be considered a valid destination
#define BAD_NETS "0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, ::/96, ::ffff:0:0/96, 100::/64, 2001:db8::/32"
#define DONT_QUERY LOCAL_NETS ", " BAD_NETS
