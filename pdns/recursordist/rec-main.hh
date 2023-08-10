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

#ifdef NOD_ENABLED
#include "nod.hh"
#endif /* NOD_ENABLED */

#ifdef HAVE_BOOST_CONTAINER_FLAT_SET_HPP
#include <boost/container/flat_set.hpp>
#endif

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

  // get a string repesentation of the client address, including proxy info if applicable
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

  ComboAddress d_remote; // the address the query is coming from
  ComboAddress d_source; // the address we assume the query is coming from, might be set by proxy protocol
  ComboAddress d_local; // the address we received the query on
  ComboAddress d_destination; // the address we assume the query is sent to, might be set by proxy protocol
  ComboAddress d_mappedSource; // the source address after being mapped by table based proxy mapping
  RecEventTrace d_eventTrace;
  boost::uuids::uuid d_uuid;
  string d_requestorId;
  string d_deviceId;
  string d_deviceName;
  struct timeval d_kernelTimestamp
  {
    0, 0
  };
  std::string d_query;
  std::unordered_set<std::string> d_policyTags;
  const std::unordered_set<std::string> d_gettagPolicyTags;
  std::string d_routingTag;
  std::vector<DNSRecord> d_records;

  // d_data is tied to this LuaContext so we need to keep it alive and use it, not a newer one, as long as d_data exists
  shared_ptr<RecursorLua4> d_luaContext;
  LuaContext::LuaObject d_data;

  EDNSSubnetOpts d_ednssubnet;
  shared_ptr<TCPConnection> d_tcpConnection;
  boost::optional<uint16_t> d_extendedErrorCode{boost::none};
  string d_extendedErrorExtra;
  boost::optional<int> d_rcode{boost::none};
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

  LWResult::Result getSocket(const ComboAddress& toaddr, int* fileDesc);

  // return a socket to the pool, or simply erase it
  void returnSocket(int fileDesc);

private:
  // returns -1 for errors which might go away, throws for ones that won't
  static int makeClientSocket(int family);
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
extern unsigned int g_maxTCPPerClient;
extern int g_tcpTimeout;
extern uint16_t g_udpTruncationThreshold;
extern double g_balancingFactor;
extern size_t g_maxUDPQueriesPerRound;
extern bool g_useKernelTimestamp;
extern thread_local std::shared_ptr<NetmaskGroup> t_allowFrom;
extern thread_local std::shared_ptr<NetmaskGroup> t_allowNotifyFrom;
extern thread_local std::shared_ptr<notifyset_t> t_allowNotifyFor;
extern thread_local std::unique_ptr<UDPClientSocks> t_udpclientsocks;
extern bool g_useIncomingECS;
extern boost::optional<ComboAddress> g_dns64Prefix;
extern DNSName g_dns64PrefixReverse;
extern uint64_t g_latencyStatSize;
extern NetmaskGroup g_proxyProtocolACL;
extern std::atomic<bool> g_statsWanted;
extern uint32_t g_disthashseed;
extern int g_argc;
extern char** g_argv;
extern std::shared_ptr<SyncRes::domainmap_t> g_initialDomainMap; // new threads needs this to be setup
extern std::shared_ptr<NetmaskGroup> g_initialAllowFrom; // new thread needs to be setup with this
extern std::shared_ptr<NetmaskGroup> g_initialAllowNotifyFrom; // new threads need this to be setup
extern std::shared_ptr<notifyset_t> g_initialAllowNotifyFor; // new threads need this to be setup
extern thread_local std::shared_ptr<Regex> t_traceRegex;
extern thread_local FDWrapper t_tracefd;
extern string g_programname;
extern string g_pidfname;
extern RecursorControlChannel g_rcc; // only active in the handler thread

extern thread_local std::unique_ptr<ProxyMapping> t_proxyMapping;
using ProxyMappingStats_t = std::unordered_map<Netmask, ProxyMappingCounts>;

#ifdef NOD_ENABLED
extern bool g_nodEnabled;
extern DNSName g_nodLookupDomain;
extern bool g_nodLog;
extern SuffixMatchNode g_nodDomainWL;
extern std::string g_nod_pbtag;
extern bool g_udrEnabled;
extern bool g_udrLog;
extern std::string g_udr_pbtag;
extern thread_local std::shared_ptr<nod::NODDB> t_nodDBp;
extern thread_local std::shared_ptr<nod::UniqueResponseDB> t_udrDBp;
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

#ifdef HAVE_BOOST_CONTAINER_FLAT_SET_HPP
extern boost::container::flat_set<uint16_t> g_avoidUdpSourcePorts;
#else
extern std::set<uint16_t> g_avoidUdpSourcePorts;
#endif

/* without reuseport, all listeners share the same sockets */
typedef vector<pair<int, std::function<void(int, boost::any&)>>> deferredAdd_t;
extern deferredAdd_t g_deferredAdds;

typedef map<ComboAddress, uint32_t, ComboAddress::addressOnlyLessThan> tcpClientCounts_t;
extern thread_local std::unique_ptr<tcpClientCounts_t> t_tcpClientCounts;

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
// First we have the handler thread, t_id == 0 (some other helper
// threads like SNMP might have t_id == 0 as well) then the
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
    return s_threadInfos.at(t_id);
  }

  static RecThreadInfo& info(unsigned int i)
  {
    return s_threadInfos.at(i);
  }

  static vector<RecThreadInfo>& infos()
  {
    return s_threadInfos;
  }

  bool isDistributor() const
  {
    if (t_id == 0) {
      return false;
    }
    return s_weDistributeQueries && listener;
  }

  bool isHandler() const
  {
    if (t_id == 0) {
      return true;
    }
    return handler;
  }

  bool isWorker() const
  {
    return worker;
  }

  bool isListener() const
  {
    return listener;
  }

  bool isTaskThread() const
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

  void setTaskThread()
  {
    taskThread = true;
  }

  static unsigned int id()
  {
    return t_id;
  }

  static void setThreadId(unsigned int id)
  {
    t_id = id;
  }

  std::string getName() const
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

  static unsigned int numWorkers()
  {
    return s_numWorkerThreads;
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

  static void setNumWorkerThreads(unsigned int n)
  {
    s_numWorkerThreads = n;
  }

  static void setNumDistributorThreads(unsigned int n)
  {
    s_numDistributorThreads = n;
  }

  static unsigned int numRecursorThreads()
  {
    return numHandlers() + numDistributors() + numWorkers() + numTaskThreads();
  }

  static int runThreads(Logr::log_t);
  static void makeThreadPipes(Logr::log_t);

  void setExitCode(int e)
  {
    exitCode = e;
  }

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

private:
  void start(unsigned int id, const string& name, const std::map<unsigned int, std::set<int>>& cpusMap, Logr::log_t);

  std::string name;
  std::thread thread;
  int exitCode{0};

  // handle the web server, carbon, statistics and the control channel
  bool handler{false};
  // accept incoming queries (and distributes them to the workers if pdns-distributes-queries is set)
  bool listener{false};
  // process queries
  bool worker{false};
  // run async tasks: from TaskQueue and ZoneToCache
  bool taskThread{false};

  static thread_local unsigned int t_id;
  static std::vector<RecThreadInfo> s_threadInfos;
  static bool s_weDistributeQueries; // if true, 1 or more threads listen on the incoming query sockets and distribute them to workers
  static unsigned int s_numDistributorThreads;
  static unsigned int s_numWorkerThreads;
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
                       bool& foundECS, EDNSSubnetOpts* ednssubnet, EDNSOptionViewMap* options);
void protobufLogQuery(LocalStateHolder<LuaConfigItems>& luaconfsLocal, const boost::uuids::uuid& uniqueId, const ComboAddress& remote, const ComboAddress& local, const ComboAddress& mappedSource, const Netmask& ednssubnet, bool tcp, uint16_t queryID, size_t len, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::unordered_set<std::string>& policyTags, const std::string& requestorId, const std::string& deviceId, const std::string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta);
bool isAllowNotifyForZone(DNSName qname);
bool checkForCacheHit(bool qnameParsed, unsigned int tag, const string& data,
                      DNSName& qname, uint16_t& qtype, uint16_t& qclass,
                      const struct timeval& now,
                      string& response, uint32_t& qhash,
                      RecursorPacketCache::OptPBData& pbData, bool tcp, const ComboAddress& source, const ComboAddress& mappedSource);
void protobufLogResponse(pdns::ProtoZero::RecMessage& message);
void protobufLogResponse(const struct dnsheader* header, LocalStateHolder<LuaConfigItems>& luaconfsLocal,
                         const RecursorPacketCache::OptPBData& pbData, const struct timeval& tv,
                         bool tcp, const ComboAddress& source, const ComboAddress& destination,
                         const ComboAddress& mappedSource, const EDNSSubnetOpts& ednssubnet,
                         const boost::uuids::uuid& uniqueId, const string& requestorId, const string& deviceId,
                         const string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta,
                         const RecEventTrace& eventTrace,
                         const std::unordered_set<std::string>& policyTags);
void requestWipeCaches(const DNSName& canon);
void startDoResolve(void*);
bool expectProxyProtocol(const ComboAddress& from);
void finishTCPReply(std::unique_ptr<DNSComboWriter>&, bool hadError, bool updateInFlight);
void checkFastOpenSysctl(bool active, Logr::log_t);
void checkTFOconnect(Logr::log_t);
void makeTCPServerSockets(deferredAdd_t& deferredAdds, std::set<int>& tcpSockets, Logr::log_t);
void handleNewTCPQuestion(int fileDesc, FDMultiplexer::funcparam_t&);

void makeUDPServerSockets(deferredAdd_t& deferredAdds, Logr::log_t);
string doTraceRegex(FDWrapper file, vector<string>::const_iterator begin, vector<string>::const_iterator end);

#define LOCAL_NETS "127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10"
#define LOCAL_NETS_INVERSE "!127.0.0.0/8, !10.0.0.0/8, !100.64.0.0/10, !169.254.0.0/16, !192.168.0.0/16, !172.16.0.0/12, !::1/128, !fc00::/7, !fe80::/10"
// Bad Nets taken from both:
// http://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
// and
// http://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
// where such a network may not be considered a valid destination
#define BAD_NETS "0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, ::/96, ::ffff:0:0/96, 100::/64, 2001:db8::/32"
#define DONT_QUERY LOCAL_NETS ", " BAD_NETS
