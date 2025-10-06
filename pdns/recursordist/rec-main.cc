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
#include <sys/stat.h>

#include "rec-main.hh"

#include "aggressive_nsec.hh"
#include "capabilities.hh"
#include "arguments.hh"
#include "dns_random.hh"
#include "rec_channel.hh"
#include "rec-tcpout.hh"
#include "version.hh"
#include "query-local-address.hh"
#include "validate-recursor.hh"
#include "pubsuffix.hh"
#include "opensslsigners.hh"
#include "ws-recursor.hh"
#include "rec-taskqueue.hh"
#include "secpoll-recursor.hh"
#include "logging.hh"
#include "dnsseckeeper.hh"
#include "rec-rust-lib/cxxsettings.hh"
#include "json.hh"
#include "rec-system-resolve.hh"
#include "root-dnssec.hh"
#include "ratelimitedlog.hh"
#include "rec-rust-lib/rust/web.rs.h"

#ifdef NOD_ENABLED
#include "nod.hh"
#endif /* NOD_ENABLED */

#ifdef HAVE_LIBSODIUM
#include <sodium.h>

#include <cstddef>
#include <utility>
#endif

#ifdef HAVE_SYSTEMD
// All calls are coming form the same function, so no use for CODE_LINE, CODE_FUNC etc
#define SD_JOURNAL_SUPPRESS_LOCATION
#include <systemd/sd-daemon.h>
#include <systemd/sd-journal.h>
#endif

#ifdef HAVE_FSTRM
thread_local FrameStreamServersInfo t_frameStreamServersInfo;
thread_local FrameStreamServersInfo t_nodFrameStreamServersInfo;
#endif /* HAVE_FSTRM */

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

string g_programname = "pdns_recursor";
string g_pidfname;
RecursorControlChannel g_rcc; // only active in the handler thread
bool g_regressionTestMode;
bool g_yamlSettings;
string g_yamlSettingsSuffix;
bool g_luaSettingsInYAML;

#ifdef NOD_ENABLED
bool g_nodEnabled;
DNSName g_nodLookupDomain;
bool g_nodLog;
SuffixMatchNode g_nodDomainWL;
SuffixMatchNode g_udrDomainWL;
std::string g_nod_pbtag;
bool g_udrEnabled;
bool g_udrLog;
std::string g_udr_pbtag;
std::unique_ptr<nod::NODDB> g_nodDBp;
std::unique_ptr<nod::UniqueResponseDB> g_udrDBp;
#endif /* NOD_ENABLED */

std::atomic<bool> statsWanted;
uint32_t g_disthashseed;
bool g_useIncomingECS;
static shared_ptr<NetmaskGroup> g_initialProxyProtocolACL;
static shared_ptr<std::set<ComboAddress>> g_initialProxyProtocolExceptions;
boost::optional<ComboAddress> g_dns64Prefix{boost::none};
DNSName g_dns64PrefixReverse;
unsigned int g_maxChainLength;
LockGuarded<std::shared_ptr<SyncRes::domainmap_t>> g_initialDomainMap; // new threads needs this to be setup
LockGuarded<std::shared_ptr<NetmaskGroup>> g_initialAllowFrom; // new thread needs to be setup with this
LockGuarded<std::shared_ptr<NetmaskGroup>> g_initialAllowNotifyFrom; // new threads need this to be setup
LockGuarded<std::shared_ptr<notifyset_t>> g_initialAllowNotifyFor; // new threads need this to be setup
bool g_logRPZChanges{false};
static time_t s_statisticsInterval;
static std::atomic<uint32_t> s_counter;
int g_argc;
char** g_argv;
static string s_structured_logger_backend;
static Logger::Urgency s_logUrgency;

std::shared_ptr<Logr::Logger> g_slogtcpin;
std::shared_ptr<Logr::Logger> g_slogudpin;
std::shared_ptr<Logr::Logger> g_slogudpout;

/* without reuseport, all listeners share the same sockets */
static deferredAdd_t s_deferredUDPadds;
static deferredAdd_t s_deferredTCPadds;

/* first we have the handler thread, t_id == 0 (threads not created as a RecursorThread have t_id = NOT_INITED)
   then the distributor threads if any
   and finally the workers */
std::vector<RecThreadInfo> RecThreadInfo::s_threadInfos;

std::unique_ptr<ProxyMapping> g_proxyMapping; // new threads needs this to be setup
thread_local std::unique_ptr<ProxyMapping> t_proxyMapping;

bool RecThreadInfo::s_weDistributeQueries; // if true, 1 or more threads listen on the incoming query sockets and distribute them to workers
unsigned int RecThreadInfo::s_numDistributorThreads;
unsigned int RecThreadInfo::s_numUDPWorkerThreads;
unsigned int RecThreadInfo::s_numTCPWorkerThreads;
thread_local unsigned int RecThreadInfo::t_id{RecThreadInfo::TID_NOT_INITED};

pdns::RateLimitedLog g_rateLimitedLogger;

static void runStartStopLua(bool start, Logr::log_t log);

static std::map<unsigned int, std::set<int>> parseCPUMap(Logr::log_t log)
{
  std::map<unsigned int, std::set<int>> result;

  const std::string value = ::arg()["cpu-map"];

  if (!value.empty() && !isSettingThreadCPUAffinitySupported()) {
    log->info(Logr::Warning, "CPU mapping requested but not supported, skipping");
    return result;
  }

  std::vector<std::string> parts;

  stringtok(parts, value, " \t");

  for (const auto& part : parts) {
    if (part.find('=') == string::npos) {
      continue;
    }

    try {
      auto headers = splitField(part, '=');
      boost::trim(headers.first);
      boost::trim(headers.second);

      auto threadId = pdns::checked_stoi<unsigned int>(headers.first);
      std::vector<std::string> cpus;

      stringtok(cpus, headers.second, ",");

      for (const auto& cpu : cpus) {
        int cpuId = std::stoi(cpu);

        result[threadId].insert(cpuId);
      }
    }
    catch (const std::exception& e) {
      log->error(Logr::Error, e.what(), "Error parsing cpu-map entry", "entry", Logging::Loggable(part));
    }
  }

  return result;
}

static void setCPUMap(const std::map<unsigned int, std::set<int>>& cpusMap, unsigned int n, pthread_t tid, Logr::log_t log)
{
  const auto& cpuMapping = cpusMap.find(n);
  if (cpuMapping == cpusMap.cend()) {
    return;
  }
  int ret = mapThreadToCPUList(tid, cpuMapping->second);
  if (ret == 0) {
    log->info(Logr::Info, "CPU affinity has been set", "thread", Logging::Loggable(n), "cpumap", Logging::IterLoggable(cpuMapping->second.begin(), cpuMapping->second.end()));
  }
  else {
    log->error(Logr::Warning, ret, "Error setting CPU affinity", "thread", Logging::Loggable(n), "cpumap", Logging::IterLoggable(cpuMapping->second.begin(), cpuMapping->second.end()));
  }
}

static void recursorThread();

void RecThreadInfo::start(unsigned int tid, const string& tname, const std::map<unsigned int, std::set<int>>& cpusMap, Logr::log_t log)
{
  name = tname;
  thread = std::thread([tid, tname] {
    t_id = tid;
    const string threadPrefix = "rec/";
    setThreadName(threadPrefix + tname);
    recursorThread();
  });
  setCPUMap(cpusMap, tid, thread.native_handle(), log);
}

int RecThreadInfo::runThreads(Logr::log_t log)
{
  int ret = EXIT_SUCCESS;
  const auto cpusMap = parseCPUMap(log);

  if (RecThreadInfo::numDistributors() + RecThreadInfo::numUDPWorkers() == 1) {
    log->info(Logr::Notice, "Operating with single UDP distributor/worker thread");

    /* This thread handles the web server, carbon, statistics and the control channel */
    unsigned int currentThreadId = 0;
    auto& handlerInfo = RecThreadInfo::info(currentThreadId);
    handlerInfo.setHandler();
    handlerInfo.start(currentThreadId, "web+stat", cpusMap, log);

    // We skip the single UDP worker thread 1, it's handled after the loop and taskthreads
    currentThreadId = 2;
    for (unsigned int thread = 0; thread < RecThreadInfo::numTCPWorkers(); thread++, currentThreadId++) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.setTCPListener();
      info.setWorker();
      info.start(currentThreadId, "tcpworker", cpusMap, log);
    }

    for (unsigned int thread = 0; thread < RecThreadInfo::numTaskThreads(); thread++, currentThreadId++) {
      auto& taskInfo = RecThreadInfo::info(currentThreadId);
      taskInfo.setTaskThread();
      taskInfo.start(currentThreadId, "task", cpusMap, log);
    }

    if (::arg().mustDo("webserver")) {
      serveRustWeb();
    }

    currentThreadId = 1;
    auto& info = RecThreadInfo::info(currentThreadId);
    info.setListener();
    info.setWorker();
    RecThreadInfo::setThreadId(currentThreadId);
    recursorThread();

    // Skip handler thread (it might be still handling the quit-nicely) and 1, which is actually the main thread in this case;
    // handler thread (0) will be handled in main().
    for (unsigned int thread = 2; thread < RecThreadInfo::numRecursorThreads(); thread++) {
      auto& tInfo = RecThreadInfo::info(thread);
      tInfo.thread.join();
      if (tInfo.exitCode != 0) {
        ret = tInfo.exitCode;
      }
    }
  }
  else {
    // Setup RecThreadInfo objects
    unsigned int currentThreadId = 1;
    if (RecThreadInfo::weDistributeQueries()) {
      for (unsigned int thread = 0; thread < RecThreadInfo::numDistributors(); thread++, currentThreadId++) {
        RecThreadInfo::info(currentThreadId).setListener();
      }
    }
    for (unsigned int thread = 0; thread < RecThreadInfo::numUDPWorkers(); thread++, currentThreadId++) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.setListener(!RecThreadInfo::weDistributeQueries());
      info.setWorker();
    }
    for (unsigned int thread = 0; thread < RecThreadInfo::numTCPWorkers(); thread++, currentThreadId++) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.setTCPListener();
      info.setWorker();
    }
    for (unsigned int thread = 0; thread < RecThreadInfo::numTaskThreads(); thread++, currentThreadId++) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.setTaskThread();
    }

    // And now start the actual threads
    currentThreadId = 1;
    if (RecThreadInfo::weDistributeQueries()) {
      log->info(Logr::Notice, "Launching distributor threads", "count", Logging::Loggable(RecThreadInfo::numDistributors()));
      for (unsigned int thread = 0; thread < RecThreadInfo::numDistributors(); thread++, currentThreadId++) {
        auto& info = RecThreadInfo::info(currentThreadId);
        info.start(currentThreadId, "distr", cpusMap, log);
      }
    }
    log->info(Logr::Notice, "Launching worker threads", "count", Logging::Loggable(RecThreadInfo::numUDPWorkers()));

    for (unsigned int thread = 0; thread < RecThreadInfo::numUDPWorkers(); thread++, currentThreadId++) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.start(currentThreadId, "worker", cpusMap, log);
    }

    log->info(Logr::Notice, "Launching tcpworker threads", "count", Logging::Loggable(RecThreadInfo::numTCPWorkers()));

    for (unsigned int thread = 0; thread < RecThreadInfo::numTCPWorkers(); thread++, currentThreadId++) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.start(currentThreadId, "tcpworker", cpusMap, log);
    }

    for (unsigned int thread = 0; thread < RecThreadInfo::numTaskThreads(); thread++, currentThreadId++) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.start(currentThreadId, "task", cpusMap, log);
    }

    /* This thread handles the web server, carbon, statistics and the control channel */
    currentThreadId = 0;
    auto& info = RecThreadInfo::info(currentThreadId);
    info.setHandler();
    info.start(currentThreadId, "web+stat", cpusMap, log);

    if (::arg().mustDo("webserver")) {
      serveRustWeb();
    }
    for (auto& tInfo : RecThreadInfo::infos()) {
      // who handles the handler? the caller!
      if (tInfo.isHandler()) {
        continue;
      }
      tInfo.thread.join();
      if (tInfo.exitCode != 0) {
        ret = tInfo.exitCode;
      }
    }
  }
  return ret;
}

void RecThreadInfo::makeThreadPipes(Logr::log_t log)
{
  auto pipeBufferSize = ::arg().asNum("distribution-pipe-buffer-size");
  if (pipeBufferSize > 0) {
    log->info(Logr::Info, "Resizing the buffer of the distribution pipe", "size", Logging::Loggable(pipeBufferSize));
  }

  /* thread 0 is the handler / SNMP, worker threads start at 1 */
  for (unsigned int thread = 0; thread < numRecursorThreads(); ++thread) {
    auto& threadInfo = info(thread);

    std::array<int, 2> fileDesc{};
    if (pipe(fileDesc.data()) < 0) {
      unixDie("Creating pipe for inter-thread communications");
    }

    threadInfo.pipes.readToThread = fileDesc[0];
    threadInfo.pipes.writeToThread = fileDesc[1];

    // handler thread only gets first pipe, not the others
    if (thread == 0) {
      continue;
    }

    if (pipe(fileDesc.data()) < 0) {
      unixDie("Creating pipe for inter-thread communications");
    }

    threadInfo.pipes.readFromThread = fileDesc[0];
    threadInfo.pipes.writeFromThread = fileDesc[1];

    if (pipe(fileDesc.data()) < 0) {
      unixDie("Creating pipe for inter-thread communications");
    }

    threadInfo.pipes.readQueriesToThread = fileDesc[0];
    threadInfo.pipes.writeQueriesToThread = fileDesc[1];

    if (pipeBufferSize > 0) {
      if (!setPipeBufferSize(threadInfo.pipes.writeQueriesToThread, pipeBufferSize)) {
        int err = errno;
        log->error(Logr::Warning, err, "Error resizing the buffer of the distribution pipe for thread", "thread", Logging::Loggable(thread), "size", Logging::Loggable(pipeBufferSize));
        auto existingSize = getPipeBufferSize(threadInfo.pipes.writeQueriesToThread);
        if (existingSize > 0) {
          log->info(Logr::Warning, "The current size of the distribution pipe's buffer for thread", "thread", Logging::Loggable(thread), "size", Logging::Loggable(existingSize));
        }
      }
    }

    if (!setNonBlocking(threadInfo.pipes.writeQueriesToThread)) {
      unixDie("Making pipe for inter-thread communications non-blocking");
    }
  }
}

ArgvMap& arg()
{
  static ArgvMap theArg;
  return theArg;
}

static FDMultiplexer* getMultiplexer(Logr::log_t log)
{
  FDMultiplexer* ret = nullptr;
  for (const auto& mplexer : FDMultiplexer::getMultiplexerMap()) {
    try {
      ret = mplexer.second(FDMultiplexer::s_maxevents);
      return ret;
    }
    catch (FDMultiplexerException& fe) {
      log->error(Logr::Warning, fe.what(), "Non-fatal error initializing possible multiplexer, falling back");
    }
    catch (...) {
      log->info(Logr::Warning, "Non-fatal error initializing possible multiplexer");
    }
  }
  log->info(Logr::Error, "No working multiplexer found!");
  _exit(1);
}

static std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>> startProtobufServers(const ProtobufExportConfig& config, Logr::log_t log)
{
  auto result = std::make_shared<std::vector<std::unique_ptr<RemoteLogger>>>();

  for (const auto& server : config.servers) {
    try {
      auto logger = make_unique<RemoteLogger>(server, config.timeout, 100 * config.maxQueuedEntries, config.reconnectWaitTime, config.asyncConnect);
      logger->setLogQueries(config.logQueries);
      logger->setLogResponses(config.logResponses);
      result->emplace_back(std::move(logger));
    }
    catch (const std::exception& e) {
      log->error(Logr::Error, e.what(), "Exception while starting protobuf logger", "exception", Logging::Loggable("std::exception"), "server", Logging::Loggable(server));
    }
    catch (const PDNSException& e) {
      log->error(Logr::Error, e.reason, "Exception while starting protobuf logger", "exception", Logging::Loggable("PDNSException"), "server", Logging::Loggable(server));
    }
  }

  return result;
}

bool checkProtobufExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal)
{
  if (!luaconfsLocal->protobufExportConfig.enabled) {
    if (t_protobufServers.servers) {
      t_protobufServers.servers.reset();
      t_protobufServers.config = luaconfsLocal->protobufExportConfig;
    }

    return false;
  }

  /* if the server was not running, or if it was running according to a
     previous configuration */
  if (t_protobufServers.generation < luaconfsLocal->generation && t_protobufServers.config != luaconfsLocal->protobufExportConfig) {

    if (t_protobufServers.servers) {
      t_protobufServers.servers.reset();
    }
    auto log = g_slog->withName("protobuf");
    t_protobufServers.servers = startProtobufServers(luaconfsLocal->protobufExportConfig, log);
    t_protobufServers.config = luaconfsLocal->protobufExportConfig;
    t_protobufServers.generation = luaconfsLocal->generation;
  }

  return true;
}

bool checkOutgoingProtobufExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal)
{
  if (!luaconfsLocal->outgoingProtobufExportConfig.enabled) {
    if (t_outgoingProtobufServers.servers) {
      t_outgoingProtobufServers.servers.reset();
      t_outgoingProtobufServers.config = luaconfsLocal->outgoingProtobufExportConfig;
    }

    return false;
  }

  /* if the server was not running, or if it was running according to a
     previous configuration */
  if (t_outgoingProtobufServers.generation < luaconfsLocal->generation && t_outgoingProtobufServers.config != luaconfsLocal->outgoingProtobufExportConfig) {

    if (t_outgoingProtobufServers.servers) {
      t_outgoingProtobufServers.servers.reset();
    }
    auto log = g_slog->withName("protobuf");
    t_outgoingProtobufServers.servers = startProtobufServers(luaconfsLocal->outgoingProtobufExportConfig, log);
    t_outgoingProtobufServers.config = luaconfsLocal->outgoingProtobufExportConfig;
    t_outgoingProtobufServers.generation = luaconfsLocal->generation;
  }

  return true;
}

void protobufLogQuery(LocalStateHolder<LuaConfigItems>& luaconfsLocal, const boost::uuids::uuid& uniqueId, const ComboAddress& remote, const ComboAddress& local, const ComboAddress& mappedSource, const Netmask& ednssubnet, bool tcp, size_t len, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::unordered_set<std::string>& policyTags, const std::string& requestorId, const std::string& deviceId, const std::string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta, const boost::optional<uint32_t>& ednsVersion, const dnsheader& header, const pdns::trace::TraceID& traceID)
{
  auto log = g_slog->withName("pblq");

  if (!t_protobufServers.servers) {
    return;
  }

  ComboAddress requestor;
  if (!luaconfsLocal->protobufExportConfig.logMappedFrom) {
    Netmask requestorNM(remote, remote.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
    requestor = requestorNM.getMaskedNetwork();
    requestor.setPort(remote.getPort());
  }
  else {
    Netmask requestorNM(mappedSource, mappedSource.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
    requestor = requestorNM.getMaskedNetwork();
    requestor.setPort(mappedSource.getPort());
  }

  pdns::ProtoZero::RecMessage msg{128, std::string::size_type(policyTags.empty() ? 0 : 64)}; // It's a guess
  msg.setType(pdns::ProtoZero::Message::MessageType::DNSQueryType);
  msg.setRequest(uniqueId, requestor, local, qname, qtype, qclass, header.id, tcp ? pdns::ProtoZero::Message::TransportProtocol::TCP : pdns::ProtoZero::Message::TransportProtocol::UDP, len);
  msg.setServerIdentity(SyncRes::s_serverID);
  msg.setEDNSSubnet(ednssubnet, ednssubnet.isIPv4() ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
  msg.setRequestorId(requestorId);
  msg.setDeviceId(deviceId);
  msg.setDeviceName(deviceName);
  msg.setWorkerId(RecThreadInfo::thread_local_id());
  // For queries, packetCacheHit and outgoingQueries are not relevant

  if (!policyTags.empty()) {
    msg.addPolicyTags(policyTags);
  }
  for (const auto& mit : meta) {
    msg.setMeta(mit.first, mit.second.stringVal, mit.second.intVal);
  }
  msg.setHeaderFlags(*getFlagsFromDNSHeader(&header));
  if (ednsVersion) {
    msg.setEDNSVersion(*ednsVersion);
  }
  if (traceID != pdns::trace::s_emptyTraceID) {
    msg.setOpenTelemtryTraceID(traceID);
  }

  std::string strMsg(msg.finishAndMoveBuf());
  for (auto& server : *t_protobufServers.servers) {
    remoteLoggerQueueData(*server, strMsg);
  }
}

void protobufLogResponse(pdns::ProtoZero::RecMessage& message)
{
  if (!t_protobufServers.servers) {
    return;
  }

  std::string msg(message.finishAndMoveBuf());
  for (auto& server : *t_protobufServers.servers) {
    remoteLoggerQueueData(*server, msg);
  }
}

void protobufLogResponse(const DNSName& qname, QType qtype,
                         const struct dnsheader* header, LocalStateHolder<LuaConfigItems>& luaconfsLocal,
                         const RecursorPacketCache::OptPBData& pbData, const struct timeval& tval,
                         bool tcp, const ComboAddress& source, const ComboAddress& destination,
                         const ComboAddress& mappedSource,
                         const EDNSSubnetOpts& ednssubnet,
                         const boost::uuids::uuid& uniqueId, const string& requestorId, const string& deviceId,
                         const string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta,
                         const RecEventTrace& eventTrace,
                         pdns::trace::InitialSpanInfo& otTrace,
                         const std::unordered_set<std::string>& policyTags)
{
  pdns::ProtoZero::RecMessage pbMessage(pbData ? pbData->d_message : "", pbData ? pbData->d_response : "", 64, 10); // The extra bytes we are going to add
  // Normally we take the immutable string from the cache and append a few values, but if it's not there (can this happen?)
  // we start with an empty string and append the minimal
  if (!pbData) {
    pbMessage.setType(pdns::ProtoZero::Message::MessageType::DNSResponseType);
    pbMessage.setServerIdentity(SyncRes::s_serverID);
  }

  // In response part
  if (g_useKernelTimestamp && tval.tv_sec != 0) {
    pbMessage.setQueryTime(tval.tv_sec, tval.tv_usec);
  }
  else {
    pbMessage.setQueryTime(g_now.tv_sec, g_now.tv_usec);
  }

  // In message part
  if (!luaconfsLocal->protobufExportConfig.logMappedFrom) {
    pbMessage.setSocketFamily(source.sin4.sin_family);
    Netmask requestorNM(source, source.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
    const auto& requestor = requestorNM.getMaskedNetwork();
    pbMessage.setFrom(requestor);
    pbMessage.setFromPort(source.getPort());
  }
  else {
    pbMessage.setSocketFamily(mappedSource.sin4.sin_family);
    Netmask requestorNM(mappedSource, mappedSource.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
    const auto& requestor = requestorNM.getMaskedNetwork();
    pbMessage.setFrom(requestor);
    pbMessage.setFromPort(mappedSource.getPort());
  }
  pbMessage.setMessageIdentity(uniqueId);
  pbMessage.setTo(destination);
  pbMessage.setSocketProtocol(tcp ? pdns::ProtoZero::Message::TransportProtocol::TCP : pdns::ProtoZero::Message::TransportProtocol::UDP);
  pbMessage.setId(header->id);

  pbMessage.setTime();
  pbMessage.setEDNSSubnet(ednssubnet.getSource(), ednssubnet.getSource().isIPv4() ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
  pbMessage.setRequestorId(requestorId);
  pbMessage.setDeviceId(deviceId);
  pbMessage.setDeviceName(deviceName);
  pbMessage.setToPort(destination.getPort());
  pbMessage.setWorkerId(RecThreadInfo::thread_local_id());
  // this method is only used for PC cache hits
  pbMessage.setPacketCacheHit(true);
  // we do not set outgoingQueries, it is not relevant for PC cache hits

  for (const auto& metaItem : meta) {
    pbMessage.setMeta(metaItem.first, metaItem.second.stringVal, metaItem.second.intVal);
  }
#ifdef NOD_ENABLED
  if (g_nodEnabled) {
    pbMessage.setNewlyObservedDomain(false);
  }
#endif
  if (eventTrace.enabled() && (SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_pb) != 0) {
    pbMessage.addEvents(eventTrace);
  }
  if (eventTrace.enabled() && (SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_ot) != 0) {
    auto trace = pdns::trace::TracesData::boilerPlate("rec", qname.toLogString() + '/' + qtype.toString(), eventTrace.convertToOT(otTrace));
    pbMessage.setOpenTelemetryData(trace.encode());
  }
  if (otTrace.trace_id != pdns::trace::s_emptyTraceID) {
    pbMessage.setOpenTelemtryTraceID(otTrace.trace_id);
  }
  pbMessage.addPolicyTags(policyTags);

  protobufLogResponse(pbMessage);
}

#ifdef HAVE_FSTRM

static std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>> startFrameStreamServers(const FrameStreamExportConfig& config, Logr::log_t log)
{
  auto result = std::make_shared<std::vector<std::unique_ptr<FrameStreamLogger>>>();

  for (const auto& server : config.servers) {
    try {
      std::unordered_map<string, unsigned> options;
      options["bufferHint"] = config.bufferHint;
      options["flushTimeout"] = config.flushTimeout;
      options["inputQueueSize"] = config.inputQueueSize;
      options["outputQueueSize"] = config.outputQueueSize;
      options["queueNotifyThreshold"] = config.queueNotifyThreshold;
      options["reopenInterval"] = config.reopenInterval;
      unique_ptr<FrameStreamLogger> fsl = nullptr;
      try {
        ComboAddress address(server);
        fsl = make_unique<FrameStreamLogger>(address.sin4.sin_family, address.toStringWithPort(), true, options);
      }
      catch (const PDNSException& e) {
        fsl = make_unique<FrameStreamLogger>(AF_UNIX, server, true, options);
      }
      fsl->setLogQueries(config.logQueries);
      fsl->setLogResponses(config.logResponses);
      fsl->setLogNODs(config.logNODs);
      fsl->setLogUDRs(config.logUDRs);
      result->emplace_back(std::move(fsl));
    }
    catch (const std::exception& e) {
      log->error(Logr::Error, e.what(), "Exception while starting dnstap framestream logger", "exception", Logging::Loggable("std::exception"), "server", Logging::Loggable(server));
    }
    catch (const PDNSException& e) {
      log->error(Logr::Error, e.reason, "Exception while starting dnstap framestream logger", "exception", Logging::Loggable("PDNSException"), "server", Logging::Loggable(server));
    }
  }

  return result;
}

static void asyncFrameStreamLoggersCleanup(std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>&& servers)
{
  auto thread = std::thread([&] {
    servers.reset();
  });
  thread.detach();
}

bool checkFrameStreamExport(LocalStateHolder<LuaConfigItems>& luaconfsLocal, const FrameStreamExportConfig& config, FrameStreamServersInfo& serverInfos)
{
  if (!config.enabled) {
    if (serverInfos.servers) {
      // dt's take care of cleanup
      asyncFrameStreamLoggersCleanup(std::move(serverInfos.servers));
      serverInfos.config = config;
    }

    return false;
  }

  /* if the server was not running, or if it was running according to a previous
   * configuration
   */
  if (serverInfos.generation < luaconfsLocal->generation && serverInfos.config != config) {
    if (serverInfos.servers) {
      // dt's take care of cleanup
      asyncFrameStreamLoggersCleanup(std::move(serverInfos.servers));
    }

    auto dnsTapLog = g_slog->withName("dnstap");
    serverInfos.servers = startFrameStreamServers(config, dnsTapLog);
    serverInfos.config = config;
    serverInfos.generation = luaconfsLocal->generation;
  }

  return true;
}

#endif /* HAVE_FSTRM */

static void makeControlChannelSocket(int processNum = -1)
{
  string sockname = ::arg()["socket-dir"] + "/" + g_programname;
  if (processNum >= 0) {
    sockname += "." + std::to_string(processNum);
  }
  sockname += ".controlsocket";
  g_rcc.listen(sockname);

  uid_t sockowner = -1;
  gid_t sockgroup = -1;

  if (!::arg().isEmpty("socket-group")) {
    sockgroup = ::arg().asGid("socket-group");
  }
  if (!::arg().isEmpty("socket-owner")) {
    sockowner = ::arg().asUid("socket-owner");
  }

  if (sockgroup != static_cast<gid_t>(-1) || sockowner != static_cast<uid_t>(-1)) {
    if (chown(sockname.c_str(), sockowner, sockgroup) < 0) {
      unixDie("Failed to chown control socket");
    }
  }

  // do mode change if socket-mode is given
  if (!::arg().isEmpty("socket-mode")) {
    mode_t sockmode = ::arg().asMode("socket-mode");
    if (chmod(sockname.c_str(), sockmode) < 0) {
      unixDie("Failed to chmod control socket");
    }
  }
}

static void writePid(Logr::log_t log)
{
  if (!::arg().mustDo("write-pid")) {
    return;
  }
  ofstream ostr(g_pidfname.c_str(), std::ios_base::app);
  if (ostr) {
    ostr << Utility::getpid() << endl;
  }
  else {
    int err = errno;
    log->error(Logr::Error, err, "Writing pid failed", "pid", Logging::Loggable(Utility::getpid()), "file", Logging::Loggable(g_pidfname));
  }
}

static void checkSocketDir(Logr::log_t log)
{
  string dir(::arg()["socket-dir"]);
  string msg;

  struct stat dirStat = {};
  if (stat(dir.c_str(), &dirStat) == -1) {
    msg = "it does not exist or cannot access";
  }
  else if (!S_ISDIR(dirStat.st_mode)) {
    msg = "it is not a directory";
  }
  else if (access(dir.c_str(), R_OK | W_OK | X_OK) != 0) {
    msg = "cannot read, write or search";
  }
  else {
    return;
  }
  dir = ::arg()["chroot"] + dir;
  log->error(Logr::Error, msg, "Problem with socket directory, see https://docs.powerdns.com/recursor/upgrade.html#x-to-4-3-0", "dir", Logging::Loggable(dir));
  _exit(1);
}

#ifdef NOD_ENABLED
static void setupNODThread(Logr::log_t log)
{
  if (g_nodEnabled) {
    uint32_t num_cells = ::arg().asNum("new-domain-db-size");
    g_nodDBp = std::make_unique<nod::NODDB>(num_cells);
    try {
      g_nodDBp->setCacheDir(::arg()["new-domain-history-dir"]);
    }
    catch (const PDNSException& e) {
      log->error(Logr::Error, e.reason, "new-domain-history-dir is not readable or does not exists", "dir", Logging::Loggable(::arg()["new-domain-history-dir"]));
      _exit(1);
    }
    if (!g_nodDBp->init()) {
      log->info(Logr::Error, "Could not initialize domain tracking");
      _exit(1);
    }
    if (::arg().asNum("new-domain-db-snapshot-interval") > 0) {
      g_nodDBp->setSnapshotInterval(::arg().asNum("new-domain-db-snapshot-interval"));
      std::thread thread([tid = std::this_thread::get_id()]() {
        g_nodDBp->housekeepingThread(tid);
      });
      thread.detach();
    }
  }
  if (g_udrEnabled) {
    uint32_t num_cells = ::arg().asNum("unique-response-db-size");
    g_udrDBp = std::make_unique<nod::UniqueResponseDB>(num_cells);
    try {
      g_udrDBp->setCacheDir(::arg()["unique-response-history-dir"]);
    }
    catch (const PDNSException& e) {
      log->info(Logr::Error, "unique-response-history-dir is not readable or does not exist", "dir", Logging::Loggable(::arg()["unique-response-history-dir"]));
      _exit(1);
    }
    if (!g_udrDBp->init()) {
      log->info(Logr::Error, "Could not initialize unique response tracking");
      _exit(1);
    }
    if (::arg().asNum("new-domain-db-snapshot-interval") > 0) {
      g_udrDBp->setSnapshotInterval(::arg().asNum("new-domain-db-snapshot-interval"));
      std::thread thread([tid = std::this_thread::get_id()]() {
        g_udrDBp->housekeepingThread(tid);
      });
      thread.detach();
    }
  }
}

static void parseIgnorelist(const std::string& wlist, SuffixMatchNode& matchNode)
{
  vector<string> parts;
  stringtok(parts, wlist, ",; ");
  for (const auto& part : parts) {
    matchNode.add(DNSName(part));
  }
}

static void parseIgnorelistFile(const std::string& fname, SuffixMatchNode& matchNode)
{
  string line;
  std::ifstream ignorelistFileStream(fname);
  if (!ignorelistFileStream) {
    throw ArgException(fname + " could not be opened");
  }

  while (getline(ignorelistFileStream, line)) {
    boost::trim(line);

    try {
      matchNode.add(DNSName(line));
    }
    catch (const std::exception& e) {
      g_slog->withName("config")->error(Logr::Warning, e.what(), "Ignoring line of ignorelist due to an error", "exception", Logging::Loggable("std::exception"));
    }
  }
}

static void setupNODGlobal()
{
  // Setup NOD subsystem
  g_nodEnabled = ::arg().mustDo("new-domain-tracking");
  g_nodLookupDomain = DNSName(::arg()["new-domain-lookup"]);
  g_nodLog = ::arg().mustDo("new-domain-log");
  parseIgnorelist(::arg()["new-domain-whitelist"], g_nodDomainWL);
  parseIgnorelist(::arg()["new-domain-ignore-list"], g_nodDomainWL);
  if (!::arg().isEmpty("new-domain-ignore-list-file")) {
    parseIgnorelistFile(::arg()["new-domain-ignore-list-file"], g_nodDomainWL);
  }

  // Setup Unique DNS Response subsystem
  g_udrEnabled = ::arg().mustDo("unique-response-tracking");
  g_udrLog = ::arg().mustDo("unique-response-log");
  g_nod_pbtag = ::arg()["new-domain-pb-tag"];
  g_udr_pbtag = ::arg()["unique-response-pb-tag"];
  parseIgnorelist(::arg()["unique-response-ignore-list"], g_udrDomainWL);
  if (!::arg().isEmpty("unique-response-ignore-list-file")) {
    parseIgnorelistFile(::arg()["unique-response-ignore-list-file"], g_udrDomainWL);
  }
}
#endif /* NOD_ENABLED */

static void daemonize(Logr::log_t log)
{
  if (auto pid = fork(); pid != 0) {
    if (pid < 0) {
      int err = errno;
      log->error(Logr::Critical, err, "Fork failed");
      exit(1); // NOLINT(concurrency-mt-unsafe)
    }
    exit(0); // NOLINT(concurrency-mt-unsafe)
  }

  setsid();

  int devNull = open("/dev/null", O_RDWR); /* open stdin */
  if (devNull < 0) {
    int err = errno;
    log->error(Logr::Critical, err, "Unable to open /dev/null");
  }
  else {
    dup2(devNull, 0); /* stdin */
    dup2(devNull, 1); /* stderr */
    dup2(devNull, 2); /* stderr */
    close(devNull);
  }
}

static void termIntHandler([[maybe_unused]] int arg)
{
  _exit(1);
}

static void usr1Handler([[maybe_unused]] int arg)
{
  statsWanted = true;
}

static void usr2Handler([[maybe_unused]] int arg)
{
  g_quiet = !g_quiet;
  SyncRes::setDefaultLogMode(g_quiet ? SyncRes::LogNone : SyncRes::Log);
  ::arg().set("quiet") = g_quiet ? "yes" : "no";
}

static void checkLinuxIPv6Limits([[maybe_unused]] Logr::log_t log)
{
#ifdef __linux__
  string line;
  if (readFileIfThere("/proc/sys/net/ipv6/route/max_size", &line)) {
    int lim = std::stoi(line);
    if (lim < 16384) {
      log->info(Logr::Error, "If using IPv6, please raise sysctl net.ipv6.route.max_size to a size >= 16384", "current", Logging::Loggable(lim));
    }
  }
#endif
}

static void checkOrFixLinuxMapCountLimits([[maybe_unused]] Logr::log_t log)
{
#ifdef __linux__
  string line;
  if (readFileIfThere("/proc/sys/vm/max_map_count", &line)) {
    auto lim = std::stoull(line);
    // mthread stack use 3 maps per stack (2 guard pages + stack itself). Multiple by 4 for extra allowance.
    // Also add 2 for handler and task threads.
    auto workers = RecThreadInfo::numTCPWorkers() + RecThreadInfo::numUDPWorkers() + 2;
    auto mapsNeeded = 4ULL * g_maxMThreads * workers;
    if (lim < mapsNeeded) {
      g_maxMThreads = static_cast<unsigned int>(lim / (4ULL * workers));
      log->info(Logr::Error, "sysctl vm.max_map_count < mapsNeeded, this may cause 'bad_alloc' exceptions, adjusting max-mthreads",
                "vm.max_map_count", Logging::Loggable(lim), "mapsNeeded", Logging::Loggable(mapsNeeded),
                "max-mthreads", Logging::Loggable(g_maxMThreads));
    }
  }
#endif
}

static void checkOrFixFDS(unsigned int listeningSockets, Logr::log_t log)
{
  const auto availFDs = getFilenumLimit();
  // Posix threads
  const auto threads = RecThreadInfo::numRecursorThreads();
  // We do not count the handler and task threads, they do not spawn many mthreads at once
  const auto workers = RecThreadInfo::numUDPWorkers() + RecThreadInfo::numTCPWorkers();

  // Static part: the FDs from the start, pipes, controlsocket, web socket, listen sockets
  unsigned int staticPart = 25; // general  allowance, including control socket, web, snmp
  // Handler thread gets one pipe, the others all of them
  staticPart += 2 + (threads - 1) * (sizeof(RecThreadInfo::ThreadPipeSet) / sizeof(int)); // number of fd's in ThreadPipeSet
  // listen sockets
  staticPart += listeningSockets;
  // Another fd per thread for poll/kqueue
  staticPart += threads;
  // Incoming TCP, connections are shared by threads and are kept open for a while
  staticPart += g_maxTCPClients;

  // Dynamic parts per worker
  // Each mthread uses one fd for either outgoing UDP or outgoing TCP (but not simultaneously)
  unsigned int perWorker = g_maxMThreads;
  // plus each worker thread can have a number of idle outgoing TCP connections
  perWorker += TCPOutConnectionManager::s_maxIdlePerThread;

  auto wantFDs = staticPart + workers * perWorker;

  if (wantFDs > availFDs) {
    unsigned int hardlimit = getFilenumLimit(true);
    if (staticPart >= hardlimit) {
      log->info(Logr::Critical, "Number of available filedescriptors is lower than the minimum needed",
                "hardlimit", Logging::Loggable(hardlimit), "minimum", Logging::Loggable(staticPart));
      _exit(1);
    }
    if (hardlimit >= wantFDs) {
      setFilenumLimit(wantFDs);
      log->info(Logr::Warning, "Raised soft limit on number of filedescriptors to match max-mthreads and threads settings", "limit", Logging::Loggable(wantFDs));
    }
    else {
      auto newval = (hardlimit - staticPart) / workers;
      log->info(Logr::Warning, "Insufficient number of filedescriptors available for max-mthreads*threads setting! Reducing max-mthreads", "hardlimit", Logging::Loggable(hardlimit), "want", Logging::Loggable(wantFDs), "max-mthreads", Logging::Loggable(newval));
      g_maxMThreads = newval;
      setFilenumLimit(hardlimit);
    }
  }
}

#ifdef HAVE_SYSTEMD
static void loggerSDBackend(const Logging::Entry& entry)
{
  static const set<std::string, CIStringComparePOSIX> special = {
    "message",
    "message_id",
    "priority",
    "code_file",
    "code_line",
    "code_func",
    "errno",
    "invocation_id",
    "user_invocation_id",
    "syslog_facility",
    "syslog_identifier",
    "syslog_pid",
    "syslog_timestamp",
    "syslog_raw",
    "documentation",
    "tid",
    "unit",
    "user_unit",
    "object_pid"};

  // First map SL priority to syslog's Urgency
  Logger::Urgency urgency = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (urgency > s_logUrgency) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Not that lower Urgency means higher number.
    return;
  }
  // We need to keep the string in mem until sd_journal_sendv has ben called
  vector<string> strings;
  auto appendKeyAndVal = [&strings](const string& key, const string& value) {
    strings.emplace_back(key + "=" + value);
  };
  appendKeyAndVal("MESSAGE", entry.message);
  if (entry.error) {
    appendKeyAndVal("ERROR", entry.error.get());
  }
  appendKeyAndVal("LEVEL", std::to_string(entry.level));
  appendKeyAndVal("PRIORITY", std::to_string(entry.d_priority));
  if (entry.name) {
    appendKeyAndVal("SUBSYSTEM", entry.name.get());
  }
  std::array<char, 64> timebuf{};
  appendKeyAndVal("TIMESTAMP", Logging::toTimestampStringMilli(entry.d_timestamp, timebuf));
  for (const auto& value : entry.values) {
    if (value.first.at(0) == '_' || special.count(value.first) != 0) {
      string key{"PDNS"};
      key.append(value.first);
      appendKeyAndVal(toUpper(key), value.second);
    }
    else {
      appendKeyAndVal(toUpper(value.first), value.second);
    }
  }
  // Thread id filled in by backend, since the SL code does not know about RecursorThreads
  // We use the Recursor thread, other threads get id 0. May need to revisit.
  appendKeyAndVal("TID", std::to_string(RecThreadInfo::thread_local_id()));

  vector<iovec> iov;
  iov.reserve(strings.size());
  for (const auto& str : strings) {
    // iovec has no 2 arg constructor, so make it explicit
    iov.emplace_back(iovec{const_cast<void*>(reinterpret_cast<const void*>(str.data())), str.size()}); // NOLINT: it's the API
  }
  sd_journal_sendv(iov.data(), static_cast<int>(iov.size()));
}
#endif

static void loggerJSONBackend(const Logging::Entry& entry)
{
  // First map SL priority to syslog's Urgency
  Logger::Urgency urg = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (urg > s_logUrgency) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Not that lower Urgency means higher number.
    return;
  }

  std::array<char, 64> timebuf{};
  json11::Json::object json = {
    {"msg", entry.message},
    {"level", std::to_string(entry.level)},
    // Thread id filled in by backend, since the SL code does not know about RecursorThreads
    // We use the Recursor thread, other threads get id 0. May need to revisit.
    {"tid", std::to_string(RecThreadInfo::thread_local_id())},
    {"ts", Logging::toTimestampStringMilli(entry.d_timestamp, timebuf)},
  };

  if (entry.error) {
    json.emplace("error", entry.error.get());
  }

  if (entry.name) {
    json.emplace("subsystem", entry.name.get());
  }

  if (entry.d_priority != 0) {
    json.emplace("priority", std::to_string(entry.d_priority));
  }

  for (auto const& value : entry.values) {
    json.emplace(value.first, value.second);
  }

  static thread_local std::string out;
  out.clear();
  json11::Json doc(std::move(json));
  doc.dump(out);
  cerr << out << endl;
}

static void loggerBackend(const Logging::Entry& entry)
{
  static thread_local std::stringstream buf;

  // First map SL priority to syslog's Urgency
  Logger::Urgency urg = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (urg > s_logUrgency) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Not that lower Urgency means higher number.
    return;
  }
  buf.str("");
  buf << "msg=" << std::quoted(entry.message);
  if (entry.error) {
    buf << " error=" << std::quoted(entry.error.get());
  }

  if (entry.name) {
    buf << " subsystem=" << std::quoted(entry.name.get());
  }
  buf << " level=" << std::quoted(std::to_string(entry.level));
  if (entry.d_priority != 0) {
    buf << " prio=" << std::quoted(Logr::Logger::toString(entry.d_priority));
  }
  // Thread id filled in by backend, since the SL code does not know about RecursorThreads
  // We use the Recursor thread, other threads get id 0. May need to revisit.
  buf << " tid=" << std::quoted(std::to_string(RecThreadInfo::thread_local_id()));
  std::array<char, 64> timebuf{};
  buf << " ts=" << std::quoted(Logging::toTimestampStringMilli(entry.d_timestamp, timebuf));
  for (auto const& value : entry.values) {
    buf << " ";
    buf << value.first << "=" << std::quoted(value.second);
  }

  g_log << urg << buf.str() << endl;
}

static std::string ratePercentage(uint64_t nom, uint64_t denom)
{
  if (denom == 0) {
    return "0";
  }
  std::ostringstream str;
  str << std::setprecision(2) << std::fixed << 100.0 * static_cast<double>(nom) / static_cast<double>(denom);
  return str.str();
}

static void doStats()
{
  static time_t lastOutputTime;
  static uint64_t lastQueryCount;

  auto cacheHits = g_recCache->getCacheHits();
  auto cacheMisses = g_recCache->getCacheMisses();
  auto cacheSize = g_recCache->size();
  auto rc_stats = g_recCache->stats();
  auto pc_stats = g_packetCache ? g_packetCache->stats() : std::pair<uint64_t, uint64_t>{0, 0};
  auto rrc = ratePercentage(rc_stats.first, rc_stats.second);
  auto rpc = ratePercentage(pc_stats.first, pc_stats.second);
  auto negCacheSize = g_negCache->size();
  auto taskPushes = getTaskPushes();
  auto taskExpired = getTaskExpired();
  auto taskSize = getTaskSize();
  auto pcSize = g_packetCache ? g_packetCache->size() : 0;
  auto pcHits = g_packetCache ? g_packetCache->getHits() : 0;
  auto pcMisses = g_packetCache ? g_packetCache->getMisses() : 0;

  auto qcounter = g_Counters.sum(rec::Counter::qcounter);
  auto outqueries = g_Counters.sum(rec::Counter::outqueries);
  auto throttledqueries = g_Counters.sum(rec::Counter::throttledqueries);
  auto tcpoutqueries = g_Counters.sum(rec::Counter::tcpoutqueries);
  auto dotoutqueries = g_Counters.sum(rec::Counter::dotoutqueries);
  auto outgoingtimeouts = g_Counters.sum(rec::Counter::outgoingtimeouts);

  auto log = g_slog->withName("stats");

  if (qcounter > 0) {
    const string report = "Periodic statistics report";
    log->info(Logr::Info, report,
              "questions", Logging::Loggable(qcounter),
              "cache-entries", Logging::Loggable(cacheSize),
              "negcache-entries", Logging::Loggable(negCacheSize),
              "record-cache-hitratio-perc", Logging::Loggable(ratePercentage(cacheHits, cacheHits + cacheMisses)),
              "record-cache-contended", Logging::Loggable(rc_stats.first),
              "record-cache-acquired", Logging::Loggable(rc_stats.second),
              "record-cache-contended-perc", Logging::Loggable(rrc));
    log->info(Logr::Info, report,
              "packetcache-contended", Logging::Loggable(pc_stats.first),
              "packetcache-acquired", Logging::Loggable(pc_stats.second),
              "packetcache-contended-perc", Logging::Loggable(rpc),
              "packetcache-entries", Logging::Loggable(pcSize),
              "packetcache-hitratio-perc", Logging::Loggable(ratePercentage(pcHits, pcHits + pcMisses)));
    log->info(Logr::Info, report,
              "throttle-entries", Logging::Loggable(SyncRes::getThrottledServersSize()),
              "nsspeed-entries", Logging::Loggable(SyncRes::getNSSpeedsSize()),
              "failed-host-entries", Logging::Loggable(SyncRes::getFailedServersSize()),
              "edns-entries", Logging::Loggable(SyncRes::getEDNSStatusesSize()),
              "non-resolving-nameserver-entries", Logging::Loggable(SyncRes::getNonResolvingNSSize()),
              "saved-parent-ns-sets-entries", Logging::Loggable(SyncRes::getSaveParentsNSSetsSize()));
    log->info(Logr::Info, report,
              "throttled-queries-perc", Logging::Loggable(ratePercentage(throttledqueries, outqueries + throttledqueries)),
              "outqueries", Logging::Loggable(outqueries),
              "tcp-outqueries", Logging::Loggable(tcpoutqueries),
              "dot-outqueries", Logging::Loggable(dotoutqueries),
              "idle-tcpout-connections", Logging::Loggable(getCurrentIdleTCPConnections()),
              "concurrent-queries", Logging::Loggable(broadcastAccFunction<uint64_t>(pleaseGetConcurrentQueries)),
              "outgoing-timeouts", Logging::Loggable(outgoingtimeouts),
              "outqueries-per-query-perc", Logging::Loggable(ratePercentage(outqueries, qcounter)));
    log->info(Logr::Info, report,
              "taskqueue-pushed", Logging::Loggable(taskPushes),
              "taskqueue-expired", Logging::Loggable(taskExpired),
              "taskqueue-size", Logging::Loggable(taskSize));

    size_t idx = 0;
    for (const auto& threadInfo : RecThreadInfo::infos()) {
      if (threadInfo.isWorker()) {
        log->info(Logr::Info, "Queries handled by thread", "thread", Logging::Loggable(idx), "tname", Logging::Loggable(threadInfo.getName()), "count", Logging::Loggable(threadInfo.getNumberOfDistributedQueries()));
        ++idx;
      }
    }
    time_t now = time(nullptr);
    if (lastOutputTime != 0 && lastQueryCount != 0 && now != lastOutputTime) {
      log->info(Logr::Info, "Periodic QPS report", "qps", Logging::Loggable((qcounter - lastQueryCount) / (now - lastOutputTime)),
                "averagedOver", Logging::Loggable(now - lastOutputTime));
    }
    lastOutputTime = now;
    lastQueryCount = qcounter;
  }
  else if (statsWanted) {
    log->info(Logr::Notice, "No stats yet");
  }

  statsWanted = false;
}

static std::shared_ptr<NetmaskGroup> parseACL(const std::string& aclFile, const std::string& aclSetting, Logr::log_t log)
{
  auto result = std::make_shared<NetmaskGroup>();

  const string file = ::arg()[aclFile];

  if (!file.empty()) {
    if (boost::ends_with(file, ".yml")) {
      ::rust::vec<::rust::string> vec;
      pdns::settings::rec::readYamlAllowFromFile(file, vec, log);
      for (const auto& subnet : vec) {
        result->addMask(string(subnet));
      }
    }
    else {
      string line;
      ifstream ifs(file);
      if (!ifs) {
        int err = errno;
        throw runtime_error("Could not open '" + file + "': " + stringerror(err));
      }

      while (getline(ifs, line)) {
        auto pos = line.find('#');
        if (pos != string::npos) {
          line.resize(pos);
        }
        boost::trim(line);
        if (line.empty()) {
          continue;
        }

        result->addMask(line);
      }
    }
    log->info(Logr::Info, "Done parsing ranges from file, will override setting", "setting", Logging::Loggable(aclSetting),
              "number", Logging::Loggable(result->size()), "file", Logging::Loggable(file));
  }
  else if (!::arg()[aclSetting].empty()) {
    vector<string> ips;
    stringtok(ips, ::arg()[aclSetting], ", ");

    for (const auto& address : ips) {
      result->addMask(address);
    }
    log->info(Logr::Info, "Setting access control", "acl", Logging::Loggable(aclSetting), "addresses", Logging::IterLoggable(ips.begin(), ips.end()));
  }

  return result;
}

static void* pleaseSupplantAllowFrom(std::shared_ptr<NetmaskGroup> nmgroup)
{
  t_allowFrom = std::move(nmgroup);
  return nullptr;
}

static void* pleaseSupplantAllowNotifyFrom(std::shared_ptr<NetmaskGroup> nmgroup)
{
  t_allowNotifyFrom = std::move(nmgroup);
  return nullptr;
}

void* pleaseSupplantAllowNotifyFor(std::shared_ptr<notifyset_t> allowNotifyFor)
{
  t_allowNotifyFor = std::move(allowNotifyFor);
  return nullptr;
}

static void* pleaseSupplantProxyProtocolSettings(std::shared_ptr<NetmaskGroup> acl, std::shared_ptr<std::set<ComboAddress>> except)
{
  t_proxyProtocolACL = std::move(acl);
  t_proxyProtocolExceptions = std::move(except);
  return nullptr;
}

void parseACLs()
{
  auto log = g_slog->withName("config");

  static bool l_initialized;
  const std::array<string, 6> aclNames = {
    "allow-from-file",
    "allow-from",
    "allow-notify-from-file",
    "allow-notify-from",
    "proxy-protocol-from",
    "proxy-protocol-exceptions"};

  if (l_initialized) { // only reload configuration file on second call

    string configName = ::arg()["config-dir"] + "/recursor";
    if (!::arg()["config-name"].empty()) {
      configName = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"];
    }
    cleanSlashes(configName);

    if (g_yamlSettings) {
      configName += g_yamlSettingsSuffix;
      string msg;
      pdns::rust::settings::rec::Recursorsettings settings;
      // XXX Does ::arg()["include-dir"] have the right value, i.e. potentially overriden by command line?
      auto yamlstatus = pdns::settings::rec::readYamlSettings(configName, ::arg()["include-dir"], settings, msg, log);

      switch (yamlstatus) {
      case pdns::settings::rec::YamlSettingsStatus::CannotOpen:
        throw runtime_error("Unable to open '" + configName + "': " + msg);
        break;
      case pdns::settings::rec::YamlSettingsStatus::PresentButFailed:
        throw runtime_error("Error processing '" + configName + "': " + msg);
        break;
      case pdns::settings::rec::YamlSettingsStatus::OK:
        pdns::settings::rec::processAPIDir(arg()["include-dir"], settings, log);
        // Does *not* set include-dir
        pdns::settings::rec::setArgsForACLRelatedSettings(settings);
        break;
      }
    }
    else {
      configName += ".conf";
      if (!::arg().preParseFile(configName, "allow-from-file")) {
        throw runtime_error("Unable to re-parse configuration file '" + configName + "'");
      }
      ::arg().preParseFile(configName, "allow-from", LOCAL_NETS);

      if (!::arg().preParseFile(configName, "allow-notify-from-file")) {
        throw runtime_error("Unable to re-parse configuration file '" + configName + "'");
      }
      ::arg().preParseFile(configName, "allow-notify-from");
      ::arg().preParseFile(configName, "proxy-protocol-from");
      ::arg().preParseFile(configName, "proxy-protocol-exceptions");

      ::arg().preParseFile(configName, "include-dir");
      ::arg().preParse(g_argc, g_argv, "include-dir");

      // then process includes
      std::vector<std::string> extraConfigs;
      ::arg().gatherIncludes(::arg()["include-dir"], ".conf", extraConfigs);

      for (const std::string& fileName : extraConfigs) {
        for (const auto& aclName : aclNames) {
          if (!::arg().preParseFile(fileName, aclName, ::arg()[aclName])) {
            throw runtime_error("Unable to re-parse configuration file include '" + fileName + "'");
          }
        }
      }
    }
  }
  // Process command line args potentially overriding settings read from file
  for (const auto& aclName : aclNames) {
    ::arg().preParse(g_argc, g_argv, aclName);
  }

  auto allowFrom = parseACL("allow-from-file", "allow-from", log);

  if (allowFrom->empty()) {
    if (::arg()["local-address"] != "127.0.0.1" && ::arg().asNum("local-port") == 53) {
      log->info(Logr::Warning, "WARNING: Allowing queries from all IP addresses - this can be a security risk!");
    }
    allowFrom = nullptr;
  }

  *g_initialAllowFrom.lock() = allowFrom;
  // coverity[copy_constructor_call] maybe this can be avoided, but be careful as pointers get passed to other threads
  broadcastFunction([=] { return pleaseSupplantAllowFrom(allowFrom); });

  auto allowNotifyFrom = parseACL("allow-notify-from-file", "allow-notify-from", log);

  *g_initialAllowNotifyFrom.lock() = allowNotifyFrom;
  // coverity[copy_constructor_call] maybe this can be avoided, but be careful as pointers get passed to other threads
  broadcastFunction([=] { return pleaseSupplantAllowNotifyFrom(allowNotifyFrom); });

  std::shared_ptr<NetmaskGroup> proxyProtocolACL;
  std::shared_ptr<std::set<ComboAddress>> proxyProtocolExceptions;
  if (!::arg()["proxy-protocol-from"].empty()) {
    proxyProtocolACL = std::make_shared<NetmaskGroup>();
    proxyProtocolACL->toMasks(::arg()["proxy-protocol-from"]);

    std::vector<std::string> vec;
    stringtok(vec, ::arg()["proxy-protocol-exceptions"], ", ");
    if (!vec.empty()) {
      proxyProtocolExceptions = std::make_shared<std::set<ComboAddress>>();
      for (const auto& sockAddrStr : vec) {
        ComboAddress sockAddr(sockAddrStr, 53);
        proxyProtocolExceptions->emplace(sockAddr);
      }
    }
  }
  g_initialProxyProtocolACL = proxyProtocolACL;
  g_initialProxyProtocolExceptions = proxyProtocolExceptions;

  // coverity[copy_constructor_call] maybe this can be avoided, but be careful as pointers get passed to other threads
  broadcastFunction([=] { return pleaseSupplantProxyProtocolSettings(proxyProtocolACL, proxyProtocolExceptions); });

  l_initialized = true;
}

static std::mutex pipeBroadCastMutex{};

void broadcastFunction(const pipefunc_t& func)
{
  // we do not want the handler and web code to use pipes simultaneously
  std::scoped_lock lock(pipeBroadCastMutex);

  /* This function might be called by the worker with t_id not inited during startup
     for the initialization of ACLs and domain maps. After that it should only
     be called by the handler. */

  if (RecThreadInfo::infos().empty() && !RecThreadInfo::is_thread_inited()) {
    /* the handler and  distributors will call themselves below, but
       during startup we get called while g_threadInfos has not been
       populated yet to update the ACL or domain maps, so we need to
       handle that case.
    */
    func();
  }

  unsigned int thread = 0;
  for (const auto& threadInfo : RecThreadInfo::infos()) {
    if (thread++ == RecThreadInfo::thread_local_id()) {
      func(); // don't write to ourselves!
      continue;
    }

    ThreadMSG* tmsg = new ThreadMSG(); // NOLINT: manual ownership handling
    tmsg->func = func;
    tmsg->wantAnswer = true;
    if (write(threadInfo.getPipes().writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) { // NOLINT: sizeof correct
      delete tmsg; // NOLINT: manual ownership handling

      unixDie("write to thread pipe returned wrong size or error");
    }

    string* resp = nullptr;
    if (read(threadInfo.getPipes().readFromThread, &resp, sizeof(resp)) != sizeof(resp)) { // NOLINT: sizeof correct
      unixDie("read from thread pipe returned wrong size or error");
    }

    if (resp != nullptr) {
      delete resp; // NOLINT: manual ownership handling
      resp = nullptr;
    }
    // coverity[leaked_storage]
  }
}

template <class T>
void* voider(const std::function<T*()>& func)
{
  return func();
}

static vector<ComboAddress>& operator+=(vector<ComboAddress>& lhs, const vector<ComboAddress>& rhs)
{
  lhs.insert(lhs.end(), rhs.begin(), rhs.end());
  return lhs;
}

static vector<pair<DNSName, uint16_t>>& operator+=(vector<pair<DNSName, uint16_t>>& lhs, const vector<pair<DNSName, uint16_t>>& rhs)
{
  lhs.insert(lhs.end(), rhs.begin(), rhs.end());
  return lhs;
}

static ProxyMappingStats_t& operator+=(ProxyMappingStats_t& lhs, const ProxyMappingStats_t& rhs)
{
  for (const auto& [key, entry] : rhs) {
    lhs[key].netmaskMatches += entry.netmaskMatches;
    lhs[key].suffixMatches += entry.suffixMatches;
  }
  return lhs;
}

static RemoteLoggerStats_t& operator+=(RemoteLoggerStats_t& lhs, const RemoteLoggerStats_t& rhs)
{
  for (const auto& [key, entry] : rhs) {
    lhs[key] += entry;
  }
  return lhs;
}

// This function should only be called by the handler and web thread to gather metrics, wipe the
// cache, reload the Lua script (not the Lua config) or change the current trace regex, and by the
// SNMP thread to gather metrics.  Note that this currently skips the handler, but includes the
// taskThread(s).
template <class T>
T broadcastAccFunction(const std::function<T*()>& func)
{
  if (RecThreadInfo::thread_local_id() != 0) {
    g_slog->withName("runtime")->info(Logr::Critical, "broadcastAccFunction has been called by a worker"); // tid will be added
    _exit(1);
  }

  // we do not want the handler and web code to use pipes simultaneously
  std::scoped_lock lock(pipeBroadCastMutex);

  unsigned int thread = 0;
  T ret = T();
  for (const auto& threadInfo : RecThreadInfo::infos()) {
    if (thread++ == RecThreadInfo::thread_local_id()) {
      continue;
    }

    const auto& tps = threadInfo.getPipes();
    ThreadMSG* tmsg = new ThreadMSG(); // NOLINT: manual ownership handling
    tmsg->func = [func] { return voider<T>(func); };
    tmsg->wantAnswer = true;

    if (write(tps.writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) { // NOLINT:: sizeof correct
      delete tmsg; // NOLINT: manual ownership handling
      unixDie("write to thread pipe returned wrong size or error");
    }

    T* resp = nullptr;
    if (read(tps.readFromThread, &resp, sizeof(resp)) != sizeof(resp)) // NOLINT: sizeof correct
      unixDie("read from thread pipe returned wrong size or error");

    if (resp) {
      ret += *resp;
      delete resp; // NOLINT: manual ownership handling
      resp = nullptr;
    }
    // coverity[leaked_storage]
  }
  return ret;
}

template string broadcastAccFunction(const std::function<string*()>& fun); // explicit instantiation
template RecursorControlChannel::Answer broadcastAccFunction(const std::function<RecursorControlChannel::Answer*()>& fun); // explicit instantiation
template uint64_t broadcastAccFunction(const std::function<uint64_t*()>& fun); // explicit instantiation
template vector<ComboAddress> broadcastAccFunction(const std::function<vector<ComboAddress>*()>& fun); // explicit instantiation
template vector<pair<DNSName, uint16_t>> broadcastAccFunction(const std::function<vector<pair<DNSName, uint16_t>>*()>& fun); // explicit instantiation
template ThreadTimes broadcastAccFunction(const std::function<ThreadTimes*()>& fun);
template ProxyMappingStats_t broadcastAccFunction(const std::function<ProxyMappingStats_t*()>& fun);
template RemoteLoggerStats_t broadcastAccFunction(const std::function<RemoteLoggerStats_t*()>& fun);

static int initNet(Logr::log_t log)
{
  checkLinuxIPv6Limits(log);
  try {
    pdns::parseQueryLocalAddress(::arg()["query-local-address"]);
  }
  catch (std::exception& e) {
    log->error(Logr::Error, e.what(), "Unable to assign local query address");
    return 99;
  }

  if (pdns::isQueryLocalAddressFamilyEnabled(AF_INET)) {
    SyncRes::s_doIPv4 = true;
    log->info(Logr::Notice, "Enabling IPv4 transport for outgoing queries");
  }
  else {
    log->info(Logr::Warning, "NOT using IPv4 for outgoing queries - add an IPv4 address (like '0.0.0.0') to query-local-address to enable");
  }

  if (pdns::isQueryLocalAddressFamilyEnabled(AF_INET6)) {
    SyncRes::s_doIPv6 = true;
    log->info(Logr::Notice, "Enabling IPv6 transport for outgoing queries");
  }
  else {
    log->info(Logr::Warning, "NOT using IPv6 for outgoing queries - add an IPv6 address (like '::') to query-local-address to enable");
  }

  if (!SyncRes::s_doIPv6 && !SyncRes::s_doIPv4) {
    log->info(Logr::Error, "No outgoing addresses configured! Can not continue");
    return 99;
  }
  return 0;
}

static int initDNSSEC(Logr::log_t log)
{
  if (::arg()["dnssec"] == "off") {
    g_dnssecmode = DNSSECMode::Off;
  }
  else if (::arg()["dnssec"] == "process-no-validate") {
    g_dnssecmode = DNSSECMode::ProcessNoValidate;
  }
  else if (::arg()["dnssec"] == "process") {
    g_dnssecmode = DNSSECMode::Process;
  }
  else if (::arg()["dnssec"] == "validate") {
    g_dnssecmode = DNSSECMode::ValidateAll;
  }
  else if (::arg()["dnssec"] == "log-fail") {
    g_dnssecmode = DNSSECMode::ValidateForLog;
  }
  else {
    log->info(Logr::Error, "Unknown DNSSEC mode", "dnssec", Logging::Loggable(::arg()["dnssec"]));
    return 1;
  }

  {
    auto value = ::arg().asNum("signature-inception-skew");
    if (value < 0) {
      log->info(Logr::Error, "A negative value for 'signature-inception-skew' is not allowed");
      return 1;
    }
    g_signatureInceptionSkew = value;
  }

  g_dnssecLogBogus = ::arg().mustDo("dnssec-log-bogus");
  g_maxNSEC3Iterations = ::arg().asNum("nsec3-max-iterations");
  g_maxRRSIGsPerRecordToConsider = ::arg().asNum("max-rrsigs-per-record");
  g_maxNSEC3sPerRecordToConsider = ::arg().asNum("max-nsec3s-per-record");
  g_maxDNSKEYsToConsider = ::arg().asNum("max-dnskeys");
  g_maxDSsToConsider = ::arg().asNum("max-ds-per-zone");

  vector<string> nums;
  bool automatic = true;
  if (!::arg()["dnssec-disabled-algorithms"].empty()) {
    automatic = false;
    stringtok(nums, ::arg()["dnssec-disabled-algorithms"], ", ");
    for (const auto& num : nums) {
      DNSCryptoKeyEngine::switchOffAlgorithm(pdns::checked_stoi<unsigned int>(num));
    }
  }
  else {
    for (auto algo : {DNSSECKeeper::RSASHA1, DNSSECKeeper::RSASHA1NSEC3SHA1}) {
      if (!DNSCryptoKeyEngine::verifyOne(algo)) {
        DNSCryptoKeyEngine::switchOffAlgorithm(algo);
        nums.push_back(std::to_string(algo));
      }
    }
  }
  if (!nums.empty()) {
    log->info(Logr::Notice, "Disabled DNSSEC algorithms", "automatically", Logging::Loggable(automatic), "algorithms", Logging::IterLoggable(nums.begin(), nums.end()));
  }

  return 0;
}

static void initDontQuery(Logr::log_t log)
{
  if (!::arg()["dont-query"].empty()) {
    vector<string> ips;
    stringtok(ips, ::arg()["dont-query"], ", ");
    ips.emplace_back("0.0.0.0");
    ips.emplace_back("::");

    for (const auto& anIP : ips) {
      SyncRes::addDontQuery(anIP);
    }
    log->info(Logr::Notice, "Will not send queries to", "addresses", Logging::IterLoggable(ips.begin(), ips.end()));
  }
}

static int initSyncRes(Logr::log_t log)
{
  SyncRes::s_minimumTTL = ::arg().asNum("minimum-ttl-override");
  SyncRes::s_minimumECSTTL = ::arg().asNum("ecs-minimum-ttl-override");
  SyncRes::s_maxnegttl = ::arg().asNum("max-negative-ttl");
  SyncRes::s_maxbogusttl = ::arg().asNum("max-cache-bogus-ttl");
  SyncRes::s_maxcachettl = max(::arg().asNum("max-cache-ttl"), 15);

  SyncRes::s_packetcachettl = ::arg().asNum("packetcache-ttl");
  // Cap the packetcache-servfail-ttl and packetcache-negative-ttl to packetcache-ttl
  SyncRes::s_packetcacheservfailttl = std::min(static_cast<unsigned int>(::arg().asNum("packetcache-servfail-ttl")), SyncRes::s_packetcachettl);
  SyncRes::s_packetcachenegativettl = std::min(static_cast<unsigned int>(::arg().asNum("packetcache-negative-ttl")), SyncRes::s_packetcachettl);

  SyncRes::s_serverdownmaxfails = ::arg().asNum("server-down-max-fails");
  SyncRes::s_serverdownthrottletime = ::arg().asNum("server-down-throttle-time");
  SyncRes::s_unthrottle_n = ::arg().asNum("bypass-server-throttling-probability");
  SyncRes::s_nonresolvingnsmaxfails = ::arg().asNum("non-resolving-ns-max-fails");
  SyncRes::s_nonresolvingnsthrottletime = ::arg().asNum("non-resolving-ns-throttle-time");
  SyncRes::s_serverID = ::arg()["server-id"];
  // This bound is dynamically adjusted in SyncRes, depending on qname minimization being active
  SyncRes::s_maxqperq = ::arg().asNum("max-qperq");
  SyncRes::s_maxnsperresolve = ::arg().asNum("max-ns-per-resolve");
  SyncRes::s_maxnsaddressqperq = ::arg().asNum("max-ns-address-qperq");
  SyncRes::s_maxtotusec = 1000 * ::arg().asNum("max-total-msec");
  SyncRes::s_maxdepth = ::arg().asNum("max-recursion-depth");
  SyncRes::s_maxvalidationsperq = ::arg().asNum("max-signature-validations-per-query");
  SyncRes::s_maxnsec3iterationsperq = ::arg().asNum("max-nsec3-hash-computations-per-query");
  SyncRes::s_rootNXTrust = ::arg().mustDo("root-nx-trust");
  SyncRes::s_refresh_ttlperc = ::arg().asNum("refresh-on-ttl-perc");
  SyncRes::s_locked_ttlperc = ::arg().asNum("record-cache-locked-ttl-perc");
  RecursorPacketCache::s_refresh_ttlperc = SyncRes::s_refresh_ttlperc;
  SyncRes::s_tcp_fast_open = ::arg().asNum("tcp-fast-open");
  SyncRes::s_tcp_fast_open_connect = ::arg().mustDo("tcp-fast-open-connect");

  SyncRes::s_dot_to_port_853 = ::arg().mustDo("dot-to-port-853");
  SyncRes::s_event_trace_enabled = ::arg().asNum("event-trace-enabled");
  SyncRes::s_save_parent_ns_set = ::arg().mustDo("save-parent-ns-set");
  SyncRes::s_max_busy_dot_probes = ::arg().asNum("max-busy-dot-probes");
  SyncRes::s_max_CNAMES_followed = ::arg().asNum("max-cnames-followed");
  {
    uint64_t sse = ::arg().asNum("serve-stale-extensions");
    if (sse > std::numeric_limits<uint16_t>::max()) {
      log->info(Logr::Error, "Illegal serve-stale-extensions value; range = 0..65536", "value", Logging::Loggable(sse));
      return 1;
    }
    MemRecursorCache::s_maxServedStaleExtensions = sse;
    NegCache::s_maxServedStaleExtensions = sse;
  }
  MemRecursorCache::s_maxRRSetSize = ::arg().asNum("max-rrset-size");
  MemRecursorCache::s_limitQTypeAny = ::arg().mustDo("limit-qtype-any");

  if (SyncRes::s_tcp_fast_open_connect) {
    checkFastOpenSysctl(true, log);
    checkTFOconnect(log);
  }
  SyncRes::s_ecsipv4limit = ::arg().asNum("ecs-ipv4-bits");
  SyncRes::s_ecsipv6limit = ::arg().asNum("ecs-ipv6-bits");
  SyncRes::clearECSStats();
  SyncRes::s_ecsipv4cachelimit = ::arg().asNum("ecs-ipv4-cache-bits");
  SyncRes::s_ecsipv6cachelimit = ::arg().asNum("ecs-ipv6-cache-bits");
  SyncRes::s_ecsipv4nevercache = ::arg().mustDo("ecs-ipv4-never-cache");
  SyncRes::s_ecsipv6nevercache = ::arg().mustDo("ecs-ipv6-never-cache");
  SyncRes::s_ecscachelimitttl = ::arg().asNum("ecs-cache-limit-ttl");

  SyncRes::s_qnameminimization = ::arg().mustDo("qname-minimization");
  SyncRes::s_minimize_one_label = ::arg().asNum("qname-minimize-one-label");
  SyncRes::s_max_minimize_count = ::arg().asNum("qname-max-minimize-count");

  SyncRes::s_hardenNXD = SyncRes::HardenNXD::DNSSEC;
  string value = ::arg()["nothing-below-nxdomain"];
  if (value == "yes") {
    SyncRes::s_hardenNXD = SyncRes::HardenNXD::Yes;
  }
  else if (value == "no") {
    SyncRes::s_hardenNXD = SyncRes::HardenNXD::No;
  }
  else if (value != "dnssec") {
    log->info(Logr::Error, "Unknown nothing-below-nxdomain mode", "mode", Logging::Loggable(value));
    return 1;
  }

  if (!::arg().isEmpty("ecs-scope-zero-address")) {
    ComboAddress scopeZero(::arg()["ecs-scope-zero-address"]);
    SyncRes::setECSScopeZeroAddress(Netmask(scopeZero, scopeZero.isIPv4() ? 32 : 128));
  }
  else {
    Netmask netmask;
    bool done = false;

    auto addr = pdns::getNonAnyQueryLocalAddress(AF_INET);
    if (addr.sin4.sin_family != 0) {
      netmask = Netmask(addr, 32);
      done = true;
    }
    if (!done) {
      addr = pdns::getNonAnyQueryLocalAddress(AF_INET6);
      if (addr.sin4.sin_family != 0) {
        netmask = Netmask(addr, 128);
        done = true;
      }
    }
    if (!done) {
      netmask = Netmask(ComboAddress("127.0.0.1"), 32);
    }
    SyncRes::setECSScopeZeroAddress(netmask);
  }

  SyncRes::parseEDNSSubnetAllowlist(::arg()["edns-subnet-whitelist"]);
  SyncRes::parseEDNSSubnetAllowlist(::arg()["edns-subnet-allow-list"]);
  SyncRes::parseEDNSSubnetAddFor(::arg()["ecs-add-for"]);
  g_useIncomingECS = ::arg().mustDo("use-incoming-edns-subnet");
  return 0;
}

static unsigned int initDistribution(Logr::log_t log)
{
  unsigned int count = 0;
  g_balancingFactor = ::arg().asDouble("distribution-load-factor");
  if (g_balancingFactor != 0.0 && g_balancingFactor < 1.0) {
    g_balancingFactor = 0.0;
    log->info(Logr::Warning, "Asked to run with a distribution-load-factor below 1.0, disabling it instead");
  }

#ifdef SO_REUSEPORT
  g_reusePort = ::arg().mustDo("reuseport");
#endif

  RecThreadInfo::resize(RecThreadInfo::numRecursorThreads());

  if (g_reusePort) {
    unsigned int threadNum = 1;
    if (RecThreadInfo::weDistributeQueries()) {
      /* first thread is the handler, then distributors */
      for (unsigned int i = 0; i < RecThreadInfo::numDistributors(); i++, threadNum++) {
        auto& info = RecThreadInfo::info(threadNum);
        auto& deferredAdds = info.getDeferredAdds();
        // The two last arguments to make{UDP,TCP}ServerSockets are used for logging purposes only, same for calls below
        count += makeUDPServerSockets(deferredAdds, log, i == RecThreadInfo::numDistributors() - 1, RecThreadInfo::numDistributors());
      }
    }
    else {
      /* first thread is the handler, there is no distributor here and workers are accepting queries */
      for (unsigned int i = 0; i < RecThreadInfo::numUDPWorkers(); i++, threadNum++) {
        auto& info = RecThreadInfo::info(threadNum);
        auto& deferredAdds = info.getDeferredAdds();
        count += makeUDPServerSockets(deferredAdds, log, i == RecThreadInfo::numUDPWorkers() - 1, RecThreadInfo::numUDPWorkers());
      }
    }
    threadNum = 1 + RecThreadInfo::numDistributors() + RecThreadInfo::numUDPWorkers();
    for (unsigned int i = 0; i < RecThreadInfo::numTCPWorkers(); i++, threadNum++) {
      auto& info = RecThreadInfo::info(threadNum);
      auto& deferredAdds = info.getDeferredAdds();
      auto& tcpSockets = info.getTCPSockets();
      count += makeTCPServerSockets(deferredAdds, tcpSockets, log, i == RecThreadInfo::numTCPWorkers() - 1, RecThreadInfo::numTCPWorkers());
    }
  }
  else {
    std::set<int> tcpSockets;
    /* we don't have reuseport so we can only open one socket per
       listening addr:port and everyone will listen on it */
    count += makeUDPServerSockets(s_deferredUDPadds, log, true, 1);
    count += makeTCPServerSockets(s_deferredTCPadds, tcpSockets, log, true, 1);

    // TCP queries are handled by TCP workers
    for (unsigned int i = 0; i < RecThreadInfo::numTCPWorkers(); i++) {
      auto& info = RecThreadInfo::info(i + 1 + RecThreadInfo::numDistributors() + RecThreadInfo::numUDPWorkers());
      info.setTCPSockets(tcpSockets);
    }
  }
  return count;
}

static int initForks(Logr::log_t log)
{
  int forks = 0;
  for (; forks < ::arg().asNum("processes") - 1; ++forks) {
    if (fork() == 0) { // we are child
      break;
    }
  }

  if (::arg().mustDo("daemon")) {
    log->info(Logr::Warning, "Calling daemonize, going to background");
    g_log.toConsole(Logger::Critical);
    daemonize(log);
  }

  if (Utility::getpid() == 1) {
    /* We are running as pid 1, register sigterm and sigint handler

      The Linux kernel will handle SIGTERM and SIGINT for all processes, except PID 1.
      It assumes that the processes running as pid 1 is an "init" like system.
      For years, this was a safe assumption, but containers change that: in
      most (all?) container implementations, the application itself is running
      as pid 1. This means that sending signals to those applications, will not
      be handled by default. Results might be "your container not responding
      when asking it to stop", or "ctrl-c not working even when the app is
      running in the foreground inside a container".

      So TL;DR: If we're running pid 1 (container), we should handle SIGTERM and SIGINT ourselves */

    signal(SIGTERM, termIntHandler);
    signal(SIGINT, termIntHandler);
  }

  signal(SIGUSR1, usr1Handler);
  signal(SIGUSR2, usr2Handler);
  signal(SIGPIPE, SIG_IGN); // NOLINT: Posix API
  return forks;
}

static int initPorts(Logr::log_t log)
{
  int port = ::arg().asNum("udp-source-port-min");
  if (port < 1024 || port > 65535) {
    log->info(Logr::Error, "Unable to launch, udp-source-port-min is not a valid port number");
    return 99; // this isn't going to fix itself either
  }
  g_minUdpSourcePort = port;
  port = ::arg().asNum("udp-source-port-max");
  if (port < 1024 || port > 65535 || port < g_minUdpSourcePort) {
    log->info(Logr::Error, "Unable to launch, udp-source-port-max is not a valid port number or is smaller than udp-source-port-min");
    return 99; // this isn't going to fix itself either
  }
  g_maxUdpSourcePort = port;
  std::vector<string> parts{};
  stringtok(parts, ::arg()["udp-source-port-avoid"], ", ");
  for (const auto& part : parts) {
    port = std::stoi(part);
    if (port < 1024 || port > 65535) {
      log->info(Logr::Error, "Unable to launch, udp-source-port-avoid contains an invalid port number", "port", Logging::Loggable(part));
      return 99; // this isn't going to fix itself either
    }
    g_avoidUdpSourcePorts.insert(port);
  }
  return 0;
}

static void initSNMP([[maybe_unused]] Logr::log_t log)
{
  if (::arg().mustDo("snmp-agent")) {
#ifdef HAVE_NET_SNMP
    string setting = ::arg()["snmp-daemon-socket"];
    if (setting.empty()) {
      setting = ::arg()["snmp-master-socket"];
    }
    g_snmpAgent = std::make_shared<RecursorSNMPAgent>("recursor", setting);
    g_snmpAgent->run();
#else
    const std::string msg = "snmp-agent set but SNMP support not compiled in";
    log->info(Logr::Error, msg);
#endif // HAVE_NET_SNMP
  }
}

static int initControl(Logr::log_t log, uid_t newuid, int forks)
{
  if (!::arg()["chroot"].empty()) {
#ifdef HAVE_SYSTEMD
    char* ns;
    ns = getenv("NOTIFY_SOCKET");
    if (ns != nullptr) {
      log->info(Logr::Error, "Unable to chroot when running from systemd. Please disable chroot= or set the 'Type' for this service to 'simple'");
      return 1;
    }
#endif
    if (chroot(::arg()["chroot"].c_str()) < 0 || chdir("/") < 0) {
      int err = errno;
      log->error(Logr::Error, err, "Unable to chroot", "chroot", Logging::Loggable(::arg()["chroot"]));
      return 1;
    }
    log->info(Logr::Info, "Chrooted", "chroot", Logging::Loggable(::arg()["chroot"]));
  }

  checkSocketDir(log);

  g_pidfname = ::arg()["socket-dir"] + "/" + g_programname + ".pid";
  if (!g_pidfname.empty()) {
    unlink(g_pidfname.c_str()); // remove possible old pid file
  }
  writePid(log);

  makeControlChannelSocket(::arg().asNum("processes") > 1 ? forks : -1);

  Utility::dropUserPrivs(newuid);
  try {
    /* we might still have capabilities remaining, for example if we have been started as root
       without --setuid (please don't do that) or as an unprivileged user with ambient capabilities
       like CAP_NET_BIND_SERVICE.
    */
    dropCapabilities();
  }
  catch (const std::exception& e) {
    log->error(Logr::Warning, e.what(), "Could not drop capabilities");
  }
  return 0;
}

static void initSuffixMatchNodes([[maybe_unused]] Logr::log_t log)
{
  {
    SuffixMatchNode dontThrottleNames;
    vector<string> parts;
    stringtok(parts, ::arg()["dont-throttle-names"], " ,");
    for (const auto& part : parts) {
      dontThrottleNames.add(DNSName(part));
    }
    g_dontThrottleNames.setState(std::move(dontThrottleNames));

    NetmaskGroup dontThrottleNetmasks;
    dontThrottleNetmasks.toMasks(::arg()["dont-throttle-netmasks"]);
    g_dontThrottleNetmasks.setState(std::move(dontThrottleNetmasks));
  }

  {
    SuffixMatchNode xdnssecNames;
    vector<string> parts;
    stringtok(parts, ::arg()["x-dnssec-names"], " ,");
    for (const auto& part : parts) {
      xdnssecNames.add(DNSName(part));
    }
    g_xdnssec.setState(std::move(xdnssecNames));
  }

  {
    SuffixMatchNode dotauthNames;
    vector<string> parts;
    stringtok(parts, ::arg()["dot-to-auth-names"], " ,");
#ifndef HAVE_DNS_OVER_TLS
    if (!parts.empty()) {
      log->info(Logr::Error, "dot-to-auth-names setting contains names, but Recursor was built without DNS over TLS support. Setting will be ignored");
    }
#endif
    for (const auto& part : parts) {
      dotauthNames.add(DNSName(part));
    }
    g_DoTToAuthNames.setState(std::move(dotauthNames));
  }
}

static void initCarbon()
{
  CarbonConfig config;
  stringtok(config.servers, arg()["carbon-server"], ", ");
  config.hostname = arg()["carbon-ourname"];
  config.instance_name = arg()["carbon-instance"];
  config.namespace_name = arg()["carbon-namespace"];
  g_carbonConfig.setState(std::move(config));
}

static int initDNS64(Logr::log_t log)
{
  if (!::arg()["dns64-prefix"].empty()) {
    try {
      auto dns64Prefix = Netmask(::arg()["dns64-prefix"]);
      if (dns64Prefix.getBits() != 96) {
        log->info(Logr::Error, "Invalid prefix for 'dns64-prefix', the current implementation only supports /96 prefixes", "prefix", Logging::Loggable(::arg()["dns64-prefix"]));
        return 1;
      }
      g_dns64Prefix = dns64Prefix.getNetwork();
      g_dns64PrefixReverse = reverseNameFromIP(*g_dns64Prefix);
      /* /96 is 24 nibbles + 2 for "ip6.arpa." */
      while (g_dns64PrefixReverse.countLabels() > 26) {
        g_dns64PrefixReverse.chopOff();
      }
    }
    catch (const NetmaskException& ne) {
      log->info(Logr::Error, "Invalid prefix", "dns64-prefix", Logging::Loggable(::arg()["dns64-prefix"]));
      return 1;
    }
  }
  return 0;
}

static int serviceMain(Logr::log_t log)
{
  g_log.setName(g_programname);
  g_log.disableSyslog(::arg().mustDo("disable-syslog"));
  g_log.setTimestamps(::arg().mustDo("log-timestamp"));
  g_regressionTestMode = ::arg().mustDo("devonly-regression-test-mode");

  if (!::arg()["logging-facility"].empty()) {
    int val = logFacilityToLOG(::arg().asNum("logging-facility"));
    if (val >= 0) {
      g_log.setFacility(val);
    }
    else {
      log->info(Logr::Error, "Unknown logging facility", "facility", Logging::Loggable(::arg().asNum("logging-facility")));
    }
  }

  g_disthashseed = dns_random_uint32();

  int ret = initNet(log);
  if (ret != 0) {
    return ret;
  }
  // keep this ABOVE loadRecursorLuaConfig!
  ret = initDNSSEC(log);
  if (ret != 0) {
    return ret;
  }
  g_maxCacheEntries = ::arg().asNum("max-cache-entries");

  auto luaResult = luaconfig(false);
  if (luaResult.d_ret != 0) {
    log->error(Logr::Error, luaResult.d_str, "Cannot load Lua or equivalent YAML configuration");
    return 1;
  }

  parseACLs();
  initPublicSuffixList(::arg()["public-suffix-list-file"]);

  initDontQuery(log);

  RecThreadInfo::setWeDistributeQueries(::arg().mustDo("pdns-distributes-queries"));
  if (RecThreadInfo::weDistributeQueries()) {
    log->info(Logr::Notice, "PowerDNS Recursor itself will distribute queries over threads");
  }

  g_outgoingEDNSBufsize = ::arg().asNum("edns-outgoing-bufsize");

  if (::arg()["trace"] == "fail") {
    SyncRes::setDefaultLogMode(SyncRes::Store);
  }
  else if (::arg().mustDo("trace")) {
    SyncRes::setDefaultLogMode(SyncRes::Log);
    ::arg().set("quiet") = "no";
    g_quiet = false;
  }

  ret = initSyncRes(log);
  if (ret != 0) {
    return ret;
  }

  if (!::arg()["proxy-protocol-from"].empty()) {
    g_initialProxyProtocolACL = std::make_shared<NetmaskGroup>();
    g_initialProxyProtocolACL->toMasks(::arg()["proxy-protocol-from"]);

    std::vector<std::string> vec;
    stringtok(vec, ::arg()["proxy-protocol-exceptions"], ", ");
    if (!vec.empty()) {
      g_initialProxyProtocolExceptions = std::make_shared<std::set<ComboAddress>>();
      for (const auto& sockAddrStr : vec) {
        ComboAddress sockAddr(sockAddrStr, 53);
        g_initialProxyProtocolExceptions->emplace(sockAddr);
      }
    }
  }
  g_proxyProtocolMaximumSize = ::arg().asNum("proxy-protocol-maximum-size");

  ret = initDNS64(log);
  if (ret != 0) {
    return ret;
  }
  g_networkTimeoutMsec = ::arg().asNum("network-timeout");

  { // Reduce scope of locks (otherwise Coverity induces from this line the global vars below should be
    // protected by a mutex)
    std::tie(*g_initialDomainMap.lock(), *g_initialAllowNotifyFor.lock()) = parseZoneConfiguration(g_yamlSettings);
  }

  g_latencyStatSize = ::arg().asNum("latency-statistic-size");

  g_logCommonErrors = ::arg().mustDo("log-common-errors");
  g_logRPZChanges = ::arg().mustDo("log-rpz-changes");

  g_anyToTcp = ::arg().mustDo("any-to-tcp");
  g_allowNoRD = ::arg().mustDo("allow-no-rd");
  g_udpTruncationThreshold = ::arg().asNum("udp-truncation-threshold");

  g_lowercaseOutgoing = ::arg().mustDo("lowercase-outgoing");

  g_paddingFrom.toMasks(::arg()["edns-padding-from"]);
  if (::arg()["edns-padding-mode"] == "always") {
    g_paddingMode = PaddingMode::Always;
  }
  else if (::arg()["edns-padding-mode"] == "padded-queries-only") {
    g_paddingMode = PaddingMode::PaddedQueries;
  }
  else {
    log->info(Logr::Error, "Unknown edns-padding-mode", "edns-padding-mode", Logging::Loggable(::arg()["edns-padding-mode"]));
    return 1;
  }
  g_paddingTag = ::arg().asNum("edns-padding-tag");
  g_paddingOutgoing = ::arg().mustDo("edns-padding-out");
  g_ECSHardening = ::arg().mustDo("edns-subnet-harden");

  // Ignong errors return value, as YAML parsing already checked the format of the entries.
  enableOutgoingCookies(::arg().mustDo("outgoing-cookies"), ::arg()["outgoing-cookies-unsupported"]);

  RecThreadInfo::setNumDistributorThreads(::arg().asNum("distributor-threads"));
  RecThreadInfo::setNumUDPWorkerThreads(::arg().asNum("threads"));
  if (RecThreadInfo::numUDPWorkers() < 1) {
    log->info(Logr::Warning, "Asked to run with 0 threads, raising to 1 instead");
    RecThreadInfo::setNumUDPWorkerThreads(1);
  }
  RecThreadInfo::setNumTCPWorkerThreads(::arg().asNum("tcp-threads"));
  if (RecThreadInfo::numTCPWorkers() < 1) {
    log->info(Logr::Warning, "Asked to run with 0 TCP threads, raising to 1 instead");
    RecThreadInfo::setNumTCPWorkerThreads(1);
  }

  g_maxMThreads = ::arg().asNum("max-mthreads");

  int64_t maxInFlight = ::arg().asNum("max-concurrent-requests-per-tcp-connection");
  if (maxInFlight < 1 || maxInFlight > USHRT_MAX || maxInFlight >= g_maxMThreads) {
    log->info(Logr::Warning, "Asked to run with illegal max-concurrent-requests-per-tcp-connection, setting to default (10)");
    TCPConnection::s_maxInFlight = 10;
  }
  else {
    TCPConnection::s_maxInFlight = maxInFlight;
  }

  int64_t millis = ::arg().asNum("tcp-out-max-idle-ms");
  TCPOutConnectionManager::s_maxIdleTime = timeval{millis / 1000, (static_cast<suseconds_t>(millis) % 1000) * 1000};
  TCPOutConnectionManager::s_maxIdlePerAuth = ::arg().asNum("tcp-out-max-idle-per-auth");
  TCPOutConnectionManager::s_maxQueries = ::arg().asNum("tcp-out-max-queries");
  TCPOutConnectionManager::s_maxIdlePerThread = ::arg().asNum("tcp-out-max-idle-per-thread");
  TCPOutConnectionManager::setupOutgoingTLSTables();

  g_gettagNeedsEDNSOptions = ::arg().mustDo("gettag-needs-edns-options");

  s_statisticsInterval = ::arg().asNum("statistics-interval");

  SyncRes::s_addExtendedResolutionDNSErrors = ::arg().mustDo("extended-resolution-errors");

  if (::arg().asNum("aggressive-nsec-cache-size") > 0) {
    if (g_dnssecmode == DNSSECMode::ValidateAll || g_dnssecmode == DNSSECMode::ValidateForLog || g_dnssecmode == DNSSECMode::Process) {
      g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(::arg().asNum("aggressive-nsec-cache-size"));
    }
    else {
      log->info(Logr::Warning, "Aggressive NSEC/NSEC3 caching is enabled but DNSSEC validation is not set to 'validate', 'log-fail' or 'process', ignoring");
    }
  }

  AggressiveNSECCache::s_nsec3DenialProofMaxCost = ::arg().asNum("aggressive-cache-max-nsec3-hash-cost");
  AggressiveNSECCache::s_maxNSEC3CommonPrefix = static_cast<uint8_t>(std::round(std::log2(::arg().asNum("aggressive-cache-min-nsec3-hit-ratio"))));
  log->info(Logr::Debug, "NSEC3 aggressive cache tuning", "aggressive-cache-min-nsec3-hit-ratio", Logging::Loggable(::arg().asNum("aggressive-cache-min-nsec3-hit-ratio")), "maxCommonPrefixBits", Logging::Loggable(AggressiveNSECCache::s_maxNSEC3CommonPrefix));

  initSuffixMatchNodes(log);
  initCarbon();
  auto listeningSockets = initDistribution(log);

#ifdef NOD_ENABLED
  // Setup newly observed domain globals
  setupNODGlobal();
#endif /* NOD_ENABLED */

  auto forks = initForks(log);

  g_tcpTimeout = ::arg().asNum("client-tcp-timeout");
  g_maxTCPClients = ::arg().asNum("max-tcp-clients");
  g_maxTCPPerClient = ::arg().asNum("max-tcp-per-client");
  g_tcpMaxQueriesPerConn = ::arg().asNum("max-tcp-queries-per-connection");
  g_maxUDPQueriesPerRound = ::arg().asNum("max-udp-queries-per-round");

  g_useKernelTimestamp = ::arg().mustDo("protobuf-use-kernel-timestamp");
  g_maxChainLength = ::arg().asNum("max-chain-length");

  checkOrFixFDS(listeningSockets, log);
  checkOrFixLinuxMapCountLimits(log);

#ifdef HAVE_LIBSODIUM
  if (sodium_init() == -1) {
    log->info(Logr::Error, "Unable to initialize sodium crypto library");
    return 99;
  }
#endif

  openssl_thread_setup();
  openssl_seed();

  gid_t newgid = 0;
  if (!::arg()["setgid"].empty()) {
    newgid = strToGID(::arg()["setgid"]);
  }
  uid_t newuid = 0;
  if (!::arg()["setuid"].empty()) {
    newuid = strToUID(::arg()["setuid"]);
  }

  Utility::dropGroupPrivs(newuid, newgid);

  ret = initControl(log, newuid, forks);
  if (ret != 0) {
    return ret;
  }

  {
    auto lci = g_luaconfs.getCopy();
    startLuaConfigDelayedThreads(lci, lci.generation);
  }

  RecThreadInfo::makeThreadPipes(log);

  disableStats(StatComponent::API, ::arg()["stats-api-blacklist"]);
  disableStats(StatComponent::Carbon, ::arg()["stats-carbon-blacklist"]);
  disableStats(StatComponent::RecControl, ::arg()["stats-rec-control-blacklist"]);
  disableStats(StatComponent::SNMP, ::arg()["stats-snmp-blacklist"]);

  disableStats(StatComponent::API, ::arg()["stats-api-disabled-list"]);
  disableStats(StatComponent::Carbon, ::arg()["stats-carbon-disabled-list"]);
  disableStats(StatComponent::RecControl, ::arg()["stats-rec-control-disabled-list"]);
  disableStats(StatComponent::SNMP, ::arg()["stats-snmp-disabled-list"]);

  // Run before any thread doing stats related things
  registerAllStats();

  initSNMP(log);

  ret = initPorts(log);
  if (ret != 0) {
    return ret;
  }

#ifdef NOD_ENABLED
  setupNODThread(log);
#endif /* NOD_ENABLED */

  runStartStopLua(true, log);
  ret = RecThreadInfo::runThreads(log);
  runStartStopLua(false, log);
  return ret;
}

static void handlePipeRequest(int fileDesc, FDMultiplexer::funcparam_t& /* var */)
{
  ThreadMSG* tmsg = nullptr;

  if (read(fileDesc, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) { // fd == readToThread || fd == readQueriesToThread NOLINT: sizeof correct
    unixDie("read from thread pipe returned wrong size or error");
  }

  void* resp = nullptr;
  try {
    resp = tmsg->func();
  }
  catch (const PDNSException& pdnsException) {
    g_rateLimitedLogger.log(g_slog->withName("runtime"), "PIPE function", pdnsException);
  }
  catch (const MOADNSException& moadnsexception) {
    if (g_logCommonErrors) {
      g_slog->withName("runtime")->error(moadnsexception.what(), "PIPE function created an exception", "excepion", Logging::Loggable("MOADNSException"));
    }
  }
  catch (const std::exception& stdException) {
    g_rateLimitedLogger.log(g_slog->withName("runtime"), "PIPE function", stdException);
  }
  catch (...) {
    g_rateLimitedLogger.log(g_slog->withName("runtime"), "PIPE function");
  }
  if (tmsg->wantAnswer) {
    if (write(RecThreadInfo::self().getPipes().writeFromThread, &resp, sizeof(resp)) != sizeof(resp)) {
      delete tmsg; // NOLINT: manual ownership handling
      unixDie("write to thread pipe returned wrong size or error");
    }
  }

  delete tmsg; // NOLINT: manual ownership handling
}

static void handleRCC(int fileDesc, FDMultiplexer::funcparam_t& /* var */)
{
  auto log = g_slog->withName("control");
  try {
    FDWrapper clientfd = accept(fileDesc, nullptr, nullptr);
    if (clientfd == -1) {
      throw PDNSException("accept failed");
    }
    string msg = g_rcc.recv(clientfd).d_str;
    log->info(Logr::Info, "Received rec_control command via control socket", "command", Logging::Loggable(msg));

    RecursorControlParser::func_t* command = nullptr;
    auto answer = RecursorControlParser::getAnswer(clientfd, msg, &command);

    if (command != doExitNicely) {
      g_rcc.send(clientfd, answer);
    }
    command();
    if (command == doExitNicely) {
      g_rcc.send(clientfd, answer);
    }
  }
  catch (const std::exception& e) {
    log->error(Logr::Error, e.what(), "Exception while dealing with control socket request", "exception", Logging::Loggable("std::exception"));
  }
  catch (const PDNSException& ae) {
    log->error(Logr::Error, ae.reason, "Exception while dealing with control socket request", "exception", Logging::Loggable("PDNSException"));
  }
}

class PeriodicTask
{
public:
  PeriodicTask(const string& aName, time_t aTime) :
    period{aTime, 0}, name(aName)
  {
    if (aTime <= 0) {
      throw PDNSException("Invalid period of periodic task " + aName);
    }
  }

  void runIfDue(struct timeval& now, const std::function<void()>& function)
  {
    if (last_run < now - period) {
      function();
      Utility::gettimeofday(&last_run);
      now = last_run;
    }
  }

  [[nodiscard]] time_t getPeriod() const
  {
    return period.tv_sec;
  }

  void setPeriod(time_t newperiod)
  {
    period.tv_sec = newperiod;
  }

  void updateLastRun()
  {
    Utility::gettimeofday(&last_run);
  }

  [[nodiscard]] bool hasRun() const
  {
    return last_run.tv_sec != 0 || last_run.tv_usec != 0;
  }

private:
  struct timeval last_run{
    0, 0};
  struct timeval period;
  string name;
};

static void houseKeepingWork(Logr::log_t log)
{
  struct timeval now{};
  Utility::gettimeofday(&now);
  t_Counters.updateSnap(now, g_regressionTestMode);

  // Below are the tasks that run for every recursorThread, including handler and taskThread

  static thread_local PeriodicTask pruneTCPTask{"pruneTCPTask", 5};
  pruneTCPTask.runIfDue(now, [now]() {
    t_tcp_manager.cleanup(now);
  });

  const auto& info = RecThreadInfo::self();

  // Threads handling packets process config changes in the input path, but not all threads process input packets
  // distr threads only process TCP, so that may not happenn very often. So do all periodically.
  static thread_local PeriodicTask exportConfigTask{"exportConfigTask", 30};
  auto luaconfsLocal = g_luaconfs.getLocal();
  exportConfigTask.runIfDue(now, [&luaconfsLocal]() {
    checkProtobufExport(luaconfsLocal);
    checkOutgoingProtobufExport(luaconfsLocal);
#ifdef HAVE_FSTRM
    checkFrameStreamExport(luaconfsLocal, luaconfsLocal->frameStreamExportConfig, t_frameStreamServersInfo);
    checkFrameStreamExport(luaconfsLocal, luaconfsLocal->nodFrameStreamExportConfig, t_nodFrameStreamServersInfo);
#endif
  });

  // Below are the thread specific tasks for the handler and the taskThread
  // Likley a few handler tasks could be moved to the taskThread
  if (info.isTaskThread()) {
    // TaskQueue is run always
    runTasks(10, g_logCommonErrors);

    static PeriodicTask ztcTask{"ZTC", 60};
    static map<DNSName, RecZoneToCache::State> ztcStates;
    ztcTask.runIfDue(now, [&luaconfsLocal]() {
      RecZoneToCache::maintainStates(luaconfsLocal->ztcConfigs, ztcStates, luaconfsLocal->generation);
      for (const auto& ztc : luaconfsLocal->ztcConfigs) {
        RecZoneToCache::ZoneToCache(ztc.second, ztcStates.at(ztc.first));
      }
    });
  }
  else if (info.isHandler()) {
    if (g_packetCache) {
      static PeriodicTask packetCacheTask{"packetCacheTask", 5};
      packetCacheTask.runIfDue(now, [now]() {
        g_packetCache->doPruneTo(now.tv_sec, g_maxPacketCacheEntries);
      });
    }
    static PeriodicTask recordCachePruneTask{"RecordCachePruneTask", 5};
    recordCachePruneTask.runIfDue(now, [now]() {
      g_recCache->doPrune(now.tv_sec, g_maxCacheEntries);
    });

    static PeriodicTask negCachePruneTask{"NegCachePrunteTask", 5};
    negCachePruneTask.runIfDue(now, [now]() {
      g_negCache->prune(now.tv_sec, g_maxCacheEntries / 8);
    });

    static PeriodicTask aggrNSECPruneTask{"AggrNSECPruneTask", 5};
    aggrNSECPruneTask.runIfDue(now, [now]() {
      if (g_aggressiveNSECCache) {
        g_aggressiveNSECCache->prune(now.tv_sec);
      }
    });

    static PeriodicTask pruneNSpeedTask{"pruneNSSpeedTask", 30};
    pruneNSpeedTask.runIfDue(now, [now]() {
      SyncRes::pruneNSSpeeds(now.tv_sec - 300);
    });

    static PeriodicTask pruneEDNSTask{"pruneEDNSTask", 60};
    pruneEDNSTask.runIfDue(now, [now]() {
      SyncRes::pruneEDNSStatuses(now.tv_sec);
    });

    if (SyncRes::s_max_busy_dot_probes > 0) {
      static PeriodicTask pruneDoTProbeMap{"pruneDoTProbeMapTask", 60};
      pruneDoTProbeMap.runIfDue(now, [now]() {
        SyncRes::pruneDoTProbeMap(now.tv_sec);
      });
    }

    static PeriodicTask pruneThrottledTask{"pruneThrottledTask", 5};
    pruneThrottledTask.runIfDue(now, [now]() {
      SyncRes::pruneThrottledServers(now.tv_sec);
    });

    static PeriodicTask pruneFailedServersTask{"pruneFailedServerTask", 5};
    pruneFailedServersTask.runIfDue(now, [now]() {
      SyncRes::pruneFailedServers(now.tv_sec - static_cast<time_t>(SyncRes::s_serverdownthrottletime * 10));
    });

    static PeriodicTask pruneNonResolvingTask{"pruneNonResolvingTask", 5};
    pruneNonResolvingTask.runIfDue(now, [now]() {
      SyncRes::pruneNonResolving(now.tv_sec - SyncRes::s_nonresolvingnsthrottletime);
    });

    static PeriodicTask pruneSaveParentSetTask{"pruneSaveParentSetTask", 60};
    pruneSaveParentSetTask.runIfDue(now, [now]() {
      SyncRes::pruneSaveParentsNSSets(now.tv_sec);
    });

    static PeriodicTask pruneCookiesTask{"pruneCookiesTask", 30};
    pruneCookiesTask.runIfDue(now, [now]() {
      pruneCookies(now.tv_sec - 3000);
    });

    // By default, refresh at 80% of max-cache-ttl with a minimum period of 10s
    const unsigned int minRootRefreshInterval = 10;
    static PeriodicTask rootUpdateTask{"rootUpdateTask", std::max(SyncRes::s_maxcachettl * 8 / 10, minRootRefreshInterval)};
    rootUpdateTask.runIfDue(now, [now, &log, minRootRefreshInterval]() {
      int res = 0;
      if (!g_regressionTestMode) {
        res = SyncRes::getRootNS(now, nullptr, 0, log);
      }
      if (res == 0) {
        // Success, go back to the defaut period
        rootUpdateTask.setPeriod(std::max(SyncRes::s_maxcachettl * 8 / 10, minRootRefreshInterval));
      }
      else {
        // On failure, go to the middle of the remaining period (initially 80% / 8 = 10%) and shorten the interval on each
        // failure by dividing the existing interval by 8, keeping the minimum interval at 10s.
        // So with a 1 day period and failures we'll see a refresh attempt at 69120, 69120+11520, 69120+11520+1440, ...
        rootUpdateTask.setPeriod(std::max<time_t>(rootUpdateTask.getPeriod() / 8, minRootRefreshInterval));
      }
    });

    static PeriodicTask secpollTask{"secpollTask", 3600};
    static time_t t_last_secpoll;
    secpollTask.runIfDue(now, [&log]() {
      try {
        doSecPoll(&t_last_secpoll, log);
      }
      catch (const std::exception& e) {
        log->error(Logr::Error, e.what(), "Exception while performing security poll");
      }
      catch (const PDNSException& e) {
        log->error(Logr::Error, e.reason, "Exception while performing security poll");
      }
      catch (const ImmediateServFailException& e) {
        log->error(Logr::Error, e.reason, "Exception while performing security poll");
      }
      catch (const PolicyHitException& e) {
        log->info(Logr::Error, "Policy hit while performing security poll");
      }
      catch (...) {
        log->info(Logr::Error, "Exception while performing security poll");
      }
    });

    const time_t taInterval = std::max(1, static_cast<int>(luaconfsLocal->trustAnchorFileInfo.interval) * 3600);
    static PeriodicTask trustAnchorTask{"trustAnchorTask", taInterval};
    if (!trustAnchorTask.hasRun()) {
      // Loading the Lua config file already "refreshed" the TAs
      trustAnchorTask.updateLastRun();
    }
    // interval might have ben updated
    trustAnchorTask.setPeriod(taInterval);
    trustAnchorTask.runIfDue(now, [&luaconfsLocal, &log]() {
      if (!luaconfsLocal->trustAnchorFileInfo.fname.empty() && luaconfsLocal->trustAnchorFileInfo.interval != 0) {
        log->info(Logr::Debug, "Refreshing Trust Anchors from file");
        try {
          map<DNSName, dsset_t> dsAnchors;
          if (updateTrustAnchorsFromFile(luaconfsLocal->trustAnchorFileInfo.fname, dsAnchors, log)) {
            g_luaconfs.modify([&dsAnchors](LuaConfigItems& lci) {
              lci.dsAnchors = dsAnchors;
            });
          }
        }
        catch (const PDNSException& pe) {
          log->error(Logr::Error, pe.reason, "Unable to update Trust Anchors");
        }
      }
    });
  }
  t_Counters.updateSnap(g_regressionTestMode);
}

static void houseKeeping(void* /* ignored */)
{
  auto log = g_slog->withName("housekeeping");
  static thread_local bool t_running; // houseKeeping can get suspended in secpoll, and be restarted, which makes us do duplicate work

  try {
    if (t_running) {
      return;
    }
    t_running = true;
    houseKeepingWork(log);
    t_running = false;
  }
  catch (const PDNSException& ae) {
    t_running = false;
    log->error(Logr::Error, ae.reason, "Fatal error in housekeeping thread");
    throw;
  }
  catch (...) {
    t_running = false;
    log->info(Logr::Error, "Uncaught exception in housekeeping thread");
    throw;
  }
}

static void runLuaMaintenance(RecThreadInfo& threadInfo, time_t& last_lua_maintenance, time_t luaMaintenanceInterval)
{
  if (t_pdl != nullptr) {
    // lua-dns-script directive is present, call the maintenance callback if needed
    if (threadInfo.isWorker()) { // either UDP of TCP worker
      // Only on threads processing queries
      if (g_now.tv_sec - last_lua_maintenance >= luaMaintenanceInterval) {
        struct timeval start{};
        Utility::gettimeofday(&start);
        t_pdl->maintenance();
        last_lua_maintenance = g_now.tv_sec;
        struct timeval stop{};
        Utility::gettimeofday(&stop);
        t_Counters.at(rec::Counter::maintenanceUsec) += uSec(stop - start);
        ++t_Counters.at(rec::Counter::maintenanceCalls);
      }
    }
  }
}

static void recLoop()
{
  time_t last_stat = 0;
  time_t last_carbon = 0;
  time_t last_lua_maintenance = 0;
  time_t carbonInterval = ::arg().asNum("carbon-interval");
  time_t luaMaintenanceInterval = ::arg().asNum("lua-maintenance-interval");

  auto& threadInfo = RecThreadInfo::self();

  while (!RecursorControlChannel::stop) {
    try {
      while (g_multiTasker->schedule(g_now)) {
        ; // MTasker letting the mthreads do their thing
      }

      // Use primes, it avoid not being scheduled in cases where the counter has a regular pattern.
      // We want to call handler thread often, it gets scheduled about 2 times per second
      if (((threadInfo.isHandler() || threadInfo.isTaskThread()) && s_counter % 11 == 0) || s_counter % 499 == 0) {
        timeval start{};
        Utility::gettimeofday(&start);
        g_multiTasker->makeThread(houseKeeping, nullptr);
        if (!threadInfo.isTaskThread()) {
          timeval stop{};
          Utility::gettimeofday(&stop);
          t_Counters.at(rec::Counter::maintenanceUsec) += uSec(stop - start);
          ++t_Counters.at(rec::Counter::maintenanceCalls);
        }
      }

      if (s_counter % 55 == 0) {
        auto expired = t_fdm->getTimeouts(g_now);

        for (const auto& exp : expired) {
          auto conn = boost::any_cast<shared_ptr<TCPConnection>>(exp.second);
          if (g_logCommonErrors) {
            g_slogtcpin->info(Logr::Warning, "Timeout from remote TCP client", "remote", Logging::Loggable(conn->d_remote));
          }
          t_fdm->removeReadFD(exp.first);
        }
      }

      s_counter++;

      if (threadInfo.isHandler()) {
        if (statsWanted || (s_statisticsInterval > 0 && (g_now.tv_sec - last_stat) >= s_statisticsInterval)) {
          doStats();
          last_stat = g_now.tv_sec;
        }

        Utility::gettimeofday(&g_now, nullptr);

        if ((g_now.tv_sec - last_carbon) >= carbonInterval) {
          g_multiTasker->makeThread(doCarbonDump, nullptr);
          last_carbon = g_now.tv_sec;
        }
      }
      runLuaMaintenance(threadInfo, last_lua_maintenance, luaMaintenanceInterval);

      auto timeoutUsec = g_multiTasker->nextWaiterDelayUsec(500000);
      t_fdm->run(&g_now, static_cast<int>(timeoutUsec / 1000));
      // 'run' updates g_now for us
    }
    catch (const PDNSException& pdnsException) {
      g_rateLimitedLogger.log(g_slog->withName("runtime"), "recLoop", pdnsException);
    }
    catch (const std::exception& stdException) {
      g_rateLimitedLogger.log(g_slog->withName("runtime"), "recLoop", stdException);
    }
    catch (...) {
      g_rateLimitedLogger.log(g_slog->withName("runtime"), "recLoop");
    }
  }
}

static void recursorThread()
{
  auto log = g_slog->withName("runtime");
  t_Counters.updateSnap(true);
  try {
    auto& threadInfo = RecThreadInfo::self();
    {
      SyncRes tmp(g_now); // make sure it allocates tsstorage before we do anything, like primeHints or so..
      SyncRes::setDomainMap(*g_initialDomainMap.lock());
      t_allowFrom = *g_initialAllowFrom.lock();
      t_allowNotifyFrom = *g_initialAllowNotifyFrom.lock();
      t_allowNotifyFor = *g_initialAllowNotifyFor.lock();
      t_proxyProtocolACL = g_initialProxyProtocolACL;
      t_proxyProtocolExceptions = g_initialProxyProtocolExceptions;
      t_udpclientsocks = std::make_unique<UDPClientSocks>();
      if (g_proxyMapping) {
        t_proxyMapping = make_unique<ProxyMapping>(*g_proxyMapping);
      }
      else {
        t_proxyMapping = nullptr;
      }

      if (threadInfo.isHandler()) {
        if (!primeHints()) {
          threadInfo.setExitCode(EXIT_FAILURE);
          RecursorControlChannel::stop = true;
          log->info(Logr::Critical, "Priming cache failed, stopping");
        }
        log->info(Logr::Debug, "Done priming cache with root hints");
      }
    }

    /* the listener threads handle TCP queries */
    if (threadInfo.isWorker() || threadInfo.isListener()) {
      try {
        if (!::arg()["lua-dns-script"].empty()) {
          t_pdl = std::make_shared<RecursorLua4>();
          t_pdl->loadFile(::arg()["lua-dns-script"]);
          log->info(Logr::Warning, "Loading Lua script from file", "name", Logging::Loggable(::arg()["lua-dns-script"]));
        }
      }
      catch (std::exception& e) {
        log->error(Logr::Error, e.what(), "Failed to load Lua script from file", "name", Logging::Loggable(::arg()["lua-dns-script"]));
        _exit(99);
      }
    }

    if (unsigned int ringsize = ::arg().asNum("stats-ringbuffer-entries") / RecThreadInfo::numUDPWorkers(); ringsize != 0) {
      t_remotes = std::make_unique<addrringbuf_t>();
      if (RecThreadInfo::weDistributeQueries()) {
        t_remotes->set_capacity(::arg().asNum("stats-ringbuffer-entries") / RecThreadInfo::numDistributors());
      }
      else {
        t_remotes->set_capacity(ringsize);
      }
      t_servfailremotes = std::make_unique<addrringbuf_t>();
      t_servfailremotes->set_capacity(ringsize);
      t_bogusremotes = std::make_unique<addrringbuf_t>();
      t_bogusremotes->set_capacity(ringsize);
      t_largeanswerremotes = std::make_unique<addrringbuf_t>();
      t_largeanswerremotes->set_capacity(ringsize);
      t_timeouts = std::make_unique<addrringbuf_t>();
      t_timeouts->set_capacity(ringsize);

      t_queryring = std::make_unique<boost::circular_buffer<pair<DNSName, uint16_t>>>();
      t_queryring->set_capacity(ringsize);
      t_servfailqueryring = std::make_unique<boost::circular_buffer<pair<DNSName, uint16_t>>>();
      t_servfailqueryring->set_capacity(ringsize);
      t_bogusqueryring = std::make_unique<boost::circular_buffer<pair<DNSName, uint16_t>>>();
      t_bogusqueryring->set_capacity(ringsize);
    }
    g_multiTasker = std::make_unique<MT_t>(::arg().asNum("stack-size"), ::arg().asNum("stack-cache-size"));
    threadInfo.setMT(g_multiTasker.get());

    {
      /* start protobuf export threads if needed, don't keep a ref to lua config around */
      auto luaconfsLocal = g_luaconfs.getLocal();
      checkProtobufExport(luaconfsLocal);
      checkOutgoingProtobufExport(luaconfsLocal);
#ifdef HAVE_FSTRM
      checkFrameStreamExport(luaconfsLocal, luaconfsLocal->frameStreamExportConfig, t_frameStreamServersInfo);
      checkFrameStreamExport(luaconfsLocal, luaconfsLocal->nodFrameStreamExportConfig, t_nodFrameStreamServersInfo);
#endif
      for (const auto& rpz : luaconfsLocal->rpzs) {
        string name = rpz.polName.empty() ? (rpz.zoneXFRParams.primaries.empty() ? "rpzFile" : rpz.zoneXFRParams.name) : rpz.polName;
        t_Counters.at(rec::PolicyNameHits::policyName).counts[name] = 0;
      }
    }

    t_fdm = unique_ptr<FDMultiplexer>(getMultiplexer(log));
    t_fdm->addReadFD(threadInfo.getPipes().readToThread, handlePipeRequest);

    if (threadInfo.isHandler()) {
      log->info(Logr::Info, "Enabled multiplexer", "name", Logging::Loggable(t_fdm->getName()));
    }
    else {
      t_fdm->addReadFD(threadInfo.getPipes().readQueriesToThread, handlePipeRequest);

      if (threadInfo.isListener()) {
        if (g_reusePort) {
          /* then every listener has its own FDs */
          for (const auto& deferred : threadInfo.getDeferredAdds()) {
            t_fdm->addReadFD(deferred.first, deferred.second);
          }
        }
        else {
          /* otherwise all listeners are listening on the same ones */
          for (const auto& deferred : threadInfo.isTCPListener() ? s_deferredTCPadds : s_deferredUDPadds) {
            t_fdm->addReadFD(deferred.first, deferred.second);
          }
        }
      }
    }

    if (threadInfo.isHandler()) {
      t_fdm->addReadFD(g_rcc.getDescriptor(), handleRCC); // control channel
    }

#ifdef HAVE_SYSTEMD
    if (threadInfo.isHandler()) {
      // There is a race, as some threads might not be ready yet to do work.
      // To solve that, threads should notify RecThreadInfo they are done initializing.
      // But we lack a mechanism for that at this point in time.
      sd_notify(0, "READY=1");
    }
#endif

    recLoop();
  }
  catch (const PDNSException& ae) {
    log->error(Logr::Error, ae.reason, "Exception in RecursorThread", "exception", Logging::Loggable("PDNSException"));
  }
  catch (const std::exception& e) {
    log->error(Logr::Error, e.what(), "Exception in RecursorThread", "exception", Logging::Loggable("std::exception"));
  }
  catch (...) {
    log->info(Logr::Error, "Exception in RecursorThread");
  }
}

static pair<int, bool> doYamlConfig(int argc, char* argv[], const pdns::rust::settings::rec::Recursorsettings& settings) // NOLINT: Posix API
{
  if (!::arg().mustDo("config")) {
    return {0, false};
  }
  const string config = ::arg()["config"];
  if (config == "diff" || config.empty()) {
    ::arg().parse(argc, argv);
    ProxyMapping proxyMapping;
    LuaConfigItems lci;
    pdns::settings::rec::fromBridgeStructToLuaConfig(settings, lci, proxyMapping);
    auto yaml = settings.to_yaml_string();
    cout << yaml << endl;
  }
  else if (config == "default") {
    auto yaml = pdns::settings::rec::defaultsToYaml();
    cout << yaml << endl;
  }
  else if (config == "check") {
    // Kinda redundant, if we came here we already read and checked the config....x
  }
  return {0, true};
}

static pair<int, bool> doConfig(Logr::log_t startupLog, const string& configname, int argc, char* argv[]) // NOLINT: Posix API
{
  if (::arg().mustDo("config")) {
    string config = ::arg()["config"];
    if (config == "check") {
      try {
        if (!::arg().file(configname)) {
          startupLog->error("No such file", "Unable to open configuration file", "config_file", Logging::Loggable(configname));
          return {1, true};
        }
        ::arg().parse(argc, argv);
        return {0, true};
      }
      catch (const ArgException& argException) {
        startupLog->error("Cannot parse configuration", "Unable to parse configuration file", "config_file", Logging::Loggable(configname), "reason", Logging::Loggable(argException.reason));
        return {1, true};
      }
    }
    else if (config == "default" || config.empty()) {
      auto yaml = pdns::settings::rec::defaultsToYaml();
      cout << yaml << endl;
    }
    else if (config == "diff") {
      if (!::arg().laxFile(configname)) {
        startupLog->error("No such file", "Unable to open configuration file", "config_file", Logging::Loggable(configname));
        return {1, true};
      }
      ::arg().laxParse(argc, argv);
      cout << ::arg().configstring(true, false);
    }
    else {
      if (!::arg().laxFile(configname)) {
        startupLog->error("No such file", "Unable to open configuration file", "config_file", Logging::Loggable(configname));
        return {1, true};
      }
      ::arg().laxParse(argc, argv);
      cout << ::arg().configstring(true, true);
    }
    return {0, true};
  }
  return {0, false};
}

LockGuarded<pdns::rust::settings::rec::Recursorsettings> g_yamlStruct;

static void runStartStopLua(bool start, Logr::log_t log)
{
  auto settings = g_yamlStruct.lock();
  const auto& script = settings->recursor.lua_start_stop_script;
  if (script.empty()) {
    return;
  }
  auto lua = std::make_shared<RecursorLua4>();
  lua->runStartStopFunction(std::string(script), start, log);
}

static void handleRuntimeDefaults(Logr::log_t log)
{
#ifdef HAVE_FIBER_SANITIZER
  // Asan needs more stack
  if (::arg().asNum("stack-size") == 200000) { // the default in table.py
    ::arg().set("stack-size", "stack size per mthread") = "600000";
  }
#endif

  const string RUNTIME = "*runtime determined*";
  if (::arg()["version-string"] == RUNTIME) { // i.e. not set explicitly
    ::arg().set("version-string") = fullVersionString();
  }

  if (::arg()["server-id"] == RUNTIME) { // i.e. not set explicitly
    auto myHostname = getHostname();
    if (!myHostname.has_value()) {
      log->info(Logr::Warning, "Unable to get the hostname, NSID and id.server values will be empty");
    }
    ::arg().set("server-id") = myHostname.has_value() ? *myHostname : "";
  }

  if (::arg()["socket-dir"].empty()) {
    auto* runtimeDir = getenv("RUNTIME_DIRECTORY"); // NOLINT(concurrency-mt-unsafe,cppcoreguidelines-pro-type-vararg)
    if (runtimeDir != nullptr) {
      ::arg().set("socket-dir") = runtimeDir;
    }
  }

  if (::arg()["socket-dir"].empty()) {
    if (::arg()["chroot"].empty()) {
      ::arg().set("socket-dir") = std::string(LOCALSTATEDIR) + "/pdns-recursor";
    }
    else {
      ::arg().set("socket-dir") = "/";
    }
  }

  if (::arg().asNum("threads") == 1) {
    if (::arg().mustDo("pdns-distributes-queries")) {
      log->info(Logr::Warning, "Only one thread, no need to distribute queries ourselves");
      ::arg().set("pdns-distributes-queries") = "no";
    }
  }

  if (::arg().mustDo("pdns-distributes-queries") && ::arg().asNum("distributor-threads") == 0) {
    log->info(Logr::Warning, "Asked to run with pdns-distributes-queries set but no distributor threads, raising to 1");
    ::arg().set("distributor-threads") = "1";
  }

  if (!::arg().mustDo("pdns-distributes-queries") && ::arg().asNum("distributor-threads") > 0) {
    log->info(Logr::Warning, "Not distributing queries, setting distributor threads to 0");
    ::arg().set("distributor-threads") = "0";
  }
}

static void setupLogging(const string& logname)
{
  if (logname == "systemd-journal") {
#ifdef HAVE_SYSTEMD
    if (int fileDesc = sd_journal_stream_fd("pdns-recusor", LOG_DEBUG, 0); fileDesc >= 0) {
      g_slog = Logging::Logger::create(loggerSDBackend);
      close(fileDesc);
    }
#endif
    if (g_slog == nullptr) {
      cerr << "Requested structured logging to systemd-journal, but it is not available" << endl;
    }
  }
  else if (logname == "json") {
    g_slog = Logging::Logger::create(loggerJSONBackend);
    if (g_slog == nullptr) {
      cerr << "JSON logging requested but it is not available" << endl;
    }
  }

  if (g_slog == nullptr) {
    g_slog = Logging::Logger::create(loggerBackend);
  }
}

DoneRunning g_doneRunning;

int main(int argc, char** argv)
{
  g_argc = argc;
  g_argv = argv;
  versionSetProduct(ProductRecursor);
  reportAllTypes();

  int ret = EXIT_SUCCESS;

  try {
    pdns::settings::rec::defineOldStyleSettings();
    ::arg().setDefaults();
    g_log.toConsole(Logger::Info);
    ::arg().laxParse(argc, argv); // do a lax parse

    if (::arg().mustDo("version")) {
      cout << getProductVersion();
      cout << getBuildConfiguration();
      return 0;
    }
    if (::arg().mustDo("help")) {
      cout << "syntax:" << endl
           << endl;
      cout << ::arg().helpstring(::arg()["help"]) << endl;
      return 0;
    }

    // Pick up options given on command line to setup logging asap.
    g_quiet = ::arg().mustDo("quiet");
    s_logUrgency = (Logger::Urgency)::arg().asNum("loglevel");
    s_structured_logger_backend = ::arg()["structured-logging-backend"];

    if (!g_quiet && s_logUrgency < Logger::Info) { // Logger::Info=6, Logger::Debug=7
      s_logUrgency = Logger::Info; // if you do --quiet=no, you need Info to also see the query log
    }
    g_log.setLoglevel(s_logUrgency);
    g_log.toConsole(s_logUrgency);

    for (const string& line : getProductVersionLines()) {
      g_log << Logger::Info << line << endl;
    }
    if (!::arg().mustDo("structured-logging")) {
      g_log << Logger::Error << "Disabling structured logging is not supported anymore" << endl;
    }

    g_yamlSettings = false;
    string configname = ::arg()["config-dir"] + "/recursor";
    if (!::arg()["config-name"].empty()) {
      configname = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"];
      g_programname += "-" + ::arg()["config-name"];
    }
    cleanSlashes(configname);

    if (!::arg().getCommands().empty()) {
      cerr << "Fatal: non-option";
      if (::arg().getCommands().size() > 1) {
        cerr << "s";
      }
      cerr << " (";
      bool first = true;
      for (const auto& command : ::arg().getCommands()) {
        if (!first) {
          cerr << ", ";
        }
        first = false;
        cerr << command;
      }
      cerr << ") on the command line, perhaps a '--setting=123' statement missed the '='?" << endl;
      return 99;
    }

    setupLogging(s_structured_logger_backend);

    // Missing: a mechanism to call setVerbosity(x)
    auto startupLog = g_slog->withName("config");
    g_slogtcpin = g_slog->withName("in")->withValues("proto", Logging::Loggable("tcp"));
    g_slogudpin = g_slog->withName("in")->withValues("proto", Logging::Loggable("udp"));
    g_slogout = g_slog->withName("out");

    ::arg().setSLog(startupLog);

    string yamlconfigname;
    pdns::rust::settings::rec::Recursorsettings settings;
    pdns::settings::rec::YamlSettingsStatus yamlstatus{};

    for (const string suffix : {".yml", ".conf"}) {
      yamlconfigname = configname + suffix;
      yamlstatus = pdns::settings::rec::tryReadYAML(yamlconfigname, true, g_yamlSettings, g_luaSettingsInYAML, settings, startupLog);
      if (yamlstatus == pdns::settings::rec::YamlSettingsStatus::OK) {
        g_yamlSettingsSuffix = suffix;
        break;
      }
      if (suffix == ".yml" && yamlstatus == pdns::settings::rec::PresentButFailed) {
        return 1;
      }
    }

    if (g_yamlSettings) {
      bool mustExit = false;
      std::tie(ret, mustExit) = doYamlConfig(argc, argv, settings);
      if (ret != 0 || mustExit) {
        return ret;
      }
    }
    if (yamlstatus == pdns::settings::rec::YamlSettingsStatus::OK) {
      auto lock = g_yamlStruct.lock();
      *lock = std::move(settings);
    }
    else {
      configname += ".conf";
      startupLog->info(Logr::Warning, "Trying to read YAML from .yml or .conf failed, falling back to old-style config read", "configname", Logging::Loggable(configname));
      bool mustExit = false;
      std::tie(ret, mustExit) = doConfig(startupLog, configname, argc, argv);
      if (ret != 0 || mustExit) {
        return ret;
      }
      if (!::arg().file(configname)) {
        startupLog->error("No such file", "Unable to open configuration file", "config_file", Logging::Loggable(configname));
      }
      else {
        if (!::arg().mustDo("enable-old-settings")) {
          startupLog->info(Logr::Error, "Old-style settings syntax not supported by default anymore", "configname", Logging::Loggable(configname));
          startupLog->info(Logr::Error, "Convert to YAML settings. If not feasible use --enable-old-settings on the command line. This option will be removed in a future release.");
          return EXIT_FAILURE;
        }
        startupLog->info(Logr::Warning, "Convert to YAML settings. The --enable-old-settings option on the command line will be removed in a future release.");
      }
    }

    // Reparse, now with config file as well, both for old-style as for YAML settings
    ::arg().parse(argc, argv);

    g_quiet = ::arg().mustDo("quiet");
    s_logUrgency = (Logger::Urgency)::arg().asNum("loglevel");

    if (s_logUrgency < Logger::Error) {
      s_logUrgency = Logger::Error;
    }
    if (!g_quiet && s_logUrgency < Logger::Info) { // Logger::Info=6, Logger::Debug=7
      s_logUrgency = Logger::Info; // if you do --quiet=no, you need Info to also see the query log
    }
    g_log.setLoglevel(s_logUrgency);
    g_log.toConsole(s_logUrgency);

    if (!::arg()["chroot"].empty() && !::arg()["api-config-dir"].empty()) {
      startupLog->info(Logr::Error, "Cannot use chroot and enable the API at the same time");
      return EXIT_FAILURE;
    }

    handleRuntimeDefaults(startupLog);

    if (auto ttl = ::arg().asNum("system-resolver-ttl"); ttl != 0) {
      time_t interval = ttl;
      if (::arg().asNum("system-resolver-interval") != 0) {
        interval = ::arg().asNum("system-resolver-interval");
      }
      bool selfResolveCheck = ::arg().mustDo("system-resolver-self-resolve-check");
      // Cannot use SyncRes::s_serverID, it is not set yet
      pdns::RecResolve::setInstanceParameters(arg()["server-id"], ttl, interval, selfResolveCheck, []() { reloadZoneConfiguration(g_yamlSettings); });
    }

    g_recCache = std::make_unique<MemRecursorCache>(::arg().asNum("record-cache-shards"));
    g_negCache = std::make_unique<NegCache>(::arg().asNum("record-cache-shards") / 8);
    if (!::arg().mustDo("disable-packetcache")) {
      g_maxPacketCacheEntries = ::arg().asNum("max-packetcache-entries");
      g_packetCache = std::make_unique<RecursorPacketCache>(g_maxPacketCacheEntries, ::arg().asNum("packetcache-shards"));
    }

    ret = serviceMain(startupLog);
    {
      std::scoped_lock lock(g_doneRunning.mutex);
      g_doneRunning.done = true;
      g_doneRunning.condVar.notify_one();
    }
    RecThreadInfo::joinThread0();
  }
  catch (const PDNSException& ae) {
    g_slog->withName("config")->error(Logr::Critical, ae.reason, "Fatal error", "exception", Logging::Loggable("PDNSException"));
    ret = EXIT_FAILURE;
  }
  catch (const std::exception& e) {
    g_slog->withName("config")->error(Logr::Critical, e.what(), "Fatal error", "exception", Logging::Loggable("std::exception"));
    ret = EXIT_FAILURE;
  }
  catch (...) {
    g_slog->withName("config")->info(Logr::Critical, "Fatal error");
    ret = EXIT_FAILURE;
  }

  return ret;
}

static RecursorControlChannel::Answer* doReloadLuaScript()
{
  string fname = ::arg()["lua-dns-script"];
  auto log = g_slog->withName("runtime")->withValues("name", Logging::Loggable(fname));
  try {
    if (fname.empty()) {
      t_pdl.reset();
      log->info(Logr::Info, "Unloaded current lua script");
      return new RecursorControlChannel::Answer{0, string("unloaded\n")};
    }

    t_pdl = std::make_shared<RecursorLua4>();
    try {
      t_pdl->loadFile(fname);
    }
    catch (std::runtime_error& ex) {
      string msg = std::to_string(RecThreadInfo::thread_local_id()) + " Retaining current script, could not read '" + fname + "': " + ex.what();
      log->error(Logr::Error, ex.what(), "Retaining current script, could not read new script");
      return new RecursorControlChannel::Answer{1, msg + "\n"};
    }
  }
  catch (std::exception& e) {
    log->error(Logr::Error, e.what(), "Retaining current script, error in new script");
    return new RecursorControlChannel::Answer{1, string("retaining current script, error from '" + fname + "': " + e.what() + "\n")};
  }

  log->info(Logr::Warning, "(Re)loaded lua script");
  return new RecursorControlChannel::Answer{0, string("(re)loaded '" + fname + "'\n")};
}

RecursorControlChannel::Answer doQueueReloadLuaScript(vector<string>::const_iterator begin, vector<string>::const_iterator end)
{
  if (begin != end) {
    ::arg().set("lua-dns-script") = *begin;
  }

  return broadcastAccFunction<RecursorControlChannel::Answer>(doReloadLuaScript);
}

static string* pleaseUseNewTraceRegex(const std::string& newRegex, int file)
{
  try {
    if (newRegex.empty()) {
      t_traceRegex.reset();
      t_tracefd = FDWrapper();
      return new string("unset\n");
    }
    if (file == -1) {
      return new string("could not dup file\n");
    }
    t_traceRegex = std::make_shared<Regex>(newRegex);
    t_tracefd = file;
    return new string("ok\n"); // NOLINT(cppcoreguidelines-owning-memory): it's the API
  }
  catch (const PDNSException& ae) {
    return new string(ae.reason + "\n"); // NOLINT(cppcoreguidelines-owning-memory): it's the API
  }
}

string doTraceRegex(FDWrapper file, vector<string>::const_iterator begin, vector<string>::const_iterator end)
{
  int fileno = dup(file);
  // Potential dup failure handled in pleaseUseNewTraceRegex()
  return broadcastAccFunction<string>([=] { return pleaseUseNewTraceRegex(begin != end ? *begin : "", fileno); });
}

struct WipeCacheResult wipeCaches(const DNSName& canon, bool subtree, uint16_t qtype)
{
  struct WipeCacheResult res;

  try {
    res.record_count = static_cast<int>(g_recCache->doWipeCache(canon, subtree, qtype));
    // scanbuild complains here about an allocated function object that is being leaked. Needs investigation
    if (g_packetCache) {
      res.packet_count = static_cast<int>(g_packetCache->doWipePacketCache(canon, qtype, subtree));
    }
    res.negative_record_count = static_cast<int>(g_negCache->wipe(canon, subtree));
    if (g_aggressiveNSECCache) {
      g_aggressiveNSECCache->removeZoneInfo(canon, subtree);
    }
  }
  catch (const std::exception& e) {
    auto log = g_slog->withName("runtime");
    log->error(Logr::Warning, e.what(), "Wipecache failed");
  }

  return res;
}

void startLuaConfigDelayedThreads(const LuaConfigItems& luaConfig, uint64_t generation)
{
  for (const auto& rpzPrimary : luaConfig.rpzs) {
    if (rpzPrimary.zoneXFRParams.primaries.empty()) {
      continue;
    }
    try {
      // RPZIXTracker uses call by value for its args. That is essential, since we want copies so
      // that RPZIXFRTracker gets values with the proper lifetime.
      std::thread theThread(RPZIXFRTracker, rpzPrimary, generation);
      theThread.detach();
    }
    catch (const std::exception& e) {
      g_slog->withName("rpz")->error(Logr::Error, e.what(), "Exception starting RPZIXFRTracker thread", "exception", Logging::Loggable("std::exception"));
      exit(1); // NOLINT(concurrency-mt-unsafe)
    }
    catch (const PDNSException& e) {
      g_slog->withName("rpz")->error(Logr::Error, e.reason, "Exception starting RPZIXFRTracker thread", "exception", Logging::Loggable("PDNSException"));
      exit(1); // NOLINT(concurrency-mt-unsafe)
    }
  }
  for (const auto& fcz : luaConfig.catalogzones) {
    if (fcz.d_params.primaries.empty()) {
      continue;
    }
    try {
      // ZoneXFRTracker uses call by value for its args. That is essential, since we want copies so
      // that ZoneXFRTracker gets values with the proper lifetime.
      std::thread theThread(FWCatZoneXFR::zoneXFRTracker, fcz.d_params, generation);
      theThread.detach();
    }
    catch (const std::exception& e) {
      g_slog->withName("zone")->error(Logr::Error, e.what(), "Exception starting ZoneXFRTracker thread", "exception", Logging::Loggable("std::exception"));
      exit(1); // NOLINT(concurrency-mt-unsafe)
    }
    catch (const PDNSException& e) {
      g_slog->withName("zone")->error(Logr::Error, e.reason, "Exception starting ZoneXFRTracker thread", "exception", Logging::Loggable("PDNSException"));
      exit(1); // NOLINT(concurrency-mt-unsafe)
    }
  }
}

static void* pleaseInitPolCounts(const string& name)
{
  if (t_Counters.at(rec::PolicyNameHits::policyName).counts.count(name) == 0) {
    t_Counters.at(rec::PolicyNameHits::policyName).counts[name] = 0;
  }
  return nullptr;
}

static bool activateRPZFile(const RPZTrackerParams& params, LuaConfigItems& lci, shared_ptr<DNSFilterEngine::Zone>& zone)
{
  auto log = lci.d_slog->withValues("file", Logging::Loggable(params.zoneXFRParams.name));

  zone->setName(params.polName.empty() ? "rpzFile" : params.polName);
  try {
    log->info(Logr::Info, "Loading RPZ from file");
    loadRPZFromFile(params.zoneXFRParams.name, zone, params.defpol, params.defpolOverrideLocal, params.maxTTL);
    log->info(Logr::Info, "Done loading RPZ from file");
  }
  catch (const std::exception& e) {
    log->error(Logr::Error, e.what(), "Exception while loading RPZ zone from file");
    zone->clear();
    return false;
  }
  return true;
}

static void activateRPZPrimary(RPZTrackerParams& params, LuaConfigItems& lci, shared_ptr<DNSFilterEngine::Zone>& zone, const DNSName& domain)
{
  auto log = lci.d_slog->withValues("seedfile", Logging::Loggable(params.seedFileName), "zone", Logging::Loggable(params.zoneXFRParams.name));

  if (!params.seedFileName.empty()) {
    log->info(Logr::Info, "Pre-loading RPZ zone from seed file");
    try {
      params.zoneXFRParams.soaRecordContent = loadRPZFromFile(params.seedFileName, zone, params.defpol, params.defpolOverrideLocal, params.maxTTL);

      if (zone->getDomain() != domain) {
        throw PDNSException("The RPZ zone " + params.zoneXFRParams.name + " loaded from the seed file (" + zone->getDomain().toString() + ") does not match the one passed in parameter (" + domain.toString() + ")");
      }

      if (params.zoneXFRParams.soaRecordContent == nullptr) {
        throw PDNSException("The RPZ zone " + params.zoneXFRParams.name + " loaded from the seed file (" + zone->getDomain().toString() + ") has no SOA record");
      }
    }
    catch (const PDNSException& e) {
      log->error(Logr::Warning, e.reason, "Exception while pre-loading RPZ zone", "exception", Logging::Loggable("PDNSException"));
      zone->clear();
    }
    catch (const std::exception& e) {
      log->error(Logr::Warning, e.what(), "Exception while pre-loading RPZ zone", "exception", Logging::Loggable("std::exception"));
      zone->clear();
    }
  }
}

static void activateRPZs(LuaConfigItems& lci)
{
  for (auto& params : lci.rpzs) {
    auto zone = std::make_shared<DNSFilterEngine::Zone>();
    if (params.zoneXFRParams.zoneSizeHint != 0) {
      zone->reserve(params.zoneXFRParams.zoneSizeHint);
    }
    if (!params.tags.empty()) {
      std::unordered_set<std::string> tags;
      for (const auto& tag : params.tags) {
        tags.emplace(tag);
      }
      zone->setTags(tags);
    }
    zone->setPolicyOverridesGettag(params.defpolOverrideLocal);
    if (params.extendedErrorCode != std::numeric_limits<uint32_t>::max()) {
      zone->setExtendedErrorCode(params.extendedErrorCode);
      if (!params.extendedErrorExtra.empty()) {
        zone->setExtendedErrorExtra(params.extendedErrorExtra);
      }
    }
    zone->setIncludeSOA(params.includeSOA);
    zone->setIgnoreDuplicates(params.ignoreDuplicates);

    if (params.zoneXFRParams.primaries.empty()) {
      if (activateRPZFile(params, lci, zone)) {
        lci.dfe.addZone(zone);
      }
    }
    else {
      DNSName domain(params.zoneXFRParams.name);
      zone->setDomain(domain);
      zone->setName(params.polName.empty() ? params.zoneXFRParams.name : params.polName);
      params.zoneXFRParams.zoneIdx = lci.dfe.addZone(zone);
      activateRPZPrimary(params, lci, zone, domain);
    }
    broadcastFunction([name = zone->getName()] { return pleaseInitPolCounts(name); });
  }
}

static void activateForwardingCatalogZones(LuaConfigItems& lci)
{
  size_t idx = 0;
  for (auto& fcz : lci.catalogzones) {

    auto& params = fcz.d_params;
    params.zoneIdx = idx++;
    auto zone = std::make_shared<CatalogZone>();
    // zoneSizeHint ignored
    zone->setName(DNSName(params.name));
    fcz.d_catz = std::move(zone);
  }
}

void activateLuaConfig(LuaConfigItems& lci)
{
  if (!lci.trustAnchorFileInfo.fname.empty()) {
    warnIfDNSSECDisabled("Warning: reading Trust Anchors from file, but dnssec is set to 'off'!");
    updateTrustAnchorsFromFile(lci.trustAnchorFileInfo.fname, lci.dsAnchors, lci.d_slog);
  }
  if (lci.dsAnchors.size() > rootDSs.size()) {
    warnIfDNSSECDisabled("Warning: adding Trust Anchor for DNSSEC, but dnssec is set to 'off'!");
  }
  if (!lci.negAnchors.empty()) {
    warnIfDNSSECDisabled("Warning: adding Negative Trust Anchor for DNSSEC, but dnssec is set to 'off'!");
  }
  activateRPZs(lci);
  activateForwardingCatalogZones(lci);
  g_luaconfs.setState(lci);
}
