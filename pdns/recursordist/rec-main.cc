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

#ifdef NOD_ENABLED
#include "nod.hh"
#endif /* NOD_ENABLED */

#ifdef HAVE_LIBSODIUM
#include <sodium.h>

#include <cstddef>
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

string g_programname = "pdns_recursor";
string g_pidfname;
RecursorControlChannel g_rcc; // only active in the handler thread
bool g_regressionTestMode;

#ifdef NOD_ENABLED
bool g_nodEnabled;
DNSName g_nodLookupDomain;
bool g_nodLog;
SuffixMatchNode g_nodDomainWL;
std::string g_nod_pbtag;
bool g_udrEnabled;
bool g_udrLog;
std::string g_udr_pbtag;
thread_local std::shared_ptr<nod::NODDB> t_nodDBp;
thread_local std::shared_ptr<nod::UniqueResponseDB> t_udrDBp;
#endif /* NOD_ENABLED */

std::atomic<bool> statsWanted;
uint32_t g_disthashseed;
bool g_useIncomingECS;
NetmaskGroup g_proxyProtocolACL;
boost::optional<ComboAddress> g_dns64Prefix{boost::none};
DNSName g_dns64PrefixReverse;
std::shared_ptr<SyncRes::domainmap_t> g_initialDomainMap; // new threads needs this to be setup
std::shared_ptr<NetmaskGroup> g_initialAllowFrom; // new thread needs to be setup with this
std::shared_ptr<NetmaskGroup> g_initialAllowNotifyFrom; // new threads need this to be setup
std::shared_ptr<notifyset_t> g_initialAllowNotifyFor; // new threads need this to be setup
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
deferredAdd_t g_deferredAdds;

/* first we have the handler thread, t_id == 0 (some other
   helper threads like SNMP might have t_id == 0 as well)
   then the distributor threads if any
   and finally the workers */
std::vector<RecThreadInfo> RecThreadInfo::s_threadInfos;

std::unique_ptr<ProxyMapping> g_proxyMapping; // new threads needs this to be setup
thread_local std::unique_ptr<ProxyMapping> t_proxyMapping;

bool RecThreadInfo::s_weDistributeQueries; // if true, 1 or more threads listen on the incoming query sockets and distribute them to workers
unsigned int RecThreadInfo::s_numDistributorThreads;
unsigned int RecThreadInfo::s_numWorkerThreads;
thread_local unsigned int RecThreadInfo::t_id;

static std::map<unsigned int, std::set<int>> parseCPUMap(Logr::log_t log)
{
  std::map<unsigned int, std::set<int>> result;

  const std::string value = ::arg()["cpu-map"];

  if (!value.empty() && !isSettingThreadCPUAffinitySupported()) {
    SLOG(g_log << Logger::Warning << "CPU mapping requested but not supported, skipping" << endl,
         log->info(Logr::Warning, "CPU mapping requested but not supported, skipping"));
    return result;
  }

  std::vector<std::string> parts;

  stringtok(parts, value, " \t");

  for (const auto& part : parts) {
    if (part.find('=') == string::npos)
      continue;

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
      SLOG(g_log << Logger::Error << "Error parsing cpu-map entry '" << part << "': " << e.what() << endl,
           log->error(Logr::Error, e.what(), "Error parsing cpu-map entry", "entry", Logging::Loggable(part)));
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
  int rc = mapThreadToCPUList(tid, cpuMapping->second);
  if (rc == 0) {
    if (!g_slogStructured) {
      g_log << Logger::Info << "CPU affinity for thread " << n << " has been set to CPU map:";
      for (const auto cpu : cpuMapping->second) {
        g_log << Logger::Info << " " << cpu;
      }
      g_log << Logger::Info << endl;
    }
    else {
      log->info(Logr::Info, "CPU affinity has been set", "thread", Logging::Loggable(n), "cpumap", Logging::IterLoggable(cpuMapping->second.begin(), cpuMapping->second.end()));
    }
  }
  else {
    if (!g_slogStructured) {
      g_log << Logger::Warning << "Error setting CPU affinity for thread " << n << " to CPU map:";
      for (const auto cpu : cpuMapping->second) {
        g_log << Logger::Info << " " << cpu;
      }
      g_log << Logger::Info << ' ' << strerror(rc) << endl;
    }
    else {
      log->error(Logr::Warning, rc, "Error setting CPU affinity", "thread", Logging::Loggable(n), "cpumap", Logging::IterLoggable(cpuMapping->second.begin(), cpuMapping->second.end()));
    }
  }
}

static void recursorThread();

void RecThreadInfo::start(unsigned int id, const string& tname, const std::map<unsigned int, std::set<int>>& cpusMap, Logr::log_t log)
{
  name = tname;
  thread = std::thread([id, tname] {
    t_id = id;
    const string threadPrefix = "rec/";
    setThreadName(threadPrefix + tname);
    recursorThread();
  });
  setCPUMap(cpusMap, id, thread.native_handle(), log);
}

int RecThreadInfo::runThreads(Logr::log_t log)
{
  int ret = EXIT_SUCCESS;
  unsigned int currentThreadId = 1;
  const auto cpusMap = parseCPUMap(log);

  if (RecThreadInfo::numDistributors() + RecThreadInfo::numWorkers() == 1) {
    SLOG(g_log << Logger::Warning << "Operating with single distributor/worker thread" << endl,
         log->info(Logr::Notice, "Operating with single distributor/worker thread"));

    /* This thread handles the web server, carbon, statistics and the control channel */
    auto& handlerInfo = RecThreadInfo::info(0);
    handlerInfo.setHandler();
    handlerInfo.start(0, "web+stat", cpusMap, log);
    auto& taskInfo = RecThreadInfo::info(2);
    taskInfo.setTaskThread();
    taskInfo.start(2, "task", cpusMap, log);

    auto& info = RecThreadInfo::info(currentThreadId);
    info.setListener();
    info.setWorker();
    info.setThreadId(currentThreadId++);
    recursorThread();

    handlerInfo.thread.join();
    if (handlerInfo.exitCode != 0) {
      ret = handlerInfo.exitCode;
    }
    taskInfo.thread.join();
    if (taskInfo.exitCode != 0) {
      ret = taskInfo.exitCode;
    }
  }
  else {
    // Setup RecThreadInfo objects
    unsigned int tmp = currentThreadId;
    if (RecThreadInfo::weDistributeQueries()) {
      for (unsigned int n = 0; n < RecThreadInfo::numDistributors(); ++n) {
        RecThreadInfo::info(tmp++).setListener();
      }
    }
    for (unsigned int n = 0; n < RecThreadInfo::numWorkers(); ++n) {
      auto& info = RecThreadInfo::info(tmp++);
      info.setListener(!RecThreadInfo::weDistributeQueries());
      info.setWorker();
    }
    for (unsigned int n = 0; n < RecThreadInfo::numTaskThreads(); ++n) {
      auto& info = RecThreadInfo::info(tmp++);
      info.setTaskThread();
    }

    // And now start the actual threads
    if (RecThreadInfo::weDistributeQueries()) {
      SLOG(g_log << Logger::Warning << "Launching " << RecThreadInfo::numDistributors() << " distributor threads" << endl,
           log->info(Logr::Notice, "Launching distributor threads", "count", Logging::Loggable(RecThreadInfo::numDistributors())));
      for (unsigned int n = 0; n < RecThreadInfo::numDistributors(); ++n) {
        auto& info = RecThreadInfo::info(currentThreadId);
        info.start(currentThreadId++, "distr", cpusMap, log);
      }
    }
    SLOG(g_log << Logger::Warning << "Launching " << RecThreadInfo::numWorkers() << " worker threads" << endl,
         log->info(Logr::Notice, "Launching worker threads", "count", Logging::Loggable(RecThreadInfo::numWorkers())));

    for (unsigned int n = 0; n < RecThreadInfo::numWorkers(); ++n) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.start(currentThreadId++, "worker", cpusMap, log);
    }

    for (unsigned int n = 0; n < RecThreadInfo::numTaskThreads(); ++n) {
      auto& info = RecThreadInfo::info(currentThreadId);
      info.start(currentThreadId++, "task", cpusMap, log);
    }

    /* This thread handles the web server, carbon, statistics and the control channel */
    auto& info = RecThreadInfo::info(0);
    info.setHandler();
    info.start(0, "web+stat", cpusMap, log);

    for (auto& ti : RecThreadInfo::infos()) {
      ti.thread.join();
      if (ti.exitCode != 0) {
        ret = ti.exitCode;
      }
    }
  }
  return ret;
}

void RecThreadInfo::makeThreadPipes(Logr::log_t log)
{
  auto pipeBufferSize = ::arg().asNum("distribution-pipe-buffer-size");
  if (pipeBufferSize > 0) {
    SLOG(g_log << Logger::Info << "Resizing the buffer of the distribution pipe to " << pipeBufferSize << endl,
         log->info(Logr::Info, "Resizing the buffer of the distribution pipe", "size", Logging::Loggable(pipeBufferSize)));
  }

  /* thread 0 is the handler / SNMP, worker threads start at 1 */
  for (unsigned int n = 0; n < numRecursorThreads(); ++n) {
    auto& threadInfo = info(n);

    int fd[2];
    if (pipe(fd) < 0)
      unixDie("Creating pipe for inter-thread communications");

    threadInfo.pipes.readToThread = fd[0];
    threadInfo.pipes.writeToThread = fd[1];

    // handler thread only gets first pipe, not the others
    if (n == 0) {
      continue;
    }

    if (pipe(fd) < 0)
      unixDie("Creating pipe for inter-thread communications");

    threadInfo.pipes.readFromThread = fd[0];
    threadInfo.pipes.writeFromThread = fd[1];

    if (pipe(fd) < 0)
      unixDie("Creating pipe for inter-thread communications");

    threadInfo.pipes.readQueriesToThread = fd[0];
    threadInfo.pipes.writeQueriesToThread = fd[1];

    if (pipeBufferSize > 0) {
      if (!setPipeBufferSize(threadInfo.pipes.writeQueriesToThread, pipeBufferSize)) {
        int err = errno;
        SLOG(g_log << Logger::Warning << "Error resizing the buffer of the distribution pipe for thread " << n << " to " << pipeBufferSize << ": " << strerror(err) << endl,
             log->error(Logr::Warning, err, "Error resizing the buffer of the distribution pipe for thread", "thread", Logging::Loggable(n), "size", Logging::Loggable(pipeBufferSize)));
        auto existingSize = getPipeBufferSize(threadInfo.pipes.writeQueriesToThread);
        if (existingSize > 0) {
          SLOG(g_log << Logger::Warning << "The current size of the distribution pipe's buffer for thread " << n << " is " << existingSize << endl,
               log->info(Logr::Warning, "The current size of the distribution pipe's buffer for thread", "thread", Logging::Loggable(n), "size", Logging::Loggable(existingSize)));
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
  FDMultiplexer* ret;
  for (const auto& i : FDMultiplexer::getMultiplexerMap()) {
    try {
      ret = i.second(FDMultiplexer::s_maxevents);
      return ret;
    }
    catch (FDMultiplexerException& fe) {
      SLOG(g_log << Logger::Warning << "Non-fatal error initializing possible multiplexer (" << fe.what() << "), falling back" << endl,
           log->error(Logr::Warning, fe.what(), "Non-fatal error initializing possible multiplexer, falling back"));
    }
    catch (...) {
      SLOG(g_log << Logger::Warning << "Non-fatal error initializing possible multiplexer" << endl,
           log->info(Logr::Warning, "Non-fatal error initializing possible multiplexer"));
    }
  }
  SLOG(g_log << Logger::Error << "No working multiplexer found!" << endl,
       log->info(Logr::Error, "No working multiplexer found!"));
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
      SLOG(g_log << Logger::Error << "Error while starting protobuf logger to '" << server << ": " << e.what() << endl,
           log->error(Logr::Error, e.what(), "Exception while starting protobuf logger", "exception", Logging::Loggable("std::exception"), "server", Logging::Loggable(server)));
    }
    catch (const PDNSException& e) {
      SLOG(g_log << Logger::Error << "Error while starting protobuf logger to '" << server << ": " << e.reason << endl,
           log->error(Logr::Error, e.reason, "Exception while starting protobuf logger", "exception", Logging::Loggable("PDNSException"), "server", Logging::Loggable(server)));
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

void protobufLogQuery(LocalStateHolder<LuaConfigItems>& luaconfsLocal, const boost::uuids::uuid& uniqueId, const ComboAddress& remote, const ComboAddress& local, const ComboAddress& mappedRemote, const Netmask& ednssubnet, bool tcp, uint16_t id, size_t len, const DNSName& qname, uint16_t qtype, uint16_t qclass, const std::unordered_set<std::string>& policyTags, const std::string& requestorId, const std::string& deviceId, const std::string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta)
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
    Netmask requestorNM(mappedRemote, mappedRemote.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
    requestor = requestorNM.getMaskedNetwork();
    requestor.setPort(mappedRemote.getPort());
  }

  pdns::ProtoZero::RecMessage m{128, std::string::size_type(policyTags.empty() ? 0 : 64)}; // It's a guess
  m.setType(pdns::ProtoZero::Message::MessageType::DNSQueryType);
  m.setRequest(uniqueId, requestor, local, qname, qtype, qclass, id, tcp ? pdns::ProtoZero::Message::TransportProtocol::TCP : pdns::ProtoZero::Message::TransportProtocol::UDP, len);
  m.setServerIdentity(SyncRes::s_serverID);
  m.setEDNSSubnet(ednssubnet, ednssubnet.isIPv4() ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
  m.setRequestorId(requestorId);
  m.setDeviceId(deviceId);
  m.setDeviceName(deviceName);

  if (!policyTags.empty()) {
    m.addPolicyTags(policyTags);
  }
  for (const auto& mit : meta) {
    m.setMeta(mit.first, mit.second.stringVal, mit.second.intVal);
  }

  std::string msg(m.finishAndMoveBuf());
  for (auto& server : *t_protobufServers.servers) {
    remoteLoggerQueueData(*server, msg);
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

void protobufLogResponse(const struct dnsheader* dh, LocalStateHolder<LuaConfigItems>& luaconfsLocal,
                         const RecursorPacketCache::OptPBData& pbData, const struct timeval& tv,
                         bool tcp, const ComboAddress& source, const ComboAddress& destination,
                         const ComboAddress& mappedSource,
                         const EDNSSubnetOpts& ednssubnet,
                         const boost::uuids::uuid& uniqueId, const string& requestorId, const string& deviceId,
                         const string& deviceName, const std::map<std::string, RecursorLua4::MetaValue>& meta,
                         const RecEventTrace& eventTrace)
{
  pdns::ProtoZero::RecMessage pbMessage(pbData ? pbData->d_message : "", pbData ? pbData->d_response : "", 64, 10); // The extra bytes we are going to add
  // Normally we take the immutable string from the cache and append a few values, but if it's not there (can this happen?)
  // we start with an empty string and append the minimal
  if (!pbData) {
    pbMessage.setType(pdns::ProtoZero::Message::MessageType::DNSResponseType);
    pbMessage.setServerIdentity(SyncRes::s_serverID);
  }

  // In response part
  if (g_useKernelTimestamp && tv.tv_sec) {
    pbMessage.setQueryTime(tv.tv_sec, tv.tv_usec);
  }
  else {
    pbMessage.setQueryTime(g_now.tv_sec, g_now.tv_usec);
  }

  // In message part
  if (!luaconfsLocal->protobufExportConfig.logMappedFrom) {
    Netmask requestorNM(source, source.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
    auto requestor = requestorNM.getMaskedNetwork();
    pbMessage.setFrom(requestor);
    pbMessage.setFromPort(source.getPort());
  }
  else {
    Netmask requestorNM(mappedSource, mappedSource.sin4.sin_family == AF_INET ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
    auto requestor = requestorNM.getMaskedNetwork();
    pbMessage.setFrom(requestor);
    pbMessage.setFromPort(mappedSource.getPort());
  }
  pbMessage.setMessageIdentity(uniqueId);
  pbMessage.setTo(destination);
  pbMessage.setSocketProtocol(tcp ? pdns::ProtoZero::Message::TransportProtocol::TCP : pdns::ProtoZero::Message::TransportProtocol::UDP);
  pbMessage.setId(dh->id);

  pbMessage.setTime();
  pbMessage.setEDNSSubnet(ednssubnet.source, ednssubnet.source.isIPv4() ? luaconfsLocal->protobufMaskV4 : luaconfsLocal->protobufMaskV6);
  pbMessage.setRequestorId(requestorId);
  pbMessage.setDeviceId(deviceId);
  pbMessage.setDeviceName(deviceName);
  pbMessage.setToPort(destination.getPort());
  for (const auto& m : meta) {
    pbMessage.setMeta(m.first, m.second.stringVal, m.second.intVal);
  }
#ifdef NOD_ENABLED
  if (g_nodEnabled) {
    pbMessage.setNewlyObservedDomain(false);
  }
#endif
  if (eventTrace.enabled() && SyncRes::s_event_trace_enabled & SyncRes::event_trace_to_pb) {
    pbMessage.addEvents(eventTrace);
  }
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
      FrameStreamLogger* fsl = nullptr;
      try {
        ComboAddress address(server);
        fsl = new FrameStreamLogger(address.sin4.sin_family, address.toStringWithPort(), true, options);
      }
      catch (const PDNSException& e) {
        fsl = new FrameStreamLogger(AF_UNIX, server, true, options);
      }
      fsl->setLogQueries(config.logQueries);
      fsl->setLogResponses(config.logResponses);
      fsl->setLogNODs(config.logNODs);
      fsl->setLogUDRs(config.logUDRs);
      result->emplace_back(fsl);
    }
    catch (const std::exception& e) {
      SLOG(g_log << Logger::Error << "Error while starting dnstap framestream logger to '" << server << ": " << e.what() << endl,
           log->error(Logr::Error, e.what(), "Exception while starting dnstap framestream logger", "exception", Logging::Loggable("std::exception"), "server", Logging::Loggable(server)));
    }
    catch (const PDNSException& e) {
      SLOG(g_log << Logger::Error << "Error while starting dnstap framestream logger to '" << server << ": " << e.reason << endl,
           log->error(Logr::Error, e.reason, "Exception while starting dnstap framestream logger", "exception", Logging::Loggable("PDNSException"), "server", Logging::Loggable(server)));
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
  if (processNum >= 0)
    sockname += "." + std::to_string(processNum);
  sockname += ".controlsocket";
  g_rcc.listen(sockname);

  int sockowner = -1;
  int sockgroup = -1;

  if (!::arg().isEmpty("socket-group"))
    sockgroup = ::arg().asGid("socket-group");
  if (!::arg().isEmpty("socket-owner"))
    sockowner = ::arg().asUid("socket-owner");

  if (sockgroup > -1 || sockowner > -1) {
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
  if (!::arg().mustDo("write-pid"))
    return;
  ofstream of(g_pidfname.c_str(), std::ios_base::app);
  if (of)
    of << Utility::getpid() << endl;
  else {
    int err = errno;
    SLOG(g_log << Logger::Error << "Writing pid for " << Utility::getpid() << " to " << g_pidfname << " failed: " << stringerror(err) << endl,
         log->error(Logr::Error, err, "Writing pid failed", "pid", Logging::Loggable(Utility::getpid()), "file", Logging::Loggable(g_pidfname)));
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
  SLOG(g_log << Logger::Error << "Problem with socket directory " << dir << ": " << msg << "; see https://docs.powerdns.com/recursor/upgrade.html#x-to-4-3-0" << endl,
       log->error(Logr::Error, msg, "Problem with socket directory, see https://docs.powerdns.com/recursor/upgrade.html#x-to-4-3-0", "dir", Logging::Loggable(dir)));
  _exit(1);
}

#ifdef NOD_ENABLED
static void setupNODThread(Logr::log_t log)
{
  if (g_nodEnabled) {
    uint32_t num_cells = ::arg().asNum("new-domain-db-size");
    t_nodDBp = std::make_shared<nod::NODDB>(num_cells);
    try {
      t_nodDBp->setCacheDir(::arg()["new-domain-history-dir"]);
    }
    catch (const PDNSException& e) {
      SLOG(g_log << Logger::Error << "new-domain-history-dir (" << ::arg()["new-domain-history-dir"] << ") is not readable or does not exist" << endl,
           log->error(Logr::Error, e.reason, "new-domain-history-dir is not readbale or does not exists", "dir", Logging::Loggable(::arg()["new-domain-history-dir"])));
      _exit(1);
    }
    if (!t_nodDBp->init()) {
      SLOG(g_log << Logger::Error << "Could not initialize domain tracking" << endl,
           log->info(Logr::Error, "Could not initialize domain tracking"));
      _exit(1);
    }
    std::thread t(nod::NODDB::startHousekeepingThread, t_nodDBp, std::this_thread::get_id());
    t.detach();
  }
  if (g_udrEnabled) {
    uint32_t num_cells = ::arg().asNum("unique-response-db-size");
    t_udrDBp = std::make_shared<nod::UniqueResponseDB>(num_cells);
    try {
      t_udrDBp->setCacheDir(::arg()["unique-response-history-dir"]);
    }
    catch (const PDNSException& e) {
      SLOG(g_log << Logger::Error << "unique-response-history-dir (" << ::arg()["unique-response-history-dir"] << ") is not readable or does not exist" << endl,
           log->info(Logr::Error, "unique-response-history-dir is not readable or does not exist", "dir", Logging::Loggable(::arg()["unique-response-history-dir"])));
      _exit(1);
    }
    if (!t_udrDBp->init()) {
      SLOG(g_log << Logger::Error << "Could not initialize unique response tracking" << endl,
           log->info(Logr::Error, "Could not initialize unique response tracking"));
      _exit(1);
    }
    std::thread t(nod::UniqueResponseDB::startHousekeepingThread, t_udrDBp, std::this_thread::get_id());
    t.detach();
  }
}

static void parseNODIgnorelist(const std::string& wlist)
{
  vector<string> parts;
  stringtok(parts, wlist, ",; ");
  for (const auto& a : parts) {
    g_nodDomainWL.add(DNSName(a));
  }
}

static void setupNODGlobal()
{
  // Setup NOD subsystem
  g_nodEnabled = ::arg().mustDo("new-domain-tracking");
  g_nodLookupDomain = DNSName(::arg()["new-domain-lookup"]);
  g_nodLog = ::arg().mustDo("new-domain-log");
  parseNODIgnorelist(::arg()["new-domain-whitelist"]);
  parseNODIgnorelist(::arg()["new-domain-ignore-list"]);

  // Setup Unique DNS Response subsystem
  g_udrEnabled = ::arg().mustDo("unique-response-tracking");
  g_udrLog = ::arg().mustDo("unique-response-log");
  g_nod_pbtag = ::arg()["new-domain-pb-tag"];
  g_udr_pbtag = ::arg()["unique-response-pb-tag"];
}
#endif /* NOD_ENABLED */

static void daemonize(Logr::log_t log)
{
  if (fork())
    exit(0); // bye bye

  setsid();

  int i = open("/dev/null", O_RDWR); /* open stdin */
  if (i < 0) {
    int err = errno;
    SLOG(g_log << Logger::Critical << "Unable to open /dev/null: " << stringerror(err) << endl,
         log->error(Logr::Critical, err, "Unable to open /dev/null"));
  }
  else {
    dup2(i, 0); /* stdin */
    dup2(i, 1); /* stderr */
    dup2(i, 2); /* stderr */
    close(i);
  }
}

static void termIntHandler(int)
{
  doExit();
}

static void usr1Handler(int)
{
  statsWanted = true;
}

static void usr2Handler(int)
{
  g_quiet = !g_quiet;
  SyncRes::setDefaultLogMode(g_quiet ? SyncRes::LogNone : SyncRes::Log);
  ::arg().set("quiet") = g_quiet ? "" : "no";
}

static void checkLinuxIPv6Limits([[maybe_unused]] Logr::log_t log)
{
#ifdef __linux__
  string line;
  if (readFileIfThere("/proc/sys/net/ipv6/route/max_size", &line)) {
    int lim = std::stoi(line);
    if (lim < 16384) {
      SLOG(g_log << Logger::Error << "If using IPv6, please raise sysctl net.ipv6.route.max_size, currently set to " << lim << " which is < 16384" << endl,
           log->info(Logr::Error, "If using IPv6, please raise sysctl net.ipv6.route.max_size to a size >= 16384", "current", Logging::Loggable(lim)));
    }
  }
#endif
}

static void checkOrFixFDS(Logr::log_t log)
{
  unsigned int availFDs = getFilenumLimit();
  unsigned int wantFDs = g_maxMThreads * RecThreadInfo::numWorkers() + 25; // even healthier margin then before
  wantFDs += RecThreadInfo::numWorkers() * TCPOutConnectionManager::s_maxIdlePerThread;

  if (wantFDs > availFDs) {
    unsigned int hardlimit = getFilenumLimit(true);
    if (hardlimit >= wantFDs) {
      setFilenumLimit(wantFDs);
      SLOG(g_log << Logger::Warning << "Raised soft limit on number of filedescriptors to " << wantFDs << " to match max-mthreads and threads settings" << endl,
           log->info(Logr::Warning, "Raised soft limit on number of filedescriptors to match max-mthreads and threads settings", "limit", Logging::Loggable(wantFDs)));
    }
    else {
      int newval = (hardlimit - 25 - TCPOutConnectionManager::s_maxIdlePerThread) / RecThreadInfo::numWorkers();
      SLOG(g_log << Logger::Warning << "Insufficient number of filedescriptors available for max-mthreads*threads setting! (" << hardlimit << " < " << wantFDs << "), reducing max-mthreads to " << newval << endl,
           log->info(Logr::Warning, "Insufficient number of filedescriptors available for max-mthreads*threads setting! Reducing max-mthreads", "hardlimit", Logging::Loggable(hardlimit), "want", Logging::Loggable(wantFDs), "max-mthreads", Logging::Loggable(newval)));
      g_maxMThreads = newval;
      setFilenumLimit(hardlimit);
    }
  }
}

// static std::string s_timestampFormat = "%m-%dT%H:%M:%S";
static std::string s_timestampFormat = "%s";

static const char* toTimestampStringMilli(const struct timeval& tv, char* buf, size_t sz)
{
  size_t len = 0;
  if (s_timestampFormat != "%s") {
    // strftime is not thread safe, it can access locale information
    static std::mutex m;
    auto lock = std::lock_guard(m);
    struct tm tm;
    len = strftime(buf, sz, s_timestampFormat.c_str(), localtime_r(&tv.tv_sec, &tm));
  }
  if (len == 0) {
    len = snprintf(buf, sz, "%lld", static_cast<long long>(tv.tv_sec));
  }

  snprintf(buf + len, sz - len, ".%03ld", static_cast<long>(tv.tv_usec) / 1000);
  return buf;
}

#ifdef HAVE_SYSTEMD
static void loggerSDBackend(const Logging::Entry& entry)
{
  // First map SL priority to syslog's Urgency
  Logger::Urgency u = entry.d_priority ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (u > s_logUrgency) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Not that lower Urgency means higher number.
    return;
  }
  // We need to keep the string in mem until sd_journal_sendv has ben called
  vector<string> strings;
  auto appendKeyAndVal = [&strings](const string& k, const string& v) {
    strings.emplace_back(k + "=" + v);
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
  char timebuf[64];
  appendKeyAndVal("TIMESTAMP", toTimestampStringMilli(entry.d_timestamp, timebuf, sizeof(timebuf)));
  for (auto const& v : entry.values) {
    appendKeyAndVal(toUpper(v.first), v.second);
  }
  // Thread id filled in by backend, since the SL code does not know about RecursorThreads
  // We use the Recursor thread, other threads get id 0. May need to revisit.
  appendKeyAndVal("TID", std::to_string(RecThreadInfo::id()));

  vector<iovec> iov;
  iov.reserve(strings.size());
  for (const auto& s : strings) {
    // iovec has no 2 arg constructor, so make it explicit
    iov.emplace_back(iovec{const_cast<void*>(reinterpret_cast<const void*>(s.data())), s.size()});
  }
  sd_journal_sendv(iov.data(), static_cast<int>(iov.size()));
}
#endif

static void loggerBackend(const Logging::Entry& entry)
{
  static thread_local std::stringstream buf;

  // First map SL priority to syslog's Urgency
  Logger::Urgency u = entry.d_priority ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (u > s_logUrgency) {
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
  if (entry.d_priority) {
    buf << " prio=" << std::quoted(Logr::Logger::toString(entry.d_priority));
  }
  // Thread id filled in by backend, since the SL code does not know about RecursorThreads
  // We use the Recursor thread, other threads get id 0. May need to revisit.
  buf << " tid=" << std::quoted(std::to_string(RecThreadInfo::id()));
  char timebuf[64];
  buf << " ts=" << std::quoted(toTimestampStringMilli(entry.d_timestamp, timebuf, sizeof(timebuf)));
  for (auto const& v : entry.values) {
    buf << " ";
    buf << v.first << "=" << std::quoted(v.second);
  }

  g_log << u << buf.str() << endl;
}

static int ratePercentage(uint64_t nom, uint64_t denom)
{
  if (denom == 0) {
    return 0;
  }
  return round(100.0 * nom / denom);
}

static void doStats(void)
{
  static time_t lastOutputTime;
  static uint64_t lastQueryCount;

  uint64_t cacheHits = g_recCache->cacheHits;
  uint64_t cacheMisses = g_recCache->cacheMisses;
  uint64_t cacheSize = g_recCache->size();
  auto rc_stats = g_recCache->stats();
  auto pc_stats = g_packetCache ? g_packetCache->stats() : std::pair<uint64_t, uint64_t>{0, 0};
  double rrc = rc_stats.second == 0 ? 0.0 : (100.0 * rc_stats.first / rc_stats.second);
  double rpc = pc_stats.second == 0 ? 0.0 : (100.0 * pc_stats.first / pc_stats.second);
  uint64_t negCacheSize = g_negCache->size();
  auto taskPushes = getTaskPushes();
  auto taskExpired = getTaskExpired();
  auto taskSize = getTaskSize();
  uint64_t pcSize = g_packetCache ? g_packetCache->size() : 0;
  uint64_t pcHits = g_packetCache ? g_packetCache->getHits() : 0;

  auto log = g_slog->withName("stats");

  auto qcounter = g_Counters.sum(rec::Counter::qcounter);
  auto syncresqueries = g_Counters.sum(rec::Counter::syncresqueries);
  auto outqueries = g_Counters.sum(rec::Counter::outqueries);
  auto throttledqueries = g_Counters.sum(rec::Counter::throttledqueries);
  auto tcpoutqueries = g_Counters.sum(rec::Counter::tcpoutqueries);
  auto dotoutqueries = g_Counters.sum(rec::Counter::dotoutqueries);
  auto outgoingtimeouts = g_Counters.sum(rec::Counter::outgoingtimeouts);
  if (qcounter > 0 && (cacheHits + cacheMisses) > 0 && syncresqueries > 0 && outqueries > 0) {
    if (!g_slogStructured) {
      g_log << Logger::Notice << "stats: " << qcounter << " questions, " << cacheSize << " cache entries, " << negCacheSize << " negative entries, " << ratePercentage(cacheHits, cacheHits + cacheMisses) << "% cache hits" << endl;
      g_log << Logger::Notice << "stats: record cache contended/acquired " << rc_stats.first << '/' << rc_stats.second << " = " << rrc << '%' << endl;
      g_log << Logger::Notice << "stats: packet cache contended/acquired " << pc_stats.first << '/' << pc_stats.second << " = " << rpc << '%' << endl;

      g_log << Logger::Notice << "stats: throttle map: "
            << SyncRes::getThrottledServersSize() << ", ns speeds: "
            << SyncRes::getNSSpeedsSize() << ", failed ns: "
            << SyncRes::getFailedServersSize() << ", ednsmap: "
            << SyncRes::getEDNSStatusesSize() << ", non-resolving: "
            << SyncRes::getNonResolvingNSSize() << ", saved-parentsets: "
            << SyncRes::getSaveParentsNSSetsSize()
            << endl;
      g_log << Logger::Notice << "stats: outpacket/query ratio " << ratePercentage(outqueries, syncresqueries) << "%";
      g_log << Logger::Notice << ", " << ratePercentage(throttledqueries, outqueries + throttledqueries) << "% throttled" << endl;
      g_log << Logger::Notice << "stats: " << tcpoutqueries << "/" << dotoutqueries << "/" << getCurrentIdleTCPConnections() << " outgoing tcp/dot/idle connections, " << broadcastAccFunction<uint64_t>(pleaseGetConcurrentQueries) << " queries running, " << outgoingtimeouts << " outgoing timeouts " << endl;

      g_log << Logger::Notice << "stats: " << pcSize << " packet cache entries, " << ratePercentage(pcHits, qcounter) << "% packet cache hits" << endl;

      g_log << Logger::Notice << "stats: tasks pushed/expired/queuesize: " << taskPushes << '/' << taskExpired << '/' << taskSize << endl;
    }
    else {
      const string m = "Periodic statistics report";
      log->info(Logr::Info, m,
                "questions", Logging::Loggable(qcounter),
                "cache-entries", Logging::Loggable(cacheSize),
                "negcache-entries", Logging::Loggable(negCacheSize),
                "record-cache-hitratio-perc", Logging::Loggable(ratePercentage(cacheHits, cacheHits + cacheMisses)),
                "record-cache-contended", Logging::Loggable(rc_stats.first),
                "record-cache-acquired", Logging::Loggable(rc_stats.second),
                "record-cache-contended-perc", Logging::Loggable(rrc),
                "packetcache-contended", Logging::Loggable(pc_stats.first),
                "packetcache-acquired", Logging::Loggable(pc_stats.second),
                "packetcache-contended-perc", Logging::Loggable(rpc));
      log->info(Logr::Info, m,
                "throttle-entries", Logging::Loggable(SyncRes::getThrottledServersSize()),
                "nsspeed-entries", Logging::Loggable(SyncRes::getNSSpeedsSize()),
                "failed-host-entries", Logging::Loggable(SyncRes::getFailedServersSize()),
                "edns-entries", Logging::Loggable(SyncRes::getEDNSStatusesSize()),
                "non-resolving-nameserver-entries", Logging::Loggable(SyncRes::getNonResolvingNSSize()),
                "saved-parent-ns-sets-entries", Logging::Loggable(SyncRes::getSaveParentsNSSetsSize()),
                "outqueries-per-query", Logging::Loggable(ratePercentage(outqueries, syncresqueries)));
      log->info(Logr::Info, m,
                "throttled-queries-perc", Logging::Loggable(ratePercentage(throttledqueries, outqueries + throttledqueries)),
                "tcp-outqueries", Logging::Loggable(tcpoutqueries),
                "dot-outqueries", Logging::Loggable(dotoutqueries),
                "idle-tcpout-connections", Logging::Loggable(getCurrentIdleTCPConnections()),
                "concurrent-queries", Logging::Loggable(broadcastAccFunction<uint64_t>(pleaseGetConcurrentQueries)),
                "outgoing-timeouts", Logging::Loggable(outgoingtimeouts));
      log->info(Logr::Info, m,
                "packetcache-entries", Logging::Loggable(pcSize),
                "packetcache-hitratio-perc", Logging::Loggable(ratePercentage(pcHits, qcounter)),
                "taskqueue-pushed", Logging::Loggable(taskPushes),
                "taskqueue-expired", Logging::Loggable(taskExpired),
                "taskqueue-size", Logging::Loggable(taskSize));
    }
    size_t idx = 0;
    for (const auto& threadInfo : RecThreadInfo::infos()) {
      if (threadInfo.isWorker()) {
        SLOG(g_log << Logger::Notice << "stats: thread " << idx << " has been distributed " << threadInfo.numberOfDistributedQueries << " queries" << endl,
             log->info(Logr::Info, "Queries handled by thread", "thread", Logging::Loggable(idx), "count", Logging::Loggable(threadInfo.numberOfDistributedQueries)));
        ++idx;
      }
    }
    time_t now = time(0);
    if (lastOutputTime && lastQueryCount && now != lastOutputTime) {
      SLOG(g_log << Logger::Notice << "stats: " << (qcounter - lastQueryCount) / (now - lastOutputTime) << " qps (average over " << (now - lastOutputTime) << " seconds)" << endl,
           log->info(Logr::Info, "Periodic QPS report", "qps", Logging::Loggable((qcounter - lastQueryCount) / (now - lastOutputTime)),
                     "averagedOver", Logging::Loggable(now - lastOutputTime)));
    }
    lastOutputTime = now;
    lastQueryCount = qcounter;
  }
  else if (statsWanted) {
    SLOG(g_log << Logger::Notice << "stats: no stats yet!" << endl,
         log->info(Logr::Notice, "No stats yet"));
  }

  statsWanted = false;
}

static std::shared_ptr<NetmaskGroup> parseACL(const std::string& aclFile, const std::string& aclSetting, Logr::log_t log)
{
  auto result = std::make_shared<NetmaskGroup>();

  if (!::arg()[aclFile].empty()) {
    string line;
    ifstream ifs(::arg()[aclFile].c_str());
    if (!ifs) {
      throw runtime_error("Could not open '" + ::arg()[aclFile] + "': " + stringerror());
    }

    string::size_type pos;
    while (getline(ifs, line)) {
      pos = line.find('#');
      if (pos != string::npos)
        line.resize(pos);
      boost::trim(line);
      if (line.empty())
        continue;

      result->addMask(line);
    }
    SLOG(g_log << Logger::Info << "Done parsing " << result->size() << " " << aclSetting << " ranges from file '" << ::arg()[aclFile] << "' - overriding '" << aclSetting << "' setting" << endl,
         log->info(Logr::Info, "Done parsing ranges from file, will override setting", "setting", Logging::Loggable(aclSetting),
                   "number", Logging::Loggable(result->size()), "file", Logging::Loggable(::arg()[aclFile])));
  }
  else if (!::arg()[aclSetting].empty()) {
    vector<string> ips;
    stringtok(ips, ::arg()[aclSetting], ", ");

    for (const auto& i : ips) {
      result->addMask(i);
    }
    if (!g_slogStructured) {
      g_log << Logger::Info << aclSetting << ": ";
      for (vector<string>::const_iterator i = ips.begin(); i != ips.end(); ++i) {
        if (i != ips.begin())
          g_log << Logger::Info << ", ";
        g_log << Logger::Info << *i;
      }
      g_log << Logger::Info << endl;
    }
    else {
      log->info(Logr::Info, "Setting access control", "acl", Logging::Loggable(aclSetting), "addresses", Logging::IterLoggable(ips.begin(), ips.end()));
    }
  }

  return result;
}

static void* pleaseSupplantAllowFrom(std::shared_ptr<NetmaskGroup> ng)
{
  t_allowFrom = ng;
  return nullptr;
}

static void* pleaseSupplantAllowNotifyFrom(std::shared_ptr<NetmaskGroup> ng)
{
  t_allowNotifyFrom = ng;
  return nullptr;
}

void* pleaseSupplantAllowNotifyFor(std::shared_ptr<notifyset_t> ns)
{
  t_allowNotifyFor = ns;
  return nullptr;
}

void parseACLs()
{
  auto log = g_slog->withName("config");

  static bool l_initialized;

  if (l_initialized) { // only reload configuration file on second call
    string configName = ::arg()["config-dir"] + "/recursor.conf";
    if (!::arg()["config-name"].empty()) {
      configName = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"] + ".conf";
    }
    cleanSlashes(configName);

    if (!::arg().preParseFile(configName.c_str(), "allow-from-file")) {
      throw runtime_error("Unable to re-parse configuration file '" + configName + "'");
    }
    ::arg().preParseFile(configName.c_str(), "allow-from", LOCAL_NETS);

    if (!::arg().preParseFile(configName.c_str(), "allow-notify-from-file")) {
      throw runtime_error("Unable to re-parse configuration file '" + configName + "'");
    }
    ::arg().preParseFile(configName.c_str(), "allow-notify-from");

    ::arg().preParseFile(configName.c_str(), "include-dir");
    ::arg().preParse(g_argc, g_argv, "include-dir");

    // then process includes
    std::vector<std::string> extraConfigs;
    ::arg().gatherIncludes(extraConfigs);

    for (const std::string& fileName : extraConfigs) {
      if (!::arg().preParseFile(fileName.c_str(), "allow-from-file", ::arg()["allow-from-file"])) {
        throw runtime_error("Unable to re-parse configuration file include '" + fileName + "'");
      }
      if (!::arg().preParseFile(fileName.c_str(), "allow-from", ::arg()["allow-from"])) {
        throw runtime_error("Unable to re-parse configuration file include '" + fileName + "'");
      }

      if (!::arg().preParseFile(fileName.c_str(), "allow-notify-from-file", ::arg()["allow-notify-from-file"])) {
        throw runtime_error("Unable to re-parse configuration file include '" + fileName + "'");
      }
      if (!::arg().preParseFile(fileName.c_str(), "allow-notify-from", ::arg()["allow-notify-from"])) {
        throw runtime_error("Unable to re-parse configuration file include '" + fileName + "'");
      }
    }

    ::arg().preParse(g_argc, g_argv, "allow-from-file");
    ::arg().preParse(g_argc, g_argv, "allow-from");

    ::arg().preParse(g_argc, g_argv, "allow-notify-from-file");
    ::arg().preParse(g_argc, g_argv, "allow-notify-from");
  }

  auto allowFrom = parseACL("allow-from-file", "allow-from", log);

  if (allowFrom->empty()) {
    if (::arg()["local-address"] != "127.0.0.1" && ::arg().asNum("local-port") == 53) {
      SLOG(g_log << Logger::Warning << "WARNING: Allowing queries from all IP addresses - this can be a security risk!" << endl,
           log->info(Logr::Warning, "WARNING: Allowing queries from all IP addresses - this can be a security risk!"));
    }
    allowFrom = nullptr;
  }

  g_initialAllowFrom = allowFrom;
  broadcastFunction([=] { return pleaseSupplantAllowFrom(allowFrom); });

  auto allowNotifyFrom = parseACL("allow-notify-from-file", "allow-notify-from", log);

  g_initialAllowNotifyFrom = allowNotifyFrom;
  broadcastFunction([=] { return pleaseSupplantAllowNotifyFrom(allowNotifyFrom); });

  l_initialized = true;
}

void broadcastFunction(const pipefunc_t& func)
{
  /* This function might be called by the worker with t_id 0 during startup
     for the initialization of ACLs and domain maps. After that it should only
     be called by the handler. */

  if (RecThreadInfo::infos().empty() && RecThreadInfo::id() == 0) {
    /* the handler and  distributors will call themselves below, but
       during startup we get called while g_threadInfos has not been
       populated yet to update the ACL or domain maps, so we need to
       handle that case.
    */
    func();
  }

  unsigned int thread = 0;
  for (const auto& threadInfo : RecThreadInfo::infos()) {
    if (thread++ == RecThreadInfo::id()) {
      func(); // don't write to ourselves!
      continue;
    }

    ThreadMSG* tmsg = new ThreadMSG(); // NOLINT: manual ownership handling
    tmsg->func = func;
    tmsg->wantAnswer = true;
    if (write(threadInfo.pipes.writeToThread, &tmsg, sizeof(tmsg)) != sizeof(tmsg)) { // NOLINT: sizeof correct
      delete tmsg; // NOLINT: manual ownership handling

      unixDie("write to thread pipe returned wrong size or error");
    }

    string* resp = nullptr;
    if (read(threadInfo.pipes.readFromThread, &resp, sizeof(resp)) != sizeof(resp)) { // NOLINT: sizeof correct
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

static vector<ComboAddress>& operator+=(vector<ComboAddress>& a, const vector<ComboAddress>& b)
{
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

static vector<pair<DNSName, uint16_t>>& operator+=(vector<pair<DNSName, uint16_t>>& a, const vector<pair<DNSName, uint16_t>>& b)
{
  a.insert(a.end(), b.begin(), b.end());
  return a;
}

static ProxyMappingStats_t& operator+=(ProxyMappingStats_t& a, const ProxyMappingStats_t& b)
{
  for (const auto& [key, entry] : b) {
    a[key].netmaskMatches += entry.netmaskMatches;
    a[key].suffixMatches += entry.suffixMatches;
  }
  return a;
}

static RemoteLoggerStats_t& operator+=(RemoteLoggerStats_t& a, const RemoteLoggerStats_t& b)
{
  for (const auto& [key, entry] : b) {
    a[key] += entry;
  }
  return a;
}

// This function should only be called by the handler to gather
// metrics, wipe the cache, reload the Lua script (not the Lua config)
// or change the current trace regex, and by the SNMP thread to gather
// metrics.
// Note that this currently skips the handler, but includes the taskThread(s).
template <class T>
T broadcastAccFunction(const std::function<T*()>& func)
{
  if (!RecThreadInfo::self().isHandler()) {
    SLOG(g_log << Logger::Error << "broadcastAccFunction has been called by a worker (" << RecThreadInfo::id() << ")" << endl,
         g_slog->withName("runtime")->info(Logr::Critical, "broadcastAccFunction has been called by a worker")); // tid will be added
    _exit(1);
  }

  unsigned int thread = 0;
  T ret = T();
  for (const auto& threadInfo : RecThreadInfo::infos()) {
    if (thread++ == RecThreadInfo::id()) {
      continue;
    }

    const auto& tps = threadInfo.pipes;
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
    SLOG(g_log << Logger::Error << "Assigning local query addresses: " << e.what(),
         log->error(Logr::Error, e.what(), "Unable to assign local query address"));
    return 99;
  }

  if (pdns::isQueryLocalAddressFamilyEnabled(AF_INET)) {
    SyncRes::s_doIPv4 = true;
    SLOG(g_log << Logger::Warning << "Enabling IPv4 transport for outgoing queries" << endl,
         log->info(Logr::Notice, "Enabling IPv4 transport for outgoing queries"));
  }
  else {
    SLOG(g_log << Logger::Warning << "NOT using IPv4 for outgoing queries - add an IPv4 address (like '0.0.0.0') to query-local-address to enable" << endl,
         log->info(Logr::Warning, "NOT using IPv4 for outgoing queries - add an IPv4 address (like '0.0.0.0') to query-local-address to enable"));
  }

  if (pdns::isQueryLocalAddressFamilyEnabled(AF_INET6)) {
    SyncRes::s_doIPv6 = true;
    SLOG(g_log << Logger::Warning << "Enabling IPv6 transport for outgoing queries" << endl,
         log->info(Logr::Notice, "Enabling IPv6 transport for outgoing queries"));
  }
  else {
    SLOG(g_log << Logger::Warning << "NOT using IPv6 for outgoing queries - add an IPv6 address (like '::') to query-local-address to enable" << endl,
         log->info(Logr::Warning, "NOT using IPv6 for outgoing queries - add an IPv6 address (like '::') to query-local-address to enable"));
  }

  if (!SyncRes::s_doIPv6 && !SyncRes::s_doIPv4) {
    SLOG(g_log << Logger::Error << "No outgoing addresses configured! Can not continue" << endl,
         log->info(Logr::Error, "No outgoing addresses configured! Can not continue"));
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
    SLOG(g_log << Logger::Error << "Unknown DNSSEC mode " << ::arg()["dnssec"] << endl,
         log->info(Logr::Error, "Unknown DNSSEC mode", "dnssec", Logging::Loggable(::arg()["dnssec"])));
    return 1;
  }

  g_signatureInceptionSkew = ::arg().asNum("signature-inception-skew");
  if (g_signatureInceptionSkew < 0) {
    SLOG(g_log << Logger::Error << "A negative value for 'signature-inception-skew' is not allowed" << endl,
         log->info(Logr::Error, "A negative value for 'signature-inception-skew' is not allowed"));
    return 1;
  }

  g_dnssecLogBogus = ::arg().mustDo("dnssec-log-bogus");
  g_maxNSEC3Iterations = ::arg().asNum("nsec3-max-iterations");
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
    if (!g_slogStructured) {
      g_log << Logger::Warning << "Will not send queries to: ";
      for (auto i = ips.begin(); i != ips.end(); ++i) {
        if (i != ips.begin()) {
          g_log << Logger::Warning << ", ";
        }
        g_log << Logger::Warning << *i;
      }
      g_log << Logger::Warning << endl;
    }
    else {
      log->info(Logr::Notice, "Will not send queries to", "addresses", Logging::IterLoggable(ips.begin(), ips.end()));
    }
  }
}

static int initSyncRes(Logr::log_t log, const std::optional<std::string>& myHostname)
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
  SyncRes::s_nonresolvingnsmaxfails = ::arg().asNum("non-resolving-ns-max-fails");
  SyncRes::s_nonresolvingnsthrottletime = ::arg().asNum("non-resolving-ns-throttle-time");
  SyncRes::s_serverID = ::arg()["server-id"];
  SyncRes::s_maxqperq = ::arg().asNum("max-qperq");
  SyncRes::s_maxnsperresolve = ::arg().asNum("max-ns-per-resolve");
  SyncRes::s_maxnsaddressqperq = ::arg().asNum("max-ns-address-qperq");
  SyncRes::s_maxtotusec = 1000 * ::arg().asNum("max-total-msec");
  SyncRes::s_maxdepth = ::arg().asNum("max-recursion-depth");
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
  {
    uint64_t sse = ::arg().asNum("serve-stale-extensions");
    if (sse > std::numeric_limits<uint16_t>::max()) {
      SLOG(g_log << Logger::Error << "Illegal serve-stale-extensions value: " << sse << "; range = 0..65536" << endl,
           log->info(Logr::Error, "Illegal serve-stale-extensions value; range = 0..65536", "value", Logging::Loggable(sse)));
      return 1;
    }
    MemRecursorCache::s_maxServedStaleExtensions = sse;
    NegCache::s_maxServedStaleExtensions = sse;
  }

  if (SyncRes::s_tcp_fast_open_connect) {
    checkFastOpenSysctl(true, log);
    checkTFOconnect(log);
  }

  if (SyncRes::s_serverID.empty()) {
    SyncRes::s_serverID = myHostname.has_value() ? *myHostname : "";
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

  if (SyncRes::s_qnameminimization) {
    // With an empty cache, a rev ipv6 query with dnssec enabled takes
    // almost 100 queries. Default maxqperq is 60.
    SyncRes::s_maxqperq = std::max(SyncRes::s_maxqperq, static_cast<unsigned int>(100));
  }

  SyncRes::s_hardenNXD = SyncRes::HardenNXD::DNSSEC;
  string value = ::arg()["nothing-below-nxdomain"];
  if (value == "yes") {
    SyncRes::s_hardenNXD = SyncRes::HardenNXD::Yes;
  }
  else if (value == "no") {
    SyncRes::s_hardenNXD = SyncRes::HardenNXD::No;
  }
  else if (value != "dnssec") {
    SLOG(g_log << Logger::Error << "Unknown nothing-below-nxdomain mode: " << value << endl,
         log->info(Logr::Error, "Unknown nothing-below-nxdomain mode", "mode", Logging::Loggable(value)));
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
    if (addr.sin4.sin_family != 0) { // NOLINT: union access
      netmask = Netmask(addr, 32);
      done = true;
    }
    if (!done) {
      addr = pdns::getNonAnyQueryLocalAddress(AF_INET6);
      if (addr.sin4.sin_family != 0) { // NOLINT: union access
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

static void initDistribution(Logr::log_t log)
{
  g_balancingFactor = ::arg().asDouble("distribution-load-factor");
  if (g_balancingFactor != 0.0 && g_balancingFactor < 1.0) {
    g_balancingFactor = 0.0;
    SLOG(g_log << Logger::Warning << "Asked to run with a distribution-load-factor below 1.0, disabling it instead" << endl,
         log->info(Logr::Warning, "Asked to run with a distribution-load-factor below 1.0, disabling it instead"));
  }

#ifdef SO_REUSEPORT
  g_reusePort = ::arg().mustDo("reuseport");
#endif

  RecThreadInfo::infos().resize(RecThreadInfo::numHandlers() + RecThreadInfo::numDistributors() + RecThreadInfo::numWorkers() + RecThreadInfo::numTaskThreads());

  if (g_reusePort) {
    if (RecThreadInfo::weDistributeQueries()) {
      /* first thread is the handler, then distributors */
      for (unsigned int threadId = 1; threadId <= RecThreadInfo::numDistributors(); threadId++) {
        auto& info = RecThreadInfo::info(threadId);
        auto& deferredAdds = info.deferredAdds;
        auto& tcpSockets = info.tcpSockets;
        makeUDPServerSockets(deferredAdds, log);
        makeTCPServerSockets(deferredAdds, tcpSockets, log);
      }
    }
    else {
      /* first thread is the handler, there is no distributor here and workers are accepting queries */
      for (unsigned int threadId = 1; threadId <= RecThreadInfo::numWorkers(); threadId++) {
        auto& info = RecThreadInfo::info(threadId);
        auto& deferredAdds = info.deferredAdds;
        auto& tcpSockets = info.tcpSockets;
        makeUDPServerSockets(deferredAdds, log);
        makeTCPServerSockets(deferredAdds, tcpSockets, log);
      }
    }
  }
  else {
    std::set<int> tcpSockets;
    /* we don't have reuseport so we can only open one socket per
       listening addr:port and everyone will listen on it */
    makeUDPServerSockets(g_deferredAdds, log);
    makeTCPServerSockets(g_deferredAdds, tcpSockets, log);

    /* every listener (so distributor if g_weDistributeQueries, workers otherwise)
       needs to listen to the shared sockets */
    if (RecThreadInfo::weDistributeQueries()) {
      /* first thread is the handler, then distributors */
      for (unsigned int threadId = 1; threadId <= RecThreadInfo::numDistributors(); threadId++) {
        RecThreadInfo::info(threadId).tcpSockets = tcpSockets;
      }
    }
    else {
      /* first thread is the handler, there is no distributor here and workers are accepting queries */
      for (unsigned int threadId = 1; threadId <= RecThreadInfo::numWorkers(); threadId++) {
        RecThreadInfo::info(threadId).tcpSockets = tcpSockets;
      }
    }
  }
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
    SLOG(g_log << Logger::Warning << "Calling daemonize, going to background" << endl,
         log->info(Logr::Warning, "Calling daemonize, going to background"));
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
    SLOG(g_log << Logger::Error << "Unable to launch, udp-source-port-min is not a valid port number" << endl,
         log->info(Logr::Error, "Unable to launch, udp-source-port-min is not a valid port number"));
    return 99; // this isn't going to fix itself either
  }
  g_minUdpSourcePort = port;
  port = ::arg().asNum("udp-source-port-max");
  if (port < 1024 || port > 65535 || port < g_minUdpSourcePort) {
    SLOG(g_log << Logger::Error << "Unable to launch, udp-source-port-max is not a valid port number or is smaller than udp-source-port-min" << endl,
         log->info(Logr::Error, "Unable to launch, udp-source-port-max is not a valid port number or is smaller than udp-source-port-min"));
    return 99; // this isn't going to fix itself either
  }
  g_maxUdpSourcePort = port;
  std::vector<string> parts{};
  stringtok(parts, ::arg()["udp-source-port-avoid"], ", ");
  for (const auto& part : parts) {
    port = std::stoi(part);
    if (port < 1024 || port > 65535) {
      SLOG(g_log << Logger::Error << "Unable to launch, udp-source-port-avoid contains an invalid port number: " << part << endl,
           log->info(Logr::Error, "Unable to launch, udp-source-port-avoid contains an invalid port number", "port", Logging::Loggable(part)));
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
    SLOG(g_log << Logger::Error << msg << endl,
         log->info(Logr::Error, msg));
#endif // HAVE_NET_SNMP
  }
}

static int initControl(Logr::log_t log, uid_t newuid, int forks) // NOLINT(bugprone-easily-swappable-parameter*) #12791 Remove NOLINT(readability-function-cognitive-complexity) omoerbeek
{
  if (!::arg()["chroot"].empty()) {
#ifdef HAVE_SYSTEMD
    char* ns;
    ns = getenv("NOTIFY_SOCKET");
    if (ns != nullptr) {
      SLOG(g_log << Logger::Error << "Unable to chroot when running from systemd. Please disable chroot= or set the 'Type' for this service to 'simple'" << endl,
           log->info(Logr::Error, "Unable to chroot when running from systemd. Please disable chroot= or set the 'Type' for this service to 'simple'"));
      return 1;
    }
#endif
    if (chroot(::arg()["chroot"].c_str()) < 0 || chdir("/") < 0) {
      int err = errno;
      SLOG(g_log << Logger::Error << "Unable to chroot to '" + ::arg()["chroot"] + "': " << stringerror(err) << ", exiting" << endl,
           log->error(Logr::Error, err, "Unable to chroot", "chroot", Logging::Loggable(::arg()["chroot"])));
      return 1;
    }
    SLOG(g_log << Logger::Info << "Chrooted to '" << ::arg()["chroot"] << "'" << endl,
         log->info(Logr::Info, "Chrooted", "chroot", Logging::Loggable(::arg()["chroot"])));
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
    SLOG(g_log << Logger::Warning << e.what() << endl,
         log->error(Logr::Warning, e.what(), "Could not drop capabilities"));
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

    parts.clear();
    NetmaskGroup dontThrottleNetmasks;
    stringtok(parts, ::arg()["dont-throttle-netmasks"], " ,");
    for (const auto& part : parts) {
      dontThrottleNetmasks.addMask(Netmask(part));
    }
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
    if (parts.size()) {
      SLOG(g_log << Logger::Error << "dot-to-auth-names setting contains names, but Recursor was built without DNS over TLS support. Setting will be ignored." << endl,
           log->info(Logr::Error, "dot-to-auth-names setting contains names, but Recursor was built without DNS over TLS support. Setting will be ignored"));
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
        SLOG(g_log << Logger::Error << "Invalid prefix for 'dns64-prefix', the current implementation only supports /96 prefixes: " << ::arg()["dns64-prefix"] << endl,
             log->info(Logr::Error, "Invalid prefix for 'dns64-prefix', the current implementation only supports /96 prefixes", "prefix", Logging::Loggable(::arg()["dns64-prefix"])));
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
      SLOG(g_log << Logger::Error << "Invalid prefix '" << ::arg()["dns64-prefix"] << "' for 'dns64-prefix': " << ne.reason << endl,
           log->info(Logr::Error, "Invalid prefix", "dns64-prefix", Logging::Loggable(::arg()["dns64-prefix"])));
      return 1;
    }
  }
  return 0;
}

static int serviceMain(Logr::log_t log) // NOLINT(readability-function-cognitive-complexity) #12791 Remove NOLINT(readability-function-cognitive-complexity) omoerbeek
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
      SLOG(g_log << Logger::Error << "Unknown logging facility " << ::arg().asNum("logging-facility") << endl,
           log->info(Logr::Error, "Unknown logging facility", "facility", Logging::Loggable(::arg().asNum("logging-facility"))));
    }
  }

  showProductVersion();

  g_disthashseed = dns_random(0xffffffff);

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

  luaConfigDelayedThreads delayedLuaThreads;
  try {
    ProxyMapping proxyMapping;
    loadRecursorLuaConfig(::arg()["lua-config-file"], delayedLuaThreads, proxyMapping);
    // Initial proxy mapping
    g_proxyMapping = proxyMapping.empty() ? nullptr : std::make_unique<ProxyMapping>(proxyMapping);
  }
  catch (PDNSException& e) {
    SLOG(g_log << Logger::Error << "Cannot load Lua configuration: " << e.reason << endl,
         log->error(Logr::Error, e.reason, "Cannot load Lua configuration"));
    return 1;
  }

  parseACLs();
  initPublicSuffixList(::arg()["public-suffix-list-file"]);

  initDontQuery(log);

  RecThreadInfo::setWeDistributeQueries(::arg().mustDo("pdns-distributes-queries"));
  if (RecThreadInfo::weDistributeQueries()) {
    SLOG(g_log << Logger::Warning << "PowerDNS Recursor itself will distribute queries over threads" << endl,
         log->info(Logr::Notice, "PowerDNS Recursor itself will distribute queries over threads"));
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
  auto myHostname = getHostname();
  if (!myHostname.has_value()) {
    SLOG(g_log << Logger::Warning << "Unable to get the hostname, NSID and id.server values will be empty" << endl,
         log->info(Logr::Warning, "Unable to get the hostname, NSID and id.server values will be empty"));
  }

  ret = initSyncRes(log, myHostname);
  if (ret != 0) {
    return ret;
  }

  g_proxyProtocolACL.toMasks(::arg()["proxy-protocol-from"]);
  g_proxyProtocolMaximumSize = ::arg().asNum("proxy-protocol-maximum-size");

  ret = initDNS64(log);
  if (ret != 0) {
    return ret;
  }
  g_networkTimeoutMsec = ::arg().asNum("network-timeout");

  std::tie(g_initialDomainMap, g_initialAllowNotifyFor) = parseZoneConfiguration();

  g_latencyStatSize = ::arg().asNum("latency-statistic-size");

  g_logCommonErrors = ::arg().mustDo("log-common-errors");
  g_logRPZChanges = ::arg().mustDo("log-rpz-changes");

  g_anyToTcp = ::arg().mustDo("any-to-tcp");
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
    SLOG(g_log << Logger::Error << "Unknown edns-padding-mode: " << ::arg()["edns-padding-mode"] << endl,
         log->info(Logr::Error, "Unknown edns-padding-mode", "edns-padding-mode", Logging::Loggable(::arg()["edns-padding-mode"])));
    return 1;
  }
  g_paddingTag = ::arg().asNum("edns-padding-tag");
  g_paddingOutgoing = ::arg().mustDo("edns-padding-out");

  RecThreadInfo::setNumDistributorThreads(::arg().asNum("distributor-threads"));
  RecThreadInfo::setNumWorkerThreads(::arg().asNum("threads"));
  if (RecThreadInfo::numWorkers() < 1) {
    SLOG(g_log << Logger::Warning << "Asked to run with 0 threads, raising to 1 instead" << endl,
         log->info(Logr::Warning, "Asked to run with 0 threads, raising to 1 instead"));
    RecThreadInfo::setNumWorkerThreads(1);
  }

  g_maxMThreads = ::arg().asNum("max-mthreads");

  int64_t maxInFlight = ::arg().asNum("max-concurrent-requests-per-tcp-connection");
  if (maxInFlight < 1 || maxInFlight > USHRT_MAX || maxInFlight >= g_maxMThreads) {
    SLOG(g_log << Logger::Warning << "Asked to run with illegal max-concurrent-requests-per-tcp-connection, setting to default (10)" << endl,
         log->info(Logr::Warning, "Asked to run with illegal max-concurrent-requests-per-tcp-connection, setting to default (10)"));
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

  g_gettagNeedsEDNSOptions = ::arg().mustDo("gettag-needs-edns-options");

  s_statisticsInterval = ::arg().asNum("statistics-interval");

  SyncRes::s_addExtendedResolutionDNSErrors = ::arg().mustDo("extended-resolution-errors");

  if (::arg().asNum("aggressive-nsec-cache-size") > 0) {
    if (g_dnssecmode == DNSSECMode::ValidateAll || g_dnssecmode == DNSSECMode::ValidateForLog || g_dnssecmode == DNSSECMode::Process) {
      g_aggressiveNSECCache = make_unique<AggressiveNSECCache>(::arg().asNum("aggressive-nsec-cache-size"));
    }
    else {
      SLOG(g_log << Logger::Warning << "Aggressive NSEC/NSEC3 caching is enabled but DNSSEC validation is not set to 'validate', 'log-fail' or 'process', ignoring" << endl,
           log->info(Logr::Warning, "Aggressive NSEC/NSEC3 caching is enabled but DNSSEC validation is not set to 'validate', 'log-fail' or 'process', ignoring"));
    }
  }

  AggressiveNSECCache::s_maxNSEC3CommonPrefix = static_cast<uint8_t>(std::round(std::log2(::arg().asNum("aggressive-cache-min-nsec3-hit-ratio"))));
  SLOG(g_log << Logger::Debug << "NSEC3 aggressive cache tuning: aggressive-cache-min-nsec3-hit-ratio: " << ::arg().asNum("aggressive-cache-min-nsec3-hit-ratio") << " max common prefix bits: " << std::to_string(AggressiveNSECCache::s_maxNSEC3CommonPrefix) << endl,
       log->info(Logr::Debug, "NSEC3 aggressive cache tuning", "aggressive-cache-min-nsec3-hit-ratio", Logging::Loggable(::arg().asNum("aggressive-cache-min-nsec3-hit-ratio")), "maxCommonPrefixBits", Logging::Loggable(AggressiveNSECCache::s_maxNSEC3CommonPrefix)));

  initSuffixMatchNodes(log);
  initCarbon();
  initDistribution(log);

#ifdef NOD_ENABLED
  // Setup newly observed domain globals
  setupNODGlobal();
#endif /* NOD_ENABLED */

  auto forks = initForks(log);

  checkOrFixFDS(log);

#ifdef HAVE_LIBSODIUM
  if (sodium_init() == -1) {
    SLOG(g_log << Logger::Error << "Unable to initialize sodium crypto library" << endl,
         log->info(Logr::Error, "Unable to initialize sodium crypto library"));
    return 99;
  }
#endif

  openssl_thread_setup();
  openssl_seed();
  /* setup rng before chroot */
  dns_random_init();

  if (::arg()["server-id"].empty()) {
    ::arg().set("server-id") = myHostname.has_value() ? *myHostname : "";
  }

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

  startLuaConfigDelayedThreads(delayedLuaThreads, g_luaconfs.getCopy().generation);
  delayedLuaThreads.rpzPrimaryThreads.clear(); // no longer needed

  RecThreadInfo::makeThreadPipes(log);

  g_tcpTimeout = ::arg().asNum("client-tcp-timeout");
  g_maxTCPPerClient = ::arg().asNum("max-tcp-per-client");
  g_tcpMaxQueriesPerConn = ::arg().asNum("max-tcp-queries-per-connection");
  g_maxUDPQueriesPerRound = ::arg().asNum("max-udp-queries-per-round");

  g_useKernelTimestamp = ::arg().mustDo("protobuf-use-kernel-timestamp");

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

  return RecThreadInfo::runThreads(log);
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
  catch (std::exception& e) {
    if (g_logCommonErrors) {
      SLOG(g_log << Logger::Error << "PIPE function we executed created exception: " << e.what() << endl, // but what if they wanted an answer.. we send 0
           g_slog->withName("runtime")->error(Logr::Error, e.what(), "PIPE function we executed created exception", "exception", Logging::Loggable("std::exception")));
    }
  }
  catch (PDNSException& e) {
    if (g_logCommonErrors) {
      SLOG(g_log << Logger::Error << "PIPE function we executed created PDNS exception: " << e.reason << endl, // but what if they wanted an answer.. we send 0
           g_slog->withName("runtime")->error(Logr::Error, e.reason, "PIPE function we executed created exception", "exception", Logging::Loggable("PDNSException")));
    }
  }
  if (tmsg->wantAnswer) {
    if (write(RecThreadInfo::self().pipes.writeFromThread, &resp, sizeof(resp)) != sizeof(resp)) {
      delete tmsg; // NOLINT: manual ownership handling
      unixDie("write to thread pipe returned wrong size or error");
    }
  }

  delete tmsg; // NOLINT: manual ownership handling
}

static void handleRCC(int fd, FDMultiplexer::funcparam_t& /* var */)
{
  auto log = g_slog->withName("control");
  try {
    FDWrapper clientfd = accept(fd, nullptr, nullptr);
    if (clientfd == -1) {
      throw PDNSException("accept failed");
    }
    string msg = g_rcc.recv(clientfd).d_str;
    SLOG(g_log << Logger::Info << "Received rec_control command '" << msg << "' via controlsocket" << endl,
         log->info(Logr::Info, "Received rec_control command via control socket", "command", Logging::Loggable(msg)));

    RecursorControlParser rcp;
    RecursorControlParser::func_t* command;
    auto answer = rcp.getAnswer(clientfd, msg, &command);

    g_rcc.send(clientfd, answer);
    command();
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "Error dealing with control socket request: " << e.what() << endl,
         log->error(Logr::Error, e.what(), "Exception while dealing with control socket request", "exception", Logging::Loggable("std::exception")));
  }
  catch (const PDNSException& ae) {
    SLOG(g_log << Logger::Error << "Error dealing with control socket request: " << ae.reason << endl,
         log->error(Logr::Error, ae.reason, "Exception while dealing with control socket request", "exception", Logging::Loggable("PDNSException")));
  }
}

class PeriodicTask
{
public:
  PeriodicTask(const string& n, time_t p) :
    period{p, 0}, name(n)
  {
    if (p <= 0) {
      throw PDNSException("Invalid period of periodic task " + n);
    }
  }

  void runIfDue(struct timeval& now, const std::function<void()>& f)
  {
    if (last_run < now - period) {
      // cerr << RecThreadInfo::id() << ' ' << name << ' ' << now.tv_sec << '.' << now.tv_usec << " running" << endl;
      f();
      Utility::gettimeofday(&last_run);
      now = last_run;
    }
  }

  time_t getPeriod() const
  {
    return period.tv_sec;
  }

  void setPeriod(time_t p)
  {
    period.tv_sec = p;
  }

  void updateLastRun()
  {
    Utility::gettimeofday(&last_run);
  }

  bool hasRun() const
  {
    return last_run.tv_sec != 0 || last_run.tv_usec != 0;
  }

private:
  struct timeval last_run
  {
    0, 0
  };
  struct timeval period;
  const string name;
};

static void houseKeepingWork(Logr::log_t log) // NOLINT(readability-function-cognitive-complexity) #12791 Remove NOLINT(readability-function-cognitive-complexity) omoerbeek
{
  struct timeval now
  {
  };
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
      packetCacheTask.runIfDue(now, []() {
        g_packetCache->doPruneTo(g_maxPacketCacheEntries);
      });
    }
    static PeriodicTask recordCachePruneTask{"RecordCachePruneTask", 5};
    recordCachePruneTask.runIfDue(now, []() {
      g_recCache->doPrune(g_maxCacheEntries);
    });

    static PeriodicTask negCachePruneTask{"NegCachePrunteTask", 5};
    negCachePruneTask.runIfDue(now, []() {
      g_negCache->prune(g_maxCacheEntries / 8);
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
        SLOG(g_log << Logger::Error << "Exception while performing security poll: " << e.what() << endl,
             log->error(Logr::Error, e.what(), "Exception while performing security poll"));
      }
      catch (const PDNSException& e) {
        SLOG(g_log << Logger::Error << "Exception while performing security poll: " << e.reason << endl,
             log->error(Logr::Error, e.reason, "Exception while performing security poll"));
      }
      catch (const ImmediateServFailException& e) {
        SLOG(g_log << Logger::Error << "Exception while performing security poll: " << e.reason << endl,
             log->error(Logr::Error, e.reason, "Exception while performing security poll"));
      }
      catch (const PolicyHitException& e) {
        SLOG(g_log << Logger::Error << "Policy hit while performing security poll" << endl,
             log->info(Logr::Error, "Policy hit while performing security poll"));
      }
      catch (...) {
        SLOG(g_log << Logger::Error << "Exception while performing security poll" << endl,
             log->info(Logr::Error, "Exception while performing security poll"));
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
        SLOG(g_log << Logger::Debug << "Refreshing Trust Anchors from file" << endl,
             log->info(Logr::Debug, "Refreshing Trust Anchors from file"));
        try {
          map<DNSName, dsmap_t> dsAnchors;
          if (updateTrustAnchorsFromFile(luaconfsLocal->trustAnchorFileInfo.fname, dsAnchors, log)) {
            g_luaconfs.modify([&dsAnchors](LuaConfigItems& lci) {
              lci.dsAnchors = dsAnchors;
            });
          }
        }
        catch (const PDNSException& pe) {
          SLOG(g_log << Logger::Error << "Unable to update Trust Anchors: " << pe.reason << endl,
               log->error(Logr::Error, pe.reason, "Unable to update Trust Anchors"));
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
    SLOG(g_log << Logger::Error << "Fatal error in housekeeping thread: " << ae.reason << endl,
         log->error(Logr::Error, ae.reason, "Fatal error in housekeeping thread"));
    throw;
  }
  catch (...) {
    t_running = false;
    SLOG(g_log << Logger::Error << "Uncaught exception in housekeeping thread" << endl,
         log->info(Logr::Error, "Uncaught exception in housekeeping thread"));
    throw;
  }
}

static void runLuaMaintenance(RecThreadInfo& threadInfo, time_t& last_lua_maintenance, time_t luaMaintenanceInterval)
{
  if (t_pdl != nullptr) {
    // lua-dns-script directive is present, call the maintenance callback if needed
    /* remember that the listener threads handle TCP queries */
    if (threadInfo.isWorker() || threadInfo.isListener()) {
      // Only on threads processing queries
      if (g_now.tv_sec - last_lua_maintenance >= luaMaintenanceInterval) {
        struct timeval start
        {
        };
        Utility::gettimeofday(&start);
        t_pdl->maintenance();
        last_lua_maintenance = g_now.tv_sec;
        struct timeval stop
        {
        };
        Utility::gettimeofday(&stop);
        t_Counters.at(rec::Counter::maintenanceUsec) += uSec(stop - start);
        ++t_Counters.at(rec::Counter::maintenanceCalls);
      }
    }
  }
}

static void runTCPMaintenance(RecThreadInfo& threadInfo, bool& listenOnTCP, unsigned int maxTcpClients)
{
  if (threadInfo.isListener()) {
    if (listenOnTCP) {
      if (TCPConnection::getCurrentConnections() > maxTcpClients) { // shutdown, too many connections
        for (const auto fileDesc : threadInfo.tcpSockets) {
          t_fdm->removeReadFD(fileDesc);
        }
        listenOnTCP = false;
      }
    }
    else {
      if (TCPConnection::getCurrentConnections() <= maxTcpClients) { // reenable
        for (const auto fileDesc : threadInfo.tcpSockets) {
          t_fdm->addReadFD(fileDesc, handleNewTCPQuestion);
        }
        listenOnTCP = true;
      }
    }
  }
}

static void recLoop()
{
  unsigned int maxTcpClients = ::arg().asNum("max-tcp-clients");
  bool listenOnTCP{true};
  time_t last_stat = 0;
  time_t last_carbon = 0;
  time_t last_lua_maintenance = 0;
  time_t carbonInterval = ::arg().asNum("carbon-interval");
  time_t luaMaintenanceInterval = ::arg().asNum("lua-maintenance-interval");

  auto& threadInfo = RecThreadInfo::self();

  while (!RecursorControlChannel::stop) {
    while (MT->schedule(&g_now)) {
      ; // MTasker letting the mthreads do their thing
    }

    // Use primes, it avoid not being scheduled in cases where the counter has a regular pattern.
    // We want to call handler thread often, it gets scheduled about 2 times per second
    if (((threadInfo.isHandler() || threadInfo.isTaskThread()) && s_counter % 11 == 0) || s_counter % 499 == 0) {
      struct timeval start
      {
      };
      Utility::gettimeofday(&start);
      MT->makeThread(houseKeeping, nullptr);
      if (!threadInfo.isTaskThread()) {
        struct timeval stop
        {
        };
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
          SLOG(g_log << Logger::Warning << "Timeout from remote TCP client " << conn->d_remote.toStringWithPort() << endl, // NOLINT: union access
               g_slogtcpin->info(Logr::Warning, "Timeout from remote TCP client", "remote", Logging::Loggable(conn->d_remote)));
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
        MT->makeThread(doCarbonDump, nullptr);
        last_carbon = g_now.tv_sec;
      }
    }
    runLuaMaintenance(threadInfo, last_lua_maintenance, luaMaintenanceInterval);

    t_fdm->run(&g_now);
    // 'run' updates g_now for us

    runTCPMaintenance(threadInfo, listenOnTCP, maxTcpClients);
  }
}

static void recursorThread() // NOLINT(readability-function-cognitive-complexity) #12791 Remove NOLINT(readability-function-cognitive-complexity) omoerbeek
{
  auto log = g_slog->withName("runtime");
  t_Counters.updateSnap(true);
  try {
    auto& threadInfo = RecThreadInfo::self();
    {
      SyncRes tmp(g_now); // make sure it allocates tsstorage before we do anything, like primeHints or so..
      SyncRes::setDomainMap(g_initialDomainMap);
      t_allowFrom = g_initialAllowFrom;
      t_allowNotifyFrom = g_initialAllowNotifyFrom;
      t_allowNotifyFor = g_initialAllowNotifyFor;
      t_udpclientsocks = std::make_unique<UDPClientSocks>();
      t_tcpClientCounts = std::make_unique<tcpClientCounts_t>();
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
          SLOG(g_log << Logger::Critical << "Priming cache failed, stopping" << endl,
               log->info(Logr::Critical, "Priming cache failed, stopping"));
        }
        SLOG(g_log << Logger::Debug << "Done priming cache with root hints" << endl,
             log->info(Logr::Debug, "Done priming cache with root hints"));
      }
    }

#ifdef NOD_ENABLED
    if (threadInfo.isWorker()) {
      setupNODThread(log);
    }
#endif /* NOD_ENABLED */

    /* the listener threads handle TCP queries */
    if (threadInfo.isWorker() || threadInfo.isListener()) {
      try {
        if (!::arg()["lua-dns-script"].empty()) {
          t_pdl = std::make_shared<RecursorLua4>();
          t_pdl->loadFile(::arg()["lua-dns-script"]);
          SLOG(g_log << Logger::Warning << "Loaded 'lua' script from '" << ::arg()["lua-dns-script"] << "'" << endl,
               log->info(Logr::Warning, "Loading Lua script from file", "name", Logging::Loggable(::arg()["lua-dns-script"])));
        }
      }
      catch (std::exception& e) {
        SLOG(g_log << Logger::Error << "Failed to load 'lua' script from '" << ::arg()["lua-dns-script"] << "': " << e.what() << endl,
             log->error(Logr::Error, e.what(), "Failed to load Lua script from file", "name", Logging::Loggable(::arg()["lua-dns-script"])));
        _exit(99);
      }
    }

    unsigned int ringsize = ::arg().asNum("stats-ringbuffer-entries") / RecThreadInfo::numWorkers();
    if (ringsize != 0) {
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
    MT = std::make_unique<MT_t>(::arg().asNum("stack-size"), ::arg().asNum("stack-cache-size"));
    threadInfo.mt = MT.get();

    /* start protobuf export threads if needed */
    auto luaconfsLocal = g_luaconfs.getLocal();
    checkProtobufExport(luaconfsLocal);
    checkOutgoingProtobufExport(luaconfsLocal);
#ifdef HAVE_FSTRM
    checkFrameStreamExport(luaconfsLocal, luaconfsLocal->frameStreamExportConfig, t_frameStreamServersInfo);
    checkFrameStreamExport(luaconfsLocal, luaconfsLocal->nodFrameStreamExportConfig, t_nodFrameStreamServersInfo);
#endif

    t_fdm = unique_ptr<FDMultiplexer>(getMultiplexer(log));

    std::unique_ptr<RecursorWebServer> rws;

    t_fdm->addReadFD(threadInfo.pipes.readToThread, handlePipeRequest);

    if (threadInfo.isHandler()) {
      if (::arg().mustDo("webserver")) {
        SLOG(g_log << Logger::Warning << "Enabling web server" << endl,
             log->info(Logr::Info, "Enabling web server"))
        try {
          rws = make_unique<RecursorWebServer>(t_fdm.get());
        }
        catch (const PDNSException& e) {
          SLOG(g_log << Logger::Error << "Unable to start the internal web server: " << e.reason << endl,
               log->error(Logr::Critical, e.reason, "Exception while starting internal web server"));
          _exit(99);
        }
      }
      SLOG(g_log << Logger::Info << "Enabled '" << t_fdm->getName() << "' multiplexer" << endl,
           log->info(Logr::Info, "Enabled multiplexer", "name", Logging::Loggable(t_fdm->getName())));
    }
    else {
      t_fdm->addReadFD(threadInfo.pipes.readQueriesToThread, handlePipeRequest);

      if (threadInfo.isListener()) {
        if (g_reusePort) {
          /* then every listener has its own FDs */
          for (const auto& deferred : threadInfo.deferredAdds) {
            t_fdm->addReadFD(deferred.first, deferred.second);
          }
        }
        else {
          /* otherwise all listeners are listening on the same ones */
          for (const auto& deferred : g_deferredAdds) {
            t_fdm->addReadFD(deferred.first, deferred.second);
          }
        }
      }
    }

    if (threadInfo.isHandler()) {
      t_fdm->addReadFD(g_rcc.d_fd, handleRCC); // control channel
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
  catch (PDNSException& ae) {
    SLOG(g_log << Logger::Error << "Exception: " << ae.reason << endl,
         log->error(Logr::Error, ae.reason, "Exception in RecursorThread", "exception", Logging::Loggable("PDNSException")))
  }
  catch (std::exception& e) {
    SLOG(g_log << Logger::Error << "STL Exception: " << e.what() << endl,
         log->error(Logr::Error, e.what(), "Exception in RecursorThread", "exception", Logging::Loggable("std::exception")))
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "any other exception in main: " << endl,
         log->info(Logr::Error, "Exception in RecursorThread"));
  }
}

static void initArgs()
{
#if HAVE_FIBER_SANITIZER
  // Asan needs more stack
  ::arg().set("stack-size", "stack size per mthread") = "600000";
#else
  ::arg().set("stack-size", "stack size per mthread") = "200000";
#endif
  ::arg().set("stack-cache-size", "Size of the stack cache, per mthread") = "100";
  // This mode forces metrics snap updates and disable root-refresh, to get consistent counters
  ::arg().setSwitch("devonly-regression-test-mode", "internal use only") = "no";
  ::arg().set("soa-minimum-ttl", "Don't change") = "0";
  ::arg().set("no-shuffle", "Don't change") = "off";
  ::arg().set("local-port", "port to listen on") = "53";
  ::arg().set("local-address", "IP addresses to listen on, separated by spaces or commas. Also accepts ports.") = "127.0.0.1";
  ::arg().setSwitch("non-local-bind", "Enable binding to non-local addresses by using FREEBIND / BINDANY socket options") = "no";
  ::arg().set("trace", "if we should output heaps of logging. set to 'fail' to only log failing domains") = "off";
  ::arg().set("dnssec", "DNSSEC mode: off/process-no-validate/process (default)/log-fail/validate") = "process";
  ::arg().set("dnssec-log-bogus", "Log DNSSEC bogus validations") = "no";
  ::arg().set("signature-inception-skew", "Allow the signature inception to be off by this number of seconds") = "60";
  ::arg().set("daemon", "Operate as a daemon") = "no";
  ::arg().setSwitch("write-pid", "Write a PID file") = "yes";
  ::arg().set("loglevel", "Amount of logging. Higher is more. Do not set below 3") = "6";
  ::arg().set("disable-syslog", "Disable logging to syslog, useful when running inside a supervisor that logs stdout") = "no";
  ::arg().set("log-timestamp", "Print timestamps in log lines, useful to disable when running with a tool that timestamps stdout already") = "yes";
  ::arg().set("log-common-errors", "If we should log rather common errors") = "no";
  ::arg().set("chroot", "switch to chroot jail") = "";
  ::arg().set("setgid", "If set, change group id to this gid for more security"
#ifdef HAVE_SYSTEMD
#define SYSTEMD_SETID_MSG ". When running inside systemd, use the User and Group settings in the unit-file!"
              SYSTEMD_SETID_MSG
#endif
              )
    = "";
  ::arg().set("setuid", "If set, change user id to this uid for more security"
#ifdef HAVE_SYSTEMD
              SYSTEMD_SETID_MSG
#endif
              )
    = "";
  ::arg().set("network-timeout", "Wait this number of milliseconds for network i/o") = "1500";
  ::arg().set("threads", "Launch this number of threads") = "2";
  ::arg().set("distributor-threads", "Launch this number of distributor threads, distributing queries to other threads") = "0";
  ::arg().set("processes", "Launch this number of processes (EXPERIMENTAL, DO NOT CHANGE)") = "1"; // if we un-experimental this, need to fix openssl rand seeding for multiple PIDs!
  ::arg().set("config-name", "Name of this virtual configuration - will rename the binary image") = "";
  ::arg().set("api-config-dir", "Directory where REST API stores config and zones") = "";
  ::arg().set("api-key", "Static pre-shared authentication key for access to the REST API") = "";
  ::arg().setSwitch("webserver", "Start a webserver (for REST API)") = "no";
  ::arg().set("webserver-address", "IP Address of webserver to listen on") = "127.0.0.1";
  ::arg().set("webserver-port", "Port of webserver to listen on") = "8082";
  ::arg().set("webserver-password", "Password required for accessing the webserver") = "";
  ::arg().set("webserver-allow-from", "Webserver access is only allowed from these subnets") = "127.0.0.1,::1";
  ::arg().set("webserver-loglevel", "Amount of logging in the webserver (none, normal, detailed)") = "normal";
  ::arg().setSwitch("webserver-hash-plaintext-credentials", "Whether to hash passwords and api keys supplied in plaintext, to prevent keeping the plaintext version in memory at runtime") = "no";
  ::arg().set("carbon-ourname", "If set, overrides our reported hostname for carbon stats") = "";
  ::arg().set("carbon-server", "If set, send metrics in carbon (graphite) format to this server IP address") = "";
  ::arg().set("carbon-interval", "Number of seconds between carbon (graphite) updates") = "30";
  ::arg().set("carbon-namespace", "If set overwrites the first part of the carbon string") = "pdns";
  ::arg().set("carbon-instance", "If set overwrites the instance name default") = "recursor";

  ::arg().set("statistics-interval", "Number of seconds between printing of recursor statistics, 0 to disable") = "1800";
  ::arg().set("quiet", "Suppress logging of questions and answers") = "";
  ::arg().set("logging-facility", "Facility to log messages as. 0 corresponds to local0") = "";
  ::arg().set("config-dir", "Location of configuration directory (recursor.conf)") = SYSCONFDIR;
  ::arg().set("socket-owner", "Owner of socket") = "";
  ::arg().set("socket-group", "Group of socket") = "";
  ::arg().set("socket-mode", "Permissions for socket") = "";

  ::arg().set("socket-dir", string("Where the controlsocket will live, ") + LOCALSTATEDIR + "/pdns-recursor when unset and not chrooted"
#ifdef HAVE_SYSTEMD
                + ". Set to the RUNTIME_DIRECTORY environment variable when that variable has a value (e.g. under systemd).")
    = "";
  auto* runtimeDir = getenv("RUNTIME_DIRECTORY"); // NOLINT(concurrency-mt-unsafe,cppcoreguidelines-pro-type-vararg)
  if (runtimeDir != nullptr) {
    ::arg().set("socket-dir") = runtimeDir;
  }
#else
              )
    = "";
#endif
  ::arg().set("query-local-address", "Source IP address for sending queries") = "0.0.0.0";
  ::arg().set("client-tcp-timeout", "Timeout in seconds when talking to TCP clients") = "2";
  ::arg().set("max-mthreads", "Maximum number of simultaneous Mtasker threads") = "2048";
  ::arg().set("max-tcp-clients", "Maximum number of simultaneous TCP clients") = "128";
  ::arg().set("max-concurrent-requests-per-tcp-connection", "Maximum number of requests handled concurrently per TCP connection") = "10";
  ::arg().set("server-down-max-fails", "Maximum number of consecutive timeouts (and unreachables) to mark a server as down ( 0 => disabled )") = "64";
  ::arg().set("server-down-throttle-time", "Number of seconds to throttle all queries to a server after being marked as down") = "60";
  ::arg().set("dont-throttle-names", "Do not throttle nameservers with this name or suffix") = "";
  ::arg().set("dont-throttle-netmasks", "Do not throttle nameservers with this IP netmask") = "";
  ::arg().set("non-resolving-ns-max-fails", "Number of failed address resolves of a nameserver to start throttling it, 0 is disabled") = "5";
  ::arg().set("non-resolving-ns-throttle-time", "Number of seconds to throttle a nameserver with a name failing to resolve") = "60";

  ::arg().set("hint-file", "If set, load root hints from this file") = "";
  ::arg().set("max-cache-entries", "If set, maximum number of entries in the main cache") = "1000000";
  ::arg().set("max-negative-ttl", "maximum number of seconds to keep a negative cached entry in memory") = "3600";
  ::arg().set("max-cache-bogus-ttl", "maximum number of seconds to keep a Bogus (positive or negative) cached entry in memory") = "3600";
  ::arg().set("max-cache-ttl", "maximum number of seconds to keep a cached entry in memory") = "86400";
  ::arg().set("packetcache-ttl", "maximum number of seconds to keep a cached entry in packetcache") = "86400";
  ::arg().set("max-packetcache-entries", "maximum number of entries to keep in the packetcache") = "500000";
  ::arg().set("packetcache-servfail-ttl", "maximum number of seconds to keep a cached servfail entry in packetcache") = "60";
  ::arg().set("packetcache-negative-ttl", "maximum number of seconds to keep a cached NxDomain or NoData entry in packetcache") = "60";
  ::arg().set("server-id", "Returned when queried for 'id.server' TXT or NSID, defaults to hostname, set custom or 'disabled'") = "";
  ::arg().set("stats-ringbuffer-entries", "maximum number of packets to store statistics for") = "10000";
  ::arg().set("version-string", "string reported on version.pdns or version.bind") = fullVersionString();
  ::arg().set("allow-from", "If set, only allow these comma separated netmasks to recurse") = LOCAL_NETS;
  ::arg().set("allow-from-file", "If set, load allowed netmasks from this file") = "";
  ::arg().set("allow-notify-for", "If set, NOTIFY requests for these zones will be allowed") = "";
  ::arg().set("allow-notify-for-file", "If set, load NOTIFY-allowed zones from this file") = "";
  ::arg().set("allow-notify-from", "If set, NOTIFY requests from these comma separated netmasks will be allowed") = "";
  ::arg().set("allow-notify-from-file", "If set, load NOTIFY-allowed netmasks from this file") = "";
  ::arg().set("entropy-source", "If set, read entropy from this file") = "/dev/urandom";
  ::arg().set("dont-query", "If set, do not query these netmasks for DNS data") = DONT_QUERY;
  ::arg().set("max-tcp-per-client", "If set, maximum number of TCP sessions per client (IP address)") = "0";
  ::arg().set("max-tcp-queries-per-connection", "If set, maximum number of TCP queries in a TCP connection") = "0";
  ::arg().set("spoof-nearmiss-max", "If non-zero, assume spoofing after this many near misses") = "1";
  ::arg().set("single-socket", "If set, only use a single socket for outgoing queries") = "off";
  ::arg().set("auth-zones", "Zones for which we have authoritative data, comma separated domain=file pairs ") = "";
  ::arg().set("lua-config-file", "More powerful configuration options") = "";
  ::arg().setSwitch("allow-trust-anchor-query", "Allow queries for trustanchor.server CH TXT and negativetrustanchor.server CH TXT") = "no";

  ::arg().set("forward-zones", "Zones for which we forward queries, comma separated domain=ip pairs") = "";
  ::arg().set("forward-zones-recurse", "Zones for which we forward queries with recursion bit, comma separated domain=ip pairs") = "";
  ::arg().set("forward-zones-file", "File with (+)domain=ip pairs for forwarding") = "";
  ::arg().set("export-etc-hosts", "If we should serve up contents from /etc/hosts") = "off";
  ::arg().set("export-etc-hosts-search-suffix", "Also serve up the contents of /etc/hosts with this suffix") = "";
  ::arg().set("etc-hosts-file", "Path to 'hosts' file") = "/etc/hosts";
  ::arg().set("serve-rfc1918", "If we should be authoritative for RFC 1918 private IP space") = "yes";
  ::arg().set("lua-dns-script", "Filename containing an optional 'lua' script that will be used to modify dns answers") = "";
  ::arg().set("lua-maintenance-interval", "Number of seconds between calls to the lua user defined maintenance() function") = "1";
  ::arg().set("latency-statistic-size", "Number of latency values to calculate the qa-latency average") = "10000";
  ::arg().setSwitch("disable-packetcache", "Disable packetcache") = "no";
  ::arg().set("ecs-ipv4-bits", "Number of bits of IPv4 address to pass for EDNS Client Subnet") = "24";
  ::arg().set("ecs-ipv4-cache-bits", "Maximum number of bits of IPv4 mask to cache ECS response") = "24";
  ::arg().set("ecs-ipv6-bits", "Number of bits of IPv6 address to pass for EDNS Client Subnet") = "56";
  ::arg().set("ecs-ipv6-cache-bits", "Maximum number of bits of IPv6 mask to cache ECS response") = "56";
  ::arg().setSwitch("ecs-ipv4-never-cache", "If we should never cache IPv4 ECS responses") = "no";
  ::arg().setSwitch("ecs-ipv6-never-cache", "If we should never cache IPv6 ECS responses") = "no";
  ::arg().set("ecs-minimum-ttl-override", "The minimum TTL for records in ECS-specific answers") = "1";
  ::arg().set("ecs-cache-limit-ttl", "Minimum TTL to cache ECS response") = "0";
  ::arg().set("edns-subnet-whitelist", "List of netmasks and domains that we should enable EDNS subnet for (deprecated)") = "";
  ::arg().set("edns-subnet-allow-list", "List of netmasks and domains that we should enable EDNS subnet for") = "";
  ::arg().set("ecs-add-for", "List of client netmasks for which EDNS Client Subnet will be added") = "0.0.0.0/0, ::/0, " LOCAL_NETS_INVERSE;
  ::arg().set("ecs-scope-zero-address", "Address to send to allow-listed authoritative servers for incoming queries with ECS prefix-length source of 0") = "";
  ::arg().setSwitch("use-incoming-edns-subnet", "Pass along received EDNS Client Subnet information") = "no";
  ::arg().setSwitch("pdns-distributes-queries", "If PowerDNS itself should distribute queries over threads") = "no";
  ::arg().setSwitch("root-nx-trust", "If set, believe that an NXDOMAIN from the root means the TLD does not exist") = "yes";
  ::arg().setSwitch("any-to-tcp", "Answer ANY queries with tc=1, shunting to TCP") = "no";
  ::arg().setSwitch("lowercase-outgoing", "Force outgoing questions to lowercase") = "no";
  ::arg().setSwitch("gettag-needs-edns-options", "If EDNS Options should be extracted before calling the gettag() hook") = "no";
  ::arg().set("udp-truncation-threshold", "Maximum UDP response size before we truncate") = "1232";
  ::arg().set("edns-outgoing-bufsize", "Outgoing EDNS buffer size") = "1232";
  ::arg().set("minimum-ttl-override", "The minimum TTL") = "1";
  ::arg().set("max-qperq", "Maximum outgoing queries per query") = "60";
  ::arg().set("max-ns-per-resolve", "Maximum number of NS records to consider to resolve a name, 0 is no limit") = "13";
  ::arg().set("max-ns-address-qperq", "Maximum outgoing NS address queries per query") = "10";
  ::arg().set("max-total-msec", "Maximum total wall-clock time per query in milliseconds, 0 for unlimited") = "7000";
  ::arg().set("max-recursion-depth", "Maximum number of internal recursion calls per query, 0 for unlimited") = "40";
  ::arg().set("max-udp-queries-per-round", "Maximum number of UDP queries processed per recvmsg() round, before returning back to normal processing") = "10000";
  ::arg().set("protobuf-use-kernel-timestamp", "Compute the latency of queries in protobuf messages by using the timestamp set by the kernel when the query was received (when available)") = "";
  ::arg().set("distribution-pipe-buffer-size", "Size in bytes of the internal buffer of the pipe used by the distributor to pass incoming queries to a worker thread") = "0";

  ::arg().set("include-dir", "Include *.conf files from this directory") = "";
  ::arg().set("security-poll-suffix", "Domain name from which to query security update notifications") = "secpoll.powerdns.com.";

#ifdef SO_REUSEPORT
  ::arg().setSwitch("reuseport", "Enable SO_REUSEPORT allowing multiple recursors processes to listen to 1 address") = "yes";
#else
  ::arg().setSwitch("reuseport", "Enable SO_REUSEPORT allowing multiple recursors processes to listen to 1 address") = "no";
#endif
  ::arg().setSwitch("snmp-agent", "If set, register as an SNMP agent") = "no";
  ::arg().set("snmp-master-socket", "If set and snmp-agent is set, the socket to use to register to the SNMP daemon (deprecated)") = "";
  ::arg().set("snmp-daemon-socket", "If set and snmp-agent is set, the socket to use to register to the SNMP daemon") = "";

  std::string defaultAPIDisabledStats = "cache-bytes, packetcache-bytes, special-memory-usage";
  for (size_t idx = 0; idx < 32; idx++) {
    defaultAPIDisabledStats += ", ecs-v4-response-bits-" + std::to_string(idx + 1);
  }
  for (size_t idx = 0; idx < 128; idx++) {
    defaultAPIDisabledStats += ", ecs-v6-response-bits-" + std::to_string(idx + 1);
  }
  std::string defaultDisabledStats = defaultAPIDisabledStats + ", cumul-clientanswers, cumul-authanswers, policy-hits, proxy-mapping-total, remote-logger-count";

  ::arg().set("stats-api-blacklist", "List of statistics that are disabled when retrieving the complete list of statistics via the API (deprecated)") = defaultAPIDisabledStats;
  ::arg().set("stats-carbon-blacklist", "List of statistics that are prevented from being exported via Carbon (deprecated)") = defaultDisabledStats;
  ::arg().set("stats-rec-control-blacklist", "List of statistics that are prevented from being exported via rec_control get-all (deprecated)") = defaultDisabledStats;
  ::arg().set("stats-snmp-blacklist", "List of statistics that are prevented from being exported via SNMP (deprecated)") = defaultDisabledStats;

  ::arg().set("stats-api-disabled-list", "List of statistics that are disabled when retrieving the complete list of statistics via the API") = defaultAPIDisabledStats;
  ::arg().set("stats-carbon-disabled-list", "List of statistics that are prevented from being exported via Carbon") = defaultDisabledStats;
  ::arg().set("stats-rec-control-disabled-list", "List of statistics that are prevented from being exported via rec_control get-all") = defaultDisabledStats;
  ::arg().set("stats-snmp-disabled-list", "List of statistics that are prevented from being exported via SNMP") = defaultDisabledStats;

  ::arg().set("tcp-fast-open", "Enable TCP Fast Open support on the listening sockets, using the supplied numerical value as the queue size") = "0";
  ::arg().set("tcp-fast-open-connect", "Enable TCP Fast Open support on outgoing sockets") = "no";
  ::arg().set("nsec3-max-iterations", "Maximum number of iterations allowed for an NSEC3 record") = "150";

  ::arg().set("cpu-map", "Thread to CPU mapping, space separated thread-id=cpu1,cpu2..cpuN pairs") = "";

  ::arg().setSwitch("log-rpz-changes", "Log additions and removals to RPZ zones at Info level") = "no";

  ::arg().set("proxy-protocol-from", "A Proxy Protocol header is only allowed from these subnets") = "";
  ::arg().set("proxy-protocol-maximum-size", "The maximum size of a proxy protocol payload, including the TLV values") = "512";

  ::arg().set("dns64-prefix", "DNS64 prefix") = "";

  ::arg().set("udp-source-port-min", "Minimum UDP port to bind on") = "1024";
  ::arg().set("udp-source-port-max", "Maximum UDP port to bind on") = "65535";
  ::arg().set("udp-source-port-avoid", "List of comma separated UDP port number to avoid") = "11211";
  ::arg().set("rng", "Specify random number generator to use. Valid values are auto,sodium,openssl,getrandom,arc4random,urandom.") = "auto";
  ::arg().set("public-suffix-list-file", "Path to the Public Suffix List file, if any") = "";
  ::arg().set("distribution-load-factor", "The load factor used when PowerDNS is distributing queries to worker threads") = "0.0";

  ::arg().setSwitch("qname-minimization", "Use Query Name Minimization") = "yes";
  ::arg().setSwitch("nothing-below-nxdomain", "When an NXDOMAIN exists in cache for a name with fewer labels than the qname, send NXDOMAIN without doing a lookup (see RFC 8020)") = "dnssec";
  ::arg().set("max-generate-steps", "Maximum number of $GENERATE steps when loading a zone from a file") = "0";
  ::arg().set("max-include-depth", "Maximum nested $INCLUDE depth when loading a zone from a file") = "20";

  ::arg().set("record-cache-shards", "Number of shards in the record cache") = "1024";
  ::arg().set("packetcache-shards", "Number of shards in the packet cache") = "1024";

  ::arg().set("refresh-on-ttl-perc", "If a record is requested from the cache and only this % of original TTL remains, refetch") = "0";
  ::arg().set("record-cache-locked-ttl-perc", "Replace records in record cache only after this % of original TTL has passed") = "0";

  ::arg().set("x-dnssec-names", "Collect DNSSEC statistics for names or suffixes in this list in separate x-dnssec counters") = "";

#ifdef NOD_ENABLED
  ::arg().set("new-domain-tracking", "Track newly observed domains (i.e. never seen before).") = "no";
  ::arg().set("new-domain-log", "Log newly observed domains.") = "yes";
  ::arg().set("new-domain-lookup", "Perform a DNS lookup newly observed domains as a subdomain of the configured domain") = "";
  ::arg().set("new-domain-history-dir", "Persist new domain tracking data here to persist between restarts") = string(NODCACHEDIR) + "/nod";
  ::arg().set("new-domain-whitelist", "List of domains (and implicitly all subdomains) which will never be considered a new domain (deprecated)") = "";
  ::arg().set("new-domain-ignore-list", "List of domains (and implicitly all subdomains) which will never be considered a new domain") = "";
  ::arg().set("new-domain-db-size", "Size of the DB used to track new domains in terms of number of cells. Defaults to 67108864") = "67108864";
  ::arg().set("new-domain-pb-tag", "If protobuf is configured, the tag to use for messages containing newly observed domains. Defaults to 'pdns-nod'") = "pdns-nod";
  ::arg().set("unique-response-tracking", "Track unique responses (tuple of query name, type and RR).") = "no";
  ::arg().set("unique-response-log", "Log unique responses") = "yes";
  ::arg().set("unique-response-history-dir", "Persist unique response tracking data here to persist between restarts") = string(NODCACHEDIR) + "/udr";
  ::arg().set("unique-response-db-size", "Size of the DB used to track unique responses in terms of number of cells. Defaults to 67108864") = "67108864";
  ::arg().set("unique-response-pb-tag", "If protobuf is configured, the tag to use for messages containing unique DNS responses. Defaults to 'pdns-udr'") = "pdns-udr";
#endif /* NOD_ENABLED */

  ::arg().setSwitch("extended-resolution-errors", "If set, send an EDNS Extended Error extension on resolution failures, like DNSSEC validation errors") = "no";

  ::arg().set("aggressive-nsec-cache-size", "The number of records to cache in the aggressive cache. If set to a value greater than 0, and DNSSEC processing or validation is enabled, the recursor will cache NSEC and NSEC3 records to generate negative answers, as defined in rfc8198") = "100000";
  ::arg().set("aggressive-cache-min-nsec3-hit-ratio", "The minimum expected hit ratio to store NSEC3 records into the aggressive cache") = "2000";

  ::arg().set("edns-padding-from", "List of netmasks (proxy IP in case of proxy-protocol presence, client IP otherwise) for which EDNS padding will be enabled in responses, provided that 'edns-padding-mode' applies") = "";
  ::arg().set("edns-padding-mode", "Whether to add EDNS padding to all responses ('always') or only to responses for queries containing the EDNS padding option ('padded-queries-only', the default). In both modes, padding will only be added to responses for queries coming from `edns-padding-from`_ sources") = "padded-queries-only";
  ::arg().set("edns-padding-tag", "Packetcache tag associated to responses sent with EDNS padding, to prevent sending these to clients for which padding is not enabled.") = "7830";
  ::arg().setSwitch("edns-padding-out", "Whether to add EDNS padding to outgoing DoT messages") = "yes";

  ::arg().setSwitch("dot-to-port-853", "Force DoT connection to target port 853 if DoT compiled in") = "yes";
  ::arg().set("dot-to-auth-names", "Use DoT to authoritative servers with these names or suffixes") = "";
  ::arg().set("event-trace-enabled", "If set, event traces are collected and send out via protobuf logging (1), logfile (2) or both(3)") = "0";

  ::arg().set("tcp-out-max-idle-ms", "Time TCP/DoT connections are left idle in milliseconds or 0 if no limit") = "10000";
  ::arg().set("tcp-out-max-idle-per-auth", "Maximum number of idle TCP/DoT connections to a specific IP per thread, 0 means do not keep idle connections open") = "10";
  ::arg().set("tcp-out-max-queries", "Maximum total number of queries per TCP/DoT connection, 0 means no limit") = "0";
  ::arg().set("tcp-out-max-idle-per-thread", "Maximum number of idle TCP/DoT connections per thread") = "100";
  ::arg().setSwitch("structured-logging", "Prefer structured logging") = "yes";
  ::arg().set("structured-logging-backend", "Structured logging backend") = "default";
  ::arg().setSwitch("save-parent-ns-set", "Save parent NS set to be used if child NS set fails") = "yes";
  ::arg().set("max-busy-dot-probes", "Maximum number of concurrent DoT probes") = "0";
  ::arg().set("serve-stale-extensions", "Number of times a record's ttl is extended by 30s to be served stale") = "0";

  ::arg().setCmd("help", "Provide a helpful message");
  ::arg().setCmd("version", "Print version string");
  ::arg().setCmd("config", "Output blank configuration. You can use --config=check to test the config file and command line arguments.");
  ::arg().setDefaults();
  g_log.toConsole(Logger::Info);
}

static pair<int, bool> doConfig(Logr::log_t startupLog, const string& configname, int argc, char* argv[]) // NOLINT: Posix API
{
  if (::arg().mustDo("config")) {
    string config = ::arg()["config"];
    if (config == "check") {
      try {
        if (!::arg().file(configname.c_str())) {
          SLOG(g_log << Logger::Warning << "Unable to open configuration file '" << configname << "'" << endl,
               startupLog->error("No such file", "Unable to open configuration file", "config_file", Logging::Loggable(configname)));
          return {1, true};
        }
        ::arg().parse(argc, argv);
        return {0, true};
      }
      catch (const ArgException& argException) {
        SLOG(g_log << Logger::Warning << "Unable to parse configuration file '" << configname << "': " << argException.reason << endl,
             startupLog->error("Cannot parse configuration", "Unable to parse configuration file", "config_file", Logging::Loggable(configname), "reason", Logging::Loggable(argException.reason)));
        return {1, true};
      }
    }
    else if (config == "default" || config.empty()) {
      cout << ::arg().configstring(false, true);
    }
    else if (config == "diff") {
      if (!::arg().laxFile(configname.c_str())) {
        SLOG(g_log << Logger::Warning << "Unable to open configuration file '" << configname << "'" << endl,
             startupLog->error("No such file", "Unable to open configuration file", "config_file", Logging::Loggable(configname)));
        return {1, true};
      }
      ::arg().laxParse(argc, argv);
      cout << ::arg().configstring(true, false);
    }
    else {
      if (!::arg().laxFile(configname.c_str())) {
        SLOG(g_log << Logger::Warning << "Unable to open configuration file '" << configname << "'" << endl,
             startupLog->error("No such file", "Unable to open configuration file", "config_file", Logging::Loggable(configname)));
        return {1, true};
      }
      ::arg().laxParse(argc, argv);
      cout << ::arg().configstring(true, true);
    }
    return {0, true};
  }
  return {0, false};
}

int main(int argc, char** argv) // NOLINT(readability-function-cognitive-complexity) #12791 Remove NOLINT(readability-function-cognitive-complexity) omoerbeek
{
  g_argc = argc;
  g_argv = argv;
  Utility::srandom();
  versionSetProduct(ProductRecursor);
  reportBasicTypes();
  reportOtherTypes();

  int ret = EXIT_SUCCESS;

  try {
    initArgs();
    ::arg().laxParse(argc, argv); // do a lax parse

    if (::arg().mustDo("version")) {
      showProductVersion();
      showBuildConfiguration();
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
    g_slogStructured = ::arg().mustDo("structured-logging");
    s_structured_logger_backend = ::arg()["structured-logging-backend"];

    if (s_logUrgency < Logger::Error) {
      s_logUrgency = Logger::Error;
    }
    if (!g_quiet && s_logUrgency < Logger::Info) { // Logger::Info=6, Logger::Debug=7
      s_logUrgency = Logger::Info; // if you do --quiet=no, you need Info to also see the query log
    }
    g_log.setLoglevel(s_logUrgency);
    g_log.toConsole(s_logUrgency);

    string configname = ::arg()["config-dir"] + "/recursor.conf";
    if (!::arg()["config-name"].empty()) {
      configname = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"] + ".conf";
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

    if (s_structured_logger_backend == "systemd-journal") {
#ifdef HAVE_SYSTEMD
      if (int fd = sd_journal_stream_fd("pdns-recusor", LOG_DEBUG, 0); fd >= 0) {
        g_slog = Logging::Logger::create(loggerSDBackend);
        close(fd);
      }
#endif
      if (g_slog == nullptr) {
        cerr << "Structured logging to systemd-journal requested but it is not available" << endl;
      }
    }

    if (g_slog == nullptr) {
      g_slog = Logging::Logger::create(loggerBackend);
    }

    // Missing: a mechanism to call setVerbosity(x)
    auto startupLog = g_slog->withName("config");
    g_slogtcpin = g_slog->withName("in")->withValues("proto", Logging::Loggable("tcp"));
    g_slogudpin = g_slog->withName("in")->withValues("proto", Logging::Loggable("udp"));
    g_slogout = g_slog->withName("out");

    ::arg().setSLog(startupLog);

    bool mustExit = false;
    std::tie(ret, mustExit) = doConfig(startupLog, configname, argc, argv);
    if (ret != 0 || mustExit) {
      return ret;
    }

    if (!::arg().file(configname.c_str())) {
      SLOG(g_log << Logger::Warning << "Unable to open configuration file '" << configname << "'" << endl,
           startupLog->error("No such file", "Unable to open configuration file", "config_file", Logging::Loggable(configname)));
    }

    // Reparse, now with config file as well
    ::arg().parse(argc, argv);

    g_quiet = ::arg().mustDo("quiet");
    s_logUrgency = (Logger::Urgency)::arg().asNum("loglevel");
    g_slogStructured = ::arg().mustDo("structured-logging");

    if (s_logUrgency < Logger::Error) {
      s_logUrgency = Logger::Error;
    }
    if (!g_quiet && s_logUrgency < Logger::Info) { // Logger::Info=6, Logger::Debug=7
      s_logUrgency = Logger::Info; // if you do --quiet=no, you need Info to also see the query log
    }
    g_log.setLoglevel(s_logUrgency);
    g_log.toConsole(s_logUrgency);

    if (!::arg()["chroot"].empty() && !::arg()["api-config-dir"].empty()) {
      SLOG(g_log << Logger::Error << "Using chroot and enabling the API is not possible" << endl,
           startupLog->info(Logr::Error, "Cannot use chroot and enable the API at the same time"));
      return EXIT_FAILURE;
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
        SLOG(g_log << Logger::Warning << "Asked to run with pdns-distributes-queries set but no distributor threads, raising to 1" << endl,
             startupLog->v(1)->info("Only one thread, no need to distribute queries ourselves"));
        ::arg().set("pdns-distributes-queries") = "no";
      }
    }

    if (::arg().mustDo("pdns-distributes-queries") && ::arg().asNum("distributor-threads") <= 0) {
      SLOG(g_log << Logger::Warning << "Asked to run with pdns-distributes-queries set but no distributor threads, raising to 1" << endl,
           startupLog->v(1)->info("Asked to run with pdns-distributes-queries set but no distributor threads, raising to 1"));
      ::arg().set("distributor-threads") = "1";
    }

    if (!::arg().mustDo("pdns-distributes-queries")) {
      ::arg().set("distributor-threads") = "0";
    }

    g_recCache = std::make_unique<MemRecursorCache>(::arg().asNum("record-cache-shards"));
    g_negCache = std::make_unique<NegCache>(::arg().asNum("record-cache-shards") / 8);
    if (!::arg().mustDo("disable-packetcache")) {
      g_maxPacketCacheEntries = ::arg().asNum("max-packetcache-entries");
      g_packetCache = std::make_unique<RecursorPacketCache>(g_maxPacketCacheEntries, ::arg().asNum("packetcache-shards"));
    }

    ret = serviceMain(startupLog);
  }
  catch (const PDNSException& ae) {
    SLOG(g_log << Logger::Error << "Exception: " << ae.reason << endl,
         g_slog->withName("config")->error(Logr::Critical, ae.reason, "Fatal error", "exception", Logging::Loggable("PDNSException")));
    ret = EXIT_FAILURE;
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "STL Exception: " << e.what() << endl,
         g_slog->withName("config")->error(Logr::Critical, e.what(), "Fatal error", "exception", Logging::Loggable("std::exception")));
    ret = EXIT_FAILURE;
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "any other exception in main: " << endl,
         g_slog->withName("config")->info(Logr::Critical, "Fatal error"));
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
      SLOG(g_log << Logger::Info << RecThreadInfo::id() << " Unloaded current lua script" << endl,
           log->info(Logr::Info, "Unloaded current lua script"));
      return new RecursorControlChannel::Answer{0, string("unloaded\n")};
    }

    t_pdl = std::make_shared<RecursorLua4>();
    try {
      t_pdl->loadFile(fname);
    }
    catch (std::runtime_error& ex) {
      string msg = std::to_string(RecThreadInfo::id()) + " Retaining current script, could not read '" + fname + "': " + ex.what();
      SLOG(g_log << Logger::Error << msg << endl,
           log->error(Logr::Error, ex.what(), "Retaining current script, could not read new script"));
      return new RecursorControlChannel::Answer{1, msg + "\n"};
    }
  }
  catch (std::exception& e) {
    SLOG(g_log << Logger::Error << RecThreadInfo::id() << " Retaining current script, error from '" << fname << "': " << e.what() << endl,
         log->error(Logr::Error, e.what(), "Retaining current script, error in new script"));
    return new RecursorControlChannel::Answer{1, string("retaining current script, error from '" + fname + "': " + e.what() + "\n")};
  }

  SLOG(g_log << Logger::Warning << RecThreadInfo::id() << " (Re)loaded lua script from '" << fname << "'" << endl,
       log->info(Logr::Warning, "(Re)loaded lua script"));
  return new RecursorControlChannel::Answer{0, string("(re)loaded '" + fname + "'\n")};
}

RecursorControlChannel::Answer doQueueReloadLuaScript(vector<string>::const_iterator begin, vector<string>::const_iterator end)
{
  if (begin != end)
    ::arg().set("lua-dns-script") = *begin;

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
    return new string("ok\n");
  }
  catch (const PDNSException& ae) {
    return new string(ae.reason + "\n");
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
    res.record_count = g_recCache->doWipeCache(canon, subtree, qtype);
    // scanbuild complains here about an allocated function object that is being leaked. Needs investigation
    if (g_packetCache) {
      res.packet_count = g_packetCache->doWipePacketCache(canon, qtype, subtree);
    }
    res.negative_record_count = g_negCache->wipe(canon, subtree);
    if (g_aggressiveNSECCache) {
      g_aggressiveNSECCache->removeZoneInfo(canon, subtree);
    }
  }
  catch (const std::exception& e) {
    auto log = g_slog->withName("runtime");
    SLOG(g_log << Logger::Warning << ", failed: " << e.what() << endl,
         log->error(Logr::Warning, e.what(), "Wipecache failed"));
  }

  return res;
}
