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

#include "config.h"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <getopt.h>
#include <grp.h>
#include <limits>
#include <memory>
#include <netinet/tcp.h>
#include <optional>
#include <pwd.h>
#include <set>
#include <sys/resource.h>
#include <unistd.h>
#include <vector>

#include "dns.hh"
#include "dnsdist-dnscrypt.hh"
#include "dnsdist-idstate.hh"
#include "dnsdist-opentelemetry.hh"
#include "dnsdist-systemd.hh"
#include "logging.hh"
#include "logr.hh"
#include "protozero-trace.hh"
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "dnsdist.hh"
#include "dnsdist-async.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-carbon.hh"
#include "dnsdist-configuration.hh"
#include "dnsdist-configuration-yaml.hh"
#include "dnsdist-console.hh"
#include "dnsdist-console-completion.hh"
#include "dnsdist-lua-bindings-opentelemetry.hh"
#include "dnsdist-delay-pipe.hh"
#include "dnsdist-discovery.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-frontend.hh"
#include "dnsdist-healthchecks.hh"
#include "dnsdist-logging.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-hooks.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-random.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-secpoll.hh"
#include "dnsdist-self-answers.hh"
#include "dnsdist-snmp.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-udp.hh"
#include "dnsdist-web.hh"
#include "dnsdist-xsk.hh"

#include "base64.hh"
#include "capabilities.hh"
#include "coverage.hh"
#include "dolog.hh"
#include "dnsname.hh"
#include "ednsoptions.hh"
#include "gettime.hh"
#include "lock.hh"
#include "misc.hh"
#include "sstuff.hh"
#include "threadname.hh"

/* Known sins:

   Receiver is currently single threaded
      not *that* bad actually, but now that we are thread safe, might want to scale
*/

/* the RuleAction plan
   Set of Rules, if one matches, it leads to an Action
   Both rules and actions could conceivably be Lua based.
   On the C++ side, both could be inherited from a class Rule and a class Action,
   on the Lua side we can't do that. */

using std::thread;

string g_outputBuffer;

shared_ptr<BPFFilter> g_defaultBPFFilter{nullptr};

/* UDP: the grand design. Per socket we listen on for incoming queries there is one thread.
   Then we have a bunch of connected sockets for talking to downstream servers.
   We send directly to those sockets.

   For the return path, per downstream server we have a thread that listens to responses.

   Per socket there is an array of 2^16 states, when we send out a packet downstream, we note
   there the original requestor and the original id. The new ID is the offset in the array.

   When an answer comes in on a socket, we look up the offset by the id, and lob it to the
   original requestor.

   IDs are assigned by atomic increments of the socket offset.
 */

Rings g_rings;

void handleServerStateChange(const string& nameWithAddr, bool newResult)
{
  try {
    auto lua = g_lua.lock();
    dnsdist::lua::hooks::runServerStateChangeHooks(*lua, nameWithAddr, newResult);
  }
  catch (const std::exception& exp) {
    SLOG(warnlog("Error calling the Lua hook for Server State Change: %s", exp.what()),
         dnsdist::logging::getTopLogger("backend-state-update")->error(Logr::Warning, exp.what(), "Error calling the Lua hook for backend state change", "backend.name", Logging::Loggable(nameWithAddr)));
  }
}

std::shared_ptr<dnsdist::udp::UDPTCPCrossQuerySender> dnsdist::udp::UDPCrossProtocolQuery::s_sender = std::make_shared<UDPTCPCrossQuerySender>();

static void maintThread()
{
  setThreadName("dnsdist/main");
  constexpr int interval = 1;
  size_t counter = 0;
  size_t otCounter = 0;
  int32_t secondsToWaitLog = 0;
  auto sLogger = dnsdist::logging::getTopLogger("maintenance");

  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(interval));

    dnsdist::configuration::refreshLocalRuntimeConfiguration();
    std::shared_ptr<pdns::trace::dnsdist::Tracer> tracer = dnsdist::configuration::getCurrentRuntimeConfiguration().d_opentelemetryMaintenanceInterval != 0 && otCounter % dnsdist::configuration::getCurrentRuntimeConfiguration().d_opentelemetryMaintenanceInterval == 0 ? pdns::trace::dnsdist::Tracer::getTracer() : nullptr;
    otCounter++;
    if (tracer != nullptr) {
      tracer->setScopeSpanName("dnsdist/maintenance");
    }
    auto maint_closer = pdns::trace::dnsdist::getCloserForInternalSpan(tracer, "maintenanceThread");
    auto lua = g_lua.lock();

    pdns::trace::dnsdist::runWithLuaTracing(*lua, tracer, [&lua, &tracer, &secondsToWaitLog, &sLogger]() {
      try {
        auto maintenanceCallback = lua->readVariable<std::optional<std::function<void()>>>("maintenance");
        if (maintenanceCallback) {
          auto closer = pdns::trace::dnsdist::getCloserForInternalSpan(tracer, "maintenanceFunction");
          (*maintenanceCallback)();
        }
        {
          auto closer = pdns::trace::dnsdist::getCloserForInternalSpan(tracer, "maintenanceHooks");
          dnsdist::lua::hooks::runMaintenanceHooks(*lua, tracer);
        }
#if !defined(DISABLE_DYNBLOCKS)
        {
          auto closer = pdns::trace::dnsdist::getCloserForInternalSpan(tracer, "DynamicBlocks::runRegisteredGroups");
          dnsdist::DynamicBlocks::runRegisteredGroups(*lua);
        }
#endif /* DISABLE_DYNBLOCKS */
        secondsToWaitLog = 0;
      }
      catch (const std::exception& e) {
        if (secondsToWaitLog <= 0) {
          auto logger = sLogger;
#ifndef DISABLE_PROTOBUF
          if (tracer != nullptr) {
            logger = logger->withValues("traceID", Logging::Loggable{tracer->getTraceID().toLogString()});
          }
#endif
          SLOG(warnlog("Error during execution of maintenance function(s): %s", e.what()),
               logger->error(Logr::Warning, e.what(), "Error during execution of maintenance function(s)"));
          secondsToWaitLog = 61;
        }
        secondsToWaitLog -= interval;
      }
    });

    counter++;
    if (counter >= dnsdist::configuration::getCurrentRuntimeConfiguration().d_cacheCleaningDelay) {
      auto closer = pdns::trace::dnsdist::getCloserForInternalSpan(tracer, "CacheClean");
      /* keep track, for each cache, of whether we should keep
       expired entries */
      std::map<std::shared_ptr<DNSDistPacketCache>, bool> caches;

      /* gather all caches actually used by at least one pool, and see
         if something prevents us from cleaning the expired entries */
      const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
      for (const auto& entry : pools) {
        const auto& pool = entry.second;

        const auto& packetCache = pool.packetCache;
        if (!packetCache) {
          continue;
        }

        auto pair = caches.insert({packetCache, false});
        auto& iter = pair.first;
        /* if we need to keep stale data for this cache (ie, not clear
           expired entries when at least one pool using this cache
           has all its backends down) */
        if (packetCache->keepStaleData() && !iter->second) {
          /* so far all pools had at least one backend up */
          if (pool.shouldKeepStaleData()) {
            iter->second = true;
          }
        }
      }

      const time_t now = time(nullptr);
      for (const auto& pair : caches) {
        /* shall we keep expired entries ? */
        if (pair.second) {
          continue;
        }
        const auto& packetCache = pair.first;
        size_t upTo = (packetCache->getMaxEntries() * (100 - dnsdist::configuration::getCurrentRuntimeConfiguration().d_cacheCleaningPercentage)) / 100;
        packetCache->purgeExpired(upTo, now);
      }
      counter = 0;
    }

#ifndef DISABLE_PROTOBUF
    if (tracer != nullptr) {
      maint_closer = std::nullopt; // set the stop time by destructing the Closer
      pdns::trace::dnsdist::sendTracesToRemoteLoggers(tracer, dnsdist::configuration::getCurrentRuntimeConfiguration().d_maintenanceRemoteLoggers);
    }
#endif
  }
}

#ifndef DISABLE_DYNBLOCKS
static void dynBlockMaintenanceThread()
{
  setThreadName("dnsdist/dynBloc");

  dnsdist::configuration::refreshLocalRuntimeConfiguration();
  DynBlockMaintenance::run();
}
#endif

#ifndef DISABLE_SECPOLL
static void secPollThread()
{
  setThreadName("dnsdist/secpoll");

  for (;;) {
    const auto& runtimeConfig = dnsdist::configuration::refreshLocalRuntimeConfiguration();

    try {
      dnsdist::secpoll::doSecPoll(runtimeConfig.d_secPollSuffix);
    }
    catch (...) {
    }
    // coverity[store_truncates_time_t]
    std::this_thread::sleep_for(std::chrono::seconds(runtimeConfig.d_secPollInterval));
  }
}
#endif /* DISABLE_SECPOLL */

static std::atomic<bool> s_exiting{false};
void doExitNicely(int exitCode = EXIT_SUCCESS);

static void checkExiting()
{
  if (s_exiting) {
    doExitNicely();
  }
}

static void healthChecksThread()
{
  setThreadName("dnsdist/healthC");

  constexpr int intervalUsec = 1000 * 1000;
  struct timeval lastRound{
    .tv_sec = 0,
    .tv_usec = 0};

  for (;;) {
    try {
      checkExiting();

      timeval now{};
      gettimeofday(&now, nullptr);
      auto elapsedTimeUsec = uSec(now - lastRound);
      if (elapsedTimeUsec < intervalUsec) {
        usleep(intervalUsec - elapsedTimeUsec);
        gettimeofday(&lastRound, nullptr);
      }
      else {
        lastRound = now;
      }

      std::unique_ptr<FDMultiplexer> mplexer{nullptr};
      const auto& runtimeConfig = dnsdist::configuration::refreshLocalRuntimeConfiguration();

      // this points to the actual shared_ptrs!
      // coverity[auto_causes_copy]
      const auto servers = runtimeConfig.d_backends;
      for (const auto& dss : servers) {
        dss->updateStatisticsInfo();

        dss->handleUDPTimeouts();

        if (!dss->healthCheckRequired()) {
          continue;
        }

        if (!mplexer) {
          mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(servers.size()));
        }

        if (!queueHealthCheck(mplexer, dss)) {
          dss->submitHealthCheckResult(false, false);
        }
      }

      if (mplexer) {
        handleQueuedHealthChecks(*mplexer);
      }
    }
    catch (const std::exception& exp) {
      VERBOSESLOG(infolog("Exception in the health-check thread: %s", exp.what()),
                  dnsdist::logging::getTopLogger("health-check")->error(Logr::Info, exp.what(), "Exception in the health-check thread"));
    }
  }
}

static void bindAny([[maybe_unused]] int addressFamily, [[maybe_unused]] int sock, [[maybe_unused]] const std::shared_ptr<const Logr::Logger>& logger)
{
  __attribute__((unused)) int one = 1;

#ifdef IP_FREEBIND
  if (setsockopt(sock, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) < 0) {
    SLOG(warnlog("Warning: IP_FREEBIND setsockopt failed: %s", stringerror()),
         logger->error(Logr::Warning, stringerror(), "Warning: IP_FREEBIND setsockopt failed"));
  }
#endif

#ifdef IP_BINDANY
  if (addressFamily == AF_INET) {
    if (setsockopt(sock, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) < 0) {
      SLOG(warnlog("Warning: IP_BINDANY setsockopt failed: %s", stringerror()),
           logger->error(Logr::Warning, stringerror(), "Warning: IP_BINDANY setsockopt failed"));
    }
  }
#endif
#ifdef IPV6_BINDANY
  if (addressFamily == AF_INET6) {
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) < 0) {
      SLOG(warnlog("Warning: IPV6_BINDANY setsockopt failed: %s", stringerror()),
           logger->error(Logr::Warning, stringerror(), "Warning: IPV6_BINDANY setsockopt failed"));
    }
  }
#endif
#ifdef SO_BINDANY
  if (setsockopt(sock, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) < 0) {
    SLOG(warnlog("Warning: SO_BINDANY setsockopt failed: %s", stringerror()),
         logger->error(Logr::Warning, stringerror(), "Warning: SO_BINDANY setsockopt failed"));
  }
#endif
}

static void dropGroupPrivs(gid_t gid)
{
  if (gid != 0) {
    if (setgid(gid) == 0) {
      if (setgroups(0, nullptr) < 0) {
        SLOG(warnlog("Warning: Unable to drop supplementary gids: %s", stringerror()),
             dnsdist::logging::getTopLogger("setup")->error(Logr::Warning, stringerror(), "Warning: Unable to drop supplementary gids"));
      }
    }
    else {
      SLOG(warnlog("Warning: Unable to set group ID to %d: %s", gid, stringerror()),
           dnsdist::logging::getTopLogger("setup")->error(Logr::Warning, stringerror(), "Warning: Unable to set group ID", "systemd.gid", Logging::Loggable(gid)));
    }
  }
}

static void dropUserPrivs(uid_t uid)
{
  if (uid != 0) {
    if (setuid(uid) < 0) {
      SLOG(warnlog("Warning: Unable to set user ID to %d: %s", uid, stringerror()),
           dnsdist::logging::getTopLogger("setup")->error(Logr::Warning, stringerror(), "Warning: Unable to set user ID", "system.uid", Logging::Loggable(uid)));
    }
  }
}

static void checkFileDescriptorsLimits(size_t udpBindsCount, size_t tcpBindsCount)
{
  const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
  /* stdin, stdout, stderr */
  rlim_t requiredFDsCount = 3;
  const auto& backends = dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends;
  /* UDP sockets to backends */
  size_t backendUDPSocketsCount = 0;
  for (const auto& backend : backends) {
    backendUDPSocketsCount += backend->sockets.size();
  }
  requiredFDsCount += backendUDPSocketsCount;
  /* TCP sockets to backends */
  if (immutableConfig.d_maxTCPClientThreads > 0) {
    requiredFDsCount += (backends.size() * immutableConfig.d_maxTCPClientThreads);
  }
  /* listening sockets */
  requiredFDsCount += udpBindsCount;
  requiredFDsCount += tcpBindsCount;
  /* number of TCP connections currently served, assuming 1 connection per worker thread which is of course not right */
  if (immutableConfig.d_maxTCPClientThreads > 0) {
    requiredFDsCount += immutableConfig.d_maxTCPClientThreads;
    /* max pipes for communicating between TCP acceptors and client threads */
    requiredFDsCount += (immutableConfig.d_maxTCPClientThreads * 2);
  }
  /* max TCP queued connections */
  requiredFDsCount += immutableConfig.d_maxTCPQueuedConnections;
  /* DelayPipe pipe */
  requiredFDsCount += 2;
  /* syslog socket */
  requiredFDsCount++;
  /* webserver main socket */
  requiredFDsCount++;
  /* console main socket */
  requiredFDsCount++;
  /* carbon export */
  requiredFDsCount++;
  /* history file */
  requiredFDsCount++;
  rlimit resourceLimits{};
  getrlimit(RLIMIT_NOFILE, &resourceLimits);
  if (resourceLimits.rlim_cur <= requiredFDsCount) {
    SLOG(warnlog("Warning, this configuration can use more than %d file descriptors, web server and console connections not included, and the current limit is %d.", std::to_string(requiredFDsCount), std::to_string(resourceLimits.rlim_cur)),
         dnsdist::logging::getTopLogger("setup")->info(Logr::Warning, "Warning, this configuration can use more file descriptors, web server and console connections not included, than the currently configured limit", "system.required_file_descriptors", Logging::Loggable(requiredFDsCount), "system.file_descriptors_limit", Logging::Loggable(resourceLimits.rlim_cur)));
#ifdef HAVE_SYSTEMD
    SLOG(warnlog("You can increase this value by using LimitNOFILE= in the systemd unit file or ulimit."),
         dnsdist::logging::getTopLogger("setup")->info(Logr::Warning, "You can increase this value by using LimitNOFILE= in the systemd unit file over ulimit"));
#else
    SLOG(warnlog("You can increase this value by using ulimit."),
         dnsdist::logging::getTopLogger("setup")->info(Logr::Warning, "You can increase this value by using ulimit."));
#endif
  }
}

static void setupLocalSocket(ClientState& clientState, const ComboAddress& addr, int& socket, bool tcp, [[maybe_unused]] bool warn, const std::shared_ptr<const Logr::Logger>& logger)
{
  static bool s_warned_ipv6_recvpktinfo = false;
  socket = SSocket(addr.sin4.sin_family, !tcp ? SOCK_DGRAM : SOCK_STREAM, 0);

  if (tcp) {
    SSetsockopt(socket, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(socket, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1);
#endif
    if (clientState.fastOpenQueueSize > 0) {
#ifdef TCP_FASTOPEN
      SSetsockopt(socket, IPPROTO_TCP, TCP_FASTOPEN, clientState.fastOpenQueueSize);
#ifdef TCP_FASTOPEN_KEY
      const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
      if (!immutableConfig.d_tcpFastOpenKey.empty()) {
        auto res = setsockopt(socket, IPPROTO_IP, TCP_FASTOPEN_KEY, immutableConfig.d_tcpFastOpenKey.data(), immutableConfig.d_tcpFastOpenKey.size() * sizeof(immutableConfig.d_tcpFastOpenKey[0]));
        if (res == -1) {
          throw runtime_error("setsockopt for level IPPROTO_TCP and opname TCP_FASTOPEN_KEY failed: " + stringerror());
        }
      }
#endif /* TCP_FASTOPEN_KEY */
#else /* TCP_FASTOPEN */
      if (warn) {
        SLOG(warnlog("TCP Fast Open has been configured on local address '%s' but is not supported", addr.toStringWithPort()),
             logger->info(Logr::Warning, "TCP Fast Open has been configured but is not supported", "frontend.adddress", Logging::Loggable(addr)));
      }
#endif /* TCP_FASTOPEN */
    }
  }

  if (addr.sin4.sin_family == AF_INET6) {
    SSetsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, 1);
  }

  bindAny(addr.sin4.sin_family, socket, logger);

  if (!tcp && IsAnyAddress(addr)) {
    int one = 1;
    (void)setsockopt(socket, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one)); // linux supports this, so why not - might fail on other systems
#ifdef IPV6_RECVPKTINFO
    if (addr.isIPv6() && setsockopt(socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) < 0 && !s_warned_ipv6_recvpktinfo) {
      SLOG(warnlog("Warning: IPV6_RECVPKTINFO setsockopt failed: %s", stringerror()),
           logger->error(Logr::Warning, stringerror(), "IPV6_RECVPKTINFO setsockopt failed", "frontend.address", Logging::Loggable(addr)));
      s_warned_ipv6_recvpktinfo = true;
    }
#endif
  }

  if (clientState.reuseport) {
    if (!setReusePort(socket)) {
      if (warn) {
        /* no need to warn again if configured but support is not available, we already did for UDP */
        SLOG(warnlog("SO_REUSEPORT has been configured on local address '%s' but is not supported", addr.toStringWithPort()),
             logger->info(Logr::Warning, "SO_REUSEPORT has been configured but is not supported", "frontend.adddress", Logging::Loggable(addr)));
      }
    }
  }

  const bool isQUIC = clientState.doqFrontend != nullptr || clientState.doh3Frontend != nullptr;
  if (isQUIC) {
    /* disable fragmentation and force PMTU discovery for QUIC-enabled sockets */
    try {
      setSocketForcePMTU(socket, addr.sin4.sin_family);
    }
    catch (const std::exception& e) {
      SLOG(warnlog("Failed to set IP_MTU_DISCOVER on QUIC server socket for local address '%s': %s", addr.toStringWithPort(), e.what()),
           logger->error(Logr::Warning, e.what(), "Failed to set IP_MTU_DISCOVER on QUIC server socket", "frontend.adddress", Logging::Loggable(addr)));
    }
  }
  else if (!tcp && !clientState.dnscryptCtx) {
    /* Only set this on IPv4 UDP sockets.
       Don't set it for DNSCrypt binds. DNSCrypt pads queries for privacy
       purposes, so we do receive large, sometimes fragmented datagrams. */
    try {
      setSocketIgnorePMTU(socket, addr.sin4.sin_family);
    }
    catch (const std::exception& e) {
      SLOG(warnlog("Failed to set IP_MTU_DISCOVER on UDP server socket for local address '%s': %s", addr.toStringWithPort(), e.what()),
           logger->error(Logr::Warning, e.what(), "Failed to set IP_MTU_DISCOVER on UDP server socket", "frontend.address", Logging::Loggable(addr)));
    }
  }

  if (!tcp) {
    dnsdist::udp::setUDPSocketBufferSizes(socket, *logger, dnsdist::udp::Context::Frontend, addr);
  }

  const std::string& itf = clientState.interface;
  if (!itf.empty()) {
#ifdef SO_BINDTODEVICE
    int res = setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, itf.c_str(), itf.length());
    if (res != 0) {
      SLOG(warnlog("Error setting up the interface on local address '%s': %s", addr.toStringWithPort(), stringerror()),
           logger->error(Logr::Warning, stringerror(), "Error setting up the interface", "frontend.address", Logging::Loggable(addr)));
    }
#else
    if (warn) {
      SLOG(warnlog("An interface has been configured on local address '%s' but SO_BINDTODEVICE is not supported", addr.toStringWithPort()),
           logger->error(Logr::Warning, stringerror(), "An interface has been configured but SO_BINDTODEVICE is not supported", "frontend.address", Logging::Loggable(addr)));
    }
#endif
  }

#ifdef HAVE_EBPF
  /* for now eBPF filtering is not enabled on QUIC sockets because the eBPF code tries
     to parse the QNAME from the payload for all UDP datagrams, which obviously does not
     work well for these. */
  if (!isQUIC && g_defaultBPFFilter && !g_defaultBPFFilter->isExternal()) {
    clientState.attachFilter(g_defaultBPFFilter, socket);
    VERBOSESLOG(infolog("Attaching default BPF Filter to %s frontend %s", (!tcp ? std::string("UDP") : std::string("TCP")), addr.toStringWithPort()),
                logger->info(Logr::Info, "Attaching default BPF Filter to frontend", "frontend.address", Logging::Loggable(addr), "network.transport", Logging::Loggable((!tcp ? std::string("udp") : std::string("tcp")))));
  }
#endif /* HAVE_EBPF */

  SBind(socket, addr);

  if (tcp) {
    SListen(socket, clientState.tcpListenQueueSize);

    if (clientState.tlsFrontend != nullptr) {
      SLOG(infolog("Listening on %s for TLS", addr.toStringWithPort()),
           logger->info(Logr::Info, "Listening on DoT frontend", "frontend.address", Logging::Loggable(addr)));
    }
    else if (clientState.dohFrontend != nullptr) {
      SLOG(infolog("Listening on %s for DoH", addr.toStringWithPort()),
           logger->info(Logr::Info, "Listening on DoH frontend", "frontend.address", Logging::Loggable(addr)));
    }
    else if (clientState.dnscryptCtx != nullptr) {
      SLOG(infolog("Listening on %s for DNSCrypt", addr.toStringWithPort()),
           logger->info(Logr::Info, "Listening on DNSCrypt frontend", "frontend.address", Logging::Loggable(addr)));
    }
    else {
      SLOG(infolog("Listening on %s", addr.toStringWithPort()),
           logger->info(Logr::Info, "Listening on Do53 frontend", "frontend.address", Logging::Loggable(addr)));
    }
  }
  else {
    if (clientState.doqFrontend != nullptr) {
      SLOG(infolog("Listening on %s for DoQ", addr.toStringWithPort()),
           logger->info(Logr::Info, "Listening on DoQ frontend", "frontend.address", Logging::Loggable(addr)));
    }
    else if (clientState.doh3Frontend != nullptr) {
      SLOG(infolog("Listening on %s for DoH3", addr.toStringWithPort()),
           logger->info(Logr::Info, "Listening on DoH3 frontend", "frontend.address", Logging::Loggable(addr)));
    }
#ifdef HAVE_XSK
    else if (clientState.xskInfo != nullptr) {
      SLOG(infolog("Listening on %s (XSK-enabled)", addr.toStringWithPort()),
           logger->info(Logr::Info, "Listening on XSK-enabled frontend", "frontend.address", Logging::Loggable(addr)));
    }
#endif
  }
}

static void setUpLocalBind(ClientState& cstate, const std::shared_ptr<const Logr::Logger>& logger)
{
  /* skip some warnings if there is an identical UDP context */
  bool warn = !cstate.tcp || cstate.tlsFrontend != nullptr || cstate.dohFrontend != nullptr;
  int& descriptor = !cstate.tcp ? cstate.udpFD : cstate.tcpFD;
  (void)warn;

  setupLocalSocket(cstate, cstate.local, descriptor, cstate.tcp, warn, logger);

  for (auto& [addr, socket] : cstate.d_additionalAddresses) {
    setupLocalSocket(cstate, addr, socket, true, false, logger);
  }

  if (cstate.tlsFrontend != nullptr) {
    if (!cstate.tlsFrontend->setupTLS()) {
      SLOG(errlog("Error while setting up TLS on local address '%s', exiting", cstate.local.toStringWithPort()),
           logger->info(Logr::Error, "Error while setting up TLS bind, exiting", "frontend.address", Logging::Loggable(cstate.local)));
      _exit(EXIT_FAILURE);
    }
  }

  if (cstate.dohFrontend != nullptr) {
    cstate.dohFrontend->setup();
  }
  if (cstate.doqFrontend != nullptr) {
    cstate.doqFrontend->setup();
  }
  if (cstate.doh3Frontend != nullptr) {
    cstate.doh3Frontend->setup();
  }

  cstate.ready = true;
}

struct CommandLineParameters
{
  vector<string> locals;
  vector<string> remotes;
  string command;
  string config;
  string uid;
  string gid;
  string structuredLoggingBackend;
  bool checkConfig{false};
  bool beClient{false};
  bool beSupervised{false};
  bool useStructuredLogging{true};
};

static void usage()
{
  cout << endl;
  cout << "Syntax: dnsdist [-C,--config file] [-c,--client [IP[:PORT]]]\n";
  cout << "[-e,--execute cmd] [-h,--help] [-l,--local addr]\n";
  cout << "[-v,--verbose] [--check-config] [--version]\n";
  cout << "\n";
  cout << "-a,--acl netmask                      Add this netmask to the ACL\n";
  cout << "-C,--config file                      Load configuration from 'file'\n";
  cout << "-c,--client                           Operate as a client, connect to dnsdist. This reads\n";
  cout << "                                      controlSocket from your configuration file, but also\n";
  cout << "                                      accepts an IP:PORT argument\n";
#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO)
  cout << "-k,--setkey KEY                       Use KEY for encrypted communication to dnsdist. This\n";
  cout << "                                      is similar to setting setKey in the configuration file.\n";
  cout << "                                      NOTE: this will leak this key in your shell's history\n";
  cout << "                                      and in the systems running process list.\n";
#endif
  cout << "--check-config                        Validate the configuration file and exit. The exit-code\n";
  cout << "                                      reflects the validation, 0 is OK, 1 means an error.\n";
  cout << "                                      Any errors are printed as well.\n";
  cout << "-e,--execute cmd                      Connect to dnsdist and execute 'cmd'\n";
  cout << "-g,--gid gid                          Change the process group ID after binding sockets\n";
  cout << "-h,--help                             Display this helpful message\n";
  cout << "-l,--local address                    Listen on this local address\n";
  cout << "--supervised                          Don't open a console, I'm supervised\n";
  cout << "                                      (use with e.g. systemd and daemontools)\n";
  cout << "--disable-syslog                      Don't log to syslog, only to stdout\n";
  cout << "                                      (use with e.g. systemd)\n";
  cout << "--log-timestamps                      Prepend timestamps to messages logged to stdout\n";
  cout << "--structured-logging true|false       Whether to enable structured logging\n";
  cout << "--structured-logging-backend BACKEND  The backend to use when structured logging is enabled\n";
  cout << "                                      Supported values are 'default', 'json' and 'systemd-journal'\n";
  cout << "-u,--uid uid                          Change the process user ID after binding sockets\n";
  cout << "-v,--verbose                          Enable verbose mode\n";
  cout << "-V,--version                          Show dnsdist version information and exit\n";
}

#include "sanitizer.hh"

#if defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE)
#include <sanitizer/lsan_interface.h>
#endif

#if defined(COVERAGE) || (defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE))
static void cleanupLuaObjects(LuaContext& /* luaCtx */)
{
  dnsdist::lua::hooks::clearExitCallbacks();
  /* when our coverage mode is enabled, we need to make sure
     that the Lua objects are destroyed before the Lua contexts. */
  dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_ruleChains = dnsdist::rules::RuleChains();
    config.d_lbPolicy = std::make_shared<ServerPolicy>();
    config.d_pools.clear();
    config.d_backends.clear();
  });
  dnsdist::webserver::clearWebHandlers();
  dnsdist::lua::hooks::clearMaintenanceHooks();
  dnsdist::lua::hooks::clearServerStateChangeCallbacks();
}
#endif /* defined(COVERAGE) || (defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE)) */

void doExitNicely(int exitCode)
{
  if (s_exiting) {
    if (dnsdist::logging::LoggingConfiguration::getSyslog()) {
      syslog(LOG_INFO, "Exiting on user request");
    }
    std::cout << "Exiting on user request" << std::endl;
  }

#ifdef HAVE_SYSTEMD
  sd_notify(0, "STOPPING=1");
#endif /* HAVE_SYSTEMD */

#if defined(COVERAGE) || (defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE))
  if (dnsdist::g_asyncHolder) {
    dnsdist::g_asyncHolder->stop();
  }

  for (auto& backend : dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends) {
    backend->stop();
  }
#endif

  {
    auto lock = g_lua.lock();
    dnsdist::lua::hooks::runExitCallbacks(*lock);
#if defined(COVERAGE) || (defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE))
    cleanupLuaObjects(*lock);
    *lock = LuaContext();
#endif
  }

#if defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE)
  __lsan_do_leak_check();
#endif /* __SANITIZE_ADDRESS__ && HAVE_LEAK_SANITIZER_INTERFACE */

#ifdef COVERAGE
  pdns::coverage::dumpCoverageData();
#endif

  /* do not call destructors, because we have some
     dependencies between objects that are not trivial
     to solve.
  */
  _exit(exitCode);
}

static void sigTermHandler(int /* sig */)
{
  s_exiting.store(true);
}

static void reportFeatures()
{
#ifdef LUAJIT_VERSION
  cout << "dnsdist " << VERSION << " (" << LUA_RELEASE << " [" << LUAJIT_VERSION << "])" << endl;
#else
  cout << "dnsdist " << VERSION << " (" << LUA_RELEASE << ")" << endl;
#endif
  cout << "Enabled features: ";
#ifdef HAVE_XSK
  cout << "AF_XDP ";
#endif
#ifdef HAVE_CDB
  cout << "cdb ";
#endif
#ifdef HAVE_DNS_OVER_QUIC
  cout << "dns-over-quic ";
#endif
#ifdef HAVE_DNS_OVER_HTTP3
  cout << "dns-over-http3 ";
#endif
#ifdef HAVE_DNS_OVER_TLS
  cout << "dns-over-tls(";
#ifdef HAVE_GNUTLS
  cout << "gnutls";
#ifdef HAVE_LIBSSL
  cout << " ";
#endif
#endif /* HAVE_GNUTLS */
#ifdef HAVE_LIBSSL
  cout << "openssl";
#endif
  cout << ") ";
#endif /* HAVE_DNS_OVER_TLS */
#ifdef HAVE_DNS_OVER_HTTPS
  cout << "dns-over-https(";
#ifdef HAVE_NGHTTP2
  cout << "nghttp2";
#endif /* HAVE_NGHTTP2 */
  cout << ") ";
#endif /* HAVE_DNS_OVER_HTTPS */
#ifdef HAVE_DNSCRYPT
  cout << "dnscrypt ";
#endif
#ifdef HAVE_EBPF
  cout << "ebpf ";
#endif
#ifdef HAVE_FSTRM
  cout << "fstrm ";
#endif
#ifdef HAVE_IPCIPHER
  cout << "ipcipher ";
#endif
#ifdef HAVE_IPCRYPT2
  cout << "ipcrypt2 ";
#endif
#ifdef HAVE_LIBEDIT
  cout << "libedit ";
#endif
#ifdef HAVE_LIBSODIUM
  cout << "libsodium ";
#endif
#ifdef HAVE_LMDB
  cout << "lmdb ";
#endif
#ifdef HAVE_MMDB
  cout << "mmdb ";
#endif
#ifndef DISABLE_PROTOBUF
  cout << "protobuf ";
#endif
#ifdef HAVE_RE2
  cout << "re2 ";
#endif
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
  cout << "recvmmsg/sendmmsg ";
#endif
#endif /* DISABLE_RECVMMSG */
#ifdef HAVE_NET_SNMP
  cout << "snmp ";
#endif
#ifdef HAVE_SYSTEMD
  cout << "systemd ";
#endif
#ifdef HAVE_YAML_CONFIGURATION
  cout << "yaml ";
#endif
  cout << endl;
// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#ifdef DNSDIST_CONFIG_ARGS
#define double_escape(s) #s
#define escape_quotes(s) double_escape(s)
  // NOLINTEND(cppcoreguidelines-macro-usage)
  cout << "Configured with: " << escape_quotes(DNSDIST_CONFIG_ARGS) << endl;
#undef escape_quotes
#undef double_escape
#endif
}

static void parseParameters(int argc, char** argv, CommandLineParameters& cmdLine, ComboAddress& clientAddress)
{
  const std::array<struct option, 18> longopts{{{"acl", required_argument, nullptr, 'a'},
                                                {"check-config", no_argument, nullptr, 1},
                                                {"client", no_argument, nullptr, 'c'},
                                                {"config", required_argument, nullptr, 'C'},
                                                {"disable-syslog", no_argument, nullptr, 2},
                                                {"execute", required_argument, nullptr, 'e'},
                                                {"gid", required_argument, nullptr, 'g'},
                                                {"help", no_argument, nullptr, 'h'},
                                                {"local", required_argument, nullptr, 'l'},
                                                {"log-timestamps", no_argument, nullptr, 4},
                                                {"setkey", required_argument, nullptr, 'k'},
                                                {"structured-logging", required_argument, nullptr, 's'},
                                                {"structured-logging-backend", required_argument, nullptr, 5},
                                                {"supervised", no_argument, nullptr, 3},
                                                {"uid", required_argument, nullptr, 'u'},
                                                {"verbose", no_argument, nullptr, 'v'},
                                                {"version", no_argument, nullptr, 'V'},
                                                {nullptr, 0, nullptr, 0}}};
  int longindex = 0;
  string optstring;
  dnsdist::configuration::RuntimeConfiguration newConfig;

  while (true) {
    // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
    int gotChar = getopt_long(argc, argv, "a:cC:e:g:hk:l:u:svV", longopts.data(), &longindex);
    if (gotChar == -1) {
      break;
    }
    switch (gotChar) {
    case 1:
      cmdLine.checkConfig = true;
      break;
    case 2:
      dnsdist::logging::LoggingConfiguration::setSyslog(false);
      break;
    case 3:
      cmdLine.beSupervised = true;
      break;
    case 4:
      dnsdist::logging::LoggingConfiguration::setLogTimestamps(true);
      break;
    case 5:
      cmdLine.structuredLoggingBackend = optarg;
      break;
    case 'C':
      cmdLine.config = optarg;
      break;
    case 'c':
      cmdLine.beClient = true;
      break;
    case 'e':
      cmdLine.command = optarg;
      break;
    case 'g':
      cmdLine.gid = optarg;
      break;
    case 'h':
      cout << "dnsdist " << VERSION << endl;
      usage();
      cout << "\n";
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      exit(EXIT_SUCCESS);
      break;
    case 'a':
      optstring = optarg;
      newConfig.d_ACL.addMask(optstring);
      break;
    case 'k':
#if defined HAVE_LIBSODIUM || defined(HAVE_LIBCRYPTO)
    {
      std::string consoleKey;
      if (B64Decode(string(optarg), consoleKey) < 0) {
        cerr << "Unable to decode key '" << optarg << "'." << endl;
        // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
        exit(EXIT_FAILURE);
      }
      dnsdist::configuration::updateRuntimeConfiguration([&consoleKey](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_consoleKey = std::move(consoleKey);
      });
    }
#else
      cerr << "dnsdist has been built without libsodium or libcrypto, -k/--setkey is unsupported." << endl;
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      exit(EXIT_FAILURE);
#endif
    break;
    case 'l':
      cmdLine.locals.push_back(boost::trim_copy(string(optarg)));
      break;
    case 's':
      cmdLine.useStructuredLogging = (boost::to_lower_copy(std::string(optarg)) == "true");
      break;
    case 'u':
      cmdLine.uid = optarg;
      break;
    case 'v':
      newConfig.d_verbose = true;
      break;
    case 'V':
      reportFeatures();
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      exit(EXIT_SUCCESS);
      break;
    case '?':
      // getopt_long printed an error message.
      usage();
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      exit(EXIT_FAILURE);
      break;
    }
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): argv
  argv += optind;

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): argv
  for (const auto* ptr = argv; *ptr != nullptr; ++ptr) {
    if (cmdLine.beClient) {
      clientAddress = ComboAddress(*ptr, 5199);
    }
    else {
      cmdLine.remotes.emplace_back(*ptr);
    }
  }

  dnsdist::configuration::updateRuntimeConfiguration([&newConfig](dnsdist::configuration::RuntimeConfiguration& config) {
    config = std::move(newConfig);
  });
}
static void setupPools(const std::shared_ptr<const Logr::Logger>& logger)
{
  bool precompute = false;
  const auto& currentConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (currentConfig.d_lbPolicy->getName() == "chashed") {
    precompute = true;
  }
  else {
    for (const auto& entry : currentConfig.d_pools) {
      if (entry.second.policy != nullptr && entry.second.policy->getName() == "chashed") {
        precompute = true;
        break;
      }
    }
  }
  if (precompute) {
    VERBOSESLOG(infolog("Pre-computing hashes for consistent hash load-balancing policy"),
                logger->info(Logr::Info, "Pre-computing hashes for consistent hash load-balancing policy"));

    // pre compute hashes
    for (const auto& backend : currentConfig.d_backends) {
      if (backend->d_config.d_weight < 100) {
        VERBOSESLOG(infolog("Warning, the backend '%s' has a very low weight (%d), which will not yield a good distribution of queries with the 'chashed' policy. Please consider raising it to at least '100'.", backend->getName(), backend->d_config.d_weight),
                    logger->info(Logr::Info, "Warning, this backend has a very low weight, which will not yield a good distribution of queries with the 'chashed' policy. Please consider raising it to at least '100'", "backend.name", Logging::Loggable(backend->getName()), "backend.weight", Logging::Loggable(backend->d_config.d_weight)));
      }

      backend->hash();
    }
  }
}

static void dropPrivileges(const CommandLineParameters& cmdLine)
{
  uid_t newgid = getegid();
  gid_t newuid = geteuid();

  if (!cmdLine.gid.empty()) {
    newgid = strToGID(cmdLine.gid);
  }

  if (!cmdLine.uid.empty()) {
    newuid = strToUID(cmdLine.uid);
  }

  bool retainedCapabilities = true;
  if (!dnsdist::configuration::getImmutableConfiguration().d_capabilitiesToRetain.empty() && (getegid() != newgid || geteuid() != newuid)) {
    retainedCapabilities = keepCapabilitiesAfterSwitchingIDs();
  }

  if (getegid() != newgid) {
    if (running_in_service_mgr()) {
      SLOG(errlog("--gid/-g set on command-line, but dnsdist was started as a systemd service. Use the 'Group' setting in the systemd unit file to set the group to run as"),
           dnsdist::logging::getTopLogger("setup")->info(Logr::Error, "--gid/-g set on command-line, but dnsdist was started as a systemd service. Use the 'Group' setting in the systemd unit file to set the group to run as"));
      _exit(EXIT_FAILURE);
    }
    dropGroupPrivs(newgid);
  }

  if (geteuid() != newuid) {
    if (running_in_service_mgr()) {
      SLOG(errlog("--uid/-u set on command-line, but dnsdist was started as a systemd service. Use the 'User' setting in the systemd unit file to set the user to run as"),
           dnsdist::logging::getTopLogger("setup")->info(Logr::Error, "--uid/-u set on command-line, but dnsdist was started as a systemd service. Use the 'User' setting in the systemd unit file to set the user to run as"));
      _exit(EXIT_FAILURE);
    }
    dropUserPrivs(newuid);
  }

  if (retainedCapabilities) {
    dropCapabilitiesAfterSwitchingIDs();
  }

  try {
    /* we might still have capabilities remaining,
       for example if we have been started as root
       without --uid or --gid (please don't do that)
       or as an unprivileged user with ambient
       capabilities like CAP_NET_BIND_SERVICE.
    */
    dropCapabilities(dnsdist::configuration::getImmutableConfiguration().d_capabilitiesToRetain);
  }
  catch (const std::exception& e) {
    SLOG(warnlog("%s", e.what()),
         dnsdist::logging::getTopLogger("setup")->error(Logr::Warning, e.what(), "Error while dropping capabilities"));
  }
}

static void initFrontends(const CommandLineParameters& cmdLine)
{
  auto frontends = dnsdist::configuration::getImmutableConfiguration().d_frontends;

  if (!cmdLine.locals.empty()) {
    for (auto it = frontends.begin(); it != frontends.end();) {
      /* DoH, DoT and DNSCrypt frontends are separate */
      if ((*it)->dohFrontend == nullptr && (*it)->tlsFrontend == nullptr && (*it)->dnscryptCtx == nullptr && (*it)->doqFrontend == nullptr && (*it)->doh3Frontend == nullptr) {
        it = frontends.erase(it);
      }
      else {
        ++it;
      }
    }

    for (const auto& loc : cmdLine.locals) {
      /* UDP */
      frontends.emplace_back(std::make_unique<ClientState>(ComboAddress(loc, 53), false, false, 0, "", std::set<int>{}, true, false));
      /* TCP */
      frontends.emplace_back(std::make_unique<ClientState>(ComboAddress(loc, 53), true, false, 0, "", std::set<int>{}, true, false));
    }
  }

  if (frontends.empty()) {
    /* UDP */
    frontends.emplace_back(std::make_unique<ClientState>(ComboAddress("127.0.0.1", 53), false, false, 0, "", std::set<int>{}, true, false));
    /* TCP */
    frontends.emplace_back(std::make_unique<ClientState>(ComboAddress("127.0.0.1", 53), true, false, 0, "", std::set<int>{}, true, false));
  }

  dnsdist::configuration::updateImmutableConfiguration([&frontends](dnsdist::configuration::ImmutableConfiguration& config) {
    config.d_frontends = std::move(frontends);
  });
}

namespace dnsdist
{
static void startFrontends()
{
#ifdef HAVE_XSK
  for (auto& xskContext : dnsdist::xsk::g_xsk) {
    std::thread xskThread(dnsdist::xsk::XskRouter, std::move(xskContext));
    xskThread.detach();
  }
#endif /* HAVE_XSK */

  std::vector<ClientState*> tcpStates;
  std::vector<ClientState*> udpStates;
  for (const auto& clientState : dnsdist::getFrontends()) {
#ifdef HAVE_XSK
    if (clientState->xskInfo) {
      dnsdist::xsk::addDestinationAddress(clientState->local);

      std::thread xskCT(dnsdist::xsk::XskClientThread, clientState.get());
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(xskCT.native_handle(), clientState->cpus);
      }
      xskCT.detach();
    }
#endif /* HAVE_XSK */

    if (clientState->doqFrontend != nullptr) {
#ifdef HAVE_DNS_OVER_QUIC
      std::thread doqThreadHandle(doqThread, clientState.get());
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(doqThreadHandle.native_handle(), clientState->cpus);
      }
      doqThreadHandle.detach();
#endif /* HAVE_DNS_OVER_QUIC */
      continue;
    }
    if (clientState->doh3Frontend != nullptr) {
#ifdef HAVE_DNS_OVER_HTTP3
      std::thread doh3ThreadHandle(doh3Thread, clientState.get());
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(doh3ThreadHandle.native_handle(), clientState->cpus);
      }
      doh3ThreadHandle.detach();
#endif /* HAVE_DNS_OVER_HTTP3 */
      continue;
    }
    if (clientState->udpFD >= 0) {
#ifdef USE_SINGLE_ACCEPTOR_THREAD
      udpStates.push_back(clientState.get());
#else /* USE_SINGLE_ACCEPTOR_THREAD */
      std::thread udpClientThreadHandle(dnsdist::udp::udpClientThread, std::vector<ClientState*>{clientState.get()});
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(udpClientThreadHandle.native_handle(), clientState->cpus);
      }
      udpClientThreadHandle.detach();
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
    }
    else if (clientState->tcpFD >= 0) {
#ifdef USE_SINGLE_ACCEPTOR_THREAD
      tcpStates.push_back(clientState.get());
#else /* USE_SINGLE_ACCEPTOR_THREAD */
      std::thread tcpAcceptorThreadHandle(tcpAcceptorThread, std::vector<ClientState*>{clientState.get()});
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(tcpAcceptorThreadHandle.native_handle(), clientState->cpus);
      }
      tcpAcceptorThreadHandle.detach();
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
    }
  }
#ifdef USE_SINGLE_ACCEPTOR_THREAD
  if (!udpStates.empty()) {
    std::thread udpThreadHandle(udpClientThread, udpStates);
    udpThreadHandle.detach();
  }

  /* Gives TCP client threads by default */
  g_tcpclientthreads = std::make_unique<TCPClientCollection>(1, tcpStates);
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
}
}

struct ListeningSockets
{
  Socket d_consoleSocket{-1};
  std::vector<std::pair<ComboAddress, Socket>> d_webServerSockets;
};

static ListeningSockets initListeningSockets()
{
  ListeningSockets result;
  const auto& currentConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();

  if (currentConfig.d_consoleEnabled) {
    const auto& local = currentConfig.d_consoleServerAddress;
    try {
      result.d_consoleSocket = Socket(local.sin4.sin_family, SOCK_STREAM, 0);
      result.d_consoleSocket.bind(local, true);
      result.d_consoleSocket.listen(5);
    }
    catch (const std::exception& exp) {
      SLOG(errlog("Unable to bind to control socket on %s: %s", local.toStringWithPort(), exp.what()),
           dnsdist::logging::getTopLogger("setup")->error(Logr::Error, exp.what(), "Unable to bind to console control socket", "network.local.address", Logging::Loggable(local)));
      if (currentConfig.d_consoleBindFatal) {
        _exit(EXIT_FAILURE);
      }
    }
  }

  for (const auto& local : currentConfig.d_webServerAddresses) {
    try {
      auto webServerSocket = Socket(local.sin4.sin_family, SOCK_STREAM, 0);
      webServerSocket.bind(local, true);
      webServerSocket.listen(5);
      result.d_webServerSockets.emplace_back(local, std::move(webServerSocket));
    }
    catch (const std::exception& exp) {
      SLOG(errlog("Unable to bind to web server socket on %s: %s", local.toStringWithPort(), exp.what()),
           dnsdist::logging::getTopLogger("setup")->error(Logr::Error, exp.what(), "Unable to bind to web server socket", "network.local.address", Logging::Loggable(local)));
      if (currentConfig.d_webserverBindFatal) {
        _exit(EXIT_FAILURE);
      }
    }
  }

  return result;
}

static std::optional<std::string> lookForTentativeConfigurationFileWithExtension(const std::string& configurationFile, const std::string& extension)
{
  auto dotPos = configurationFile.rfind('.');
  if (dotPos == std::string::npos) {
    return std::nullopt;
  }
  auto tentativeFile = configurationFile.substr(0, dotPos + 1) + extension;
  if (!std::filesystem::exists(tentativeFile)) {
    return std::nullopt;
  }
  return tentativeFile;
}

static bool loadConfigurationFromFile(const std::string& configurationFile, bool isClient, bool configCheck, const std::shared_ptr<const Logr::Logger>& logger)
{
  if (boost::ends_with(configurationFile, ".yml")) {
    // the bindings are always needed, for example for inline Lua
    dnsdist::lua::setupLuaBindingsOnly(*(g_lua.lock()), isClient, configCheck);

    if (auto tentativeLuaConfFile = lookForTentativeConfigurationFileWithExtension(configurationFile, "lua")) {
      SLOG(infolog("Loading configuration from auto-discovered Lua file %s", *tentativeLuaConfFile),
           logger->info(Logr::Info, "Loading configuration from auto-discovered Lua file", "path", Logging::Loggable(*tentativeLuaConfFile)));

      dnsdist::configuration::lua::loadLuaConfigurationFile(*(g_lua.lock()), *tentativeLuaConfFile, configCheck);
    }

    SLOG(infolog("Loading configuration from YAML file %s", configurationFile),
         logger->info(Logr::Info, "Loading configuration from YAML file", "path", Logging::Loggable(configurationFile)));

    if (!dnsdist::configuration::yaml::loadConfigurationFromFile(configurationFile, isClient, configCheck)) {
      return false;
    }
    if (!isClient && !configCheck) {
      dnsdist::lua::setupLuaConfigurationOptions(*(g_lua.lock()), false, false);
    }
    return true;
  }

  dnsdist::lua::setupLua(*(g_lua.lock()), isClient, configCheck);
  if (boost::ends_with(configurationFile, ".lua")) {
    SLOG(infolog("Loading configuration from Lua file %s", configurationFile),
         logger->info(Logr::Info, "Loading configuration from Lua file", "path", Logging::Loggable(configurationFile)));

    dnsdist::configuration::lua::loadLuaConfigurationFile(*(g_lua.lock()), configurationFile, configCheck);
    if (auto tentativeYamlConfFile = lookForTentativeConfigurationFileWithExtension(configurationFile, "yml")) {
      SLOG(infolog("Loading configuration from auto-discovered YAML file %s", *tentativeYamlConfFile),
           logger->info(Logr::Info, "Loading configuration from auto-discovered YAML file", "path", Logging::Loggable(*tentativeYamlConfFile)));
      return dnsdist::configuration::yaml::loadConfigurationFromFile(*tentativeYamlConfFile, isClient, configCheck);
    }
  }
  else {
    SLOG(infolog("Loading configuration from Lua file %s", configurationFile),
         logger->info(Logr::Info, "Loading configuration from Lua file", "path", Logging::Loggable(configurationFile)));

    dnsdist::configuration::lua::loadLuaConfigurationFile(*(g_lua.lock()), configurationFile, configCheck);
  }
  return true;
}

int main(int argc, char** argv)
{
  try {
    CommandLineParameters cmdLine{};
    size_t udpBindsCount = 0;
    size_t tcpBindsCount = 0;

    dnsdist::console::completion::setupCompletion();

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast): SIG_IGN macro
    signal(SIGPIPE, SIG_IGN);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast): SIG_IGN macro
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, sigTermHandler);

    /* for now, we will create the correct backend after parsing the configuration */
    dnsdist::logging::setup("");
    auto setupLogger = dnsdist::logging::getTopLogger("setup");

    openlog("dnsdist", LOG_PID | LOG_NDELAY, LOG_DAEMON);

#ifdef HAVE_LIBSODIUM
    if (sodium_init() == -1) {
      cerr << "Unable to initialize crypto library" << endl;
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only on thread at this point
      exit(EXIT_FAILURE);
    }
#endif
    dnsdist::initRandom();

#ifdef HAVE_XSK
    try {
      dnsdist::xsk::clearDestinationAddresses();
    }
    catch (const std::exception& exp) {
      /* silently handle failures: at this point we don't even know if XSK is enabled,
         and we might not have the correct map (not the default one). */
    }
#endif /* HAVE_XSK */

    ComboAddress clientAddress = ComboAddress();

    parseParameters(argc, argv, cmdLine, clientAddress);
    if (cmdLine.config.empty()) {
      cmdLine.config = SYSCONFDIR "/dnsdist.yml";
      if (!std::filesystem::exists(cmdLine.config) && std::filesystem::exists(SYSCONFDIR "/dnsdist.conf")) {
        cmdLine.config = SYSCONFDIR "/dnsdist.conf";
      }
    }
    dnsdist::configuration::updateImmutableConfiguration([&cmdLine](dnsdist::configuration::ImmutableConfiguration& config) {
      config.d_loggingBackend = cmdLine.structuredLoggingBackend;
      config.d_structuredLogging = cmdLine.useStructuredLogging;
    });

    if (cmdLine.useStructuredLogging && !cmdLine.structuredLoggingBackend.empty()) {
      dnsdist::logging::setup(cmdLine.structuredLoggingBackend);
      setupLogger = dnsdist::logging::getTopLogger("setup");
    }

    dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_lbPolicy = std::make_shared<ServerPolicy>("leastOutstanding", leastOutstanding, false);
    });

    if (cmdLine.beClient || !cmdLine.command.empty()) {
      if (!loadConfigurationFromFile(cmdLine.config, true, false, setupLogger)) {
#ifdef COVERAGE
        doExitNicely(EXIT_FAILURE);
#else
        _exit(EXIT_FAILURE);
#endif
      }
      if (clientAddress != ComboAddress()) {
        dnsdist::configuration::updateRuntimeConfiguration([&clientAddress](dnsdist::configuration::RuntimeConfiguration& config) {
          config.d_consoleServerAddress = clientAddress;
        });
      }
      dnsdist::console::doClient(cmdLine.command);
#ifdef COVERAGE
      doExitNicely(EXIT_SUCCESS);
#else
      _exit(EXIT_SUCCESS);
#endif
    }

    dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
      auto& acl = config.d_ACL;
      if (acl.empty()) {
        for (const auto& addr : {"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"}) {
          acl.addMask(addr);
        }
      }
      for (const auto& mask : {"127.0.0.1/8", "::1/128"}) {
        config.d_consoleACL.addMask(mask);
      }
      config.d_webServerACL.toMasks("127.0.0.1, ::1");
    });

    dnsdist::webserver::registerBuiltInWebHandlers();

    if (cmdLine.checkConfig) {
      if (!loadConfigurationFromFile(cmdLine.config, false, true, setupLogger)) {
#ifdef COVERAGE
        doExitNicely(EXIT_FAILURE);
#else
        _exit(EXIT_FAILURE);
#endif
      }
      // No exception was thrown
      dnsdist::logging::setup(dnsdist::configuration::getImmutableConfiguration().d_loggingBackend);
      setupLogger = dnsdist::logging::getTopLogger("setup");

      SLOG(infolog("Configuration '%s' OK!", cmdLine.config),
           setupLogger->info(Logr::Info, "Configuration OK", "path", Logging::Loggable(cmdLine.config)));
      doExitNicely();
    }

    SLOG(infolog("dnsdist %s comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2", VERSION),
         setupLogger->info(Logr::Info, "dnsdist " VERSION " comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2"));

    dnsdist::g_asyncHolder = std::make_unique<dnsdist::AsynchronousHolder>();

    /* create the default pool no matter what */
    createPoolIfNotExists("");

    if (!loadConfigurationFromFile(cmdLine.config, false, false, setupLogger)) {
#ifdef COVERAGE
      doExitNicely(EXIT_FAILURE);
#else
      _exit(EXIT_FAILURE);
#endif
    }

    dnsdist::logging::setup(dnsdist::configuration::getImmutableConfiguration().d_loggingBackend);
    setupLogger = dnsdist::logging::getTopLogger("setup");

    // we only want to update this value if it has not been set by either the Lua or YAML configuration,
    // and we need to stop touching this value once the backends' hashes have been computed, in setupPools()
    dnsdist::configuration::updateImmutableConfiguration([](dnsdist::configuration::ImmutableConfiguration& config) {
      if (config.d_hashPerturbation == 0) {
        config.d_hashPerturbation = dnsdist::getRandomValue(0xffffffff);
      }
    });

    setupPools(setupLogger);

    initFrontends(cmdLine);

    for (const auto& frontend : dnsdist::getFrontends()) {
      if (!frontend->tcp) {
        ++udpBindsCount;
      }
      else {
        ++tcpBindsCount;
      }
    }

    dnsdist::configuration::setImmutableConfigurationDone();

    {
      const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
      setTCPDownstreamMaxIdleConnectionsPerBackend(immutableConfig.d_outgoingTCPMaxIdlePerBackend);
      setTCPDownstreamMaxIdleTime(immutableConfig.d_outgoingTCPMaxIdleTime);
      setTCPDownstreamCleanupInterval(immutableConfig.d_outgoingTCPCleanupInterval);
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
      setDoHDownstreamMaxIdleConnectionsPerBackend(immutableConfig.d_outgoingDoHMaxIdlePerBackend);
      setDoHDownstreamMaxIdleTime(immutableConfig.d_outgoingDoHMaxIdleTime);
      setDoHDownstreamCleanupInterval(immutableConfig.d_outgoingDoHCleanupInterval);
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
    }

    {
      const auto& config = dnsdist::configuration::getImmutableConfiguration();
      Rings::RingsConfiguration ringsConfig{
        .capacity = config.d_ringsCapacity,
        .numberOfShards = config.d_ringsNumberOfShards,
        .nbLockTries = config.d_ringsNbLockTries,
        .samplingRate = config.d_ringsSamplingRate,
        .recordQueries = config.d_ringsRecordQueries,
        .recordResponses = config.d_ringsRecordResponses,
      };
      g_rings.init(ringsConfig);
    }

    for (const auto& frontend : dnsdist::getFrontends()) {
      setUpLocalBind(*frontend, setupLogger);
    }

    {
      std::string acls;
      auto aclEntries = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.toStringVector();
      for (const auto& aclEntry : aclEntries) {
        if (!acls.empty()) {
          acls += ", ";
        }
        acls += aclEntry;
      }
      SLOG(infolog("ACL allowing queries from: %s", acls),
           setupLogger->info(Logr::Info, "Allowing queries from", "acl", Logging::Loggable(acls)));
    }
    {
      std::string acls;
      auto aclEntries = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleACL.toStringVector();
      for (const auto& entry : aclEntries) {
        if (!acls.empty()) {
          acls += ", ";
        }
        acls += entry;
      }
      SLOG(infolog("Console ACL allowing connections from: %s", acls),
           setupLogger->info(Logr::Info, "Allowing console connections from", "acl", Logging::Loggable(acls)));
    }

    auto listeningSockets = initListeningSockets();

#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO)
    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleEnabled && dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey.empty()) {
      SLOG(warnlog("Warning, the console has been enabled via 'controlSocket()' but no key has been set with 'setKey()' so all connections will fail until a key has been set"),
           setupLogger->info(Logr::Warning, "The console has been enabled via 'controlSocket()' but no key has been set with 'setKey()' so allconnections will fail until a key has been set"));
    }
#endif

    dropPrivileges(cmdLine);

    /* this need to be done _after_ dropping privileges */
#ifndef DISABLE_DELAY_PIPE
    dnsdist::delay_pipe::g_delay = std::make_unique<DelayPipe<dnsdist::delay_pipe::DelayedPacket>>();
#endif /* DISABLE_DELAY_PIPE */

#if defined(HAVE_NET_SNMP)
    if (dnsdist::configuration::getImmutableConfiguration().d_snmpEnabled) {
      g_snmpAgent = std::make_unique<DNSDistSNMPAgent>("dnsdist", dnsdist::configuration::getImmutableConfiguration().d_snmpDaemonSocketPath);
      g_snmpAgent->run();
    }
#endif /* HAVE_NET_SNMP */

    /* we need to create the TCP worker threads before the
       acceptor ones, otherwise we might crash when processing
       the first TCP query */
#ifndef USE_SINGLE_ACCEPTOR_THREAD
    const auto maxTCPClientThreads = dnsdist::configuration::getImmutableConfiguration().d_maxTCPClientThreads;
    /* the limit is completely arbitrary: hopefully high enough not to trigger too many false positives
       but low enough to be useful */
    if (maxTCPClientThreads >= 50U) {
      SLOG(warnlog("setMaxTCPClientThreads(%d) might create a large number of TCP connections to backends, and is probably not needed, please consider lowering it", maxTCPClientThreads),
           setupLogger->info(Logr::Warning, "The current setMaxTCPClientThreads() value might create a large number of TCP connections to backends, and is probably not needed, please consider lowering it", "dnsdist.max_tcp_client_threads", Logging::Loggable(maxTCPClientThreads)));
    }
    g_tcpclientthreads = std::make_unique<TCPClientCollection>(maxTCPClientThreads, std::vector<ClientState*>());
#endif

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    initDoHWorkers();
#endif

    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleEnabled) {
      std::thread consoleControlThread(dnsdist::console::controlThread, std::move(listeningSockets.d_consoleSocket));
      consoleControlThread.detach();
    }
    for (auto& [listeningAddress, socket] : listeningSockets.d_webServerSockets) {
      std::thread webServerThread(dnsdist::webserver::WebserverThread, listeningAddress, std::move(socket));
      webServerThread.detach();
    }

    for (const auto& backend : dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends) {
      if (backend->connected) {
        backend->start();
      }
    }

    if (!cmdLine.remotes.empty()) {
      for (const auto& address : cmdLine.remotes) {
        DownstreamState::Config config;
        config.remote = ComboAddress(address, 53);
        auto ret = std::make_shared<DownstreamState>(std::move(config), nullptr, true);
        addServerToPool("", ret);
        ret->start();
        dnsdist::configuration::updateRuntimeConfiguration([&ret](dnsdist::configuration::RuntimeConfiguration& runtimeConfig) {
          runtimeConfig.d_backends.push_back(std::move(ret));
        });
      }
    }

    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends.empty()) {
      SLOG(errlog("No downstream servers defined: all packets will get dropped"),
           setupLogger->info(Logr::Error, "No downstream servers defined: all packets will get dropped"));
      // you might define them later, but you need to know
    }

    checkFileDescriptorsLimits(udpBindsCount, tcpBindsCount);

    {
      // coverity[auto_causes_copy]
      const auto states = dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends; // it is a copy, but the internal shared_ptrs are the real deal
      auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(states.size()));
      for (auto& dss : states) {

        if (dss->d_config.d_availability == DownstreamState::Availability::Auto) {
          if (dss->d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active) {
            dss->d_nextCheck = dss->d_config.checkInterval;
          }

          if (!queueHealthCheck(mplexer, dss, true)) {
            dss->submitHealthCheckResult(true, false);
            dss->setUpStatus(false);
            SLOG(warnlog("Marking downstream %s as 'down'", dss->getNameWithAddr()),
                 setupLogger->info(Logr::Warning, "Marking downstream backend server as 'down'", "backend.name", Logging::Loggable(dss->getName()), "backend.address", Logging::Loggable(dss->d_config.remote), "backend.health_check.status", Logging::Loggable("down")));
          }
        }
      }
      handleQueuedHealthChecks(*mplexer, true);
    }

    dnsdist::startFrontends();

    dnsdist::ServiceDiscovery::run();

#ifndef DISABLE_CARBON
    dnsdist::Carbon::run(dnsdist::configuration::getCurrentRuntimeConfiguration().d_carbonEndpoints);
#endif /* DISABLE_CARBON */

    thread stattid(maintThread);
    stattid.detach();

    thread healththread(healthChecksThread);

#ifndef DISABLE_DYNBLOCKS
    thread dynBlockMaintThread(dynBlockMaintenanceThread);
    dynBlockMaintThread.detach();
#endif /* DISABLE_DYNBLOCKS */

#ifndef DISABLE_SECPOLL
    if (!dnsdist::configuration::getCurrentRuntimeConfiguration().d_secPollSuffix.empty()) {
      thread secpollthread(secPollThread);
      secpollthread.detach();
    }
#endif /* DISABLE_SECPOLL */

    if (cmdLine.beSupervised) {
#ifdef HAVE_SYSTEMD
      sd_notify(0, "READY=1");
#endif
      healththread.join();
    }
    else {
      healththread.detach();
      dnsdist::console::doConsole();
    }
    doExitNicely();
  }
  catch (const LuaContext::ExecutionErrorException& e) {
    try {
      SLOG(errlog("Fatal Lua error: %s", e.what()),
           dnsdist::logging::getTopLogger("main")->error(Logr::Error, e.what(), "Fatal Lua error"));
      std::rethrow_if_nested(e);
    }
    catch (const std::exception& ne) {
      SLOG(errlog("Details: %s", ne.what()),
           dnsdist::logging::getTopLogger("main")->error(Logr::Error, ne.what(), "Additional details for fatal Lua error"));
    }
    catch (const PDNSException& ae) {
      SLOG(errlog("Fatal pdns error: %s", ae.reason),
           dnsdist::logging::getTopLogger("main")->error(Logr::Error, ae.reason, "Additional PowerDNS details for fatal Lua error"));
    }
    doExitNicely(EXIT_FAILURE);
  }
  catch (const std::exception& e) {
    SLOG(errlog("Fatal error: %s", e.what()),
         dnsdist::logging::getTopLogger("main")->error(Logr::Error, e.what(), "Fatal error"));
    doExitNicely(EXIT_FAILURE);
  }
  catch (const PDNSException& ae) {
    SLOG(errlog("Fatal pdns error: %s", ae.reason),
         dnsdist::logging::getTopLogger("main")->error(Logr::Error, ae.reason, "Fatal PowerDNS error"));
    doExitNicely(EXIT_FAILURE);
  }
}
