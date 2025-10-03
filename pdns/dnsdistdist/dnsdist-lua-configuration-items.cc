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

#include <string>
#include <vector>

#include "config.h"
#include "dnsdist-configuration.hh"
#include "dnsdist-lua.hh"
#include "dolog.hh"

namespace dnsdist::lua
{
struct BooleanConfigurationItems
{
  const std::function<void(dnsdist::configuration::RuntimeConfiguration& config, bool newValue)> mutator;
};

struct UnsignedIntegerConfigurationItems
{
  const std::function<void(dnsdist::configuration::RuntimeConfiguration& config, uint64_t value)> mutator;
  const uint64_t maximumValue{std::numeric_limits<uint64_t>::max()};
};

struct StringConfigurationItems
{
  const std::function<void(dnsdist::configuration::RuntimeConfiguration& config, const std::string& value)> mutator;
};

struct BooleanImmutableConfigurationItems
{
  const std::function<void(dnsdist::configuration::ImmutableConfiguration& config, bool newValue)> mutator;
};
struct UnsignedIntegerImmutableConfigurationItems
{
  const std::function<void(dnsdist::configuration::ImmutableConfiguration& config, uint64_t value)> mutator;
  const uint64_t maximumValue{std::numeric_limits<uint64_t>::max()};
};

struct DoubleImmutableConfigurationItems
{
  const std::function<void(dnsdist::configuration::ImmutableConfiguration& config, double value)> mutator;
  const double minimumValue{1.0};
};

// clang-format off
static const std::map<std::string, BooleanConfigurationItems> s_booleanConfigItems{
  {"truncateTC", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_truncateTC = newValue; }}},
  {"fixupCase", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_fixupCase = newValue; }}},
  {"setECSOverride", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_ecsOverride = newValue; }}},
  {"setQueryCount", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_queryCountConfig.d_enabled = newValue; }}},
  {"setVerbose", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_verbose = newValue; }}},
  {"setVerboseHealthChecks", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_verboseHealthChecks = newValue; }}},
  {"setOpenTelemetryTracing", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_openTelemetryTracing = newValue; }}},
  {"setServFailWhenNoServer", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_servFailOnNoPolicy = newValue; }}},
  {"setRoundRobinFailOnNoServer", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_roundrobinFailOnNoServer = newValue; }}},
  {"setDropEmptyQueries", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_dropEmptyQueries = newValue; }}},
  {"setAllowEmptyResponse", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_allowEmptyResponse = newValue; }}},
  {"setConsoleConnectionsLogging", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_logConsoleConnections = newValue; }}},
  {"setProxyProtocolApplyACLToProxiedClients", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_applyACLToProxiedClients = newValue; }}},
  {"setAddEDNSToSelfGeneratedResponses", {[](dnsdist::configuration::RuntimeConfiguration& config, bool newValue) { config.d_addEDNSToSelfGeneratedResponses = newValue; }}},
};

static const std::map<std::string, UnsignedIntegerConfigurationItems> s_unsignedIntegerConfigItems{
  {"setCacheCleaningDelay", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_cacheCleaningDelay = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setCacheCleaningPercentage", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_cacheCleaningPercentage = newValue; }, 100U}},
  {"setOutgoingTLSSessionsCacheMaxTicketsPerBackend", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_tlsSessionCacheMaxSessionsPerBackend = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setOutgoingTLSSessionsCacheCleanupDelay", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_tlsSessionCacheCleanupDelay = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setOutgoingTLSSessionsCacheMaxTicketValidity", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_tlsSessionCacheSessionValidity = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setECSSourcePrefixV4", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_ECSSourcePrefixV4 = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setECSSourcePrefixV6", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_ECSSourcePrefixV6 = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setTCPRecvTimeout", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_tcpRecvTimeout = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setTCPSendTimeout", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_tcpSendTimeout = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setMaxTCPQueriesPerConnection", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_maxTCPQueriesPerConn = newValue; }, std::numeric_limits<uint64_t>::max()}},
  {"setMaxTCPConnectionDuration", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_maxTCPConnectionDuration = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setStaleCacheEntriesTTL", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_staleCacheEntriesTTL = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setConsoleOutputMaxMsgSize", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_consoleOutputMsgMaxSize = newValue; }, std::numeric_limits<uint32_t>::max()}},
#ifndef DISABLE_SECPOLL
  {"setSecurityPollInterval", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_secPollInterval = newValue; }, std::numeric_limits<uint32_t>::max()}},
#endif /* DISABLE_SECPOLL */
  {"setProxyProtocolMaximumPayloadSize", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_proxyProtocolMaximumSize = std::max(static_cast<uint64_t>(16), newValue); }, std::numeric_limits<uint32_t>::max()}},
  {"setPayloadSizeOnSelfGeneratedAnswers", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) {
    if (newValue < 512) {
      warnlog("setPayloadSizeOnSelfGeneratedAnswers() is set too low, using 512 instead!");
      g_outputBuffer = "setPayloadSizeOnSelfGeneratedAnswers() is set too low, using 512 instead!";
      newValue = 512;
    }
    if (newValue > dnsdist::configuration::s_udpIncomingBufferSize) {
      warnlog("setPayloadSizeOnSelfGeneratedAnswers() is set too high, capping to %d instead!", dnsdist::configuration::s_udpIncomingBufferSize);
      g_outputBuffer = "setPayloadSizeOnSelfGeneratedAnswers() is set too high, capping to " + std::to_string(dnsdist::configuration::s_udpIncomingBufferSize) + " instead";
      newValue = dnsdist::configuration::s_udpIncomingBufferSize;
    }
    config.d_payloadSizeSelfGenAnswers = newValue;
  },
   std::numeric_limits<uint64_t>::max()}},
#ifndef DISABLE_DYNBLOCKS
  {"setDynBlocksPurgeInterval", {[](dnsdist::configuration::RuntimeConfiguration& config, uint64_t newValue) { config.d_dynBlocksPurgeInterval = newValue; }, std::numeric_limits<uint32_t>::max()}},
#endif /* DISABLE_DYNBLOCKS */
};

static const std::map<std::string, StringConfigurationItems> s_stringConfigItems{
#ifndef DISABLE_SECPOLL
  {"setSecurityPollSuffix", {[](dnsdist::configuration::RuntimeConfiguration& config, const std::string& newValue) { config.d_secPollSuffix = newValue; }}},
#endif /* DISABLE_SECPOLL */
};

static const std::map<std::string, BooleanImmutableConfigurationItems> s_booleanImmutableConfigItems{
  {"setRandomizedOutgoingSockets", {[](dnsdist::configuration::ImmutableConfiguration& config, bool newValue) { config.d_randomizeUDPSocketsToBackend = newValue; }}},
  {"setRandomizedIdsOverUDP", {[](dnsdist::configuration::ImmutableConfiguration& config, bool newValue) { config.d_randomizeIDsToBackend = newValue; }}},
};

static const std::map<std::string, UnsignedIntegerImmutableConfigurationItems> s_unsignedIntegerImmutableConfigItems{
  {"setMaxTCPQueuedConnections", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_maxTCPQueuedConnections = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setMaxTCPClientThreads", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_maxTCPClientThreads = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setMaxTCPConnectionsPerClient", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_maxTCPConnectionsPerClient = newValue; }, std::numeric_limits<uint64_t>::max()}},
  {"setTCPInternalPipeBufferSize", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpInternalPipeBufferSize = newValue; }, std::numeric_limits<uint64_t>::max()}},
  {"setMaxCachedTCPConnectionsPerDownstream", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_outgoingTCPMaxIdlePerBackend = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setTCPDownstreamCleanupInterval", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_outgoingTCPCleanupInterval = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setTCPDownstreamMaxIdleTime", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_outgoingTCPMaxIdleTime = newValue; }, std::numeric_limits<uint16_t>::max()}},
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
  {"setOutgoingDoHWorkerThreads", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_outgoingDoHWorkers = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setMaxIdleDoHConnectionsPerDownstream", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_outgoingDoHMaxIdlePerBackend = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setDoHDownstreamCleanupInterval", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_outgoingDoHCleanupInterval = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setDoHDownstreamMaxIdleTime", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_outgoingDoHMaxIdleTime = newValue; }, std::numeric_limits<uint16_t>::max()}},
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
  {"setMaxUDPOutstanding", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_maxUDPOutstanding = newValue; }, std::numeric_limits<uint16_t>::max()}},
  {"setWHashedPertubation" /* Deprecated */, {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_hashPerturbation = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setWHashedPerturbation", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_hashPerturbation = newValue; }, std::numeric_limits<uint32_t>::max()}},
#ifndef DISABLE_RECVMMSG
  {"setUDPMultipleMessagesVectorSize", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_udpVectorSize = newValue; }, std::numeric_limits<uint32_t>::max()}},
#endif /* DISABLE_RECVMMSG */
  {"setUDPTimeout", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_udpTimeout = newValue; }, std::numeric_limits<uint8_t>::max()}},
  {"setConsoleMaximumConcurrentConnections", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_consoleMaxConcurrentConnections = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setRingBuffersLockRetries", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_ringsNbLockTries = newValue; }, std::numeric_limits<uint64_t>::max()}},
  {"setMaxTCPConnectionRatePerClient", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_maxTCPConnectionsRatePerClient = newValue; }, std::numeric_limits<uint64_t>::max()}},
  {"setMaxTLSResumedSessionRatePerClient", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_maxTLSResumedSessionsRatePerClient = newValue; }, std::numeric_limits<uint64_t>::max()}},
  {"setMaxTLSNewSessionRatePerClient", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_maxTLSNewSessionsRatePerClient = newValue; }, std::numeric_limits<uint64_t>::max()}},
  {"setTCPConnectionRateInterval", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpConnectionsRatePerClientInterval = newValue; }, std::numeric_limits<uint64_t>::max()}},
  {"setMaxTCPReadIOsPerQuery", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_maxTCPReadIOsPerQuery = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setBanDurationForExceedingMaxReadIOsPerQuery", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpBanDurationForExceedingMaxReadIOsPerQuery = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setBanDurationForExceedingTCPTLSRate", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpBanDurationForExceedingTCPTLSRate = newValue; }, std::numeric_limits<uint32_t>::max()}},
  {"setTCPConnectionsOverloadThreshold", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpConnectionsOverloadThreshold = newValue; }, std::numeric_limits<uint8_t>::max()}},
  {"setTCPConnectionsMaskV4", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpConnectionsMaskV4 = newValue; }, std::numeric_limits<uint8_t>::max()}},
  {"setTCPConnectionsMaskV6", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpConnectionsMaskV6 = newValue; }, std::numeric_limits<uint8_t>::max()}},
  {"setTCPConnectionsMaskV4Port", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpConnectionsMaskV4Port = newValue; }, std::numeric_limits<uint8_t>::max()}},
  {"setTCPConnectionsOverloadThreshold", {[](dnsdist::configuration::ImmutableConfiguration& config, uint64_t newValue) { config.d_tcpConnectionsOverloadThreshold = newValue; }, 100}},
};

static const std::map<std::string, DoubleImmutableConfigurationItems> s_doubleImmutableConfigItems{
  {"setConsistentHashingBalancingFactor", {[](dnsdist::configuration::ImmutableConfiguration& config, double newValue) { config.d_consistentHashBalancingFactor = newValue; }, 1.0}},
  {"setWeightedBalancingFactor", {[](dnsdist::configuration::ImmutableConfiguration& config, double newValue) { config.d_weightedBalancingFactor = newValue; }, 1.0}},
};
// clang-format on

void setupConfigurationItems(LuaContext& luaCtx)
{
  for (const auto& item : s_booleanConfigItems) {
    luaCtx.writeFunction(item.first, [&item = item.second](bool value) {
      setLuaSideEffect();
      dnsdist::configuration::updateRuntimeConfiguration([value, &item](dnsdist::configuration::RuntimeConfiguration& config) {
        item.mutator(config, value);
      });
    });
  }

  for (const auto& item : s_unsignedIntegerConfigItems) {
    luaCtx.writeFunction(item.first, [&name = item.first, &item = item.second](uint64_t value) {
      setLuaSideEffect();
      checkParameterBound(name, value, item.maximumValue);
      dnsdist::configuration::updateRuntimeConfiguration([value, &item](dnsdist::configuration::RuntimeConfiguration& config) {
        item.mutator(config, value);
      });
    });
  }

  for (const auto& item : s_stringConfigItems) {
    luaCtx.writeFunction(item.first, [&item = item.second](const std::string& value) {
      setLuaSideEffect();
      dnsdist::configuration::updateRuntimeConfiguration([value, &item](dnsdist::configuration::RuntimeConfiguration& config) {
        item.mutator(config, value);
      });
    });
  }

  for (const auto& item : s_booleanImmutableConfigItems) {
    luaCtx.writeFunction(item.first, [&name = item.first, &item = item.second](bool value) {
      try {
        dnsdist::configuration::updateImmutableConfiguration([value, &item](dnsdist::configuration::ImmutableConfiguration& config) {
          item.mutator(config, value);
        });
      }
      catch (const std::exception& exp) {
        g_outputBuffer = name + " cannot be used at runtime!\n";
        errlog("%s cannot be used at runtime!", name);
      }
    });
  }

  for (const auto& item : s_unsignedIntegerImmutableConfigItems) {
    luaCtx.writeFunction(item.first, [&name = item.first, &item = item.second](uint64_t value) {
      checkParameterBound(name, value, item.maximumValue);
      try {
        dnsdist::configuration::updateImmutableConfiguration([value, &item](dnsdist::configuration::ImmutableConfiguration& config) {
          item.mutator(config, value);
        });
      }
      catch (const std::exception& exp) {
        g_outputBuffer = name + " cannot be used at runtime!\n";
        errlog("%s cannot be used at runtime!", name);
      }
    });
  }
  for (const auto& item : s_doubleImmutableConfigItems) {
    luaCtx.writeFunction(item.first, [&name = item.first, &item = item.second](double value) {
      if (value != 0 && value < item.minimumValue) {
        g_outputBuffer = "Invalid value passed to " + name + "()!\n";
        errlog("Invalid value passed to %s()!", name);
        return;
      }

      try {
        dnsdist::configuration::updateImmutableConfiguration([value, &item](dnsdist::configuration::ImmutableConfiguration& config) {
          item.mutator(config, value);
        });
      }
      catch (const std::exception& exp) {
        g_outputBuffer = name + " cannot be used at runtime!\n";
        errlog("%s cannot be used at runtime!", name);
      }
      setLuaSideEffect();
    });
  }
}
}
