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

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>

#include "config.h"
#include "credentials.hh"
#include "dnsdist-actions.hh"
#include "dnsdist-carbon.hh"
#include "dnsdist-query-count.hh"
#include "dnsdist-rule-chains.hh"
#include "iputils.hh"

class ServerPolicy;
struct ServerPool;
struct DownstreamState;
struct ClientState;

using servers_t = std::vector<std::shared_ptr<DownstreamState>>;

namespace dnsdist::configuration
{
/* This part of the configuration is compile-time only */
/* when we add EDNS to a query, we don't want to advertise
   a large buffer size */
static constexpr size_t s_EdnsUDPPayloadSize{512};
static constexpr uint16_t s_defaultPayloadSizeSelfGenAnswers = 1232;
static constexpr uint16_t s_udpIncomingBufferSize{1500}; // don't accept UDP queries larger than this value
static_assert(s_defaultPayloadSizeSelfGenAnswers < s_udpIncomingBufferSize, "The UDP responder's payload size should be smaller or equal to our incoming buffer size");

/* this part of the configuration can only be updated at configuration
   time, and is immutable once the configuration phase is over */
struct ImmutableConfiguration
{
  std::set<std::string> d_capabilitiesToRetain;
  std::vector<uint32_t> d_tcpFastOpenKey;
  std::vector<std::shared_ptr<ClientState>> d_frontends;
  std::string d_snmpDaemonSocketPath;
#ifdef __linux__
  // On Linux this gives us 128k pending queries (default is 8192 queries),
  // which should be enough to deal with huge spikes
  uint64_t d_maxTCPQueuedConnections{10000};
  size_t d_tcpInternalPipeBufferSize{1048576U};
#else
  uint64_t d_maxTCPQueuedConnections{1000};
  size_t d_tcpInternalPipeBufferSize{0};
#endif
  double d_weightedBalancingFactor{0};
  double d_consistentHashBalancingFactor{0};
  std::optional<uint64_t> d_outgoingDoHWorkers{std::nullopt};
  uint64_t d_consoleMaxConcurrentConnections{0};
  uint64_t d_outgoingDoHMaxIdleTime{300};
  uint64_t d_outgoingTCPMaxIdleTime{300};
  uint64_t d_outgoingDoHCleanupInterval{60};
  uint64_t d_outgoingTCPCleanupInterval{60};
  uint64_t d_outgoingDoHMaxIdlePerBackend{10};
  uint64_t d_outgoingTCPMaxIdlePerBackend{10};
  uint64_t d_maxTCPClientThreads{10};
  uint64_t d_maxTCPConnectionsRatePerClient{0};
  uint64_t d_maxTLSResumedSessionsRatePerClient{0};
  uint64_t d_maxTLSNewSessionsRatePerClient{0};
  uint64_t d_tcpConnectionsRatePerClientInterval{5};
  size_t d_maxTCPConnectionsPerClient{0};
  size_t d_udpVectorSize{1};
  size_t d_ringsCapacity{10000};
  size_t d_ringsNumberOfShards{10};
  size_t d_ringsNbLockTries{5};
  uint32_t d_socketUDPSendBuffer{0};
  uint32_t d_socketUDPRecvBuffer{0};
  uint32_t d_hashPerturbation{0};
  uint32_t d_maxTCPReadIOsPerQuery{50};
  uint32_t d_tcpBanDurationForExceedingMaxReadIOsPerQuery{60};
  uint32_t d_tcpBanDurationForExceedingTCPTLSRate{10};
  uint16_t d_maxUDPOutstanding{std::numeric_limits<uint16_t>::max()};
  uint8_t d_udpTimeout{2};
  uint8_t d_tcpConnectionsOverloadThreshold{90};
  uint8_t d_tcpConnectionsMaskV4{32};
  uint8_t d_tcpConnectionsMaskV6{128};
  uint8_t d_tcpConnectionsMaskV4Port{0};
  bool d_randomizeUDPSocketsToBackend{false};
  bool d_randomizeIDsToBackend{false};
  bool d_ringsRecordQueries{true};
  bool d_ringsRecordResponses{true};
  bool d_snmpEnabled{false};
  bool d_snmpTrapsEnabled{false};
};

/* this part of the configuration can be updated at runtime via
   a RCU-like mechanism */
struct RuntimeConfiguration
{
  rules::RuleChains d_ruleChains;
  servers_t d_backends;
#ifndef DISABLE_CARBON
  std::vector<dnsdist::Carbon::Endpoint> d_carbonEndpoints;
#endif /* DISABLE_CARBON */
  std::unordered_map<std::string, std::shared_ptr<ServerPool>> d_pools;
  std::shared_ptr<const CredentialsHolder> d_webPassword;
  std::shared_ptr<const CredentialsHolder> d_webAPIKey;
  std::optional<std::unordered_map<std::string, std::string>> d_webCustomHeaders;
  std::shared_ptr<ServerPolicy> d_lbPolicy;
  NetmaskGroup d_ACL;
  NetmaskGroup d_proxyProtocolACL;
  NetmaskGroup d_consoleACL;
  NetmaskGroup d_webServerACL;
  std::set<ComboAddress> d_webServerAddresses;
  dnsdist::QueryCount::Configuration d_queryCountConfig;
  ComboAddress d_consoleServerAddress{"127.0.0.1:5199"};
  std::string d_consoleKey;
  std::string d_secPollSuffix{"secpoll.powerdns.com."};
  std::string d_apiConfigDirectory;
  uint64_t d_dynBlocksPurgeInterval{60};
  size_t d_maxTCPQueriesPerConn{0};
  size_t d_maxTCPConnectionDuration{0};
  size_t d_proxyProtocolMaximumSize{512};
  uint32_t d_staleCacheEntriesTTL{0};
  uint32_t d_secPollInterval{3600};
  uint32_t d_consoleOutputMsgMaxSize{10000000};
  uint16_t d_payloadSizeSelfGenAnswers{s_defaultPayloadSizeSelfGenAnswers};
  uint16_t d_tcpRecvTimeout{2};
  uint16_t d_tcpSendTimeout{2};
  /* rfc7871: "11.1. Privacy" */
  uint16_t d_ECSSourcePrefixV4{24};
  uint16_t d_ECSSourcePrefixV6{56};
  uint16_t d_cacheCleaningDelay{60};
  uint16_t d_cacheCleaningPercentage{100};
  uint16_t d_tlsSessionCacheCleanupDelay{60};
  uint16_t d_tlsSessionCacheSessionValidity{600};
  uint16_t d_tlsSessionCacheMaxSessionsPerBackend{20};
  DNSAction::Action d_dynBlockAction{DNSAction::Action::Drop};
  bool d_apiRequiresAuthentication{true};
  bool d_dashboardRequiresAuthentication{true};
  bool d_statsRequireAuthentication{true};
  bool d_truncateTC{false};
  bool d_fixupCase{false};
  bool d_queryCountEnabled{false};
  bool d_ecsOverride{false};
  bool d_verbose{false};
  bool d_verboseHealthChecks{false};
  bool d_apiReadWrite{false};
  bool d_roundrobinFailOnNoServer{false};
  bool d_servFailOnNoPolicy{false};
  bool d_allowEmptyResponse{false};
  bool d_dropEmptyQueries{false};
  bool d_consoleEnabled{false};
  bool d_logConsoleConnections{true};
  bool d_addEDNSToSelfGeneratedResponses{true};
  bool d_applyACLToProxiedClients{false};
};

/* Be careful not to hold on this for too long, it can be invalidated
   by the next call to getCurrentRuntimeConfiguration() from the
   same thread, so better be sure that any function you are not calling
   while holding to this reference does not call getCurrentRuntimeConfiguration()
   itself. When in doubt, better call getCurrentRuntimeConfiguration() twice.
*/
const RuntimeConfiguration& getCurrentRuntimeConfiguration();
/* Get the runtime-immutable configuration */
const ImmutableConfiguration& getImmutableConfiguration();
/* Update the runtime-immutable part of the configuration. This function can only be called
   during configuration time (isConfigurationDone() returns false), and will throw otherwise. */
void updateImmutableConfiguration(const std::function<void(ImmutableConfiguration&)>& mutator);
void updateRuntimeConfiguration(const std::function<void(RuntimeConfiguration&)>& mutator);
/* Whether parsing the configuration is done, meaning the runtime-immutable part of the
   configuration is now sealed */
bool isImmutableConfigurationDone();
void setImmutableConfigurationDone();
}
