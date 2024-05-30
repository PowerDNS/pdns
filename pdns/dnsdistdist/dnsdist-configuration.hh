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
#include <map>
#include <string>

#include "dnsdist-query-count.hh"
#include "iputils.hh"

/* so what could you do:
   drop,
   fake up nxdomain,
   provide actual answer,
   allow & and stop processing,
   continue processing,
   modify header:    (servfail|refused|notimp), set TC=1,
   send to pool */

struct DNSQuestion;
struct DNSResponse;

class DNSAction
{
public:
  enum class Action : uint8_t
  {
    Drop,
    Nxdomain,
    Refused,
    Spoof,
    Allow,
    HeaderModify,
    Pool,
    Delay,
    Truncate,
    ServFail,
    None,
    NoOp,
    NoRecurse,
    SpoofRaw,
    SpoofPacket,
    SetTag,
  };
  static std::string typeToString(const Action& action)
  {
    switch (action) {
    case Action::Drop:
      return "Drop";
    case Action::Nxdomain:
      return "Send NXDomain";
    case Action::Refused:
      return "Send Refused";
    case Action::Spoof:
      return "Spoof an answer";
    case Action::SpoofPacket:
      return "Spoof a raw answer from bytes";
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
    case Action::SetTag:
      return "Set Tag";
    case Action::None:
    case Action::NoOp:
      return "Do nothing";
    case Action::NoRecurse:
      return "Set rd=0";
    }

    return "Unknown";
  }

  virtual Action operator()(DNSQuestion*, std::string* ruleresult) const = 0;
  virtual ~DNSAction() = default;
  virtual std::string toString() const = 0;
  virtual std::map<std::string, double> getStats() const
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
  enum class Action : uint8_t
  {
    Allow,
    Delay,
    Drop,
    HeaderModify,
    ServFail,
    Truncate,
    None
  };
  virtual Action operator()(DNSResponse*, std::string* ruleresult) const = 0;
  virtual ~DNSResponseAction() = default;
  virtual std::string toString() const = 0;
  virtual void reload()
  {
  }
};

namespace dnsdist::configuration
{
/* when we add EDNS to a query, we don't want to advertise
   a large buffer size */
static constexpr size_t s_EdnsUDPPayloadSize{512};
static constexpr uint16_t s_defaultPayloadSizeSelfGenAnswers = 1232;
static constexpr uint16_t s_udpIncomingBufferSize{1500}; // don't accept UDP queries larger than this value
static_assert(s_defaultPayloadSizeSelfGenAnswers < s_udpIncomingBufferSize, "The UDP responder's payload size should be smaller or equal to our incoming buffer size");

struct Configuration
{
  std::set<std::string> d_capabilitiesToRetain;
  std::string d_consoleKey;
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
  uint64_t d_maxTCPClientThreads{0};
  size_t d_maxTCPConnectionsPerClient{0};
  size_t d_udpVectorSize{1};
  uint32_t d_socketUDPSendBuffer{0};
  uint32_t d_socketUDPRecvBuffer{0};
  uint32_t d_hashPerturbation{0};
  uint16_t d_maxUDPOutstanding{std::numeric_limits<uint16_t>::max()};
  uint8_t d_udpTimeout{2};
  bool d_randomizeUDPSocketsToBackend{false};
  bool d_randomizeIDsToBackend{false};
};

struct RuntimeConfiguration
{
  NetmaskGroup d_proxyProtocolACL;
  NetmaskGroup d_consoleACL;
  dnsdist::QueryCount::Configuration d_queryCountConfig;
  std::string d_secPollSuffix{"secpoll.powerdns.com."};
  std::string d_apiConfigDirectory;
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
  bool d_snmpEnabled{false};
  bool d_snmpTrapsEnabled{false};
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
const Configuration& getImmutableConfiguration();
/* Update the runtime-immutable part of the configuration. This function can only be called
   during configuration time (isConfigurationDone() returns false), and will throw otherwise. */
void updateImmutableConfiguration(const std::function<void(Configuration&)>& mutator);
void updateRuntimeConfiguration(const std::function<void(RuntimeConfiguration&)>& mutator);
/* Whether parsing the configuration is done, meaning the runtime-immutable part of the
   configuration is now sealed */
bool isConfigurationDone();
void setConfigurationDone();
}
