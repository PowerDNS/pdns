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

#include <unordered_map>

#include "rec-snmp.hh"
#include "rec_channel.hh"

#include "logger.hh"
#include "logging.hh"

#ifdef HAVE_NET_SNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/definitions.h>
#include <net-snmp/types.h>
#include <net-snmp/utilities.h>
#include <net-snmp/config_api.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#undef INET6 /* SRSLY? */

#define RECURSOR_OID 1, 3, 6, 1, 4, 1, 43315, 2
#define RECURSOR_STATS_OID RECURSOR_OID, 1
#define RECURSOR_TRAPS_OID RECURSOR_OID, 10, 0
#define RECURSOR_TRAP_OBJECTS_OID RECURSOR_OID, 11

using oid10 = std::array<oid, 10>;
using oid11 = std::array<oid, 11>;

static const oid11 trapReasonOID = {RECURSOR_TRAP_OBJECTS_OID, 1, 0};
static const oid11 customTrapOID = {RECURSOR_TRAPS_OID, 1};

static const oid10 questionsOID = {RECURSOR_STATS_OID, 1};
static const oid10 ipv6QuestionsOID = {RECURSOR_STATS_OID, 2};
static const oid10 tcpQuestionsOID = {RECURSOR_STATS_OID, 3};
static const oid10 cacheHitsOID = {RECURSOR_STATS_OID, 4};
static const oid10 cacheMissesOID = {RECURSOR_STATS_OID, 5};
static const oid10 cacheEntriesOID = {RECURSOR_STATS_OID, 6};
static const oid10 cacheBytesOID = {RECURSOR_STATS_OID, 7};
static const oid10 packetcacheHitsOID = {RECURSOR_STATS_OID, 8};
static const oid10 packetcacheMissesOID = {RECURSOR_STATS_OID, 9};
static const oid10 packetcacheEntriesOID = {RECURSOR_STATS_OID, 10};
static const oid10 packetcacheBytesOID = {RECURSOR_STATS_OID, 11};
static const oid10 mallocBytesOID = {RECURSOR_STATS_OID, 12};
static const oid10 servfailAnswersOID = {RECURSOR_STATS_OID, 13};
static const oid10 nxdomainAnswersOID = {RECURSOR_STATS_OID, 14};
static const oid10 noerrorAnswersOID = {RECURSOR_STATS_OID, 15};
static const oid10 unauthorizedUdpOID = {RECURSOR_STATS_OID, 16};
static const oid10 unauthorizedTcpOID = {RECURSOR_STATS_OID, 17};
static const oid10 tcpClientOverflowOID = {RECURSOR_STATS_OID, 18};
static const oid10 clientParseErrorsOID = {RECURSOR_STATS_OID, 19};
static const oid10 serverParseErrorsOID = {RECURSOR_STATS_OID, 20};
static const oid10 tooOldDropsOID = {RECURSOR_STATS_OID, 21};
static const oid10 answers01OID = {RECURSOR_STATS_OID, 22};
static const oid10 answers110OID = {RECURSOR_STATS_OID, 23};
static const oid10 answers10100OID = {RECURSOR_STATS_OID, 24};
static const oid10 answers1001000OID = {RECURSOR_STATS_OID, 25};
static const oid10 answersSlowOID = {RECURSOR_STATS_OID, 26};
static const oid10 auth4Answers01OID = {RECURSOR_STATS_OID, 27};
static const oid10 auth4Answers110OID = {RECURSOR_STATS_OID, 28};
static const oid10 auth4Answers10100OID = {RECURSOR_STATS_OID, 29};
static const oid10 auth4Answers1001000OID = {RECURSOR_STATS_OID, 30};
static const oid10 auth4AnswersslowOID = {RECURSOR_STATS_OID, 31};
static const oid10 auth6Answers01OID = {RECURSOR_STATS_OID, 32};
static const oid10 auth6Answers110OID = {RECURSOR_STATS_OID, 33};
static const oid10 auth6Answers10100OID = {RECURSOR_STATS_OID, 34};
static const oid10 auth6Answers1001000OID = {RECURSOR_STATS_OID, 35};
static const oid10 auth6AnswersSlowOID = {RECURSOR_STATS_OID, 36};
static const oid10 qaLatencyOID = {RECURSOR_STATS_OID, 37};
static const oid10 unexpectedPacketsOID = {RECURSOR_STATS_OID, 38};
static const oid10 caseMismatchesOID = {RECURSOR_STATS_OID, 39};
static const oid10 spoofPreventsOID = {RECURSOR_STATS_OID, 40};
static const oid10 nssetInvalidationsOID = {RECURSOR_STATS_OID, 41};
static const oid10 resourceLimitsOID = {RECURSOR_STATS_OID, 42};
static const oid10 overCapacityDropsOID = {RECURSOR_STATS_OID, 43};
static const oid10 policyDropsOID = {RECURSOR_STATS_OID, 44};
static const oid10 noPacketErrorOID = {RECURSOR_STATS_OID, 45};
static const oid10 dlgOnlyDropsOID = {RECURSOR_STATS_OID, 46};
static const oid10 ignoredPacketsOID = {RECURSOR_STATS_OID, 47};
static const oid10 maxMthreadStackOID = {RECURSOR_STATS_OID, 48};
static const oid10 negcacheEntriesOID = {RECURSOR_STATS_OID, 49};
static const oid10 throttleEntriesOID = {RECURSOR_STATS_OID, 50};
static const oid10 nsspeedsEntriesOID = {RECURSOR_STATS_OID, 51};
static const oid10 failedHostEntriesOID = {RECURSOR_STATS_OID, 52};
static const oid10 concurrentQueriesOID = {RECURSOR_STATS_OID, 53};
static const oid10 securityStatusOID = {RECURSOR_STATS_OID, 54};
static const oid10 outgoingTimeoutsOID = {RECURSOR_STATS_OID, 55};
static const oid10 outgoing4TimeoutsOID = {RECURSOR_STATS_OID, 56};
static const oid10 outgoing6TimeoutsOID = {RECURSOR_STATS_OID, 57};
static const oid10 tcpOutqueriesOID = {RECURSOR_STATS_OID, 58};
static const oid10 allOutqueriesOID = {RECURSOR_STATS_OID, 59};
static const oid10 ipv6OutqueriesOID = {RECURSOR_STATS_OID, 60};
static const oid10 throttledOutqueriesOID = {RECURSOR_STATS_OID, 61};
static const oid10 dontOutqueriesOID = {RECURSOR_STATS_OID, 62};
static const oid10 unreachablesOID = {RECURSOR_STATS_OID, 63};
static const oid10 chainResendsOID = {RECURSOR_STATS_OID, 64};
static const oid10 tcpClientsOID = {RECURSOR_STATS_OID, 65};
#ifdef __linux__
static const oid10 udpRecvbufErrorsOID = {RECURSOR_STATS_OID, 66};
static const oid10 udpSndbufErrorsOID = {RECURSOR_STATS_OID, 67};
static const oid10 udpNoportErrorsOID = {RECURSOR_STATS_OID, 68};
static const oid10 udpinErrorsOID = {RECURSOR_STATS_OID, 69};
#endif /* __linux__ */
static const oid10 ednsPingMatchesOID = {RECURSOR_STATS_OID, 70};
static const oid10 ednsPingMismatchesOID = {RECURSOR_STATS_OID, 71};
static const oid10 dnssecQueriesOID = {RECURSOR_STATS_OID, 72};
static const oid10 nopingOutqueriesOID = {RECURSOR_STATS_OID, 73};
static const oid10 noednsOutqueriesOID = {RECURSOR_STATS_OID, 74};
static const oid10 uptimeOID = {RECURSOR_STATS_OID, 75};
static const oid10 realMemoryUsageOID = {RECURSOR_STATS_OID, 76};
static const oid10 fdUsageOID = {RECURSOR_STATS_OID, 77};
static const oid10 userMsecOID = {RECURSOR_STATS_OID, 78};
static const oid10 sysMsecOID = {RECURSOR_STATS_OID, 79};
static const oid10 dnssecValidationsOID = {RECURSOR_STATS_OID, 80};
static const oid10 dnssecResultInsecureOID = {RECURSOR_STATS_OID, 81};
static const oid10 dnssecResultSecureOID = {RECURSOR_STATS_OID, 82};
static const oid10 dnssecResultBogusOID = {RECURSOR_STATS_OID, 83};
static const oid10 dnssecResultIndeterminateOID = {RECURSOR_STATS_OID, 84};
static const oid10 dnssecResultNtaOID = {RECURSOR_STATS_OID, 85};
static const oid10 policyResultNoactionOID = {RECURSOR_STATS_OID, 86};
static const oid10 policyResultDropOID = {RECURSOR_STATS_OID, 87};
static const oid10 policyResultNxdomainOID = {RECURSOR_STATS_OID, 88};
static const oid10 policyResultNodataOID = {RECURSOR_STATS_OID, 89};
static const oid10 policyResultTruncateOID = {RECURSOR_STATS_OID, 90};
static const oid10 policyResultCustomOID = {RECURSOR_STATS_OID, 91};
static const oid10 queryPipeFullDropsOID = {RECURSOR_STATS_OID, 92};
static const oid10 truncatedDropsOID = {RECURSOR_STATS_OID, 93};
static const oid10 emptyQueriesOID = {RECURSOR_STATS_OID, 94};
static const oid10 dnssecAuthenticDataQueriesOID = {RECURSOR_STATS_OID, 95};
static const oid10 dnssecCheckDisabledQueriesOID = {RECURSOR_STATS_OID, 96};
static const oid10 variableResponsesOID = {RECURSOR_STATS_OID, 97};
static const oid10 specialMemoryUsageOID = {RECURSOR_STATS_OID, 98};
static const oid10 rebalancedQueriesOID = {RECURSOR_STATS_OID, 99};
static const oid10 qnameMinFallbackSuccessOID = {RECURSOR_STATS_OID, 100};
static const oid10 proxyProtocolInvalidOID = {RECURSOR_STATS_OID, 101};
static const oid10 recordCacheContendedOID = {RECURSOR_STATS_OID, 102};
static const oid10 recordCacheAcquiredOID = {RECURSOR_STATS_OID, 103};
static const oid10 nodLookupsDroppedOversizeOID = {RECURSOR_STATS_OID, 104};
static const oid10 taskQueuePushedOID = {RECURSOR_STATS_OID, 105};
static const oid10 taskQueueExpiredOID = {RECURSOR_STATS_OID, 106};
static const oid10 taskQueueSizeOID = {RECURSOR_STATS_OID, 107};
static const oid10 aggressiveNSECCacheEntriesOID = {RECURSOR_STATS_OID, 108};
static const oid10 aggressiveNSECCacheNSECHitsOID = {RECURSOR_STATS_OID, 109};
static const oid10 aggressiveNSECCacheNSEC3HitsOID = {RECURSOR_STATS_OID, 110};
static const oid10 aggressiveNSECCacheNSECWCHitsOID = {RECURSOR_STATS_OID, 111};
static const oid10 aggressiveNSECCacheNSEC3WCHitsOID = {RECURSOR_STATS_OID, 112};
static const oid10 dotOutqueriesOID = {RECURSOR_STATS_OID, 113};
static const oid10 dns64PrefixAnswers = {RECURSOR_STATS_OID, 114};
static const oid10 almostExpiredPushed = {RECURSOR_STATS_OID, 115};
static const oid10 almostExpiredRun = {RECURSOR_STATS_OID, 116};
static const oid10 almostExpiredExceptions = {RECURSOR_STATS_OID, 117};
#ifdef __linux__
static const oid10 udpInCsumErrorsOID = {RECURSOR_STATS_OID, 118};
static const oid10 udp6RecvbufErrorsOID = {RECURSOR_STATS_OID, 119};
static const oid10 udp6SndbufErrorsOID = {RECURSOR_STATS_OID, 120};
static const oid10 udp6NoportErrorsOID = {RECURSOR_STATS_OID, 121};
static const oid10 udp6InErrorsOID = {RECURSOR_STATS_OID, 122};
static const oid10 udp6InCsumErrorsOID = {RECURSOR_STATS_OID, 123};
#endif /* __linux__ */
static const oid10 sourceDisallowedNotifyOID = {RECURSOR_STATS_OID, 124};
static const oid10 zoneDisallowedNotifyOID = {RECURSOR_STATS_OID, 125};
static const oid10 nonResolvingNameserverEntriesOID = {RECURSOR_STATS_OID, 126};
static const oid10 maintenanceUSecOID = {RECURSOR_STATS_OID, 127};
static const oid10 maintenanceCallsOID = {RECURSOR_STATS_OID, 128};

static const oid10 rcode0AnswersOID = {RECURSOR_STATS_OID, 129};
static const oid10 rcode1AnswersOID = {RECURSOR_STATS_OID, 130};
static const oid10 rcode2AnswersOID = {RECURSOR_STATS_OID, 131};
static const oid10 rcode3AnswersOID = {RECURSOR_STATS_OID, 132};
static const oid10 rcode4AnswersOID = {RECURSOR_STATS_OID, 133};
static const oid10 rcode5AnswersOID = {RECURSOR_STATS_OID, 134};
static const oid10 rcode6AnswersOID = {RECURSOR_STATS_OID, 135};
static const oid10 rcode7AnswersOID = {RECURSOR_STATS_OID, 136};
static const oid10 rcode8AnswersOID = {RECURSOR_STATS_OID, 137};
static const oid10 rcode9AnswersOID = {RECURSOR_STATS_OID, 138};
static const oid10 rcode10AnswersOID = {RECURSOR_STATS_OID, 139};
static const oid10 rcode11AnswersOID = {RECURSOR_STATS_OID, 140};
static const oid10 rcode12AnswersOID = {RECURSOR_STATS_OID, 141};
static const oid10 rcode13AnswersOID = {RECURSOR_STATS_OID, 142};
static const oid10 rcode14AnswersOID = {RECURSOR_STATS_OID, 143};
static const oid10 rcode15AnswersOID = {RECURSOR_STATS_OID, 144};

static const oid10 packetCacheContendedOID = {RECURSOR_STATS_OID, 145};
static const oid10 packetCacheAcquiredOID = {RECURSOR_STATS_OID, 146};
static const oid10 nodEventsOID = {RECURSOR_STATS_OID, 147};
static const oid10 udrEventsOID = {RECURSOR_STATS_OID, 148};
static const oid10 maxChainLengthOID = {RECURSOR_STATS_OID, 149};
static const oid10 maxChainWeightOID = {RECURSOR_STATS_OID, 150};
static const oid10 chainLimitsOID = {RECURSOR_STATS_OID, 151};
static const oid10 tcpOverflowOID = {RECURSOR_STATS_OID, 152};
static const oid10 ecsMissingOID = {RECURSOR_STATS_OID, 153};

static std::unordered_map<oid, std::string> s_statsMap;

/* We are never called for a GETNEXT if it's registered as a
   "instance", as it's "magically" handled for us.  */
/* a instance handler also only hands us one request at a time, so
   we don't need to loop over a list of requests; we'll only get one. */

static int handleCounter64Stats(netsnmp_mib_handler* /* handler */,
                                netsnmp_handler_registration* reginfo,
                                netsnmp_agent_request_info* reqinfo,
                                netsnmp_request_info* requests)
{
  if (reqinfo->mode != MODE_GET) {
    return SNMP_ERR_GENERR;
  }

  if (reginfo->rootoid_len != OID_LENGTH(questionsOID) + 1) {
    return SNMP_ERR_GENERR;
  }

  const auto& iter = s_statsMap.find(reginfo->rootoid[reginfo->rootoid_len - 2]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic) it's the API
  if (iter == s_statsMap.end()) {
    return SNMP_ERR_GENERR;
  }

  auto value = getStatByName(iter->second);
  if (value) {
    return RecursorSNMPAgent::setCounter64Value(requests, *value);
  }
  return RecursorSNMPAgent::setCounter64Value(requests, 0);
}

static int handleDisabledCounter64Stats(netsnmp_mib_handler* /* handler */,
                                        netsnmp_handler_registration* reginfo,
                                        netsnmp_agent_request_info* reqinfo,
                                        netsnmp_request_info* requests)
{
  if (reqinfo->mode != MODE_GET) {
    return SNMP_ERR_GENERR;
  }

  if (reginfo->rootoid_len != OID_LENGTH(questionsOID) + 1) {
    return SNMP_ERR_GENERR;
  }

  return RecursorSNMPAgent::setCounter64Value(requests, 0);
}

static void registerCounter64Stat(const std::string& name, const oid10& statOID)
{
  if (statOID.size() != OID_LENGTH(questionsOID)) {
    SLOG(g_log << Logger::Error << "Invalid OID for SNMP Counter64 statistic " << name << endl,
         g_slog->withName("snmp")->info(Logr::Error, "Invalid OID for SNMP Counter64 statistic", "name", Logging::Loggable(name)));
    return;
  }

  if (s_statsMap.find(statOID.at(statOID.size() - 1)) != s_statsMap.end()) {
    SLOG(g_log << Logger::Error << "OID for SNMP Counter64 statistic " << name << " has already been registered" << endl,
         g_slog->withName("snmp")->info(Logr::Error, "OID for SNMP Counter64 statistic has already been registered", "name", Logging::Loggable(name)));
    return;
  }

  s_statsMap[statOID.at(statOID.size() - 1)] = name;
  netsnmp_register_scalar(netsnmp_create_handler_registration(name.c_str(),
                                                              isStatDisabled(StatComponent::SNMP, name) ? handleDisabledCounter64Stats : handleCounter64Stats,
                                                              statOID.data(),
                                                              statOID.size(),
                                                              HANDLER_CAN_RONLY));
}

#endif /* HAVE_NET_SNMP */

std::shared_ptr<RecursorSNMPAgent> g_snmpAgent{nullptr};

bool RecursorSNMPAgent::sendCustomTrap([[maybe_unused]] const std::string& reason)
{
#ifdef HAVE_NET_SNMP
  netsnmp_variable_list* varList = nullptr;

  addSNMPTrapOID(&varList,
                 customTrapOID.data(),
                 customTrapOID.size() * sizeof(oid));

  snmp_varlist_add_variable(&varList,
                            trapReasonOID.data(),
                            trapReasonOID.size(),
                            ASN_OCTET_STR,
                            reason.c_str(),
                            reason.size());

  return sendTrap(d_sender, varList);
#endif /* HAVE_NET_SNMP */
  return true;
}

RecursorSNMPAgent::RecursorSNMPAgent(const std::string& name, const std::string& daemonSocket) :
  SNMPAgent(name, daemonSocket)
{
#ifdef HAVE_NET_SNMP
  registerCounter64Stat("questions", questionsOID);
  registerCounter64Stat("ipv6-questions", ipv6QuestionsOID);
  registerCounter64Stat("tcp-questions", tcpQuestionsOID);
  registerCounter64Stat("cache-hits", cacheHitsOID);
  registerCounter64Stat("cache-misses", cacheMissesOID);
  registerCounter64Stat("cache-entries", cacheEntriesOID);
  registerCounter64Stat("cache-bytes", cacheBytesOID);
  registerCounter64Stat("packetcache-hits", packetcacheHitsOID);
  registerCounter64Stat("packetcache-misses", packetcacheMissesOID);
  registerCounter64Stat("packetcache-entries", packetcacheEntriesOID);
  registerCounter64Stat("packetcache-bytes", packetcacheBytesOID);
  registerCounter64Stat("malloc-bytes", mallocBytesOID);
  registerCounter64Stat("servfail-answers", servfailAnswersOID);
  registerCounter64Stat("nxdomain-answers", nxdomainAnswersOID);
  registerCounter64Stat("noerror-answers", noerrorAnswersOID);
  registerCounter64Stat("unauthorized-udp", unauthorizedUdpOID);
  registerCounter64Stat("unauthorized-tcp", unauthorizedTcpOID);
  registerCounter64Stat("source-disallowed-notify", sourceDisallowedNotifyOID);
  registerCounter64Stat("zone-disallowed-notify", zoneDisallowedNotifyOID);
  registerCounter64Stat("tcp-client-overflow", tcpClientOverflowOID);
  registerCounter64Stat("client-parse-errors", clientParseErrorsOID);
  registerCounter64Stat("server-parse-errors", serverParseErrorsOID);
  registerCounter64Stat("too-old-drops", tooOldDropsOID);
  registerCounter64Stat("query-pipe-full-drops", queryPipeFullDropsOID);
  registerCounter64Stat("truncated-drops", truncatedDropsOID);
  registerCounter64Stat("empty-queries", emptyQueriesOID);
  registerCounter64Stat("variable-responses", variableResponsesOID);
  registerCounter64Stat("answers0-1", answers01OID);
  registerCounter64Stat("answers1-10", answers110OID);
  registerCounter64Stat("answers10-100", answers10100OID);
  registerCounter64Stat("answers100-1000", answers1001000OID);
  registerCounter64Stat("answers-slow", answersSlowOID);
  registerCounter64Stat("auth4-answers0-1", auth4Answers01OID);
  registerCounter64Stat("auth4-answers1-10", auth4Answers110OID);
  registerCounter64Stat("auth4-answers10-100", auth4Answers10100OID);
  registerCounter64Stat("auth4-answers100-1000", auth4Answers1001000OID);
  registerCounter64Stat("auth4-answers-slow", auth4AnswersslowOID);
  registerCounter64Stat("auth6-answers0-1", auth6Answers01OID);
  registerCounter64Stat("auth6-answers1-10", auth6Answers110OID);
  registerCounter64Stat("auth6-answers10-100", auth6Answers10100OID);
  registerCounter64Stat("auth6-answers100-1000", auth6Answers1001000OID);
  registerCounter64Stat("auth6-answers-slow", auth6AnswersSlowOID);
  registerCounter64Stat("qa-latency", qaLatencyOID);
  registerCounter64Stat("unexpected-packets", unexpectedPacketsOID);
  registerCounter64Stat("case-mismatches", caseMismatchesOID);
  registerCounter64Stat("spoof-prevents", spoofPreventsOID);
  registerCounter64Stat("nsset-invalidations", nssetInvalidationsOID);
  registerCounter64Stat("resource-limits", resourceLimitsOID);
  registerCounter64Stat("over-capacity-drops", overCapacityDropsOID);
  registerCounter64Stat("policy-drops", policyDropsOID);
  registerCounter64Stat("no-packet-error", noPacketErrorOID);
  registerCounter64Stat("dlg-only-drops", dlgOnlyDropsOID);
  registerCounter64Stat("ignored-packets", ignoredPacketsOID);
  registerCounter64Stat("max-mthread-stack", maxMthreadStackOID);
  registerCounter64Stat("negcache-entries", negcacheEntriesOID);
  registerCounter64Stat("throttle-entries", throttleEntriesOID);
  registerCounter64Stat("nsspeeds-entries", nsspeedsEntriesOID);
  registerCounter64Stat("failed-host-entries", failedHostEntriesOID);
  registerCounter64Stat("concurrent-queries", concurrentQueriesOID);
  registerCounter64Stat("security-status", securityStatusOID);
  registerCounter64Stat("outgoing-timeouts", outgoingTimeoutsOID);
  registerCounter64Stat("outgoing4-timeouts", outgoing4TimeoutsOID);
  registerCounter64Stat("outgoing6-timeouts", outgoing6TimeoutsOID);
  registerCounter64Stat("tcp-outqueries", tcpOutqueriesOID);
  registerCounter64Stat("all-outqueries", allOutqueriesOID);
  registerCounter64Stat("ipv6-outqueries", ipv6OutqueriesOID);
  registerCounter64Stat("throttled-outqueries", throttledOutqueriesOID);
  registerCounter64Stat("dont-outqueries", dontOutqueriesOID);
  registerCounter64Stat("qname-min-fallback-success", qnameMinFallbackSuccessOID);
  registerCounter64Stat("unreachables", unreachablesOID);
  registerCounter64Stat("chain-resends", chainResendsOID);
  registerCounter64Stat("tcp-clients", tcpClientsOID);
#ifdef __linux__
  registerCounter64Stat("udp-recvbuf-errors", udpRecvbufErrorsOID);
  registerCounter64Stat("udp-sndbuf-errors", udpSndbufErrorsOID);
  registerCounter64Stat("udp-noport-errors", udpNoportErrorsOID);
  registerCounter64Stat("udp-in-errors", udpinErrorsOID);
  registerCounter64Stat("udp-in-csums-errors", udpInCsumErrorsOID);
  registerCounter64Stat("udp6-recvbuf-errors", udp6RecvbufErrorsOID);
  registerCounter64Stat("udp6-sndbuf-errors", udp6SndbufErrorsOID);
  registerCounter64Stat("udp6-noport-errors", udp6NoportErrorsOID);
  registerCounter64Stat("udp6-in-errors", udp6InErrorsOID);
  registerCounter64Stat("udp6-in-csums-errors", udp6InCsumErrorsOID);
#endif /* __linux__ */
  registerCounter64Stat("edns-ping-matches", ednsPingMatchesOID);
  registerCounter64Stat("edns-ping-mismatches", ednsPingMismatchesOID);
  registerCounter64Stat("dnssec-queries", dnssecQueriesOID);
  registerCounter64Stat("dnssec-authentic-data-queries", dnssecAuthenticDataQueriesOID);
  registerCounter64Stat("dnssec-check-disabled-queries", dnssecCheckDisabledQueriesOID);
  registerCounter64Stat("noping-outqueries", nopingOutqueriesOID);
  registerCounter64Stat("noedns-outqueries", noednsOutqueriesOID);
  registerCounter64Stat("uptime", uptimeOID);
  registerCounter64Stat("real-memory-usage", realMemoryUsageOID);
  registerCounter64Stat("fd-usage", fdUsageOID);
  registerCounter64Stat("user-msec", userMsecOID);
  registerCounter64Stat("sys-msec", sysMsecOID);
  registerCounter64Stat("dnssec-validations", dnssecValidationsOID);
  registerCounter64Stat("dnssec-result-insecure", dnssecResultInsecureOID);
  registerCounter64Stat("dnssec-result-secure", dnssecResultSecureOID);
  registerCounter64Stat("dnssec-result-bogus", dnssecResultBogusOID);
  registerCounter64Stat("dnssec-result-indeterminate", dnssecResultIndeterminateOID);
  registerCounter64Stat("dnssec-result-nta", dnssecResultNtaOID);
  registerCounter64Stat("policy-result-noaction", policyResultNoactionOID);
  registerCounter64Stat("policy-result-drop", policyResultDropOID);
  registerCounter64Stat("policy-result-nxdomain", policyResultNxdomainOID);
  registerCounter64Stat("policy-result-nodata", policyResultNodataOID);
  registerCounter64Stat("policy-result-truncate", policyResultTruncateOID);
  registerCounter64Stat("policy-result-custom", policyResultCustomOID);
  registerCounter64Stat("special-memory-usage", specialMemoryUsageOID);
  registerCounter64Stat("rebalanced-queries", rebalancedQueriesOID);
  registerCounter64Stat("proxy-protocol-invalid", proxyProtocolInvalidOID);
  registerCounter64Stat("record-cache-contended", recordCacheContendedOID);
  registerCounter64Stat("record-cache-acquired", recordCacheAcquiredOID);
  registerCounter64Stat("nod-lookups-dropped-oversize", nodLookupsDroppedOversizeOID);
  registerCounter64Stat("tasqueue-pushed", taskQueuePushedOID);
  registerCounter64Stat("taskqueue-expired", taskQueueExpiredOID);
  registerCounter64Stat("taskqueue-size", taskQueueSizeOID);
  registerCounter64Stat("aggressive-nsec-cache-entries", aggressiveNSECCacheEntriesOID);
  registerCounter64Stat("aggressive-nsec-cache-nsec-hits", aggressiveNSECCacheNSECHitsOID);
  registerCounter64Stat("aggressive-nsec-cache-nsec3-hits", aggressiveNSECCacheNSEC3HitsOID);
  registerCounter64Stat("aggressive-nsec-cache-nsec-wc-hits", aggressiveNSECCacheNSECWCHitsOID);
  registerCounter64Stat("aggressive-nsec-cache-nsec-wc3-hits", aggressiveNSECCacheNSEC3WCHitsOID);
  registerCounter64Stat("dot-outqueries", dotOutqueriesOID);
  registerCounter64Stat("dns64-prefix-answers", dns64PrefixAnswers);
  registerCounter64Stat("almost-expired-pushed", almostExpiredPushed);
  registerCounter64Stat("almost-expired-run", almostExpiredRun);
  registerCounter64Stat("almost-expired-exceptions", almostExpiredExceptions);
  registerCounter64Stat("non-resolving-nameserver-entries", nonResolvingNameserverEntriesOID);
  registerCounter64Stat("maintenance-usec", maintenanceUSecOID);
  registerCounter64Stat("maintenance-calls", maintenanceCallsOID);
  registerCounter64Stat("chain-limits", chainLimitsOID);

#define RCODE(num) registerCounter64Stat("auth-" + RCode::to_short_s(num) + "-answers", rcode##num##AnswersOID) // NOLINT(cppcoreguidelines-macro-usage)
  RCODE(0);
  RCODE(1);
  RCODE(2);
  RCODE(3);
  RCODE(4);
  RCODE(5);
  RCODE(6);
  RCODE(7);
  RCODE(8);
  RCODE(9);
  RCODE(10);
  RCODE(11);
  RCODE(12);
  RCODE(13);
  RCODE(14);
  RCODE(15);

  registerCounter64Stat("packetcache-contended", packetCacheContendedOID);
  registerCounter64Stat("packetcache-acquired", packetCacheAcquiredOID);
  registerCounter64Stat("nod-events", nodEventsOID);
  registerCounter64Stat("udr-events", udrEventsOID);
  registerCounter64Stat("max-chain-length", maxChainLengthOID);
  registerCounter64Stat("max-chain-weight", maxChainWeightOID);
  registerCounter64Stat("tcp-overflow", tcpOverflowOID);
  registerCounter64Stat("ecs-missing", ecsMissingOID);

#endif /* HAVE_NET_SNMP */
}
