
#include <unordered_map>

#include "rec-snmp.hh"
#include "rec_channel.hh"

#include "logger.hh"
#include "logging.hh"

#ifdef HAVE_NET_SNMP

#define RECURSOR_OID 1, 3, 6, 1, 4, 1, 43315, 2
#define RECURSOR_STATS_OID RECURSOR_OID, 1
#define RECURSOR_TRAPS_OID RECURSOR_OID, 10, 0
#define RECURSOR_TRAP_OBJECTS_OID RECURSOR_OID, 11

static const oid trapReasonOID[] = {RECURSOR_TRAP_OBJECTS_OID, 1, 0};
static const oid customTrapOID[] = {RECURSOR_TRAPS_OID, 1};

static const oid questionsOID[] = {RECURSOR_STATS_OID, 1};
static const oid ipv6QuestionsOID[] = {RECURSOR_STATS_OID, 2};
static const oid tcpQuestionsOID[] = {RECURSOR_STATS_OID, 3};
static const oid cacheHitsOID[] = {RECURSOR_STATS_OID, 4};
static const oid cacheMissesOID[] = {RECURSOR_STATS_OID, 5};
static const oid cacheEntriesOID[] = {RECURSOR_STATS_OID, 6};
static const oid cacheBytesOID[] = {RECURSOR_STATS_OID, 7};
static const oid packetcacheHitsOID[] = {RECURSOR_STATS_OID, 8};
static const oid packetcacheMissesOID[] = {RECURSOR_STATS_OID, 9};
static const oid packetcacheEntriesOID[] = {RECURSOR_STATS_OID, 10};
static const oid packetcacheBytesOID[] = {RECURSOR_STATS_OID, 11};
static const oid mallocBytesOID[] = {RECURSOR_STATS_OID, 12};
static const oid servfailAnswersOID[] = {RECURSOR_STATS_OID, 13};
static const oid nxdomainAnswersOID[] = {RECURSOR_STATS_OID, 14};
static const oid noerrorAnswersOID[] = {RECURSOR_STATS_OID, 15};
static const oid unauthorizedUdpOID[] = {RECURSOR_STATS_OID, 16};
static const oid unauthorizedTcpOID[] = {RECURSOR_STATS_OID, 17};
static const oid tcpClientOverflowOID[] = {RECURSOR_STATS_OID, 18};
static const oid clientParseErrorsOID[] = {RECURSOR_STATS_OID, 19};
static const oid serverParseErrorsOID[] = {RECURSOR_STATS_OID, 20};
static const oid tooOldDropsOID[] = {RECURSOR_STATS_OID, 21};
static const oid answers01OID[] = {RECURSOR_STATS_OID, 22};
static const oid answers110OID[] = {RECURSOR_STATS_OID, 23};
static const oid answers10100OID[] = {RECURSOR_STATS_OID, 24};
static const oid answers1001000OID[] = {RECURSOR_STATS_OID, 25};
static const oid answersSlowOID[] = {RECURSOR_STATS_OID, 26};
static const oid auth4Answers01OID[] = {RECURSOR_STATS_OID, 27};
static const oid auth4Answers110OID[] = {RECURSOR_STATS_OID, 28};
static const oid auth4Answers10100OID[] = {RECURSOR_STATS_OID, 29};
static const oid auth4Answers1001000OID[] = {RECURSOR_STATS_OID, 30};
static const oid auth4AnswersslowOID[] = {RECURSOR_STATS_OID, 31};
static const oid auth6Answers01OID[] = {RECURSOR_STATS_OID, 32};
static const oid auth6Answers110OID[] = {RECURSOR_STATS_OID, 33};
static const oid auth6Answers10100OID[] = {RECURSOR_STATS_OID, 34};
static const oid auth6Answers1001000OID[] = {RECURSOR_STATS_OID, 35};
static const oid auth6AnswersSlowOID[] = {RECURSOR_STATS_OID, 36};
static const oid qaLatencyOID[] = {RECURSOR_STATS_OID, 37};
static const oid unexpectedPacketsOID[] = {RECURSOR_STATS_OID, 38};
static const oid caseMismatchesOID[] = {RECURSOR_STATS_OID, 39};
static const oid spoofPreventsOID[] = {RECURSOR_STATS_OID, 40};
static const oid nssetInvalidationsOID[] = {RECURSOR_STATS_OID, 41};
static const oid resourceLimitsOID[] = {RECURSOR_STATS_OID, 42};
static const oid overCapacityDropsOID[] = {RECURSOR_STATS_OID, 43};
static const oid policyDropsOID[] = {RECURSOR_STATS_OID, 44};
static const oid noPacketErrorOID[] = {RECURSOR_STATS_OID, 45};
static const oid dlgOnlyDropsOID[] = {RECURSOR_STATS_OID, 46};
static const oid ignoredPacketsOID[] = {RECURSOR_STATS_OID, 47};
static const oid maxMthreadStackOID[] = {RECURSOR_STATS_OID, 48};
static const oid negcacheEntriesOID[] = {RECURSOR_STATS_OID, 49};
static const oid throttleEntriesOID[] = {RECURSOR_STATS_OID, 50};
static const oid nsspeedsEntriesOID[] = {RECURSOR_STATS_OID, 51};
static const oid failedHostEntriesOID[] = {RECURSOR_STATS_OID, 52};
static const oid concurrentQueriesOID[] = {RECURSOR_STATS_OID, 53};
static const oid securityStatusOID[] = {RECURSOR_STATS_OID, 54};
static const oid outgoingTimeoutsOID[] = {RECURSOR_STATS_OID, 55};
static const oid outgoing4TimeoutsOID[] = {RECURSOR_STATS_OID, 56};
static const oid outgoing6TimeoutsOID[] = {RECURSOR_STATS_OID, 57};
static const oid tcpOutqueriesOID[] = {RECURSOR_STATS_OID, 58};
static const oid allOutqueriesOID[] = {RECURSOR_STATS_OID, 59};
static const oid ipv6OutqueriesOID[] = {RECURSOR_STATS_OID, 60};
static const oid throttledOutqueriesOID[] = {RECURSOR_STATS_OID, 61};
static const oid dontOutqueriesOID[] = {RECURSOR_STATS_OID, 62};
static const oid unreachablesOID[] = {RECURSOR_STATS_OID, 63};
static const oid chainResendsOID[] = {RECURSOR_STATS_OID, 64};
static const oid tcpClientsOID[] = {RECURSOR_STATS_OID, 65};
#ifdef __linux__
static const oid udpRecvbufErrorsOID[] = {RECURSOR_STATS_OID, 66};
static const oid udpSndbufErrorsOID[] = {RECURSOR_STATS_OID, 67};
static const oid udpNoportErrorsOID[] = {RECURSOR_STATS_OID, 68};
static const oid udpinErrorsOID[] = {RECURSOR_STATS_OID, 69};
#endif /* __linux__ */
static const oid ednsPingMatchesOID[] = {RECURSOR_STATS_OID, 70};
static const oid ednsPingMismatchesOID[] = {RECURSOR_STATS_OID, 71};
static const oid dnssecQueriesOID[] = {RECURSOR_STATS_OID, 72};
static const oid nopingOutqueriesOID[] = {RECURSOR_STATS_OID, 73};
static const oid noednsOutqueriesOID[] = {RECURSOR_STATS_OID, 74};
static const oid uptimeOID[] = {RECURSOR_STATS_OID, 75};
static const oid realMemoryUsageOID[] = {RECURSOR_STATS_OID, 76};
static const oid fdUsageOID[] = {RECURSOR_STATS_OID, 77};
static const oid userMsecOID[] = {RECURSOR_STATS_OID, 78};
static const oid sysMsecOID[] = {RECURSOR_STATS_OID, 79};
static const oid dnssecValidationsOID[] = {RECURSOR_STATS_OID, 80};
static const oid dnssecResultInsecureOID[] = {RECURSOR_STATS_OID, 81};
static const oid dnssecResultSecureOID[] = {RECURSOR_STATS_OID, 82};
static const oid dnssecResultBogusOID[] = {RECURSOR_STATS_OID, 83};
static const oid dnssecResultIndeterminateOID[] = {RECURSOR_STATS_OID, 84};
static const oid dnssecResultNtaOID[] = {RECURSOR_STATS_OID, 85};
static const oid policyResultNoactionOID[] = {RECURSOR_STATS_OID, 86};
static const oid policyResultDropOID[] = {RECURSOR_STATS_OID, 87};
static const oid policyResultNxdomainOID[] = {RECURSOR_STATS_OID, 88};
static const oid policyResultNodataOID[] = {RECURSOR_STATS_OID, 89};
static const oid policyResultTruncateOID[] = {RECURSOR_STATS_OID, 90};
static const oid policyResultCustomOID[] = {RECURSOR_STATS_OID, 91};
static const oid queryPipeFullDropsOID[] = {RECURSOR_STATS_OID, 92};
static const oid truncatedDropsOID[] = {RECURSOR_STATS_OID, 93};
static const oid emptyQueriesOID[] = {RECURSOR_STATS_OID, 94};
static const oid dnssecAuthenticDataQueriesOID[] = {RECURSOR_STATS_OID, 95};
static const oid dnssecCheckDisabledQueriesOID[] = {RECURSOR_STATS_OID, 96};
static const oid variableResponsesOID[] = {RECURSOR_STATS_OID, 97};
static const oid specialMemoryUsageOID[] = {RECURSOR_STATS_OID, 98};
static const oid rebalancedQueriesOID[] = {RECURSOR_STATS_OID, 99};
static const oid qnameMinFallbackSuccessOID[] = {RECURSOR_STATS_OID, 100};
static const oid proxyProtocolInvalidOID[] = {RECURSOR_STATS_OID, 101};
static const oid recordCacheContendedOID[] = {RECURSOR_STATS_OID, 102};
static const oid recordCacheAcquiredOID[] = {RECURSOR_STATS_OID, 103};
static const oid nodLookupsDroppedOversizeOID[] = {RECURSOR_STATS_OID, 104};
static const oid taskQueuePushedOID[] = {RECURSOR_STATS_OID, 105};
static const oid taskQueueExpiredOID[] = {RECURSOR_STATS_OID, 106};
static const oid taskQueueSizeOID[] = {RECURSOR_STATS_OID, 107};
static const oid aggressiveNSECCacheEntriesOID[] = {RECURSOR_STATS_OID, 108};
static const oid aggressiveNSECCacheNSECHitsOID[] = {RECURSOR_STATS_OID, 109};
static const oid aggressiveNSECCacheNSEC3HitsOID[] = {RECURSOR_STATS_OID, 110};
static const oid aggressiveNSECCacheNSECWCHitsOID[] = {RECURSOR_STATS_OID, 111};
static const oid aggressiveNSECCacheNSEC3WCHitsOID[] = {RECURSOR_STATS_OID, 112};
static const oid dotOutqueriesOID[] = {RECURSOR_STATS_OID, 113};
static const oid dns64PrefixAnswers[] = {RECURSOR_STATS_OID, 114};
static const oid almostExpiredPushed[] = {RECURSOR_STATS_OID, 115};
static const oid almostExpiredRun[] = {RECURSOR_STATS_OID, 116};
static const oid almostExpiredExceptions[] = {RECURSOR_STATS_OID, 117};
#ifdef __linux__
static const oid udpInCsumErrorsOID[] = {RECURSOR_STATS_OID, 118};
static const oid udp6RecvbufErrorsOID[] = {RECURSOR_STATS_OID, 119};
static const oid udp6SndbufErrorsOID[] = {RECURSOR_STATS_OID, 120};
static const oid udp6NoportErrorsOID[] = {RECURSOR_STATS_OID, 121};
static const oid udp6InErrorsOID[] = {RECURSOR_STATS_OID, 122};
static const oid udp6InCsumErrorsOID[] = {RECURSOR_STATS_OID, 123};
#endif /* __linux__ */
static const oid sourceDisallowedNotifyOID[] = {RECURSOR_STATS_OID, 124};
static const oid zoneDisallowedNotifyOID[] = {RECURSOR_STATS_OID, 125};
static const oid nonResolvingNameserverEntriesOID[] = {RECURSOR_STATS_OID, 126};
static const oid maintenanceUSecOID[] = {RECURSOR_STATS_OID, 127};
static const oid maintenanceCallsOID[] = {RECURSOR_STATS_OID, 128};

static const oid rcode0AnswersOID[] = {RECURSOR_STATS_OID, 129};
static const oid rcode1AnswersOID[] = {RECURSOR_STATS_OID, 130};
static const oid rcode2AnswersOID[] = {RECURSOR_STATS_OID, 131};
static const oid rcode3AnswersOID[] = {RECURSOR_STATS_OID, 132};
static const oid rcode4AnswersOID[] = {RECURSOR_STATS_OID, 133};
static const oid rcode5AnswersOID[] = {RECURSOR_STATS_OID, 134};
static const oid rcode6AnswersOID[] = {RECURSOR_STATS_OID, 135};
static const oid rcode7AnswersOID[] = {RECURSOR_STATS_OID, 136};
static const oid rcode8AnswersOID[] = {RECURSOR_STATS_OID, 137};
static const oid rcode9AnswersOID[] = {RECURSOR_STATS_OID, 138};
static const oid rcode10AnswersOID[] = {RECURSOR_STATS_OID, 139};
static const oid rcode11AnswersOID[] = {RECURSOR_STATS_OID, 140};
static const oid rcode12AnswersOID[] = {RECURSOR_STATS_OID, 141};
static const oid rcode13AnswersOID[] = {RECURSOR_STATS_OID, 142};
static const oid rcode14AnswersOID[] = {RECURSOR_STATS_OID, 143};
static const oid rcode15AnswersOID[] = {RECURSOR_STATS_OID, 144};

static const oid packetCacheContendedOID[] = {RECURSOR_STATS_OID, 145};
static const oid packetCacheAcquiredOID[] = {RECURSOR_STATS_OID, 146};
static const oid nodEventsOID[] = {RECURSOR_STATS_OID, 147};
static const oid udrEventsOID[] = {RECURSOR_STATS_OID, 148};
static const oid maxChainLengthOID[] = {RECURSOR_STATS_OID, 149};
static const oid maxChainWeightOID[] = {RECURSOR_STATS_OID, 150};
static const oid chainLimitsOID[] = {RECURSOR_STATS_OID, 151};
static const oid tcpOverflowOID[] = {RECURSOR_STATS_OID, 152};
static const oid ecsMissingOID[] = {RECURSOR_STATS_OID, 153};

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

  const auto& it = s_statsMap.find(reginfo->rootoid[reginfo->rootoid_len - 2]);
  if (it == s_statsMap.end()) {
    return SNMP_ERR_GENERR;
  }

  auto value = getStatByName(it->second);
  if (value) {
    return RecursorSNMPAgent::setCounter64Value(requests, *value);
  }
  else {
    return RecursorSNMPAgent::setCounter64Value(requests, 0);
  }
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

static void registerCounter64Stat(const std::string& name, const oid statOID[], size_t statOIDLength)
{
  if (statOIDLength != OID_LENGTH(questionsOID)) {
    SLOG(g_log << Logger::Error << "Invalid OID for SNMP Counter64 statistic " << name << endl,
         g_slog->withName("snmp")->info(Logr::Error, "Invalid OID for SNMP Counter64 statistic", "name", Logging::Loggable(name)));
    return;
  }

  if (s_statsMap.find(statOID[statOIDLength - 1]) != s_statsMap.end()) {
    SLOG(g_log << Logger::Error << "OID for SNMP Counter64 statistic " << name << " has already been registered" << endl,
         g_slog->withName("snmp")->info(Logr::Error, "OID for SNMP Counter64 statistic has already been registered", "name", Logging::Loggable(name)));
    return;
  }

  s_statsMap[statOID[statOIDLength - 1]] = name.c_str();
  netsnmp_register_scalar(netsnmp_create_handler_registration(name.c_str(),
                                                              isStatDisabled(StatComponent::SNMP, name) ? handleDisabledCounter64Stats : handleCounter64Stats,
                                                              statOID,
                                                              statOIDLength,
                                                              HANDLER_CAN_RONLY));
}

#endif /* HAVE_NET_SNMP */

std::shared_ptr<RecursorSNMPAgent> g_snmpAgent{nullptr};

bool RecursorSNMPAgent::sendCustomTrap([[maybe_unused]] const std::string& reason)
{
#ifdef HAVE_NET_SNMP
  netsnmp_variable_list* varList = nullptr;

  snmp_varlist_add_variable(&varList,
                            snmpTrapOID,
                            snmpTrapOIDLen,
                            ASN_OBJECT_ID,
                            customTrapOID,
                            OID_LENGTH(customTrapOID) * sizeof(oid));

  snmp_varlist_add_variable(&varList,
                            trapReasonOID,
                            OID_LENGTH(trapReasonOID),
                            ASN_OCTET_STR,
                            reason.c_str(),
                            reason.size());

  return sendTrap(d_sender, varList);
#endif /* HAVE_NET_SNMP */
  return true;
}

RecursorSNMPAgent::RecursorSNMPAgent(const std::string& name, const std::string& masterSocket) :
  SNMPAgent(name, masterSocket)
{
#ifdef HAVE_NET_SNMP
  registerCounter64Stat("questions", questionsOID, OID_LENGTH(questionsOID));
  registerCounter64Stat("ipv6-questions", ipv6QuestionsOID, OID_LENGTH(ipv6QuestionsOID));
  registerCounter64Stat("tcp-questions", tcpQuestionsOID, OID_LENGTH(tcpQuestionsOID));
  registerCounter64Stat("cache-hits", cacheHitsOID, OID_LENGTH(cacheHitsOID));
  registerCounter64Stat("cache-misses", cacheMissesOID, OID_LENGTH(cacheMissesOID));
  registerCounter64Stat("cache-entries", cacheEntriesOID, OID_LENGTH(cacheEntriesOID));
  registerCounter64Stat("cache-bytes", cacheBytesOID, OID_LENGTH(cacheBytesOID));
  registerCounter64Stat("packetcache-hits", packetcacheHitsOID, OID_LENGTH(packetcacheHitsOID));
  registerCounter64Stat("packetcache-misses", packetcacheMissesOID, OID_LENGTH(packetcacheMissesOID));
  registerCounter64Stat("packetcache-entries", packetcacheEntriesOID, OID_LENGTH(packetcacheEntriesOID));
  registerCounter64Stat("packetcache-bytes", packetcacheBytesOID, OID_LENGTH(packetcacheBytesOID));
  registerCounter64Stat("malloc-bytes", mallocBytesOID, OID_LENGTH(mallocBytesOID));
  registerCounter64Stat("servfail-answers", servfailAnswersOID, OID_LENGTH(servfailAnswersOID));
  registerCounter64Stat("nxdomain-answers", nxdomainAnswersOID, OID_LENGTH(nxdomainAnswersOID));
  registerCounter64Stat("noerror-answers", noerrorAnswersOID, OID_LENGTH(noerrorAnswersOID));
  registerCounter64Stat("unauthorized-udp", unauthorizedUdpOID, OID_LENGTH(unauthorizedUdpOID));
  registerCounter64Stat("unauthorized-tcp", unauthorizedTcpOID, OID_LENGTH(unauthorizedTcpOID));
  registerCounter64Stat("source-disallowed-notify", sourceDisallowedNotifyOID, OID_LENGTH(sourceDisallowedNotifyOID));
  registerCounter64Stat("zone-disallowed-notify", zoneDisallowedNotifyOID, OID_LENGTH(zoneDisallowedNotifyOID));
  registerCounter64Stat("tcp-client-overflow", tcpClientOverflowOID, OID_LENGTH(tcpClientOverflowOID));
  registerCounter64Stat("client-parse-errors", clientParseErrorsOID, OID_LENGTH(clientParseErrorsOID));
  registerCounter64Stat("server-parse-errors", serverParseErrorsOID, OID_LENGTH(serverParseErrorsOID));
  registerCounter64Stat("too-old-drops", tooOldDropsOID, OID_LENGTH(tooOldDropsOID));
  registerCounter64Stat("query-pipe-full-drops", queryPipeFullDropsOID, OID_LENGTH(queryPipeFullDropsOID));
  registerCounter64Stat("truncated-drops", truncatedDropsOID, OID_LENGTH(truncatedDropsOID));
  registerCounter64Stat("empty-queries", emptyQueriesOID, OID_LENGTH(emptyQueriesOID));
  registerCounter64Stat("variable-responses", variableResponsesOID, OID_LENGTH(variableResponsesOID));
  registerCounter64Stat("answers0-1", answers01OID, OID_LENGTH(answers01OID));
  registerCounter64Stat("answers1-10", answers110OID, OID_LENGTH(answers110OID));
  registerCounter64Stat("answers10-100", answers10100OID, OID_LENGTH(answers10100OID));
  registerCounter64Stat("answers100-1000", answers1001000OID, OID_LENGTH(answers1001000OID));
  registerCounter64Stat("answers-slow", answersSlowOID, OID_LENGTH(answersSlowOID));
  registerCounter64Stat("auth4-answers0-1", auth4Answers01OID, OID_LENGTH(auth4Answers01OID));
  registerCounter64Stat("auth4-answers1-10", auth4Answers110OID, OID_LENGTH(auth4Answers110OID));
  registerCounter64Stat("auth4-answers10-100", auth4Answers10100OID, OID_LENGTH(auth4Answers10100OID));
  registerCounter64Stat("auth4-answers100-1000", auth4Answers1001000OID, OID_LENGTH(auth4Answers1001000OID));
  registerCounter64Stat("auth4-answers-slow", auth4AnswersslowOID, OID_LENGTH(auth4AnswersslowOID));
  registerCounter64Stat("auth6-answers0-1", auth6Answers01OID, OID_LENGTH(auth6Answers01OID));
  registerCounter64Stat("auth6-answers1-10", auth6Answers110OID, OID_LENGTH(auth6Answers110OID));
  registerCounter64Stat("auth6-answers10-100", auth6Answers10100OID, OID_LENGTH(auth6Answers10100OID));
  registerCounter64Stat("auth6-answers100-1000", auth6Answers1001000OID, OID_LENGTH(auth6Answers1001000OID));
  registerCounter64Stat("auth6-answers-slow", auth6AnswersSlowOID, OID_LENGTH(auth6AnswersSlowOID));
  registerCounter64Stat("qa-latency", qaLatencyOID, OID_LENGTH(qaLatencyOID));
  registerCounter64Stat("unexpected-packets", unexpectedPacketsOID, OID_LENGTH(unexpectedPacketsOID));
  registerCounter64Stat("case-mismatches", caseMismatchesOID, OID_LENGTH(caseMismatchesOID));
  registerCounter64Stat("spoof-prevents", spoofPreventsOID, OID_LENGTH(spoofPreventsOID));
  registerCounter64Stat("nsset-invalidations", nssetInvalidationsOID, OID_LENGTH(nssetInvalidationsOID));
  registerCounter64Stat("resource-limits", resourceLimitsOID, OID_LENGTH(resourceLimitsOID));
  registerCounter64Stat("over-capacity-drops", overCapacityDropsOID, OID_LENGTH(overCapacityDropsOID));
  registerCounter64Stat("policy-drops", policyDropsOID, OID_LENGTH(policyDropsOID));
  registerCounter64Stat("no-packet-error", noPacketErrorOID, OID_LENGTH(noPacketErrorOID));
  registerCounter64Stat("dlg-only-drops", dlgOnlyDropsOID, OID_LENGTH(dlgOnlyDropsOID));
  registerCounter64Stat("ignored-packets", ignoredPacketsOID, OID_LENGTH(ignoredPacketsOID));
  registerCounter64Stat("max-mthread-stack", maxMthreadStackOID, OID_LENGTH(maxMthreadStackOID));
  registerCounter64Stat("negcache-entries", negcacheEntriesOID, OID_LENGTH(negcacheEntriesOID));
  registerCounter64Stat("throttle-entries", throttleEntriesOID, OID_LENGTH(throttleEntriesOID));
  registerCounter64Stat("nsspeeds-entries", nsspeedsEntriesOID, OID_LENGTH(nsspeedsEntriesOID));
  registerCounter64Stat("failed-host-entries", failedHostEntriesOID, OID_LENGTH(failedHostEntriesOID));
  registerCounter64Stat("concurrent-queries", concurrentQueriesOID, OID_LENGTH(concurrentQueriesOID));
  registerCounter64Stat("security-status", securityStatusOID, OID_LENGTH(securityStatusOID));
  registerCounter64Stat("outgoing-timeouts", outgoingTimeoutsOID, OID_LENGTH(outgoingTimeoutsOID));
  registerCounter64Stat("outgoing4-timeouts", outgoing4TimeoutsOID, OID_LENGTH(outgoing4TimeoutsOID));
  registerCounter64Stat("outgoing6-timeouts", outgoing6TimeoutsOID, OID_LENGTH(outgoing6TimeoutsOID));
  registerCounter64Stat("tcp-outqueries", tcpOutqueriesOID, OID_LENGTH(tcpOutqueriesOID));
  registerCounter64Stat("all-outqueries", allOutqueriesOID, OID_LENGTH(allOutqueriesOID));
  registerCounter64Stat("ipv6-outqueries", ipv6OutqueriesOID, OID_LENGTH(ipv6OutqueriesOID));
  registerCounter64Stat("throttled-outqueries", throttledOutqueriesOID, OID_LENGTH(throttledOutqueriesOID));
  registerCounter64Stat("dont-outqueries", dontOutqueriesOID, OID_LENGTH(dontOutqueriesOID));
  registerCounter64Stat("qname-min-fallback-success", qnameMinFallbackSuccessOID, OID_LENGTH(qnameMinFallbackSuccessOID));
  registerCounter64Stat("unreachables", unreachablesOID, OID_LENGTH(unreachablesOID));
  registerCounter64Stat("chain-resends", chainResendsOID, OID_LENGTH(chainResendsOID));
  registerCounter64Stat("tcp-clients", tcpClientsOID, OID_LENGTH(tcpClientsOID));
#ifdef __linux__
  registerCounter64Stat("udp-recvbuf-errors", udpRecvbufErrorsOID, OID_LENGTH(udpRecvbufErrorsOID));
  registerCounter64Stat("udp-sndbuf-errors", udpSndbufErrorsOID, OID_LENGTH(udpSndbufErrorsOID));
  registerCounter64Stat("udp-noport-errors", udpNoportErrorsOID, OID_LENGTH(udpNoportErrorsOID));
  registerCounter64Stat("udp-in-errors", udpinErrorsOID, OID_LENGTH(udpinErrorsOID));
  registerCounter64Stat("udp-in-csums-errors", udpInCsumErrorsOID, OID_LENGTH(udpInCsumErrorsOID));
  registerCounter64Stat("udp6-recvbuf-errors", udp6RecvbufErrorsOID, OID_LENGTH(udp6RecvbufErrorsOID));
  registerCounter64Stat("udp6-sndbuf-errors", udp6SndbufErrorsOID, OID_LENGTH(udp6SndbufErrorsOID));
  registerCounter64Stat("udp6-noport-errors", udp6NoportErrorsOID, OID_LENGTH(udp6NoportErrorsOID));
  registerCounter64Stat("udp6-in-errors", udp6InErrorsOID, OID_LENGTH(udp6InErrorsOID));
  registerCounter64Stat("udp6-in-csums-errors", udp6InCsumErrorsOID, OID_LENGTH(udp6InCsumErrorsOID));
#endif /* __linux__ */
  registerCounter64Stat("edns-ping-matches", ednsPingMatchesOID, OID_LENGTH(ednsPingMatchesOID));
  registerCounter64Stat("edns-ping-mismatches", ednsPingMismatchesOID, OID_LENGTH(ednsPingMismatchesOID));
  registerCounter64Stat("dnssec-queries", dnssecQueriesOID, OID_LENGTH(dnssecQueriesOID));
  registerCounter64Stat("dnssec-authentic-data-queries", dnssecAuthenticDataQueriesOID, OID_LENGTH(dnssecAuthenticDataQueriesOID));
  registerCounter64Stat("dnssec-check-disabled-queries", dnssecCheckDisabledQueriesOID, OID_LENGTH(dnssecCheckDisabledQueriesOID));
  registerCounter64Stat("noping-outqueries", nopingOutqueriesOID, OID_LENGTH(nopingOutqueriesOID));
  registerCounter64Stat("noedns-outqueries", noednsOutqueriesOID, OID_LENGTH(noednsOutqueriesOID));
  registerCounter64Stat("uptime", uptimeOID, OID_LENGTH(uptimeOID));
  registerCounter64Stat("real-memory-usage", realMemoryUsageOID, OID_LENGTH(realMemoryUsageOID));
  registerCounter64Stat("fd-usage", fdUsageOID, OID_LENGTH(fdUsageOID));
  registerCounter64Stat("user-msec", userMsecOID, OID_LENGTH(userMsecOID));
  registerCounter64Stat("sys-msec", sysMsecOID, OID_LENGTH(sysMsecOID));
  registerCounter64Stat("dnssec-validations", dnssecValidationsOID, OID_LENGTH(dnssecValidationsOID));
  registerCounter64Stat("dnssec-result-insecure", dnssecResultInsecureOID, OID_LENGTH(dnssecResultInsecureOID));
  registerCounter64Stat("dnssec-result-secure", dnssecResultSecureOID, OID_LENGTH(dnssecResultSecureOID));
  registerCounter64Stat("dnssec-result-bogus", dnssecResultBogusOID, OID_LENGTH(dnssecResultBogusOID));
  registerCounter64Stat("dnssec-result-indeterminate", dnssecResultIndeterminateOID, OID_LENGTH(dnssecResultIndeterminateOID));
  registerCounter64Stat("dnssec-result-nta", dnssecResultNtaOID, OID_LENGTH(dnssecResultNtaOID));
  registerCounter64Stat("policy-result-noaction", policyResultNoactionOID, OID_LENGTH(policyResultNoactionOID));
  registerCounter64Stat("policy-result-drop", policyResultDropOID, OID_LENGTH(policyResultDropOID));
  registerCounter64Stat("policy-result-nxdomain", policyResultNxdomainOID, OID_LENGTH(policyResultNxdomainOID));
  registerCounter64Stat("policy-result-nodata", policyResultNodataOID, OID_LENGTH(policyResultNodataOID));
  registerCounter64Stat("policy-result-truncate", policyResultTruncateOID, OID_LENGTH(policyResultTruncateOID));
  registerCounter64Stat("policy-result-custom", policyResultCustomOID, OID_LENGTH(policyResultCustomOID));
  registerCounter64Stat("special-memory-usage", specialMemoryUsageOID, OID_LENGTH(specialMemoryUsageOID));
  registerCounter64Stat("rebalanced-queries", rebalancedQueriesOID, OID_LENGTH(rebalancedQueriesOID));
  registerCounter64Stat("proxy-protocol-invalid", proxyProtocolInvalidOID, OID_LENGTH(proxyProtocolInvalidOID));
  registerCounter64Stat("record-cache-contended", recordCacheContendedOID, OID_LENGTH(recordCacheContendedOID));
  registerCounter64Stat("record-cache-acquired", recordCacheAcquiredOID, OID_LENGTH(recordCacheAcquiredOID));
  registerCounter64Stat("nod-lookups-dropped-oversize", nodLookupsDroppedOversizeOID, OID_LENGTH(nodLookupsDroppedOversizeOID));
  registerCounter64Stat("tasqueue-pushed", taskQueuePushedOID, OID_LENGTH(taskQueuePushedOID));
  registerCounter64Stat("taskqueue-expired", taskQueueExpiredOID, OID_LENGTH(taskQueueExpiredOID));
  registerCounter64Stat("taskqueue-size", taskQueueSizeOID, OID_LENGTH(taskQueueSizeOID));
  registerCounter64Stat("aggressive-nsec-cache-entries", aggressiveNSECCacheEntriesOID, OID_LENGTH(aggressiveNSECCacheEntriesOID));
  registerCounter64Stat("aggressive-nsec-cache-nsec-hits", aggressiveNSECCacheNSECHitsOID, OID_LENGTH(aggressiveNSECCacheNSECHitsOID));
  registerCounter64Stat("aggressive-nsec-cache-nsec3-hits", aggressiveNSECCacheNSEC3HitsOID, OID_LENGTH(aggressiveNSECCacheNSEC3HitsOID));
  registerCounter64Stat("aggressive-nsec-cache-nsec-wc-hits", aggressiveNSECCacheNSECWCHitsOID, OID_LENGTH(aggressiveNSECCacheNSECWCHitsOID));
  registerCounter64Stat("aggressive-nsec-cache-nsec-wc3-hits", aggressiveNSECCacheNSEC3WCHitsOID, OID_LENGTH(aggressiveNSECCacheNSEC3WCHitsOID));
  registerCounter64Stat("dot-outqueries", dotOutqueriesOID, OID_LENGTH(dotOutqueriesOID));
  registerCounter64Stat("dns64-prefix-answers", dns64PrefixAnswers, OID_LENGTH(dns64PrefixAnswers));
  registerCounter64Stat("almost-expired-pushed", almostExpiredPushed, OID_LENGTH(almostExpiredPushed));
  registerCounter64Stat("almost-expired-run", almostExpiredRun, OID_LENGTH(almostExpiredRun));
  registerCounter64Stat("almost-expired-exceptions", almostExpiredExceptions, OID_LENGTH(almostExpiredExceptions));
  registerCounter64Stat("non-resolving-nameserver-entries", nonResolvingNameserverEntriesOID, OID_LENGTH(nonResolvingNameserverEntriesOID));
  registerCounter64Stat("maintenance-usec", maintenanceUSecOID, OID_LENGTH(maintenanceUSecOID));
  registerCounter64Stat("maintenance-calls", maintenanceCallsOID, OID_LENGTH(maintenanceCallsOID));
  registerCounter64Stat("packetcache-contended", packetCacheContendedOID, OID_LENGTH(packetCacheContendedOID));
  registerCounter64Stat("packetcache-acquired", packetCacheAcquiredOID, OID_LENGTH(packetCacheAcquiredOID));

#define RCODE(num) registerCounter64Stat("auth-" + RCode::to_short_s(num) + "-answers", rcode##num##AnswersOID, OID_LENGTH(rcode##num##AnswersOID))
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

  registerCounter64Stat("packetcache-contended", packetCacheContendedOID, OID_LENGTH(packetCacheContendedOID));
  registerCounter64Stat("packetcache-acquired", packetCacheAcquiredOID, OID_LENGTH(packetCacheAcquiredOID));
  registerCounter64Stat("nod-events", nodEventsOID, OID_LENGTH(nodEventsOID));
  registerCounter64Stat("udr-events", udrEventsOID, OID_LENGTH(udrEventsOID));
  registerCounter64Stat("max-chain-length", maxChainLengthOID, OID_LENGTH(maxChainLengthOID));
  registerCounter64Stat("max-chain-weight", maxChainWeightOID, OID_LENGTH(maxChainWeightOID));
  registerCounter64Stat("chain-limits", chainLimitsOID, OID_LENGTH(chainLimitsOID));
  registerCounter64Stat("tcp-overflow", tcpOverflowOID, OID_LENGTH(tcpOverflowOID));
  registerCounter64Stat("ecs-missing", ecsMissingOID, OID_LENGTH(ecsMissingOID));

#endif /* HAVE_NET_SNMP */
}
