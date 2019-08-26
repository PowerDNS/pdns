
#include <unordered_map>

#include "rec-snmp.hh"
#include "rec_channel.hh"

#include "logger.hh"

#ifdef HAVE_NET_SNMP

#define RECURSOR_OID 1, 3, 6, 1, 4, 1, 43315, 2
#define RECURSOR_STATS_OID RECURSOR_OID, 1
#define RECURSOR_TRAPS_OID RECURSOR_OID, 10, 0
#define RECURSOR_TRAP_OBJECTS_OID RECURSOR_OID, 11

static const oid trapReasonOID[] = { RECURSOR_TRAP_OBJECTS_OID, 1, 0 };
static const oid customTrapOID[] = { RECURSOR_TRAPS_OID, 1 };

static const oid questionsOID[] = { RECURSOR_STATS_OID, 1 };
static const oid ipv6QuestionsOID[] = { RECURSOR_STATS_OID, 2 };
static const oid tcpQuestionsOID[] = { RECURSOR_STATS_OID, 3 };
static const oid cacheHitsOID[] = { RECURSOR_STATS_OID, 4 };
static const oid cacheMissesOID[] = { RECURSOR_STATS_OID, 5 };
static const oid cacheEntriesOID[] = { RECURSOR_STATS_OID, 6 };
static const oid cacheBytesOID[] = { RECURSOR_STATS_OID, 7 };
static const oid packetcacheHitsOID[] = { RECURSOR_STATS_OID, 8 };
static const oid packetcacheMissesOID[] = { RECURSOR_STATS_OID, 9 };
static const oid packetcacheEntriesOID[] = { RECURSOR_STATS_OID, 10 };
static const oid packetcacheBytesOID[] = { RECURSOR_STATS_OID, 11 };
static const oid mallocBytesOID[] = { RECURSOR_STATS_OID, 12 };
static const oid servfailAnswersOID[] = { RECURSOR_STATS_OID, 13 };
static const oid nxdomainAnswersOID[] = { RECURSOR_STATS_OID, 14 };
static const oid noerrorAnswersOID[] = { RECURSOR_STATS_OID, 15 };
static const oid unauthorizedUdpOID[] = { RECURSOR_STATS_OID, 16 };
static const oid unauthorizedTcpOID[] = { RECURSOR_STATS_OID, 17 };
static const oid tcpClientOverflowOID[] = { RECURSOR_STATS_OID, 18 };
static const oid clientParseErrorsOID[] = { RECURSOR_STATS_OID, 19 };
static const oid serverParseErrorsOID[] = { RECURSOR_STATS_OID, 20 };
static const oid tooOldDropsOID[] = { RECURSOR_STATS_OID, 21 };
static const oid answers01OID[] = { RECURSOR_STATS_OID, 22 };
static const oid answers110OID[] = { RECURSOR_STATS_OID, 23 };
static const oid answers10100OID[] = { RECURSOR_STATS_OID, 24 };
static const oid answers1001000OID[] = { RECURSOR_STATS_OID, 25 };
static const oid answersSlowOID[] = { RECURSOR_STATS_OID, 26 };
static const oid auth4Answers01OID[] = { RECURSOR_STATS_OID, 27 };
static const oid auth4Answers110OID[] = { RECURSOR_STATS_OID, 28 };
static const oid auth4Answers10100OID[] = { RECURSOR_STATS_OID, 29 };
static const oid auth4Answers1001000OID[] = { RECURSOR_STATS_OID, 30 };
static const oid auth4AnswersslowOID[] = { RECURSOR_STATS_OID, 31 };
static const oid auth6Answers01OID[] = { RECURSOR_STATS_OID, 32 };
static const oid auth6Answers110OID[] = { RECURSOR_STATS_OID, 33 };
static const oid auth6Answers10100OID[] = { RECURSOR_STATS_OID, 34 };
static const oid auth6Answers1001000OID[] = { RECURSOR_STATS_OID, 35 };
static const oid auth6AnswersSlowOID[] = { RECURSOR_STATS_OID, 36 };
static const oid qaLatencyOID[] = { RECURSOR_STATS_OID, 37 };
static const oid unexpectedPacketsOID[] = { RECURSOR_STATS_OID, 38 };
static const oid caseMismatchesOID[] = { RECURSOR_STATS_OID, 39 };
static const oid spoofPreventsOID[] = { RECURSOR_STATS_OID, 40 };
static const oid nssetInvalidationsOID[] = { RECURSOR_STATS_OID, 41 };
static const oid resourceLimitsOID[] = { RECURSOR_STATS_OID, 42 };
static const oid overCapacityDropsOID[] = { RECURSOR_STATS_OID, 43 };
static const oid policyDropsOID[] = { RECURSOR_STATS_OID, 44 };
static const oid noPacketErrorOID[] = { RECURSOR_STATS_OID, 45 };
static const oid dlgOnlyDropsOID[] = { RECURSOR_STATS_OID, 46 };
static const oid ignoredPacketsOID[] = { RECURSOR_STATS_OID, 47 };
static const oid maxMthreadStackOID[] = { RECURSOR_STATS_OID, 48 };
static const oid negcacheEntriesOID[] = { RECURSOR_STATS_OID, 49 };
static const oid throttleEntriesOID[] = { RECURSOR_STATS_OID, 50 };
static const oid nsspeedsEntriesOID[] = { RECURSOR_STATS_OID, 51 };
static const oid failedHostEntriesOID[] = { RECURSOR_STATS_OID, 52 };
static const oid concurrentQueriesOID[] = { RECURSOR_STATS_OID, 53 };
static const oid securityStatusOID[] = { RECURSOR_STATS_OID, 54 };
static const oid outgoingTimeoutsOID[] = { RECURSOR_STATS_OID, 55 };
static const oid outgoing4TimeoutsOID[] = { RECURSOR_STATS_OID, 56 };
static const oid outgoing6TimeoutsOID[] = { RECURSOR_STATS_OID, 57 };
static const oid tcpOutqueriesOID[] = { RECURSOR_STATS_OID, 58 };
static const oid allOutqueriesOID[] = { RECURSOR_STATS_OID, 59 };
static const oid ipv6OutqueriesOID[] = { RECURSOR_STATS_OID, 60 };
static const oid throttledOutqueriesOID[] = { RECURSOR_STATS_OID, 61 };
static const oid dontOutqueriesOID[] = { RECURSOR_STATS_OID, 62 };
static const oid unreachablesOID[] = { RECURSOR_STATS_OID, 63 };
static const oid chainResendsOID[] = { RECURSOR_STATS_OID, 64 };
static const oid tcpClientsOID[] = { RECURSOR_STATS_OID, 65 };
static const oid udpRecvbufErrorsOID[] = { RECURSOR_STATS_OID, 66 };
static const oid udpSndbufErrorsOID[] = { RECURSOR_STATS_OID, 67 };
static const oid udpNoportErrorsOID[] = { RECURSOR_STATS_OID, 68 };
static const oid udpinErrorsOID[] = { RECURSOR_STATS_OID, 69 };
static const oid ednsPingMatchesOID[] = { RECURSOR_STATS_OID, 70 };
static const oid ednsPingMismatchesOID[] = { RECURSOR_STATS_OID, 71 };
static const oid dnssecQueriesOID[] = { RECURSOR_STATS_OID, 72 };
static const oid nopingOutqueriesOID[] = { RECURSOR_STATS_OID, 73 };
static const oid noednsOutqueriesOID[] = { RECURSOR_STATS_OID, 74 };
static const oid uptimeOID[] = { RECURSOR_STATS_OID, 75 };
static const oid realMemoryUsageOID[] = { RECURSOR_STATS_OID, 76 };
static const oid fdUsageOID[] = { RECURSOR_STATS_OID, 77 };
static const oid userMsecOID[] = { RECURSOR_STATS_OID, 78 };
static const oid sysMsecOID[] = { RECURSOR_STATS_OID, 79 };
static const oid dnssecValidationsOID[] = { RECURSOR_STATS_OID, 80 };
static const oid dnssecResultInsecureOID[] = { RECURSOR_STATS_OID, 81 };
static const oid dnssecResultSecureOID[] = { RECURSOR_STATS_OID, 82 };
static const oid dnssecResultBogusOID[] = { RECURSOR_STATS_OID, 83 };
static const oid dnssecResultIndeterminateOID[] = { RECURSOR_STATS_OID, 84 };
static const oid dnssecResultNtaOID[] = { RECURSOR_STATS_OID, 85 };
static const oid policyResultNoactionOID[] = { RECURSOR_STATS_OID, 86 };
static const oid policyResultDropOID[] = { RECURSOR_STATS_OID, 87 };
static const oid policyResultNxdomainOID[] = { RECURSOR_STATS_OID, 88 };
static const oid policyResultNodataOID[] = { RECURSOR_STATS_OID, 89 };
static const oid policyResultTruncateOID[] = { RECURSOR_STATS_OID, 90 };
static const oid policyResultCustomOID[] = { RECURSOR_STATS_OID, 91 };
static const oid queryPipeFullDropsOID[] = { RECURSOR_STATS_OID, 92 };
static const oid truncatedDropsOID[] = { RECURSOR_STATS_OID, 93 };
static const oid emptyQueriesOID[] = { RECURSOR_STATS_OID, 94 };
static const oid dnssecAuthenticDataQueriesOID[] = { RECURSOR_STATS_OID, 95 };
static const oid dnssecCheckDisabledQueriesOID[] = { RECURSOR_STATS_OID, 96 };
static const oid variableResponsesOID[] = { RECURSOR_STATS_OID, 97 };
static const oid specialMemoryUsageOID[] = { RECURSOR_STATS_OID, 98 };
static const oid rebalancedQueriesOID[] = { RECURSOR_STATS_OID, 99 };

static std::unordered_map<oid, std::string> s_statsMap;

/* We are never called for a GETNEXT if it's registered as a
   "instance", as it's "magically" handled for us.  */
/* a instance handler also only hands us one request at a time, so
   we don't need to loop over a list of requests; we'll only get one. */

static int handleCounter64Stats(netsnmp_mib_handler* handler,
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

  optional<uint64_t> value = getStatByName(it->second);
  if (value) {
    return RecursorSNMPAgent::setCounter64Value(requests, *value);
  } else {
    return RecursorSNMPAgent::setCounter64Value(requests, 0);
  }
}

static int handleDisabledCounter64Stats(netsnmp_mib_handler* handler,
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
    g_log<<Logger::Error<<"Invalid OID for SNMP Counter64 statistic "<<name<<endl;
    return;
  }

  if (s_statsMap.find(statOID[statOIDLength - 1]) != s_statsMap.end()) {
    g_log<<Logger::Error<<"OID for SNMP Counter64 statistic "<<name<<" has already been registered"<<endl;
    return;
  }

  s_statsMap[statOID[statOIDLength - 1]] = name.c_str();
  netsnmp_register_scalar(netsnmp_create_handler_registration(name.c_str(),
                                                              isStatBlacklisted(StatComponent::SNMP, name) ?
                                                              handleDisabledCounter64Stats : handleCounter64Stats,
                                                              statOID,
                                                              statOIDLength,
                                                              HANDLER_CAN_RONLY));
}

#endif /* HAVE_NET_SNMP */

std::shared_ptr<RecursorSNMPAgent> g_snmpAgent{nullptr};

bool RecursorSNMPAgent::sendCustomTrap(const std::string& reason)
{
#ifdef HAVE_NET_SNMP
  netsnmp_variable_list* varList = nullptr;

  snmp_varlist_add_variable(&varList,
                            snmpTrapOID,
                            snmpTrapOIDLen,
                            ASN_OBJECT_ID,
                            customTrapOID,
                            OID_LENGTH(customTrapOID)  * sizeof(oid));

  snmp_varlist_add_variable(&varList,
                            trapReasonOID,
                            OID_LENGTH(trapReasonOID),
                            ASN_OCTET_STR,
                            reason.c_str(),
                            reason.size());

  return sendTrap(d_trapPipe[1], varList);
#endif /* HAVE_NET_SNMP */
  return true;
}


RecursorSNMPAgent::RecursorSNMPAgent(const std::string& name, const std::string& masterSocket): SNMPAgent(name, masterSocket)
{
#ifdef HAVE_NET_SNMP
  /* This is done so that the statistics maps are
     initialized. */
  registerAllStats();

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
  registerCounter64Stat("unreachables", unreachablesOID, OID_LENGTH(unreachablesOID));
  registerCounter64Stat("chain-resends", chainResendsOID, OID_LENGTH(chainResendsOID));
  registerCounter64Stat("tcp-clients", tcpClientsOID, OID_LENGTH(tcpClientsOID));
#ifdef __linux__
  registerCounter64Stat("udp-recvbuf-errors", udpRecvbufErrorsOID, OID_LENGTH(udpRecvbufErrorsOID));
  registerCounter64Stat("udp-sndbuf-errors", udpSndbufErrorsOID, OID_LENGTH(udpSndbufErrorsOID));
  registerCounter64Stat("udp-noport-errors", udpNoportErrorsOID, OID_LENGTH(udpNoportErrorsOID));
  registerCounter64Stat("udp-in-errors", udpinErrorsOID, OID_LENGTH(udpinErrorsOID));
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
#endif /* HAVE_NET_SNMP */
}
