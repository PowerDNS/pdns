
#include "dnsdist-snmp.hh"
#include "dolog.hh"

#ifdef HAVE_NET_SNMP

#define DNSDIST_OID 1, 3, 6, 1, 4, 1, 43315, 3
#define DNSDIST_STATS_OID DNSDIST_OID, 1
#define DNSDIST_STATS_TABLE_OID DNSDIST_OID, 2
#define DNSDIST_TRAPS_OID DNSDIST_OID, 10, 0
#define DNSDIST_TRAP_OBJECTS_OID DNSDIST_OID, 11

static const oid queriesOID[] = { DNSDIST_STATS_OID, 1 };
static const oid responsesOID[] = { DNSDIST_STATS_OID, 2 };
static const oid servfailResponsesOID[] = { DNSDIST_STATS_OID, 3 };
static const oid aclDropsOID[] = { DNSDIST_STATS_OID, 4 };
// 5 was BlockFilter, removed in 1.2.0
static const oid ruleDropOID[] = { DNSDIST_STATS_OID, 6 };
static const oid ruleNXDomainOID[] = { DNSDIST_STATS_OID, 7 };
static const oid ruleRefusedOID[] = { DNSDIST_STATS_OID, 8 };
static const oid selfAnsweredOID[] = { DNSDIST_STATS_OID, 9 };
static const oid downstreamTimeoutsOID[] = { DNSDIST_STATS_OID, 10 };
static const oid downstreamSendErrorsOID[] = { DNSDIST_STATS_OID, 11 };
static const oid truncFailOID[] = { DNSDIST_STATS_OID, 12 };
static const oid noPolicyOID[] = { DNSDIST_STATS_OID, 13 };
static const oid latency0_1OID[] = { DNSDIST_STATS_OID, 14 };
static const oid latency1_10OID[] = { DNSDIST_STATS_OID, 15 };
static const oid latency10_50OID[] = { DNSDIST_STATS_OID, 16 };
static const oid latency50_100OID[] = { DNSDIST_STATS_OID, 17 };
static const oid latency100_1000OID[] = { DNSDIST_STATS_OID, 18 };
static const oid latencySlowOID[] = { DNSDIST_STATS_OID, 19 };
static const oid latencyAvg100OID[] = { DNSDIST_STATS_OID, 20 };
static const oid latencyAvg1000OID[] = { DNSDIST_STATS_OID, 21 };
static const oid latencyAvg10000OID[] = { DNSDIST_STATS_OID, 22 };
static const oid latencyAvg1000000OID[] = { DNSDIST_STATS_OID, 23 };
static const oid uptimeOID[] = { DNSDIST_STATS_OID, 24 };
static const oid realMemoryUsageOID[] = { DNSDIST_STATS_OID, 25 };
static const oid nonCompliantQueriesOID[] = { DNSDIST_STATS_OID, 26 };
static const oid nonCompliantResponsesOID[] = { DNSDIST_STATS_OID, 27 };
static const oid rdQueriesOID[] = { DNSDIST_STATS_OID, 28 };
static const oid emptyQueriesOID[] = { DNSDIST_STATS_OID, 29 };
static const oid cacheHitsOID[] = { DNSDIST_STATS_OID, 30 };
static const oid cacheMissesOID[] = { DNSDIST_STATS_OID, 31 };
static const oid cpuUserMSecOID[] = { DNSDIST_STATS_OID, 32 };
static const oid cpuSysMSecOID[] = { DNSDIST_STATS_OID, 33 };
static const oid fdUsageOID[] = { DNSDIST_STATS_OID, 34 };
static const oid dynBlockedOID[] = { DNSDIST_STATS_OID, 35 };
static const oid dynBlockedNMGSizeOID[] = { DNSDIST_STATS_OID, 36 };
static const oid ruleServFailOID[] = { DNSDIST_STATS_OID, 37 };
static const oid securityStatusOID[] = { DNSDIST_STATS_OID, 38 };
static const oid specialMemoryUsageOID[] = { DNSDIST_STATS_OID, 39 };

static std::unordered_map<oid, DNSDistStats::entry_t> s_statsMap;

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

  if (reginfo->rootoid_len != OID_LENGTH(queriesOID) + 1) {
    return SNMP_ERR_GENERR;
  }

  const auto& it = s_statsMap.find(reginfo->rootoid[reginfo->rootoid_len - 2]);
  if (it == s_statsMap.end()) {
    return SNMP_ERR_GENERR;
  }

  if (const auto& val = boost::get<DNSDistStats::stat_t*>(&it->second)) {
    return DNSDistSNMPAgent::setCounter64Value(requests, (*val)->load());
  }

  return SNMP_ERR_GENERR;
}

static void registerCounter64Stat(const char* name, const oid statOID[], size_t statOIDLength, std::atomic<uint64_t>* ptr)
{
  if (statOIDLength != OID_LENGTH(queriesOID)) {
    errlog("Invalid OID for SNMP Counter64 statistic %s", name);
    return;
  }

  if (s_statsMap.find(statOID[statOIDLength - 1]) != s_statsMap.end()) {
    errlog("OID for SNMP Counter64 statistic %s has already been registered", name);
    return;
  }

  s_statsMap[statOID[statOIDLength - 1]] = ptr;
  netsnmp_register_scalar(netsnmp_create_handler_registration(name,
                                                              handleCounter64Stats,
                                                              statOID,
                                                              statOIDLength,
                                                              HANDLER_CAN_RONLY));
}

static int handleFloatStats(netsnmp_mib_handler* handler,
                            netsnmp_handler_registration* reginfo,
                            netsnmp_agent_request_info* reqinfo,
                            netsnmp_request_info* requests)
{
  if (reqinfo->mode != MODE_GET) {
    return SNMP_ERR_GENERR;
  }

  if (reginfo->rootoid_len != OID_LENGTH(queriesOID) + 1) {
    return SNMP_ERR_GENERR;
  }

  const auto& it = s_statsMap.find(reginfo->rootoid[reginfo->rootoid_len - 2]);
  if (it == s_statsMap.end()) {
    return SNMP_ERR_GENERR;
  }

  if (const auto& val = boost::get<double*>(&it->second)) {
    std::string str(std::to_string(**val));
    snmp_set_var_typed_value(requests->requestvb,
                             ASN_OCTET_STR,
                             str.c_str(),
                             str.size());
    return SNMP_ERR_NOERROR;
  }

  return SNMP_ERR_GENERR;
}

static void registerFloatStat(const char* name, const oid statOID[], size_t statOIDLength, double* ptr)
{
  if (statOIDLength != OID_LENGTH(queriesOID)) {
    errlog("Invalid OID for SNMP Float statistic %s", name);
    return;
  }

  if (s_statsMap.find(statOID[statOIDLength - 1]) != s_statsMap.end()) {
    errlog("OID for SNMP Float statistic %s has already been registered", name);
    return;
  }

  s_statsMap[statOID[statOIDLength - 1]] = ptr;
  netsnmp_register_scalar(netsnmp_create_handler_registration(name,
                                                              handleFloatStats,
                                                              statOID,
                                                              statOIDLength,
                                                              HANDLER_CAN_RONLY));
}

static int handleGauge64Stats(netsnmp_mib_handler* handler,
                              netsnmp_handler_registration* reginfo,
                              netsnmp_agent_request_info* reqinfo,
                              netsnmp_request_info* requests)
{
  if (reqinfo->mode != MODE_GET) {
    return SNMP_ERR_GENERR;
  }

  if (reginfo->rootoid_len != OID_LENGTH(queriesOID) + 1) {
    return SNMP_ERR_GENERR;
  }

  const auto& it = s_statsMap.find(reginfo->rootoid[reginfo->rootoid_len - 2]);
  if (it == s_statsMap.end()) {
    return SNMP_ERR_GENERR;
  }

  std::string str;
  uint64_t value = (*boost::get<DNSDistStats::statfunction_t>(&it->second))(str);
  return DNSDistSNMPAgent::setCounter64Value(requests, value);
}

static void registerGauge64Stat(const char* name, const oid statOID[], size_t statOIDLength, DNSDistStats::statfunction_t ptr)
{
  if (statOIDLength != OID_LENGTH(queriesOID)) {
    errlog("Invalid OID for SNMP Gauge64 statistic %s", name);
    return;
  }

  if (s_statsMap.find(statOID[statOIDLength - 1]) != s_statsMap.end()) {
    errlog("OID for SNMP Gauge64 statistic %s has already been registered", name);
    return;
  }

  s_statsMap[statOID[statOIDLength - 1]] = ptr;
  netsnmp_register_scalar(netsnmp_create_handler_registration(name,
                                                              handleGauge64Stats,
                                                              statOID,
                                                              statOIDLength,
                                                              HANDLER_CAN_RONLY));
}

/* column number definitions for table backendStatTable */
#define COLUMN_BACKENDID                1
#define COLUMN_BACKENDNAME              2
#define COLUMN_BACKENDLATENCY           3
#define COLUMN_BACKENDWEIGHT            4
#define COLUMN_BACKENDOUTSTANDING       5
#define COLUMN_BACKENDQPSLIMIT          6
#define COLUMN_BACKENDREUSED            7
#define COLUMN_BACKENDSTATE             8
#define COLUMN_BACKENDADDRESS           9
#define COLUMN_BACKENDPOOLS             10
#define COLUMN_BACKENDQPS               11
#define COLUMN_BACKENDQUERIES           12
#define COLUMN_BACKENDORDER             13

static const oid backendStatTableOID[] = { DNSDIST_STATS_TABLE_OID };
static const oid backendNameOID[] = { DNSDIST_STATS_TABLE_OID, 1, 2 };
static const oid backendStateOID[] = { DNSDIST_STATS_TABLE_OID, 1, 8};
static const oid backendAddressOID[] = { DNSDIST_STATS_TABLE_OID, 1, 9};

static const oid socketFamilyOID[] = { DNSDIST_TRAP_OBJECTS_OID, 1, 0 };
static const oid socketProtocolOID[] = { DNSDIST_TRAP_OBJECTS_OID, 2, 0 };
static const oid fromAddressOID[] = { DNSDIST_TRAP_OBJECTS_OID, 3, 0 };
static const oid toAddressOID[] = { DNSDIST_TRAP_OBJECTS_OID, 4, 0 };
static const oid queryTypeOID[] = { DNSDIST_TRAP_OBJECTS_OID, 5, 0 };
static const oid querySizeOID[] = { DNSDIST_TRAP_OBJECTS_OID, 6, 0 };
static const oid queryIDOID[] = { DNSDIST_TRAP_OBJECTS_OID, 7, 0 };
static const oid qNameOID[] = { DNSDIST_TRAP_OBJECTS_OID, 8, 0 };
static const oid qClassOID[] = { DNSDIST_TRAP_OBJECTS_OID, 9, 0 };
static const oid qTypeOID[] = { DNSDIST_TRAP_OBJECTS_OID, 10, 0 };
static const oid trapReasonOID[] = { DNSDIST_TRAP_OBJECTS_OID, 11, 0 };

static const oid backendStatusChangeTrapOID[] = { DNSDIST_TRAPS_OID, 1 };
static const oid actionTrapOID[] = { DNSDIST_TRAPS_OID, 2 };
static const oid customTrapOID[] = { DNSDIST_TRAPS_OID, 3 };

static servers_t s_servers;
static size_t s_currentServerIdx = 0;

static netsnmp_variable_list* backendStatTable_get_next_data_point(void** loop_context,
                                                                   void** my_data_context,
                                                                   netsnmp_variable_list* put_index_data,
                                                                   netsnmp_iterator_info* mydata)
{
  if (s_currentServerIdx >= s_servers.size()) {
    return NULL;
  }

  *my_data_context = (void*) (s_servers[s_currentServerIdx]).get();
  snmp_set_var_typed_integer(put_index_data, ASN_UNSIGNED, s_currentServerIdx);
  s_currentServerIdx++;

  return put_index_data;
}

static netsnmp_variable_list* backendStatTable_get_first_data_point(void** loop_context,
                                                                    void** data_context,
                                                                    netsnmp_variable_list* put_index_data,
                                                                    netsnmp_iterator_info* data)
{
  s_currentServerIdx = 0;

  /* get a copy of the shared_ptrs so they are not
     destroyed while we process the request */
  auto dstates = g_dstates.getLocal();
  s_servers.clear();
  s_servers.reserve(dstates->size());
  for (const auto& server : *dstates) {
    s_servers.push_back(server);
  }

  return backendStatTable_get_next_data_point(loop_context,
                                              data_context,
                                              put_index_data,
                                              data);
}

static int backendStatTable_handler(netsnmp_mib_handler* handler,
                                    netsnmp_handler_registration* reginfo,
                                    netsnmp_agent_request_info* reqinfo,
                                    netsnmp_request_info* requests)
{
  netsnmp_request_info* request;

  switch (reqinfo->mode) {
  case MODE_GET:
    for (request = requests; request; request = request->next) {
      netsnmp_table_request_info* table_info = netsnmp_extract_table_info(request);
      const DownstreamState* server = (const DownstreamState*) netsnmp_extract_iterator_context(request);

      if (!server) {
        continue;
      }

      switch (table_info->colnum) {
      case COLUMN_BACKENDNAME:
        snmp_set_var_typed_value(request->requestvb,
                                 ASN_OCTET_STR,
                                 server->name.c_str(),
                                 server->name.size());
        break;
      case COLUMN_BACKENDLATENCY:
        DNSDistSNMPAgent::setCounter64Value(request,
                                            server->latencyUsec/1000.0);
        break;
      case COLUMN_BACKENDWEIGHT:
        DNSDistSNMPAgent::setCounter64Value(request,
                                            server->weight);
        break;
      case COLUMN_BACKENDOUTSTANDING:
        DNSDistSNMPAgent::setCounter64Value(request,
                                            server->outstanding);
        break;
      case COLUMN_BACKENDQPSLIMIT:
        DNSDistSNMPAgent::setCounter64Value(request,
                                            server->qps.getRate());
        break;
      case COLUMN_BACKENDREUSED:
        DNSDistSNMPAgent::setCounter64Value(request, server->reuseds);
        break;
      case COLUMN_BACKENDSTATE:
      {
        std::string state(server->getStatus());
        snmp_set_var_typed_value(request->requestvb,
                                 ASN_OCTET_STR,
                                 state.c_str(),
                                 state.size());
        break;
      }
      case COLUMN_BACKENDADDRESS:
      {
        std::string addr(server->remote.toStringWithPort());
        snmp_set_var_typed_value(request->requestvb,
                                 ASN_OCTET_STR,
                                 addr.c_str(),
                                 addr.size());
        break;
      }
      case COLUMN_BACKENDPOOLS:
      {
        std::string pools;
        for(auto& p : server->pools) {
          if(!pools.empty())
            pools+=" ";
          pools+=p;
        }
        snmp_set_var_typed_value(request->requestvb,
                                 ASN_OCTET_STR,
                                 pools.c_str(),
                                 pools.size());
        break;
      }
      case COLUMN_BACKENDQPS:
        DNSDistSNMPAgent::setCounter64Value(request, server->queryLoad);
        break;
      case COLUMN_BACKENDQUERIES:
        DNSDistSNMPAgent::setCounter64Value(request, server->queries);
        break;
      case COLUMN_BACKENDORDER:
        DNSDistSNMPAgent::setCounter64Value(request, server->order);
        break;
      default:
        netsnmp_set_request_error(reqinfo,
                                  request,
                                  SNMP_NOSUCHOBJECT);
        break;
      }
    }
    break;
  }
  return SNMP_ERR_NOERROR;
}
#endif /* HAVE_NET_SNMP */

bool DNSDistSNMPAgent::sendBackendStatusChangeTrap(const std::shared_ptr<DownstreamState>& dss)
{
#ifdef HAVE_NET_SNMP
  const string backendAddress = dss->remote.toStringWithPort();
  const string backendStatus = dss->getStatus();
  netsnmp_variable_list* varList = nullptr;

  snmp_varlist_add_variable(&varList,
                            snmpTrapOID,
                            snmpTrapOIDLen,
                            ASN_OBJECT_ID,
                            backendStatusChangeTrapOID,
                            OID_LENGTH(backendStatusChangeTrapOID)  * sizeof(oid));


  snmp_varlist_add_variable(&varList,
                            backendNameOID,
                            OID_LENGTH(backendNameOID),
                            ASN_OCTET_STR,
                            dss->name.c_str(),
                            dss->name.size());

  snmp_varlist_add_variable(&varList,
                            backendAddressOID,
                            OID_LENGTH(backendAddressOID),
                            ASN_OCTET_STR,
                            backendAddress.c_str(),
                            backendAddress.size());

  snmp_varlist_add_variable(&varList,
                            backendStateOID,
                            OID_LENGTH(backendStateOID),
                            ASN_OCTET_STR,
                            backendStatus.c_str(),
                            backendStatus.size());

  return sendTrap(d_trapPipe[1], varList);
#else
  return true;
#endif /* HAVE_NET_SNMP */
}

bool DNSDistSNMPAgent::sendCustomTrap(const std::string& reason)
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
#else
  return true;
#endif /* HAVE_NET_SNMP */
}

bool DNSDistSNMPAgent::sendDNSTrap(const DNSQuestion& dq, const std::string& reason)
{
#ifdef HAVE_NET_SNMP
  std::string local = dq.local->toString();
  std::string remote = dq.remote->toString();
  std::string qname = dq.qname->toStringNoDot();
  const uint32_t socketFamily = dq.remote->isIPv4() ? 1 : 2;
  const uint32_t socketProtocol = dq.tcp ? 2 : 1;
  const uint32_t queryType = dq.dh->qr ? 2 : 1;
  const uint32_t querySize = (uint32_t) dq.len;
  const uint32_t queryID = (uint32_t) ntohs(dq.dh->id);
  const uint32_t qType = (uint32_t) dq.qtype;
  const uint32_t qClass = (uint32_t) dq.qclass;

  netsnmp_variable_list* varList = nullptr;

  snmp_varlist_add_variable(&varList,
                            snmpTrapOID,
                            snmpTrapOIDLen,
                            ASN_OBJECT_ID,
                            actionTrapOID,
                            OID_LENGTH(actionTrapOID)  * sizeof(oid));

  snmp_varlist_add_variable(&varList,
                            socketFamilyOID,
                            OID_LENGTH(socketFamilyOID),
                            ASN_INTEGER,
                            (u_char *) &socketFamily,
                            sizeof(socketFamily));

  snmp_varlist_add_variable(&varList,
                            socketProtocolOID,
                            OID_LENGTH(socketProtocolOID),
                            ASN_INTEGER,
                            (u_char *) &socketProtocol,
                            sizeof(socketProtocol));

  snmp_varlist_add_variable(&varList,
                            fromAddressOID,
                            OID_LENGTH(fromAddressOID),
                            ASN_OCTET_STR,
                            remote.c_str(),
                            remote.size());

  snmp_varlist_add_variable(&varList,
                            toAddressOID,
                            OID_LENGTH(toAddressOID),
                            ASN_OCTET_STR,
                            local.c_str(),
                            local.size());

  snmp_varlist_add_variable(&varList,
                            queryTypeOID,
                            OID_LENGTH(queryTypeOID),
                            ASN_INTEGER,
                            (u_char *) &queryType,
                            sizeof(queryType));

  snmp_varlist_add_variable(&varList,
                            querySizeOID,
                            OID_LENGTH(querySizeOID),
                            ASN_UNSIGNED,
                            (u_char *) &querySize,
                            sizeof(querySize));

  snmp_varlist_add_variable(&varList,
                            queryIDOID,
                            OID_LENGTH(queryIDOID),
                            ASN_UNSIGNED,
                            (u_char *) &queryID,
                            sizeof(queryID));

  snmp_varlist_add_variable(&varList,
                            qNameOID,
                            OID_LENGTH(qNameOID),
                            ASN_OCTET_STR,
                            qname.c_str(),
                            qname.size());

  snmp_varlist_add_variable(&varList,
                            qClassOID,
                            OID_LENGTH(qClassOID),
                            ASN_UNSIGNED,
                            (u_char *) &qClass,
                            sizeof(qClass));

  snmp_varlist_add_variable(&varList,
                            qTypeOID,
                            OID_LENGTH(qTypeOID),
                            ASN_UNSIGNED,
                            (u_char *) &qType,
                            sizeof(qType));

  snmp_varlist_add_variable(&varList,
                            trapReasonOID,
                            OID_LENGTH(trapReasonOID),
                            ASN_OCTET_STR,
                            reason.c_str(),
                            reason.size());

  return sendTrap(d_trapPipe[1], varList);
#else
  return true;
#endif /* HAVE_NET_SNMP */
}

DNSDistSNMPAgent::DNSDistSNMPAgent(const std::string& name, const std::string& masterSocket): SNMPAgent(name, masterSocket)
{
#ifdef HAVE_NET_SNMP

  registerCounter64Stat("queries", queriesOID, OID_LENGTH(queriesOID), &g_stats.queries);
  registerCounter64Stat("responses", responsesOID, OID_LENGTH(responsesOID), &g_stats.responses);
  registerCounter64Stat("servfailResponses", servfailResponsesOID, OID_LENGTH(servfailResponsesOID), &g_stats.servfailResponses);
  registerCounter64Stat("aclDrops", aclDropsOID, OID_LENGTH(aclDropsOID), &g_stats.aclDrops);
  registerCounter64Stat("ruleDrop", ruleDropOID, OID_LENGTH(ruleDropOID), &g_stats.ruleDrop);
  registerCounter64Stat("ruleNXDomain", ruleNXDomainOID, OID_LENGTH(ruleNXDomainOID), &g_stats.ruleNXDomain);
  registerCounter64Stat("ruleRefused", ruleRefusedOID, OID_LENGTH(ruleRefusedOID), &g_stats.ruleRefused);
  registerCounter64Stat("ruleServFail", ruleServFailOID, OID_LENGTH(ruleServFailOID), &g_stats.ruleServFail);
  registerCounter64Stat("selfAnswered", selfAnsweredOID, OID_LENGTH(selfAnsweredOID), &g_stats.selfAnswered);
  registerCounter64Stat("downstreamTimeouts", downstreamTimeoutsOID, OID_LENGTH(downstreamTimeoutsOID), &g_stats.downstreamTimeouts);
  registerCounter64Stat("downstreamSendErrors", downstreamSendErrorsOID, OID_LENGTH(downstreamSendErrorsOID), &g_stats.downstreamSendErrors);
  registerCounter64Stat("truncFail", truncFailOID, OID_LENGTH(truncFailOID), &g_stats.truncFail);
  registerCounter64Stat("noPolicy", noPolicyOID, OID_LENGTH(noPolicyOID), &g_stats.noPolicy);
  registerCounter64Stat("latency0_1", latency0_1OID, OID_LENGTH(latency0_1OID), &g_stats.latency0_1);
  registerCounter64Stat("latency1_10", latency1_10OID, OID_LENGTH(latency1_10OID), &g_stats.latency1_10);
  registerCounter64Stat("latency10_50", latency10_50OID, OID_LENGTH(latency10_50OID), &g_stats.latency10_50);
  registerCounter64Stat("latency50_100", latency50_100OID, OID_LENGTH(latency50_100OID), &g_stats.latency50_100);
  registerCounter64Stat("latency100_1000", latency100_1000OID, OID_LENGTH(latency100_1000OID), &g_stats.latency100_1000);
  registerCounter64Stat("latencySlow", latencySlowOID, OID_LENGTH(latencySlowOID), &g_stats.latencySlow);
  registerCounter64Stat("nonCompliantQueries", nonCompliantQueriesOID, OID_LENGTH(nonCompliantQueriesOID), &g_stats.nonCompliantQueries);
  registerCounter64Stat("nonCompliantResponses", nonCompliantResponsesOID, OID_LENGTH(nonCompliantResponsesOID), &g_stats.nonCompliantResponses);
  registerCounter64Stat("rdQueries", rdQueriesOID, OID_LENGTH(rdQueriesOID), &g_stats.rdQueries);
  registerCounter64Stat("emptyQueries", emptyQueriesOID, OID_LENGTH(emptyQueriesOID), &g_stats.emptyQueries);
  registerCounter64Stat("cacheHits", cacheHitsOID, OID_LENGTH(cacheHitsOID), &g_stats.cacheHits);
  registerCounter64Stat("cacheMisses", cacheMissesOID, OID_LENGTH(cacheMissesOID), &g_stats.cacheMisses);
  registerCounter64Stat("dynBlocked", dynBlockedOID, OID_LENGTH(dynBlockedOID), &g_stats.dynBlocked);
  registerFloatStat("latencyAvg100", latencyAvg100OID, OID_LENGTH(latencyAvg100OID), &g_stats.latencyAvg100);
  registerFloatStat("latencyAvg1000", latencyAvg1000OID, OID_LENGTH(latencyAvg1000OID), &g_stats.latencyAvg1000);
  registerFloatStat("latencyAvg10000", latencyAvg10000OID, OID_LENGTH(latencyAvg10000OID), &g_stats.latencyAvg10000);
  registerFloatStat("latencyAvg1000000", latencyAvg1000000OID, OID_LENGTH(latencyAvg1000000OID), &g_stats.latencyAvg1000000);
  registerGauge64Stat("uptime", uptimeOID, OID_LENGTH(uptimeOID), &uptimeOfProcess);
  registerGauge64Stat("specialMemoryUsage", specialMemoryUsageOID, OID_LENGTH(specialMemoryUsageOID), &getSpecialMemoryUsage);
  registerGauge64Stat("cpuUserMSec", cpuUserMSecOID, OID_LENGTH(cpuUserMSecOID), &getCPUTimeUser);
  registerGauge64Stat("cpuSysMSec", cpuSysMSecOID, OID_LENGTH(cpuSysMSecOID), &getCPUTimeSystem);
  registerGauge64Stat("fdUsage", fdUsageOID, OID_LENGTH(fdUsageOID), &getOpenFileDescriptors);
  registerGauge64Stat("dynBlockedNMGSize", dynBlockedNMGSizeOID, OID_LENGTH(dynBlockedNMGSizeOID), [](const std::string&) { return g_dynblockNMG.getLocal()->size(); });
  registerGauge64Stat("securityStatus", securityStatusOID, OID_LENGTH(securityStatusOID), [](const std::string&) { return g_stats.securityStatus.load(); });
  registerGauge64Stat("realMemoryUsage", realMemoryUsageOID, OID_LENGTH(realMemoryUsageOID), &getRealMemoryUsage);


  netsnmp_table_registration_info* table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
  netsnmp_table_helper_add_indexes(table_info,
                                   ASN_GAUGE,  /* index: backendId */
                                   0);
  table_info->min_column = COLUMN_BACKENDNAME;
  table_info->max_column = COLUMN_BACKENDORDER;
  netsnmp_iterator_info* iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
  iinfo->get_first_data_point = backendStatTable_get_first_data_point;
  iinfo->get_next_data_point = backendStatTable_get_next_data_point;
  iinfo->table_reginfo = table_info;

  netsnmp_register_table_iterator(netsnmp_create_handler_registration("backendStatTable",
                                                                      backendStatTable_handler,
                                                                      backendStatTableOID,
                                                                      OID_LENGTH(backendStatTableOID),
                                                                      HANDLER_CAN_RONLY),
                                  iinfo);

#endif /* HAVE_NET_SNMP */
}
