
#include "dnsdist-snmp.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-metrics.hh"
#include "dolog.hh"

std::unique_ptr<DNSDistSNMPAgent> g_snmpAgent{nullptr};

#ifdef HAVE_NET_SNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/definitions.h>
#include <net-snmp/types.h>
#include <net-snmp/utilities.h>
#include <net-snmp/config_api.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#undef INET6 /* SRSLY? */

#define DNSDIST_OID 1, 3, 6, 1, 4, 1, 43315, 3
#define DNSDIST_STATS_OID DNSDIST_OID, 1
#define DNSDIST_STATS_TABLE_OID DNSDIST_OID, 2
#define DNSDIST_TRAPS_OID DNSDIST_OID, 10, 0
#define DNSDIST_TRAP_OBJECTS_OID DNSDIST_OID, 11

using OIDStat = std::array<oid, 10>;
using OIDTrap = std::array<oid, 11>;
using OIDTrapObject = std::array<oid, 11>;
using OIDStatTable = std::array<oid, 12>;

static const OIDStat queriesOID{DNSDIST_STATS_OID, 1};
static const OIDStat responsesOID{DNSDIST_STATS_OID, 2};
static const OIDStat servfailResponsesOID{DNSDIST_STATS_OID, 3};
static const OIDStat aclDropsOID{DNSDIST_STATS_OID, 4};
// 5 was BlockFilter, removed in 1.2.0
static const OIDStat ruleDropOID{DNSDIST_STATS_OID, 6};
static const OIDStat ruleNXDomainOID{DNSDIST_STATS_OID, 7};
static const OIDStat ruleRefusedOID{DNSDIST_STATS_OID, 8};
static const OIDStat selfAnsweredOID{DNSDIST_STATS_OID, 9};
static const OIDStat downstreamTimeoutsOID{DNSDIST_STATS_OID, 10};
static const OIDStat downstreamSendErrorsOID{DNSDIST_STATS_OID, 11};
static const OIDStat truncFailOID{DNSDIST_STATS_OID, 12};
static const OIDStat noPolicyOID{DNSDIST_STATS_OID, 13};
static const OIDStat latency0_1OID{DNSDIST_STATS_OID, 14};
static const OIDStat latency1_10OID{DNSDIST_STATS_OID, 15};
static const OIDStat latency10_50OID{DNSDIST_STATS_OID, 16};
static const OIDStat latency50_100OID{DNSDIST_STATS_OID, 17};
static const OIDStat latency100_1000OID{DNSDIST_STATS_OID, 18};
static const OIDStat latencySlowOID{DNSDIST_STATS_OID, 19};
static const OIDStat latencyAvg100OID{DNSDIST_STATS_OID, 20};
static const OIDStat latencyAvg1000OID{DNSDIST_STATS_OID, 21};
static const OIDStat latencyAvg10000OID{DNSDIST_STATS_OID, 22};
static const OIDStat latencyAvg1000000OID{DNSDIST_STATS_OID, 23};
static const OIDStat uptimeOID{DNSDIST_STATS_OID, 24};
static const OIDStat realMemoryUsageOID{DNSDIST_STATS_OID, 25};
static const OIDStat nonCompliantQueriesOID{DNSDIST_STATS_OID, 26};
static const OIDStat nonCompliantResponsesOID{DNSDIST_STATS_OID, 27};
static const OIDStat rdQueriesOID{DNSDIST_STATS_OID, 28};
static const OIDStat emptyQueriesOID{DNSDIST_STATS_OID, 29};
static const OIDStat cacheHitsOID{DNSDIST_STATS_OID, 30};
static const OIDStat cacheMissesOID{DNSDIST_STATS_OID, 31};
static const OIDStat cpuUserMSecOID{DNSDIST_STATS_OID, 32};
static const OIDStat cpuSysMSecOID{DNSDIST_STATS_OID, 33};
static const OIDStat fdUsageOID{DNSDIST_STATS_OID, 34};
static const OIDStat dynBlockedOID{DNSDIST_STATS_OID, 35};
static const OIDStat dynBlockedNMGSizeOID{DNSDIST_STATS_OID, 36};
static const OIDStat ruleServFailOID{DNSDIST_STATS_OID, 37};
static const OIDStat securityStatusOID{DNSDIST_STATS_OID, 38};
static const OIDStat specialMemoryUsageOID{DNSDIST_STATS_OID, 39};
static const OIDStat ruleTruncatedOID{DNSDIST_STATS_OID, 40};

static std::unordered_map<oid, dnsdist::metrics::Stats::entry_t> s_statsMap;

/* We are never called for a GETNEXT if it's registered as a
   "instance", as it's "magically" handled for us.  */
/* a instance handler also only hands us one request at a time, so
   we don't need to loop over a list of requests; we'll only get one. */

static int handleCounter64Stats(netsnmp_mib_handler* handler,
                                netsnmp_handler_registration* reginfo,
                                netsnmp_agent_request_info* reqinfo,
                                netsnmp_request_info* requests)
{
  (void)handler;
  if (reqinfo->mode != MODE_GET) {
    return SNMP_ERR_GENERR;
  }

  if (reginfo->rootoid_len != OID_LENGTH(queriesOID) + 1) {
    return SNMP_ERR_GENERR;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): net-snmp API
  const auto& stIt = s_statsMap.find(reginfo->rootoid[reginfo->rootoid_len - 2]);
  if (stIt == s_statsMap.end()) {
    return SNMP_ERR_GENERR;
  }

  if (const auto& val = std::get_if<pdns::stat_t*>(&stIt->second)) {
    return DNSDistSNMPAgent::setCounter64Value(requests, (*val)->load());
  }

  return SNMP_ERR_GENERR;
}

static void registerCounter64Stat(const char* name, const OIDStat& statOID, pdns::stat_t* ptr)
{
  if (statOID.size() != OID_LENGTH(queriesOID)) {
    errlog("Invalid OID for SNMP Counter64 statistic %s", name);
    return;
  }

  if (s_statsMap.find(statOID.at(statOID.size() - 1)) != s_statsMap.end()) {
    errlog("OID for SNMP Counter64 statistic %s has already been registered", name);
    return;
  }

  s_statsMap[statOID.at(statOID.size() - 1)] = ptr;
  netsnmp_register_scalar(netsnmp_create_handler_registration(name,
                                                              handleCounter64Stats,
                                                              statOID.data(),
                                                              statOID.size(),
                                                              HANDLER_CAN_RONLY));
}

static int handleFloatStats(netsnmp_mib_handler* handler,
                            netsnmp_handler_registration* reginfo,
                            netsnmp_agent_request_info* reqinfo,
                            netsnmp_request_info* requests)
{
  (void)handler;
  if (reqinfo->mode != MODE_GET) {
    return SNMP_ERR_GENERR;
  }

  if (reginfo->rootoid_len != OID_LENGTH(queriesOID) + 1) {
    return SNMP_ERR_GENERR;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): net-snmp API
  const auto& stIt = s_statsMap.find(reginfo->rootoid[reginfo->rootoid_len - 2]);
  if (stIt == s_statsMap.end()) {
    return SNMP_ERR_GENERR;
  }

  if (const auto& val = std::get_if<pdns::stat_double_t*>(&stIt->second)) {
    std::string str(std::to_string((*val)->load()));
    snmp_set_var_typed_value(requests->requestvb,
                             ASN_OCTET_STR,
                             str.c_str(),
                             str.size());
    return SNMP_ERR_NOERROR;
  }

  return SNMP_ERR_GENERR;
}

static void registerFloatStat(const char* name, const OIDStat& statOID, pdns::stat_double_t* ptr)
{
  if (statOID.size() != OID_LENGTH(queriesOID)) {
    errlog("Invalid OID for SNMP Float statistic %s", name);
    return;
  }

  if (s_statsMap.find(statOID.at(statOID.size() - 1)) != s_statsMap.end()) {
    errlog("OID for SNMP Float statistic %s has already been registered", name);
    return;
  }

  s_statsMap[statOID.at(statOID.size() - 1)] = ptr;
  netsnmp_register_scalar(netsnmp_create_handler_registration(name,
                                                              handleFloatStats,
                                                              statOID.data(),
                                                              statOID.size(),
                                                              HANDLER_CAN_RONLY));
}

static int handleGauge64Stats(netsnmp_mib_handler* handler,
                              netsnmp_handler_registration* reginfo,
                              netsnmp_agent_request_info* reqinfo,
                              netsnmp_request_info* requests)
{
  (void)handler;
  if (reqinfo->mode != MODE_GET) {
    return SNMP_ERR_GENERR;
  }

  if (reginfo->rootoid_len != OID_LENGTH(queriesOID) + 1) {
    return SNMP_ERR_GENERR;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): net-snmp API
  const auto& stIt = s_statsMap.find(reginfo->rootoid[reginfo->rootoid_len - 2]);
  if (stIt == s_statsMap.end()) {
    return SNMP_ERR_GENERR;
  }

  std::string str;
  uint64_t value = (*std::get_if<dnsdist::metrics::Stats::statfunction_t>(&stIt->second))(str);
  return DNSDistSNMPAgent::setCounter64Value(requests, value);
}

static void registerGauge64Stat(const char* name, const OIDStat& statOID, const dnsdist::metrics::Stats::statfunction_t& ptr)
{
  if (statOID.size() != OID_LENGTH(queriesOID)) {
    errlog("Invalid OID for SNMP Gauge64 statistic %s", name);
    return;
  }

  if (s_statsMap.find(statOID.at(statOID.size() - 1)) != s_statsMap.end()) {
    errlog("OID for SNMP Gauge64 statistic %s has already been registered", name);
    return;
  }

  s_statsMap[statOID.at(statOID.size() - 1)] = ptr;
  netsnmp_register_scalar(netsnmp_create_handler_registration(name,
                                                              handleGauge64Stats,
                                                              statOID.data(),
                                                              statOID.size(),
                                                              HANDLER_CAN_RONLY));
}

/* column number definitions for table backendStatTable */
static constexpr unsigned int COLUMN_BACKENDNAME = 2;
static constexpr unsigned int COLUMN_BACKENDLATENCY = 3;
static constexpr unsigned int COLUMN_BACKENDWEIGHT = 4;
static constexpr unsigned int COLUMN_BACKENDOUTSTANDING = 5;
static constexpr unsigned int COLUMN_BACKENDQPSLIMIT = 6;
static constexpr unsigned int COLUMN_BACKENDREUSED = 7;
static constexpr unsigned int COLUMN_BACKENDSTATE = 8;
static constexpr unsigned int COLUMN_BACKENDADDRESS = 9;
static constexpr unsigned int COLUMN_BACKENDPOOLS = 10;
static constexpr unsigned int COLUMN_BACKENDQPS = 11;
static constexpr unsigned int COLUMN_BACKENDQUERIES = 12;
static constexpr unsigned int COLUMN_BACKENDORDER = 13;

static const std::array<oid, 9> backendStatTableOID{DNSDIST_STATS_TABLE_OID};
static const OIDStatTable backendNameOID{DNSDIST_STATS_TABLE_OID, 1, 2};
static const OIDStatTable backendStateOID{DNSDIST_STATS_TABLE_OID, 1, 8};
static const OIDStatTable backendAddressOID{DNSDIST_STATS_TABLE_OID, 1, 9};

static const OIDTrapObject socketFamilyOID{DNSDIST_TRAP_OBJECTS_OID, 1, 0};
static const OIDTrapObject socketProtocolOID{DNSDIST_TRAP_OBJECTS_OID, 2, 0};
static const OIDTrapObject fromAddressOID{DNSDIST_TRAP_OBJECTS_OID, 3, 0};
static const OIDTrapObject toAddressOID{DNSDIST_TRAP_OBJECTS_OID, 4, 0};
static const OIDTrapObject queryTypeOID{DNSDIST_TRAP_OBJECTS_OID, 5, 0};
static const OIDTrapObject querySizeOID{DNSDIST_TRAP_OBJECTS_OID, 6, 0};
static const OIDTrapObject queryIDOID{DNSDIST_TRAP_OBJECTS_OID, 7, 0};
static const OIDTrapObject qNameOID{DNSDIST_TRAP_OBJECTS_OID, 8, 0};
static const OIDTrapObject qClassOID{DNSDIST_TRAP_OBJECTS_OID, 9, 0};
static const OIDTrapObject qTypeOID{DNSDIST_TRAP_OBJECTS_OID, 10, 0};
static const OIDTrapObject trapReasonOID{DNSDIST_TRAP_OBJECTS_OID, 11, 0};

static const OIDTrap backendStatusChangeTrapOID{DNSDIST_TRAPS_OID, 1};
static const OIDTrap actionTrapOID{DNSDIST_TRAPS_OID, 2};
static const OIDTrap customTrapOID{DNSDIST_TRAPS_OID, 3};

static servers_t s_servers;
static size_t s_currentServerIdx = 0;

static netsnmp_variable_list* backendStatTable_get_next_data_point(void** loop_context,
                                                                   void** my_data_context,
                                                                   netsnmp_variable_list* put_index_data,
                                                                   netsnmp_iterator_info* mydata)
{
  (void)loop_context;
  (void)mydata;
  if (s_currentServerIdx >= s_servers.size()) {
    return nullptr;
  }

  *my_data_context = (void*)(s_servers[s_currentServerIdx]).get();
  snmp_set_var_typed_integer(put_index_data, ASN_UNSIGNED, static_cast<long>(s_currentServerIdx));
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
  auto backends = dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends;
  s_servers.clear();
  s_servers.reserve(backends.size());
  for (auto& server : backends) {
    s_servers.push_back(std::move(server));
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
  (void)handler;
  (void)reginfo;
  netsnmp_request_info* request{nullptr};

  switch (reqinfo->mode) {
  case MODE_GET:
    for (request = requests; request != nullptr; request = request->next) {
      netsnmp_table_request_info* table_info = netsnmp_extract_table_info(request);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): net-snmp API
      const auto* server = reinterpret_cast<const DownstreamState*>(netsnmp_extract_iterator_context(request));
      if (server == nullptr) {
        continue;
      }

      switch (table_info->colnum) {
      case COLUMN_BACKENDNAME:
        snmp_set_var_typed_value(request->requestvb,
                                 ASN_OCTET_STR,
                                 server->getName().c_str(),
                                 server->getName().size());
        break;
      case COLUMN_BACKENDLATENCY:
        DNSDistSNMPAgent::setCounter64Value(request,
                                            static_cast<uint64_t>(server->getRelevantLatencyUsec() / 1000.0));
        break;
      case COLUMN_BACKENDWEIGHT:
        DNSDistSNMPAgent::setCounter64Value(request,
                                            server->d_config.d_weight);
        break;
      case COLUMN_BACKENDOUTSTANDING:
        DNSDistSNMPAgent::setCounter64Value(request,
                                            server->outstanding.load());
        break;
      case COLUMN_BACKENDQPSLIMIT:
        DNSDistSNMPAgent::setCounter64Value(request,
                                            server->getQPSLimit());
        break;
      case COLUMN_BACKENDREUSED:
        DNSDistSNMPAgent::setCounter64Value(request, server->reuseds.load());
        break;
      case COLUMN_BACKENDSTATE: {
        std::string state(server->getStatus());
        snmp_set_var_typed_value(request->requestvb,
                                 ASN_OCTET_STR,
                                 state.c_str(),
                                 state.size());
        break;
      }
      case COLUMN_BACKENDADDRESS: {
        std::string addr(server->d_config.remote.toStringWithPort());
        snmp_set_var_typed_value(request->requestvb,
                                 ASN_OCTET_STR,
                                 addr.c_str(),
                                 addr.size());
        break;
      }
      case COLUMN_BACKENDPOOLS: {
        std::string pools;
        for (const auto& pool : server->d_config.pools) {
          if (!pools.empty()) {
            pools += " ";
          }
          pools += pool;
        }
        snmp_set_var_typed_value(request->requestvb,
                                 ASN_OCTET_STR,
                                 pools.c_str(),
                                 pools.size());
        break;
      }
      case COLUMN_BACKENDQPS:
        DNSDistSNMPAgent::setCounter64Value(request, static_cast<uint64_t>(server->queryLoad.load()));
        break;
      case COLUMN_BACKENDQUERIES:
        DNSDistSNMPAgent::setCounter64Value(request, server->queries.load());
        break;
      case COLUMN_BACKENDORDER:
        DNSDistSNMPAgent::setCounter64Value(request, server->d_config.order);
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

bool DNSDistSNMPAgent::sendBackendStatusChangeTrap([[maybe_unused]] const DownstreamState& dss)
{
#ifdef HAVE_NET_SNMP
  const string backendAddress = dss.d_config.remote.toStringWithPort();
  const string backendStatus = dss.getStatus();
  netsnmp_variable_list* varList = nullptr;

  addSNMPTrapOID(&varList,
                 backendStatusChangeTrapOID.data(),
                 backendStatusChangeTrapOID.size() * sizeof(oid));

  snmp_varlist_add_variable(&varList,
                            backendNameOID.data(),
                            backendNameOID.size(),
                            ASN_OCTET_STR,
                            dss.getName().c_str(),
                            dss.getName().size());

  snmp_varlist_add_variable(&varList,
                            backendAddressOID.data(),
                            backendAddressOID.size(),
                            ASN_OCTET_STR,
                            backendAddress.c_str(),
                            backendAddress.size());

  snmp_varlist_add_variable(&varList,
                            backendStateOID.data(),
                            backendStateOID.size(),
                            ASN_OCTET_STR,
                            backendStatus.c_str(),
                            backendStatus.size());

  return sendTrap(d_sender, varList);
#else
  return true;
#endif /* HAVE_NET_SNMP */
}

bool DNSDistSNMPAgent::sendCustomTrap([[maybe_unused]] const std::string& reason)
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
#else
  return true;
#endif /* HAVE_NET_SNMP */
}

bool DNSDistSNMPAgent::sendDNSTrap([[maybe_unused]] const DNSQuestion& dnsQuestion, [[maybe_unused]] const std::string& reason)
{
#ifdef HAVE_NET_SNMP
  std::string local = dnsQuestion.ids.origDest.toString();
  std::string remote = dnsQuestion.ids.origRemote.toString();
  std::string qname = dnsQuestion.ids.qname.toStringNoDot();
  const uint32_t socketFamily = dnsQuestion.ids.origRemote.isIPv4() ? 1 : 2;
  const uint32_t socketProtocol = dnsQuestion.overTCP() ? 2 : 1;
  const uint32_t queryType = dnsQuestion.getHeader()->qr ? 2 : 1;
  const auto querySize = static_cast<uint32_t>(dnsQuestion.getData().size());
  const auto queryID = static_cast<uint32_t>(ntohs(dnsQuestion.getHeader()->id));
  const auto qType = static_cast<uint32_t>(dnsQuestion.ids.qtype);
  const auto qClass = static_cast<uint32_t>(dnsQuestion.ids.qclass);

  netsnmp_variable_list* varList = nullptr;

  addSNMPTrapOID(&varList,
                 actionTrapOID.data(),
                 actionTrapOID.size() * sizeof(oid));

  snmp_varlist_add_variable(&varList,
                            socketFamilyOID.data(),
                            socketFamilyOID.size(),
                            ASN_INTEGER,
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): net-snmp API
                            reinterpret_cast<const u_char*>(&socketFamily),
                            sizeof(socketFamily));

  snmp_varlist_add_variable(&varList,
                            socketProtocolOID.data(),
                            socketProtocolOID.size(),
                            ASN_INTEGER,
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): net-snmp API
                            reinterpret_cast<const u_char*>(&socketProtocol),
                            sizeof(socketProtocol));

  snmp_varlist_add_variable(&varList,
                            fromAddressOID.data(),
                            fromAddressOID.size(),
                            ASN_OCTET_STR,
                            remote.c_str(),
                            remote.size());

  snmp_varlist_add_variable(&varList,
                            toAddressOID.data(),
                            toAddressOID.size(),
                            ASN_OCTET_STR,
                            local.c_str(),
                            local.size());

  snmp_varlist_add_variable(&varList,
                            queryTypeOID.data(),
                            queryTypeOID.size(),
                            ASN_INTEGER,
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): net-snmp API
                            reinterpret_cast<const u_char*>(&queryType),
                            sizeof(queryType));

  snmp_varlist_add_variable(&varList,
                            querySizeOID.data(),
                            querySizeOID.size(),
                            ASN_UNSIGNED,
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): net-snmp API
                            reinterpret_cast<const u_char*>(&querySize),
                            sizeof(querySize));

  snmp_varlist_add_variable(&varList,
                            queryIDOID.data(),
                            queryIDOID.size(),
                            ASN_UNSIGNED,
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): net-snmp API
                            reinterpret_cast<const u_char*>(&queryID),
                            sizeof(queryID));

  snmp_varlist_add_variable(&varList,
                            qNameOID.data(),
                            qNameOID.size(),
                            ASN_OCTET_STR,
                            qname.c_str(),
                            qname.size());

  snmp_varlist_add_variable(&varList,
                            qClassOID.data(),
                            qClassOID.size(),
                            ASN_UNSIGNED,
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): net-snmp API
                            reinterpret_cast<const u_char*>(&qClass),
                            sizeof(qClass));

  snmp_varlist_add_variable(&varList,
                            qTypeOID.data(),
                            qTypeOID.size(),
                            ASN_UNSIGNED,
                            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): net-snmp API
                            reinterpret_cast<const u_char*>(&qType),
                            sizeof(qType));

  snmp_varlist_add_variable(&varList,
                            trapReasonOID.data(),
                            trapReasonOID.size(),
                            ASN_OCTET_STR,
                            reason.c_str(),
                            reason.size());

  return sendTrap(d_sender, varList);
#else
  return true;
#endif /* HAVE_NET_SNMP */
}

DNSDistSNMPAgent::DNSDistSNMPAgent(const std::string& name, const std::string& daemonSocket) :
  SNMPAgent(name, daemonSocket)
{
#ifdef HAVE_NET_SNMP

  registerCounter64Stat("queries", queriesOID, &dnsdist::metrics::g_stats.queries);
  registerCounter64Stat("responses", responsesOID, &dnsdist::metrics::g_stats.responses);
  registerCounter64Stat("servfailResponses", servfailResponsesOID, &dnsdist::metrics::g_stats.servfailResponses);
  registerCounter64Stat("aclDrops", aclDropsOID, &dnsdist::metrics::g_stats.aclDrops);
  registerCounter64Stat("ruleDrop", ruleDropOID, &dnsdist::metrics::g_stats.ruleDrop);
  registerCounter64Stat("ruleNXDomain", ruleNXDomainOID, &dnsdist::metrics::g_stats.ruleNXDomain);
  registerCounter64Stat("ruleRefused", ruleRefusedOID, &dnsdist::metrics::g_stats.ruleRefused);
  registerCounter64Stat("ruleServFail", ruleServFailOID, &dnsdist::metrics::g_stats.ruleServFail);
  registerCounter64Stat("ruleTruncated", ruleTruncatedOID, &dnsdist::metrics::g_stats.ruleTruncated);
  registerCounter64Stat("selfAnswered", selfAnsweredOID, &dnsdist::metrics::g_stats.selfAnswered);
  registerCounter64Stat("downstreamTimeouts", downstreamTimeoutsOID, &dnsdist::metrics::g_stats.downstreamTimeouts);
  registerCounter64Stat("downstreamSendErrors", downstreamSendErrorsOID, &dnsdist::metrics::g_stats.downstreamSendErrors);
  registerCounter64Stat("truncFail", truncFailOID, &dnsdist::metrics::g_stats.truncFail);
  registerCounter64Stat("noPolicy", noPolicyOID, &dnsdist::metrics::g_stats.noPolicy);
  registerCounter64Stat("latency0_1", latency0_1OID, &dnsdist::metrics::g_stats.latency0_1);
  registerCounter64Stat("latency1_10", latency1_10OID, &dnsdist::metrics::g_stats.latency1_10);
  registerCounter64Stat("latency10_50", latency10_50OID, &dnsdist::metrics::g_stats.latency10_50);
  registerCounter64Stat("latency50_100", latency50_100OID, &dnsdist::metrics::g_stats.latency50_100);
  registerCounter64Stat("latency100_1000", latency100_1000OID, &dnsdist::metrics::g_stats.latency100_1000);
  registerCounter64Stat("latencySlow", latencySlowOID, &dnsdist::metrics::g_stats.latencySlow);
  registerCounter64Stat("nonCompliantQueries", nonCompliantQueriesOID, &dnsdist::metrics::g_stats.nonCompliantQueries);
  registerCounter64Stat("nonCompliantResponses", nonCompliantResponsesOID, &dnsdist::metrics::g_stats.nonCompliantResponses);
  registerCounter64Stat("rdQueries", rdQueriesOID, &dnsdist::metrics::g_stats.rdQueries);
  registerCounter64Stat("emptyQueries", emptyQueriesOID, &dnsdist::metrics::g_stats.emptyQueries);
  registerCounter64Stat("cacheHits", cacheHitsOID, &dnsdist::metrics::g_stats.cacheHits);
  registerCounter64Stat("cacheMisses", cacheMissesOID, &dnsdist::metrics::g_stats.cacheMisses);
  registerCounter64Stat("dynBlocked", dynBlockedOID, &dnsdist::metrics::g_stats.dynBlocked);
  registerFloatStat("latencyAvg100", latencyAvg100OID, &dnsdist::metrics::g_stats.latencyAvg100);
  registerFloatStat("latencyAvg1000", latencyAvg1000OID, &dnsdist::metrics::g_stats.latencyAvg1000);
  registerFloatStat("latencyAvg10000", latencyAvg10000OID, &dnsdist::metrics::g_stats.latencyAvg10000);
  registerFloatStat("latencyAvg1000000", latencyAvg1000000OID, &dnsdist::metrics::g_stats.latencyAvg1000000);
  registerGauge64Stat("uptime", uptimeOID, &uptimeOfProcess);
  registerGauge64Stat("specialMemoryUsage", specialMemoryUsageOID, &getSpecialMemoryUsage);
  registerGauge64Stat("cpuUserMSec", cpuUserMSecOID, &getCPUTimeUser);
  registerGauge64Stat("cpuSysMSec", cpuSysMSecOID, &getCPUTimeSystem);
  registerGauge64Stat("fdUsage", fdUsageOID, &getOpenFileDescriptors);
  registerGauge64Stat("dynBlockedNMGSize", dynBlockedNMGSizeOID, [](const std::string&) { return dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(); });
  registerGauge64Stat("securityStatus", securityStatusOID, [](const std::string&) { return dnsdist::metrics::g_stats.securityStatus.load(); });
  registerGauge64Stat("realMemoryUsage", realMemoryUsageOID, &getRealMemoryUsage);

  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): net-snmp API
  auto* table_info = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
  netsnmp_table_helper_add_indexes(table_info,
                                   ASN_GAUGE, /* index: backendId */
                                   0);
  table_info->min_column = COLUMN_BACKENDNAME;
  table_info->max_column = COLUMN_BACKENDORDER;
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory): net-snmp API
  auto* iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
  iinfo->get_first_data_point = backendStatTable_get_first_data_point;
  iinfo->get_next_data_point = backendStatTable_get_next_data_point;
  iinfo->table_reginfo = table_info;

  netsnmp_register_table_iterator(netsnmp_create_handler_registration("backendStatTable",
                                                                      backendStatTable_handler,
                                                                      backendStatTableOID.data(),
                                                                      backendStatTableOID.size(),
                                                                      HANDLER_CAN_RONLY),
                                  iinfo);

#endif /* HAVE_NET_SNMP */
}
