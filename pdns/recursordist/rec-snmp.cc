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

#include "rec-oids-gen.h"

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
    g_slog->withName("snmp")->info(Logr::Error, "Invalid OID for SNMP Counter64 statistic", "name", Logging::Loggable(name));
    return;
  }

  if (s_statsMap.find(statOID.at(statOID.size() - 1)) != s_statsMap.end()) {
    g_slog->withName("snmp")->info(Logr::Error, "OID for SNMP Counter64 statistic has already been registered", "name", Logging::Loggable(name));
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

#include "rec-snmp-gen.h"

#endif /* HAVE_NET_SNMP */
}
