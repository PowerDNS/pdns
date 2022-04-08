#pragma once
#include "config.h"

#include <string>
#include <thread>
#include <unistd.h>

#ifdef HAVE_NET_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/definitions.h>
#include <net-snmp/types.h>
#include <net-snmp/utilities.h>
#include <net-snmp/config_api.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#undef INET6 /* SRSLY? */
#endif /* HAVE_NET_SNMP */

#include "mplexer.hh"
#include "channel.hh"

class SNMPAgent
{
public:
  SNMPAgent(const std::string& name, const std::string& daemonSocket);
  virtual ~SNMPAgent()
  {
  }

  void run()
  {
#ifdef HAVE_NET_SNMP
  d_thread = std::thread(&SNMPAgent::worker, this);
  d_thread.detach();
#endif /* HAVE_NET_SNMP */
  }

#ifdef HAVE_NET_SNMP
  static int setCounter64Value(netsnmp_request_info* request,
                               uint64_t value);
#endif /* HAVE_NET_SNMP */
protected:
#ifdef HAVE_NET_SNMP
  /* OID for snmpTrapOID.0 */
  static const oid snmpTrapOID[];
  static const size_t snmpTrapOIDLen;

  static bool sendTrap(pdns::channel::Sender<netsnmp_variable_list, void(*)(netsnmp_variable_list*)>& sender,
                       netsnmp_variable_list* varList);

  pdns::channel::Sender<netsnmp_variable_list, void(*)(netsnmp_variable_list*)> d_sender;
  pdns::channel::Receiver<netsnmp_variable_list, void(*)(netsnmp_variable_list*)> d_receiver;
#endif /* HAVE_NET_SNMP */
private:
  void worker();
  static void handleTrapsCB(int fd, FDMultiplexer::funcparam_t& var);
  static void handleSNMPQueryCB(int fd, FDMultiplexer::funcparam_t& var);
  void handleTrapsEvent();
  void handleSNMPQueryEvent(int fd);

  std::thread d_thread;
};
