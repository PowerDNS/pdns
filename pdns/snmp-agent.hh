#ifndef SNMP_AGENT_HH
#define SNMP_AGENT_HH

#include "config.h"

#include <string>
#include <thread>
#include <unistd.h>

#ifdef HAVE_NET_SNMP
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#undef INET6 /* SRSLY? */
#endif /* HAVE_NET_SNMP */

class SNMPAgent
{
public:
  SNMPAgent(const std::string& name, const std::string& masterSocket);
  virtual ~SNMPAgent()
  {
#ifdef HAVE_NET_SNMP
    close(d_trapPipe[0]);
    close(d_trapPipe[1]);
#endif /* HAVE_NET_SNMP */
  }

  void run()
  {
#ifdef HAVE_NET_SNMP
  d_thread = std::move(std::thread(&SNMPAgent::worker, this));
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

  static bool sendTrap(int fd,
                       netsnmp_variable_list* varList);

  void handleTraps();

  int d_trapPipe[2] = { -1, -1};
#endif /* HAVE_NET_SNMP */
private:
  void worker();

  std::thread d_thread;
};

#endif /* SNMP_AGENT_HH */
