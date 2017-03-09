#include "snmp-agent.hh"
#include "misc.hh"

#ifdef HAVE_NET_SNMP

const oid SNMPAgent::snmpTrapOID[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
const size_t SNMPAgent::snmpTrapOIDLen = OID_LENGTH(SNMPAgent::snmpTrapOID);

int SNMPAgent::setCounter64Value(netsnmp_request_info* request,
                                 uint64_t value)
{
  struct counter64 val64;
  val64.high = value >> 32;
  val64.low = value & 0xffffffff;
  snmp_set_var_typed_value(request->requestvb,
                           ASN_COUNTER64,
                           &val64,
                           sizeof(val64));
  return SNMP_ERR_NOERROR;
}

bool SNMPAgent::sendTrap(int fd,
                         netsnmp_variable_list* varList)
{
  ssize_t written = write(fd, &varList, sizeof(varList));

  if (written != sizeof(varList)) {
    snmp_free_varbind(varList);
    return false;
  }
  return true;
}

void SNMPAgent::handleTraps()
{
  netsnmp_variable_list* varList = nullptr;
  ssize_t got = 0;

  do {
    got = read(d_trapPipe[0], &varList, sizeof(varList));

    if (got == sizeof(varList)) {
      send_v2trap(varList);
      snmp_free_varbind(varList);
    }
  }
  while (got > 0);
}
#endif /* HAVE_NET_SNMP */

void SNMPAgent::worker()
{
#ifdef HAVE_NET_SNMP
  int numfds = 0;
  int block = 1;
  fd_set fdset;
  struct timeval timeout = { 0, 0 };

  while(true) {
    numfds = FD_SETSIZE;

    FD_ZERO(&fdset);
    FD_SET(d_trapPipe[0], &fdset);
    snmp_select_info(&numfds, &fdset, &timeout, &block);

    int res = select(FD_SETSIZE, &fdset, NULL, NULL, NULL);

    if (res == 2) {
      FD_CLR(d_trapPipe[0], &fdset);
      snmp_read(&fdset);
      handleTraps();
    }
    else if (res == 1)
    {
      if (FD_ISSET(d_trapPipe[0], &fdset)) {
        handleTraps();
      } else {
        snmp_read(&fdset);
      }
    }
    else if (res == 0) {
      snmp_timeout();
    }
  }
#endif /* HAVE_NET_SNMP */
}

SNMPAgent::SNMPAgent(const std::string& name, const std::string& masterSocket)
{
#ifdef HAVE_NET_SNMP
  netsnmp_enable_subagent();
  snmp_disable_log();
  if (!masterSocket.empty()) {
    netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                          NETSNMP_DS_AGENT_X_SOCKET,
                          masterSocket.c_str());
  }
  /* no need to load any MIBS,
     and it causes import errors if some modules are not present */
  setenv("MIBS", "", 1);

  init_agent(name.c_str());
  init_snmp(name.c_str());

  if (pipe(d_trapPipe) < 0)
    unixDie("Creating pipe");

  if (!setNonBlocking(d_trapPipe[0])) {
    close(d_trapPipe[0]);
    close(d_trapPipe[1]);
    unixDie("Setting pipe non-blocking");
  }

  if (!setNonBlocking(d_trapPipe[1])) {
    close(d_trapPipe[0]);
    close(d_trapPipe[1]);
    unixDie("Setting pipe non-blocking");
  }

#endif /* HAVE_NET_SNMP */
}
