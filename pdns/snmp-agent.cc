#include "snmp-agent.hh"
#include "misc.hh"
#include "threadname.hh"
#ifdef RECURSOR
#include "logger.hh"
#else
#include "dolog.hh"
#endif

#ifdef HAVE_NET_SNMP

#ifndef HAVE_SNMP_SELECT_INFO2
/* that's terrible, because it means we are going to have trouble with large
   FD numbers at some point.. */
# define netsnmp_large_fd_set fd_set
# define snmp_read2 snmp_read
# define snmp_select_info2 snmp_select_info
# define netsnmp_large_fd_set_init(...)
# define netsnmp_large_fd_set_cleanup(...)
# define NETSNMP_LARGE_FD_SET FD_SET
# define NETSNMP_LARGE_FD_CLR FD_CLR
# define NETSNMP_LARGE_FD_ZERO FD_ZERO
# define NETSNMP_LARGE_FD_ISSET FD_ISSET
#else
# include <net-snmp/library/large_fd_set.h>
#endif

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

void SNMPAgent::handleTrapsEvent()
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

void SNMPAgent::handleSNMPQueryEvent(int fd)
{
  netsnmp_large_fd_set fdset;
  netsnmp_large_fd_set_init(&fdset, FD_SETSIZE);
  NETSNMP_LARGE_FD_ZERO(&fdset);
  NETSNMP_LARGE_FD_SET(fd, &fdset);
  snmp_read2(&fdset);
}

void SNMPAgent::handleTrapsCB(int fd, FDMultiplexer::funcparam_t& var)
{
  SNMPAgent** agent = boost::any_cast<SNMPAgent*>(&var);
  if (!agent || !*agent)
    throw std::runtime_error("Invalid value received in SNMP trap callback");

  (*agent)->handleTrapsEvent();
}

void SNMPAgent::handleSNMPQueryCB(int fd, FDMultiplexer::funcparam_t& var)
{
  SNMPAgent** agent = boost::any_cast<SNMPAgent*>(&var);
  if (!agent || !*agent)
    throw std::runtime_error("Invalid value received in SNMP trap callback");

  (*agent)->handleSNMPQueryEvent(fd);
}

#endif /* HAVE_NET_SNMP */

void SNMPAgent::worker()
{
#ifdef HAVE_NET_SNMP
  FDMultiplexer* mplexer = FDMultiplexer::getMultiplexerSilent();
  if (mplexer == nullptr) {
    throw std::runtime_error("No FD multiplexer found for the SNMP agent!");
  }

#ifdef RECURSOR
  string threadName = "pdns-r/SNMP";
#else
  string threadName = "dnsdist/SNMP";
#endif
  setThreadName(threadName);

  int maxfd = 0;
  int block = 1;
  netsnmp_large_fd_set fdset;
  struct timeval timeout = { 0, 0 };
  struct timeval now;

  /* we want to be notified if a trap is waiting
   to be sent */
  mplexer->addReadFD(d_trapPipe[0], &handleTrapsCB, this);

  while(true) {
    netsnmp_large_fd_set_init(&fdset, FD_SETSIZE);
    NETSNMP_LARGE_FD_ZERO(&fdset);

    block = 1;
    timeout = { 0, 0 };
    snmp_select_info2(&maxfd, &fdset, &timeout, &block);

    for (int fd = 0; fd < maxfd; fd++) {
      if (NETSNMP_LARGE_FD_ISSET(fd, &fdset)) {
        mplexer->addReadFD(fd, &handleSNMPQueryCB, this);
      }
    }

    /* run updates now */
    int res = mplexer->run(&now, (timeout.tv_sec * 1000) + (timeout.tv_usec / 1000));

    /* we handle timeouts here, the rest has already been handled by callbacks */
    if (res == 0) {
      snmp_timeout();
      run_alarms();
    }

    for (int fd = 0; fd < maxfd; fd++) {
      if (NETSNMP_LARGE_FD_ISSET(fd, &fdset)) {
        try {
          mplexer->removeReadFD(fd);
        }
        catch(const FDMultiplexerException& e) {
          /* we might get an exception when removing a closed file descriptor,
             just ignore it */
        }
      }
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

  /* we use select() so don't use SIGALARM to handle alarms.
     Note that we need to handle alarms for automatic reconnection
     to the master to work.
  */
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                         NETSNMP_DS_LIB_ALARM_DONT_USE_SIG,
                         1);

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
