#include "snmp-agent.hh"
#include "misc.hh"
#include "threadname.hh"
#ifdef RECURSOR
#include "logger.hh"
#else
#include "dolog.hh"
#endif

#ifdef HAVE_NET_SNMP

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/definitions.h>
#include <net-snmp/types.h>
#include <net-snmp/utilities.h>
#include <net-snmp/config_api.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#undef INET6 /* SRSLY? */

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

static const std::array<oid, 11> s_snmpTrapOID = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };

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

void SNMPAgent::addSNMPTrapOID(netsnmp_variable_list** varList, const void* value, size_t len)
{
  snmp_varlist_add_variable(varList,
                            s_snmpTrapOID.data(),
                            s_snmpTrapOID.size(),
                            ASN_OBJECT_ID,
                            value,
                            len);
}

bool SNMPAgent::sendTrap(pdns::channel::Sender<netsnmp_variable_list, void(*)(netsnmp_variable_list*)>& sender,
                         netsnmp_variable_list* varList)
{
  try  {
    auto obj = std::unique_ptr<netsnmp_variable_list, void(*)(netsnmp_variable_list*)>(varList, snmp_free_varbind);
    return sender.send(std::move(obj));
  }
  catch (...) {
    return false;
  }
}

void SNMPAgent::handleTrapsEvent()
{
  try {
    while (true) {
      auto obj = d_receiver.receive(snmp_free_varbind);
      if (!obj) {
        break;
      }
      send_v2trap(obj->get());
    }
  }
  catch (const std::exception& e) {
  }
}

void SNMPAgent::handleSNMPQueryEvent(int fd)
{
  netsnmp_large_fd_set fdset;
  netsnmp_large_fd_set_init(&fdset, FD_SETSIZE);
  NETSNMP_LARGE_FD_ZERO(&fdset);
  NETSNMP_LARGE_FD_SET(fd, &fdset);
  snmp_read2(&fdset);
}

void SNMPAgent::handleTrapsCB(int /* fd */, FDMultiplexer::funcparam_t& var)
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
  string threadName = "rec/snmp";
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
  mplexer->addReadFD(d_receiver.getDescriptor(), &handleTrapsCB, this);

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

SNMPAgent::SNMPAgent([[maybe_unused]] const std::string& name, [[maybe_unused]] const std::string& daemonSocket)
{
#ifdef HAVE_NET_SNMP
  netsnmp_enable_subagent();
  snmp_disable_log();
  if (!daemonSocket.empty()) {
    netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
                          NETSNMP_DS_AGENT_X_SOCKET,
                          daemonSocket.c_str());
  }
  /* no need to load any MIBS,
     and it causes import errors if some modules are not present */
  setenv("MIBS", "", 1);

  init_agent(name.c_str());

  /* we use select() so don't use SIGALARM to handle alarms.
     Note that we need to handle alarms for automatic reconnection
     to the daemon to work.
  */
  netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                         NETSNMP_DS_LIB_ALARM_DONT_USE_SIG,
                         1);

  init_snmp(name.c_str());

  auto [sender, receiver] = pdns::channel::createObjectQueue<netsnmp_variable_list, void(*)(netsnmp_variable_list*)>();
  d_sender = std::move(sender);
  d_receiver = std::move(receiver);
#endif /* HAVE_NET_SNMP */
}
