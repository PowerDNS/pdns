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

#include <dirent.h>
#include <fstream>

// for OpenBSD, sys/socket.h needs to come before net/if.h
#include <sys/socket.h>
#include <net/if.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <thread>

#include "dnsdist.hh"
#include "dnsdist-console.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-healthchecks.hh"
#include "dnsdist-lua.hh"
#ifdef LUAJIT_VERSION
#include "dnsdist-lua-ffi.hh"
#endif /* LUAJIT_VERSION */
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-secpoll.hh"
#include "dnsdist-web.hh"

#include "base64.hh"
#include "dnswriter.hh"
#include "dolog.hh"
#include "lock.hh"
#include "sodcrypto.hh"

#ifdef HAVE_LIBSSL
#include "libssl.hh"
#endif

#include <boost/logic/tribool.hpp>
#include <boost/lexical_cast.hpp>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

using std::thread;

static boost::optional<std::vector<std::function<void(void)>>> g_launchWork = boost::none;

boost::tribool g_noLuaSideEffect;
static bool g_included{false};

/* this is a best effort way to prevent logging calls with no side-effects in the output of delta()
   Functions can declare setLuaNoSideEffect() and if nothing else does declare a side effect, or nothing
   has done so before on this invocation, this call won't be part of delta() output */
void setLuaNoSideEffect()
{
  if(g_noLuaSideEffect==false) // there has been a side effect already
    return;
  g_noLuaSideEffect=true;
}

void setLuaSideEffect()
{
  g_noLuaSideEffect=false;
}

bool getLuaNoSideEffect()
{
  if (g_noLuaSideEffect) {
    return true;
  }
  return false;
}

void resetLuaSideEffect()
{
  g_noLuaSideEffect = boost::logic::indeterminate;
}

typedef std::unordered_map<std::string, boost::variant<bool, int, std::string, std::vector<std::pair<int,int> >, std::vector<std::pair<int, std::string> >, std::map<std::string,std::string>  > > localbind_t;

static void parseLocalBindVars(boost::optional<localbind_t> vars, bool& reusePort, int& tcpFastOpenQueueSize, std::string& interface, std::set<int>& cpus, int& tcpListenQueueSize, size_t& maxInFlightQueriesPerConnection, size_t& tcpMaxConcurrentConnections)
{
  if (vars) {
    if (vars->count("reusePort")) {
      reusePort = boost::get<bool>((*vars)["reusePort"]);
    }
    if (vars->count("tcpFastOpenQueueSize")) {
      tcpFastOpenQueueSize = boost::get<int>((*vars)["tcpFastOpenQueueSize"]);
    }
    if (vars->count("tcpListenQueueSize")) {
      tcpListenQueueSize = boost::get<int>((*vars)["tcpListenQueueSize"]);
    }
    if (vars->count("maxConcurrentTCPConnections")) {
      tcpMaxConcurrentConnections = boost::get<int>((*vars)["maxConcurrentTCPConnections"]);
    }
    if (vars->count("maxInFlight")) {
      maxInFlightQueriesPerConnection = boost::get<int>((*vars)["maxInFlight"]);
    }
    if (vars->count("interface")) {
      interface = boost::get<std::string>((*vars)["interface"]);
    }
    if (vars->count("cpus")) {
      for (const auto& cpu : boost::get<std::vector<std::pair<int,int>>>((*vars)["cpus"])) {
        cpus.insert(cpu.second);
      }
    }
  }
}

#if defined(HAVE_DNS_OVER_TLS) || defined(HAVE_DNS_OVER_HTTPS)
static bool loadTLSCertificateAndKeys(const std::string& context, std::vector<std::pair<std::string, std::string>>& pairs, boost::variant<std::string, std::vector<std::pair<int,std::string>>> certFiles, boost::variant<std::string, std::vector<std::pair<int,std::string>>> keyFiles)
{
  if (certFiles.type() == typeid(std::string) && keyFiles.type() == typeid(std::string)) {
    auto certFile = boost::get<std::string>(certFiles);
    auto keyFile = boost::get<std::string>(keyFiles);
    pairs.clear();
    pairs.push_back({certFile, keyFile});
  }
  else if (certFiles.type() == typeid(std::vector<std::pair<int,std::string>>) && keyFiles.type() == typeid(std::vector<std::pair<int,std::string>>))
  {
    auto certFilesVect = boost::get<std::vector<std::pair<int,std::string>>>(certFiles);
    auto keyFilesVect = boost::get<std::vector<std::pair<int,std::string>>>(keyFiles);
    if (certFilesVect.size() == keyFilesVect.size()) {
      pairs.clear();
      for (size_t idx = 0; idx < certFilesVect.size(); idx++) {
        pairs.push_back({certFilesVect.at(idx).second, keyFilesVect.at(idx).second});
      }
    }
    else {
      errlog("Error, mismatching number of certificates and keys in call to %s()!", context);
      g_outputBuffer="Error, mismatching number of certificates and keys in call to " + context + "()!";
      return false;
    }
  }
  else {
    errlog("Error, mismatching number of certificates and keys in call to %s()!", context);
    g_outputBuffer="Error, mismatching number of certificates and keys in call to " + context + "()!";
    return false;
  }

  return true;
}

static void parseTLSConfig(TLSConfig& config, const std::string& context, boost::optional<localbind_t> vars)
{
  if (vars->count("ciphers")) {
    config.d_ciphers = boost::get<const string>((*vars)["ciphers"]);
  }

  if (vars->count("ciphersTLS13")) {
    config.d_ciphers13 = boost::get<const string>((*vars)["ciphersTLS13"]);
  }

#ifdef HAVE_LIBSSL
  if (vars->count("minTLSVersion")) {
    config.d_minTLSVersion = libssl_tls_version_from_string(boost::get<const string>((*vars)["minTLSVersion"]));
  }
#endif /* HAVE_LIBSSL */

  if (vars->count("ticketKeyFile")) {
    config.d_ticketKeyFile = boost::get<const string>((*vars)["ticketKeyFile"]);
  }

  if (vars->count("ticketsKeysRotationDelay")) {
    config.d_ticketsKeyRotationDelay = boost::get<int>((*vars)["ticketsKeysRotationDelay"]);
  }

  if (vars->count("numberOfTicketsKeys")) {
    config.d_numberOfTicketsKeys = boost::get<int>((*vars)["numberOfTicketsKeys"]);
  }

  if (vars->count("preferServerCiphers")) {
    config.d_preferServerCiphers = boost::get<bool>((*vars)["preferServerCiphers"]);
  }

  if (vars->count("sessionTimeout")) {
    config.d_sessionTimeout = boost::get<int>((*vars)["sessionTimeout"]);
  }

  if (vars->count("sessionTickets")) {
    config.d_enableTickets = boost::get<bool>((*vars)["sessionTickets"]);
  }

  if (vars->count("numberOfStoredSessions")) {
    auto value = boost::get<int>((*vars)["numberOfStoredSessions"]);
    if (value < 0) {
      errlog("Invalid value '%d' for %s() parameter 'numberOfStoredSessions', should be >= 0, dismissing", value, context);
      g_outputBuffer="Invalid value '" +  std::to_string(value) + "' for " + context + "() parameter 'numberOfStoredSessions', should be >= 0, dismissing";
    }
    config.d_maxStoredSessions = value;
  }

  if (vars->count("ocspResponses")) {
    auto files = boost::get<std::vector<std::pair<int, std::string>>>((*vars)["ocspResponses"]);
    for (const auto& file : files) {
      config.d_ocspFiles.push_back(file.second);
    }
  }

  if (vars->count("keyLogFile")) {
#ifdef HAVE_SSL_CTX_SET_KEYLOG_CALLBACK
    config.d_keyLogFile = boost::get<const string>((*vars)["keyLogFile"]);
#else
    errlog("TLS Key logging has been enabled using the 'keyLogFile' parameter to %s(), but this version of OpenSSL does not support it", context);
    g_outputBuffer = "TLS Key logging has been enabled using the 'keyLogFile' parameter to " + context + "(), but this version of OpenSSL does not support it";
#endif
  }

  if (vars->count("releaseBuffers")) {
    config.d_releaseBuffers = boost::get<bool>((*vars)["releaseBuffers"]);
  }

  if (vars->count("enableRenegotiation")) {
    config.d_enableRenegotiation = boost::get<bool>((*vars)["enableRenegotiation"]);
  }
}

#endif // defined(HAVE_DNS_OVER_TLS) || defined(HAVE_DNS_OVER_HTTPS)

static void setupLuaConfig(LuaContext& luaCtx, bool client, bool configCheck)
{
  typedef std::unordered_map<std::string, boost::variant<bool, std::string, vector<pair<int, std::string> >, DownstreamState::checkfunc_t > > newserver_t;
  luaCtx.writeFunction("inClientStartup", [client]() {
        return client && !g_configurationDone;
  });

  luaCtx.writeFunction("inConfigCheck", [configCheck]() {
        return !configCheck;
  });

  luaCtx.writeFunction("newServer",
                      [client, configCheck](boost::variant<string,newserver_t> pvars, boost::optional<int> qps) {
      setLuaSideEffect();

      std::shared_ptr<DownstreamState> ret = std::make_shared<DownstreamState>(ComboAddress(), ComboAddress(), 0, std::string(), 1, !(client || configCheck));
      newserver_t vars;

      ComboAddress serverAddr;
      std::string serverAddressStr;
      if(auto addrStr = boost::get<string>(&pvars)) {
        serverAddressStr = *addrStr;
        if(qps) {
          vars["qps"] = std::to_string(*qps);
        }
      } else {
        vars = boost::get<newserver_t>(pvars);
        serverAddressStr = boost::get<string>(vars["address"]);
      }

      try {
        serverAddr = ComboAddress(serverAddressStr, 53);
      }
      catch(const PDNSException& e) {
        g_outputBuffer="Error creating new server: "+string(e.reason);
        errlog("Error creating new server with address %s: %s", serverAddressStr, e.reason);
        return ret;
      }
      catch(std::exception& e) {
        g_outputBuffer="Error creating new server: "+string(e.what());
        errlog("Error creating new server with address %s: %s", serverAddressStr, e.what());
        return ret;
      }

      if(IsAnyAddress(serverAddr)) {
        g_outputBuffer="Error creating new server: invalid address for a downstream server.";
        errlog("Error creating new server: %s is not a valid address for a downstream server", serverAddressStr);
        return ret;
      }

      ComboAddress sourceAddr;
      std::string sourceItfName;
      unsigned int sourceItf = 0;
      size_t numberOfSockets = 1;
      std::set<int> cpus;

      if(vars.count("source")) {
        /* handle source in the following forms:
           - v4 address ("192.0.2.1")
           - v6 address ("2001:DB8::1")
           - interface name ("eth0")
           - v4 address and interface name ("192.0.2.1@eth0")
           - v6 address and interface name ("2001:DB8::1@eth0")
        */
        const string source = boost::get<string>(vars["source"]);
        bool parsed = false;
        std::string::size_type pos = source.find("@");
        if (pos == std::string::npos) {
          /* no '@', try to parse that as a valid v4/v6 address */
          try {
            sourceAddr = ComboAddress(source);
            parsed = true;
          }
          catch(...)
          {
          }
        }

        if (parsed == false)
        {
          /* try to parse as interface name, or v4/v6@itf */
          sourceItfName = source.substr(pos == std::string::npos ? 0 : pos + 1);
          unsigned int itfIdx = if_nametoindex(sourceItfName.c_str());

          if (itfIdx != 0) {
            if (pos == 0 || pos == std::string::npos) {
              /* "eth0" or "@eth0" */
              sourceItf = itfIdx;
            }
            else {
              /* "192.0.2.1@eth0" */
              sourceAddr = ComboAddress(source.substr(0, pos));
              sourceItf = itfIdx;
            }
#ifdef SO_BINDTODEVICE
            /* we need to retain CAP_NET_RAW to be able to set SO_BINDTODEVICE in the health checks */
            g_capabilitiesToRetain.insert("CAP_NET_RAW");
#endif
          }
          else
          {
            warnlog("Dismissing source %s because '%s' is not a valid interface name", source, sourceItfName);
          }
        }
      }

      if (vars.count("sockets")) {
        numberOfSockets = std::stoul(boost::get<string>(vars["sockets"]));
        if (numberOfSockets == 0) {
          warnlog("Dismissing invalid number of sockets '%s', using 1 instead", boost::get<string>(vars["sockets"]));
          numberOfSockets = 1;
        }
      }

      // create but don't connect the socket in client or check-config modes
      ret=std::make_shared<DownstreamState>(serverAddr, sourceAddr, sourceItf, sourceItfName, numberOfSockets, !(client || configCheck));
      if (!(client || configCheck)) {
        infolog("Added downstream server %s", serverAddr.toStringWithPort());
      }

      if(vars.count("qps")) {
        int qpsVal=std::stoi(boost::get<string>(vars["qps"]));
        ret->qps=QPSLimiter(qpsVal, qpsVal);
      }

      if(vars.count("order")) {
        ret->order=std::stoi(boost::get<string>(vars["order"]));
      }

      if(vars.count("weight")) {
        try {
          int weightVal=std::stoi(boost::get<string>(vars["weight"]));

          if(weightVal < 1) {
            errlog("Error creating new server: downstream weight value must be greater than 0.");
            return ret;
          }

          ret->setWeight(weightVal);
        }
        catch(std::exception& e) {
          // std::stoi will throw an exception if the string isn't in a value int range
          errlog("Error creating new server: downstream weight value must be between %s and %s", 1, std::numeric_limits<int>::max());
          return ret;
        }
      }

      if(vars.count("retries")) {
        ret->retries=std::stoi(boost::get<string>(vars["retries"]));
      }

      if(vars.count("checkInterval")) {
        ret->checkInterval=static_cast<unsigned int>(std::stoul(boost::get<string>(vars["checkInterval"])));
      }

      if(vars.count("tcpConnectTimeout")) {
        ret->tcpConnectTimeout=std::stoi(boost::get<string>(vars["tcpConnectTimeout"]));
      }

      if(vars.count("tcpSendTimeout")) {
        ret->tcpSendTimeout=std::stoi(boost::get<string>(vars["tcpSendTimeout"]));
      }

      if(vars.count("tcpRecvTimeout")) {
        ret->tcpRecvTimeout=std::stoi(boost::get<string>(vars["tcpRecvTimeout"]));
      }

      if(vars.count("tcpFastOpen")) {
        bool fastOpen = boost::get<bool>(vars["tcpFastOpen"]);
        if (fastOpen) {
#ifdef MSG_FASTOPEN
          ret->tcpFastOpen=true;
#else
          warnlog("TCP Fast Open has been configured on downstream server %s but is not supported", boost::get<string>(vars["address"]));
#endif
        }
      }

      if(vars.count("maxInFlight")) {
        ret->d_maxInFlightQueriesPerConn = std::stoi(boost::get<string>(vars["maxInFlight"]));
      }

      if(vars.count("name")) {
        ret->setName(boost::get<string>(vars["name"]));
      }

      if (vars.count("id")) {
        ret->setId(boost::lexical_cast<boost::uuids::uuid>(boost::get<string>(vars["id"])));
      }

      if(vars.count("checkName")) {
        ret->checkName=DNSName(boost::get<string>(vars["checkName"]));
      }

      if(vars.count("checkType")) {
        ret->checkType=boost::get<string>(vars["checkType"]);
      }

      if(vars.count("checkClass")) {
        ret->checkClass=std::stoi(boost::get<string>(vars["checkClass"]));
      }

      if(vars.count("checkFunction")) {
        ret->checkFunction= boost::get<DownstreamState::checkfunc_t>(vars["checkFunction"]);
      }

      if(vars.count("checkTimeout")) {
        ret->checkTimeout = std::stoi(boost::get<string>(vars["checkTimeout"]));
      }

      if(vars.count("setCD")) {
        ret->setCD=boost::get<bool>(vars["setCD"]);
      }

      if(vars.count("mustResolve")) {
        ret->mustResolve=boost::get<bool>(vars["mustResolve"]);
      }

      if(vars.count("useClientSubnet")) {
        ret->useECS=boost::get<bool>(vars["useClientSubnet"]);
      }

      if(vars.count("useProxyProtocol")) {
        ret->useProxyProtocol = boost::get<bool>(vars["useProxyProtocol"]);
      }

      if(vars.count("disableZeroScope")) {
        ret->disableZeroScope=boost::get<bool>(vars["disableZeroScope"]);
      }

      if(vars.count("ipBindAddrNoPort")) {
        ret->ipBindAddrNoPort=boost::get<bool>(vars["ipBindAddrNoPort"]);
      }

      if(vars.count("addXPF")) {
        ret->xpfRRCode=std::stoi(boost::get<string>(vars["addXPF"]));
      }

      if(vars.count("maxCheckFailures")) {
        ret->maxCheckFailures=std::stoi(boost::get<string>(vars["maxCheckFailures"]));
      }

      if(vars.count("rise")) {
        ret->minRiseSuccesses=std::stoi(boost::get<string>(vars["rise"]));
      }

      if(vars.count("reconnectOnUp")) {
        ret->reconnectOnUp=boost::get<bool>(vars["reconnectOnUp"]);
      }

      if(vars.count("cpus")) {
        for (const auto& cpu : boost::get<vector<pair<int,string>>>(vars["cpus"])) {
          cpus.insert(std::stoi(cpu.second));
        }
      }

      /* this needs to be done _AFTER_ the order has been set,
         since the server are kept ordered inside the pool */
      auto localPools = g_pools.getCopy();
      if(vars.count("pool")) {
        if(auto* pool = boost::get<string>(&vars["pool"])) {
          ret->pools.insert(*pool);
        }
        else {
          auto pools = boost::get<vector<pair<int, string> > >(vars["pool"]);
          for(auto& p : pools) {
            ret->pools.insert(p.second);
          }
        }
        for(const auto& poolName: ret->pools) {
          addServerToPool(localPools, poolName, ret);
        }
      }
      else {
        addServerToPool(localPools, "", ret);
      }
      g_pools.setState(localPools);

      if (ret->connected) {
        ret->threadStarted.test_and_set();

        if (g_launchWork) {
          g_launchWork->push_back([ret,cpus]() {
                                    ret->tid = thread(responderThread, ret);
                                    if (!cpus.empty()) {
                                      mapThreadToCPUList(ret->tid.native_handle(), cpus);
                                    }
                                  });
        }
        else {
          ret->tid = thread(responderThread, ret);
          if (!cpus.empty()) {
            mapThreadToCPUList(ret->tid.native_handle(), cpus);
          }
        }
      }

      auto states = g_dstates.getCopy();
      states.push_back(ret);
      std::stable_sort(states.begin(), states.end(), [](const decltype(ret)& a, const decltype(ret)& b) {
                                                       return a->order < b->order;
                                                     });
      g_dstates.setState(states);
      return ret;
      } );

  luaCtx.writeFunction("rmServer",
                      [](boost::variant<std::shared_ptr<DownstreamState>, int, std::string> var)
                      {
                        setLuaSideEffect();
                        shared_ptr<DownstreamState> server = nullptr;
                        auto states = g_dstates.getCopy();
                        if (auto* rem = boost::get<shared_ptr<DownstreamState>>(&var)) {
                          server = *rem;
                        }
                        else if (auto str = boost::get<std::string>(&var)) {
                          const auto uuid = getUniqueID(*str);
                          for (auto& state : states) {
                            if (state->id == uuid) {
                              server = state;
                            }
                          }
                        }
                        else {
                          int idx = boost::get<int>(var);
                          server = states.at(idx);
                        }
                        if (!server) {
                          throw std::runtime_error("unable to locate the requested server");
                        }
                        auto localPools = g_pools.getCopy();
                        for (const string& poolName : server->pools) {
                          removeServerFromPool(localPools, poolName, server);
                        }
                        /* the server might also be in the default pool */
                        removeServerFromPool(localPools, "", server);
                        g_pools.setState(localPools);
                        states.erase(remove(states.begin(), states.end(), server), states.end());
                        g_dstates.setState(states);
                        server->stop();
                      } );

  luaCtx.writeFunction("truncateTC", [](bool tc) { setLuaSideEffect(); g_truncateTC=tc; });
  luaCtx.writeFunction("fixupCase", [](bool fu) { setLuaSideEffect(); g_fixupCase=fu; });

  luaCtx.writeFunction("addACL", [](const std::string& domain) {
      setLuaSideEffect();
      g_ACL.modify([domain](NetmaskGroup& nmg) { nmg.addMask(domain); });
    });

  luaCtx.writeFunction("rmACL", [](const std::string& netmask) {
    setLuaSideEffect();
    g_ACL.modify([netmask](NetmaskGroup& nmg) { nmg.deleteMask(netmask); });
  });

  luaCtx.writeFunction("setLocal", [client](const std::string& addr, boost::optional<localbind_t> vars) {
      setLuaSideEffect();
      if(client)
	return;
      if (g_configurationDone) {
        g_outputBuffer="setLocal cannot be used at runtime!\n";
        return;
      }
      bool reusePort = false;
      int tcpFastOpenQueueSize = 0;
      int tcpListenQueueSize = 0;
      size_t maxInFlightQueriesPerConn = 0;
      size_t tcpMaxConcurrentConnections = 0;
      std::string interface;
      std::set<int> cpus;

      parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections);

      try {
	ComboAddress loc(addr, 53);
        for (auto it = g_frontends.begin(); it != g_frontends.end(); ) {
          /* DoH, DoT and DNSCrypt frontends are separate */
          if ((*it)->tlsFrontend == nullptr && (*it)->dnscryptCtx == nullptr && (*it)->dohFrontend == nullptr) {
            it = g_frontends.erase(it);
          }
          else {
            ++it;
          }
        }

        // only works pre-startup, so no sync necessary
        g_frontends.push_back(std::unique_ptr<ClientState>(new ClientState(loc, false, reusePort, tcpFastOpenQueueSize, interface, cpus)));
        auto tcpCS = std::unique_ptr<ClientState>(new ClientState(loc, true, reusePort, tcpFastOpenQueueSize, interface, cpus));
        if (tcpListenQueueSize > 0) {
          tcpCS->tcpListenQueueSize = tcpListenQueueSize;
        }
        if (maxInFlightQueriesPerConn > 0) {
          tcpCS->d_maxInFlightQueriesPerConn = maxInFlightQueriesPerConn;
        }
        if (tcpMaxConcurrentConnections > 0) {
          tcpCS->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConnections;
        }

        g_frontends.push_back(std::move(tcpCS));
      }
      catch(const std::exception& e) {
	g_outputBuffer="Error: "+string(e.what())+"\n";
      }
    });

  luaCtx.writeFunction("addLocal", [client](const std::string& addr, boost::optional<localbind_t> vars) {
      setLuaSideEffect();
      if(client)
	return;
      if (g_configurationDone) {
        g_outputBuffer="addLocal cannot be used at runtime!\n";
        return;
      }
      bool reusePort = false;
      int tcpFastOpenQueueSize = 0;
      int tcpListenQueueSize = 0;
      size_t maxInFlightQueriesPerConn = 0;
      size_t tcpMaxConcurrentConnections = 0;
      std::string interface;
      std::set<int> cpus;

      parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections);

      try {
	ComboAddress loc(addr, 53);
        // only works pre-startup, so no sync necessary
        g_frontends.push_back(std::unique_ptr<ClientState>(new ClientState(loc, false, reusePort, tcpFastOpenQueueSize, interface, cpus)));
        auto tcpCS = std::unique_ptr<ClientState>(new ClientState(loc, true, reusePort, tcpFastOpenQueueSize, interface, cpus));
        if (tcpListenQueueSize > 0) {
          tcpCS->tcpListenQueueSize = tcpListenQueueSize;
        }
        if (maxInFlightQueriesPerConn > 0) {
          tcpCS->d_maxInFlightQueriesPerConn = maxInFlightQueriesPerConn;
        }
        if (tcpMaxConcurrentConnections > 0) {
          tcpCS->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConnections;
        }
        g_frontends.push_back(std::move(tcpCS));
      }
      catch(std::exception& e) {
        g_outputBuffer="Error: "+string(e.what())+"\n";
        errlog("Error while trying to listen on %s: %s\n", addr, string(e.what()));
      }
    });

  luaCtx.writeFunction("setACL", [](boost::variant<string,vector<pair<int, string>>> inp) {
      setLuaSideEffect();
      NetmaskGroup nmg;
      if(auto str = boost::get<string>(&inp)) {
	nmg.addMask(*str);
      }
      else for(const auto& p : boost::get<vector<pair<int,string>>>(inp)) {
	nmg.addMask(p.second);
      }
      g_ACL.setState(nmg);
  });

  luaCtx.writeFunction("setACLFromFile", [](const std::string& file) {
      setLuaSideEffect();
      NetmaskGroup nmg;

      ifstream ifs(file);
      if(!ifs) {
        throw std::runtime_error("Could not open '"+file+"': "+stringerror());
      }

      string::size_type pos;
      string line;
      while(getline(ifs,line)) {
        pos=line.find('#');
        if(pos!=string::npos)
          line.resize(pos);
        boost::trim(line);
        if(line.empty())
          continue;

        nmg.addMask(line);
      }

      g_ACL.setState(nmg);
  });

  luaCtx.writeFunction("showACL", []() {
      setLuaNoSideEffect();
      vector<string> vec;

      g_ACL.getLocal()->toStringVector(&vec);

      for(const auto& s : vec)
        g_outputBuffer+=s+"\n";

    });

  luaCtx.writeFunction("shutdown", []() {
#ifdef HAVE_SYSTEMD
      sd_notify(0, "STOPPING=1");
#endif /* HAVE_SYSTEMD */
#if 0
      // Useful for debugging leaks, but might lead to race under load
      // since other threads are still running.
      for(auto& frontend : g_tlslocals) {
        frontend->cleanup();
      }
      g_tlslocals.clear();
#endif /* 0 */
      _exit(0);
  } );

  typedef std::unordered_map<std::string, boost::variant<bool, std::string> > showserversopts_t;

  luaCtx.writeFunction("showServers", [](boost::optional<showserversopts_t> vars) {
      setLuaNoSideEffect();
      bool showUUIDs = false;
      if (vars) {
        if (vars->count("showUUIDs")) {
          showUUIDs = boost::get<bool>((*vars)["showUUIDs"]);
        }
      }
      try {
        ostringstream ret;
        boost::format fmt;
        if (showUUIDs) {
          fmt = boost::format("%1$-3d %15$-36s %2$-20.20s %|62t|%3% %|92t|%4$5s %|88t|%5$7.1f %|103t|%6$7d %|106t|%7$3d %|115t|%8$2d %|117t|%9$10d %|123t|%10$7d %|128t|%11$5.1f %|146t|%12$5.1f %|152t|%13$11d %14%" );
          //             1        2          3       4        5       6       7       8           9        10        11       12     13              14        15
          ret << (fmt % "#" % "Name" % "Address" % "State" % "Qps" % "Qlim" % "Ord" % "Wt" % "Queries" % "Drops" % "Drate" % "Lat" % "Outstanding" % "Pools" % "UUID") << endl;
        } else {
          fmt = boost::format("%1$-3d %2$-20.20s %|25t|%3% %|55t|%4$5s %|51t|%5$7.1f %|66t|%6$7d %|69t|%7$3d %|78t|%8$2d %|80t|%9$10d %|86t|%10$7d %|91t|%11$5.1f %|109t|%12$5.1f %|115t|%13$11d %14%" );
          ret << (fmt % "#" % "Name" % "Address" % "State" % "Qps" % "Qlim" % "Ord" % "Wt" % "Queries" % "Drops" % "Drate" % "Lat" % "Outstanding" % "Pools") << endl;
        }

        uint64_t totQPS{0}, totQueries{0}, totDrops{0};
        int counter=0;
        auto states = g_dstates.getLocal();
        for(const auto& s : *states) {
          string status = s->getStatus();
          string pools;
          for(auto& p : s->pools) {
            if(!pools.empty())
              pools+=" ";
            pools+=p;
          }
          if (showUUIDs) {
            ret << (fmt % counter % s->getName() % s->remote.toStringWithPort() %
                    status %
                    s->queryLoad % s->qps.getRate() % s->order % s->weight % s->queries.load() % s->reuseds.load() % (s->dropRate) % (s->latencyUsec/1000.0) % s->outstanding.load() % pools % s->id) << endl;
          } else {
            ret << (fmt % counter % s->getName() % s->remote.toStringWithPort() %
                    status %
                    s->queryLoad % s->qps.getRate() % s->order % s->weight % s->queries.load() % s->reuseds.load() % (s->dropRate) % (s->latencyUsec/1000.0) % s->outstanding.load() % pools) << endl;
          }
          totQPS += s->queryLoad;
          totQueries += s->queries.load();
          totDrops += s->reuseds.load();
          ++counter;
        }
        if (showUUIDs) {
          ret<< (fmt % "All" % "" % "" % ""
                 %
                 (double)totQPS % "" % "" % "" % totQueries % totDrops % "" % "" % "" % "" % "" ) << endl;
        } else {
          ret<< (fmt % "All" % "" % "" % ""
                 %
                 (double)totQPS % "" % "" % "" % totQueries % totDrops % "" % "" % "" % "" ) << endl;
        }

        g_outputBuffer=ret.str();
      } catch(std::exception& e) {
        g_outputBuffer=e.what();
        throw;
      }
    });

  luaCtx.writeFunction("getServers", []() {
      setLuaNoSideEffect();
      vector<pair<int, std::shared_ptr<DownstreamState> > > ret;
      int count=1;
      for(const auto& s : g_dstates.getCopy()) {
	ret.push_back(make_pair(count++, s));
      }
      return ret;
    });

  luaCtx.writeFunction("getPoolServers", [](string pool) {
      const auto poolServers = getDownstreamCandidates(g_pools.getCopy(), pool);
      return *poolServers;
    });

  luaCtx.writeFunction("getServer", [client](boost::variant<unsigned int, std::string> i) {
      if (client) {
        return std::make_shared<DownstreamState>(ComboAddress(), ComboAddress(), 0, std::string(), 1, false);
      }
      auto states = g_dstates.getCopy();
      if (auto str = boost::get<std::string>(&i)) {
        const auto uuid = getUniqueID(*str);
        for (auto& state : states) {
          if (state->id == uuid) {
            return state;
          }
        }
      }
      else if (auto pos = boost::get<unsigned int>(&i)) {
        return states.at(*pos);
      }

      g_outputBuffer = "Error: no rule matched\n";
      return std::shared_ptr<DownstreamState>(nullptr);
    });

  luaCtx.writeFunction("carbonServer", [](const std::string& address, boost::optional<string> ourName,
					 boost::optional<unsigned int> interval, boost::optional<string> namespace_name,
                                         boost::optional<string> instance_name) {
      setLuaSideEffect();
      auto ours = g_carbon.getCopy();
      ours.push_back({
        ComboAddress(address, 2003),
        (namespace_name && !namespace_name->empty()) ? *namespace_name : "dnsdist",
        ourName ? *ourName : "",
        (instance_name && !instance_name->empty()) ? *instance_name : "main" ,
        interval ? *interval : 30
      });
      g_carbon.setState(ours);
  });

  luaCtx.writeFunction("webserver", [client,configCheck](const std::string& address, const boost::optional<std::string> password, const boost::optional<std::string> apiKey, const boost::optional<std::map<std::string, std::string> > customHeaders, const boost::optional<std::string> acl) {
      setLuaSideEffect();
      ComboAddress local;
      try {
        local = ComboAddress(address);
      }
      catch (const PDNSException& e) {
        throw std::runtime_error(std::string("Error parsing the bind address for the webserver: ") + e.reason);
      }

      if (client || configCheck) {
        return;
      }

      if (password || apiKey || customHeaders || acl) {
        warnlog("Passing additional parameters to 'webserver()' is deprecated, please use 'setWebserverConfig()' instead.");
      }

      try {
        int sock = SSocket(local.sin4.sin_family, SOCK_STREAM, 0);
        SSetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
        SBind(sock, local);
        SListen(sock, 5);
        auto launch=[sock, local, password, apiKey, customHeaders, acl]() {
          if (password) {
            setWebserverPassword(*password);
          }

          if (apiKey) {
            setWebserverAPIKey(apiKey);
          }

          if (customHeaders) {
            setWebserverCustomHeaders(customHeaders);
          }

          if (acl) {
            setWebserverACL(*acl);
          }
          thread t(dnsdistWebserverThread, sock, local);
          t.detach();
        };
        if (g_launchWork) {
          g_launchWork->push_back(launch);
        }
        else {
          launch();
        }
      }
      catch (const std::exception& e) {
        g_outputBuffer="Unable to bind to webserver socket on " + local.toStringWithPort() + ": " + e.what();
        errlog("Unable to bind to webserver socket on %s: %s", local.toStringWithPort(), e.what());
      }

    });

  typedef std::unordered_map<std::string, boost::variant<bool, std::string, std::map<std::string, std::string>> > webserveropts_t;

  luaCtx.writeFunction("setWebserverConfig", [](boost::optional<webserveropts_t> vars) {
      setLuaSideEffect();

      if (!vars) {
        return ;
      }

      if (vars->count("password")) {
        const std::string password = boost::get<std::string>(vars->at("password"));

        setWebserverPassword(password);
      }

      if (vars->count("apiKey")) {
        const std::string apiKey = boost::get<std::string>(vars->at("apiKey"));

        setWebserverAPIKey(apiKey);
      }

      if (vars->count("acl")) {
        const std::string acl = boost::get<std::string>(vars->at("acl"));

        setWebserverACL(acl);
      }

      if (vars->count("customHeaders")) {
        const boost::optional<std::map<std::string, std::string> > headers = boost::get<std::map<std::string, std::string> >(vars->at("customHeaders"));

        setWebserverCustomHeaders(headers);
      }

      if (vars->count("statsRequireAuthentication")) {
        setWebserverStatsRequireAuthentication(boost::get<bool>(vars->at("statsRequireAuthentication")));
      }

      if (vars->count("maxConcurrentConnections")) {
        setWebserverMaxConcurrentConnections(std::stoi(boost::get<std::string>(vars->at("maxConcurrentConnections"))));
      }
    });

  luaCtx.writeFunction("controlSocket", [client,configCheck](const std::string& str) {
      setLuaSideEffect();
      ComboAddress local(str, 5199);

      if(client || configCheck) {
	g_serverControl = local;
	return;
      }

      g_consoleEnabled = true;
#ifdef HAVE_LIBSODIUM
      if (g_configurationDone && g_consoleKey.empty()) {
        warnlog("Warning, the console has been enabled via 'controlSocket()' but no key has been set with 'setKey()' so all connections will fail until a key has been set");
      }
#endif

      try {
	int sock = SSocket(local.sin4.sin_family, SOCK_STREAM, 0);
	SSetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
	SBind(sock, local);
	SListen(sock, 5);
	auto launch=[sock, local]() {
	    thread t(controlThread, sock, local);
	    t.detach();
	};
	if (g_launchWork) {
	  g_launchWork->push_back(launch);
        }
	else {
	  launch();
        }
      }
      catch(std::exception& e) {
	g_outputBuffer="Unable to bind to control socket on " + local.toStringWithPort() + ": " + e.what();
	errlog("Unable to bind to control socket on %s: %s", local.toStringWithPort(), e.what());
      }
    });

  luaCtx.writeFunction("addConsoleACL", [](const std::string& netmask) {
      setLuaSideEffect();
#ifndef HAVE_LIBSODIUM
      warnlog("Allowing remote access to the console while libsodium support has not been enabled is not secure, and will result in cleartext communications");
#endif

      g_consoleACL.modify([netmask](NetmaskGroup& nmg) { nmg.addMask(netmask); });
    });

  luaCtx.writeFunction("setConsoleACL", [](boost::variant<string,vector<pair<int, string>>> inp) {
      setLuaSideEffect();

#ifndef HAVE_LIBSODIUM
      warnlog("Allowing remote access to the console while libsodium support has not been enabled is not secure, and will result in cleartext communications");
#endif

      NetmaskGroup nmg;
      if(auto str = boost::get<string>(&inp)) {
	nmg.addMask(*str);
      }
      else for(const auto& p : boost::get<vector<pair<int,string>>>(inp)) {
	nmg.addMask(p.second);
      }
      g_consoleACL.setState(nmg);
  });

  luaCtx.writeFunction("showConsoleACL", []() {
      setLuaNoSideEffect();

#ifndef HAVE_LIBSODIUM
      warnlog("Allowing remote access to the console while libsodium support has not been enabled is not secure, and will result in cleartext communications");
#endif

      vector<string> vec;
      g_consoleACL.getLocal()->toStringVector(&vec);

      for(const auto& s : vec) {
        g_outputBuffer += s + "\n";
      }
    });

  luaCtx.writeFunction("setConsoleMaximumConcurrentConnections", [](size_t max) {
      setLuaSideEffect();
      setConsoleMaximumConcurrentConnections(max);
  });

  luaCtx.writeFunction("clearQueryCounters", []() {
      unsigned int size{0};
      {
        auto records = g_qcount.records.write_lock();
        size = records->size();
        records->clear();
      }

      boost::format fmt("%d records cleared from query counter buffer\n");
      g_outputBuffer = (fmt % size).str();
    });

  luaCtx.writeFunction("getQueryCounters", [](boost::optional<unsigned int> optMax) {
      setLuaNoSideEffect();
      auto records = g_qcount.records.read_lock();
      g_outputBuffer = "query counting is currently: ";
      g_outputBuffer+= g_qcount.enabled ? "enabled" : "disabled";
      g_outputBuffer+= (boost::format(" (%d records in buffer)\n") % records->size()).str();

      boost::format fmt("%-3d %s: %d request(s)\n");
      unsigned int max = optMax ? *optMax : 10;
      unsigned int index{1};
      for (auto it = records->begin(); it != records->end() && index <= max; ++it, ++index) {
        g_outputBuffer += (fmt % index % it->first % it->second).str();
      }
    });

  luaCtx.writeFunction("setQueryCount", [](bool enabled) { g_qcount.enabled=enabled; });

  luaCtx.writeFunction("setQueryCountFilter", [](QueryCountFilter func) {
      g_qcount.filter = func;
    });

  luaCtx.writeFunction("makeKey", []() {
      setLuaNoSideEffect();
      g_outputBuffer="setKey("+newKey()+")\n";
    });

  luaCtx.writeFunction("setKey", [](const std::string& key) {
      if(!g_configurationDone && ! g_consoleKey.empty()) { // this makes sure the commandline -k key prevails over dnsdist.conf
        return;                                     // but later setKeys() trump the -k value again
      }
#ifndef HAVE_LIBSODIUM
      warnlog("Calling setKey() while libsodium support has not been enabled is not secure, and will result in cleartext communications");
#endif

      setLuaSideEffect();
      string newkey;
      if(B64Decode(key, newkey) < 0) {
        g_outputBuffer=string("Unable to decode ")+key+" as Base64";
        errlog("%s", g_outputBuffer);
      }
      else
	g_consoleKey=newkey;
    });

  luaCtx.writeFunction("clearConsoleHistory", []() {
      clearConsoleHistory();
    });

  luaCtx.writeFunction("testCrypto", [](boost::optional<string> optTestMsg)
   {
     setLuaNoSideEffect();
#ifdef HAVE_LIBSODIUM
     try {
       string testmsg;

       if (optTestMsg) {
         testmsg = *optTestMsg;
       }
       else {
         testmsg = "testStringForCryptoTests";
       }

       SodiumNonce sn, sn2;
       sn.init();
       sn2=sn;
       string encrypted = sodEncryptSym(testmsg, g_consoleKey, sn);
       string decrypted = sodDecryptSym(encrypted, g_consoleKey, sn2);

       sn.increment();
       sn2.increment();

       encrypted = sodEncryptSym(testmsg, g_consoleKey, sn);
       decrypted = sodDecryptSym(encrypted, g_consoleKey, sn2);

       if(testmsg == decrypted)
	 g_outputBuffer="Everything is ok!\n";
       else
	 g_outputBuffer="Crypto failed.. (the decoded value does not match the cleartext one)\n";
     }
     catch(const std::exception& e) {
       g_outputBuffer="Crypto failed: "+std::string(e.what())+"\n";
     }
     catch(...) {
       g_outputBuffer="Crypto failed..\n";
     }
#else
     g_outputBuffer="Crypto not available.\n";
#endif
   });

  luaCtx.writeFunction("setTCPRecvTimeout", [](int timeout) { g_tcpRecvTimeout=timeout; });

  luaCtx.writeFunction("setTCPSendTimeout", [](int timeout) { g_tcpSendTimeout=timeout; });

  luaCtx.writeFunction("setUDPTimeout", [](int timeout) { g_udpTimeout=timeout; });

  luaCtx.writeFunction("setMaxUDPOutstanding", [](uint16_t max) {
      if (!g_configurationDone) {
        g_maxOutstanding = max;
      } else {
        g_outputBuffer="Max UDP outstanding cannot be altered at runtime!\n";
      }
    });

  luaCtx.writeFunction("setMaxTCPClientThreads", [](uint64_t max) {
      if (!g_configurationDone) {
        g_maxTCPClientThreads = max;
      } else {
        g_outputBuffer="Maximum TCP client threads count cannot be altered at runtime!\n";
      }
    });

  luaCtx.writeFunction("setMaxTCPQueuedConnections", [](uint64_t max) {
      if (!g_configurationDone) {
        g_maxTCPQueuedConnections = max;
      } else {
        g_outputBuffer="The maximum number of queued TCP connections cannot be altered at runtime!\n";
      }
    });

  luaCtx.writeFunction("setMaxTCPQueriesPerConnection", [](size_t max) {
      if (!g_configurationDone) {
        g_maxTCPQueriesPerConn = max;
      } else {
        g_outputBuffer="The maximum number of queries per TCP connection cannot be altered at runtime!\n";
      }
    });

  luaCtx.writeFunction("setMaxTCPConnectionsPerClient", [](size_t max) {
      if (!g_configurationDone) {
        g_maxTCPConnectionsPerClient = max;
      } else {
        g_outputBuffer="The maximum number of TCP connection per client cannot be altered at runtime!\n";
      }
    });

  luaCtx.writeFunction("setMaxTCPConnectionDuration", [](size_t max) {
      if (!g_configurationDone) {
        g_maxTCPConnectionDuration = max;
      } else {
        g_outputBuffer="The maximum duration of a TCP connection cannot be altered at runtime!\n";
      }
    });

  luaCtx.writeFunction("setMaxCachedTCPConnectionsPerDownstream", [](size_t max) {
    setMaxCachedTCPConnectionsPerDownstream(max);
    });

  luaCtx.writeFunction("setCacheCleaningDelay", [](uint32_t delay) { g_cacheCleaningDelay = delay; });

  luaCtx.writeFunction("setCacheCleaningPercentage", [](uint16_t percentage) { if (percentage < 100) g_cacheCleaningPercentage = percentage; else g_cacheCleaningPercentage = 100; });

  luaCtx.writeFunction("setECSSourcePrefixV4", [](uint16_t prefix) { g_ECSSourcePrefixV4=prefix; });

  luaCtx.writeFunction("setECSSourcePrefixV6", [](uint16_t prefix) { g_ECSSourcePrefixV6=prefix; });

  luaCtx.writeFunction("setECSOverride", [](bool override) { g_ECSOverride=override; });

  luaCtx.writeFunction("showDynBlocks", []() {
      setLuaNoSideEffect();
      auto slow = g_dynblockNMG.getCopy();
      struct timespec now;
      gettime(&now);
      boost::format fmt("%-24s %8d %8d %-10s %-20s %s\n");
      g_outputBuffer = (fmt % "What" % "Seconds" % "Blocks" % "Warning" % "Action" % "Reason").str();
      for(const auto& e: slow) {
        if (now < e.second.until) {
          uint64_t counter = e.second.blocks;
          if (g_defaultBPFFilter && e.second.bpf) {
            counter += g_defaultBPFFilter->getHits(e.first.getNetwork());
          }
          g_outputBuffer+= (fmt % e.first.toString() % (e.second.until.tv_sec - now.tv_sec) % counter % (e.second.warning ? "true" : "false") % DNSAction::typeToString(e.second.action != DNSAction::Action::None ? e.second.action : g_dynBlockAction) % e.second.reason).str();
        }
      }
      auto slow2 = g_dynblockSMT.getCopy();
      slow2.visit([&now, &fmt](const SuffixMatchTree<DynBlock>& node) {
          if(now <node.d_value.until) {
            string dom("empty");
            if(!node.d_value.domain.empty())
              dom = node.d_value.domain.toString();
            g_outputBuffer+= (fmt % dom % (node.d_value.until.tv_sec - now.tv_sec) % node.d_value.blocks % (node.d_value.warning ? "true" : "false") % DNSAction::typeToString(node.d_value.action != DNSAction::Action::None ? node.d_value.action : g_dynBlockAction) % node.d_value.reason).str();
          }
        });

    });

  luaCtx.writeFunction("clearDynBlocks", []() {
      setLuaSideEffect();
      nmts_t nmg;
      g_dynblockNMG.setState(nmg);
      SuffixMatchTree<DynBlock> smt;
      g_dynblockSMT.setState(smt);
    });

  luaCtx.writeFunction("addDynBlocks",
                      [](const std::unordered_map<ComboAddress,unsigned int, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual>& m, const std::string& msg, boost::optional<int> seconds, boost::optional<DNSAction::Action> action) {
                           if (m.empty()) {
                             return;
                           }
                           setLuaSideEffect();
			   auto slow = g_dynblockNMG.getCopy();
			   struct timespec until, now;
			   gettime(&now);
			   until=now;
                           int actualSeconds = seconds ? *seconds : 10;
			   until.tv_sec += actualSeconds;
			   for(const auto& capair : m) {
			     unsigned int count = 0;
                             auto got = slow.lookup(Netmask(capair.first));
                             bool expired=false;
			     if(got) {
			       if(until < got->second.until) // had a longer policy
				 continue;
			       if(now < got->second.until) // only inherit count on fresh query we are extending
				 count=got->second.blocks;
                               else
                                 expired=true;
			     }
			     DynBlock db{msg,until,DNSName(),(action ? *action : DNSAction::Action::None)};
			     db.blocks=count;
                             if(!got || expired)
                               warnlog("Inserting dynamic block for %s for %d seconds: %s", capair.first.toString(), actualSeconds, msg);
			     slow.insert(Netmask(capair.first)).second=db;
			   }
			   g_dynblockNMG.setState(slow);
			 });

  luaCtx.writeFunction("addDynBlockSMT",
                      [](const vector<pair<unsigned int, string> >&names, const std::string& msg, boost::optional<int> seconds, boost::optional<DNSAction::Action> action) {
                           if (names.empty()) {
                             return;
                           }
                           setLuaSideEffect();
			   auto slow = g_dynblockSMT.getCopy();
			   struct timespec until, now;
			   gettime(&now);
			   until=now;
                           int actualSeconds = seconds ? *seconds : 10;
			   until.tv_sec += actualSeconds;

			   for(const auto& capair : names) {
			     unsigned int count = 0;
                             DNSName domain(capair.second);
                             domain.makeUsLowerCase();
                             auto got = slow.lookup(domain);
                             bool expired=false;
			     if(got) {
			       if(until < got->until) // had a longer policy
				 continue;
			       if(now < got->until) // only inherit count on fresh query we are extending
				 count=got->blocks;
                               else
                                 expired=true;
			     }

			     DynBlock db{msg,until,domain,(action ? *action : DNSAction::Action::None)};
			     db.blocks=count;
                             if(!got || expired)
                               warnlog("Inserting dynamic block for %s for %d seconds: %s", domain, actualSeconds, msg);
			     slow.add(domain, std::move(db));
			   }
			   g_dynblockSMT.setState(slow);
			 });

  luaCtx.writeFunction("setDynBlocksAction", [](DNSAction::Action action) {
      if (!g_configurationDone) {
        if (action == DNSAction::Action::Drop || action == DNSAction::Action::NoOp || action == DNSAction::Action::Nxdomain || action == DNSAction::Action::Refused || action == DNSAction::Action::Truncate || action == DNSAction::Action::NoRecurse) {
          g_dynBlockAction = action;
        }
        else {
          errlog("Dynamic blocks action can only be Drop, NoOp, NXDomain, Refused, Truncate or NoRecurse!");
          g_outputBuffer="Dynamic blocks action can only be Drop, NoOp, NXDomain, Refused, Truncate or NoRecurse!\n";
        }
      } else {
        g_outputBuffer="Dynamic blocks action cannot be altered at runtime!\n";
      }
    });

  luaCtx.writeFunction("setDynBlocksPurgeInterval", [](unsigned int interval) {
    DynBlockMaintenance::s_expiredDynBlocksPurgeInterval = interval;
  });

  luaCtx.writeFunction("addDNSCryptBind", [](const std::string& addr, const std::string& providerName, boost::variant<std::string, std::vector<std::pair<int, std::string>>> certFiles, boost::variant<std::string, std::vector<std::pair<int, std::string>>> keyFiles, boost::optional<localbind_t> vars) {
      if (g_configurationDone) {
        g_outputBuffer="addDNSCryptBind cannot be used at runtime!\n";
        return;
      }
#ifdef HAVE_DNSCRYPT
      bool reusePort = false;
      int tcpFastOpenQueueSize = 0;
      int tcpListenQueueSize = 0;
      size_t maxInFlightQueriesPerConn = 0;
      size_t tcpMaxConcurrentConnections = 0;
      std::string interface;
      std::set<int> cpus;
      std::vector<DNSCryptContext::CertKeyPaths> certKeys;

      parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections);

      if (certFiles.type() == typeid(std::string) && keyFiles.type() == typeid(std::string)) {
        auto certFile = boost::get<std::string>(certFiles);
        auto keyFile = boost::get<std::string>(keyFiles);
        certKeys.push_back({certFile, keyFile});
      }
      else if (certFiles.type() == typeid(std::vector<std::pair<int,std::string>>) && keyFiles.type() == typeid(std::vector<std::pair<int,std::string>>)) {
        auto certFilesVect = boost::get<std::vector<std::pair<int,std::string>>>(certFiles);
        auto keyFilesVect = boost::get<std::vector<std::pair<int,std::string>>>(keyFiles);
        if (certFilesVect.size() == keyFilesVect.size()) {
          for (size_t idx = 0; idx < certFilesVect.size(); idx++) {
            certKeys.push_back({certFilesVect.at(idx).second, keyFilesVect.at(idx).second});
          }
        }
        else {
          errlog("Error, mismatching number of certificates and keys in call to addDNSCryptBind!");
          g_outputBuffer="Error, mismatching number of certificates and keys in call to addDNSCryptBind()!";
          return;
        }
      }
      else {
        errlog("Error, mismatching number of certificates and keys in call to addDNSCryptBind()!");
        g_outputBuffer="Error, mismatching number of certificates and keys in call to addDNSCryptBind()!";
        return;
      }

      try {
        auto ctx = std::make_shared<DNSCryptContext>(providerName, certKeys);

        /* UDP */
        auto cs = std::unique_ptr<ClientState>(new ClientState(ComboAddress(addr, 443), false, reusePort, tcpFastOpenQueueSize, interface, cpus));
        cs->dnscryptCtx = ctx;
        g_dnsCryptLocals.push_back(ctx);
        g_frontends.push_back(std::move(cs));

        /* TCP */
        cs = std::unique_ptr<ClientState>(new ClientState(ComboAddress(addr, 443), true, reusePort, tcpFastOpenQueueSize, interface, cpus));
        cs->dnscryptCtx = ctx;
        if (tcpListenQueueSize > 0) {
          cs->tcpListenQueueSize = tcpListenQueueSize;
        }
        if (maxInFlightQueriesPerConn > 0) {
            cs->d_maxInFlightQueriesPerConn = maxInFlightQueriesPerConn;
        }
        if (tcpMaxConcurrentConnections > 0) {
          cs->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConnections;
        }

        g_frontends.push_back(std::move(cs));
      }
      catch(std::exception& e) {
        errlog(e.what());
	g_outputBuffer="Error: "+string(e.what())+"\n";
      }
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif

    });

  luaCtx.writeFunction("showDNSCryptBinds", []() {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      ostringstream ret;
      boost::format fmt("%1$-3d %2% %|25t|%3$-20.20s");
      ret << (fmt % "#" % "Address" % "Provider Name") << endl;
      size_t idx = 0;

      std::unordered_set<std::shared_ptr<DNSCryptContext>> contexts;
      for (const auto& frontend : g_frontends) {
        const std::shared_ptr<DNSCryptContext> ctx = frontend->dnscryptCtx;
        if (!ctx || contexts.count(ctx) != 0) {
          continue;
        }
        contexts.insert(ctx);
        ret<< (fmt % idx % frontend->local.toStringWithPort() % ctx->getProviderName()) << endl;
        idx++;
      }

      g_outputBuffer=ret.str();
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

  luaCtx.writeFunction("getDNSCryptBind", [](size_t idx) {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      std::shared_ptr<DNSCryptContext> ret = nullptr;
      if (idx < g_dnsCryptLocals.size()) {
        ret = g_dnsCryptLocals.at(idx);
      }
      return ret;
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

  luaCtx.writeFunction("getDNSCryptBindCount", []() {
      setLuaNoSideEffect();
      return g_dnsCryptLocals.size();
    });

  luaCtx.writeFunction("generateDNSCryptProviderKeys", [client](const std::string& publicKeyFile, const std::string privateKeyFile) {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      if (client) {
        return;
      }
      unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];
      unsigned char privateKey[DNSCRYPT_PROVIDER_PRIVATE_KEY_SIZE];
      sodium_mlock(privateKey, sizeof(privateKey));

      try {
        DNSCryptContext::generateProviderKeys(publicKey, privateKey);

        ofstream pubKStream(publicKeyFile);
        pubKStream.write((char*) publicKey, sizeof(publicKey));
        pubKStream.close();

        ofstream privKStream(privateKeyFile);
        privKStream.write((char*) privateKey, sizeof(privateKey));
        privKStream.close();

        g_outputBuffer="Provider fingerprint is: " + DNSCryptContext::getProviderFingerprint(publicKey) + "\n";
      }
      catch(std::exception& e) {
        errlog(e.what());
        g_outputBuffer="Error: "+string(e.what())+"\n";
      }

      sodium_memzero(privateKey, sizeof(privateKey));
      sodium_munlock(privateKey, sizeof(privateKey));
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

  luaCtx.writeFunction("printDNSCryptProviderFingerprint", [](const std::string& publicKeyFile) {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      unsigned char publicKey[DNSCRYPT_PROVIDER_PUBLIC_KEY_SIZE];

      try {
        ifstream file(publicKeyFile);
        file.read((char *) &publicKey, sizeof(publicKey));

        if (file.fail())
          throw std::runtime_error("Invalid dnscrypt provider public key file " + publicKeyFile);

        file.close();
        g_outputBuffer="Provider fingerprint is: " + DNSCryptContext::getProviderFingerprint(publicKey) + "\n";
      }
      catch(std::exception& e) {
        errlog(e.what());
        g_outputBuffer="Error: "+string(e.what())+"\n";
      }
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

#ifdef HAVE_DNSCRYPT
  luaCtx.writeFunction("generateDNSCryptCertificate", [client](const std::string& providerPrivateKeyFile, const std::string& certificateFile, const std::string privateKeyFile, uint32_t serial, time_t begin, time_t end, boost::optional<DNSCryptExchangeVersion> version) {
      setLuaNoSideEffect();
      if (client) {
        return;
      }
      DNSCryptPrivateKey privateKey;
      DNSCryptCert cert;

      try {
        if (generateDNSCryptCertificate(providerPrivateKeyFile, serial, begin, end, version ? *version : DNSCryptExchangeVersion::VERSION1, cert, privateKey)) {
          privateKey.saveToFile(privateKeyFile);
          DNSCryptContext::saveCertFromFile(cert, certificateFile);
        }
      }
      catch(const std::exception& e) {
        errlog(e.what());
        g_outputBuffer="Error: "+string(e.what())+"\n";
      }
    });
#endif

  luaCtx.writeFunction("showPools", []() {
      setLuaNoSideEffect();
      try {
        ostringstream ret;
        boost::format fmt("%1$-20.20s %|25t|%2$20s %|25t|%3$20s %|50t|%4%" );
        //             1        2         3                4
        ret << (fmt % "Name" % "Cache" % "ServerPolicy" % "Servers" ) << endl;

        const auto localPools = g_pools.getCopy();
        for (const auto& entry : localPools) {
          const string& name = entry.first;
          const std::shared_ptr<ServerPool> pool = entry.second;
          string cache = pool->packetCache != nullptr ? pool->packetCache->toString() : "";
          string policy = g_policy.getLocal()->getName();
          if (pool->policy != nullptr) {
            policy = pool->policy->getName();
          }
          string servers;

          const auto poolServers = pool->getServers();
          for (const auto& server: *poolServers) {
            if (!servers.empty()) {
              servers += ", ";
            }
            if (!server.second->getName().empty()) {
              servers += server.second->getName();
              servers += " ";
            }
            servers += server.second->remote.toStringWithPort();
          }

          ret << (fmt % name % cache % policy % servers) << endl;
        }
        g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

  luaCtx.writeFunction("getPool", [client](const string& poolName) {
      if (client) {
        return std::make_shared<ServerPool>();
      }
      auto localPools = g_pools.getCopy();
      std::shared_ptr<ServerPool> pool = createPoolIfNotExists(localPools, poolName);
      g_pools.setState(localPools);
      return pool;
    });

  luaCtx.writeFunction("setVerboseHealthChecks", [](bool verbose) { g_verboseHealthChecks=verbose; });
  luaCtx.writeFunction("setStaleCacheEntriesTTL", [](uint32_t ttl) { g_staleCacheEntriesTTL = ttl; });

  luaCtx.writeFunction("showBinds", []() {
      setLuaNoSideEffect();
      try {
        ostringstream ret;
        boost::format fmt("%1$-3d %2$-20.20s %|35t|%3$-20.20s %|57t|%4%" );
        //             1    2           3            4
        ret << (fmt % "#" % "Address" % "Protocol" % "Queries" ) << endl;

        size_t counter = 0;
        for (const auto& front : g_frontends) {
          ret << (fmt % counter % front->local.toStringWithPort() % front->getType() % front->queries) << endl;
          counter++;
        }
        g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

  luaCtx.writeFunction("getBind", [](size_t num) {
      setLuaNoSideEffect();
      ClientState* ret = nullptr;
      if(num < g_frontends.size()) {
        ret=g_frontends[num].get();
      }
      return ret;
      });

  luaCtx.writeFunction("getBindCount", []() {
      setLuaNoSideEffect();
      return g_frontends.size();
    });

  luaCtx.writeFunction("help", [](boost::optional<std::string> command) {
      setLuaNoSideEffect();
      g_outputBuffer = "";
      for (const auto& keyword : g_consoleKeywords) {
        if (!command) {
          g_outputBuffer += keyword.toString() + "\n";
        }
        else if (keyword.name == command) {
          g_outputBuffer = keyword.toString() + "\n";
          return;
        }
      }
      if (command) {
        g_outputBuffer = "Nothing found for " + *command + "\n";
      }
    });

  luaCtx.writeFunction("showVersion", []() {
      setLuaNoSideEffect();
      g_outputBuffer = "dnsdist " + std::string(VERSION) + "\n";
    });

  luaCtx.writeFunction("showSecurityStatus", []() {
      setLuaNoSideEffect();
      g_outputBuffer = std::to_string(g_stats.securityStatus) + "\n";
    });

#ifdef HAVE_EBPF
  luaCtx.writeFunction("setDefaultBPFFilter", [](std::shared_ptr<BPFFilter> bpf) {
      if (g_configurationDone) {
        g_outputBuffer="setDefaultBPFFilter() cannot be used at runtime!\n";
        return;
      }
      g_defaultBPFFilter = bpf;
    });

  luaCtx.writeFunction("registerDynBPFFilter", [](std::shared_ptr<DynBPFFilter> dbpf) {
      if (dbpf) {
        g_dynBPFFilters.push_back(dbpf);
      }
    });

  luaCtx.writeFunction("unregisterDynBPFFilter", [](std::shared_ptr<DynBPFFilter> dbpf) {
      if (dbpf) {
        for (auto it = g_dynBPFFilters.begin(); it != g_dynBPFFilters.end(); it++) {
          if (*it == dbpf) {
            g_dynBPFFilters.erase(it);
            break;
          }
        }
      }
    });

  luaCtx.writeFunction("addBPFFilterDynBlocks", [](const std::unordered_map<ComboAddress,unsigned int, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual>& m, std::shared_ptr<DynBPFFilter> dynbpf, boost::optional<int> seconds, boost::optional<std::string> msg) {
      if (!dynbpf) {
        return;
      }
      setLuaSideEffect();
      struct timespec until, now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      until=now;
      int actualSeconds = seconds ? *seconds : 10;
      until.tv_sec += actualSeconds;
      for(const auto& capair : m) {
        if (dynbpf->block(capair.first, until)) {
          warnlog("Inserting eBPF dynamic block for %s for %d seconds: %s", capair.first.toString(), actualSeconds, msg ? *msg : "");
        }
      }
    });

#endif /* HAVE_EBPF */

  luaCtx.writeFunction<std::unordered_map<string,uint64_t>()>("getStatisticsCounters", []() {
      setLuaNoSideEffect();
      std::unordered_map<string,uint64_t> res;
      for(const auto& entry : g_stats.entries) {
        if(const auto& val = boost::get<pdns::stat_t*>(&entry.second))
          res[entry.first] = (*val)->load();
      }
      return res;
    });

  luaCtx.writeFunction("includeDirectory", [&luaCtx](const std::string& dirname) {
      if (g_configurationDone) {
        errlog("includeDirectory() cannot be used at runtime!");
        g_outputBuffer="includeDirectory() cannot be used at runtime!\n";
        return;
      }

      if (g_included) {
        errlog("includeDirectory() cannot be used recursively!");
        g_outputBuffer="includeDirectory() cannot be used recursively!\n";
        return;
      }

      g_included = true;
      struct stat st;
      if (stat(dirname.c_str(), &st)) {
        errlog("The included directory %s does not exist!", dirname.c_str());
        g_outputBuffer="The included directory " + dirname + " does not exist!";
        return;
      }

      if (!S_ISDIR(st.st_mode)) {
        errlog("The included directory %s is not a directory!", dirname.c_str());
        g_outputBuffer="The included directory " + dirname + " is not a directory!";
        return;
      }

      DIR *dirp;
      struct dirent *ent;
      std::list<std::string> files;
      if (!(dirp = opendir(dirname.c_str()))) {
        errlog("Error opening the included directory %s!", dirname.c_str());
        g_outputBuffer="Error opening the included directory " + dirname + "!";
        return;
      }

      while((ent = readdir(dirp)) != NULL) {
        if (ent->d_name[0] == '.') {
          continue;
        }

        if (boost::ends_with(ent->d_name, ".conf")) {
          std::ostringstream namebuf;
          namebuf << dirname.c_str() << "/" << ent->d_name;

          if (stat(namebuf.str().c_str(), &st) || !S_ISREG(st.st_mode)) {
            continue;
          }

          files.push_back(namebuf.str());
        }
      }

      closedir(dirp);
      files.sort();

      for (auto file = files.begin(); file != files.end(); ++file) {
        std::ifstream ifs(*file);
        if (!ifs) {
          warnlog("Unable to read configuration from '%s'", *file);
        } else {
          vinfolog("Read configuration from '%s'", *file);
        }

        luaCtx.executeCode(ifs);
      }

      g_included = false;
    });

  luaCtx.writeFunction("setAPIWritable", [](bool writable, boost::optional<std::string> apiConfigDir) {
      setLuaSideEffect();
      g_apiReadWrite = writable;
      if (apiConfigDir) {
        if (!(*apiConfigDir).empty()) {
          g_apiConfigDirectory = *apiConfigDir;
        }
        else {
          errlog("The API configuration directory value cannot be empty!");
          g_outputBuffer="The API configuration directory value cannot be empty!";
        }
      }
    });

  luaCtx.writeFunction("setServFailWhenNoServer", [](bool servfail) {
      setLuaSideEffect();
      g_servFailOnNoPolicy = servfail;
    });

  luaCtx.writeFunction("setRoundRobinFailOnNoServer", [](bool fail) {
      setLuaSideEffect();
      g_roundrobinFailOnNoServer = fail;
    });

  luaCtx.writeFunction("setConsistentHashingBalancingFactor", [](double factor) {
      setLuaSideEffect();
      if (factor >= 1.0) {
        g_consistentHashBalancingFactor = factor;
      }
      else {
        errlog("Invalid value passed to setConsistentHashingBalancingFactor()!");
        g_outputBuffer="Invalid value passed to setConsistentHashingBalancingFactor()!\n";
        return;
      }
    });

  luaCtx.writeFunction("setWeightedBalancingFactor", [](double factor) {
      setLuaSideEffect();
      if (factor >= 1.0) {
        g_weightedBalancingFactor = factor;
      }
      else {
        errlog("Invalid value passed to setWeightedBalancingFactor()!");
        g_outputBuffer="Invalid value passed to setWeightedBalancingFactor()!\n";
        return;
      }
    });

  luaCtx.writeFunction("setRingBuffersSize", [client](size_t capacity, boost::optional<size_t> numberOfShards) {
      setLuaSideEffect();
      if (g_configurationDone) {
        errlog("setRingBuffersSize() cannot be used at runtime!");
        g_outputBuffer="setRingBuffersSize() cannot be used at runtime!\n";
        return;
      }
      if (!client) {
        g_rings.setCapacity(capacity, numberOfShards ? *numberOfShards : 10);
      }
      else {
        g_rings.setCapacity(0, 1);
      }
    });

  luaCtx.writeFunction("setRingBuffersLockRetries", [](size_t retries) {
      setLuaSideEffect();
      g_rings.setNumberOfLockRetries(retries);
    });

  luaCtx.writeFunction("setWHashedPertubation", [](uint32_t pertub) {
      setLuaSideEffect();
      g_hashperturb = pertub;
    });

  luaCtx.writeFunction("setTCPUseSinglePipe", [](bool flag) {
      if (g_configurationDone) {
        g_outputBuffer="setTCPUseSinglePipe() cannot be used at runtime!\n";
        return;
      }
      setLuaSideEffect();
      g_useTCPSinglePipe = flag;
    });

  luaCtx.writeFunction("setTCPInternalPipeBufferSize", [](size_t size) { g_tcpInternalPipeBufferSize = size; });

  luaCtx.writeFunction("snmpAgent", [client,configCheck](bool enableTraps, boost::optional<std::string> daemonSocket) {
      if(client || configCheck)
        return;
#ifdef HAVE_NET_SNMP
      if (g_configurationDone) {
        errlog("snmpAgent() cannot be used at runtime!");
        g_outputBuffer="snmpAgent() cannot be used at runtime!\n";
        return;
      }

      if (g_snmpEnabled) {
        errlog("snmpAgent() cannot be used twice!");
        g_outputBuffer="snmpAgent() cannot be used twice!\n";
        return;
      }

      g_snmpEnabled = true;
      g_snmpTrapsEnabled = enableTraps;
      g_snmpAgent = new DNSDistSNMPAgent("dnsdist", daemonSocket ? *daemonSocket : std::string());
#else
      errlog("NET SNMP support is required to use snmpAgent()");
      g_outputBuffer="NET SNMP support is required to use snmpAgent()\n";
#endif /* HAVE_NET_SNMP */
    });

  luaCtx.writeFunction("sendCustomTrap", [](const std::string& str) {
      if (g_snmpAgent && g_snmpTrapsEnabled) {
        g_snmpAgent->sendCustomTrap(str);
      }
    });

  luaCtx.writeFunction("setServerPolicy", [](ServerPolicy policy) {
      setLuaSideEffect();
      g_policy.setState(policy);
    });

  luaCtx.writeFunction("setServerPolicyLua", [](string name, ServerPolicy::policyfunc_t policy) {
      setLuaSideEffect();
      g_policy.setState(ServerPolicy{name, policy, true});
    });

  luaCtx.writeFunction("setServerPolicyLuaFFI", [](string name, ServerPolicy::ffipolicyfunc_t policy) {
      setLuaSideEffect();
      auto pol = ServerPolicy(name, policy);
      g_policy.setState(std::move(pol));
    });

  luaCtx.writeFunction("setServerPolicyLuaFFIPerThread", [](string name, const std::string& policyCode) {
      setLuaSideEffect();
      auto pol = ServerPolicy(name, policyCode);
      g_policy.setState(std::move(pol));
    });

  luaCtx.writeFunction("showServerPolicy", []() {
      setLuaSideEffect();
      g_outputBuffer=g_policy.getLocal()->getName()+"\n";
    });

  luaCtx.writeFunction("setPoolServerPolicy", [](ServerPolicy policy, string pool) {
      setLuaSideEffect();
      auto localPools = g_pools.getCopy();
      setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(policy));
      g_pools.setState(localPools);
    });

  luaCtx.writeFunction("setPoolServerPolicyLua", [](string name, ServerPolicy::policyfunc_t policy, string pool) {
      setLuaSideEffect();
      auto localPools = g_pools.getCopy();
      setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(ServerPolicy{name, policy, true}));
      g_pools.setState(localPools);
    });

  luaCtx.writeFunction("setPoolServerPolicyLuaFFI", [](string name, ServerPolicy::ffipolicyfunc_t policy, string pool) {
      setLuaSideEffect();
      auto localPools = g_pools.getCopy();
      setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(ServerPolicy{name, policy}));
      g_pools.setState(localPools);
    });

  luaCtx.writeFunction("setPoolServerPolicyLuaFFIPerThread", [](string name, const std::string& policyCode, string pool) {
      setLuaSideEffect();
      auto localPools = g_pools.getCopy();
      setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(ServerPolicy{name, policyCode}));
      g_pools.setState(localPools);
    });

  luaCtx.writeFunction("showPoolServerPolicy", [](string pool) {
      setLuaSideEffect();
      auto localPools = g_pools.getCopy();
      auto poolObj = getPool(localPools, pool);
      if (poolObj->policy == nullptr) {
        g_outputBuffer=g_policy.getLocal()->getName()+"\n";
      } else {
        g_outputBuffer=poolObj->policy->getName()+"\n";
      }
    });

  luaCtx.writeFunction("setTCPDownstreamCleanupInterval", [](uint16_t interval) {
      setLuaSideEffect();
      g_downstreamTCPCleanupInterval = interval;
    });

  luaCtx.writeFunction("setConsoleConnectionsLogging", [](bool enabled) {
      g_logConsoleConnections = enabled;
    });

  luaCtx.writeFunction("setConsoleOutputMaxMsgSize", [](uint32_t size) {
      g_consoleOutputMsgMaxSize = size;
    });

  luaCtx.writeFunction("setProxyProtocolACL", [](boost::variant<string,vector<pair<int, string>>> inp) {
    if (g_configurationDone) {
      errlog("setProxyProtocolACL() cannot be used at runtime!");
      g_outputBuffer="setProxyProtocolACL() cannot be used at runtime!\n";
      return;
    }
    setLuaSideEffect();
    NetmaskGroup nmg;
    if (auto str = boost::get<string>(&inp)) {
      nmg.addMask(*str);
    }
    else {
      for(const auto& p : boost::get<vector<pair<int,string>>>(inp)) {
	nmg.addMask(p.second);
      }
    }
    g_proxyProtocolACL = std::move(nmg);
  });

  luaCtx.writeFunction("setProxyProtocolApplyACLToProxiedClients", [](bool apply) {
    if (g_configurationDone) {
      errlog("setProxyProtocolApplyACLToProxiedClients() cannot be used at runtime!");
      g_outputBuffer="setProxyProtocolApplyACLToProxiedClients() cannot be used at runtime!\n";
      return;
    }
    setLuaSideEffect();
    g_applyACLToProxiedClients = apply;
  });

  luaCtx.writeFunction("setProxyProtocolMaximumPayloadSize", [](size_t size) {
    if (g_configurationDone) {
      errlog("setProxyProtocolMaximumPayloadSize() cannot be used at runtime!");
      g_outputBuffer="setProxyProtocolMaximumPayloadSize() cannot be used at runtime!\n";
      return;
    }
    setLuaSideEffect();
    g_proxyProtocolMaximumSize = std::max(static_cast<size_t>(16), size);
  });

  luaCtx.writeFunction("setUDPMultipleMessagesVectorSize", [](size_t vSize) {
      if (g_configurationDone) {
        errlog("setUDPMultipleMessagesVectorSize() cannot be used at runtime!");
        g_outputBuffer="setUDPMultipleMessagesVectorSize() cannot be used at runtime!\n";
        return;
      }
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
      setLuaSideEffect();
      g_udpVectorSize = vSize;
#else
      errlog("recvmmsg() support is not available!");
      g_outputBuffer="recvmmsg support is not available!\n";
#endif
    });

  luaCtx.writeFunction("setAddEDNSToSelfGeneratedResponses", [](bool add) {
      g_addEDNSToSelfGeneratedResponses = add;
  });

  luaCtx.writeFunction("setPayloadSizeOnSelfGeneratedAnswers", [](uint16_t payloadSize) {
      if (payloadSize < 512) {
        warnlog("setPayloadSizeOnSelfGeneratedAnswers() is set too low, using 512 instead!");
        g_outputBuffer="setPayloadSizeOnSelfGeneratedAnswers() is set too low, using 512 instead!";
        payloadSize = 512;
      }
      if (payloadSize > s_udpIncomingBufferSize) {
        warnlog("setPayloadSizeOnSelfGeneratedAnswers() is set too high, capping to %d instead!", s_udpIncomingBufferSize);
        g_outputBuffer="setPayloadSizeOnSelfGeneratedAnswers() is set too high, capping to " + std::to_string(s_udpIncomingBufferSize) + " instead";
        payloadSize = s_udpIncomingBufferSize;
      }
      g_PayloadSizeSelfGenAnswers = payloadSize;
  });

  luaCtx.writeFunction("setSecurityPollSuffix", [](const std::string& suffix) {
      if (g_configurationDone) {
        g_outputBuffer="setSecurityPollSuffix() cannot be used at runtime!\n";
        return;
      }

      g_secPollSuffix = suffix;
  });

  luaCtx.writeFunction("setSecurityPollInterval", [](time_t newInterval) {
      if (newInterval <= 0) {
        warnlog("setSecurityPollInterval() should be > 0, skipping");
        g_outputBuffer="setSecurityPollInterval() should be > 0, skipping";
      }

      g_secPollInterval = newInterval;
  });

  luaCtx.writeFunction("setSyslogFacility", [](boost::variant<int,std::string> facility) {
    setLuaSideEffect();
    if (g_configurationDone) {
      g_outputBuffer="setSyslogFacility cannot be used at runtime!\n";
      return;
    }
    if (facility.type() == typeid(std::string)) {
      static std::map<std::string, int> const facilities = {
        { "local0", LOG_LOCAL0 },
        { "log_local0", LOG_LOCAL0 },
        { "local1", LOG_LOCAL1 },
        { "log_local1", LOG_LOCAL1 },
        { "local2", LOG_LOCAL2 },
        { "log_local2", LOG_LOCAL2 },
        { "local3", LOG_LOCAL3 },
        { "log_local3", LOG_LOCAL3 },
        { "local4", LOG_LOCAL4 },
        { "log_local4", LOG_LOCAL4 },
        { "local5", LOG_LOCAL5 },
        { "log_local5", LOG_LOCAL5 },
        { "local6", LOG_LOCAL6 },
        { "log_local6", LOG_LOCAL6 },
        { "local7", LOG_LOCAL7 },
        { "log_local7", LOG_LOCAL7 },
        /* most of these likely make very little sense
           for dnsdist, but why not? */
        { "kern", LOG_KERN },
        { "log_kern", LOG_KERN },
        { "user", LOG_USER },
        { "log_user", LOG_USER },
        { "mail", LOG_MAIL },
        { "log_mail", LOG_MAIL },
        { "daemon", LOG_DAEMON },
        { "log_daemon", LOG_DAEMON },
        { "auth", LOG_AUTH },
        { "log_auth", LOG_AUTH },
        { "syslog", LOG_SYSLOG },
        { "log_syslog", LOG_SYSLOG },
        { "lpr", LOG_LPR },
        { "log_lpr", LOG_LPR },
        { "news", LOG_NEWS },
        { "log_news", LOG_NEWS },
        { "uucp", LOG_UUCP },
        { "log_uucp", LOG_UUCP },
        { "cron", LOG_CRON },
        { "log_cron", LOG_CRON },
        { "authpriv", LOG_AUTHPRIV },
        { "log_authpriv", LOG_AUTHPRIV },
        { "ftp", LOG_FTP },
        { "log_ftp", LOG_FTP }
      };
      auto facilityStr = boost::get<std::string>(facility);
      toLowerInPlace(facilityStr);
      auto it = facilities.find(facilityStr);
      if (it == facilities.end()) {
        g_outputBuffer="Unknown facility '" + facilityStr + "' passed to setSyslogFacility()!\n";
        return;
      }
      setSyslogFacility(it->second);
    }
    else {
      setSyslogFacility(boost::get<int>(facility));
    }
  });

  luaCtx.writeFunction("addDOHLocal", [client](const std::string& addr, boost::optional<boost::variant<std::string, std::vector<std::pair<int,std::string>>>> certFiles, boost::optional<boost::variant<std::string, std::vector<std::pair<int,std::string>>>> keyFiles, boost::optional<boost::variant<std::string, vector<pair<int, std::string> > > > urls, boost::optional<localbind_t> vars) {
    if (client) {
      return;
    }
#ifdef HAVE_DNS_OVER_HTTPS
    setLuaSideEffect();
    if (g_configurationDone) {
      g_outputBuffer="addDOHLocal cannot be used at runtime!\n";
      return;
    }
    auto frontend = std::make_shared<DOHFrontend>();

    if (certFiles && !certFiles->empty() && keyFiles && !keyFiles->empty()) {
      if (!loadTLSCertificateAndKeys("addDOHLocal", frontend->d_tlsConfig.d_certKeyPairs, *certFiles, *keyFiles)) {
        return;
      }

      frontend->d_local = ComboAddress(addr, 443);
    }
    else {
      frontend->d_local = ComboAddress(addr, 80);
      infolog("No certificate provided for DoH endpoint %s, running in DNS over HTTP mode instead of DNS over HTTPS", frontend->d_local.toStringWithPort());
    }

    if (urls) {
      if (urls->type() == typeid(std::string)) {
        frontend->d_urls.push_back(boost::get<std::string>(*urls));
      }
      else if (urls->type() == typeid(std::vector<std::pair<int,std::string>>)) {
        auto urlsVect = boost::get<std::vector<std::pair<int,std::string>>>(*urls);
        for(const auto& p : urlsVect) {
          frontend->d_urls.push_back(p.second);
        }
      }
    }
    else {
      frontend->d_urls = {"/dns-query"};
    }

    bool reusePort = false;
    int tcpFastOpenQueueSize = 0;
    int tcpListenQueueSize = 0;
    size_t maxInFlightQueriesPerConn = 0;
    size_t tcpMaxConcurrentConnections = 0;
    std::string interface;
    std::set<int> cpus;

    if (vars) {
      parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConnections);

      if (vars->count("idleTimeout")) {
        frontend->d_idleTimeout = boost::get<int>((*vars)["idleTimeout"]);
      }

      if (vars->count("serverTokens")) {
        frontend->d_serverTokens = boost::get<const string>((*vars)["serverTokens"]);
      }

      if (vars->count("customResponseHeaders")) {
        for (auto const& headerMap : boost::get<std::map<std::string,std::string>>((*vars)["customResponseHeaders"])) {
          std::pair<std::string,std::string> headerResponse = std::make_pair(boost::to_lower_copy(headerMap.first), headerMap.second);
          frontend->d_customResponseHeaders.push_back(headerResponse);
        }
      }

      if (vars->count("sendCacheControlHeaders")) {
        frontend->d_sendCacheControlHeaders = boost::get<bool>((*vars)["sendCacheControlHeaders"]);
      }

      if (vars->count("trustForwardedForHeader")) {
        frontend->d_trustForwardedForHeader = boost::get<bool>((*vars)["trustForwardedForHeader"]);
      }

      if (vars->count("internalPipeBufferSize")) {
        frontend->d_internalPipeBufferSize = boost::get<int>((*vars)["internalPipeBufferSize"]);
      }

      if (vars->count("exactPathMatching")) {
        frontend->d_exactPathMatching = boost::get<bool>((*vars)["exactPathMatching"]);
      }

      parseTLSConfig(frontend->d_tlsConfig, "addDOHLocal", vars);
    }
    g_dohlocals.push_back(frontend);
    auto cs = std::unique_ptr<ClientState>(new ClientState(frontend->d_local, true, reusePort, tcpFastOpenQueueSize, interface, cpus));
    cs->dohFrontend = frontend;
    if (tcpListenQueueSize > 0) {
      cs->tcpListenQueueSize = tcpListenQueueSize;
    }
    if (tcpMaxConcurrentConnections > 0) {
      cs->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConnections;
    }
    g_frontends.push_back(std::move(cs));
#else
    throw std::runtime_error("addDOHLocal() called but DNS over HTTPS support is not present!");
#endif
  });

  luaCtx.writeFunction("showDOHFrontends", []() {
#ifdef HAVE_DNS_OVER_HTTPS
        setLuaNoSideEffect();
        try {
          ostringstream ret;
          boost::format fmt("%-3d %-20.20s %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d %-15d");
          ret << (fmt % "#" % "Address" % "HTTP" % "HTTP/1" % "HTTP/2" % "GET" % "POST" % "Bad" % "Errors" % "Redirects" % "Valid" % "# ticket keys" % "Rotation delay" % "Next rotation") << endl;
          size_t counter = 0;
          for (const auto& ctx : g_dohlocals) {
            ret << (fmt % counter % ctx->d_local.toStringWithPort() % ctx->d_httpconnects % ctx->d_http1Stats.d_nbQueries % ctx->d_http2Stats.d_nbQueries % ctx->d_getqueries % ctx->d_postqueries % ctx->d_badrequests % ctx->d_errorresponses % ctx->d_redirectresponses % ctx->d_validresponses % ctx->getTicketsKeysCount() % ctx->getTicketsKeyRotationDelay() % ctx->getNextTicketsKeyRotation()) << endl;
            counter++;
          }
          g_outputBuffer = ret.str();
        }
        catch(const std::exception& e) {
          g_outputBuffer = e.what();
          throw;
        }
#else
        g_outputBuffer="DNS over HTTPS support is not present!\n";
#endif
      });

    luaCtx.writeFunction("showDOHResponseCodes", []() {
#ifdef HAVE_DNS_OVER_HTTPS
        setLuaNoSideEffect();
        try {
          ostringstream ret;
          boost::format fmt("%-3d %-20.20s %-15d %-15d %-15d %-15d %-15d %-15d");
          g_outputBuffer = "\n- HTTP/1:\n\n";
          ret << (fmt % "#" % "Address" % "200" % "400" % "403" % "500" % "502" % "Others" ) << endl;
          size_t counter = 0;
          for (const auto& ctx : g_dohlocals) {
            ret << (fmt % counter % ctx->d_local.toStringWithPort() % ctx->d_http1Stats.d_nb200Responses % ctx->d_http1Stats.d_nb400Responses % ctx->d_http1Stats.d_nb403Responses % ctx->d_http1Stats.d_nb500Responses % ctx->d_http1Stats.d_nb502Responses % ctx->d_http1Stats.d_nbOtherResponses) << endl;
            counter++;
          }
          g_outputBuffer += ret.str();
          ret.str("");

          g_outputBuffer += "\n- HTTP/2:\n\n";
          ret << (fmt % "#" % "Address" % "200" % "400" % "403" % "500" % "502" % "Others" ) << endl;
          counter = 0;
          for (const auto& ctx : g_dohlocals) {
            ret << (fmt % counter % ctx->d_local.toStringWithPort() % ctx->d_http2Stats.d_nb200Responses % ctx->d_http2Stats.d_nb400Responses % ctx->d_http2Stats.d_nb403Responses % ctx->d_http2Stats.d_nb500Responses % ctx->d_http2Stats.d_nb502Responses % ctx->d_http2Stats.d_nbOtherResponses) << endl;
            counter++;
          }
          g_outputBuffer += ret.str();
        }
        catch(const std::exception& e) {
          g_outputBuffer = e.what();
          throw;
        }
#else
        g_outputBuffer="DNS over HTTPS support is not present!\n";
#endif
      });

    luaCtx.writeFunction("getDOHFrontend", [client](size_t index) {
        std::shared_ptr<DOHFrontend> result = nullptr;
        if (client) {
          return result;
        }
#ifdef HAVE_DNS_OVER_HTTPS
        setLuaNoSideEffect();
        try {
          if (index < g_dohlocals.size()) {
            result = g_dohlocals.at(index);
          }
          else {
            errlog("Error: trying to get DOH frontend with index %zu but we only have %zu frontend(s)\n", index, g_dohlocals.size());
            g_outputBuffer="Error: trying to get DOH frontend with index " + std::to_string(index) + " but we only have " + std::to_string(g_dohlocals.size()) + " frontend(s)\n";
          }
        }
        catch(const std::exception& e) {
          g_outputBuffer="Error while trying to get DOH frontend with index " + std::to_string(index) + ": "+string(e.what())+"\n";
          errlog("Error while trying to get DOH frontend with index %zu: %s\n", index, string(e.what()));
        }
#else
        g_outputBuffer="DNS over HTTPS support is not present!\n";
#endif
        return result;
      });

    luaCtx.writeFunction("getDOHFrontendCount", []() {
        setLuaNoSideEffect();
        return g_dohlocals.size();
      });

    luaCtx.registerFunction<void(std::shared_ptr<DOHFrontend>::*)()>("reloadCertificates", [](std::shared_ptr<DOHFrontend> frontend) {
        if (frontend != nullptr) {
          frontend->reloadCertificates();
        }
      });

    luaCtx.registerFunction<void(std::shared_ptr<DOHFrontend>::*)(boost::variant<std::string, std::vector<std::pair<int,std::string>>> certFiles, boost::variant<std::string, std::vector<std::pair<int,std::string>>> keyFiles)>("loadNewCertificatesAndKeys", [](std::shared_ptr<DOHFrontend> frontend, boost::variant<std::string, std::vector<std::pair<int,std::string>>> certFiles, boost::variant<std::string, std\
::vector<std::pair<int,std::string>>> keyFiles) {
#ifdef HAVE_DNS_OVER_HTTPS
        if (frontend != nullptr) {
          if (loadTLSCertificateAndKeys("DOHFrontend::loadNewCertificatesAndKeys", frontend->d_tlsConfig.d_certKeyPairs, certFiles, keyFiles)) {
            frontend->reloadCertificates();
          }
        }
#endif
      });

    luaCtx.registerFunction<void(std::shared_ptr<DOHFrontend>::*)()>("rotateTicketsKey", [](std::shared_ptr<DOHFrontend> frontend) {
        if (frontend != nullptr) {
          frontend->rotateTicketsKey(time(nullptr));
        }
      });

    luaCtx.registerFunction<void(std::shared_ptr<DOHFrontend>::*)(const std::string&)>("loadTicketsKeys", [](std::shared_ptr<DOHFrontend> frontend, const std::string& file) {
        if (frontend != nullptr) {
          frontend->loadTicketsKeys(file);
        }
      });

    luaCtx.registerFunction<void(std::shared_ptr<DOHFrontend>::*)(const std::map<int, std::shared_ptr<DOHResponseMapEntry>>&)>("setResponsesMap", [](std::shared_ptr<DOHFrontend> frontend, const std::map<int, std::shared_ptr<DOHResponseMapEntry>>& map) {
        if (frontend != nullptr) {
          auto newMap = std::make_shared<std::vector<std::shared_ptr<DOHResponseMapEntry>>>();
          newMap->reserve(map.size());

          for (const auto& entry : map) {
            newMap->push_back(entry.second);
          }

          frontend->d_responsesMap = std::move(newMap);
        }
      });

  luaCtx.writeFunction("addTLSLocal", [client](const std::string& addr, boost::variant<std::string, std::vector<std::pair<int,std::string>>> certFiles, boost::variant<std::string, std::vector<std::pair<int,std::string>>> keyFiles, boost::optional<localbind_t> vars) {
        if (client) {
          return;
        }
#ifdef HAVE_DNS_OVER_TLS
        setLuaSideEffect();
        if (g_configurationDone) {
          g_outputBuffer="addTLSLocal cannot be used at runtime!\n";
          return;
        }
        shared_ptr<TLSFrontend> frontend = std::make_shared<TLSFrontend>();

        if (!loadTLSCertificateAndKeys("addTLSLocal", frontend->d_tlsConfig.d_certKeyPairs, certFiles, keyFiles)) {
          return;
        }

        bool reusePort = false;
        int tcpFastOpenQueueSize = 0;
        int tcpListenQueueSize = 0;
        size_t maxInFlightQueriesPerConn = 0;
        size_t tcpMaxConcurrentConns = 0;
        std::string interface;
        std::set<int> cpus;

        if (vars) {
          parseLocalBindVars(vars, reusePort, tcpFastOpenQueueSize, interface, cpus, tcpListenQueueSize, maxInFlightQueriesPerConn, tcpMaxConcurrentConns);

          if (vars->count("provider")) {
            frontend->d_provider = boost::get<const string>((*vars)["provider"]);
            boost::algorithm::to_lower(frontend->d_provider);
          }

          parseTLSConfig(frontend->d_tlsConfig, "addTLSLocal", vars);
        }

        try {
          frontend->d_addr = ComboAddress(addr, 853);
          if (!frontend->d_provider.empty()) {
            vinfolog("Loading TLS provider '%s'", frontend->d_provider);
          }
          else {
#ifdef HAVE_LIBSSL
            vinfolog("Loading default TLS provider 'openssl'");
#else
            vinfolog("Loading default TLS provider 'gnutls'");
#endif
          }
          // only works pre-startup, so no sync necessary
          auto cs = std::unique_ptr<ClientState>(new ClientState(frontend->d_addr, true, reusePort, tcpFastOpenQueueSize, interface, cpus));
          cs->tlsFrontend = frontend;
          if (tcpListenQueueSize > 0) {
            cs->tcpListenQueueSize = tcpListenQueueSize;
          }
          if (maxInFlightQueriesPerConn > 0) {
            cs->d_maxInFlightQueriesPerConn = maxInFlightQueriesPerConn;
          }
          if (tcpMaxConcurrentConns > 0) {
            cs->d_tcpConcurrentConnectionsLimit = tcpMaxConcurrentConns;
          }

          g_tlslocals.push_back(cs->tlsFrontend);
          g_frontends.push_back(std::move(cs));
        }
        catch(const std::exception& e) {
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }
#else
        throw std::runtime_error("addTLSLocal() called but DNS over TLS support is not present!");
#endif
      });

    luaCtx.writeFunction("showTLSContexts", []() {
#ifdef HAVE_DNS_OVER_TLS
        setLuaNoSideEffect();
        try {
          ostringstream ret;
          boost::format fmt("%1$-3d %2$-20.20s %|25t|%3$-14d %|40t|%4$-14d %|54t|%5$-21.21s");
          //             1    2           3                 4                  5
          ret << (fmt % "#" % "Address" % "# ticket keys" % "Rotation delay" % "Next rotation" ) << endl;
          size_t counter = 0;
          for (const auto& ctx : g_tlslocals) {
            ret << (fmt % counter % ctx->d_addr.toStringWithPort() % ctx->getTicketsKeysCount() % ctx->getTicketsKeyRotationDelay() % ctx->getNextTicketsKeyRotation()) << endl;
            counter++;
          }
          g_outputBuffer = ret.str();
        }
        catch(const std::exception& e) {
          g_outputBuffer = e.what();
          throw;
        }
#else
        g_outputBuffer="DNS over TLS support is not present!\n";
#endif
      });

    luaCtx.writeFunction("getTLSContext", [](size_t index) {
        std::shared_ptr<TLSCtx> result = nullptr;
#ifdef HAVE_DNS_OVER_TLS
        setLuaNoSideEffect();
        try {
          if (index < g_tlslocals.size()) {
            result = g_tlslocals.at(index)->getContext();
          }
          else {
            errlog("Error: trying to get TLS context with index %zu but we only have %zu context(s)\n", index, g_tlslocals.size());
            g_outputBuffer="Error: trying to get TLS context with index " + std::to_string(index) + " but we only have " + std::to_string(g_tlslocals.size()) + " context(s)\n";
          }
        }
        catch(const std::exception& e) {
          g_outputBuffer="Error while trying to get TLS context with index " + std::to_string(index) + ": "+string(e.what())+"\n";
          errlog("Error while trying to get TLS context with index %zu: %s\n", index, string(e.what()));
        }
#else
        g_outputBuffer="DNS over TLS support is not present!\n";
#endif
        return result;
      });

    luaCtx.writeFunction("getTLSFrontend", [](size_t index) {
        std::shared_ptr<TLSFrontend> result = nullptr;
#ifdef HAVE_DNS_OVER_TLS
        setLuaNoSideEffect();
        try {
          if (index < g_tlslocals.size()) {
            result = g_tlslocals.at(index);
          }
          else {
            errlog("Error: trying to get TLS frontend with index %zu but we only have %zu frontends\n", index, g_tlslocals.size());
            g_outputBuffer="Error: trying to get TLS frontend with index " + std::to_string(index) + " but we only have " + std::to_string(g_tlslocals.size()) + " frontend(s)\n";
          }
        }
        catch(const std::exception& e) {
          g_outputBuffer="Error while trying to get TLS frontend with index " + std::to_string(index) + ": "+string(e.what())+"\n";
          errlog("Error while trying to get TLS frontend with index %zu: %s\n", index, string(e.what()));
        }
#else
        g_outputBuffer="DNS over TLS support is not present!\n";
#endif
        return result;
      });

    luaCtx.writeFunction("getTLSFrontendCount", []() {
        setLuaNoSideEffect();
        return g_tlslocals.size();
      });

    luaCtx.registerFunction<void(std::shared_ptr<TLSCtx>::*)()>("rotateTicketsKey", [](std::shared_ptr<TLSCtx>& ctx) {
        if (ctx != nullptr) {
          ctx->rotateTicketsKey(time(nullptr));
        }
      });

    luaCtx.registerFunction<void(std::shared_ptr<TLSCtx>::*)(const std::string&)>("loadTicketsKeys", [](std::shared_ptr<TLSCtx>& ctx, const std::string& file) {
        if (ctx != nullptr) {
          ctx->loadTicketsKeys(file);
        }
      });

    luaCtx.registerFunction<void(std::shared_ptr<TLSFrontend>::*)()>("rotateTicketsKey", [](std::shared_ptr<TLSFrontend>& frontend) {
        if (frontend == nullptr) {
          return;
        }
        auto ctx = frontend->getContext();
        if (ctx) {
          ctx->rotateTicketsKey(time(nullptr));
        }
      });

    luaCtx.registerFunction<void(std::shared_ptr<TLSFrontend>::*)(const std::string&)>("loadTicketsKeys", [](std::shared_ptr<TLSFrontend>& frontend, const std::string& file) {
        if (frontend == nullptr) {
          return;
        }
        auto ctx = frontend->getContext();
        if (ctx) {
          ctx->loadTicketsKeys(file);
        }
      });

    luaCtx.registerFunction<void(std::shared_ptr<TLSFrontend>::*)()>("reloadCertificates", [](std::shared_ptr<TLSFrontend>& frontend) {
        if (frontend == nullptr) {
          return;
        }
        frontend->setupTLS();
      });

    luaCtx.registerFunction<void(std::shared_ptr<TLSFrontend>::*)(boost::variant<std::string, std::vector<std::pair<int,std::string>>> certFiles, boost::variant<std::string, std::vector<std::pair<int,std::string>>> keyFiles)>("loadNewCertificatesAndKeys", [](std::shared_ptr<TLSFrontend>& frontend, boost::variant<std::string, std::vector<std::pair<int,std::string>>> certFiles, boost::variant<std::string, std::vector<std::pair<int,std::string>>> keyFiles) {
#ifdef HAVE_DNS_OVER_TLS
        if (loadTLSCertificateAndKeys("TLSFrontend::loadNewCertificatesAndKeys", frontend->d_tlsConfig.d_certKeyPairs, certFiles, keyFiles)) {
          frontend->setupTLS();
        }
#endif
      });

    luaCtx.writeFunction("reloadAllCertificates", []() {
        for (auto& frontend : g_frontends) {
          if (!frontend) {
            continue;
          }
          try {
#ifdef HAVE_DNSCRYPT
            if (frontend->dnscryptCtx) {
              frontend->dnscryptCtx->reloadCertificates();
            }
#endif /* HAVE_DNSCRYPT */
#ifdef HAVE_DNS_OVER_TLS
            if (frontend->tlsFrontend) {
              frontend->tlsFrontend->setupTLS();
            }
#endif /* HAVE_DNS_OVER_TLS */
#ifdef HAVE_DNS_OVER_HTTPS
            if (frontend->dohFrontend) {
              frontend->dohFrontend->reloadCertificates();
            }
#endif /* HAVE_DNS_OVER_HTTPS */
          }
          catch(const std::exception& e) {
            errlog("Error reloading certificates for frontend %s: %s", frontend->local.toStringWithPort(), e.what());
          }
        }
      });

    luaCtx.writeFunction("setAllowEmptyResponse", [](bool allow) { g_allowEmptyResponse=allow; });
    luaCtx.writeFunction("setDropEmptyQueries", [](bool drop) { extern bool g_dropEmptyQueries; g_dropEmptyQueries = drop; });

#if defined(HAVE_LIBSSL) && defined(HAVE_OCSP_BASIC_SIGN)
    luaCtx.writeFunction("generateOCSPResponse", [client](const std::string& certFile, const std::string& caCert, const std::string& caKey, const std::string& outFile, int ndays, int nmin) {
      if (client) {
        return;
      }

      libssl_generate_ocsp_response(certFile, caCert, caKey, outFile, ndays, nmin);
    });
#endif /* HAVE_LIBSSL && HAVE_OCSP_BASIC_SIGN*/
}

vector<std::function<void(void)>> setupLua(LuaContext& luaCtx, bool client, bool configCheck, const std::string& config)
{
  // this needs to exist only during the parsing of the configuration
  // and cannot be captured by lambdas
  g_launchWork = std::vector<std::function<void(void)>>();

  setupLuaActions(luaCtx);
  setupLuaConfig(luaCtx, client, configCheck);
  setupLuaBindings(luaCtx, client);
  setupLuaBindingsDNSCrypt(luaCtx);
  setupLuaBindingsDNSQuestion(luaCtx);
  setupLuaBindingsKVS(luaCtx, client);
  setupLuaBindingsPacketCache(luaCtx, client);
  setupLuaBindingsProtoBuf(luaCtx, client, configCheck);
  setupLuaInspection(luaCtx);
  setupLuaRules(luaCtx);
  setupLuaVars(luaCtx);
  setupLuaWeb(luaCtx);

#ifdef LUAJIT_VERSION
  luaCtx.executeCode(getLuaFFIWrappers());
#endif

  std::ifstream ifs(config);
  if(!ifs)
    warnlog("Unable to read configuration from '%s'", config);
  else
    vinfolog("Read configuration from '%s'", config);

  luaCtx.executeCode(ifs);

  auto ret = *g_launchWork;
  g_launchWork = boost::none;
  return ret;
}
