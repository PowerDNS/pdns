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
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>

#include "dnsdist.hh"
#include "dnsdist-console.hh"
#include "dnsdist-lua.hh"

#include "base64.hh"
#include "dnswriter.hh"
#include "dolog.hh"
#include "lock.hh"
#include "protobuf.hh"
#include "sodcrypto.hh"

#include <boost/logic/tribool.hpp>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

using std::thread;

static vector<std::function<void(void)>>* g_launchWork = nullptr;

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
  return g_noLuaSideEffect==true;
}

void resetLuaSideEffect()
{
  g_noLuaSideEffect = boost::logic::indeterminate;
}

typedef std::unordered_map<std::string, boost::variant<bool, int, std::string, std::vector<std::pair<int,int> > > > localbind_t;

static void parseLocalBindVars(boost::optional<localbind_t> vars, bool& doTCP, bool& reusePort, int& tcpFastOpenQueueSize, std::string& interface, std::set<int>& cpus)
{
  if (vars) {
    if (vars->count("doTCP")) {
      doTCP = boost::get<bool>((*vars)["doTCP"]);
    }
    if (vars->count("reusePort")) {
      reusePort = boost::get<bool>((*vars)["reusePort"]);
    }
    if (vars->count("tcpFastOpenQueueSize")) {
      tcpFastOpenQueueSize = boost::get<int>((*vars)["tcpFastOpenQueueSize"]);
    }
    if (vars->count("interface")) {
      interface = boost::get<std::string>((*vars)["interface"]);
    }
    if (vars->count("cpus")) {
      for (const auto cpu : boost::get<std::vector<std::pair<int,int>>>((*vars)["cpus"])) {
        cpus.insert(cpu.second);
      }
    }
  }
}

void setupLuaConfig(bool client)
{
  typedef std::unordered_map<std::string, boost::variant<bool, std::string, vector<pair<int, std::string> > > > newserver_t;

  g_lua.writeFunction("inClientStartup", [client]() {
        return client && !g_configurationDone;
  });

  g_lua.writeFunction("newServer",
      [client](boost::variant<string,newserver_t> pvars, boost::optional<int> qps) {
      setLuaSideEffect();

      std::shared_ptr<DownstreamState> ret = std::make_shared<DownstreamState>(ComboAddress());
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
			    string itfName = source.substr(pos == std::string::npos ? 0 : pos + 1);
			    unsigned int itfIdx = if_nametoindex(itfName.c_str());

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
			    }
			    else
			    {
			      warnlog("Dismissing source %s because '%s' is not a valid interface name", source, itfName);
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

      if(client) {
        // do not construct DownstreamState now, it would try binding sockets.
        return ret;
      }
      ret=std::make_shared<DownstreamState>(serverAddr, sourceAddr, sourceItf, numberOfSockets);

			if(vars.count("qps")) {
			  int qpsVal=std::stoi(boost::get<string>(vars["qps"]));
			  ret->qps=QPSLimiter(qpsVal, qpsVal);
			}

			if(vars.count("order")) {
			  ret->order=std::stoi(boost::get<string>(vars["order"]));
			}

			if(vars.count("weight")) {
			  ret->weight=std::stoi(boost::get<string>(vars["weight"]));
			}

			if(vars.count("retries")) {
			  ret->retries=std::stoi(boost::get<string>(vars["retries"]));
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

			if(vars.count("name")) {
			  ret->name=boost::get<string>(vars["name"]);
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

			if(vars.count("setCD")) {
			  ret->setCD=boost::get<bool>(vars["setCD"]);
			}

			if(vars.count("mustResolve")) {
			  ret->mustResolve=boost::get<bool>(vars["mustResolve"]);
			}

			if(vars.count("useClientSubnet")) {
			  ret->useECS=boost::get<bool>(vars["useClientSubnet"]);
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

                        if(vars.count("cpus")) {
                          for (const auto cpu : boost::get<vector<pair<int,string>>>(vars["cpus"])) {
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
			  if(g_launchWork) {
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

  g_lua.writeFunction("rmServer",
		      [](boost::variant<std::shared_ptr<DownstreamState>, int> var)
		      {
                        setLuaSideEffect();
                        shared_ptr<DownstreamState> server;
                        auto* rem = boost::get<shared_ptr<DownstreamState>>(&var);
                        auto states = g_dstates.getCopy();
                        if(rem) {
                          server = *rem;
                        }
                        else {
                          int idx = boost::get<int>(var);
                          server = states.at(idx);
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
		      } );

  g_lua.writeFunction("setServerPolicy", [](ServerPolicy policy)  {
      setLuaSideEffect();
      g_policy.setState(policy);
    });
  g_lua.writeFunction("setServerPolicyLua", [](string name, policyfunc_t policy)  {
      setLuaSideEffect();
      g_policy.setState(ServerPolicy{name, policy, true});
    });

  g_lua.writeFunction("showServerPolicy", []() {
      setLuaSideEffect();
      g_outputBuffer=g_policy.getLocal()->name+"\n";
    });

  g_lua.writeFunction("truncateTC", [](bool tc) { setLuaSideEffect(); g_truncateTC=tc; });
  g_lua.writeFunction("fixupCase", [](bool fu) { setLuaSideEffect(); g_fixupCase=fu; });

  g_lua.writeFunction("addACL", [](const std::string& domain) {
      setLuaSideEffect();
      g_ACL.modify([domain](NetmaskGroup& nmg) { nmg.addMask(domain); });
    });

  g_lua.writeFunction("setLocal", [client](const std::string& addr, boost::optional<localbind_t> vars) {
      setLuaSideEffect();
      if(client)
	return;
      if (g_configurationDone) {
        g_outputBuffer="setLocal cannot be used at runtime!\n";
        return;
      }
      bool doTCP = true;
      bool reusePort = false;
      int tcpFastOpenQueueSize = 0;
      std::string interface;
      std::set<int> cpus;

      parseLocalBindVars(vars, doTCP, reusePort, tcpFastOpenQueueSize, interface, cpus);

      try {
	ComboAddress loc(addr, 53);
	g_locals.clear();
	g_locals.push_back(std::make_tuple(loc, doTCP, reusePort, tcpFastOpenQueueSize, interface, cpus)); /// only works pre-startup, so no sync necessary
      }
      catch(std::exception& e) {
	g_outputBuffer="Error: "+string(e.what())+"\n";
      }
    });

  g_lua.writeFunction("addLocal", [client](const std::string& addr, boost::optional<localbind_t> vars) {
      setLuaSideEffect();
      if(client)
	return;
      if (g_configurationDone) {
        g_outputBuffer="addLocal cannot be used at runtime!\n";
        return;
      }
      bool doTCP = true;
      bool reusePort = false;
      int tcpFastOpenQueueSize = 0;
      std::string interface;
      std::set<int> cpus;

      parseLocalBindVars(vars, doTCP, reusePort, tcpFastOpenQueueSize, interface, cpus);

      try {
	ComboAddress loc(addr, 53);
	g_locals.push_back(std::make_tuple(loc, doTCP, reusePort, tcpFastOpenQueueSize, interface, cpus)); /// only works pre-startup, so no sync necessary
      }
      catch(std::exception& e) {
	g_outputBuffer="Error: "+string(e.what())+"\n";
      }
    });

  g_lua.writeFunction("setACL", [](boost::variant<string,vector<pair<int, string>>> inp) {
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

  g_lua.writeFunction("showACL", []() {
      setLuaNoSideEffect();
      vector<string> vec;

      g_ACL.getLocal()->toStringVector(&vec);

      for(const auto& s : vec)
        g_outputBuffer+=s+"\n";

    });

  g_lua.writeFunction("shutdown", []() {
#ifdef HAVE_SYSTEMD
      sd_notify(0, "STOPPING=1");
#endif /* HAVE_SYSTEMD */
#if 0
      // Useful for debugging leaks, but might lead to race under load
      // since other threads are still runing.
      for(auto& frontend : g_tlslocals) {
        frontend->cleanup();
      }
      g_tlslocals.clear();
#ifdef HAVE_PROTOBUF
      google::protobuf::ShutdownProtobufLibrary();
#endif /* HAVE_PROTOBUF */
#endif /* 0 */
      _exit(0);
  } );

  g_lua.writeFunction("showServers", []() {
      setLuaNoSideEffect();
      try {
      ostringstream ret;
      boost::format fmt("%1$-3d %2$-20.20s %|25t|%3% %|55t|%4$5s %|51t|%5$7.1f %|66t|%6$7d %|69t|%7$3d %|78t|%8$2d %|80t|%9$10d %|86t|%10$7d %|91t|%11$5.1f %|109t|%12$5.1f %|115t|%13$11d %14%" );
      //             1        2          3       4        5       6       7       8           9        10        11       12     13              14
      ret << (fmt % "#" % "Name" % "Address" % "State" % "Qps" % "Qlim" % "Ord" % "Wt" % "Queries" % "Drops" % "Drate" % "Lat" % "Outstanding" % "Pools") << endl;

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

	ret << (fmt % counter % s->name % s->remote.toStringWithPort() %
		status %
		s->queryLoad % s->qps.getRate() % s->order % s->weight % s->queries.load() % s->reuseds.load() % (s->dropRate) % (s->latencyUsec/1000.0) % s->outstanding.load() % pools) << endl;

	totQPS += s->queryLoad;
	totQueries += s->queries.load();
	totDrops += s->reuseds.load();
	++counter;
      }
      ret<< (fmt % "All" % "" % "" % ""
		%
	     (double)totQPS % "" % "" % "" % totQueries % totDrops % "" % "" % "" % "" ) << endl;

      g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

  g_lua.writeFunction("getServers", []() {
      setLuaNoSideEffect();
      vector<pair<int, std::shared_ptr<DownstreamState> > > ret;
      int count=1;
      for(const auto& s : g_dstates.getCopy()) {
	ret.push_back(make_pair(count++, s));
      }
      return ret;
    });

  g_lua.writeFunction("getPoolServers", [](string pool) {
      return getDownstreamCandidates(g_pools.getCopy(), pool);
    });

  g_lua.writeFunction("getServer", [client](int i) {
      if (client)
        return std::make_shared<DownstreamState>(ComboAddress());
      return g_dstates.getCopy().at(i);
    });

  g_lua.writeFunction("carbonServer", [](const std::string& address, boost::optional<string> ourName,
					 boost::optional<unsigned int> interval) {
                        setLuaSideEffect();
			auto ours = g_carbon.getCopy();
			ours.push_back({ComboAddress(address, 2003), ourName ? *ourName : "", interval ? *interval : 30});
			g_carbon.setState(ours);
		      });

  g_lua.writeFunction("webserver", [client](const std::string& address, const std::string& password, const boost::optional<std::string> apiKey, const boost::optional<std::map<std::string, std::string> > customHeaders) {
      setLuaSideEffect();
      if(client)
	return;
      ComboAddress local(address);
      try {
	int sock = SSocket(local.sin4.sin_family, SOCK_STREAM, 0);
	SSetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
	SBind(sock, local);
	SListen(sock, 5);
	auto launch=[sock, local, password, apiKey, customHeaders]() {
	  thread t(dnsdistWebserverThread, sock, local, password, apiKey ? *apiKey : "", customHeaders);
	  t.detach();
	};
	if(g_launchWork)
	  g_launchWork->push_back(launch);
	else
	  launch();
      }
      catch(std::exception& e) {
	g_outputBuffer="Unable to bind to webserver socket on " + local.toStringWithPort() + ": " + e.what();
	errlog("Unable to bind to webserver socket on %s: %s", local.toStringWithPort(), e.what());
      }

    });

  g_lua.writeFunction("controlSocket", [client](const std::string& str) {
      setLuaSideEffect();
      ComboAddress local(str, 5199);

      if(client) {
	g_serverControl = local;
	return;
      }

      try {
	int sock = SSocket(local.sin4.sin_family, SOCK_STREAM, 0);
	SSetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
	SBind(sock, local);
	SListen(sock, 5);
	auto launch=[sock, local]() {
	    thread t(controlThread, sock, local);
	    t.detach();
	};
	if(g_launchWork)
	  g_launchWork->push_back(launch);
	else
	  launch();

      }
      catch(std::exception& e) {
	g_outputBuffer="Unable to bind to control socket on " + local.toStringWithPort() + ": " + e.what();
	errlog("Unable to bind to control socket on %s: %s", local.toStringWithPort(), e.what());
      }
    });

  g_lua.writeFunction("addConsoleACL", [](const std::string& netmask) {
      setLuaSideEffect();
#ifndef HAVE_LIBSODIUM
      warnlog("Allowing remote access to the console while libsodium support has not been enabled is not secure, and will result in cleartext communications");
#endif

      g_consoleACL.modify([netmask](NetmaskGroup& nmg) { nmg.addMask(netmask); });
    });

  g_lua.writeFunction("setConsoleACL", [](boost::variant<string,vector<pair<int, string>>> inp) {
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

  g_lua.writeFunction("showConsoleACL", []() {
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

  g_lua.writeFunction("clearQueryCounters", []() {
      unsigned int size{0};
      {
        WriteLock wl(&g_qcount.queryLock);
        size = g_qcount.records.size();
        g_qcount.records.clear();
      }

      boost::format fmt("%d records cleared from query counter buffer\n");
      g_outputBuffer = (fmt % size).str();
    });

  g_lua.writeFunction("getQueryCounters", [](boost::optional<unsigned int> optMax) {
      setLuaNoSideEffect();
      ReadLock rl(&g_qcount.queryLock);
      g_outputBuffer = "query counting is currently: ";
      g_outputBuffer+= g_qcount.enabled ? "enabled" : "disabled";
      g_outputBuffer+= (boost::format(" (%d records in buffer)\n") % g_qcount.records.size()).str();

      boost::format fmt("%-3d %s: %d request(s)\n");
      QueryCountRecords::iterator it;
      unsigned int max = optMax ? *optMax : 10;
      unsigned int index{1};
      for(it = g_qcount.records.begin(); it != g_qcount.records.end() && index <= max; ++it, ++index) {
        g_outputBuffer += (fmt % index % it->first % it->second).str();
      }
    });

  g_lua.writeFunction("setQueryCount", [](bool enabled) { g_qcount.enabled=enabled; });

  g_lua.writeFunction("setQueryCountFilter", [](QueryCountFilter func) {
      g_qcount.filter = func;
    });

  g_lua.writeFunction("makeKey", []() {
      setLuaNoSideEffect();
      g_outputBuffer="setKey("+newKey()+")\n";
    });

  g_lua.writeFunction("setKey", [](const std::string& key) {
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

  g_lua.writeFunction("testCrypto", [](boost::optional<string> optTestMsg)
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
	 g_outputBuffer="Crypto failed..\n";

     }
     catch(...) {
       g_outputBuffer="Crypto failed..\n";
     }
#else
     g_outputBuffer="Crypto not available.\n";
#endif
   });

  g_lua.writeFunction("setTCPRecvTimeout", [](int timeout) { g_tcpRecvTimeout=timeout; });

  g_lua.writeFunction("setTCPSendTimeout", [](int timeout) { g_tcpSendTimeout=timeout; });

  g_lua.writeFunction("setUDPTimeout", [](int timeout) { g_udpTimeout=timeout; });

  g_lua.writeFunction("setMaxUDPOutstanding", [](uint16_t max) {
      if (!g_configurationDone) {
        g_maxOutstanding = max;
      } else {
        g_outputBuffer="Max UDP outstanding cannot be altered at runtime!\n";
      }
    });

  g_lua.writeFunction("setMaxTCPClientThreads", [](uint64_t max) {
      if (!g_configurationDone) {
        g_maxTCPClientThreads = max;
      } else {
        g_outputBuffer="Maximum TCP client threads count cannot be altered at runtime!\n";
      }
    });

  g_lua.writeFunction("setMaxTCPQueuedConnections", [](uint64_t max) {
      if (!g_configurationDone) {
        g_maxTCPQueuedConnections = max;
      } else {
        g_outputBuffer="The maximum number of queued TCP connections cannot be altered at runtime!\n";
      }
    });

  g_lua.writeFunction("setMaxTCPQueriesPerConnection", [](size_t max) {
      if (!g_configurationDone) {
        g_maxTCPQueriesPerConn = max;
      } else {
        g_outputBuffer="The maximum number of queries per TCP connection cannot be altered at runtime!\n";
      }
    });

  g_lua.writeFunction("setMaxTCPConnectionsPerClient", [](size_t max) {
      if (!g_configurationDone) {
        g_maxTCPConnectionsPerClient = max;
      } else {
        g_outputBuffer="The maximum number of TCP connection per client cannot be altered at runtime!\n";
      }
    });

  g_lua.writeFunction("setMaxTCPConnectionDuration", [](size_t max) {
      if (!g_configurationDone) {
        g_maxTCPConnectionDuration = max;
      } else {
        g_outputBuffer="The maximum duration of a TCP connection cannot be altered at runtime!\n";
      }
    });

  g_lua.writeFunction("setCacheCleaningDelay", [](uint32_t delay) { g_cacheCleaningDelay = delay; });

  g_lua.writeFunction("setCacheCleaningPercentage", [](uint16_t percentage) { if (percentage < 100) g_cacheCleaningPercentage = percentage; else g_cacheCleaningPercentage = 100; });

  g_lua.writeFunction("setECSSourcePrefixV4", [](uint16_t prefix) { g_ECSSourcePrefixV4=prefix; });

  g_lua.writeFunction("setECSSourcePrefixV6", [](uint16_t prefix) { g_ECSSourcePrefixV6=prefix; });

  g_lua.writeFunction("setECSOverride", [](bool override) { g_ECSOverride=override; });

  g_lua.writeFunction("showDynBlocks", []() {
      setLuaNoSideEffect();
      auto slow = g_dynblockNMG.getCopy();
      struct timespec now;
      gettime(&now);
      boost::format fmt("%-24s %8d %8d %s\n");
      g_outputBuffer = (fmt % "What" % "Seconds" % "Blocks" % "Reason").str();
      for(const auto& e: slow) {
	if(now < e->second.until)
	  g_outputBuffer+= (fmt % e->first.toString() % (e->second.until.tv_sec - now.tv_sec) % e->second.blocks % e->second.reason).str();
      }
      auto slow2 = g_dynblockSMT.getCopy();
      slow2.visit([&now, &fmt](const SuffixMatchTree<DynBlock>& node) {
          if(now <node.d_value.until) {
            string dom("empty");
            if(!node.d_value.domain.empty())
              dom = node.d_value.domain.toString();
            g_outputBuffer+= (fmt % dom % (node.d_value.until.tv_sec - now.tv_sec) % node.d_value.blocks % node.d_value.reason).str();
          }
        });

    });

  g_lua.writeFunction("clearDynBlocks", []() {
      setLuaSideEffect();
      nmts_t nmg;
      g_dynblockNMG.setState(nmg);
      SuffixMatchTree<DynBlock> smt;
      g_dynblockSMT.setState(smt);
    });

  g_lua.writeFunction("addDynBlocks",
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

  g_lua.writeFunction("addDynBlockSMT",
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
			     slow.add(domain, db);
			   }
			   g_dynblockSMT.setState(slow);
			 });

  g_lua.writeFunction("setDynBlocksAction", [](DNSAction::Action action) {
      if (!g_configurationDone) {
        if (action == DNSAction::Action::Drop || action == DNSAction::Action::Refused || action == DNSAction::Action::Truncate) {
          g_dynBlockAction = action;
        }
        else {
          errlog("Dynamic blocks action can only be Drop, Refused or Truncate!");
          g_outputBuffer="Dynamic blocks action can only be Drop, Refused or Truncate!\n";
        }
      } else {
        g_outputBuffer="Dynamic blocks action cannot be altered at runtime!\n";
      }
    });

  g_lua.writeFunction("addDNSCryptBind", [](const std::string& addr, const std::string& providerName, const std::string& certFile, const std::string keyFile, boost::optional<localbind_t> vars) {
      if (g_configurationDone) {
        g_outputBuffer="addDNSCryptBind cannot be used at runtime!\n";
        return;
      }
#ifdef HAVE_DNSCRYPT
      bool doTCP = true;
      bool reusePort = false;
      int tcpFastOpenQueueSize = 0;
      std::string interface;
      std::set<int> cpus;

      parseLocalBindVars(vars, doTCP, reusePort, tcpFastOpenQueueSize, interface, cpus);

      try {
        auto ctx = std::make_shared<DNSCryptContext>(providerName, certFile, keyFile);
        g_dnsCryptLocals.push_back(std::make_tuple(ComboAddress(addr, 443), ctx, reusePort, tcpFastOpenQueueSize, interface, cpus));
      }
      catch(std::exception& e) {
        errlog(e.what());
	g_outputBuffer="Error: "+string(e.what())+"\n";
      }
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif

    });

  g_lua.writeFunction("showDNSCryptBinds", []() {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      ostringstream ret;
      boost::format fmt("%1$-3d %2% %|25t|%3$-20.20s");
      ret << (fmt % "#" % "Address" % "Provider Name") << endl;
      size_t idx = 0;

      for (const auto& local : g_dnsCryptLocals) {
        const std::shared_ptr<DNSCryptContext> ctx = std::get<1>(local);
        ret<< (fmt % idx % std::get<0>(local).toStringWithPort() % ctx->getProviderName()) << endl;
        idx++;
      }

      g_outputBuffer=ret.str();
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

  g_lua.writeFunction("getDNSCryptBind", [](size_t idx) {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
      std::shared_ptr<DNSCryptContext> ret = nullptr;
      if (idx < g_dnsCryptLocals.size()) {
        ret = std::get<1>(g_dnsCryptLocals.at(idx));
      }
      return ret;
#else
      g_outputBuffer="Error: DNSCrypt support is not enabled.\n";
#endif
    });

  g_lua.writeFunction("generateDNSCryptProviderKeys", [](const std::string& publicKeyFile, const std::string privateKeyFile) {
      setLuaNoSideEffect();
#ifdef HAVE_DNSCRYPT
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

  g_lua.writeFunction("printDNSCryptProviderFingerprint", [](const std::string& publicKeyFile) {
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
  g_lua.writeFunction("generateDNSCryptCertificate", [](const std::string& providerPrivateKeyFile, const std::string& certificateFile, const std::string privateKeyFile, uint32_t serial, time_t begin, time_t end, boost::optional<DNSCryptExchangeVersion> version) {
      setLuaNoSideEffect();
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

  g_lua.writeFunction("showPools", []() {
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
          string policy = g_policy.getLocal()->name;
          if (pool->policy != nullptr) {
            policy = pool->policy->name;
          }
          string servers;

          for (const auto& server: pool->getServers()) {
            if (!servers.empty()) {
              servers += ", ";
            }
            if (!server.second->name.empty()) {
              servers += server.second->name;
              servers += " ";
            }
            servers += server.second->remote.toStringWithPort();
          }

          ret << (fmt % name % cache % policy % servers) << endl;
        }
        g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

  g_lua.writeFunction("getPool", [client](const string& poolName) {
      if (client) {
        return std::make_shared<ServerPool>();
      }
      auto localPools = g_pools.getCopy();
      std::shared_ptr<ServerPool> pool = createPoolIfNotExists(localPools, poolName);
      g_pools.setState(localPools);
      return pool;
    });

  g_lua.writeFunction("setVerboseHealthChecks", [](bool verbose) { g_verboseHealthChecks=verbose; });
  g_lua.writeFunction("setStaleCacheEntriesTTL", [](uint32_t ttl) { g_staleCacheEntriesTTL = ttl; });

  g_lua.writeFunction("showBinds", []() {
      setLuaNoSideEffect();
      try {
        ostringstream ret;
        boost::format fmt("%1$-3d %2$-20.20s %|25t|%3$-8.8s %|35t|%4%" );
        //             1    2           3            4
        ret << (fmt % "#" % "Address" % "Protocol" % "Queries" ) << endl;

        size_t counter = 0;
        for (const auto& front : g_frontends) {
          ret << (fmt % counter % front->local.toStringWithPort() % (front->udpFD != -1 ? "UDP" : "TCP") % front->queries) << endl;
          counter++;
        }
        g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

  g_lua.writeFunction("getBind", [](size_t num) {
      setLuaNoSideEffect();
      ClientState* ret = nullptr;
      if(num < g_frontends.size()) {
        ret=g_frontends[num];
      }
      return ret;
      });

  g_lua.writeFunction("help", [](boost::optional<std::string> command) {
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

  g_lua.writeFunction("showVersion", []() {
      setLuaNoSideEffect();
      g_outputBuffer = "dnsdist " + std::string(VERSION) + "\n";
    });

#ifdef HAVE_EBPF
  g_lua.writeFunction("setDefaultBPFFilter", [](std::shared_ptr<BPFFilter> bpf) {
      if (g_configurationDone) {
        g_outputBuffer="setDefaultBPFFilter() cannot be used at runtime!\n";
        return;
      }
      g_defaultBPFFilter = bpf;
    });

  g_lua.writeFunction("registerDynBPFFilter", [](std::shared_ptr<DynBPFFilter> dbpf) {
      if (dbpf) {
        g_dynBPFFilters.push_back(dbpf);
      }
    });

  g_lua.writeFunction("unregisterDynBPFFilter", [](std::shared_ptr<DynBPFFilter> dbpf) {
      if (dbpf) {
        for (auto it = g_dynBPFFilters.begin(); it != g_dynBPFFilters.end(); it++) {
          if (*it == dbpf) {
            g_dynBPFFilters.erase(it);
            break;
          }
        }
      }
    });

  g_lua.writeFunction("addBPFFilterDynBlocks", [](const std::unordered_map<ComboAddress,unsigned int, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual>& m, std::shared_ptr<DynBPFFilter> dynbpf, boost::optional<int> seconds, boost::optional<std::string> msg) {
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

  g_lua.writeFunction<std::unordered_map<string,uint64_t>()>("getStatisticsCounters", []() {
      setLuaNoSideEffect();
      std::unordered_map<string,uint64_t> res;
      for(const auto& entry : g_stats.entries) {
        if(const auto& val = boost::get<DNSDistStats::stat_t*>(&entry.second))
          res[entry.first] = (*val)->load();
      }
      return res;
    });

  g_lua.writeFunction("includeDirectory", [](const std::string& dirname) {
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

        g_lua.executeCode(ifs);
      }

      g_included = false;
    });

  g_lua.writeFunction("setAPIWritable", [](bool writable, boost::optional<std::string> apiConfigDir) {
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

  g_lua.writeFunction("setServFailWhenNoServer", [](bool servfail) {
      setLuaSideEffect();
      g_servFailOnNoPolicy = servfail;
    });

  g_lua.writeFunction("setRingBuffersSize", [](size_t capacity) {
      setLuaSideEffect();
      if (g_configurationDone) {
        errlog("setRingBuffersSize() cannot be used at runtime!");
        g_outputBuffer="setRingBuffersSize() cannot be used at runtime!\n";
        return;
      }
      g_rings.setCapacity(capacity);
    });

  g_lua.writeFunction("setWHashedPertubation", [](uint32_t pertub) {
      setLuaSideEffect();
      g_hashperturb = pertub;
    });

  g_lua.writeFunction("setTCPUseSinglePipe", [](bool flag) {
      if (g_configurationDone) {
        g_outputBuffer="setTCPUseSinglePipe() cannot be used at runtime!\n";
        return;
      }
      setLuaSideEffect();
      g_useTCPSinglePipe = flag;
    });

  g_lua.writeFunction("snmpAgent", [client](bool enableTraps, boost::optional<std::string> masterSocket) {
      if(client)
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
      g_snmpAgent = new DNSDistSNMPAgent("dnsdist", masterSocket ? *masterSocket : std::string());
#else
      errlog("NET SNMP support is required to use snmpAgent()");
      g_outputBuffer="NET SNMP support is required to use snmpAgent()\n";
#endif /* HAVE_NET_SNMP */
    });

  g_lua.writeFunction("sendCustomTrap", [](const std::string& str) {
#ifdef HAVE_NET_SNMP
      if (g_snmpAgent && g_snmpTrapsEnabled) {
        g_snmpAgent->sendCustomTrap(str);
      }
#endif /* HAVE_NET_SNMP */
    });

  g_lua.writeFunction("setPoolServerPolicy", [](ServerPolicy policy, string pool) {
      setLuaSideEffect();
      auto localPools = g_pools.getCopy();
      setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(policy));
      g_pools.setState(localPools);
    });

  g_lua.writeFunction("setPoolServerPolicyLua", [](string name, policyfunc_t policy, string pool) {
      setLuaSideEffect();
      auto localPools = g_pools.getCopy();
      setPoolPolicy(localPools, pool, std::make_shared<ServerPolicy>(ServerPolicy{name, policy, true}));
      g_pools.setState(localPools);
    });

  g_lua.writeFunction("showPoolServerPolicy", [](string pool) {
      setLuaSideEffect();
      auto localPools = g_pools.getCopy();
      auto poolObj = getPool(localPools, pool);
      if (poolObj->policy == nullptr) {
        g_outputBuffer=g_policy.getLocal()->name+"\n";
      } else {
        g_outputBuffer=poolObj->policy->name+"\n";
      }
    });

  g_lua.writeFunction("setTCPDownstreamCleanupInterval", [](uint16_t interval) {
      setLuaSideEffect();
      g_downstreamTCPCleanupInterval = interval;
    });

  g_lua.writeFunction("setConsoleConnectionsLogging", [](bool enabled) {
      g_logConsoleConnections = enabled;
    });

  g_lua.writeFunction("setUDPMultipleMessagesVectorSize", [](size_t vSize) {
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

    g_lua.writeFunction("addTLSLocal", [client](const std::string& addr, const std::string& certFile, const std::string& keyFile, boost::optional<localbind_t> vars) {
        if (client)
          return;
#ifdef HAVE_DNS_OVER_TLS
        setLuaSideEffect();
        if (g_configurationDone) {
          g_outputBuffer="addTLSLocal cannot be used at runtime!\n";
          return;
        }
        shared_ptr<TLSFrontend> frontend = std::make_shared<TLSFrontend>();
        frontend->d_certFile = certFile;
        frontend->d_keyFile = keyFile;

        if (vars) {
          bool doTCP = true;
          parseLocalBindVars(vars, doTCP, frontend->d_reusePort, frontend->d_tcpFastOpenQueueSize, frontend->d_interface, frontend->d_cpus);

          if (vars->count("provider")) {
            frontend->d_provider = boost::get<const string>((*vars)["provider"]);
          }

          if (vars->count("ciphers")) {
            frontend->d_ciphers = boost::get<const string>((*vars)["ciphers"]);
          }

          if (vars->count("ticketKeyFile")) {
            frontend->d_ticketKeyFile = boost::get<const string>((*vars)["ticketKeyFile"]);
          }

          if (vars->count("ticketsKeysRotationDelay")) {
            frontend->d_ticketsKeyRotationDelay = std::stoi(boost::get<const string>((*vars)["ticketsKeysRotationDelay"]));
          }

          if (vars->count("numberOfTicketsKeys")) {
            frontend->d_numberOfTicketsKeys = std::stoi(boost::get<const string>((*vars)["numberOfTicketsKeys"]));
          }
        }

        try {
          frontend->d_addr = ComboAddress(addr, 853);
          vinfolog("Loading TLS provider %s", frontend->d_provider);
          g_tlslocals.push_back(frontend); /// only works pre-startup, so no sync necessary
        }
        catch(const std::exception& e) {
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }
#else
        g_outputBuffer="DNS over TLS support is not present!\n";
#endif
      });

    g_lua.writeFunction("showTLSContexts", []() {
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

    g_lua.writeFunction("getTLSContext", [](size_t index) {
        std::shared_ptr<TLSCtx> result = nullptr;
#ifdef HAVE_DNS_OVER_TLS
        setLuaNoSideEffect();
        try {
          if (index < g_tlslocals.size()) {
            result = g_tlslocals.at(index)->getContext();
          }
          else {
            errlog("Error: trying to get TLS context with index %zu but we only have %zu\n", index, g_tlslocals.size());
            g_outputBuffer="Error: trying to get TLS context with index " + std::to_string(index) + " but we only have " + std::to_string(g_tlslocals.size()) + "\n";
          }
        }
        catch(const std::exception& e) {
          g_outputBuffer="Error: "+string(e.what())+"\n";
          errlog("Error: %s\n", string(e.what()));
        }
#else
        g_outputBuffer="DNS over TLS support is not present!\n";
#endif
        return result;
      });

    g_lua.registerFunction<void(std::shared_ptr<TLSCtx>::*)()>("rotateTicketsKey", [](std::shared_ptr<TLSCtx> ctx) {
        if (ctx != nullptr) {
          ctx->rotateTicketsKey(time(nullptr));
        }
      });

    g_lua.registerFunction<void(std::shared_ptr<TLSCtx>::*)(const std::string&)>("loadTicketsKeys", [](std::shared_ptr<TLSCtx> ctx, const std::string& file) {
        if (ctx != nullptr) {
          ctx->loadTicketsKeys(file);
        }
      });
}

vector<std::function<void(void)>> setupLua(bool client, const std::string& config)
{
  g_launchWork= new vector<std::function<void(void)>>();

  setupLuaActions();
  setupLuaConfig(client);
  setupLuaBindings(client);
  setupLuaBindingsDNSQuestion();
  setupLuaInspection();
  setupLuaRules();
  setupLuaVars();

  std::ifstream ifs(config);
  if(!ifs)
    warnlog("Unable to read configuration from '%s'", config);
  else
    vinfolog("Read configuration from '%s'", config);

  g_lua.executeCode(ifs);

  auto ret = *g_launchWork;
  delete g_launchWork;
  g_launchWork = nullptr;
  return ret;
}
