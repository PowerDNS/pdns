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
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include "dnsdist.hh"
#include "dnsrulactions.hh"
#include <thread>
#include "dolog.hh"
#include "sodcrypto.hh"
#include "base64.hh"
#include <fstream>
#include "dnswriter.hh"
#include "lock.hh"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

using std::thread;

static vector<std::function<void(void)>>* g_launchWork;

class LuaAction : public DNSAction
{
public:
  typedef std::function<std::tuple<int, string>(DNSQuestion* dq)> func_t;
  LuaAction(LuaAction::func_t func) : d_func(func)
  {}

  Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    auto ret = d_func(dq);
    if(ruleresult)
      *ruleresult=std::get<1>(ret);
    return (Action)std::get<0>(ret);
  }

  string toString() const override
  {
    return "Lua script";
  }

private:
  func_t d_func;
};

typedef boost::variant<string,vector<pair<int, string>>, std::shared_ptr<DNSRule> > luadnsrule_t;
std::shared_ptr<DNSRule> makeRule(const luadnsrule_t& var)
{
  if(auto src = boost::get<std::shared_ptr<DNSRule>>(&var))
    return *src;
  
  SuffixMatchNode smn;
  NetmaskGroup nmg;

  auto add=[&](string src) {
    try {
      nmg.addMask(src); // need to try mask first, all masks are domain names!
    } catch(...) {
      smn.add(DNSName(src));
    }
  };
  if(auto src = boost::get<string>(&var))
    add(*src);
  else {
    for(auto& a : boost::get<vector<pair<int, string>>>(var)) {
      add(a.second);
    }
  }
  if(nmg.empty())
    return std::make_shared<SuffixMatchNodeRule>(smn);
  else
    return std::make_shared<NetmaskGroupRule>(nmg, true);
}

std::unordered_map<int, vector<boost::variant<string,double>>> getGenResponses(unsigned int top, boost::optional<int> labels, std::function<bool(const Rings::Response&)> pred) 
{
  setLuaNoSideEffect();
  map<DNSName, int> counts;
  unsigned int total=0;
  {
    std::lock_guard<std::mutex> lock(g_rings.respMutex);
    if(!labels) {
      for(const auto& a : g_rings.respRing) {
        if(!pred(a))
          continue;
        counts[a.name]++;
        total++;
      }
    }
    else {
      unsigned int lab = *labels;
      for(auto a : g_rings.respRing) {
        if(!pred(a))
          continue;
        
        a.name.trimToLabels(lab);
        counts[a.name]++;
        total++;
      }
      
    }
  }
  //      cout<<"Looked at "<<total<<" responses, "<<counts.size()<<" different ones"<<endl;
  vector<pair<int, DNSName>> rcounts;
  rcounts.reserve(counts.size());
  for(const auto& c : counts) 
    rcounts.push_back(make_pair(c.second, c.first));
  
  sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a, 
                                          const decltype(rcounts)::value_type& b) {
         return b.first < a.first;
       });
  
  std::unordered_map<int, vector<boost::variant<string,double>>> ret;
  unsigned int count=1, rest=0;
  for(const auto& rc : rcounts) {
    if(count==top+1)
      rest+=rc.first;
    else
      ret.insert({count++, {rc.second.toString(), rc.first, 100.0*rc.first/total}});
  }
  ret.insert({count, {"Rest", rest, total > 0 ? 100.0*rest/total : 100.0}});
  return ret;
}

vector<std::function<void(void)>> setupLua(bool client, const std::string& config)
{
  g_launchWork= new vector<std::function<void(void)>>();
  typedef std::unordered_map<std::string, boost::variant<bool, std::string, vector<pair<int, std::string> > > > newserver_t;

  g_lua.writeVariable("DNSAction", std::unordered_map<string,int>{
      {"Drop", (int)DNSAction::Action::Drop}, 
      {"Nxdomain", (int)DNSAction::Action::Nxdomain}, 
      {"Spoof", (int)DNSAction::Action::Spoof}, 
      {"Allow", (int)DNSAction::Action::Allow}, 
      {"HeaderModify", (int)DNSAction::Action::HeaderModify},
      {"Pool", (int)DNSAction::Action::Pool}, 
      {"None",(int)DNSAction::Action::None},
      {"Delay", (int)DNSAction::Action::Delay}}
    );

  g_lua.writeVariable("DNSResponseAction", std::unordered_map<string,int>{
      {"Allow",        (int)DNSResponseAction::Action::Allow        },
      {"Delay",        (int)DNSResponseAction::Action::Delay        },
      {"HeaderModify", (int)DNSResponseAction::Action::HeaderModify },
      {"None",         (int)DNSResponseAction::Action::None         }
    });

  g_lua.writeVariable("DNSClass", std::unordered_map<string,int>{
      {"IN",    QClass::IN    },
      {"CHAOS", QClass::CHAOS },
      {"NONE",  QClass::NONE  },
      {"ANY",   QClass::ANY   }
    });

  g_lua.writeVariable("DNSOpcode", std::unordered_map<string,int>{
      {"Query",  Opcode::Query  },
      {"IQuery", Opcode::IQuery },
      {"Status", Opcode::Status },
      {"Notify", Opcode::Notify },
      {"Update", Opcode::Update }
    });

  g_lua.writeVariable("DNSSection", std::unordered_map<string,int>{
      {"Question",  0 },
      {"Answer",    1 },
      {"Authority", 2 },
      {"Additional",3 }
    });

  vector<pair<string, int> > rcodes = {{"NOERROR",  RCode::NoError  },
                                       {"FORMERR",  RCode::FormErr  },
                                       {"SERVFAIL", RCode::ServFail },
                                       {"NXDOMAIN", RCode::NXDomain },
                                       {"NOTIMP",   RCode::NotImp   },
                                       {"REFUSED",  RCode::Refused  },
                                       {"YXDOMAIN", RCode::YXDomain },
                                       {"YXRRSET",  RCode::YXRRSet  },
                                       {"NXRRSET",  RCode::NXRRSet  },
                                       {"NOTAUTH",  RCode::NotAuth  },
                                       {"NOTZONE",  RCode::NotZone  }
  };
  vector<pair<string, int> > dd;
  for(const auto& n : QType::names)
    dd.push_back({n.first, n.second});
  for(const auto& n : rcodes)
    dd.push_back({n.first, n.second});
  g_lua.writeVariable("dnsdist", dd);
  
  g_lua.writeFunction("newServer", 
		      [client](boost::variant<string,newserver_t> pvars, boost::optional<int> qps)
		      { 
                        setLuaSideEffect();
			if(client) {
			  return std::make_shared<DownstreamState>(ComboAddress());
			}
			ComboAddress sourceAddr;
			unsigned int sourceItf = 0;
			if(auto addressStr = boost::get<string>(&pvars)) {
			  ComboAddress address(*addressStr, 53);
			  std::shared_ptr<DownstreamState> ret;
			  if(IsAnyAddress(address)) {
			    g_outputBuffer="Error creating new server: invalid address for a downstream server.";
			    errlog("Error creating new server: %s is not a valid address for a downstream server", *addressStr);
			    return ret;
			  }
			  try {
			    ret=std::make_shared<DownstreamState>(address);
			  }
			  catch(std::exception& e) {
			    g_outputBuffer="Error creating new server: "+string(e.what());
			    errlog("Error creating new server with address %s: %s", addressStr, e.what());
			    return ret;
			  }

			  if(qps) {
			    ret->qps=QPSLimiter(*qps, *qps);
			  }
			  g_dstates.modify([ret](servers_t& servers) { 
			      servers.push_back(ret); 
			      std::stable_sort(servers.begin(), servers.end(), [](const decltype(ret)& a, const decltype(ret)& b) {
				  return a->order < b->order;
				});

			    });

			  auto localPools = g_pools.getCopy();
			  addServerToPool(localPools, "", ret);
			  g_pools.setState(localPools);

			  if(g_launchWork) {
			    g_launchWork->push_back([ret]() {
				ret->tid = move(thread(responderThread, ret));
			      });
			  }
			  else {
			    ret->tid = move(thread(responderThread, ret));
			  }

			  return ret;
			}
			auto vars=boost::get<newserver_t>(pvars);

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

			std::shared_ptr<DownstreamState> ret;
			ComboAddress address(boost::get<string>(vars["address"]), 53);
			if(IsAnyAddress(address)) {
			  g_outputBuffer="Error creating new server: invalid address for a downstream server.";
			  errlog("Error creating new server: %s is not a valid address for a downstream server", boost::get<string>(vars["address"]));
			  return ret;
			}
			try {
			  ret=std::make_shared<DownstreamState>(address, sourceAddr, sourceItf);
			}
			catch(std::exception& e) {
			  g_outputBuffer="Error creating new server: "+string(e.what());
			  errlog("Error creating new server with address %s: %s", boost::get<string>(vars["address"]), e.what());
			  return ret;
			}

			if(vars.count("qps")) {
			  int qps=std::stoi(boost::get<string>(vars["qps"]));
			  ret->qps=QPSLimiter(qps, qps);
			}

			auto localPools = g_pools.getCopy();
			if(vars.count("pool")) {
			  if(auto* pool = boost::get<string>(&vars["pool"]))
			    ret->pools.insert(*pool);
			  else {
			    auto* pools = boost::get<vector<pair<int, string> > >(&vars["pool"]);
			    for(auto& p : *pools)
			      ret->pools.insert(p.second);
			  }
			  for(const auto& poolName: ret->pools) {
			    addServerToPool(localPools, poolName, ret);
			  }
			}
			else {
			  addServerToPool(localPools, "", ret);
			}
			g_pools.setState(localPools);

			if(vars.count("order")) {
			  ret->order=std::stoi(boost::get<string>(vars["order"]));
			}

			if(vars.count("weight")) {
			  ret->weight=std::stoi(boost::get<string>(vars["weight"]));
			}

			if(vars.count("retries")) {
			  ret->retries=std::stoi(boost::get<string>(vars["retries"]));
			}

			if(vars.count("tcpSendTimeout")) {
			  ret->tcpSendTimeout=std::stoi(boost::get<string>(vars["tcpSendTimeout"]));
			}

			if(vars.count("tcpRecvTimeout")) {
			  ret->tcpRecvTimeout=std::stoi(boost::get<string>(vars["tcpRecvTimeout"]));
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

			if(vars.count("setCD")) {
			  ret->setCD=boost::get<bool>(vars["setCD"]);
			}

			if(vars.count("mustResolve")) {
			  ret->mustResolve=boost::get<bool>(vars["mustResolve"]);
			}

			if(vars.count("useClientSubnet")) {
			  ret->useECS=boost::get<bool>(vars["useClientSubnet"]);
			}

			if(vars.count("maxCheckFailures")) {
			  ret->maxCheckFailures=std::stoi(boost::get<string>(vars["maxCheckFailures"]));
			}

			if(g_launchWork) {
			  g_launchWork->push_back([ret]() {
			      ret->tid = move(thread(responderThread, ret));
			    });
			}
			else {
			  ret->tid = move(thread(responderThread, ret));
			}

			auto states = g_dstates.getCopy();
			states.push_back(ret);
			std::stable_sort(states.begin(), states.end(), [](const decltype(ret)& a, const decltype(ret)& b) {
			    return a->order < b->order;
			  });
			g_dstates.setState(states);
			return ret;
		      } );

  g_lua.writeFunction("makeRule", makeRule);

  g_lua.writeFunction("addAnyTCRule", []() {
      setLuaSideEffect();
      auto rules=g_rulactions.getCopy();
      std::vector<pair<int, shared_ptr<DNSRule> >> v;
      v.push_back({1, std::make_shared<QTypeRule>(0xff)});
      v.push_back({2, std::make_shared<TCPRule>(false)});
      rules.push_back({ std::shared_ptr<DNSRule>(new AndRule(v)), std::make_shared<TCAction>()});
      g_rulactions.setState(rules);
    });

  g_lua.writeFunction("rmRule", [](unsigned int num) {
      setLuaSideEffect();
      auto rules = g_rulactions.getCopy();
      if(num >= rules.size()) {
	g_outputBuffer = "Error: attempt to delete non-existing rule\n";
	return;
      }
      rules.erase(rules.begin()+num);
      g_rulactions.setState(rules);
    });

  g_lua.writeFunction("topRule", []() {
      setLuaSideEffect();
      auto rules = g_rulactions.getCopy();
      if(rules.empty())
	return;
      auto subject = *rules.rbegin();
      rules.erase(std::prev(rules.end()));
      rules.insert(rules.begin(), subject);
      g_rulactions.setState(rules);
    });
  g_lua.writeFunction("mvRule", [](unsigned int from, unsigned int to) {
      setLuaSideEffect();
      auto rules = g_rulactions.getCopy();
      if(from >= rules.size() || to > rules.size()) {
	g_outputBuffer = "Error: attempt to move rules from/to invalid index\n";
	return;
      }

      auto subject = rules[from];
      rules.erase(rules.begin()+from);
      if(to == rules.size())
	rules.push_back(subject);
      else {
	if(from < to)
	  --to;
	rules.insert(rules.begin()+to, subject);
      }
      g_rulactions.setState(rules);
    });
  g_lua.writeFunction("clearRules", []() {
      setLuaSideEffect();
      g_rulactions.modify([](decltype(g_rulactions)::value_type& rulactions) {
          rulactions.clear();
        });
    });

  g_lua.writeFunction("newRuleAction", [](luadnsrule_t dnsrule, std::shared_ptr<DNSAction> action) {
      auto rule=makeRule(dnsrule);
      return std::make_shared<std::pair< luadnsrule_t, std::shared_ptr<DNSAction> > >(rule, action);
    });

  g_lua.writeFunction("setRules", [](std::vector< std::pair<int, std::shared_ptr<std::pair<luadnsrule_t, std::shared_ptr<DNSAction> > > > > newruleactions) {
      setLuaSideEffect();
      g_rulactions.modify([newruleactions](decltype(g_rulactions)::value_type& gruleactions) {
          gruleactions.clear();
          for (const auto& newruleaction : newruleactions) {
            if (newruleaction.second) {
              auto rule=makeRule(newruleaction.second->first);
              gruleactions.push_back({rule, newruleaction.second->second});
            }
          }
        });
    });

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
      g_policy.setState(ServerPolicy{name, policy});
    });

  g_lua.writeFunction("showServerPolicy", []() {
      setLuaSideEffect();
      g_outputBuffer=g_policy.getLocal()->name+"\n";
    });

  g_lua.writeFunction("truncateTC", [](bool tc) { setLuaSideEffect(); g_truncateTC=tc; });
  g_lua.writeFunction("fixupCase", [](bool fu) { setLuaSideEffect(); g_fixupCase=fu; });

  g_lua.registerMember("name", &ServerPolicy::name);
  g_lua.registerMember("policy", &ServerPolicy::policy);
  g_lua.writeFunction("newServerPolicy", [](string name, policyfunc_t policy) { return ServerPolicy{name, policy};});
  g_lua.writeVariable("firstAvailable", ServerPolicy{"firstAvailable", firstAvailable});
  g_lua.writeVariable("roundrobin", ServerPolicy{"roundrobin", roundrobin});
  g_lua.writeVariable("wrandom", ServerPolicy{"wrandom", wrandom});
  g_lua.writeVariable("whashed", ServerPolicy{"whashed", whashed});
  g_lua.writeVariable("leastOutstanding", ServerPolicy{"leastOutstanding", leastOutstanding});
  g_lua.writeFunction("addACL", [](const std::string& domain) {
      setLuaSideEffect();
      g_ACL.modify([domain](NetmaskGroup& nmg) { nmg.addMask(domain); });
    });

  g_lua.writeFunction("setLocal", [client](const std::string& addr, boost::optional<bool> doTCP, boost::optional<bool> reusePort, boost::optional<int> tcpFastOpenQueueSize) {
      setLuaSideEffect();
      if(client)
	return;
      if (g_configurationDone) {
        g_outputBuffer="setLocal cannot be used at runtime!\n";
        return;
      }
      try {
	ComboAddress loc(addr, 53);
	g_locals.clear();
	g_locals.push_back(std::make_tuple(loc, doTCP ? *doTCP : true, reusePort ? *reusePort : false, tcpFastOpenQueueSize ? *tcpFastOpenQueueSize : 0)); /// only works pre-startup, so no sync necessary
      }
      catch(std::exception& e) {
	g_outputBuffer="Error: "+string(e.what())+"\n";
      }
    });

  g_lua.writeFunction("addLocal", [client](const std::string& addr, boost::optional<bool> doTCP, boost::optional<bool> reusePort, boost::optional<int> tcpFastOpenQueueSize) {
      setLuaSideEffect();
      if(client)
	return;
      if (g_configurationDone) {
        g_outputBuffer="addLocal cannot be used at runtime!\n";
        return;
      }
      try {
	ComboAddress loc(addr, 53);
	g_locals.push_back(std::make_tuple(loc, doTCP ? *doTCP : true, reusePort ? *reusePort : false, tcpFastOpenQueueSize ? *tcpFastOpenQueueSize : 0)); /// only works pre-startup, so no sync necessary
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

      g_ACL.getCopy().toStringVector(&vec);

      for(const auto& s : vec)
        g_outputBuffer+=s+"\n";

    });
  g_lua.writeFunction("shutdown", []() {
#ifdef HAVE_SYSTEMD
      sd_notify(0, "STOPPING=1");
#endif
      _exit(0);
  } );


  g_lua.writeFunction("addDomainBlock", [](const std::string& domain) { 
      setLuaSideEffect();
      SuffixMatchNode smn;
      smn.add(DNSName(domain));
	g_rulactions.modify([smn](decltype(g_rulactions)::value_type& rulactions) {
	    rulactions.push_back({
				   std::make_shared<SuffixMatchNodeRule>(smn), 
				   std::make_shared<DropAction>()  });
	  });

    });
  g_lua.writeFunction("showServers", []() {  
      setLuaNoSideEffect();
      try {
      ostringstream ret;
      boost::format fmt("%1$-3d %2$-20.20s %|25t|%3% %|55t|%4$5s %|51t|%5$7.1f %|66t|%6$7d %|69t|%7$3d %|78t|%8$2d %|80t|%9$10d %|86t|%10$7d %|91t|%11$5.1f %|109t|%12$5.1f %|115t|%13$11d %14%" );
      //             1        2          3       4        5       6       7       8           9        10        11       12     13              14
      ret << (fmt % "#" % "Name" % "Address" % "State" % "Qps" % "Qlim" % "Ord" % "Wt" % "Queries" % "Drops" % "Drate" % "Lat" % "Outstanding" % "Pools") << endl;

      uint64_t totQPS{0}, totQueries{0}, totDrops{0};
      int counter=0;
      auto states = g_dstates.getCopy();
      for(const auto& s : states) {
	string status;
	if(s->availability == DownstreamState::Availability::Up) 
	  status = "UP";
	else if(s->availability == DownstreamState::Availability::Down) 
	  status = "DOWN";
	else 
	  status = (s->upStatus ? "up" : "down");

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

  g_lua.writeFunction("addLuaAction", [](luadnsrule_t var, LuaAction::func_t func) 
		      {
                        setLuaSideEffect();
			auto rule=makeRule(var);
			g_rulactions.modify([rule,func](decltype(g_rulactions)::value_type& rulactions){
			    rulactions.push_back({rule,
				  std::make_shared<LuaAction>(func)});
			  });
		      });


  g_lua.writeFunction("NoRecurseAction", []() {
      return std::shared_ptr<DNSAction>(new NoRecurseAction);
    });

  g_lua.writeFunction("MacAddrAction", [](int code) {
      return std::shared_ptr<DNSAction>(new MacAddrAction(code));
    });


  g_lua.writeFunction("PoolAction", [](const string& a) {
      return std::shared_ptr<DNSAction>(new PoolAction(a));
    });

  g_lua.writeFunction("QPSPoolAction", [](int limit, const string& a) {
      return std::shared_ptr<DNSAction>(new QPSPoolAction(limit, a));
    });

  g_lua.writeFunction("SpoofAction", [](boost::variant<string,vector<pair<int, string>>> inp, boost::optional<string> b ) {
      vector<ComboAddress> addrs;
      if(auto s = boost::get<string>(&inp))
        addrs.push_back(ComboAddress(*s));
      else {
        const auto& v = boost::get<vector<pair<int,string>>>(inp);
        for(const auto& a: v)
          addrs.push_back(ComboAddress(a.second));
      }
      if(b)
        addrs.push_back(ComboAddress(*b));
      return std::shared_ptr<DNSAction>(new SpoofAction(addrs));
    });

  g_lua.writeFunction("SpoofCNAMEAction", [](const string& a) {
      return std::shared_ptr<DNSAction>(new SpoofAction(a));
    });

  g_lua.writeFunction("addDomainSpoof", [](const std::string& domain, boost::variant<string,vector<pair<int, string>>> inp, boost::optional<string> b) { 
      setLuaSideEffect();
      SuffixMatchNode smn;
      vector<ComboAddress> outp;
      try
      {
	smn.add(DNSName(domain));

        if(auto s = boost::get<string>(&inp))
          outp.push_back(ComboAddress(*s));
        else {
          const auto& v = boost::get<vector<pair<int,string>>>(inp);
          for(const auto& a: v)
            outp.push_back(ComboAddress(a.second));
        }
        if(b)
          outp.push_back(ComboAddress(*b));
          
      }
      catch(std::exception& e) {
	g_outputBuffer="Error parsing parameters: "+string(e.what());
	return;
      }
      g_rulactions.modify([&smn,&outp](decltype(g_rulactions)::value_type& rulactions) {
	  rulactions.push_back({
	      std::make_shared<SuffixMatchNodeRule>(smn), 
		std::make_shared<SpoofAction>(outp)  });
	});

    });

  g_lua.writeFunction("addDomainCNAMESpoof", [](const std::string& domain, const std::string& cname) {
      setLuaSideEffect();
      SuffixMatchNode smn;
      try
      {
	smn.add(DNSName(domain));
      }
      catch(std::exception& e) {
	g_outputBuffer="Error parsing parameters: "+string(e.what());
	return;
      }
      g_rulactions.modify([&smn,&cname](decltype(g_rulactions)::value_type& rulactions) {
	  rulactions.push_back({
	      std::make_shared<SuffixMatchNodeRule>(smn),
		std::make_shared<SpoofAction>(cname)  });
	});
    });

  g_lua.writeFunction("DropAction", []() {
      return std::shared_ptr<DNSAction>(new DropAction);
    });

  g_lua.writeFunction("AllowAction", []() {
      return std::shared_ptr<DNSAction>(new AllowAction);
    });

  g_lua.writeFunction("DelayAction", [](int msec) {
      return std::shared_ptr<DNSAction>(new DelayAction(msec));
    });

  g_lua.writeFunction("TCAction", []() {
      return std::shared_ptr<DNSAction>(new TCAction);
    });

  g_lua.writeFunction("DisableValidationAction", []() {
      return std::shared_ptr<DNSAction>(new DisableValidationAction);
    });

  g_lua.writeFunction("LogAction", [](const std::string& fname, boost::optional<bool> binary, boost::optional<bool> append, boost::optional<bool> buffered) {
      return std::shared_ptr<DNSAction>(new LogAction(fname, binary ? *binary : true, append ? *append : false, buffered ? *buffered : false));
    });

  g_lua.writeFunction("RCodeAction", [](int rcode) {
      return std::shared_ptr<DNSAction>(new RCodeAction(rcode));
    });

  g_lua.writeFunction("SkipCacheAction", []() {
      return std::shared_ptr<DNSAction>(new SkipCacheAction);
    });

  g_lua.writeFunction("MaxQPSIPRule", [](unsigned int qps, boost::optional<int> ipv4trunc, boost::optional<int> ipv6trunc) {
      return std::shared_ptr<DNSRule>(new MaxQPSIPRule(qps, ipv4trunc.get_value_or(32), ipv6trunc.get_value_or(64)));
    });


  g_lua.writeFunction("MaxQPSRule", [](unsigned int qps, boost::optional<int> burst) {
      if(!burst)
        return std::shared_ptr<DNSRule>(new MaxQPSRule(qps));
      else
        return std::shared_ptr<DNSRule>(new MaxQPSRule(qps, *burst));      
    });


  g_lua.writeFunction("RegexRule", [](const std::string& str) {
      return std::shared_ptr<DNSRule>(new RegexRule(str));
    });

#ifdef HAVE_RE2
  g_lua.writeFunction("RE2Rule", [](const std::string& str) {
      return std::shared_ptr<DNSRule>(new RE2Rule(str));
    });
#endif

  g_lua.writeFunction("SuffixMatchNodeRule", [](const SuffixMatchNode& smn, boost::optional<bool> quiet) {
      return std::shared_ptr<DNSRule>(new SuffixMatchNodeRule(smn, quiet ? *quiet : false));
    });

  g_lua.writeFunction("NetmaskGroupRule", [](const NetmaskGroup& nmg, boost::optional<bool> src) {
      return std::shared_ptr<DNSRule>(new NetmaskGroupRule(nmg, src ? *src : true));
    });

  g_lua.writeFunction("benchRule", [](std::shared_ptr<DNSRule> rule, boost::optional<int> times_, boost::optional<string> suffix_)  {
      setLuaNoSideEffect();
      int times = times_.get_value_or(100000);
      DNSName suffix(suffix_.get_value_or("powerdns.com"));
      struct item {
        vector<uint8_t> packet;        
        ComboAddress rem;
        DNSName qname;
        uint16_t qtype, qclass;
      };
      vector<item> items;
      items.reserve(1000);
      for(int n=0; n < 1000; ++n) {
        struct item i;
        i.qname=DNSName(std::to_string(random()));
        i.qname += suffix;
        i.qtype = random() % 0xff;
        i.qclass = 1;
        i.rem=ComboAddress("127.0.0.1");
        i.rem.sin4.sin_addr.s_addr = random();
        DNSPacketWriter pw(i.packet, i.qname, i.qtype);
        items.push_back(i);
      }

      int matches=0;
      ComboAddress dummy("127.0.0.1");
      DTime dt;
      dt.set();
      for(int n=0; n < times; ++n) {
        const item& i = items[n % items.size()];
        DNSQuestion dq(&i.qname, i.qtype, i.qclass, &i.rem, &i.rem, (struct dnsheader*)&i.packet[0], i.packet.size(), i.packet.size(), false);
        if(rule->matches(&dq))
          matches++;
      }
      double udiff=dt.udiff();
      g_outputBuffer=(boost::format("Had %d matches out of %d, %.1f qps, in %.1f usec\n") % matches % times % (1000000*(1.0*times/udiff)) % udiff).str();

    });

  g_lua.writeFunction("AllRule", []() {
      return std::shared_ptr<DNSRule>(new AllRule());
    });

  g_lua.writeFunction("QTypeRule", [](boost::variant<int, std::string> str) {
      uint16_t qtype;
      if(auto dir = boost::get<int>(&str)) {
        qtype = *dir;
      }
      else {
        string val=boost::get<string>(str);
        qtype = QType::chartocode(val.c_str());
        if(!qtype)
          throw std::runtime_error("Unable to convert '"+val+"' to a DNS type");
      }
      return std::shared_ptr<DNSRule>(new QTypeRule(qtype));
    });
  g_lua.writeFunction("QClassRule", [](int c) {
      return std::shared_ptr<DNSRule>(new QClassRule(c));
    });

  g_lua.writeFunction("OpcodeRule", [](uint8_t code) {
      return std::shared_ptr<DNSRule>(new OpcodeRule(code));
    });

  g_lua.writeFunction("AndRule", [](vector<pair<int, std::shared_ptr<DNSRule> > >a) {
      return std::shared_ptr<DNSRule>(new AndRule(a));
    });

  g_lua.writeFunction("OrRule", [](vector<pair<int, std::shared_ptr<DNSRule> > >a) {
      return std::shared_ptr<DNSRule>(new OrRule(a));
    });

  g_lua.writeFunction("TCPRule", [](bool tcp) {
      return std::shared_ptr<DNSRule>(new TCPRule(tcp));
    });

  g_lua.writeFunction("DNSSECRule", []() {
      return std::shared_ptr<DNSRule>(new DNSSECRule());
    });

  g_lua.writeFunction("NotRule", [](std::shared_ptr<DNSRule>rule) {
      return std::shared_ptr<DNSRule>(new NotRule(rule));
    });

  g_lua.writeFunction("RecordsCountRule", [](uint8_t section, uint16_t minCount, uint16_t maxCount) {
      return std::shared_ptr<DNSRule>(new RecordsCountRule(section, minCount, maxCount));
    });

  g_lua.writeFunction("RecordsTypeCountRule", [](uint8_t section, uint16_t type, uint16_t minCount, uint16_t maxCount) {
      return std::shared_ptr<DNSRule>(new RecordsTypeCountRule(section, type, minCount, maxCount));
    });

  g_lua.writeFunction("TrailingDataRule", []() {
      return std::shared_ptr<DNSRule>(new TrailingDataRule());
    });

  g_lua.writeFunction("QNameLabelsCountRule", [](unsigned int minLabelsCount, unsigned int maxLabelsCount) {
      return std::shared_ptr<DNSRule>(new QNameLabelsCountRule(minLabelsCount, maxLabelsCount));
    });

  g_lua.writeFunction("QNameWireLengthRule", [](size_t min, size_t max) {
      return std::shared_ptr<DNSRule>(new QNameWireLengthRule(min, max));
    });

  g_lua.writeFunction("RCodeRule", [](int rcode) {
      return std::shared_ptr<DNSRule>(new RCodeRule(rcode));
    });

  g_lua.writeFunction("addAction", [](luadnsrule_t var, std::shared_ptr<DNSAction> ea)
		      {
                        setLuaSideEffect();
			auto rule=makeRule(var);
			g_rulactions.modify([rule, ea](decltype(g_rulactions)::value_type& rulactions){
			    rulactions.push_back({rule, ea});
			  });
		      });


  g_lua.writeFunction("addPoolRule", [](luadnsrule_t var, string pool) {
      setLuaSideEffect();
      auto rule=makeRule(var);
	g_rulactions.modify([rule, pool](decltype(g_rulactions)::value_type& rulactions) {
	    rulactions.push_back({
		rule,
		  std::make_shared<PoolAction>(pool)  });
	  });
    });

  g_lua.writeFunction("addNoRecurseRule", [](luadnsrule_t var) {
      setLuaSideEffect();
      auto rule=makeRule(var);
	g_rulactions.modify([rule](decltype(g_rulactions)::value_type& rulactions) {
	    rulactions.push_back({
		rule,
		  std::make_shared<NoRecurseAction>()  });
	  });
    });

  g_lua.writeFunction("addDisableValidationRule", [](luadnsrule_t var) {
      setLuaSideEffect();
      auto rule=makeRule(var);
	g_rulactions.modify([rule](decltype(g_rulactions)::value_type& rulactions) {
	    rulactions.push_back({
		rule,
		  std::make_shared<DisableValidationAction>()  });
	  });
    });


  g_lua.writeFunction("addQPSPoolRule", [](luadnsrule_t var, int limit, string pool) {
      setLuaSideEffect();
      auto rule = makeRule(var);
      g_rulactions.modify([rule, pool,limit](decltype(g_rulactions)::value_type& rulactions) {
	  rulactions.push_back({
	      rule, 
		std::make_shared<QPSPoolAction>(limit, pool)  });
	});
    });

  g_lua.writeFunction("setDNSSECPool", [](const std::string& pool) {
      setLuaSideEffect();
      g_rulactions.modify([pool](decltype(g_rulactions)::value_type& rulactions) {
	  rulactions.push_back({std::make_shared<DNSSECRule>(), 
		std::make_shared<PoolAction>(pool)}); 
	});
    });

  g_lua.writeFunction("addQPSLimit", [](luadnsrule_t var, int lim) {
      setLuaSideEffect();
      auto rule = makeRule(var);
      g_rulactions.modify([lim,rule](decltype(g_rulactions)::value_type& rulactions) {
	  rulactions.push_back({rule, 
		std::make_shared<QPSAction>(lim)});
	});
    });
   
  g_lua.writeFunction("addDelay", [](luadnsrule_t var, int msec) {
      setLuaSideEffect();
      auto rule = makeRule(var);
      g_rulactions.modify([msec,rule](decltype(g_rulactions)::value_type& rulactions) {
	  rulactions.push_back({rule, 
		std::make_shared<DelayAction>(msec)});
	});
    });


  g_lua.writeFunction("showRules", []() {
     setLuaNoSideEffect();
     boost::format fmt("%-3d %9d %-50s %s\n");
     g_outputBuffer += (fmt % "#" % "Matches" % "Rule" % "Action").str();
     int num=0;
      for(const auto& lim : g_rulactions.getCopy()) {  
        string name = lim.first->toString();
	g_outputBuffer += (fmt % num % lim.first->d_matches % name % lim.second->toString()).str();
	++num;
      }
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

  g_lua.registerFunction<void(DownstreamState::*)(int)>("setQPS", [](DownstreamState& s, int lim) { s.qps = lim ? QPSLimiter(lim, lim) : QPSLimiter(); });
  g_lua.registerFunction<void(std::shared_ptr<DownstreamState>::*)(string)>("addPool", [](std::shared_ptr<DownstreamState> s, string pool) {
      auto localPools = g_pools.getCopy();
      addServerToPool(localPools, pool, s);
      g_pools.setState(localPools);
      s->pools.insert(pool);
    });
  g_lua.registerFunction<void(std::shared_ptr<DownstreamState>::*)(string)>("rmPool", [](std::shared_ptr<DownstreamState> s, string pool) {
      auto localPools = g_pools.getCopy();
      removeServerFromPool(localPools, pool, s);
      g_pools.setState(localPools);
      s->pools.erase(pool);
    });

  g_lua.registerFunction<void(DownstreamState::*)()>("getOutstanding", [](const DownstreamState& s) { g_outputBuffer=std::to_string(s.outstanding.load()); });


  g_lua.registerFunction("isUp", &DownstreamState::isUp);
  g_lua.registerFunction("setDown", &DownstreamState::setDown);
  g_lua.registerFunction("setUp", &DownstreamState::setUp);
  g_lua.registerFunction("setAuto", &DownstreamState::setAuto);
  g_lua.registerFunction("getName", &DownstreamState::getName);
  g_lua.registerFunction("getNameWithAddr", &DownstreamState::getNameWithAddr);
  g_lua.registerMember("upStatus", &DownstreamState::upStatus);
  g_lua.registerMember("weight", &DownstreamState::weight);
  g_lua.registerMember("order", &DownstreamState::order);
  g_lua.registerMember("name", &DownstreamState::name);
  
  g_lua.writeFunction("infolog", [](const string& arg) {
      infolog("%s", arg);
    });
  g_lua.writeFunction("errlog", [](const string& arg) {
      errlog("%s", arg);
    });
  g_lua.writeFunction("warnlog", [](const string& arg) {
      warnlog("%s", arg);
    });


  g_lua.writeFunction("show", [](const string& arg) {
      g_outputBuffer+=arg;
      g_outputBuffer+="\n";
    });

  g_lua.registerFunction<void(dnsheader::*)(bool)>("setRD", [](dnsheader& dh, bool v) {
      dh.rd=v;
    });

  g_lua.registerFunction<bool(dnsheader::*)()>("getRD", [](dnsheader& dh) {
      return (bool)dh.rd;
    });

  g_lua.registerFunction<void(dnsheader::*)(bool)>("setCD", [](dnsheader& dh, bool v) {
      dh.cd=v;
    });

  g_lua.registerFunction<bool(dnsheader::*)()>("getCD", [](dnsheader& dh) {
      return (bool)dh.cd;
    });


  g_lua.registerFunction<void(dnsheader::*)(bool)>("setTC", [](dnsheader& dh, bool v) {
      dh.tc=v;
      if(v) dh.ra = dh.rd; // you'll always need this, otherwise TC=1 gets ignored
    });

  g_lua.registerFunction<void(dnsheader::*)(bool)>("setQR", [](dnsheader& dh, bool v) {
      dh.qr=v;
    });


  g_lua.registerFunction("tostring", &ComboAddress::toString);
  g_lua.registerFunction("tostringWithPort", &ComboAddress::toStringWithPort);
  g_lua.registerFunction("toString", &ComboAddress::toString);
  g_lua.registerFunction("toStringWithPort", &ComboAddress::toStringWithPort);
  g_lua.registerFunction<uint16_t(ComboAddress::*)()>("getPort", [](const ComboAddress& ca) { return ntohs(ca.sin4.sin_port); } );
  g_lua.registerFunction("truncate", &ComboAddress::truncate);
  g_lua.registerFunction("isIPv4", &ComboAddress::isIPv4);
  g_lua.registerFunction("isIPv6", &ComboAddress::isIPv6);
  g_lua.registerFunction("isMappedIPv4", &ComboAddress::isMappedIPv4);
  g_lua.registerFunction("mapToIPv4", &ComboAddress::mapToIPv4);

  g_lua.registerFunction("isPartOf", &DNSName::isPartOf);
  g_lua.registerFunction("countLabels", &DNSName::countLabels);
  g_lua.registerFunction("wirelength", &DNSName::wirelength);
  g_lua.registerFunction<string(DNSName::*)()>("tostring", [](const DNSName&dn ) { return dn.toString(); });
  g_lua.registerFunction<string(DNSName::*)()>("toString", [](const DNSName&dn ) { return dn.toString(); });
  g_lua.writeFunction("newDNSName", [](const std::string& name) { return DNSName(name); });
  g_lua.writeFunction("newSuffixMatchNode", []() { return SuffixMatchNode(); });

  g_lua.registerFunction("add",(void (SuffixMatchNode::*)(const DNSName&)) &SuffixMatchNode::add);
  g_lua.registerFunction("check",(bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);

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


  g_lua.writeFunction("topClients", [](boost::optional<unsigned int> top_) {
      setLuaNoSideEffect();
      auto top = top_.get_value_or(10);
      map<ComboAddress, int,ComboAddress::addressOnlyLessThan > counts;
      unsigned int total=0;
      {
        ReadLock rl(&g_rings.queryLock);
        for(const auto& c : g_rings.queryRing) {
          counts[c.requestor]++;
          total++;
        }
      }
      vector<pair<int, ComboAddress>> rcounts;
      rcounts.reserve(counts.size());
      for(const auto& c : counts) 
	rcounts.push_back(make_pair(c.second, c.first));

      sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a, 
					      const decltype(rcounts)::value_type& b) {
	     return b.first < a.first;
	   });
      unsigned int count=1, rest=0;
      boost::format fmt("%4d  %-40s %4d %4.1f%%\n");
      for(const auto& rc : rcounts) {
	if(count==top+1)
	  rest+=rc.first;
	else
	  g_outputBuffer += (fmt % (count++) % rc.second.toString() % rc.first % (100.0*rc.first/total)).str();
      }
      g_outputBuffer += (fmt % (count) % "Rest" % rest % (total > 0 ? 100.0*rest/total : 100.0)).str();
    });

  g_lua.writeFunction("getTopQueries", [](unsigned int top, boost::optional<int> labels) {
      setLuaNoSideEffect();
      map<DNSName, int> counts;
      unsigned int total=0;
      if(!labels) {
	ReadLock rl(&g_rings.queryLock);
	for(const auto& a : g_rings.queryRing) {
	  counts[a.name]++;
	  total++;
	}
      }
      else {
	unsigned int lab = *labels;
	ReadLock rl(&g_rings.queryLock);
	for(auto a : g_rings.queryRing) {
	  a.name.trimToLabels(lab);
	  counts[a.name]++;
	  total++;
	}
      }
      // cout<<"Looked at "<<total<<" queries, "<<counts.size()<<" different ones"<<endl;
      vector<pair<int, DNSName>> rcounts;
      rcounts.reserve(counts.size());
      for(const auto& c : counts) 
	rcounts.push_back(make_pair(c.second, c.first));

      sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a, 
					      const decltype(rcounts)::value_type& b) {
	     return b.first < a.first;
	   });

      std::unordered_map<int, vector<boost::variant<string,double>>> ret;
      unsigned int count=1, rest=0;
      for(const auto& rc : rcounts) {
	if(count==top+1)
	  rest+=rc.first;
	else
	  ret.insert({count++, {rc.second.toString(), rc.first, 100.0*rc.first/total}});
      }
      ret.insert({count, {"Rest", rest, total > 0 ? 100.0*rest/total : 100.0}});
      return ret;

    });

  g_lua.executeCode(R"(function topQueries(top, labels) top = top or 10; for k,v in ipairs(getTopQueries(top,labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2], v[3])) end end)");

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

  g_lua.writeFunction("getResponseRing", []() {
      setLuaNoSideEffect();
      decltype(g_rings.respRing) ring;
      {
	std::lock_guard<std::mutex> lock(g_rings.respMutex);
	ring = g_rings.respRing;
      }
      vector<std::unordered_map<string, boost::variant<string, unsigned int> > > ret;
      ret.reserve(ring.size());
      decltype(ret)::value_type item;
      for(const auto& r : ring) {
	item["name"]=r.name.toString();
	item["qtype"]=r.qtype;
	item["rcode"]=r.dh.rcode;
	item["usec"]=r.usec;
	ret.push_back(item);
      }
      return ret;
    });

  g_lua.writeFunction("getTopResponses", [](unsigned int top, unsigned int kind, boost::optional<int> labels) {
      return getGenResponses(top, labels, [kind](const Rings::Response& r) { return r.dh.rcode == kind; });
    });

  g_lua.executeCode(R"(function topResponses(top, kind, labels) top = top or 10; kind = kind or 0; for k,v in ipairs(getTopResponses(top, kind, labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");


  g_lua.writeFunction("getSlowResponses", [](unsigned int top, unsigned int msec, boost::optional<int> labels) {
      return getGenResponses(top, labels, [msec](const Rings::Response& r) { return r.usec > msec*1000; });
    });


  g_lua.executeCode(R"(function topSlow(top, msec, labels) top = top or 10; msec = msec or 500; for k,v in ipairs(getSlowResponses(top, msec, labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");


  g_lua.writeFunction("showResponseLatency", []() {
      setLuaNoSideEffect();
      map<double, unsigned int> histo;
      double bin=100;
      for(int i=0; i < 15; ++i) {
	histo[bin];
	bin*=2;
      }

      double totlat=0;
      int size=0;
      {
	std::lock_guard<std::mutex> lock(g_rings.respMutex);
	for(const auto& r : g_rings.respRing) {
	  ++size;
	  auto iter = histo.lower_bound(r.usec);
	  if(iter != histo.end())
	    iter->second++;
	  else
	    histo.rbegin()++;
	  totlat+=r.usec;
	}
      }

      if (size == 0) {
        g_outputBuffer = "No traffic yet.\n";
        return;
      }

      g_outputBuffer = (boost::format("Average response latency: %.02f msec\n") % (0.001*totlat/size)).str();
      double highest=0;
      
      for(auto iter = histo.cbegin(); iter != histo.cend(); ++iter) {
	highest=std::max(highest, iter->second*1.0);
      }
      boost::format fmt("%7.2f\t%s\n");
      g_outputBuffer += (fmt % "msec" % "").str();

      for(auto iter = histo.cbegin(); iter != histo.cend(); ++iter) {
	int stars = (70.0 * iter->second/highest);
	char c='*';
	if(!stars && iter->second) {
	  stars=1; // you get 1 . to show something is there..
	  if(70.0*iter->second/highest > 0.5)
	    c=':';
	  else
	    c='.';
	}
	g_outputBuffer += (fmt % (iter->first/1000.0) % string(stars, c)).str();
      }
    });

  g_lua.writeFunction("newQPSLimiter", [](int rate, int burst) { return QPSLimiter(rate, burst); });
  g_lua.registerFunction("check", &QPSLimiter::check);


  g_lua.writeFunction("makeKey", []() {
      setLuaNoSideEffect();
      g_outputBuffer="setKey("+newKey()+")\n";
    });
  
  g_lua.writeFunction("setKey", [](const std::string& key) {
      setLuaSideEffect();
      if(B64Decode(key, g_key) < 0) {
	  g_outputBuffer=string("Unable to decode ")+key+" as Base64";
	  errlog("%s", g_outputBuffer);
	}
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
       string encrypted = sodEncryptSym(testmsg, g_key, sn);
       string decrypted = sodDecryptSym(encrypted, g_key, sn2);
       
       sn.increment();
       sn2.increment();

       encrypted = sodEncryptSym(testmsg, g_key, sn);
       decrypted = sodDecryptSym(encrypted, g_key, sn2);

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

  g_lua.writeFunction("setMaxUDPOutstanding", [](uint16_t max) {
      if (!g_configurationDone) {
        g_maxOutstanding = max;
      } else {
        g_outputBuffer="Max UDP outstanding cannot be altered at runtime!\n";
      }
    });

  /* DNSQuestion bindings */
  /* PowerDNS DNSQuestion compat */
  g_lua.registerMember<const ComboAddress (DNSQuestion::*)>("localaddr", [](const DNSQuestion& dq) -> const ComboAddress { return *dq.local; }, [](DNSQuestion& dq, const ComboAddress newLocal) { (void) newLocal; });
  g_lua.registerMember<const DNSName (DNSQuestion::*)>("qname", [](const DNSQuestion& dq) -> const DNSName { return *dq.qname; }, [](DNSQuestion& dq, const DNSName newName) { (void) newName; });
  g_lua.registerMember<uint16_t (DNSQuestion::*)>("qtype", [](const DNSQuestion& dq) -> uint16_t { return dq.qtype; }, [](DNSQuestion& dq, uint16_t newType) { (void) newType; });
  g_lua.registerMember<uint16_t (DNSQuestion::*)>("qclass", [](const DNSQuestion& dq) -> uint16_t { return dq.qclass; }, [](DNSQuestion& dq, uint16_t newClass) { (void) newClass; });
  g_lua.registerMember<int (DNSQuestion::*)>("rcode", [](const DNSQuestion& dq) -> int { return dq.dh->rcode; }, [](DNSQuestion& dq, int newRCode) { dq.dh->rcode = newRCode; });
  g_lua.registerMember<const ComboAddress (DNSQuestion::*)>("remoteaddr", [](const DNSQuestion& dq) -> const ComboAddress { return *dq.remote; }, [](DNSQuestion& dq, const ComboAddress newRemote) { (void) newRemote; });
  /* DNSDist DNSQuestion */
  g_lua.registerMember("dh", &DNSQuestion::dh);
  g_lua.registerMember<uint16_t (DNSQuestion::*)>("len", [](const DNSQuestion& dq) -> uint16_t { return dq.len; }, [](DNSQuestion& dq, uint16_t newlen) { dq.len = newlen; });
  g_lua.registerMember<uint8_t (DNSQuestion::*)>("opcode", [](const DNSQuestion& dq) -> uint8_t { return dq.dh->opcode; }, [](DNSQuestion& dq, uint8_t newOpcode) { (void) newOpcode; });
  g_lua.registerMember<size_t (DNSQuestion::*)>("size", [](const DNSQuestion& dq) -> size_t { return dq.size; }, [](DNSQuestion& dq, size_t newSize) { (void) newSize; });
  g_lua.registerMember<bool (DNSQuestion::*)>("tcp", [](const DNSQuestion& dq) -> bool { return dq.tcp; }, [](DNSQuestion& dq, bool newTcp) { (void) newTcp; });
  g_lua.registerMember<bool (DNSQuestion::*)>("skipCache", [](const DNSQuestion& dq) -> bool { return dq.skipCache; }, [](DNSQuestion& dq, bool newSkipCache) { dq.skipCache = newSkipCache; });
  g_lua.registerMember<bool (DNSQuestion::*)>("useECS", [](const DNSQuestion& dq) -> bool { return dq.useECS; }, [](DNSQuestion& dq, bool useECS) { dq.useECS = useECS; });
  g_lua.registerMember<bool (DNSQuestion::*)>("ecsOverride", [](const DNSQuestion& dq) -> bool { return dq.ecsOverride; }, [](DNSQuestion& dq, bool ecsOverride) { dq.ecsOverride = ecsOverride; });
  g_lua.registerMember<uint16_t (DNSQuestion::*)>("ecsPrefixLength", [](const DNSQuestion& dq) -> uint16_t { return dq.ecsPrefixLength; }, [](DNSQuestion& dq, uint16_t newPrefixLength) { dq.ecsPrefixLength = newPrefixLength; });

  /* LuaWrapper doesn't support inheritance */
  g_lua.registerMember<const ComboAddress (DNSResponse::*)>("localaddr", [](const DNSResponse& dq) -> const ComboAddress { return *dq.local; }, [](DNSResponse& dq, const ComboAddress newLocal) { (void) newLocal; });
  g_lua.registerMember<const DNSName (DNSResponse::*)>("qname", [](const DNSResponse& dq) -> const DNSName { return *dq.qname; }, [](DNSResponse& dq, const DNSName newName) { (void) newName; });
  g_lua.registerMember<uint16_t (DNSResponse::*)>("qtype", [](const DNSResponse& dq) -> uint16_t { return dq.qtype; }, [](DNSResponse& dq, uint16_t newType) { (void) newType; });
  g_lua.registerMember<uint16_t (DNSResponse::*)>("qclass", [](const DNSResponse& dq) -> uint16_t { return dq.qclass; }, [](DNSResponse& dq, uint16_t newClass) { (void) newClass; });
  g_lua.registerMember<int (DNSResponse::*)>("rcode", [](const DNSResponse& dq) -> int { return dq.dh->rcode; }, [](DNSResponse& dq, int newRCode) { dq.dh->rcode = newRCode; });
  g_lua.registerMember<const ComboAddress (DNSResponse::*)>("remoteaddr", [](const DNSResponse& dq) -> const ComboAddress { return *dq.remote; }, [](DNSResponse& dq, const ComboAddress newRemote) { (void) newRemote; });
  g_lua.registerMember("dh", &DNSResponse::dh);
  g_lua.registerMember<uint16_t (DNSResponse::*)>("len", [](const DNSResponse& dq) -> uint16_t { return dq.len; }, [](DNSResponse& dq, uint16_t newlen) { dq.len = newlen; });
  g_lua.registerMember<uint8_t (DNSResponse::*)>("opcode", [](const DNSResponse& dq) -> uint8_t { return dq.dh->opcode; }, [](DNSResponse& dq, uint8_t newOpcode) { (void) newOpcode; });
  g_lua.registerMember<size_t (DNSResponse::*)>("size", [](const DNSResponse& dq) -> size_t { return dq.size; }, [](DNSResponse& dq, size_t newSize) { (void) newSize; });
  g_lua.registerMember<bool (DNSResponse::*)>("tcp", [](const DNSResponse& dq) -> bool { return dq.tcp; }, [](DNSResponse& dq, bool newTcp) { (void) newTcp; });
  g_lua.registerMember<bool (DNSResponse::*)>("skipCache", [](const DNSResponse& dq) -> bool { return dq.skipCache; }, [](DNSResponse& dq, bool newSkipCache) { dq.skipCache = newSkipCache; });

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

  g_lua.writeFunction("showTCPStats", [] {
      setLuaNoSideEffect();
      boost::format fmt("%-10d %-10d %-10d %-10d\n");
      g_outputBuffer += (fmt % "Clients" % "MaxClients" % "Queued" % "MaxQueued").str();
      g_outputBuffer += (fmt % g_tcpclientthreads->d_numthreads % g_maxTCPClientThreads % g_tcpclientthreads->d_queued % g_maxTCPQueuedConnections).str();
    });

  g_lua.writeFunction("setCacheCleaningDelay", [](uint32_t delay) { g_cacheCleaningDelay = delay; });

  g_lua.writeFunction("setECSSourcePrefixV4", [](uint16_t prefix) { g_ECSSourcePrefixV4=prefix; });

  g_lua.writeFunction("setECSSourcePrefixV6", [](uint16_t prefix) { g_ECSSourcePrefixV6=prefix; });

  g_lua.writeFunction("setECSOverride", [](bool override) { g_ECSOverride=override; });

  g_lua.writeFunction("addResponseAction", [](luadnsrule_t var, std::shared_ptr<DNSResponseAction> ea) {
      setLuaSideEffect();
      auto rule=makeRule(var);
      g_resprulactions.modify([rule, ea](decltype(g_resprulactions)::value_type& rulactions){
          rulactions.push_back({rule, ea});
        });
    });

  g_lua.writeFunction("dumpStats", [] {
      setLuaNoSideEffect();
      vector<string> leftcolumn, rightcolumn;

      boost::format fmt("%-23s\t%+11s");
      g_outputBuffer.clear();
      auto entries = g_stats.entries;
      sort(entries.begin(), entries.end(), 
	   [](const decltype(entries)::value_type& a, const decltype(entries)::value_type& b) {
	     return a.first < b.first;
	   });
      boost::format flt("    %9.1f");
      for(const auto& e : entries) {
	string second;
	if(const auto& val = boost::get<DNSDistStats::stat_t*>(&e.second))
	  second=std::to_string((*val)->load());
	else if (const auto& val = boost::get<double*>(&e.second))
	  second=(flt % (**val)).str();
	else
	  second=std::to_string((*boost::get<DNSDistStats::statfunction_t>(&e.second))(e.first));

	if(leftcolumn.size() < g_stats.entries.size()/2)
	  leftcolumn.push_back((fmt % e.first % second).str());
	else
	  rightcolumn.push_back((fmt % e.first % second).str());
      }

      auto leftiter=leftcolumn.begin(), rightiter=rightcolumn.begin();
      boost::format clmn("%|0t|%1% %|39t|%2%\n");

      for(;leftiter != leftcolumn.end() || rightiter != rightcolumn.end();) {
	string lentry, rentry;
	if(leftiter!= leftcolumn.end()) {
	  lentry = *leftiter;
	  leftiter++;
	}
	if(rightiter!= rightcolumn.end()) {
	  rentry = *rightiter;
	  rightiter++;
	}
	g_outputBuffer += (clmn % lentry % rentry).str();
      }
    });

  moreLua(client);
  
  std::ifstream ifs(config);
  if(!ifs) 
    warnlog("Unable to read configuration from '%s'", config);
  else
    vinfolog("Read configuration from '%s'", config);

  g_lua.executeCode(ifs);

  auto ret=*g_launchWork;
  delete g_launchWork;
  g_launchWork=0;
  return ret;
}
