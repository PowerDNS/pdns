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
#include "config.h"
#include "dnsdist.hh"
#include "dnsdist-lua.hh"

#include "dolog.hh"

void setupLuaBindings(bool client)
{
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

  /* Exceptions */
  g_lua.registerFunction<string(std::exception_ptr::*)()>("__tostring", [](const std::exception_ptr& eptr) {
      try {
        if (eptr) {
          std::rethrow_exception(eptr);
        }
      } catch(const std::exception& e) {
        return string(e.what());
      } catch(const PDNSException& e) {
        return e.reason;
      } catch(...) {
        return string("Unknown exception");
      }
      return string("No exception");
    });
  /* ServerPolicy */
  g_lua.writeFunction("newServerPolicy", [](string name, policyfunc_t policy) { return ServerPolicy{name, policy, true};});
  g_lua.registerMember("name", &ServerPolicy::name);
  g_lua.registerMember("policy", &ServerPolicy::policy);
  g_lua.registerMember("isLua", &ServerPolicy::isLua);
  g_lua.registerFunction("toString", &ServerPolicy::toString);

  g_lua.writeVariable("firstAvailable", ServerPolicy{"firstAvailable", firstAvailable, false});
  g_lua.writeVariable("roundrobin", ServerPolicy{"roundrobin", roundrobin, false});
  g_lua.writeVariable("wrandom", ServerPolicy{"wrandom", wrandom, false});
  g_lua.writeVariable("whashed", ServerPolicy{"whashed", whashed, false});
  g_lua.writeVariable("chashed", ServerPolicy{"chashed", chashed, false});
  g_lua.writeVariable("leastOutstanding", ServerPolicy{"leastOutstanding", leastOutstanding, false});

  /* ServerPool */
  g_lua.registerFunction<void(std::shared_ptr<ServerPool>::*)(std::shared_ptr<DNSDistPacketCache>)>("setCache", [](std::shared_ptr<ServerPool> pool, std::shared_ptr<DNSDistPacketCache> cache) {
      if (pool) {
        pool->packetCache = cache;
      }
    });
  g_lua.registerFunction("getCache", &ServerPool::getCache);
  g_lua.registerFunction<void(std::shared_ptr<ServerPool>::*)()>("unsetCache", [](std::shared_ptr<ServerPool> pool) {
      if (pool) {
        pool->packetCache = nullptr;
      }
    });
  g_lua.registerFunction("getECS", &ServerPool::getECS);
  g_lua.registerFunction("setECS", &ServerPool::setECS);

  /* DownstreamState */
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
  g_lua.registerFunction<uint64_t(DownstreamState::*)()>("getOutstanding", [](const DownstreamState& s) { return s.outstanding.load(); });
  g_lua.registerFunction("isUp", &DownstreamState::isUp);
  g_lua.registerFunction("setDown", &DownstreamState::setDown);
  g_lua.registerFunction("setUp", &DownstreamState::setUp);
  g_lua.registerFunction<void(DownstreamState::*)(boost::optional<bool> newStatus)>("setAuto", [](DownstreamState& s, boost::optional<bool> newStatus) {
      if (newStatus) {
        s.upStatus = *newStatus;
      }
      s.setAuto();
    });
  g_lua.registerFunction("getName", &DownstreamState::getName);
  g_lua.registerFunction("getNameWithAddr", &DownstreamState::getNameWithAddr);
  g_lua.registerMember("upStatus", &DownstreamState::upStatus);
  g_lua.registerMember<int (DownstreamState::*)>("weight",
    [](const DownstreamState& s) -> int {return s.weight;},
    [](DownstreamState& s, int newWeight) {s.setWeight(newWeight);}
  );
  g_lua.registerMember("order", &DownstreamState::order);
  g_lua.registerMember("name", &DownstreamState::name);

  /* dnsheader */
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

  /* ComboAddress */
  g_lua.writeFunction("newCA", [](const std::string& name) { return ComboAddress(name); });
  g_lua.registerFunction<string(ComboAddress::*)()>("tostring", [](const ComboAddress& ca) { return ca.toString(); });
  g_lua.registerFunction<string(ComboAddress::*)()>("tostringWithPort", [](const ComboAddress& ca) { return ca.toStringWithPort(); });
  g_lua.registerFunction<string(ComboAddress::*)()>("toString", [](const ComboAddress& ca) { return ca.toString(); });
  g_lua.registerFunction<string(ComboAddress::*)()>("toStringWithPort", [](const ComboAddress& ca) { return ca.toStringWithPort(); });
  g_lua.registerFunction<uint16_t(ComboAddress::*)()>("getPort", [](const ComboAddress& ca) { return ntohs(ca.sin4.sin_port); } );
  g_lua.registerFunction<void(ComboAddress::*)(unsigned int)>("truncate", [](ComboAddress& ca, unsigned int bits) { ca.truncate(bits); });
  g_lua.registerFunction<bool(ComboAddress::*)()>("isIPv4", [](const ComboAddress& ca) { return ca.sin4.sin_family == AF_INET; });
  g_lua.registerFunction<bool(ComboAddress::*)()>("isIPv6", [](const ComboAddress& ca) { return ca.sin4.sin_family == AF_INET6; });
  g_lua.registerFunction<bool(ComboAddress::*)()>("isMappedIPv4", [](const ComboAddress& ca) { return ca.isMappedIPv4(); });
  g_lua.registerFunction<ComboAddress(ComboAddress::*)()>("mapToIPv4", [](const ComboAddress& ca) { return ca.mapToIPv4(); });
  g_lua.registerFunction<bool(nmts_t::*)(const ComboAddress&)>("match", [](nmts_t& s, const ComboAddress& ca) { return s.match(ca); });

  /* DNSName */
  g_lua.registerFunction("isPartOf", &DNSName::isPartOf);
  g_lua.registerFunction<bool(DNSName::*)()>("chopOff", [](DNSName&dn ) { return dn.chopOff(); });
  g_lua.registerFunction<unsigned int(DNSName::*)()>("countLabels", [](const DNSName& name) { return name.countLabels(); });
  g_lua.registerFunction<size_t(DNSName::*)()>("wirelength", [](const DNSName& name) { return name.wirelength(); });
  g_lua.registerFunction<string(DNSName::*)()>("tostring", [](const DNSName&dn ) { return dn.toString(); });
  g_lua.registerFunction<string(DNSName::*)()>("toString", [](const DNSName&dn ) { return dn.toString(); });
  g_lua.writeFunction("newDNSName", [](const std::string& name) { return DNSName(name); });
  g_lua.writeFunction("newSuffixMatchNode", []() { return SuffixMatchNode(); });
  g_lua.writeFunction("newDNSNameSet", []() { return DNSNameSet(); });

  /* DNSNameSet */
  g_lua.registerFunction<string(DNSNameSet::*)()>("toString", [](const DNSNameSet&dns ) { return dns.toString(); });
  g_lua.registerFunction<void(DNSNameSet::*)(DNSName&)>("add", [](DNSNameSet& dns, DNSName& dn) { dns.insert(dn); });
  g_lua.registerFunction<bool(DNSNameSet::*)(DNSName&)>("check", [](DNSNameSet& dns, DNSName& dn) { return dns.find(dn) != dns.end(); });
  g_lua.registerFunction("delete",(size_t (DNSNameSet::*)(const DNSName&)) &DNSNameSet::erase);
  g_lua.registerFunction("size",(size_t (DNSNameSet::*)() const) &DNSNameSet::size);
  g_lua.registerFunction("clear",(void (DNSNameSet::*)()) &DNSNameSet::clear);
  g_lua.registerFunction("empty",(bool (DNSNameSet::*)()) &DNSNameSet::empty);

  /* SuffixMatchNode */
  g_lua.registerFunction<void (SuffixMatchNode::*)(const boost::variant<DNSName, string, vector<pair<int, DNSName>>, vector<pair<int, string>>> &name)>("add", [](SuffixMatchNode &smn, const boost::variant<DNSName, string, vector<pair<int, DNSName>>, vector<pair<int, string>>> &name) {
      if (name.type() == typeid(DNSName)) {
          auto n = boost::get<DNSName>(name);
          smn.add(n);
          return;
      }
      if (name.type() == typeid(string)) {
          auto n = boost::get<string>(name);
          smn.add(n);
          return;
      }
      if (name.type() == typeid(vector<pair<int, DNSName>>)) {
          auto names = boost::get<vector<pair<int, DNSName>>>(name);
          for (auto const n : names) {
            smn.add(n.second);
          }
          return;
      }
      if (name.type() == typeid(vector<pair<int, string>>)) {
          auto names = boost::get<vector<pair<int, string>>>(name);
          for (auto const n : names) {
            smn.add(n.second);
          }
          return;
      }
  });
  g_lua.registerFunction("check",(bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);

  /* NetmaskGroup */
  g_lua.writeFunction("newNMG", []() { return NetmaskGroup(); });
  g_lua.registerFunction<void(NetmaskGroup::*)(const std::string&mask)>("addMask", [](NetmaskGroup&nmg, const std::string& mask)
                         {
                           nmg.addMask(mask);
                         });
  g_lua.registerFunction<void(NetmaskGroup::*)(const std::map<ComboAddress,int>& map)>("addMasks", [](NetmaskGroup&nmg, const std::map<ComboAddress,int>& map)
                         {
                           for (const auto& entry : map) {
                             nmg.addMask(Netmask(entry.first));
                           }
                         });

  g_lua.registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const)&NetmaskGroup::match);
  g_lua.registerFunction("size", &NetmaskGroup::size);
  g_lua.registerFunction("clear", &NetmaskGroup::clear);
  g_lua.registerFunction<string(NetmaskGroup::*)()>("toString", [](const NetmaskGroup& nmg ) { return "NetmaskGroup " + nmg.toString(); });

  /* QPSLimiter */
  g_lua.writeFunction("newQPSLimiter", [](int rate, int burst) { return QPSLimiter(rate, burst); });
  g_lua.registerFunction("check", &QPSLimiter::check);

  /* ClientState */
  g_lua.registerFunction<std::string(ClientState::*)()>("toString", [](const ClientState& fe) {
      setLuaNoSideEffect();
      return fe.local.toStringWithPort();
    });
  g_lua.registerMember("muted", &ClientState::muted);
#ifdef HAVE_EBPF
  g_lua.registerFunction<void(ClientState::*)(std::shared_ptr<BPFFilter>)>("attachFilter", [](ClientState& frontend, std::shared_ptr<BPFFilter> bpf) {
      if (bpf) {
        frontend.attachFilter(bpf);
      }
    });
  g_lua.registerFunction<void(ClientState::*)()>("detachFilter", [](ClientState& frontend) {
      frontend.detachFilter();
    });
#endif /* HAVE_EBPF */

  /* BPF Filter */
#ifdef HAVE_EBPF
  g_lua.writeFunction("newBPFFilter", [client](uint32_t maxV4, uint32_t maxV6, uint32_t maxQNames) {
      if (client) {
        return std::shared_ptr<BPFFilter>(nullptr);
      }
      return std::make_shared<BPFFilter>(maxV4, maxV6, maxQNames);
    });

  g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const ComboAddress& ca)>("block", [](std::shared_ptr<BPFFilter> bpf, const ComboAddress& ca) {
      if (bpf) {
        return bpf->block(ca);
      }
    });

  g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const DNSName& qname, boost::optional<uint16_t> qtype)>("blockQName", [](std::shared_ptr<BPFFilter> bpf, const DNSName& qname, boost::optional<uint16_t> qtype) {
      if (bpf) {
        return bpf->block(qname, qtype ? *qtype : 255);
      }
    });

  g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const ComboAddress& ca)>("unblock", [](std::shared_ptr<BPFFilter> bpf, const ComboAddress& ca) {
      if (bpf) {
        return bpf->unblock(ca);
      }
    });

  g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const DNSName& qname, boost::optional<uint16_t> qtype)>("unblockQName", [](std::shared_ptr<BPFFilter> bpf, const DNSName& qname, boost::optional<uint16_t> qtype) {
      if (bpf) {
        return bpf->unblock(qname, qtype ? *qtype : 255);
      }
    });

  g_lua.registerFunction<std::string(std::shared_ptr<BPFFilter>::*)()>("getStats", [](const std::shared_ptr<BPFFilter> bpf) {
      setLuaNoSideEffect();
      std::string res;
      if (bpf) {
        std::vector<std::pair<ComboAddress, uint64_t> > stats = bpf->getAddrStats();
        for (const auto& value : stats) {
          if (value.first.sin4.sin_family == AF_INET) {
            res += value.first.toString() + ": " + std::to_string(value.second) + "\n";
          }
          else if (value.first.sin4.sin_family == AF_INET6) {
            res += "[" + value.first.toString() + "]: " + std::to_string(value.second) + "\n";
          }
        }
        std::vector<std::tuple<DNSName, uint16_t, uint64_t> > qstats = bpf->getQNameStats();
        for (const auto& value : qstats) {
          res += std::get<0>(value).toString() + " " + std::to_string(std::get<1>(value)) + ": " + std::to_string(std::get<2>(value)) + "\n";
        }
      }
      return res;
    });

  g_lua.registerFunction<void(std::shared_ptr<BPFFilter>::*)()>("attachToAllBinds", [](std::shared_ptr<BPFFilter> bpf) {
      std::string res;
      if (bpf) {
        for (const auto& frontend : g_frontends) {
          frontend->attachFilter(bpf);
        }
      }
    });

    g_lua.writeFunction("newDynBPFFilter", [client](std::shared_ptr<BPFFilter> bpf) {
        if (client) {
          return std::shared_ptr<DynBPFFilter>(nullptr);
        }
        return std::make_shared<DynBPFFilter>(bpf);
      });

    g_lua.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)(const ComboAddress& addr, boost::optional<int> seconds)>("block", [](std::shared_ptr<DynBPFFilter> dbpf, const ComboAddress& addr, boost::optional<int> seconds) {
        if (dbpf) {
          struct timespec until;
          clock_gettime(CLOCK_MONOTONIC, &until);
          until.tv_sec += seconds ? *seconds : 10;
          dbpf->block(addr, until);
        }
    });

    g_lua.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)()>("purgeExpired", [](std::shared_ptr<DynBPFFilter> dbpf) {
        if (dbpf) {
          struct timespec now;
          clock_gettime(CLOCK_MONOTONIC, &now);
          dbpf->purgeExpired(now);
        }
    });

    g_lua.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)(boost::variant<std::string, std::vector<std::pair<int, std::string>>>)>("excludeRange", [](std::shared_ptr<DynBPFFilter> dbpf, boost::variant<std::string, std::vector<std::pair<int, std::string>>> ranges) {
      if (ranges.type() == typeid(std::vector<std::pair<int, std::string>>)) {
        for (const auto& range : *boost::get<std::vector<std::pair<int, std::string>>>(&ranges)) {
          dbpf->excludeRange(Netmask(range.second));
        }
      }
      else {
        dbpf->excludeRange(Netmask(*boost::get<std::string>(&ranges)));
      }
    });

    g_lua.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)(boost::variant<std::string, std::vector<std::pair<int, std::string>>>)>("includeRange", [](std::shared_ptr<DynBPFFilter> dbpf, boost::variant<std::string, std::vector<std::pair<int, std::string>>> ranges) {
      if (ranges.type() == typeid(std::vector<std::pair<int, std::string>>)) {
        for (const auto& range : *boost::get<std::vector<std::pair<int, std::string>>>(&ranges)) {
          dbpf->includeRange(Netmask(range.second));
        }
      }
      else {
        dbpf->includeRange(Netmask(*boost::get<std::string>(&ranges)));
      }
    });
#endif /* HAVE_EBPF */

  /* EDNSOptionView */
  g_lua.registerFunction<size_t(EDNSOptionView::*)()>("count", [](const EDNSOptionView& option) {
      return option.values.size();
    });
  g_lua.registerFunction<std::vector<string>(EDNSOptionView::*)()>("getValues", [] (const EDNSOptionView& option) {
    std::vector<string> values;
    for (const auto& value : option.values) {
      values.push_back(std::string(value.content, value.size));
    }
    return values;
  });

  g_lua.writeFunction("newDOHResponseMapEntry", [](const std::string& regex, uint16_t status, const std::string& content, boost::optional<std::map<std::string, std::string>> customHeaders) {
    boost::optional<std::vector<std::pair<std::string, std::string>>> headers{boost::none};
    if (customHeaders) {
      headers = std::vector<std::pair<std::string, std::string>>();
      for (const auto& header : *customHeaders) {
        headers->push_back({ boost::to_lower_copy(header.first), header.second });
      }
    }
    return std::make_shared<DOHResponseMapEntry>(regex, status, content, headers);
  });
}
