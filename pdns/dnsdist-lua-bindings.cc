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

void setupLuaBindings(LuaContext& luaCtx, bool client)
{
  luaCtx.writeFunction("infolog", [](const string& arg) {
      infolog("%s", arg);
    });
  luaCtx.writeFunction("errlog", [](const string& arg) {
      errlog("%s", arg);
    });
  luaCtx.writeFunction("warnlog", [](const string& arg) {
      warnlog("%s", arg);
    });
  luaCtx.writeFunction("show", [](const string& arg) {
      g_outputBuffer+=arg;
      g_outputBuffer+="\n";
    });

  /* Exceptions */
  luaCtx.registerFunction<string(std::exception_ptr::*)()const>("__tostring", [](const std::exception_ptr& eptr) {
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
  luaCtx.writeFunction("newServerPolicy", [](string name, ServerPolicy::policyfunc_t policy) { return std::make_shared<ServerPolicy>(name, policy, true);});
  luaCtx.registerMember("name", &ServerPolicy::d_name);
  luaCtx.registerMember("policy", &ServerPolicy::d_policy);
  luaCtx.registerMember("ffipolicy", &ServerPolicy::d_ffipolicy);
  luaCtx.registerMember("isLua", &ServerPolicy::d_isLua);
  luaCtx.registerMember("isFFI", &ServerPolicy::d_isFFI);
  luaCtx.registerMember("isPerThread", &ServerPolicy::d_isPerThread);
  luaCtx.registerFunction("toString", &ServerPolicy::toString);

  luaCtx.writeVariable("firstAvailable", ServerPolicy{"firstAvailable", firstAvailable, false});
  luaCtx.writeVariable("roundrobin", ServerPolicy{"roundrobin", roundrobin, false});
  luaCtx.writeVariable("wrandom", ServerPolicy{"wrandom", wrandom, false});
  luaCtx.writeVariable("whashed", ServerPolicy{"whashed", whashed, false});
  luaCtx.writeVariable("chashed", ServerPolicy{"chashed", chashed, false});
  luaCtx.writeVariable("leastOutstanding", ServerPolicy{"leastOutstanding", leastOutstanding, false});

  /* ServerPool */
  luaCtx.registerFunction<void(std::shared_ptr<ServerPool>::*)(std::shared_ptr<DNSDistPacketCache>)>("setCache", [](std::shared_ptr<ServerPool> pool, std::shared_ptr<DNSDistPacketCache> cache) {
      if (pool) {
        pool->packetCache = cache;
      }
    });
  luaCtx.registerFunction("getCache", &ServerPool::getCache);
  luaCtx.registerFunction<void(std::shared_ptr<ServerPool>::*)()>("unsetCache", [](std::shared_ptr<ServerPool> pool) {
      if (pool) {
        pool->packetCache = nullptr;
      }
    });
  luaCtx.registerFunction("getECS", &ServerPool::getECS);
  luaCtx.registerFunction("setECS", &ServerPool::setECS);

  /* DownstreamState */
  luaCtx.registerFunction<void(DownstreamState::*)(int)>("setQPS", [](DownstreamState& s, int lim) { s.qps = lim ? QPSLimiter(lim, lim) : QPSLimiter(); });
  luaCtx.registerFunction<void(std::shared_ptr<DownstreamState>::*)(string)>("addPool", [](std::shared_ptr<DownstreamState> s, string pool) {
      auto localPools = g_pools.getCopy();
      addServerToPool(localPools, pool, s);
      g_pools.setState(localPools);
      s->pools.insert(pool);
    });
  luaCtx.registerFunction<void(std::shared_ptr<DownstreamState>::*)(string)>("rmPool", [](std::shared_ptr<DownstreamState> s, string pool) {
      auto localPools = g_pools.getCopy();
      removeServerFromPool(localPools, pool, s);
      g_pools.setState(localPools);
      s->pools.erase(pool);
    });
  luaCtx.registerFunction<uint64_t(DownstreamState::*)()const>("getOutstanding", [](const DownstreamState& s) { return s.outstanding.load(); });
  luaCtx.registerFunction<uint64_t(DownstreamState::*)()const>("getDrops", [](const DownstreamState& s) { return s.reuseds.load(); });
  luaCtx.registerFunction<double(DownstreamState::*)()const>("getLatency", [](const DownstreamState& s) { return s.latencyUsec; });
  luaCtx.registerFunction("isUp", &DownstreamState::isUp);
  luaCtx.registerFunction("setDown", &DownstreamState::setDown);
  luaCtx.registerFunction("setUp", &DownstreamState::setUp);
  luaCtx.registerFunction<void(DownstreamState::*)(boost::optional<bool> newStatus)>("setAuto", [](DownstreamState& s, boost::optional<bool> newStatus) {
      if (newStatus) {
        s.upStatus = *newStatus;
      }
      s.setAuto();
    });
  luaCtx.registerFunction<std::string(DownstreamState::*)()const>("getName", [](const DownstreamState& s) { return s.getName(); });
  luaCtx.registerFunction<std::string(DownstreamState::*)()const>("getNameWithAddr", [](const DownstreamState& s) { return s.getNameWithAddr(); });
  luaCtx.registerMember("upStatus", &DownstreamState::upStatus);
  luaCtx.registerMember<int (DownstreamState::*)>("weight",
    [](const DownstreamState& s) -> int {return s.weight;},
    [](DownstreamState& s, int newWeight) {s.setWeight(newWeight);}
  );
  luaCtx.registerMember("order", &DownstreamState::order);
  luaCtx.registerMember<const std::string(DownstreamState::*)>("name", [](const DownstreamState& backend) -> const std::string { return backend.getName(); }, [](DownstreamState& backend, const std::string& newName) { backend.setName(newName); });
  luaCtx.registerFunction<std::string(DownstreamState::*)()const>("getID", [](const DownstreamState& s) { return boost::uuids::to_string(s.id); });

  /* dnsheader */
  luaCtx.registerFunction<void(dnsheader::*)(bool)>("setRD", [](dnsheader& dh, bool v) {
      dh.rd=v;
    });

  luaCtx.registerFunction<bool(dnsheader::*)()>("getRD", [](dnsheader& dh) {
      return (bool)dh.rd;
    });

  luaCtx.registerFunction<void(dnsheader::*)(bool)>("setRA", [](dnsheader& dh, bool v) {
      dh.ra=v;
    });

  luaCtx.registerFunction<bool(dnsheader::*)()>("getRA", [](dnsheader& dh) {
      return (bool)dh.ra;
    });

  luaCtx.registerFunction<void(dnsheader::*)(bool)>("setAD", [](dnsheader& dh, bool v) {
      dh.ad=v;
    });

  luaCtx.registerFunction<bool(dnsheader::*)()>("getAD", [](dnsheader& dh) {
      return (bool)dh.ad;
    });

  luaCtx.registerFunction<void(dnsheader::*)(bool)>("setAA", [](dnsheader& dh, bool v) {
      dh.aa=v;
    });

  luaCtx.registerFunction<bool(dnsheader::*)()>("getAA", [](dnsheader& dh) {
      return (bool)dh.aa;
    });

  luaCtx.registerFunction<void(dnsheader::*)(bool)>("setCD", [](dnsheader& dh, bool v) {
      dh.cd=v;
    });

  luaCtx.registerFunction<bool(dnsheader::*)()>("getCD", [](dnsheader& dh) {
      return (bool)dh.cd;
    });

  luaCtx.registerFunction<void(dnsheader::*)(bool)>("setTC", [](dnsheader& dh, bool v) {
      dh.tc=v;
      if(v) dh.ra = dh.rd; // you'll always need this, otherwise TC=1 gets ignored
    });

  luaCtx.registerFunction<void(dnsheader::*)(bool)>("setQR", [](dnsheader& dh, bool v) {
      dh.qr=v;
    });

  /* ComboAddress */
  luaCtx.writeFunction("newCA", [](const std::string& name) { return ComboAddress(name); });
  luaCtx.writeFunction("newCAFromRaw", [](const std::string& raw, boost::optional<uint16_t> port) {
                                        if (raw.size() == 4) {
                                          struct sockaddr_in sin4;
                                          memset(&sin4, 0, sizeof(sin4));
                                          sin4.sin_family = AF_INET;
                                          memcpy(&sin4.sin_addr.s_addr, raw.c_str(), raw.size());
                                          if (port) {
                                            sin4.sin_port = htons(*port);
                                          }
                                          return ComboAddress(&sin4);
                                        }
                                        else if (raw.size() == 16) {
                                          struct sockaddr_in6 sin6;
                                          memset(&sin6, 0, sizeof(sin6));
                                          sin6.sin6_family = AF_INET6;
                                          memcpy(&sin6.sin6_addr.s6_addr, raw.c_str(), raw.size());
                                          if (port) {
                                            sin6.sin6_port = htons(*port);
                                          }
                                          return ComboAddress(&sin6);
                                        }
                                        return ComboAddress();
                                      });
  luaCtx.registerFunction<string(ComboAddress::*)()const>("tostring", [](const ComboAddress& ca) { return ca.toString(); });
  luaCtx.registerFunction<string(ComboAddress::*)()const>("tostringWithPort", [](const ComboAddress& ca) { return ca.toStringWithPort(); });
  luaCtx.registerFunction<string(ComboAddress::*)()const>("toString", [](const ComboAddress& ca) { return ca.toString(); });
  luaCtx.registerFunction<string(ComboAddress::*)()const>("toStringWithPort", [](const ComboAddress& ca) { return ca.toStringWithPort(); });
  luaCtx.registerFunction<uint16_t(ComboAddress::*)()const>("getPort", [](const ComboAddress& ca) { return ntohs(ca.sin4.sin_port); } );
  luaCtx.registerFunction<void(ComboAddress::*)(unsigned int)>("truncate", [](ComboAddress& ca, unsigned int bits) { ca.truncate(bits); });
  luaCtx.registerFunction<bool(ComboAddress::*)()const>("isIPv4", [](const ComboAddress& ca) { return ca.sin4.sin_family == AF_INET; });
  luaCtx.registerFunction<bool(ComboAddress::*)()const>("isIPv6", [](const ComboAddress& ca) { return ca.sin4.sin_family == AF_INET6; });
  luaCtx.registerFunction<bool(ComboAddress::*)()const>("isMappedIPv4", [](const ComboAddress& ca) { return ca.isMappedIPv4(); });
  luaCtx.registerFunction<ComboAddress(ComboAddress::*)()const>("mapToIPv4", [](const ComboAddress& ca) { return ca.mapToIPv4(); });
  luaCtx.registerFunction<bool(nmts_t::*)(const ComboAddress&)>("match", [](nmts_t& s, const ComboAddress& ca) { return s.match(ca); });

  /* DNSName */
  luaCtx.registerFunction("isPartOf", &DNSName::isPartOf);
  luaCtx.registerFunction<bool(DNSName::*)()>("chopOff", [](DNSName&dn ) { return dn.chopOff(); });
  luaCtx.registerFunction<unsigned int(DNSName::*)()const>("countLabels", [](const DNSName& name) { return name.countLabels(); });
  luaCtx.registerFunction<size_t(DNSName::*)()const>("hash", [](const DNSName& name) { return name.hash(); });
  luaCtx.registerFunction<size_t(DNSName::*)()const>("wirelength", [](const DNSName& name) { return name.wirelength(); });
  luaCtx.registerFunction<string(DNSName::*)()const>("tostring", [](const DNSName&dn ) { return dn.toString(); });
  luaCtx.registerFunction<string(DNSName::*)()const>("toString", [](const DNSName&dn ) { return dn.toString(); });
  luaCtx.registerFunction<string(DNSName::*)()const>("toDNSString", [](const DNSName&dn ) { return dn.toDNSString(); });
  luaCtx.writeFunction("newDNSName", [](const std::string& name) { return DNSName(name); });
  luaCtx.writeFunction("newDNSNameFromRaw", [](const std::string& name) { return DNSName(name.c_str(), name.size(), 0, false); });
  luaCtx.writeFunction("newSuffixMatchNode", []() { return SuffixMatchNode(); });
  luaCtx.writeFunction("newDNSNameSet", []() { return DNSNameSet(); });

  /* DNSNameSet */
  luaCtx.registerFunction<string(DNSNameSet::*)()const>("toString", [](const DNSNameSet&dns ) { return dns.toString(); });
  luaCtx.registerFunction<void(DNSNameSet::*)(DNSName&)>("add", [](DNSNameSet& dns, DNSName& dn) { dns.insert(dn); });
  luaCtx.registerFunction<bool(DNSNameSet::*)(DNSName&)>("check", [](DNSNameSet& dns, DNSName& dn) { return dns.find(dn) != dns.end(); });
  luaCtx.registerFunction("delete",(size_t (DNSNameSet::*)(const DNSName&)) &DNSNameSet::erase);
  luaCtx.registerFunction("size",(size_t (DNSNameSet::*)() const) &DNSNameSet::size);
  luaCtx.registerFunction("clear",(void (DNSNameSet::*)()) &DNSNameSet::clear);
  luaCtx.registerFunction("empty",(bool (DNSNameSet::*)() const) &DNSNameSet::empty);

  /* SuffixMatchNode */
  luaCtx.registerFunction<void (SuffixMatchNode::*)(const boost::variant<DNSName, string, vector<pair<int, DNSName>>, vector<pair<int, string>>> &name)>("add", [](SuffixMatchNode &smn, const boost::variant<DNSName, string, vector<pair<int, DNSName>>, vector<pair<int, string>>> &name) {
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
          for (const auto& n : names) {
            smn.add(n.second);
          }
          return;
      }
      if (name.type() == typeid(vector<pair<int, string>>)) {
          auto names = boost::get<vector<pair<int, string>>>(name);
          for (const auto& n : names) {
            smn.add(n.second);
          }
          return;
      }
  });
  luaCtx.registerFunction<void (SuffixMatchNode::*)(const boost::variant<DNSName, string, vector<pair<int, DNSName>>, vector<pair<int, string>>> &name)>("remove", [](SuffixMatchNode &smn, const boost::variant<DNSName, string, vector<pair<int, DNSName>>, vector<pair<int, string>>> &name) {
      if (name.type() == typeid(DNSName)) {
          auto n = boost::get<DNSName>(name);
          smn.remove(n);
          return;
      }
      if (name.type() == typeid(string)) {
          auto n = boost::get<string>(name);
          DNSName d(n);
          smn.remove(d);
          return;
      }
      if (name.type() == typeid(vector<pair<int, DNSName>>)) {
          auto names = boost::get<vector<pair<int, DNSName>>>(name);
          for (const auto& n : names) {
            smn.remove(n.second);
          }
          return;
      }
      if (name.type() == typeid(vector<pair<int, string>>)) {
          auto names = boost::get<vector<pair<int, string>>>(name);
          for (const auto& n : names) {
            DNSName d(n.second);
            smn.remove(d);
          }
          return;
      }
  });

  luaCtx.registerFunction("check",(bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);

  /* Netmask */
  luaCtx.writeFunction("newNetmask", [](boost::variant<std::string,ComboAddress> s, boost::optional<uint8_t> bits) {
    if (s.type() == typeid(ComboAddress)) {
      auto ca = boost::get<ComboAddress>(s);
      if (bits) {
        return Netmask(ca, *bits);
      }
      return Netmask(ca);
    }
    else if (s.type() == typeid(std::string)) {
      auto str = boost::get<std::string>(s);
      return Netmask(str);
    }
    throw std::runtime_error("Invalid parameter passed to 'newNetmask()'");
  });
  luaCtx.registerFunction("empty", &Netmask::empty);
  luaCtx.registerFunction("getBits", &Netmask::getBits);
  luaCtx.registerFunction<ComboAddress(Netmask::*)()const>("getNetwork", [](const Netmask& nm) { return nm.getNetwork(); } ); // const reference makes this necessary
  luaCtx.registerFunction<ComboAddress(Netmask::*)()const>("getMaskedNetwork", [](const Netmask& nm) { return nm.getMaskedNetwork(); } );
  luaCtx.registerFunction("isIpv4", &Netmask::isIPv4);
  luaCtx.registerFunction("isIPv4", &Netmask::isIPv4);
  luaCtx.registerFunction("isIpv6", &Netmask::isIPv6);
  luaCtx.registerFunction("isIPv6", &Netmask::isIPv6);
  luaCtx.registerFunction("match", (bool (Netmask::*)(const string&) const)&Netmask::match);
  luaCtx.registerFunction("toString", &Netmask::toString);
  luaCtx.registerEqFunction(&Netmask::operator==);
  luaCtx.registerToStringFunction(&Netmask::toString);

  /* NetmaskGroup */
  luaCtx.writeFunction("newNMG", []() { return NetmaskGroup(); });
  luaCtx.registerFunction<void(NetmaskGroup::*)(const std::string&mask)>("addMask", [](NetmaskGroup&nmg, const std::string& mask)
                         {
                           nmg.addMask(mask);
                         });
  luaCtx.registerFunction<void(NetmaskGroup::*)(const std::map<ComboAddress,int>& map)>("addMasks", [](NetmaskGroup&nmg, const std::map<ComboAddress,int>& map)
                         {
                           for (const auto& entry : map) {
                             nmg.addMask(Netmask(entry.first));
                           }
                         });

  luaCtx.registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const)&NetmaskGroup::match);
  luaCtx.registerFunction("size", &NetmaskGroup::size);
  luaCtx.registerFunction("clear", &NetmaskGroup::clear);
  luaCtx.registerFunction<string(NetmaskGroup::*)()const>("toString", [](const NetmaskGroup& nmg ) { return "NetmaskGroup " + nmg.toString(); });

  /* QPSLimiter */
  luaCtx.writeFunction("newQPSLimiter", [](int rate, int burst) { return QPSLimiter(rate, burst); });
  luaCtx.registerFunction("check", &QPSLimiter::check);

  /* ClientState */
  luaCtx.registerFunction<std::string(ClientState::*)()const>("toString", [](const ClientState& fe) {
      setLuaNoSideEffect();
      return fe.local.toStringWithPort();
    });
  luaCtx.registerMember("muted", &ClientState::muted);
#ifdef HAVE_EBPF
  luaCtx.registerFunction<void(ClientState::*)(std::shared_ptr<BPFFilter>)>("attachFilter", [](ClientState& frontend, std::shared_ptr<BPFFilter> bpf) {
      if (bpf) {
        frontend.attachFilter(bpf);
      }
    });
  luaCtx.registerFunction<void(ClientState::*)()>("detachFilter", [](ClientState& frontend) {
      frontend.detachFilter();
    });
#endif /* HAVE_EBPF */

  /* BPF Filter */
#ifdef HAVE_EBPF
  luaCtx.writeFunction("newBPFFilter", [client](uint32_t maxV4, uint32_t maxV6, uint32_t maxQNames) {
      if (client) {
        return std::shared_ptr<BPFFilter>(nullptr);
      }
      return std::make_shared<BPFFilter>(maxV4, maxV6, maxQNames);
    });

  luaCtx.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const ComboAddress& ca)>("block", [](std::shared_ptr<BPFFilter> bpf, const ComboAddress& ca) {
      if (bpf) {
        return bpf->block(ca);
      }
    });

  luaCtx.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const DNSName& qname, boost::optional<uint16_t> qtype)>("blockQName", [](std::shared_ptr<BPFFilter> bpf, const DNSName& qname, boost::optional<uint16_t> qtype) {
      if (bpf) {
        return bpf->block(qname, qtype ? *qtype : 255);
      }
    });

  luaCtx.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const ComboAddress& ca)>("unblock", [](std::shared_ptr<BPFFilter> bpf, const ComboAddress& ca) {
      if (bpf) {
        return bpf->unblock(ca);
      }
    });

  luaCtx.registerFunction<void(std::shared_ptr<BPFFilter>::*)(const DNSName& qname, boost::optional<uint16_t> qtype)>("unblockQName", [](std::shared_ptr<BPFFilter> bpf, const DNSName& qname, boost::optional<uint16_t> qtype) {
      if (bpf) {
        return bpf->unblock(qname, qtype ? *qtype : 255);
      }
    });

  luaCtx.registerFunction<std::string(std::shared_ptr<BPFFilter>::*)()const>("getStats", [](const std::shared_ptr<BPFFilter> bpf) {
      setLuaNoSideEffect();
      std::string res;
      if (bpf) {
        auto stats = bpf->getAddrStats();
        for (const auto& value : stats) {
          if (value.first.sin4.sin_family == AF_INET) {
            res += value.first.toString() + ": " + std::to_string(value.second) + "\n";
          }
          else if (value.first.sin4.sin_family == AF_INET6) {
            res += "[" + value.first.toString() + "]: " + std::to_string(value.second) + "\n";
          }
        }
        auto qstats = bpf->getQNameStats();
        for (const auto& value : qstats) {
          res += std::get<0>(value).toString() + " " + std::to_string(std::get<1>(value)) + ": " + std::to_string(std::get<2>(value)) + "\n";
        }
      }
      return res;
    });

  luaCtx.registerFunction<void(std::shared_ptr<BPFFilter>::*)()>("attachToAllBinds", [](std::shared_ptr<BPFFilter> bpf) {
      std::string res;
      if (bpf) {
        for (const auto& frontend : g_frontends) {
          frontend->attachFilter(bpf);
        }
      }
    });

    luaCtx.writeFunction("newDynBPFFilter", [client](std::shared_ptr<BPFFilter> bpf) {
        if (client) {
          return std::shared_ptr<DynBPFFilter>(nullptr);
        }
        return std::make_shared<DynBPFFilter>(bpf);
      });

    luaCtx.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)(const ComboAddress& addr, boost::optional<int> seconds)>("block", [](std::shared_ptr<DynBPFFilter> dbpf, const ComboAddress& addr, boost::optional<int> seconds) {
        if (dbpf) {
          struct timespec until;
          clock_gettime(CLOCK_MONOTONIC, &until);
          until.tv_sec += seconds ? *seconds : 10;
          dbpf->block(addr, until);
        }
    });

    luaCtx.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)()>("purgeExpired", [](std::shared_ptr<DynBPFFilter> dbpf) {
        if (dbpf) {
          struct timespec now;
          clock_gettime(CLOCK_MONOTONIC, &now);
          dbpf->purgeExpired(now);
        }
    });

    luaCtx.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)(boost::variant<std::string, std::vector<std::pair<int, std::string>>>)>("excludeRange", [](std::shared_ptr<DynBPFFilter> dbpf, boost::variant<std::string, std::vector<std::pair<int, std::string>>> ranges) {
      if (ranges.type() == typeid(std::vector<std::pair<int, std::string>>)) {
        for (const auto& range : *boost::get<std::vector<std::pair<int, std::string>>>(&ranges)) {
          dbpf->excludeRange(Netmask(range.second));
        }
      }
      else {
        dbpf->excludeRange(Netmask(*boost::get<std::string>(&ranges)));
      }
    });

    luaCtx.registerFunction<void(std::shared_ptr<DynBPFFilter>::*)(boost::variant<std::string, std::vector<std::pair<int, std::string>>>)>("includeRange", [](std::shared_ptr<DynBPFFilter> dbpf, boost::variant<std::string, std::vector<std::pair<int, std::string>>> ranges) {
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
  luaCtx.registerFunction<size_t(EDNSOptionView::*)()const>("count", [](const EDNSOptionView& option) {
      return option.values.size();
    });
  luaCtx.registerFunction<std::vector<string>(EDNSOptionView::*)()const>("getValues", [] (const EDNSOptionView& option) {
    std::vector<string> values;
    for (const auto& value : option.values) {
      values.push_back(std::string(value.content, value.size));
    }
    return values;
  });

  luaCtx.writeFunction("newDOHResponseMapEntry", [](const std::string& regex, uint16_t status, const std::string& content, boost::optional<std::map<std::string, std::string>> customHeaders) {
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
