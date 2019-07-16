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
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "config.h"
#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-protobuf.hh"

#include "dnstap.hh"
#include "dolog.hh"
#include "fstrm_logger.hh"
#include "remote_logger.hh"

#ifdef HAVE_LIBCRYPTO
#include "ipcipher.hh"
#endif /* HAVE_LIBCRYPTO */

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

#ifdef HAVE_LIBCRYPTO
  g_lua.registerFunction<ComboAddress(ComboAddress::*)(const std::string& key)>("ipencrypt", [](const ComboAddress& ca, const std::string& key) {
      return encryptCA(ca, key);
    });
  g_lua.registerFunction<ComboAddress(ComboAddress::*)(const std::string& key)>("ipdecrypt", [](const ComboAddress& ca, const std::string& key) {
      return decryptCA(ca, key);
    });

  g_lua.writeFunction("makeIPCipherKey", [](const std::string& password) {
      return makeIPCipherKey(password);
    });
#endif /* HAVE_LIBCRYPTO */

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

  /* PacketCache */
  g_lua.writeFunction("newPacketCache", [](size_t maxEntries, boost::optional<std::unordered_map<std::string, boost::variant<bool, size_t>>> vars) {

      bool keepStaleData = false;
      size_t maxTTL = 86400;
      size_t minTTL = 0;
      size_t tempFailTTL = 60;
      size_t maxNegativeTTL = 3600;
      size_t staleTTL = 60;
      size_t numberOfShards = 1;
      bool dontAge = false;
      bool deferrableInsertLock = true;
      bool ecsParsing = false;

      if (vars) {

        if (vars->count("deferrableInsertLock")) {
          deferrableInsertLock = boost::get<bool>((*vars)["deferrableInsertLock"]);
        }

        if (vars->count("dontAge")) {
          dontAge = boost::get<bool>((*vars)["dontAge"]);
        }

        if (vars->count("keepStaleData")) {
          keepStaleData = boost::get<bool>((*vars)["keepStaleData"]);
        }

        if (vars->count("maxNegativeTTL")) {
          maxNegativeTTL = boost::get<size_t>((*vars)["maxNegativeTTL"]);
        }

        if (vars->count("maxTTL")) {
          maxTTL = boost::get<size_t>((*vars)["maxTTL"]);
        }

        if (vars->count("minTTL")) {
          minTTL = boost::get<size_t>((*vars)["minTTL"]);
        }

        if (vars->count("numberOfShards")) {
          numberOfShards = boost::get<size_t>((*vars)["numberOfShards"]);
        }

        if (vars->count("parseECS")) {
          ecsParsing = boost::get<bool>((*vars)["parseECS"]);
        }

        if (vars->count("staleTTL")) {
          staleTTL = boost::get<size_t>((*vars)["staleTTL"]);
        }

        if (vars->count("temporaryFailureTTL")) {
          tempFailTTL = boost::get<size_t>((*vars)["temporaryFailureTTL"]);
        }
      }

      auto res = std::make_shared<DNSDistPacketCache>(maxEntries, maxTTL, minTTL, tempFailTTL, maxNegativeTTL, staleTTL, dontAge, numberOfShards, deferrableInsertLock, ecsParsing);

      res->setKeepStaleData(keepStaleData);

      return res;
    });
  g_lua.registerFunction("toString", &DNSDistPacketCache::toString);
  g_lua.registerFunction("isFull", &DNSDistPacketCache::isFull);
  g_lua.registerFunction("purgeExpired", &DNSDistPacketCache::purgeExpired);
  g_lua.registerFunction("expunge", &DNSDistPacketCache::expunge);
  g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const DNSName& dname, boost::optional<uint16_t> qtype, boost::optional<bool> suffixMatch)>("expungeByName", [](
              std::shared_ptr<DNSDistPacketCache> cache,
              const DNSName& dname,
              boost::optional<uint16_t> qtype,
              boost::optional<bool> suffixMatch) {
                if (cache) {
                  g_outputBuffer="Expunged " + std::to_string(cache->expungeByName(dname, qtype ? *qtype : QType(QType::ANY).getCode(), suffixMatch ? *suffixMatch : false)) + " records\n";
                }
    });
  g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)()>("printStats", [](const std::shared_ptr<DNSDistPacketCache> cache) {
      if (cache) {
        g_outputBuffer="Entries: " + std::to_string(cache->getEntriesCount()) + "/" + std::to_string(cache->getMaxEntries()) + "\n";
        g_outputBuffer+="Hits: " + std::to_string(cache->getHits()) + "\n";
        g_outputBuffer+="Misses: " + std::to_string(cache->getMisses()) + "\n";
        g_outputBuffer+="Deferred inserts: " + std::to_string(cache->getDeferredInserts()) + "\n";
        g_outputBuffer+="Deferred lookups: " + std::to_string(cache->getDeferredLookups()) + "\n";
        g_outputBuffer+="Lookup Collisions: " + std::to_string(cache->getLookupCollisions()) + "\n";
        g_outputBuffer+="Insert Collisions: " + std::to_string(cache->getInsertCollisions()) + "\n";
        g_outputBuffer+="TTL Too Shorts: " + std::to_string(cache->getTTLTooShorts()) + "\n";
      }
    });
  g_lua.registerFunction<std::unordered_map<std::string, uint64_t>(std::shared_ptr<DNSDistPacketCache>::*)()>("getStats", [](const std::shared_ptr<DNSDistPacketCache> cache) {
      std::unordered_map<std::string, uint64_t> stats;
      if (cache) {
        stats["entries"] = cache->getEntriesCount();
        stats["maxEntries"] = cache->getMaxEntries();
        stats["hits"] = cache->getHits();
        stats["misses"] = cache->getMisses();
        stats["deferredInserts"] = cache->getDeferredInserts();
        stats["deferredLookups"] = cache->getDeferredLookups();
        stats["lookupCollisions"] = cache->getLookupCollisions();
        stats["insertCollisions"] = cache->getInsertCollisions();
        stats["ttlTooShorts"] = cache->getTTLTooShorts();
      }
      return stats;
    });
  g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const std::string& fname)>("dump", [](const std::shared_ptr<DNSDistPacketCache> cache, const std::string& fname) {
      if (cache) {

        int fd = open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
        if (fd < 0) {
          g_outputBuffer = "Error opening dump file for writing: " + stringerror() + "\n";
          return;
        }

        uint64_t records = 0;
        try {
          records = cache->dump(fd);
        }
        catch (const std::exception& e) {
          close(fd);
          throw;
        }

        close(fd);

        g_outputBuffer += "Dumped " + std::to_string(records) + " records\n";
      }
    });

  /* ProtobufMessage */
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(std::string)>("setTag", [](DNSDistProtoBufMessage& message, const std::string& strValue) {
      message.addTag(strValue);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(vector<pair<int, string>>)>("setTagArray", [](DNSDistProtoBufMessage& message, const vector<pair<int, string>>&tags) {
      for (const auto& tag : tags) {
        message.addTag(tag.second);
      }
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(boost::optional <time_t> sec, boost::optional <uint32_t> uSec)>("setProtobufResponseType",
                                        [](DNSDistProtoBufMessage& message, boost::optional <time_t> sec, boost::optional <uint32_t> uSec) {
      message.setType(DNSProtoBufMessage::Response);
      message.setQueryTime(sec?*sec:0, uSec?*uSec:0);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string& strQueryName, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob)>("addResponseRR", [](DNSDistProtoBufMessage& message,
                                                            const std::string& strQueryName, uint16_t uType, uint16_t uClass, uint32_t uTTL, const std::string& strBlob) {
      message.addRR(DNSName(strQueryName), uType, uClass, uTTL, strBlob);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const Netmask&)>("setEDNSSubnet", [](DNSDistProtoBufMessage& message, const Netmask& subnet) { message.setEDNSSubnet(subnet); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const DNSName&, uint16_t, uint16_t)>("setQuestion", [](DNSDistProtoBufMessage& message, const DNSName& qname, uint16_t qtype, uint16_t qclass) { message.setQuestion(qname, qtype, qclass); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(size_t)>("setBytes", [](DNSDistProtoBufMessage& message, size_t bytes) { message.setBytes(bytes); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(time_t, uint32_t)>("setTime", [](DNSDistProtoBufMessage& message, time_t sec, uint32_t usec) { message.setTime(sec, usec); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(time_t, uint32_t)>("setQueryTime", [](DNSDistProtoBufMessage& message, time_t sec, uint32_t usec) { message.setQueryTime(sec, usec); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(uint8_t)>("setResponseCode", [](DNSDistProtoBufMessage& message, uint8_t rcode) { message.setResponseCode(rcode); });
  g_lua.registerFunction<std::string(DNSDistProtoBufMessage::*)()>("toDebugString", [](const DNSDistProtoBufMessage& message) { return message.toDebugString(); });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const ComboAddress&)>("setRequestor", [](DNSDistProtoBufMessage& message, const ComboAddress& addr) {
      message.setRequestor(addr);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string&)>("setRequestorFromString", [](DNSDistProtoBufMessage& message, const std::string& str) {
      message.setRequestor(str);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const ComboAddress&)>("setResponder", [](DNSDistProtoBufMessage& message, const ComboAddress& addr) {
      message.setResponder(addr);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string&)>("setResponderFromString", [](DNSDistProtoBufMessage& message, const std::string& str) {
      message.setResponder(str);
    });
  g_lua.registerFunction<void(DNSDistProtoBufMessage::*)(const std::string&)>("setServerIdentity", [](DNSDistProtoBufMessage& message, const std::string& str) {
      message.setServerIdentity(str);
    });

  g_lua.registerFunction<std::string(DnstapMessage::*)()>("toDebugString", [](const DnstapMessage& message) { return message.toDebugString(); });
  g_lua.registerFunction<void(DnstapMessage::*)(const std::string&)>("setExtra", [](DnstapMessage& message, const std::string& str) {
      message.setExtra(str);
    });

  /* RemoteLogger */
  g_lua.writeFunction("newRemoteLogger", [client](const std::string& remote, boost::optional<uint16_t> timeout, boost::optional<uint64_t> maxQueuedEntries, boost::optional<uint8_t> reconnectWaitTime) {
      return std::shared_ptr<RemoteLoggerInterface>(new RemoteLogger(ComboAddress(remote), timeout ? *timeout : 2, maxQueuedEntries ? (*maxQueuedEntries*100) : 10000, reconnectWaitTime ? *reconnectWaitTime : 1, client));
    });

  g_lua.writeFunction("newFrameStreamUnixLogger", [client](const std::string& address) {
#ifdef HAVE_FSTRM
      return std::shared_ptr<RemoteLoggerInterface>(new FrameStreamLogger(AF_UNIX, address, !client));
#else
      throw std::runtime_error("fstrm support is required to build an AF_UNIX FrameStreamLogger");
#endif /* HAVE_FSTRM */
    });

  g_lua.writeFunction("newFrameStreamTcpLogger", [client](const std::string& address) {
#if defined(HAVE_FSTRM) && defined(HAVE_FSTRM_TCP_WRITER_INIT)
      return std::shared_ptr<RemoteLoggerInterface>(new FrameStreamLogger(AF_INET, address, !client));
#else
      throw std::runtime_error("fstrm with TCP support is required to build an AF_INET FrameStreamLogger");
#endif /* HAVE_FSTRM */
    });

  g_lua.registerFunction("toString", &RemoteLoggerInterface::toString);

#ifdef HAVE_DNSCRYPT
    /* DNSCryptContext bindings */
    g_lua.registerFunction<std::string(DNSCryptContext::*)()>("getProviderName", [](const DNSCryptContext& ctx) { return ctx.getProviderName().toStringNoDot(); });
    g_lua.registerFunction("markActive", &DNSCryptContext::markActive);
    g_lua.registerFunction("markInactive", &DNSCryptContext::markInactive);
    g_lua.registerFunction("removeInactiveCertificate", &DNSCryptContext::removeInactiveCertificate);
    g_lua.registerFunction<void(std::shared_ptr<DNSCryptContext>::*)(const std::string& certFile, const std::string& keyFile, boost::optional<bool> active)>("loadNewCertificate", [](std::shared_ptr<DNSCryptContext> ctx, const std::string& certFile, const std::string& keyFile, boost::optional<bool> active) {

      if (ctx == nullptr) {
        throw std::runtime_error("DNSCryptContext::loadNewCertificate() called on a nil value");
      }

      ctx->loadNewCertificate(certFile, keyFile, active ? *active : true);
    });
    g_lua.registerFunction<void(std::shared_ptr<DNSCryptContext>::*)(const DNSCryptCert& newCert, const DNSCryptPrivateKey& newKey, boost::optional<bool> active)>("addNewCertificate", [](std::shared_ptr<DNSCryptContext> ctx, const DNSCryptCert& newCert, const DNSCryptPrivateKey& newKey, boost::optional<bool> active) {

      if (ctx == nullptr) {
        throw std::runtime_error("DNSCryptContext::addNewCertificate() called on a nil value");
      }

      ctx->addNewCertificate(newCert, newKey, active ? *active : true);
    });
    g_lua.registerFunction<std::map<int, std::shared_ptr<DNSCryptCertificatePair>>(std::shared_ptr<DNSCryptContext>::*)()>("getCertificatePairs", [](std::shared_ptr<DNSCryptContext> ctx) {
      std::map<int, std::shared_ptr<DNSCryptCertificatePair>> result;

      if (ctx != nullptr) {
        size_t idx = 1;
        for (auto pair : ctx->getCertificates()) {
          result[idx++] = pair;
        }
      }

      return result;
    });

    g_lua.registerFunction<std::shared_ptr<DNSCryptCertificatePair>(std::shared_ptr<DNSCryptContext>::*)(size_t idx)>("getCertificatePair", [](std::shared_ptr<DNSCryptContext> ctx, size_t idx) {

      if (ctx == nullptr) {
        throw std::runtime_error("DNSCryptContext::getCertificatePair() called on a nil value");
      }

      std::shared_ptr<DNSCryptCertificatePair> result = nullptr;
      auto pairs = ctx->getCertificates();
      if (idx < pairs.size()) {
        result = pairs.at(idx);
      }

      return result;
    });

    g_lua.registerFunction<const DNSCryptCert(std::shared_ptr<DNSCryptContext>::*)(size_t idx)>("getCertificate", [](std::shared_ptr<DNSCryptContext> ctx, size_t idx) {

      if (ctx == nullptr) {
        throw std::runtime_error("DNSCryptContext::getCertificate() called on a nil value");
      }

      auto pairs = ctx->getCertificates();
      if (idx < pairs.size()) {
        return pairs.at(idx)->cert;
      }

      throw std::runtime_error("This DNSCrypt context has no certificate at index " + std::to_string(idx));
    });

    g_lua.registerFunction<std::string(std::shared_ptr<DNSCryptContext>::*)()>("printCertificates", [](const std::shared_ptr<DNSCryptContext> ctx) {
      ostringstream ret;

      if (ctx != nullptr) {
        size_t idx = 1;
        boost::format fmt("%1$-3d %|5t|%2$-8d %|10t|%3$-7d %|20t|%4$-21.21s %|41t|%5$-21.21s");
        ret << (fmt % "#" % "Serial" % "Version" % "From" % "To" ) << endl;

        for (auto pair : ctx->getCertificates()) {
          const auto cert = pair->cert;
          const DNSCryptExchangeVersion version = DNSCryptContext::getExchangeVersion(cert);

          ret << (fmt % idx % cert.getSerial() % (version == DNSCryptExchangeVersion::VERSION1 ? 1 : 2) % DNSCryptContext::certificateDateToStr(cert.getTSStart()) % DNSCryptContext::certificateDateToStr(cert.getTSEnd())) << endl;
        }
      }

      return ret.str();
    });

    g_lua.registerFunction<void(DNSCryptContext::*)(const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, boost::optional<DNSCryptExchangeVersion> version)>("generateAndLoadInMemoryCertificate", [](DNSCryptContext& ctx, const std::string& providerPrivateKeyFile, uint32_t serial, time_t begin, time_t end, boost::optional<DNSCryptExchangeVersion> version) {
        DNSCryptPrivateKey privateKey;
        DNSCryptCert cert;

        try {
          if (generateDNSCryptCertificate(providerPrivateKeyFile, serial, begin, end, version ? *version : DNSCryptExchangeVersion::VERSION1, cert, privateKey)) {
            ctx.addNewCertificate(cert, privateKey);
          }
        }
        catch(const std::exception& e) {
          errlog(e.what());
          g_outputBuffer="Error: "+string(e.what())+"\n";
        }
    });

    /* DNSCryptCertificatePair */
    g_lua.registerFunction<const DNSCryptCert(std::shared_ptr<DNSCryptCertificatePair>::*)()>("getCertificate", [](const std::shared_ptr<DNSCryptCertificatePair> pair) {
      if (pair == nullptr) {
        throw std::runtime_error("DNSCryptCertificatePair::getCertificate() called on a nil value");
      }
      return pair->cert;
    });
    g_lua.registerFunction<bool(std::shared_ptr<DNSCryptCertificatePair>::*)()>("isActive", [](const std::shared_ptr<DNSCryptCertificatePair> pair) {
      if (pair == nullptr) {
        throw std::runtime_error("DNSCryptCertificatePair::isActive() called on a nil value");
      }
      return pair->active;
    });

    /* DNSCryptCert */
    g_lua.registerFunction<std::string(DNSCryptCert::*)()>("getMagic", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.magic), sizeof(cert.magic)); });
    g_lua.registerFunction<std::string(DNSCryptCert::*)()>("getEsVersion", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.esVersion), sizeof(cert.esVersion)); });
    g_lua.registerFunction<std::string(DNSCryptCert::*)()>("getProtocolMinorVersion", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.protocolMinorVersion), sizeof(cert.protocolMinorVersion)); });
    g_lua.registerFunction<std::string(DNSCryptCert::*)()>("getSignature", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signature), sizeof(cert.signature)); });
    g_lua.registerFunction<std::string(DNSCryptCert::*)()>("getResolverPublicKey", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signedData.resolverPK), sizeof(cert.signedData.resolverPK)); });
    g_lua.registerFunction<std::string(DNSCryptCert::*)()>("getClientMagic", [](const DNSCryptCert& cert) { return std::string(reinterpret_cast<const char*>(cert.signedData.clientMagic), sizeof(cert.signedData.clientMagic)); });
    g_lua.registerFunction<uint32_t(DNSCryptCert::*)()>("getSerial", [](const DNSCryptCert& cert) { return cert.getSerial(); });
    g_lua.registerFunction<uint32_t(DNSCryptCert::*)()>("getTSStart", [](const DNSCryptCert& cert) { return ntohl(cert.getTSStart()); });
    g_lua.registerFunction<uint32_t(DNSCryptCert::*)()>("getTSEnd", [](const DNSCryptCert& cert) { return ntohl(cert.getTSEnd()); });
#endif

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
}
