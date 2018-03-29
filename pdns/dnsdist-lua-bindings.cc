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
#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-protobuf.hh"

#include "dnstap.hh"
#include "dolog.hh"
#include "fstrm_logger.hh"
#include "remote_logger.hh"

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

  /* ServerPolicy */
  g_lua.writeFunction("newServerPolicy", [](string name, policyfunc_t policy) { return ServerPolicy{name, policy, true};});
  g_lua.registerMember("name", &ServerPolicy::name);
  g_lua.registerMember("policy", &ServerPolicy::policy);
  g_lua.registerMember("isLua", &ServerPolicy::isLua);

  g_lua.writeVariable("firstAvailable", ServerPolicy{"firstAvailable", firstAvailable, false});
  g_lua.writeVariable("roundrobin", ServerPolicy{"roundrobin", roundrobin, false});
  g_lua.writeVariable("wrandom", ServerPolicy{"wrandom", wrandom, false});
  g_lua.writeVariable("whashed", ServerPolicy{"whashed", whashed, false});
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
  g_lua.registerFunction<void(DownstreamState::*)()>("getOutstanding", [](const DownstreamState& s) { g_outputBuffer=std::to_string(s.outstanding.load()); });
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
  g_lua.registerMember("weight", &DownstreamState::weight);
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

  /* SuffixMatchNode */
  g_lua.registerFunction("add",(void (SuffixMatchNode::*)(const DNSName&)) &SuffixMatchNode::add);
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
  g_lua.writeFunction("newPacketCache", [](size_t maxEntries, boost::optional<uint32_t> maxTTL, boost::optional<uint32_t> minTTL, boost::optional<uint32_t> tempFailTTL, boost::optional<uint32_t> staleTTL, boost::optional<bool> dontAge, boost::optional<size_t> numberOfShards, boost::optional<bool> deferrableInsertLock) {
      return std::make_shared<DNSDistPacketCache>(maxEntries, maxTTL ? *maxTTL : 86400, minTTL ? *minTTL : 0, tempFailTTL ? *tempFailTTL : 60, staleTTL ? *staleTTL : 60, dontAge ? *dontAge : false, numberOfShards ? *numberOfShards : 1, deferrableInsertLock ? *deferrableInsertLock : true);
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
                  cache->expungeByName(dname, qtype ? *qtype : QType::ANY, suffixMatch ? *suffixMatch : false);
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

  g_lua.registerFunction<std::string(DnstapMessage::*)()>("toDebugString", [](const DnstapMessage& message) { return message.toDebugString(); });
  g_lua.registerFunction<void(DnstapMessage::*)(const std::string&)>("setExtra", [](DnstapMessage& message, const std::string& str) {
      message.setExtra(str);
    });

  /* RemoteLogger */
  g_lua.writeFunction("newRemoteLogger", [client](const std::string& remote, boost::optional<uint16_t> timeout, boost::optional<uint64_t> maxQueuedEntries, boost::optional<uint8_t> reconnectWaitTime) {
      return std::shared_ptr<RemoteLoggerInterface>(new RemoteLogger(ComboAddress(remote), timeout ? *timeout : 2, maxQueuedEntries ? *maxQueuedEntries : 100, reconnectWaitTime ? *reconnectWaitTime : 1, client));
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
        boost::format fmt("%1$-3d %|5t|%2$-8d %|10t|%3$-2d %|20t|%4$-21.21s %|41t|%5$-21.21s");
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
#endif /* HAVE_EBPF */
}
