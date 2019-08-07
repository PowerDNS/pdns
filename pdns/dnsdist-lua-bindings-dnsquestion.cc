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
#include "dnsdist-ecs.hh"
#include "dnsdist-lua.hh"
#include "dnsparser.hh"

void setupLuaBindingsDNSQuestion()
{
  /* DNSQuestion */
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
  g_lua.registerMember<boost::optional<uint32_t> (DNSQuestion::*)>("tempFailureTTL",
      [](const DNSQuestion& dq) -> boost::optional<uint32_t> {
        return dq.tempFailureTTL;
      },
      [](DNSQuestion& dq, boost::optional<uint32_t> newValue) {
        dq.tempFailureTTL = newValue;
      }
    );
  g_lua.registerFunction<bool(DNSQuestion::*)()>("getDO", [](const DNSQuestion& dq) {
      return getEDNSZ(dq) & EDNS_HEADER_FLAG_DO;
    });

  g_lua.registerFunction<std::map<uint16_t, EDNSOptionView>(DNSQuestion::*)()>("getEDNSOptions", [](DNSQuestion& dq) {
      if (dq.ednsOptions == nullptr) {
        parseEDNSOptions(dq);
      }

      return *dq.ednsOptions;
    });
  g_lua.registerFunction<std::string(DNSQuestion::*)(void)>("getTrailingData", [](const DNSQuestion& dq) {
      const char* message = reinterpret_cast<const char*>(dq.dh);
      const uint16_t messageLen = getDNSPacketLength(message, dq.len);
      const std::string tail = std::string(message + messageLen, dq.len - messageLen);
      return tail;
    });
  g_lua.registerFunction<bool(DNSQuestion::*)(std::string)>("setTrailingData", [](DNSQuestion& dq, const std::string& tail) {
      char* message = reinterpret_cast<char*>(dq.dh);
      const uint16_t messageLen = getDNSPacketLength(message, dq.len);
      const uint16_t tailLen = tail.size();
      if(tailLen > (dq.size - messageLen)) {
        return false;
      }

      /* Update length and copy data from the Lua string. */
      dq.len = messageLen + tailLen;
      if(tailLen > 0) {
        tail.copy(message + messageLen, tailLen);
      }
      return true;
    });

  g_lua.registerFunction<std::string(DNSQuestion::*)()>("getServerNameIndication", [](const DNSQuestion& dq) {
      return dq.sni;
    });

  g_lua.registerFunction<void(DNSQuestion::*)(std::string)>("sendTrap", [](const DNSQuestion& dq, boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
      if (g_snmpAgent && g_snmpTrapsEnabled) {
        g_snmpAgent->sendDNSTrap(dq, reason ? *reason : "");
      }
#endif /* HAVE_NET_SNMP */
    });
  g_lua.registerFunction<void(DNSQuestion::*)(std::string, std::string)>("setTag", [](DNSQuestion& dq, const std::string& strLabel, const std::string& strValue) {
      if(dq.qTag == nullptr) {
        dq.qTag = std::make_shared<QTag>();
      }
      dq.qTag->insert({strLabel, strValue});
    });
  g_lua.registerFunction<void(DNSQuestion::*)(vector<pair<string, string>>)>("setTagArray", [](DNSQuestion& dq, const vector<pair<string, string>>&tags) {
      if (!dq.qTag) {
        dq.qTag = std::make_shared<QTag>();
      }

      for (const auto& tag : tags) {
        dq.qTag->insert({tag.first, tag.second});
      }
    });
  g_lua.registerFunction<string(DNSQuestion::*)(std::string)>("getTag", [](const DNSQuestion& dq, const std::string& strLabel) {
      if (!dq.qTag) {
        return string();
      }

      std::string strValue;
      const auto it = dq.qTag->find(strLabel);
      if (it == dq.qTag->cend()) {
        return string();
      }
      return it->second;
    });
  g_lua.registerFunction<QTag(DNSQuestion::*)(void)>("getTagArray", [](const DNSQuestion& dq) {
      if (!dq.qTag) {
        QTag empty;
        return empty;
      }

      return *dq.qTag;
    });

  /* LuaWrapper doesn't support inheritance */
  g_lua.registerMember<const ComboAddress (DNSResponse::*)>("localaddr", [](const DNSResponse& dq) -> const ComboAddress { return *dq.local; }, [](DNSResponse& dq, const ComboAddress newLocal) { (void) newLocal; });
  g_lua.registerMember<const DNSName (DNSResponse::*)>("qname", [](const DNSResponse& dq) -> const DNSName { return *dq.qname; }, [](DNSResponse& dq, const DNSName newName) { (void) newName; });
  g_lua.registerMember<uint16_t (DNSResponse::*)>("qtype", [](const DNSResponse& dq) -> uint16_t { return dq.qtype; }, [](DNSResponse& dq, uint16_t newType) { (void) newType; });
  g_lua.registerMember<uint16_t (DNSResponse::*)>("qclass", [](const DNSResponse& dq) -> uint16_t { return dq.qclass; }, [](DNSResponse& dq, uint16_t newClass) { (void) newClass; });
  g_lua.registerMember<int (DNSResponse::*)>("rcode", [](const DNSResponse& dq) -> int { return dq.dh->rcode; }, [](DNSResponse& dq, int newRCode) { dq.dh->rcode = newRCode; });
  g_lua.registerMember<const ComboAddress (DNSResponse::*)>("remoteaddr", [](const DNSResponse& dq) -> const ComboAddress { return *dq.remote; }, [](DNSResponse& dq, const ComboAddress newRemote) { (void) newRemote; });
  g_lua.registerMember<dnsheader* (DNSResponse::*)>("dh", [](const DNSResponse& dr) -> dnsheader* { return dr.dh; }, [](DNSResponse& dr, dnsheader * newdh) { dr.dh = newdh; });
  g_lua.registerMember<uint16_t (DNSResponse::*)>("len", [](const DNSResponse& dq) -> uint16_t { return dq.len; }, [](DNSResponse& dq, uint16_t newlen) { dq.len = newlen; });
  g_lua.registerMember<uint8_t (DNSResponse::*)>("opcode", [](const DNSResponse& dq) -> uint8_t { return dq.dh->opcode; }, [](DNSResponse& dq, uint8_t newOpcode) { (void) newOpcode; });
  g_lua.registerMember<size_t (DNSResponse::*)>("size", [](const DNSResponse& dq) -> size_t { return dq.size; }, [](DNSResponse& dq, size_t newSize) { (void) newSize; });
  g_lua.registerMember<bool (DNSResponse::*)>("tcp", [](const DNSResponse& dq) -> bool { return dq.tcp; }, [](DNSResponse& dq, bool newTcp) { (void) newTcp; });
  g_lua.registerMember<bool (DNSResponse::*)>("skipCache", [](const DNSResponse& dq) -> bool { return dq.skipCache; }, [](DNSResponse& dq, bool newSkipCache) { dq.skipCache = newSkipCache; });
  g_lua.registerFunction<void(DNSResponse::*)(std::function<uint32_t(uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl)> editFunc)>("editTTLs", [](const DNSResponse& dr, std::function<uint32_t(uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl)> editFunc) {
        editDNSPacketTTL((char*) dr.dh, dr.len, editFunc);
      });
  g_lua.registerFunction<std::string(DNSResponse::*)(void)>("getTrailingData", [](const DNSResponse& dq) {
      const char* message = reinterpret_cast<const char*>(dq.dh);
      const uint16_t messageLen = getDNSPacketLength(message, dq.len);
      const std::string tail = std::string(message + messageLen, dq.len - messageLen);
      return tail;
    });
  g_lua.registerFunction<bool(DNSResponse::*)(std::string)>("setTrailingData", [](DNSResponse& dq, const std::string& tail) {
      char* message = reinterpret_cast<char*>(dq.dh);
      const uint16_t messageLen = getDNSPacketLength(message, dq.len);
      const uint16_t tailLen = tail.size();
      if(tailLen > (dq.size - messageLen)) {
        return false;
      }

      /* Update length and copy data from the Lua string. */
      dq.len = messageLen + tailLen;
      if(tailLen > 0) {
        tail.copy(message + messageLen, tailLen);
      }
      return true;
    });
  g_lua.registerFunction<void(DNSResponse::*)(std::string)>("sendTrap", [](const DNSResponse& dr, boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
      if (g_snmpAgent && g_snmpTrapsEnabled) {
        g_snmpAgent->sendDNSTrap(dr, reason ? *reason : "");
      }
#endif /* HAVE_NET_SNMP */
    });

#ifdef HAVE_DNS_OVER_HTTPS
    g_lua.registerFunction<std::string(DNSQuestion::*)(void)>("getHTTPPath", [](const DNSQuestion& dq) {
      if (dq.du == nullptr) {
        return std::string();
      }
      return dq.du->getHTTPPath();
    });

    g_lua.registerFunction<std::string(DNSQuestion::*)(void)>("getHTTPQueryString", [](const DNSQuestion& dq) {
      if (dq.du == nullptr) {
        return std::string();
      }
      return dq.du->getHTTPQueryString();
    });

    g_lua.registerFunction<std::string(DNSQuestion::*)(void)>("getHTTPHost", [](const DNSQuestion& dq) {
      if (dq.du == nullptr) {
        return std::string();
      }
      return dq.du->getHTTPHost();
    });

    g_lua.registerFunction<std::string(DNSQuestion::*)(void)>("getHTTPScheme", [](const DNSQuestion& dq) {
      if (dq.du == nullptr) {
        return std::string();
      }
      return dq.du->getHTTPScheme();
    });

    g_lua.registerFunction<std::unordered_map<std::string, std::string>(DNSQuestion::*)(void)>("getHTTPHeaders", [](const DNSQuestion& dq) {
      if (dq.du == nullptr) {
        return std::unordered_map<std::string, std::string>();
      }
      return dq.du->getHTTPHeaders();
    });

    g_lua.registerFunction<void(DNSQuestion::*)(uint16_t statusCode, const std::string& body, const boost::optional<std::string> contentType)>("setHTTPResponse", [](DNSQuestion& dq, uint16_t statusCode, const std::string& body, const boost::optional<std::string> contentType) {
      if (dq.du == nullptr) {
        return;
      }
      dq.du->setHTTPResponse(statusCode, body, contentType ? *contentType : "");
    });
#endif /* HAVE_DNS_OVER_HTTPS */
}
