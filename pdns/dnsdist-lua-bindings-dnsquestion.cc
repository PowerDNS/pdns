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
#include "dnsdist-async.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-internal-queries.hh"
#include "dnsdist-lua.hh"
#include "dnsparser.hh"

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
void setupLuaBindingsDNSQuestion(LuaContext& luaCtx)
{
#ifndef DISABLE_NON_FFI_DQ_BINDINGS
  /* DNSQuestion */
  /* PowerDNS DNSQuestion compat */
  luaCtx.registerMember<const ComboAddress (DNSQuestion::*)>("localaddr", [](const DNSQuestion& dq) -> const ComboAddress { return dq.ids.origDest; }, [](DNSQuestion& dq, const ComboAddress newLocal) { (void) newLocal; });
  luaCtx.registerMember<const DNSName (DNSQuestion::*)>("qname", [](const DNSQuestion& dq) -> const DNSName { return dq.ids.qname; }, [](DNSQuestion& dq, const DNSName& newName) { (void) newName; });
  luaCtx.registerMember<uint16_t (DNSQuestion::*)>("qtype", [](const DNSQuestion& dq) -> uint16_t { return dq.ids.qtype; }, [](DNSQuestion& dq, uint16_t newType) { (void) newType; });
  luaCtx.registerMember<uint16_t (DNSQuestion::*)>("qclass", [](const DNSQuestion& dq) -> uint16_t { return dq.ids.qclass; }, [](DNSQuestion& dq, uint16_t newClass) { (void) newClass; });
  luaCtx.registerMember<int (DNSQuestion::*)>("rcode", [](const DNSQuestion& dq) -> int { return static_cast<int>(dq.getHeader()->rcode); }, [](DNSQuestion& dq, int newRCode) {
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dq.getMutableData(), [newRCode](dnsheader& header) {
      header.rcode = static_cast<decltype(header.rcode)>(newRCode);
      return true;
    });
  });
  luaCtx.registerMember<const ComboAddress (DNSQuestion::*)>("remoteaddr", [](const DNSQuestion& dq) -> const ComboAddress { return dq.ids.origRemote; }, [](DNSQuestion& dq, const ComboAddress newRemote) { (void) newRemote; });
  /* DNSDist DNSQuestion */
  luaCtx.registerMember<dnsheader* (DNSQuestion::*)>("dh", [](const DNSQuestion& dq) -> dnsheader* { return dq.getMutableHeader(); }, [](DNSQuestion& dq, const dnsheader* dh) {
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dq.getMutableData(), [&dh](dnsheader& header) {
      header = *dh;
      return true;
    });
  });
  luaCtx.registerMember<uint16_t (DNSQuestion::*)>("len", [](const DNSQuestion& dq) -> uint16_t { return dq.getData().size(); }, [](DNSQuestion& dq, uint16_t newlen) { dq.getMutableData().resize(newlen); });
  luaCtx.registerMember<uint8_t (DNSQuestion::*)>("opcode", [](const DNSQuestion& dq) -> uint8_t { return dq.getHeader()->opcode; }, [](DNSQuestion& dq, uint8_t newOpcode) { (void) newOpcode; });
  luaCtx.registerMember<bool (DNSQuestion::*)>("tcp", [](const DNSQuestion& dq) -> bool { return dq.overTCP(); }, [](DNSQuestion& dq, bool newTcp) { (void) newTcp; });
  luaCtx.registerMember<bool (DNSQuestion::*)>("skipCache", [](const DNSQuestion& dq) -> bool { return dq.ids.skipCache; }, [](DNSQuestion& dq, bool newSkipCache) { dq.ids.skipCache = newSkipCache; });
  luaCtx.registerMember<std::string (DNSQuestion::*)>("pool", [](const DNSQuestion& dq) -> std::string { return dq.ids.poolName; }, [](DNSQuestion& dq, const std::string& newPoolName) { dq.ids.poolName = newPoolName; });
  luaCtx.registerMember<bool (DNSQuestion::*)>("useECS", [](const DNSQuestion& dq) -> bool { return dq.useECS; }, [](DNSQuestion& dq, bool useECS) { dq.useECS = useECS; });
  luaCtx.registerMember<bool (DNSQuestion::*)>("ecsOverride", [](const DNSQuestion& dq) -> bool { return dq.ecsOverride; }, [](DNSQuestion& dq, bool ecsOverride) { dq.ecsOverride = ecsOverride; });
  luaCtx.registerMember<uint16_t (DNSQuestion::*)>("ecsPrefixLength", [](const DNSQuestion& dq) -> uint16_t { return dq.ecsPrefixLength; }, [](DNSQuestion& dq, uint16_t newPrefixLength) { dq.ecsPrefixLength = newPrefixLength; });
  luaCtx.registerMember<boost::optional<uint32_t> (DNSQuestion::*)>("tempFailureTTL",
      [](const DNSQuestion& dq) -> boost::optional<uint32_t> {
        return dq.ids.tempFailureTTL;
      },
      [](DNSQuestion& dq, boost::optional<uint32_t> newValue) {
        dq.ids.tempFailureTTL = newValue;
      }
    );
  luaCtx.registerMember<std::string (DNSQuestion::*)>("deviceID", [](const DNSQuestion& dq) -> std::string {
    if (dq.ids.d_protoBufData) {
      return dq.ids.d_protoBufData->d_deviceID;
    }
    return std::string();
  }, [](DNSQuestion& dq, const std::string& newValue) {
    if (!dq.ids.d_protoBufData) {
      dq.ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    dq.ids.d_protoBufData->d_deviceID = newValue;
  });
  luaCtx.registerMember<std::string (DNSQuestion::*)>("deviceName", [](const DNSQuestion& dq) -> std::string {
    if (dq.ids.d_protoBufData) {
      return dq.ids.d_protoBufData->d_deviceName;
    }
    return std::string();
  }, [](DNSQuestion& dq, const std::string& newValue) {
    if (!dq.ids.d_protoBufData) {
      dq.ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    dq.ids.d_protoBufData->d_deviceName = newValue;
  });
  luaCtx.registerMember<std::string (DNSQuestion::*)>("requestorID", [](const DNSQuestion& dq) -> std::string {
    if (dq.ids.d_protoBufData) {
      return dq.ids.d_protoBufData->d_requestorID;
    }
    return std::string();
  }, [](DNSQuestion& dq, const std::string& newValue) {
    if (!dq.ids.d_protoBufData) {
      dq.ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    dq.ids.d_protoBufData->d_requestorID = newValue;
  });
  luaCtx.registerFunction<bool(DNSQuestion::*)()const>("getDO", [](const DNSQuestion& dq) {
    return getEDNSZ(dq) & EDNS_HEADER_FLAG_DO;
    });
  luaCtx.registerFunction<std::string(DNSQuestion::*)()const>("getContent", [](const DNSQuestion& dq) {
    return std::string(reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size());
  });
  luaCtx.registerFunction<void(DNSQuestion::*)(const std::string&)>("setContent", [](DNSQuestion& dq, const std::string& raw) {
    uint16_t oldID = dq.getHeader()->id;
    auto& buffer = dq.getMutableData();
    buffer.clear();
    buffer.insert(buffer.begin(), raw.begin(), raw.end());

    dnsdist::PacketMangling::editDNSHeaderFromPacket(buffer, [oldID](dnsheader& header) {
      header.id = oldID;
      return true;
    });
  });
  luaCtx.registerFunction<std::map<uint16_t, EDNSOptionView>(DNSQuestion::*)()const>("getEDNSOptions", [](const DNSQuestion& dq) {
      if (dq.ednsOptions == nullptr) {
        parseEDNSOptions(dq);
        if (dq.ednsOptions == nullptr) {
          throw std::runtime_error("parseEDNSOptions should have populated the EDNS options");
        }
      }

      return *dq.ednsOptions;
    });
  luaCtx.registerFunction<std::string(DNSQuestion::*)(void)const>("getTrailingData", [](const DNSQuestion& dq) {
      return dq.getTrailingData();
    });
  luaCtx.registerFunction<bool(DNSQuestion::*)(std::string)>("setTrailingData", [](DNSQuestion& dq, const std::string& tail) {
      return dq.setTrailingData(tail);
    });

  luaCtx.registerFunction<std::string(DNSQuestion::*)()const>("getServerNameIndication", [](const DNSQuestion& dq) {
      return dq.sni;
    });

  luaCtx.registerFunction<std::string (DNSQuestion::*)() const>("getIncomingInterface", [](const DNSQuestion& dnsQuestion) -> std::string {
    if (dnsQuestion.ids.cs != nullptr) {
      return dnsQuestion.ids.cs->interface;
    }
    return {};
  });

  luaCtx.registerFunction<std::string (DNSQuestion::*)()const>("getProtocol", [](const DNSQuestion& dq) {
    return dq.getProtocol().toPrettyString();
  });

  luaCtx.registerFunction<timespec(DNSQuestion::*)()const>("getQueryTime", [](const DNSQuestion& dq) {
    return dq.ids.queryRealTime.getStartTime();
  });

  luaCtx.registerFunction<double (DNSQuestion::*)() const>("getElapsedUs", [](const DNSQuestion& dnsQuestion) {
    return dnsQuestion.ids.queryRealTime.udiff();
  });

  luaCtx.registerFunction<void(DNSQuestion::*)(std::string)>("sendTrap", [](const DNSQuestion& dq, boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
      if (g_snmpAgent && g_snmpTrapsEnabled) {
        g_snmpAgent->sendDNSTrap(dq, reason ? *reason : "");
      }
#endif /* HAVE_NET_SNMP */
    });

  luaCtx.registerFunction<void(DNSQuestion::*)(std::string, std::string)>("setTag", [](DNSQuestion& dq, const std::string& strLabel, const std::string& strValue) {
      dq.setTag(strLabel, strValue);
    });
  luaCtx.registerFunction<void(DNSQuestion::*)(LuaAssociativeTable<std::string>)>("setTagArray", [](DNSQuestion& dq, const LuaAssociativeTable<std::string>&tags) {
      for (const auto& tag : tags) {
        dq.setTag(tag.first, tag.second);
      }
    });
  luaCtx.registerFunction<string(DNSQuestion::*)(std::string)const>("getTag", [](const DNSQuestion& dq, const std::string& strLabel) {
      if (!dq.ids.qTag) {
        return string();
      }

      std::string strValue;
      const auto it = dq.ids.qTag->find(strLabel);
      if (it == dq.ids.qTag->cend()) {
        return string();
      }
      return it->second;
    });
  luaCtx.registerFunction<QTag(DNSQuestion::*)(void)const>("getTagArray", [](const DNSQuestion& dq) {
      if (!dq.ids.qTag) {
        QTag empty;
        return empty;
      }

      return *dq.ids.qTag;
    });

  luaCtx.registerFunction<void(DNSQuestion::*)(LuaArray<std::string>)>("setProxyProtocolValues", [](DNSQuestion& dq, const LuaArray<std::string>& values) {
    if (!dq.proxyProtocolValues) {
      dq.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>();
    }

    dq.proxyProtocolValues->clear();
    dq.proxyProtocolValues->reserve(values.size());
    for (const auto& value : values) {
      checkParameterBound("setProxyProtocolValues", value.first, std::numeric_limits<uint8_t>::max());
      dq.proxyProtocolValues->push_back({value.second, static_cast<uint8_t>(value.first)});
    }
  });

  luaCtx.registerFunction<void(DNSQuestion::*)(uint64_t, std::string)>("addProxyProtocolValue", [](DNSQuestion& dq, uint64_t type, std::string value) {
    checkParameterBound("addProxyProtocolValue", type, std::numeric_limits<uint8_t>::max());
    if (!dq.proxyProtocolValues) {
      dq.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>();
    }

    dq.proxyProtocolValues->push_back({std::move(value), static_cast<uint8_t>(type)});
  });

  luaCtx.registerFunction<LuaArray<std::string>(DNSQuestion::*)()>("getProxyProtocolValues", [](const DNSQuestion& dq) {
    LuaArray<std::string> result;
    if (!dq.proxyProtocolValues) {
      return result;
    }

    result.resize(dq.proxyProtocolValues->size());
    for (const auto& value : *dq.proxyProtocolValues) {
      result.push_back({ value.type, value.content });
    }

    return result;
  });

  luaCtx.registerFunction<bool(DNSQuestion::*)(const DNSName& newName)>("changeName", [](DNSQuestion& dq, const DNSName& newName) -> bool {
    if (!dnsdist::changeNameInDNSPacket(dq.getMutableData(), dq.ids.qname, newName)) {
      return false;
    }
    dq.ids.qname = newName;
    return true;
  });

  luaCtx.registerFunction<void(DNSQuestion::*)(const boost::variant<LuaArray<ComboAddress>, LuaArray<std::string>>&, boost::optional<uint16_t>)>("spoof", [](DNSQuestion& dnsQuestion, const boost::variant<LuaArray<ComboAddress>, LuaArray<std::string>>& response, boost::optional<uint16_t> typeForAny) {
      if (response.type() == typeid(LuaArray<ComboAddress>)) {
          std::vector<ComboAddress> data;
          auto responses = boost::get<LuaArray<ComboAddress>>(response);
          data.reserve(responses.size());
          for (const auto& resp : responses) {
            data.push_back(resp.second);
          }
          std::string result;
          SpoofAction tempSpoofAction(data);
          tempSpoofAction(&dnsQuestion, &result);
	  return;
      }
      if (response.type() == typeid(LuaArray<std::string>)) {
          std::vector<std::string> data;
          auto responses = boost::get<LuaArray<std::string>>(response);
          data.reserve(responses.size());
          for (const auto& resp : responses) {
            data.push_back(resp.second);
          }
          std::string result;
          SpoofAction tempSpoofAction(data, typeForAny ? *typeForAny : std::optional<uint16_t>());
          tempSpoofAction(&dnsQuestion, &result);
	  return;
      }
  });

  luaCtx.registerFunction<void(DNSQuestion::*)(uint16_t code, const std::string&)>("setEDNSOption", [](DNSQuestion& dq, uint16_t code, const std::string& data) {
    setEDNSOption(dq, code, data);
  });

  luaCtx.registerFunction<void(DNSQuestion::*)(uint16_t infoCode, const boost::optional<std::string>& extraText)>("setExtendedDNSError", [](DNSQuestion& dnsQuestion, uint16_t infoCode, const boost::optional<std::string>& extraText) {
    EDNSExtendedError ede;
    ede.infoCode = infoCode;
    if (extraText) {
      ede.extraText = *extraText;
    }
    dnsQuestion.ids.d_extendedError = std::make_unique<EDNSExtendedError>(ede);
  });

  luaCtx.registerFunction<bool(DNSQuestion::*)(uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)>("suspend", [](DNSQuestion& dq, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs) {
    dq.asynchronous = true;
    return dnsdist::suspendQuery(dq, asyncID, queryID, timeoutMs);
  });

  luaCtx.registerFunction<bool(DNSQuestion::*)()>("setRestartable", [](DNSQuestion& dq) {
    dq.ids.d_packet = std::make_unique<PacketBuffer>(dq.getData());
    return true;
  });

class AsynchronousObject
{
public:
  AsynchronousObject(std::unique_ptr<CrossProtocolQuery>&& obj_): object(std::move(obj_))
  {
  }

  DNSQuestion getDQ() const
  {
    return object->getDQ();
  }

  DNSResponse getDR() const
  {
    return object->getDR();
  }

  bool resume()
  {
    return dnsdist::queueQueryResumptionEvent(std::move(object));
  }

  bool drop()
  {
    auto sender = object->getTCPQuerySender();
    if (!sender) {
      return false;
    }

    struct timeval now;
    gettimeofday(&now, nullptr);
    sender->notifyIOError(now, TCPResponse(std::move(object->query)));
    return true;
  }

  bool setRCode(uint8_t rcode, bool clearAnswers)
  {
    return dnsdist::setInternalQueryRCode(object->query.d_idstate, object->query.d_buffer, rcode, clearAnswers);
  }

private:
  std::unique_ptr<CrossProtocolQuery> object;
};

  luaCtx.registerFunction<DNSQuestion(AsynchronousObject::*)(void) const>("getDQ", [](const AsynchronousObject& obj) {
      return obj.getDQ();
    });

  luaCtx.registerFunction<DNSQuestion(AsynchronousObject::*)(void) const>("getDR", [](const AsynchronousObject& obj) {
      return obj.getDR();
    });

  luaCtx.registerFunction<bool(AsynchronousObject::*)(void)>("resume", [](AsynchronousObject& obj) {
      return obj.resume();
    });

  luaCtx.registerFunction<bool(AsynchronousObject::*)(void)>("drop", [](AsynchronousObject& obj) {
      return obj.drop();
    });

  luaCtx.registerFunction<bool(AsynchronousObject::*)(uint8_t, bool)>("setRCode", [](AsynchronousObject& obj, uint8_t rcode, bool clearAnswers) {
    return obj.setRCode(rcode, clearAnswers);
  });

  luaCtx.writeFunction("getAsynchronousObject", [](uint16_t asyncID, uint16_t queryID) -> AsynchronousObject {
    if (!dnsdist::g_asyncHolder) {
      throw std::runtime_error("Unable to resume, no asynchronous holder");
    }
    auto query = dnsdist::g_asyncHolder->get(asyncID, queryID);
    if (!query) {
      throw std::runtime_error("Unable to find asynchronous object");
    }
    return AsynchronousObject(std::move(query));
  });

  /* LuaWrapper doesn't support inheritance */
  luaCtx.registerMember<const ComboAddress (DNSResponse::*)>("localaddr", [](const DNSResponse& dq) -> const ComboAddress { return dq.ids.origDest; }, [](DNSResponse& dq, const ComboAddress newLocal) { (void) newLocal; });
  luaCtx.registerMember<const DNSName (DNSResponse::*)>("qname", [](const DNSResponse& dq) -> const DNSName { return dq.ids.qname; }, [](DNSResponse& dq, const DNSName& newName) { (void) newName; });
  luaCtx.registerMember<uint16_t (DNSResponse::*)>("qtype", [](const DNSResponse& dq) -> uint16_t { return dq.ids.qtype; }, [](DNSResponse& dq, uint16_t newType) { (void) newType; });
  luaCtx.registerMember<uint16_t (DNSResponse::*)>("qclass", [](const DNSResponse& dq) -> uint16_t { return dq.ids.qclass; }, [](DNSResponse& dq, uint16_t newClass) { (void) newClass; });
  luaCtx.registerMember<int (DNSResponse::*)>("rcode", [](const DNSResponse& dq) -> int { return static_cast<int>(dq.getHeader()->rcode); }, [](DNSResponse& dq, int newRCode) {
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dq.getMutableData(), [newRCode](dnsheader& header) {
      header.rcode = static_cast<decltype(header.rcode)>(newRCode);
      return true;
    });
  });
  luaCtx.registerMember<const ComboAddress (DNSResponse::*)>("remoteaddr", [](const DNSResponse& dq) -> const ComboAddress { return dq.ids.origRemote; }, [](DNSResponse& dq, const ComboAddress newRemote) { (void) newRemote; });
  luaCtx.registerMember<dnsheader* (DNSResponse::*)>("dh", [](const DNSResponse& dr) -> dnsheader* { return dr.getMutableHeader(); }, [](DNSResponse& dr, const dnsheader* dh) {
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dr.getMutableData(), [&dh](dnsheader& header) {
      header = *dh;
      return true;
    });
  });
  luaCtx.registerMember<uint16_t (DNSResponse::*)>("len", [](const DNSResponse& dq) -> uint16_t { return dq.getData().size(); }, [](DNSResponse& dq, uint16_t newlen) { dq.getMutableData().resize(newlen); });
  luaCtx.registerMember<uint8_t (DNSResponse::*)>("opcode", [](const DNSResponse& dq) -> uint8_t { return dq.getHeader()->opcode; }, [](DNSResponse& dq, uint8_t newOpcode) { (void) newOpcode; });
  luaCtx.registerMember<bool (DNSResponse::*)>("tcp", [](const DNSResponse& dq) -> bool { return dq.overTCP(); }, [](DNSResponse& dq, bool newTcp) { (void) newTcp; });
  luaCtx.registerMember<bool (DNSResponse::*)>("skipCache", [](const DNSResponse& dq) -> bool { return dq.ids.skipCache; }, [](DNSResponse& dq, bool newSkipCache) { dq.ids.skipCache = newSkipCache; });
  luaCtx.registerMember<std::string (DNSResponse::*)>("pool", [](const DNSResponse& dq) -> std::string { return dq.ids.poolName; }, [](DNSResponse& dq, const std::string& newPoolName) { dq.ids.poolName = newPoolName; });
  luaCtx.registerFunction<void(DNSResponse::*)(std::function<uint32_t(uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl)> editFunc)>("editTTLs", [](DNSResponse& dr, std::function<uint32_t(uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl)> editFunc) {
    editDNSPacketTTL(reinterpret_cast<char *>(dr.getMutableData().data()), dr.getData().size(), editFunc);
      });
  luaCtx.registerFunction<bool(DNSResponse::*)()const>("getDO", [](const DNSResponse& dq) {
      return getEDNSZ(dq) & EDNS_HEADER_FLAG_DO;
    });
  luaCtx.registerFunction<std::string(DNSResponse::*)()const>("getContent", [](const DNSResponse& dq) {
    return std::string(reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size());
  });
  luaCtx.registerFunction<void(DNSResponse::*)(const std::string&)>("setContent", [](DNSResponse& dr, const std::string& raw) {
    uint16_t oldID = dr.getHeader()->id;
    auto& buffer = dr.getMutableData();
    buffer.clear();
    buffer.insert(buffer.begin(), raw.begin(), raw.end());
    dnsdist::PacketMangling::editDNSHeaderFromPacket(buffer, [oldID](dnsheader& header) {
      header.id = oldID;
      return true;
    });
  });

  luaCtx.registerFunction<std::map<uint16_t, EDNSOptionView>(DNSResponse::*)()const>("getEDNSOptions", [](const DNSResponse& dq) {
      if (dq.ednsOptions == nullptr) {
        parseEDNSOptions(dq);
        if (dq.ednsOptions == nullptr) {
          throw std::runtime_error("parseEDNSOptions should have populated the EDNS options");
        }
      }

      return *dq.ednsOptions;
    });
  luaCtx.registerFunction<std::string(DNSResponse::*)(void)const>("getTrailingData", [](const DNSResponse& dq) {
      return dq.getTrailingData();
    });
  luaCtx.registerFunction<bool(DNSResponse::*)(std::string)>("setTrailingData", [](DNSResponse& dq, const std::string& tail) {
      return dq.setTrailingData(tail);
    });

  luaCtx.registerFunction<void(DNSResponse::*)(std::string, std::string)>("setTag", [](DNSResponse& dr, const std::string& strLabel, const std::string& strValue) {
      dr.setTag(strLabel, strValue);
    });

  luaCtx.registerFunction<void(DNSResponse::*)(LuaAssociativeTable<std::string>)>("setTagArray", [](DNSResponse& dr, const LuaAssociativeTable<string>&tags) {
      for (const auto& tag : tags) {
        dr.setTag(tag.first, tag.second);
      }
    });
  luaCtx.registerFunction<string(DNSResponse::*)(std::string)const>("getTag", [](const DNSResponse& dr, const std::string& strLabel) {
      if (!dr.ids.qTag) {
        return string();
      }

      std::string strValue;
      const auto it = dr.ids.qTag->find(strLabel);
      if (it == dr.ids.qTag->cend()) {
        return string();
      }
      return it->second;
    });
  luaCtx.registerFunction<QTag(DNSResponse::*)(void)const>("getTagArray", [](const DNSResponse& dr) {
      if (!dr.ids.qTag) {
        QTag empty;
        return empty;
      }

      return *dr.ids.qTag;
    });

  luaCtx.registerFunction<std::string (DNSResponse::*)()const>("getProtocol", [](const DNSResponse& dr) {
    return dr.getProtocol().toPrettyString();
  });

  luaCtx.registerFunction<timespec(DNSResponse::*)()const>("getQueryTime", [](const DNSResponse& dr) {
    return dr.ids.queryRealTime.getStartTime();
  });

  luaCtx.registerFunction<double (DNSResponse::*)() const>("getElapsedUs", [](const DNSResponse& dnsResponse) {
    return dnsResponse.ids.queryRealTime.udiff();
  });

  luaCtx.registerFunction<std::string (DNSResponse::*)() const>("getIncomingInterface", [](const DNSResponse& dnsResponse) -> std::string {
    if (dnsResponse.ids.cs != nullptr) {
      return dnsResponse.ids.cs->interface;
    }
    return {};
  });

  luaCtx.registerFunction<void(DNSResponse::*)(std::string)>("sendTrap", [](const DNSResponse& dr, boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
      if (g_snmpAgent && g_snmpTrapsEnabled) {
        g_snmpAgent->sendDNSTrap(dr, reason ? *reason : "");
      }
#endif /* HAVE_NET_SNMP */
    });

#ifdef HAVE_DNS_OVER_HTTPS
    luaCtx.registerFunction<std::string(DNSQuestion::*)(void)const>("getHTTPPath", [](const DNSQuestion& dq) {
      if (dq.ids.du == nullptr) {
        return std::string();
      }
      return dq.ids.du->getHTTPPath();
    });

    luaCtx.registerFunction<std::string(DNSQuestion::*)(void)const>("getHTTPQueryString", [](const DNSQuestion& dq) {
      if (dq.ids.du == nullptr) {
        return std::string();
      }
      return dq.ids.du->getHTTPQueryString();
    });

    luaCtx.registerFunction<std::string(DNSQuestion::*)(void)const>("getHTTPHost", [](const DNSQuestion& dq) {
      if (dq.ids.du == nullptr) {
        return std::string();
      }
      return dq.ids.du->getHTTPHost();
    });

    luaCtx.registerFunction<std::string(DNSQuestion::*)(void)const>("getHTTPScheme", [](const DNSQuestion& dq) {
      if (dq.ids.du == nullptr) {
        return std::string();
      }
      return dq.ids.du->getHTTPScheme();
    });

    luaCtx.registerFunction<LuaAssociativeTable<std::string>(DNSQuestion::*)(void)const>("getHTTPHeaders", [](const DNSQuestion& dq) {
      if (dq.ids.du == nullptr) {
        return LuaAssociativeTable<std::string>();
      }
      return dq.ids.du->getHTTPHeaders();
    });

    luaCtx.registerFunction<void(DNSQuestion::*)(uint64_t statusCode, const std::string& body, const boost::optional<std::string> contentType)>("setHTTPResponse", [](DNSQuestion& dq, uint64_t statusCode, const std::string& body, const boost::optional<std::string> contentType) {
      if (dq.ids.du == nullptr) {
        return;
      }
      checkParameterBound("DNSQuestion::setHTTPResponse", statusCode, std::numeric_limits<uint16_t>::max());
      PacketBuffer vect(body.begin(), body.end());
      dq.ids.du->setHTTPResponse(statusCode, std::move(vect), contentType ? *contentType : "");
    });
#endif /* HAVE_DNS_OVER_HTTPS */

  luaCtx.registerFunction<bool(DNSQuestion::*)(bool nxd, const std::string& zone, uint64_t ttl, const std::string& mname, const std::string& rname, uint64_t serial, uint64_t refresh, uint64_t retry, uint64_t expire, uint64_t minimum)>("setNegativeAndAdditionalSOA", [](DNSQuestion& dq, bool nxd, const std::string& zone, uint64_t ttl, const std::string& mname, const std::string& rname, uint64_t serial, uint64_t refresh, uint64_t retry, uint64_t expire, uint64_t minimum) {
      checkParameterBound("setNegativeAndAdditionalSOA", ttl, std::numeric_limits<uint32_t>::max());
      checkParameterBound("setNegativeAndAdditionalSOA", serial, std::numeric_limits<uint32_t>::max());
      checkParameterBound("setNegativeAndAdditionalSOA", refresh, std::numeric_limits<uint32_t>::max());
      checkParameterBound("setNegativeAndAdditionalSOA", retry, std::numeric_limits<uint32_t>::max());
      checkParameterBound("setNegativeAndAdditionalSOA", expire, std::numeric_limits<uint32_t>::max());
      checkParameterBound("setNegativeAndAdditionalSOA", minimum, std::numeric_limits<uint32_t>::max());

      return setNegativeAndAdditionalSOA(dq, nxd, DNSName(zone), ttl, DNSName(mname), DNSName(rname), serial, refresh, retry, expire, minimum, false);
    });

  luaCtx.registerFunction<void(DNSResponse::*)(uint16_t infoCode, const boost::optional<std::string>& extraText)>("setExtendedDNSError", [](DNSResponse& dnsResponse, uint16_t infoCode, const boost::optional<std::string>& extraText) {
    EDNSExtendedError ede;
    ede.infoCode = infoCode;
    if (extraText) {
      ede.extraText = *extraText;
    }
    dnsResponse.ids.d_extendedError = std::make_unique<EDNSExtendedError>(ede);
  });

  luaCtx.registerFunction<bool(DNSResponse::*)(uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)>("suspend", [](DNSResponse& dr, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs) {
    dr.asynchronous = true;
    return dnsdist::suspendResponse(dr, asyncID, queryID, timeoutMs);
  });

  luaCtx.registerFunction<bool(DNSResponse::*)(const DNSName& newName)>("changeName", [](DNSResponse& dr, const DNSName& newName) -> bool {
    if (!dnsdist::changeNameInDNSPacket(dr.getMutableData(), dr.ids.qname, newName)) {
      return false;
    }
    dr.ids.qname = newName;
    return true;
  });

  luaCtx.registerFunction<bool(DNSResponse::*)()>("restart", [](DNSResponse& dr) {
    if (!dr.ids.d_packet) {
      return false;
    }
    dr.asynchronous = true;
    dr.getMutableData() = *dr.ids.d_packet;
    auto query = dnsdist::getInternalQueryFromDQ(dr, false);
    return dnsdist::queueQueryResumptionEvent(std::move(query));
  });

  luaCtx.registerFunction<std::shared_ptr<DownstreamState>(DNSResponse::*)(void)const>("getSelectedBackend", [](const DNSResponse& dr) {
    return dr.d_downstream;
  });
#endif /* DISABLE_NON_FFI_DQ_BINDINGS */
}
