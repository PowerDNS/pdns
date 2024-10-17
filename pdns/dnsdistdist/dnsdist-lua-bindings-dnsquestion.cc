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
#include "dnsdist-self-answers.hh"
#include "dnsdist-snmp.hh"
#include "dnsparser.hh"

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
void setupLuaBindingsDNSQuestion([[maybe_unused]] LuaContext& luaCtx)
{
#ifndef DISABLE_NON_FFI_DQ_BINDINGS
  /* DNSQuestion */
  /* PowerDNS DNSQuestion compat */
  luaCtx.registerMember<const ComboAddress(DNSQuestion::*)>(
    "localaddr", [](const DNSQuestion& dnsQuestion) -> ComboAddress { return dnsQuestion.ids.origDest; }, [](DNSQuestion& dnsQuestion, const ComboAddress newLocal) { (void)dnsQuestion; (void)newLocal; });
  luaCtx.registerMember<const DNSName(DNSQuestion::*)>(
    "qname", [](const DNSQuestion& dnsQuestion) -> DNSName { return dnsQuestion.ids.qname; }, [](DNSQuestion& dnsQuestion, const DNSName& newName) { (void)dnsQuestion; (void)newName; });
  luaCtx.registerMember<uint16_t(DNSQuestion::*)>(
    "qtype", [](const DNSQuestion& dnsQuestion) -> uint16_t { return dnsQuestion.ids.qtype; }, [](DNSQuestion& dnsQuestion, uint16_t newType) { (void)dnsQuestion; (void)newType; });
  luaCtx.registerMember<uint16_t(DNSQuestion::*)>(
    "qclass", [](const DNSQuestion& dnsQuestion) -> uint16_t { return dnsQuestion.ids.qclass; }, [](DNSQuestion& dnsQuestion, uint16_t newClass) { (void)dnsQuestion;  (void)newClass; });
  luaCtx.registerMember<int(DNSQuestion::*)>(
    "rcode",
    [](const DNSQuestion& dnsQuestion) -> int {
      return static_cast<int>(dnsQuestion.getHeader()->rcode);
    },
    [](DNSQuestion& dnsQuestion, int newRCode) {
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [newRCode](dnsheader& header) {
        header.rcode = static_cast<decltype(header.rcode)>(newRCode);
        return true;
      });
    });
  luaCtx.registerMember<const ComboAddress(DNSQuestion::*)>(
    "remoteaddr", [](const DNSQuestion& dnsQuestion) -> ComboAddress { return dnsQuestion.ids.origRemote; }, [](DNSQuestion& dnsQuestion, const ComboAddress newRemote) { (void)dnsQuestion; (void)newRemote; });
  /* DNSDist DNSQuestion */
  luaCtx.registerMember<dnsheader*(DNSQuestion::*)>(
    "dh",
    [](const DNSQuestion& dnsQuestion) -> dnsheader* {
      return dnsQuestion.getMutableHeader();
    },
    [](DNSQuestion& dnsQuestion, const dnsheader* dnsHeader) {
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [&dnsHeader](dnsheader& header) {
        header = *dnsHeader;
        return true;
      });
    });
  luaCtx.registerMember<uint16_t(DNSQuestion::*)>(
    "len", [](const DNSQuestion& dnsQuestion) -> uint16_t { return dnsQuestion.getData().size(); }, [](DNSQuestion& dnsQuestion, uint16_t newlen) { dnsQuestion.getMutableData().resize(newlen); });
  luaCtx.registerMember<uint8_t(DNSQuestion::*)>(
    "opcode", [](const DNSQuestion& dnsQuestion) -> uint8_t { return dnsQuestion.getHeader()->opcode; }, [](DNSQuestion& dnsQuestion, uint8_t newOpcode) { (void)dnsQuestion; (void)newOpcode; });
  luaCtx.registerMember<bool(DNSQuestion::*)>(
    "tcp", [](const DNSQuestion& dnsQuestion) -> bool { return dnsQuestion.overTCP(); }, [](DNSQuestion& dnsQuestion, bool newTcp) { (void)dnsQuestion; (void)newTcp; });
  luaCtx.registerMember<bool(DNSQuestion::*)>(
    "skipCache", [](const DNSQuestion& dnsQuestion) -> bool { return dnsQuestion.ids.skipCache; }, [](DNSQuestion& dnsQuestion, bool newSkipCache) { dnsQuestion.ids.skipCache = newSkipCache; });
  luaCtx.registerMember<std::string(DNSQuestion::*)>(
    "pool", [](const DNSQuestion& dnsQuestion) -> std::string { return dnsQuestion.ids.poolName; }, [](DNSQuestion& dnsQuestion, const std::string& newPoolName) { dnsQuestion.ids.poolName = newPoolName; });
  luaCtx.registerMember<bool(DNSQuestion::*)>(
    "useECS", [](const DNSQuestion& dnsQuestion) -> bool { return dnsQuestion.useECS; }, [](DNSQuestion& dnsQuestion, bool useECS) { dnsQuestion.useECS = useECS; });
  luaCtx.registerMember<bool(DNSQuestion::*)>(
    "ecsOverride", [](const DNSQuestion& dnsQuestion) -> bool { return dnsQuestion.ecsOverride; }, [](DNSQuestion& dnsQuestion, bool ecsOverride) { dnsQuestion.ecsOverride = ecsOverride; });
  luaCtx.registerMember<uint16_t(DNSQuestion::*)>(
    "ecsPrefixLength", [](const DNSQuestion& dnsQuestion) -> uint16_t { return dnsQuestion.ecsPrefixLength; }, [](DNSQuestion& dnsQuestion, uint16_t newPrefixLength) { dnsQuestion.ecsPrefixLength = newPrefixLength; });
  luaCtx.registerMember<boost::optional<uint32_t>(DNSQuestion::*)>(
    "tempFailureTTL",
    [](const DNSQuestion& dnsQuestion) -> boost::optional<uint32_t> {
      return dnsQuestion.ids.tempFailureTTL;
    },
    [](DNSQuestion& dnsQuestion, boost::optional<uint32_t> newValue) {
      dnsQuestion.ids.tempFailureTTL = newValue;
    });
  luaCtx.registerMember<std::string(DNSQuestion::*)>(
    "deviceID", [](const DNSQuestion& dnsQuestion) -> std::string {
    if (dnsQuestion.ids.d_protoBufData) {
      return dnsQuestion.ids.d_protoBufData->d_deviceID;
    }
    return {}; }, [](DNSQuestion& dnsQuestion, const std::string& newValue) {
    if (!dnsQuestion.ids.d_protoBufData) {
      dnsQuestion.ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    dnsQuestion.ids.d_protoBufData->d_deviceID = newValue; });
  luaCtx.registerMember<std::string(DNSQuestion::*)>(
    "deviceName", [](const DNSQuestion& dnsQuestion) -> std::string {
    if (dnsQuestion.ids.d_protoBufData) {
      return dnsQuestion.ids.d_protoBufData->d_deviceName;
    }
    return {}; }, [](DNSQuestion& dnsQuestion, const std::string& newValue) {
    if (!dnsQuestion.ids.d_protoBufData) {
      dnsQuestion.ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    dnsQuestion.ids.d_protoBufData->d_deviceName = newValue; });
  luaCtx.registerMember<std::string(DNSQuestion::*)>(
    "requestorID", [](const DNSQuestion& dnsQuestion) -> std::string {
    if (dnsQuestion.ids.d_protoBufData) {
      return dnsQuestion.ids.d_protoBufData->d_requestorID;
    }
    return {}; }, [](DNSQuestion& dnsQuestion, const std::string& newValue) {
    if (!dnsQuestion.ids.d_protoBufData) {
      dnsQuestion.ids.d_protoBufData = std::make_unique<InternalQueryState::ProtoBufData>();
    }
    dnsQuestion.ids.d_protoBufData->d_requestorID = newValue; });
  luaCtx.registerFunction<bool (DNSQuestion::*)() const>("getDO", [](const DNSQuestion& dnsQuestion) {
    return dnsdist::getEDNSZ(dnsQuestion) & EDNS_HEADER_FLAG_DO;
  });
  luaCtx.registerFunction<std::string (DNSQuestion::*)() const>("getContent", [](const DNSQuestion& dnsQuestion) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::string(reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size());
  });
  luaCtx.registerFunction<void (DNSQuestion::*)(const std::string&)>("setContent", [](DNSQuestion& dnsQuestion, const std::string& raw) {
    uint16_t oldID = dnsQuestion.getHeader()->id;
    auto& buffer = dnsQuestion.getMutableData();
    buffer.clear();
    buffer.insert(buffer.begin(), raw.begin(), raw.end());

    dnsdist::PacketMangling::editDNSHeaderFromPacket(buffer, [oldID](dnsheader& header) {
      header.id = oldID;
      return true;
    });
  });
  luaCtx.registerFunction<std::map<uint16_t, EDNSOptionView> (DNSQuestion::*)() const>("getEDNSOptions", [](const DNSQuestion& dnsQuestion) {
    if (dnsQuestion.ednsOptions == nullptr) {
      parseEDNSOptions(dnsQuestion);
      if (dnsQuestion.ednsOptions == nullptr) {
        throw std::runtime_error("parseEDNSOptions should have populated the EDNS options");
      }
    }

    return *dnsQuestion.ednsOptions;
  });
  luaCtx.registerFunction<std::string (DNSQuestion::*)(void) const>("getTrailingData", [](const DNSQuestion& dnsQuestion) {
    return dnsQuestion.getTrailingData();
  });
  luaCtx.registerFunction<bool (DNSQuestion::*)(std::string)>("setTrailingData", [](DNSQuestion& dnsQuestion, const std::string& tail) {
    return dnsQuestion.setTrailingData(tail);
  });

  luaCtx.registerFunction<std::string (DNSQuestion::*)() const>("getServerNameIndication", [](const DNSQuestion& dnsQuestion) {
    return dnsQuestion.sni;
  });

  luaCtx.registerFunction<std::string (DNSQuestion::*)() const>("getProtocol", [](const DNSQuestion& dnsQuestion) {
    return dnsQuestion.getProtocol().toPrettyString();
  });

  luaCtx.registerFunction<timespec (DNSQuestion::*)() const>("getQueryTime", [](const DNSQuestion& dnsQuestion) {
    return dnsQuestion.ids.queryRealTime.getStartTime();
  });

  luaCtx.registerFunction<double (DNSQuestion::*)() const>("getElapsedUs", [](const DNSQuestion& dnsQuestion) {
    return dnsQuestion.ids.queryRealTime.udiff();
  });

  luaCtx.registerFunction<void (DNSQuestion::*)(std::string)>("sendTrap", []([[maybe_unused]] const DNSQuestion& dnsQuestion, [[maybe_unused]] boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
    if (g_snmpAgent != nullptr && dnsdist::configuration::getImmutableConfiguration().d_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(dnsQuestion, reason ? *reason : "");
    }
#endif /* HAVE_NET_SNMP */
  });

  luaCtx.registerFunction<void (DNSQuestion::*)(std::string, std::string)>("setTag", [](DNSQuestion& dnsQuestion, const std::string& strLabel, const std::string& strValue) {
    dnsQuestion.setTag(strLabel, strValue);
  });
  luaCtx.registerFunction<void (DNSQuestion::*)(LuaAssociativeTable<std::string>)>("setTagArray", [](DNSQuestion& dnsQuestion, const LuaAssociativeTable<std::string>& tags) {
    for (const auto& tag : tags) {
      dnsQuestion.setTag(tag.first, tag.second);
    }
  });
  luaCtx.registerFunction<string (DNSQuestion::*)(std::string) const>("getTag", [](const DNSQuestion& dnsQuestion, const std::string& strLabel) {
    if (!dnsQuestion.ids.qTag) {
      return string();
    }

    std::string strValue;
    const auto tagIt = dnsQuestion.ids.qTag->find(strLabel);
    if (tagIt == dnsQuestion.ids.qTag->cend()) {
      return string();
    }
    return tagIt->second;
  });
  luaCtx.registerFunction<QTag (DNSQuestion::*)(void) const>("getTagArray", [](const DNSQuestion& dnsQuestion) {
    if (!dnsQuestion.ids.qTag) {
      QTag empty;
      return empty;
    }

    return *dnsQuestion.ids.qTag;
  });

  luaCtx.registerFunction<void (DNSQuestion::*)(LuaArray<std::string>)>("setProxyProtocolValues", [](DNSQuestion& dnsQuestion, const LuaArray<std::string>& values) {
    if (!dnsQuestion.proxyProtocolValues) {
      dnsQuestion.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>();
    }

    dnsQuestion.proxyProtocolValues->clear();
    dnsQuestion.proxyProtocolValues->reserve(values.size());
    for (const auto& value : values) {
      checkParameterBound("setProxyProtocolValues", value.first, std::numeric_limits<uint8_t>::max());
      dnsQuestion.proxyProtocolValues->push_back({value.second, static_cast<uint8_t>(value.first)});
    }
  });

  luaCtx.registerFunction<void (DNSQuestion::*)(uint64_t, std::string)>("addProxyProtocolValue", [](DNSQuestion& dnsQuestion, uint64_t type, std::string value) {
    checkParameterBound("addProxyProtocolValue", type, std::numeric_limits<uint8_t>::max());
    if (!dnsQuestion.proxyProtocolValues) {
      dnsQuestion.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>();
    }

    dnsQuestion.proxyProtocolValues->push_back({std::move(value), static_cast<uint8_t>(type)});
  });

  luaCtx.registerFunction<LuaArray<std::string> (DNSQuestion::*)()>("getProxyProtocolValues", [](const DNSQuestion& dnsQuestion) {
    LuaArray<std::string> result;
    if (!dnsQuestion.proxyProtocolValues) {
      return result;
    }

    result.resize(dnsQuestion.proxyProtocolValues->size());
    for (const auto& value : *dnsQuestion.proxyProtocolValues) {
      result.emplace_back(value.type, value.content);
    }

    return result;
  });

  luaCtx.registerFunction<bool (DNSQuestion::*)(const DNSName& newName)>("changeName", [](DNSQuestion& dnsQuestion, const DNSName& newName) -> bool {
    if (!dnsdist::changeNameInDNSPacket(dnsQuestion.getMutableData(), dnsQuestion.ids.qname, newName)) {
      return false;
    }
    dnsQuestion.ids.qname = newName;
    return true;
  });

  luaCtx.registerFunction<void (DNSQuestion::*)(const boost::variant<LuaArray<ComboAddress>, LuaArray<std::string>>&, boost::optional<uint16_t>)>("spoof", [](DNSQuestion& dnsQuestion, const boost::variant<LuaArray<ComboAddress>, LuaArray<std::string>>& response, boost::optional<uint16_t> typeForAny) {
    dnsdist::ResponseConfig responseConfig;
    if (response.type() == typeid(LuaArray<ComboAddress>)) {
      std::vector<ComboAddress> data;
      auto responses = boost::get<LuaArray<ComboAddress>>(response);
      data.reserve(responses.size());
      for (const auto& resp : responses) {
        data.push_back(resp.second);
      }
      dnsdist::self_answers::generateAnswerFromIPAddresses(dnsQuestion, data, responseConfig);
      return;
    }
    if (response.type() == typeid(LuaArray<std::string>)) {
      std::vector<std::string> data;
      auto responses = boost::get<LuaArray<std::string>>(response);
      data.reserve(responses.size());
      for (const auto& resp : responses) {
        data.push_back(resp.second);
      }
      dnsdist::self_answers::generateAnswerFromRDataEntries(dnsQuestion, data, typeForAny ? *typeForAny : std::optional<uint16_t>(), responseConfig);
      return;
    }
  });

  luaCtx.registerFunction<void (DNSQuestion::*)(uint16_t code, const std::string&)>("setEDNSOption", [](DNSQuestion& dnsQuestion, uint16_t code, const std::string& data) {
    setEDNSOption(dnsQuestion, code, data);
  });

  luaCtx.registerFunction<void (DNSQuestion::*)(uint16_t infoCode, const boost::optional<std::string>& extraText)>("setExtendedDNSError", [](DNSQuestion& dnsQuestion, uint16_t infoCode, const boost::optional<std::string>& extraText) {
    EDNSExtendedError ede;
    ede.infoCode = infoCode;
    if (extraText) {
      ede.extraText = *extraText;
    }
    dnsQuestion.ids.d_extendedError = std::make_unique<EDNSExtendedError>(ede);
  });

  luaCtx.registerFunction<bool (DNSQuestion::*)(uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)>("suspend", [](DNSQuestion& dnsQuestion, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs) {
    dnsQuestion.asynchronous = true;
    return dnsdist::suspendQuery(dnsQuestion, asyncID, queryID, timeoutMs);
  });

  luaCtx.registerFunction<bool (DNSQuestion::*)()>("setRestartable", [](DNSQuestion& dnsQuestion) {
    dnsQuestion.ids.d_packet = std::make_unique<PacketBuffer>(dnsQuestion.getData());
    return true;
  });

  class AsynchronousObject
  {
  public:
    AsynchronousObject(std::unique_ptr<CrossProtocolQuery>&& obj_) :
      object(std::move(obj_))
    {
    }

    [[nodiscard]] DNSQuestion getDQ() const
    {
      return object->getDQ();
    }

    [[nodiscard]] DNSResponse getDR() const
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

      timeval now{};
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

  luaCtx.registerFunction<DNSQuestion (AsynchronousObject::*)(void) const>("getDQ", [](const AsynchronousObject& obj) {
    return obj.getDQ();
  });

  luaCtx.registerFunction<DNSQuestion (AsynchronousObject::*)(void) const>("getDR", [](const AsynchronousObject& obj) {
    return obj.getDR();
  });

  luaCtx.registerFunction<bool (AsynchronousObject::*)(void)>("resume", [](AsynchronousObject& obj) {
    return obj.resume();
  });

  luaCtx.registerFunction<bool (AsynchronousObject::*)(void)>("drop", [](AsynchronousObject& obj) {
    return obj.drop();
  });

  luaCtx.registerFunction<bool (AsynchronousObject::*)(uint8_t, bool)>("setRCode", [](AsynchronousObject& obj, uint8_t rcode, bool clearAnswers) {
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
    return {std::move(query)};
  });

  /* LuaWrapper doesn't support inheritance */
  luaCtx.registerMember<const ComboAddress(DNSResponse::*)>(
    "localaddr", [](const DNSResponse& dnsQuestion) -> ComboAddress { return dnsQuestion.ids.origDest; }, [](DNSResponse& dnsQuestion, const ComboAddress newLocal) { (void)dnsQuestion; (void)newLocal; });
  luaCtx.registerMember<const DNSName(DNSResponse::*)>(
    "qname", [](const DNSResponse& dnsQuestion) -> DNSName { return dnsQuestion.ids.qname; }, [](DNSResponse& dnsQuestion, const DNSName& newName) { (void)dnsQuestion; (void)newName; });
  luaCtx.registerMember<uint16_t(DNSResponse::*)>(
    "qtype", [](const DNSResponse& dnsQuestion) -> uint16_t { return dnsQuestion.ids.qtype; }, [](DNSResponse& dnsQuestion, uint16_t newType) { (void)dnsQuestion; (void)newType; });
  luaCtx.registerMember<uint16_t(DNSResponse::*)>(
    "qclass", [](const DNSResponse& dnsQuestion) -> uint16_t { return dnsQuestion.ids.qclass; }, [](DNSResponse& dnsQuestion, uint16_t newClass) { (void)dnsQuestion; (void)newClass; });
  luaCtx.registerMember<int(DNSResponse::*)>(
    "rcode",
    [](const DNSResponse& dnsQuestion) -> int {
      return static_cast<int>(dnsQuestion.getHeader()->rcode);
    },
    [](DNSResponse& dnsQuestion, int newRCode) {
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [newRCode](dnsheader& header) {
        header.rcode = static_cast<decltype(header.rcode)>(newRCode);
        return true;
      });
    });
  luaCtx.registerMember<ComboAddress(DNSResponse::*)>(
    "remoteaddr", [](const DNSResponse& dnsQuestion) -> ComboAddress { return dnsQuestion.ids.origRemote; }, [](DNSResponse& dnsQuestion, const ComboAddress newRemote) { (void)dnsQuestion; (void)newRemote; });
  luaCtx.registerMember<dnsheader*(DNSResponse::*)>(
    "dh",
    [](const DNSResponse& dnsResponse) -> dnsheader* {
      return dnsResponse.getMutableHeader();
    },
    [](DNSResponse& dnsResponse, const dnsheader* dnsHeader) {
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsResponse.getMutableData(), [&dnsHeader](dnsheader& header) {
        header = *dnsHeader;
        return true;
      });
    });
  luaCtx.registerMember<uint16_t(DNSResponse::*)>(
    "len", [](const DNSResponse& dnsQuestion) -> uint16_t { return dnsQuestion.getData().size(); }, [](DNSResponse& dnsQuestion, uint16_t newlen) { dnsQuestion.getMutableData().resize(newlen); });
  luaCtx.registerMember<uint8_t(DNSResponse::*)>(
    "opcode", [](const DNSResponse& dnsQuestion) -> uint8_t { return dnsQuestion.getHeader()->opcode; }, [](DNSResponse& dnsQuestion, uint8_t newOpcode) { (void)dnsQuestion; (void)newOpcode; });
  luaCtx.registerMember<bool(DNSResponse::*)>(
    "tcp", [](const DNSResponse& dnsQuestion) -> bool { return dnsQuestion.overTCP(); }, [](DNSResponse& dnsQuestion, bool newTcp) { (void)dnsQuestion; (void)newTcp; });
  luaCtx.registerMember<bool(DNSResponse::*)>(
    "skipCache", [](const DNSResponse& dnsQuestion) -> bool { return dnsQuestion.ids.skipCache; }, [](DNSResponse& dnsQuestion, bool newSkipCache) { dnsQuestion.ids.skipCache = newSkipCache; });
  luaCtx.registerMember<std::string(DNSResponse::*)>(
    "pool", [](const DNSResponse& dnsQuestion) -> std::string { return dnsQuestion.ids.poolName; }, [](DNSResponse& dnsQuestion, const std::string& newPoolName) { dnsQuestion.ids.poolName = newPoolName; });
  luaCtx.registerFunction<void (DNSResponse::*)(std::function<uint32_t(uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl)> editFunc)>("editTTLs", [](DNSResponse& dnsResponse, const std::function<uint32_t(uint8_t section, uint16_t qclass, uint16_t qtype, uint32_t ttl)>& editFunc) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    editDNSPacketTTL(reinterpret_cast<char*>(dnsResponse.getMutableData().data()), dnsResponse.getData().size(), editFunc);
  });
  luaCtx.registerFunction<bool (DNSResponse::*)() const>("getDO", [](const DNSResponse& dnsQuestion) {
    return dnsdist::getEDNSZ(dnsQuestion) & EDNS_HEADER_FLAG_DO;
  });
  luaCtx.registerFunction<std::string (DNSResponse::*)() const>("getContent", [](const DNSResponse& dnsQuestion) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return std::string(reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size());
  });
  luaCtx.registerFunction<void (DNSResponse::*)(const std::string&)>("setContent", [](DNSResponse& dnsResponse, const std::string& raw) {
    uint16_t oldID = dnsResponse.getHeader()->id;
    auto& buffer = dnsResponse.getMutableData();
    buffer.clear();
    buffer.insert(buffer.begin(), raw.begin(), raw.end());
    dnsdist::PacketMangling::editDNSHeaderFromPacket(buffer, [oldID](dnsheader& header) {
      header.id = oldID;
      return true;
    });
  });

  luaCtx.registerFunction<std::map<uint16_t, EDNSOptionView> (DNSResponse::*)() const>("getEDNSOptions", [](const DNSResponse& dnsQuestion) {
    if (dnsQuestion.ednsOptions == nullptr) {
      parseEDNSOptions(dnsQuestion);
      if (dnsQuestion.ednsOptions == nullptr) {
        throw std::runtime_error("parseEDNSOptions should have populated the EDNS options");
      }
    }

    return *dnsQuestion.ednsOptions;
  });
  luaCtx.registerFunction<std::string (DNSResponse::*)(void) const>("getTrailingData", [](const DNSResponse& dnsQuestion) {
    return dnsQuestion.getTrailingData();
  });
  luaCtx.registerFunction<bool (DNSResponse::*)(std::string)>("setTrailingData", [](DNSResponse& dnsQuestion, const std::string& tail) {
    return dnsQuestion.setTrailingData(tail);
  });

  luaCtx.registerFunction<void (DNSResponse::*)(std::string, std::string)>("setTag", [](DNSResponse& dnsResponse, const std::string& strLabel, const std::string& strValue) {
    dnsResponse.setTag(strLabel, strValue);
  });

  luaCtx.registerFunction<void (DNSResponse::*)(LuaAssociativeTable<std::string>)>("setTagArray", [](DNSResponse& dnsResponse, const LuaAssociativeTable<string>& tags) {
    for (const auto& tag : tags) {
      dnsResponse.setTag(tag.first, tag.second);
    }
  });
  luaCtx.registerFunction<string (DNSResponse::*)(std::string) const>("getTag", [](const DNSResponse& dnsResponse, const std::string& strLabel) {
    if (!dnsResponse.ids.qTag) {
      return string();
    }

    std::string strValue;
    const auto tagIt = dnsResponse.ids.qTag->find(strLabel);
    if (tagIt == dnsResponse.ids.qTag->cend()) {
      return string();
    }
    return tagIt->second;
  });
  luaCtx.registerFunction<QTag (DNSResponse::*)(void) const>("getTagArray", [](const DNSResponse& dnsResponse) {
    if (!dnsResponse.ids.qTag) {
      QTag empty;
      return empty;
    }

    return *dnsResponse.ids.qTag;
  });

  luaCtx.registerFunction<std::string (DNSResponse::*)() const>("getProtocol", [](const DNSResponse& dnsResponse) {
    return dnsResponse.getProtocol().toPrettyString();
  });

  luaCtx.registerFunction<timespec (DNSResponse::*)() const>("getQueryTime", [](const DNSResponse& dnsResponse) {
    return dnsResponse.ids.queryRealTime.getStartTime();
  });

  luaCtx.registerFunction<double (DNSResponse::*)() const>("getElapsedUs", [](const DNSResponse& dnsResponse) {
    return dnsResponse.ids.queryRealTime.udiff();
  });

  luaCtx.registerFunction<void (DNSResponse::*)(std::string)>("sendTrap", []([[maybe_unused]] const DNSResponse& dnsResponse, [[maybe_unused]] boost::optional<std::string> reason) {
#ifdef HAVE_NET_SNMP
    if (g_snmpAgent != nullptr && dnsdist::configuration::getImmutableConfiguration().d_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(dnsResponse, reason ? *reason : "");
    }
#endif /* HAVE_NET_SNMP */
  });

#if defined(HAVE_DNS_OVER_HTTPS) || defined(HAVE_DNS_OVER_HTTP3)
  luaCtx.registerFunction<std::string (DNSQuestion::*)(void) const>("getHTTPPath", [](const DNSQuestion& dnsQuestion) {
    if (dnsQuestion.ids.du) {
      return dnsQuestion.ids.du->getHTTPPath();
    }
    if (dnsQuestion.ids.doh3u) {
      return dnsQuestion.ids.doh3u->getHTTPPath();
    }
    return std::string();
  });

  luaCtx.registerFunction<std::string (DNSQuestion::*)(void) const>("getHTTPQueryString", [](const DNSQuestion& dnsQuestion) {
    if (dnsQuestion.ids.du) {
      return dnsQuestion.ids.du->getHTTPQueryString();
    }
    if (dnsQuestion.ids.doh3u) {
      return dnsQuestion.ids.doh3u->getHTTPQueryString();
    }
    return std::string();
  });

  luaCtx.registerFunction<std::string (DNSQuestion::*)(void) const>("getHTTPHost", [](const DNSQuestion& dnsQuestion) {
    if (dnsQuestion.ids.du) {
      return dnsQuestion.ids.du->getHTTPHost();
    }
    if (dnsQuestion.ids.doh3u) {
      return dnsQuestion.ids.doh3u->getHTTPHost();
    }
    return std::string();
  });

  luaCtx.registerFunction<std::string (DNSQuestion::*)(void) const>("getHTTPScheme", [](const DNSQuestion& dnsQuestion) {
    if (dnsQuestion.ids.du) {
      return dnsQuestion.ids.du->getHTTPScheme();
    }
    if (dnsQuestion.ids.doh3u) {
      return dnsQuestion.ids.doh3u->getHTTPScheme();
    }
    return std::string();
  });

  luaCtx.registerFunction<LuaAssociativeTable<std::string> (DNSQuestion::*)(void) const>("getHTTPHeaders", [](const DNSQuestion& dnsQuestion) {
    if (dnsQuestion.ids.du) {
      return dnsQuestion.ids.du->getHTTPHeaders();
    }
    if (dnsQuestion.ids.doh3u) {
      return dnsQuestion.ids.doh3u->getHTTPHeaders();
    }
    return LuaAssociativeTable<std::string>();
  });

  luaCtx.registerFunction<void (DNSQuestion::*)(uint64_t statusCode, const std::string& body, const boost::optional<std::string> contentType)>("setHTTPResponse", [](DNSQuestion& dnsQuestion, uint64_t statusCode, const std::string& body, const boost::optional<std::string>& contentType) {
    if (dnsQuestion.ids.du == nullptr && dnsQuestion.ids.doh3u == nullptr) {
      return;
    }
    checkParameterBound("DNSQuestion::setHTTPResponse", statusCode, std::numeric_limits<uint16_t>::max());
    PacketBuffer vect(body.begin(), body.end());
    if (dnsQuestion.ids.du) {
      dnsQuestion.ids.du->setHTTPResponse(statusCode, std::move(vect), contentType ? *contentType : "");
    }
    else {
      dnsQuestion.ids.doh3u->setHTTPResponse(statusCode, std::move(vect), contentType ? *contentType : "");
    }
  });
#endif /* HAVE_DNS_OVER_HTTPS HAVE_DNS_OVER_HTTP3 */

  luaCtx.registerFunction<bool (DNSQuestion::*)(bool nxd, const std::string& zone, uint64_t ttl, const std::string& mname, const std::string& rname, uint64_t serial, uint64_t refresh, uint64_t retry, uint64_t expire, uint64_t minimum)>("setNegativeAndAdditionalSOA", [](DNSQuestion& dnsQuestion, bool nxd, const std::string& zone, uint64_t ttl, const std::string& mname, const std::string& rname, uint64_t serial, uint64_t refresh, uint64_t retry, uint64_t expire, uint64_t minimum) {
    checkParameterBound("setNegativeAndAdditionalSOA", ttl, std::numeric_limits<uint32_t>::max());
    checkParameterBound("setNegativeAndAdditionalSOA", serial, std::numeric_limits<uint32_t>::max());
    checkParameterBound("setNegativeAndAdditionalSOA", refresh, std::numeric_limits<uint32_t>::max());
    checkParameterBound("setNegativeAndAdditionalSOA", retry, std::numeric_limits<uint32_t>::max());
    checkParameterBound("setNegativeAndAdditionalSOA", expire, std::numeric_limits<uint32_t>::max());
    checkParameterBound("setNegativeAndAdditionalSOA", minimum, std::numeric_limits<uint32_t>::max());

    return setNegativeAndAdditionalSOA(dnsQuestion, nxd, DNSName(zone), ttl, DNSName(mname), DNSName(rname), serial, refresh, retry, expire, minimum, false);
  });

  luaCtx.registerFunction<void (DNSResponse::*)(uint16_t infoCode, const boost::optional<std::string>& extraText)>("setExtendedDNSError", [](DNSResponse& dnsResponse, uint16_t infoCode, const boost::optional<std::string>& extraText) {
    EDNSExtendedError ede;
    ede.infoCode = infoCode;
    if (extraText) {
      ede.extraText = *extraText;
    }
    dnsResponse.ids.d_extendedError = std::make_unique<EDNSExtendedError>(ede);
  });

  luaCtx.registerFunction<bool (DNSResponse::*)(uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs)>("suspend", [](DNSResponse& dnsResponse, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs) {
    dnsResponse.asynchronous = true;
    return dnsdist::suspendResponse(dnsResponse, asyncID, queryID, timeoutMs);
  });

  luaCtx.registerFunction<bool (DNSResponse::*)(const DNSName& newName)>("changeName", [](DNSResponse& dnsResponse, const DNSName& newName) -> bool {
    if (!dnsdist::changeNameInDNSPacket(dnsResponse.getMutableData(), dnsResponse.ids.qname, newName)) {
      return false;
    }
    dnsResponse.ids.qname = newName;
    return true;
  });

  luaCtx.registerFunction<bool (DNSResponse::*)()>("restart", [](DNSResponse& dnsResponse) {
    if (!dnsResponse.ids.d_packet) {
      return false;
    }
    dnsResponse.asynchronous = true;
    dnsResponse.getMutableData() = *dnsResponse.ids.d_packet;
    auto query = dnsdist::getInternalQueryFromDQ(dnsResponse, false);
    return dnsdist::queueQueryResumptionEvent(std::move(query));
  });

  luaCtx.registerFunction<std::shared_ptr<DownstreamState> (DNSResponse::*)(void) const>("getSelectedBackend", [](const DNSResponse& dnsResponse) {
    return dnsResponse.d_downstream;
  });
#endif /* DISABLE_NON_FFI_DQ_BINDINGS */
}
