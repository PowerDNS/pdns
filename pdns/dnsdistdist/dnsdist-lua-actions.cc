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
#include "dnsdist-actions-factory.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-protobuf.hh"
#include "dnsdist-rule-chains.hh"
#include "dnstap.hh"
#include "remote_logger.hh"
#include <stdexcept>

using responseParams_t = std::unordered_map<std::string, boost::variant<bool, uint32_t>>;

static dnsdist::ResponseConfig parseResponseConfig(std::optional<responseParams_t>& vars)
{
  dnsdist::ResponseConfig config;
  getOptionalValue<uint32_t>(vars, "ttl", config.ttl);
  getOptionalValue<bool>(vars, "aa", config.setAA);
  getOptionalValue<bool>(vars, "ad", config.setAD);
  getOptionalValue<bool>(vars, "ra", config.setRA);
  return config;
}

template <class T>
static std::vector<T> convertLuaArrayToRegular(const LuaArray<T>& luaArray)
{
  std::vector<T> out;
  out.reserve(luaArray.size());
  for (const auto& entry : luaArray) {
    out.emplace_back(entry.second);
  }
  return out;
}

template <class T>
std::optional<T> boostToStandardOptional(const std::optional<T>& boostOpt)
{
  return boostOpt ? *boostOpt : std::optional<T>();
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
void setupLuaActions(LuaContext& luaCtx)
{
  luaCtx.writeFunction("newRuleAction", [](const luadnsrule_t& dnsrule, std::shared_ptr<DNSAction> action, std::optional<luaruleparams_t> params) {
    boost::uuids::uuid uuid{};
    uint64_t creationOrder = 0;
    std::string name;
    parseRuleParams(params, uuid, name, creationOrder);
    checkAllParametersConsumed("newRuleAction", params);

    auto rule = makeRule(dnsrule, "newRuleAction");
    dnsdist::rules::RuleAction ruleaction({std::move(rule), std::move(action), std::move(name), uuid, creationOrder});
    return std::make_shared<dnsdist::rules::RuleAction>(ruleaction);
  });

  luaCtx.registerFunction<void (DNSAction::*)() const>("printStats", [](const DNSAction& action) {
    setLuaNoSideEffect();
    auto stats = action.getStats();
    for (const auto& stat : stats) {
      g_outputBuffer += stat.first + "\t";
      double integral = 0;
      if (std::modf(stat.second, &integral) == 0.0 && stat.second < static_cast<double>(std::numeric_limits<uint64_t>::max())) {
        g_outputBuffer += std::to_string(static_cast<uint64_t>(stat.second)) + "\n";
      }
      else {
        g_outputBuffer += std::to_string(stat.second) + "\n";
      }
    }
  });

  luaCtx.registerFunction("getStats", &DNSAction::getStats);
  luaCtx.registerFunction("reload", &DNSAction::reload);
  luaCtx.registerFunction("reload", &DNSResponseAction::reload);

  luaCtx.writeFunction("LuaAction", [](dnsdist::actions::LuaActionFunction function) {
    return dnsdist::actions::getLuaAction(std::move(function));
  });

  luaCtx.writeFunction("LuaFFIAction", [](dnsdist::actions::LuaActionFFIFunction function) {
    return dnsdist::actions::getLuaFFIAction(std::move(function));
  });

  luaCtx.writeFunction("LuaResponseAction", [](dnsdist::actions::LuaResponseActionFunction function) {
    return dnsdist::actions::getLuaResponseAction(std::move(function));
  });

  luaCtx.writeFunction("LuaFFIResponseAction", [](dnsdist::actions::LuaResponseActionFFIFunction function) {
    return dnsdist::actions::getLuaFFIResponseAction(std::move(function));
  });

  luaCtx.writeFunction("SpoofAction", [](LuaTypeOrArrayOf<std::string> inp, std::optional<responseParams_t> vars) {
    vector<ComboAddress> addrs;
    if (auto* ipaddr = boost::get<std::string>(&inp)) {
      addrs.emplace_back(*ipaddr);
    }
    else {
      const auto& ipsArray = boost::get<LuaArray<std::string>>(inp);
      for (const auto& ipAddr : ipsArray) {
        addrs.emplace_back(ipAddr.second);
      }
    }

    auto responseConfig = parseResponseConfig(vars);
    checkAllParametersConsumed("SpoofAction", vars);
    auto ret = dnsdist::actions::getSpoofAction(addrs, responseConfig);
    return ret;
  });

  luaCtx.writeFunction("SpoofSVCAction", [](const LuaArray<SVCRecordParameters>& parameters, std::optional<responseParams_t> vars) {
    auto responseConfig = parseResponseConfig(vars);
    checkAllParametersConsumed("SpoofAction", vars);
    auto svcParams = convertLuaArrayToRegular(parameters);
    auto ret = dnsdist::actions::getSpoofSVCAction(svcParams, responseConfig);
    return ret;
  });

  luaCtx.writeFunction("SpoofCNAMEAction", [](const std::string& cname, std::optional<responseParams_t> vars) {
    auto responseConfig = parseResponseConfig(vars);
    checkAllParametersConsumed("SpoofCNAMEAction", vars);
    auto ret = dnsdist::actions::getSpoofAction(DNSName(cname), responseConfig);
    return ret;
  });

  luaCtx.writeFunction("SpoofRawAction", [](LuaTypeOrArrayOf<std::string> inp, std::optional<responseParams_t> vars) {
    vector<string> raws;
    if (const auto* str = boost::get<std::string>(&inp)) {
      raws.push_back(*str);
    }
    else {
      const auto& vect = boost::get<LuaArray<std::string>>(inp);
      for (const auto& raw : vect) {
        raws.push_back(raw.second);
      }
    }
    uint32_t qtypeForAny{0};
    getOptionalValue<uint32_t>(vars, "typeForAny", qtypeForAny);
    if (qtypeForAny > std::numeric_limits<uint16_t>::max()) {
      qtypeForAny = 0;
    }
    std::optional<uint16_t> qtypeForAnyParam;
    if (qtypeForAny > 0) {
      qtypeForAnyParam = static_cast<uint16_t>(qtypeForAny);
    }
    auto responseConfig = parseResponseConfig(vars);
    checkAllParametersConsumed("SpoofRawAction", vars);
    auto ret = dnsdist::actions::getSpoofAction(raws, qtypeForAnyParam, responseConfig);
    return ret;
  });

  luaCtx.writeFunction("SpoofPacketAction", [](const std::string& response, size_t len) {
    if (len < sizeof(dnsheader)) {
      throw std::runtime_error(std::string("SpoofPacketAction: given packet len is too small"));
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    auto ret = dnsdist::actions::getSpoofAction(PacketBuffer(response.data(), response.data() + len));
    return ret;
  });

  luaCtx.writeFunction("LimitTTLResponseAction", [](uint32_t min, uint32_t max, std::optional<LuaArray<uint16_t>> types) {
    std::unordered_set<QType> capTypes;
    if (types) {
      capTypes.reserve(types->size());
      for (const auto& [idx, type] : *types) {
        capTypes.insert(QType(type));
      }
    }
    return dnsdist::actions::getLimitTTLResponseAction(min, max, std::move(capTypes));
  });

  luaCtx.writeFunction("SetMinTTLResponseAction", [](uint32_t min) {
    return dnsdist::actions::getLimitTTLResponseAction(min);
  });

  luaCtx.writeFunction("SetMaxTTLResponseAction", [](uint32_t max) {
    return dnsdist::actions::getLimitTTLResponseAction(0, max);
  });

  luaCtx.writeFunction("SetMaxReturnedTTLAction", [](uint32_t max) {
    return dnsdist::actions::getSetMaxReturnedTTLAction(max);
  });

  luaCtx.writeFunction("SetMaxReturnedTTLResponseAction", [](uint32_t max) {
    return dnsdist::actions::getSetMaxReturnedTTLResponseAction(max);
  });

  luaCtx.writeFunction("SetReducedTTLResponseAction", [](uint8_t percentage) {
    if (percentage > 100) {
      throw std::runtime_error(std::string("SetReducedTTLResponseAction takes a percentage between 0 and 100."));
    }
    return dnsdist::actions::getSetReducedTTLResponseAction(percentage);
  });

  luaCtx.writeFunction("ClearRecordTypesResponseAction", [](LuaTypeOrArrayOf<int> types) {
    std::unordered_set<QType> qtypes{};
    if (types.type() == typeid(int)) {
      qtypes.insert(boost::get<int>(types));
    }
    else if (types.type() == typeid(LuaArray<int>)) {
      const auto& typesArray = boost::get<LuaArray<int>>(types);
      for (const auto& tpair : typesArray) {
        qtypes.insert(tpair.second);
      }
    }
    return dnsdist::actions::getClearRecordTypesResponseAction(std::move(qtypes));
  });

  luaCtx.writeFunction("RCodeAction", [](uint8_t rcode, std::optional<responseParams_t> vars) {
    auto responseConfig = parseResponseConfig(vars);
    checkAllParametersConsumed("RCodeAction", vars);
    auto ret = dnsdist::actions::getRCodeAction(rcode, responseConfig);
    return ret;
  });

  luaCtx.writeFunction("ERCodeAction", [](uint8_t rcode, std::optional<responseParams_t> vars) {
    auto responseConfig = parseResponseConfig(vars);
    checkAllParametersConsumed("ERCodeAction", vars);
    auto ret = dnsdist::actions::getERCodeAction(rcode, responseConfig);
    return ret;
  });

#ifndef DISABLE_PROTOBUF
  // Used for both RemoteLogAction and RemoteLogResponseAction
  static const std::array<std::string, 2> s_validIpEncryptMethods = {"legacy", "ipcrypt-pfx"};

  luaCtx.writeFunction("RemoteLogAction", [](std::shared_ptr<RemoteLoggerInterface> logger, std::optional<dnsdist::actions::ProtobufAlterFunction> alterFunc, std::optional<LuaAssociativeTable<std::string>> vars, std::optional<LuaAssociativeTable<std::string>> metas) {
    if (logger) {
      // avoids potentially-evaluated-expression warning with clang.
      RemoteLoggerInterface& remoteLoggerRef = *logger;
      if (typeid(remoteLoggerRef) != typeid(RemoteLogger)) {
        // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
        throw std::runtime_error(std::string("RemoteLogAction only takes RemoteLogger. For other types, please look at DnstapLogAction."));
      }
    }

    std::string tags;
    dnsdist::actions::RemoteLogActionConfiguration config;
    config.logger = std::move(logger);
    if (alterFunc) {
      config.alterQueryFunc = std::move(*alterFunc);
    }
    getOptionalValue<std::string>(vars, "serverID", config.serverID);
    getOptionalValue<std::string>(vars, "ipEncryptKey", config.ipEncryptKey);
    getOptionalValue<std::string>(vars, "ipEncryptMethod", config.ipEncryptMethod);
    getOptionalValue<std::string>(vars, "exportTags", tags);

    if (metas) {
      for (const auto& [key, value] : *metas) {
        config.metas.emplace_back(key, ProtoBufMetaKey(value));
      }
    }

    if (std::find(s_validIpEncryptMethods.begin(), s_validIpEncryptMethods.end(), config.ipEncryptMethod) == s_validIpEncryptMethods.end()) {
      throw std::runtime_error("Invalid IP Encryption method in RemoteLogAction");
    }

    if (!tags.empty()) {
      config.tagsToExport = std::unordered_set<std::string>();
      if (tags != "*") {
        std::vector<std::string> tokens;
        stringtok(tokens, tags, ",");
        for (auto& token : tokens) {
          config.tagsToExport->insert(std::move(token));
        }
      }
    }

    checkAllParametersConsumed("RemoteLogAction", vars);

    return dnsdist::actions::getRemoteLogAction(config);
  });

  luaCtx.writeFunction("RemoteLogResponseAction", [](std::shared_ptr<RemoteLoggerInterface> logger, std::optional<dnsdist::actions::ProtobufAlterResponseFunction> alterFunc, std::optional<bool> includeCNAME, std::optional<LuaAssociativeTable<std::string>> vars, std::optional<LuaAssociativeTable<std::string>> metas, std::optional<bool> delay) {
    if (logger) {
      // avoids potentially-evaluated-expression warning with clang.
      RemoteLoggerInterface& remoteLoggerRef = *logger;
      if (typeid(remoteLoggerRef) != typeid(RemoteLogger)) {
        // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
        throw std::runtime_error("RemoteLogResponseAction only takes RemoteLogger. For other types, please look at DnstapLogResponseAction.");
      }
    }

    std::string tags;
    dnsdist::actions::RemoteLogActionConfiguration config;
    config.logger = std::move(logger);
    if (alterFunc) {
      config.alterResponseFunc = std::move(*alterFunc);
    }
    config.includeCNAME = includeCNAME ? *includeCNAME : false;
    getOptionalValue<std::string>(vars, "serverID", config.serverID);
    getOptionalValue<std::string>(vars, "ipEncryptKey", config.ipEncryptKey);
    getOptionalValue<std::string>(vars, "ipEncryptMethod", config.ipEncryptMethod);
    getOptionalValue<std::string>(vars, "exportTags", tags);
    getOptionalValue<std::string>(vars, "exportExtendedErrorsToMeta", config.exportExtendedErrorsToMeta);

    if (metas) {
      for (const auto& [key, value] : *metas) {
        config.metas.emplace_back(key, ProtoBufMetaKey(value));
      }
    }

    if (delay) {
      config.delay = *delay;
    }

    if (!tags.empty()) {
      config.tagsToExport = std::unordered_set<std::string>();
      if (tags != "*") {
        std::vector<std::string> tokens;
        stringtok(tokens, tags, ",");
        for (auto& token : tokens) {
          config.tagsToExport->insert(std::move(token));
        }
      }
    }
    if (std::find(s_validIpEncryptMethods.begin(), s_validIpEncryptMethods.end(), config.ipEncryptMethod) == s_validIpEncryptMethods.end()) {
      throw std::runtime_error("Invalid IP Encryption method in RemoteLogResponseAction");
    }

    checkAllParametersConsumed("RemoteLogResponseAction", vars);

    return dnsdist::actions::getRemoteLogResponseAction(config);
  });

  luaCtx.writeFunction("DnstapLogAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, std::optional<dnsdist::actions::DnstapAlterFunction> alterFunc) {
    return dnsdist::actions::getDnstapLogAction(identity, std::move(logger), alterFunc ? std::move(*alterFunc) : std::optional<dnsdist::actions::DnstapAlterFunction>());
  });

  luaCtx.writeFunction("DnstapLogResponseAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, std::optional<dnsdist::actions::DnstapAlterResponseFunction> alterFunc) {
    return dnsdist::actions::getDnstapLogResponseAction(identity, std::move(logger), alterFunc ? std::move(*alterFunc) : std::optional<dnsdist::actions::DnstapAlterResponseFunction>());
  });
#endif /* DISABLE_PROTOBUF */

  luaCtx.writeFunction("TeeAction", [](const std::string& remote, std::optional<bool> addECS, std::optional<std::string> local, std::optional<bool> addProxyProtocol) {
    std::optional<ComboAddress> localAddr;
    if (local) {
      localAddr = ComboAddress(*local, 0);
    }

    return dnsdist::actions::getTeeAction(ComboAddress(remote, 53), localAddr, addECS ? *addECS : false, addProxyProtocol ? *addProxyProtocol : false);
  });

  luaCtx.writeFunction("SetECSAction", [](const std::string& v4Netmask, std::optional<std::string> v6Netmask) {
    if (v6Netmask) {
      return dnsdist::actions::getSetECSAction(v4Netmask, *v6Netmask);
    }
    return dnsdist::actions::getSetECSAction(v4Netmask);
  });

  luaCtx.writeFunction("ContinueAction", [](std::shared_ptr<DNSAction> action) {
    return dnsdist::actions::getContinueAction(std::move(action));
  });

#ifdef HAVE_DNS_OVER_HTTPS
  luaCtx.writeFunction("HTTPStatusAction", [](uint16_t status, std::string body, std::optional<std::string> contentType, std::optional<responseParams_t> vars) {
    auto responseConfig = parseResponseConfig(vars);
    checkAllParametersConsumed("HTTPStatusAction", vars);
    auto ret = dnsdist::actions::getHTTPStatusAction(status, PacketBuffer(body.begin(), body.end()), contentType ? *contentType : "", responseConfig);
    return ret;
  });
#endif /* HAVE_DNS_OVER_HTTPS */

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  luaCtx.writeFunction("KeyValueStoreLookupAction", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag) {
    return dnsdist::actions::getKeyValueStoreLookupAction(kvs, lookupKey, destinationTag);
  });

  luaCtx.writeFunction("KeyValueStoreRangeLookupAction", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag) {
    return dnsdist::actions::getKeyValueStoreRangeLookupAction(kvs, lookupKey, destinationTag);
  });
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */

  luaCtx.writeFunction("NegativeAndSOAAction", [](bool nxd, const std::string& zone, uint32_t ttl, const std::string& mname, const std::string& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum, std::optional<responseParams_t> vars) {
    bool soaInAuthoritySection = false;
    getOptionalValue<bool>(vars, "soaInAuthoritySection", soaInAuthoritySection);
    auto responseConfig = parseResponseConfig(vars);
    checkAllParametersConsumed("NegativeAndSOAAction", vars);
    dnsdist::actions::SOAParams params{
      .serial = serial,
      .refresh = refresh,
      .retry = retry,
      .expire = expire,
      .minimum = minimum};
    auto ret = dnsdist::actions::getNegativeAndSOAAction(nxd, DNSName(zone), ttl, DNSName(mname), DNSName(rname), params, soaInAuthoritySection, responseConfig);
    return ret;
  });

  luaCtx.writeFunction("SetProxyProtocolValuesAction", [](const std::vector<std::pair<uint8_t, std::string>>& values) {
    return dnsdist::actions::getSetProxyProtocolValuesAction(values);
  });

#include "dnsdist-lua-actions-generated-body.hh"
#include "dnsdist-lua-response-actions-generated-body.hh"
}
