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
#include "dnsdist-actions.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-rule-chains.hh"

template <typename ActionT, typename IdentifierT>
static void addAction(IdentifierT identifier, const luadnsrule_t& var, const std::shared_ptr<ActionT>& action, boost::optional<luaruleparams_t>& params)
{
  setLuaSideEffect();

  std::string name;
  boost::uuids::uuid uuid{};
  uint64_t creationOrder = 0;
  parseRuleParams(params, uuid, name, creationOrder);
  checkAllParametersConsumed("addAction", params);

  auto rule = makeRule(var, "addAction");
  dnsdist::configuration::updateRuntimeConfiguration([identifier, &rule, &action, &name, &uuid, creationOrder](dnsdist::configuration::RuntimeConfiguration& config) {
    dnsdist::rules::add(config.d_ruleChains, identifier, std::move(rule), action, std::move(name), uuid, creationOrder);
  });
}

using responseParams_t = std::unordered_map<std::string, boost::variant<bool, uint32_t>>;

static void parseResponseConfig(boost::optional<responseParams_t>& vars, dnsdist::ResponseConfig& config)
{
  getOptionalValue<uint32_t>(vars, "ttl", config.ttl);
  getOptionalValue<bool>(vars, "aa", config.setAA);
  getOptionalValue<bool>(vars, "ad", config.setAD);
  getOptionalValue<bool>(vars, "ra", config.setRA);
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
void setupLuaActions(LuaContext& luaCtx)
{
  luaCtx.writeFunction("newRuleAction", [](const luadnsrule_t& dnsrule, std::shared_ptr<DNSAction> action, boost::optional<luaruleparams_t> params) {
    boost::uuids::uuid uuid{};
    uint64_t creationOrder = 0;
    std::string name;
    parseRuleParams(params, uuid, name, creationOrder);
    checkAllParametersConsumed("newRuleAction", params);

    auto rule = makeRule(dnsrule, "newRuleAction");
    dnsdist::rules::RuleAction ruleaction({std::move(rule), std::move(action), std::move(name), uuid, creationOrder});
    return std::make_shared<dnsdist::rules::RuleAction>(ruleaction);
  });

  for (const auto& chain : dnsdist::rules::getRuleChainDescriptions()) {
    auto fullName = std::string("add") + chain.prefix + std::string("Action");
    luaCtx.writeFunction(fullName, [&fullName, &chain](const luadnsrule_t& var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
      if (era.type() != typeid(std::shared_ptr<DNSAction>)) {
        throw std::runtime_error(fullName + "() can only be called with query-related actions, not response-related ones. Are you looking for addResponseAction()?");
      }

      addAction(chain.identifier, var, boost::get<std::shared_ptr<DNSAction>>(era), params);
    });
    fullName = std::string("get") + chain.prefix + std::string("Action");
    luaCtx.writeFunction(fullName, [&chain](unsigned int num) {
      setLuaNoSideEffect();
      boost::optional<std::shared_ptr<DNSAction>> ret;
      const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
      const auto& ruleactions = dnsdist::rules::getRuleChain(chains, chain.identifier);
      if (num < ruleactions.size()) {
        ret = ruleactions[num].d_action;
      }
      return ret;
    });
  }

  for (const auto& chain : dnsdist::rules::getResponseRuleChainDescriptions()) {
    const auto fullName = std::string("add") + chain.prefix + std::string("ResponseAction");
    luaCtx.writeFunction(fullName, [&fullName, &chain](const luadnsrule_t& var, boost::variant<std::shared_ptr<DNSAction>, std::shared_ptr<DNSResponseAction>> era, boost::optional<luaruleparams_t> params) {
      if (era.type() != typeid(std::shared_ptr<DNSResponseAction>)) {
        throw std::runtime_error(fullName + "() can only be called with response-related actions, not query-related ones. Are you looking for addAction()?");
      }

      addAction(chain.identifier, var, boost::get<std::shared_ptr<DNSResponseAction>>(era), params);
    });
  }

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

  luaCtx.writeFunction("LuaAction", [](LuaAction::func_t func) {
    setLuaSideEffect();
    return dnsdist::actions::getLuaAction(std::move(func));
  });

  luaCtx.writeFunction("LuaFFIAction", [](LuaFFIAction::func_t func) {
    setLuaSideEffect();
    return dnsdist::actions::getLuaFFIAction(std::move(func));
  });

  luaCtx.writeFunction("LuaFFIPerThreadAction", [](const std::string& code) {
    setLuaSideEffect();
    return dnsdist::actions::getLuaFFIPerThreadAction(code);
  });

  luaCtx.writeFunction("SetNoRecurseAction", []() {
    return dnsdist::actions::getSetNoRecurseAction();
  });

  luaCtx.writeFunction("SetMacAddrAction", [](int code) {
    return dnsdist::actions::getSetMacAddrAction(code);
  });

  luaCtx.writeFunction("SetEDNSOptionAction", [](int code, const std::string& data) {
    return dnsdist::actions::getSetEDNSOptionAction(code, data);
  });

  luaCtx.writeFunction("PoolAction", [](const std::string& poolname, boost::optional<bool> stopProcessing) {
    return dnsdist::actions::getPoolAction(poolname, stopProcessing ? *stopProcessing : true);
  });

  luaCtx.writeFunction("QPSAction", [](int limit) {
    return dnsdist::actions::getQPSAction(limit);
  });

  luaCtx.writeFunction("QPSPoolAction", [](int limit, const std::string& poolname, boost::optional<bool> stopProcessing) {
    return dnsdist::actions::getQPSPoolAction(limit, poolname, stopProcessing ? *stopProcessing : true);
  });

  luaCtx.writeFunction("SpoofAction", [](LuaTypeOrArrayOf<std::string> inp, boost::optional<responseParams_t> vars) {
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

    auto ret = dnsdist::actions::getSpoofAction(addrs);
    auto spoofaction = std::dynamic_pointer_cast<SpoofAction>(ret);
    parseResponseConfig(vars, spoofaction->getResponseConfig());
    checkAllParametersConsumed("SpoofAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SpoofSVCAction", [](const LuaArray<SVCRecordParameters>& parameters, boost::optional<responseParams_t> vars) {
    auto ret = dnsdist::actions::getSpoofSVCAction(parameters);
    auto spoofaction = std::dynamic_pointer_cast<SpoofSVCAction>(ret);
    parseResponseConfig(vars, spoofaction->getResponseConfig());
    return ret;
  });

  luaCtx.writeFunction("SpoofCNAMEAction", [](const std::string& cname, boost::optional<responseParams_t> vars) {
    auto ret = dnsdist::actions::getSpoofAction(DNSName(cname));
    auto spoofaction = std::dynamic_pointer_cast<SpoofAction>(ret);
    parseResponseConfig(vars, spoofaction->getResponseConfig());
    checkAllParametersConsumed("SpoofCNAMEAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SpoofRawAction", [](LuaTypeOrArrayOf<std::string> inp, boost::optional<responseParams_t> vars) {
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
    auto ret = dnsdist::actions::getSpoofAction(raws, qtypeForAnyParam);
    auto spoofaction = std::dynamic_pointer_cast<SpoofAction>(ret);
    parseResponseConfig(vars, spoofaction->getResponseConfig());
    checkAllParametersConsumed("SpoofRawAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SpoofPacketAction", [](const std::string& response, size_t len) {
    if (len < sizeof(dnsheader)) {
      throw std::runtime_error(std::string("SpoofPacketAction: given packet len is too small"));
    }
    auto ret = std::shared_ptr<DNSAction>(new SpoofAction(response.c_str(), len));
    return ret;
  });

  luaCtx.writeFunction("DropAction", []() {
    return std::shared_ptr<DNSAction>(new DropAction);
  });

  luaCtx.writeFunction("AllowAction", []() {
    return std::shared_ptr<DNSAction>(new AllowAction);
  });

  luaCtx.writeFunction("NoneAction", []() {
    return std::shared_ptr<DNSAction>(new NoneAction);
  });

  luaCtx.writeFunction("DelayAction", [](int msec) {
    return std::shared_ptr<DNSAction>(new DelayAction(msec));
  });

  luaCtx.writeFunction("TCAction", []() {
    return std::shared_ptr<DNSAction>(new TCAction);
  });

  luaCtx.writeFunction("TCResponseAction", []() {
    return std::shared_ptr<DNSResponseAction>(new TCResponseAction);
  });

  luaCtx.writeFunction("SetDisableValidationAction", []() {
    return std::shared_ptr<DNSAction>(new SetDisableValidationAction);
  });

  luaCtx.writeFunction("LogAction", [](boost::optional<std::string> fname, boost::optional<bool> binary, boost::optional<bool> append, boost::optional<bool> buffered, boost::optional<bool> verboseOnly, boost::optional<bool> includeTimestamp) {
    return std::shared_ptr<DNSAction>(new LogAction(fname ? *fname : "", binary ? *binary : true, append ? *append : false, buffered ? *buffered : false, verboseOnly ? *verboseOnly : true, includeTimestamp ? *includeTimestamp : false));
  });

  luaCtx.writeFunction("LogResponseAction", [](boost::optional<std::string> fname, boost::optional<bool> append, boost::optional<bool> buffered, boost::optional<bool> verboseOnly, boost::optional<bool> includeTimestamp) {
    return std::shared_ptr<DNSResponseAction>(new LogResponseAction(fname ? *fname : "", append ? *append : false, buffered ? *buffered : false, verboseOnly ? *verboseOnly : true, includeTimestamp ? *includeTimestamp : false));
  });

  luaCtx.writeFunction("LimitTTLResponseAction", [](uint32_t min, uint32_t max, boost::optional<LuaArray<uint16_t>> types) {
    std::unordered_set<QType> capTypes;
    if (types) {
      capTypes.reserve(types->size());
      for (const auto& [idx, type] : *types) {
        capTypes.insert(QType(type));
      }
    }
    return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(min, max, capTypes));
  });

  luaCtx.writeFunction("SetMinTTLResponseAction", [](uint32_t min) {
    return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(min));
  });

  luaCtx.writeFunction("SetMaxTTLResponseAction", [](uint32_t max) {
    return std::shared_ptr<DNSResponseAction>(new LimitTTLResponseAction(0, max));
  });

  luaCtx.writeFunction("SetMaxReturnedTTLAction", [](uint32_t max) {
    return std::shared_ptr<DNSAction>(new MaxReturnedTTLAction(max));
  });

  luaCtx.writeFunction("SetMaxReturnedTTLResponseAction", [](uint32_t max) {
    return std::shared_ptr<DNSResponseAction>(new MaxReturnedTTLResponseAction(max));
  });

  luaCtx.writeFunction("SetReducedTTLResponseAction", [](uint8_t percentage) {
    if (percentage > 100) {
      throw std::runtime_error(std::string("SetReducedTTLResponseAction takes a percentage between 0 and 100."));
    }
    return std::shared_ptr<DNSResponseAction>(new SetReducedTTLResponseAction(percentage));
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
    return std::shared_ptr<DNSResponseAction>(new ClearRecordTypesResponseAction(std::move(qtypes)));
  });

  luaCtx.writeFunction("RCodeAction", [](uint8_t rcode, boost::optional<responseParams_t> vars) {
    auto ret = std::shared_ptr<DNSAction>(new RCodeAction(rcode));
    auto rca = std::dynamic_pointer_cast<RCodeAction>(ret);
    parseResponseConfig(vars, rca->getResponseConfig());
    checkAllParametersConsumed("RCodeAction", vars);
    return ret;
  });

  luaCtx.writeFunction("ERCodeAction", [](uint8_t rcode, boost::optional<responseParams_t> vars) {
    auto ret = std::shared_ptr<DNSAction>(new ERCodeAction(rcode));
    auto erca = std::dynamic_pointer_cast<ERCodeAction>(ret);
    parseResponseConfig(vars, erca->getResponseConfig());
    checkAllParametersConsumed("ERCodeAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SetSkipCacheAction", []() {
    return std::shared_ptr<DNSAction>(new SetSkipCacheAction);
  });

  luaCtx.writeFunction("SetSkipCacheResponseAction", []() {
    return std::shared_ptr<DNSResponseAction>(new SetSkipCacheResponseAction);
  });

  luaCtx.writeFunction("SetTempFailureCacheTTLAction", [](int maxTTL) {
    return std::shared_ptr<DNSAction>(new SetTempFailureCacheTTLAction(maxTTL));
  });

  luaCtx.writeFunction("DropResponseAction", []() {
    return std::shared_ptr<DNSResponseAction>(new DropResponseAction);
  });

  luaCtx.writeFunction("AllowResponseAction", []() {
    return std::shared_ptr<DNSResponseAction>(new AllowResponseAction);
  });

  luaCtx.writeFunction("DelayResponseAction", [](int msec) {
    return std::shared_ptr<DNSResponseAction>(new DelayResponseAction(msec));
  });

  luaCtx.writeFunction("LuaResponseAction", [](LuaResponseAction::func_t func) {
    setLuaSideEffect();
    return std::shared_ptr<DNSResponseAction>(new LuaResponseAction(std::move(func)));
  });

  luaCtx.writeFunction("LuaFFIResponseAction", [](LuaFFIResponseAction::func_t func) {
    setLuaSideEffect();
    return std::shared_ptr<DNSResponseAction>(new LuaFFIResponseAction(std::move(func)));
  });

  luaCtx.writeFunction("LuaFFIPerThreadResponseAction", [](const std::string& code) {
    setLuaSideEffect();
    return std::shared_ptr<DNSResponseAction>(new LuaFFIPerThreadResponseAction(code));
  });

#ifndef DISABLE_PROTOBUF
  luaCtx.writeFunction("RemoteLogAction", [](std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSQuestion*, DNSDistProtoBufMessage*)>> alterFunc, boost::optional<LuaAssociativeTable<std::string>> vars, boost::optional<LuaAssociativeTable<std::string>> metas) {
    if (logger) {
      // avoids potentially-evaluated-expression warning with clang.
      RemoteLoggerInterface& remoteLoggerRef = *logger;
      if (typeid(remoteLoggerRef) != typeid(RemoteLogger)) {
        // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
        throw std::runtime_error(std::string("RemoteLogAction only takes RemoteLogger. For other types, please look at DnstapLogAction."));
      }
    }

    std::string tags;
    RemoteLogActionConfiguration config;
    config.logger = std::move(logger);
    config.alterQueryFunc = std::move(alterFunc);
    getOptionalValue<std::string>(vars, "serverID", config.serverID);
    getOptionalValue<std::string>(vars, "ipEncryptKey", config.ipEncryptKey);
    getOptionalValue<std::string>(vars, "exportTags", tags);

    if (metas) {
      for (const auto& [key, value] : *metas) {
        config.metas.emplace_back(key, ProtoBufMetaKey(value));
      }
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

    return std::shared_ptr<DNSAction>(new RemoteLogAction(config));
  });

  luaCtx.writeFunction("RemoteLogResponseAction", [](std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSResponse*, DNSDistProtoBufMessage*)>> alterFunc, boost::optional<bool> includeCNAME, boost::optional<LuaAssociativeTable<std::string>> vars, boost::optional<LuaAssociativeTable<std::string>> metas) {
    if (logger) {
      // avoids potentially-evaluated-expression warning with clang.
      RemoteLoggerInterface& remoteLoggerRef = *logger;
      if (typeid(remoteLoggerRef) != typeid(RemoteLogger)) {
        // We could let the user do what he wants, but wrapping PowerDNS Protobuf inside a FrameStream tagged as dnstap is logically wrong.
        throw std::runtime_error("RemoteLogResponseAction only takes RemoteLogger. For other types, please look at DnstapLogResponseAction.");
      }
    }

    std::string tags;
    RemoteLogActionConfiguration config;
    config.logger = std::move(logger);
    config.alterResponseFunc = std::move(alterFunc);
    config.includeCNAME = includeCNAME ? *includeCNAME : false;
    getOptionalValue<std::string>(vars, "serverID", config.serverID);
    getOptionalValue<std::string>(vars, "ipEncryptKey", config.ipEncryptKey);
    getOptionalValue<std::string>(vars, "exportTags", tags);
    getOptionalValue<std::string>(vars, "exportExtendedErrorsToMeta", config.exportExtendedErrorsToMeta);

    if (metas) {
      for (const auto& [key, value] : *metas) {
        config.metas.emplace_back(key, ProtoBufMetaKey(value));
      }
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

    checkAllParametersConsumed("RemoteLogResponseAction", vars);

    return std::shared_ptr<DNSResponseAction>(new RemoteLogResponseAction(config));
  });

  luaCtx.writeFunction("DnstapLogAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSQuestion*, DnstapMessage*)>> alterFunc) {
    return std::shared_ptr<DNSAction>(new DnstapLogAction(identity, logger, std::move(alterFunc)));
  });

  luaCtx.writeFunction("DnstapLogResponseAction", [](const std::string& identity, std::shared_ptr<RemoteLoggerInterface> logger, boost::optional<std::function<void(DNSResponse*, DnstapMessage*)>> alterFunc) {
    return std::shared_ptr<DNSResponseAction>(new DnstapLogResponseAction(identity, logger, std::move(alterFunc)));
  });
#endif /* DISABLE_PROTOBUF */

  luaCtx.writeFunction("TeeAction", [](const std::string& remote, boost::optional<bool> addECS, boost::optional<std::string> local, boost::optional<bool> addProxyProtocol) {
    boost::optional<ComboAddress> localAddr{boost::none};
    if (local) {
      localAddr = ComboAddress(*local, 0);
    }

    return std::shared_ptr<DNSAction>(new TeeAction(ComboAddress(remote, 53), localAddr, addECS ? *addECS : false, addProxyProtocol ? *addProxyProtocol : false));
  });

  luaCtx.writeFunction("SetECSPrefixLengthAction", [](uint16_t v4PrefixLength, uint16_t v6PrefixLength) {
    return std::shared_ptr<DNSAction>(new SetECSPrefixLengthAction(v4PrefixLength, v6PrefixLength));
  });

  luaCtx.writeFunction("SetECSOverrideAction", [](bool ecsOverride) {
    return std::shared_ptr<DNSAction>(new SetECSOverrideAction(ecsOverride));
  });

  luaCtx.writeFunction("SetDisableECSAction", []() {
    return std::shared_ptr<DNSAction>(new SetDisableECSAction());
  });

  luaCtx.writeFunction("SetECSAction", [](const std::string& v4Netmask, boost::optional<std::string> v6Netmask) {
    if (v6Netmask) {
      return std::shared_ptr<DNSAction>(new SetECSAction(Netmask(v4Netmask), Netmask(*v6Netmask)));
    }
    return std::shared_ptr<DNSAction>(new SetECSAction(Netmask(v4Netmask)));
  });

#ifdef HAVE_NET_SNMP
  luaCtx.writeFunction("SNMPTrapAction", [](boost::optional<std::string> reason) {
    return std::shared_ptr<DNSAction>(new SNMPTrapAction(reason ? *reason : ""));
  });

  luaCtx.writeFunction("SNMPTrapResponseAction", [](boost::optional<std::string> reason) {
    return std::shared_ptr<DNSResponseAction>(new SNMPTrapResponseAction(reason ? *reason : ""));
  });
#endif /* HAVE_NET_SNMP */

  luaCtx.writeFunction("SetTagAction", [](const std::string& tag, const std::string& value) {
    return std::shared_ptr<DNSAction>(new SetTagAction(tag, value));
  });

  luaCtx.writeFunction("SetTagResponseAction", [](const std::string& tag, const std::string& value) {
    return std::shared_ptr<DNSResponseAction>(new SetTagResponseAction(tag, value));
  });

  luaCtx.writeFunction("ContinueAction", [](std::shared_ptr<DNSAction> action) {
    return std::shared_ptr<DNSAction>(new ContinueAction(action));
  });

#ifdef HAVE_DNS_OVER_HTTPS
  luaCtx.writeFunction("HTTPStatusAction", [](uint16_t status, std::string body, boost::optional<std::string> contentType, boost::optional<responseParams_t> vars) {
    auto ret = std::shared_ptr<DNSAction>(new HTTPStatusAction(status, PacketBuffer(body.begin(), body.end()), contentType ? *contentType : ""));
    auto hsa = std::dynamic_pointer_cast<HTTPStatusAction>(ret);
    parseResponseConfig(vars, hsa->getResponseConfig());
    checkAllParametersConsumed("HTTPStatusAction", vars);
    return ret;
  });
#endif /* HAVE_DNS_OVER_HTTPS */

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  luaCtx.writeFunction("KeyValueStoreLookupAction", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag) {
    return std::shared_ptr<DNSAction>(new KeyValueStoreLookupAction(kvs, lookupKey, destinationTag));
  });

  luaCtx.writeFunction("KeyValueStoreRangeLookupAction", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey, const std::string& destinationTag) {
    return std::shared_ptr<DNSAction>(new KeyValueStoreRangeLookupAction(kvs, lookupKey, destinationTag));
  });
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */

  luaCtx.writeFunction("NegativeAndSOAAction", [](bool nxd, const std::string& zone, uint32_t ttl, const std::string& mname, const std::string& rname, uint32_t serial, uint32_t refresh, uint32_t retry, uint32_t expire, uint32_t minimum, boost::optional<responseParams_t> vars) {
    bool soaInAuthoritySection = false;
    getOptionalValue<bool>(vars, "soaInAuthoritySection", soaInAuthoritySection);
    NegativeAndSOAAction::SOAParams params{
      .serial = serial,
      .refresh = refresh,
      .retry = retry,
      .expire = expire,
      .minimum = minimum};
    auto ret = std::shared_ptr<DNSAction>(new NegativeAndSOAAction(nxd, DNSName(zone), ttl, DNSName(mname), DNSName(rname), params, soaInAuthoritySection));
    auto action = std::dynamic_pointer_cast<NegativeAndSOAAction>(ret);
    parseResponseConfig(vars, action->getResponseConfig());
    checkAllParametersConsumed("NegativeAndSOAAction", vars);
    return ret;
  });

  luaCtx.writeFunction("SetProxyProtocolValuesAction", [](const std::vector<std::pair<uint8_t, std::string>>& values) {
    return std::shared_ptr<DNSAction>(new SetProxyProtocolValuesAction(values));
  });

  luaCtx.writeFunction("SetAdditionalProxyProtocolValueAction", [](uint8_t type, const std::string& value) {
    return std::shared_ptr<DNSAction>(new SetAdditionalProxyProtocolValueAction(type, value));
  });

  luaCtx.writeFunction("SetExtendedDNSErrorAction", [](uint16_t infoCode, boost::optional<std::string> extraText) {
    return std::shared_ptr<DNSAction>(new SetExtendedDNSErrorAction(infoCode, extraText ? *extraText : ""));
  });

  luaCtx.writeFunction("SetExtendedDNSErrorResponseAction", [](uint16_t infoCode, boost::optional<std::string> extraText) {
    return std::shared_ptr<DNSResponseAction>(new SetExtendedDNSErrorResponseAction(infoCode, extraText ? *extraText : ""));
  });
}
