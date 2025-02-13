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
#pragma once

#include "dolog.hh"
#include "dnsdist.hh"

#include "ext/luawrapper/include/LuaContext.hpp"

extern RecursiveLockGuarded<LuaContext> g_lua;
extern std::string g_outputBuffer; // locking for this is ok, as locked by g_luamutex

template <class T>
using LuaArray = std::vector<std::pair<int, T>>;
template <class T>
using LuaAssociativeTable = std::unordered_map<std::string, T>;
template <class T>
using LuaTypeOrArrayOf = boost::variant<T, LuaArray<T>>;

using luaruleparams_t = LuaAssociativeTable<std::string>;

using luadnsrule_t = boost::variant<string, LuaArray<std::string>, std::shared_ptr<DNSRule>, DNSName, LuaArray<DNSName>>;
std::shared_ptr<DNSRule> makeRule(const luadnsrule_t& var, const std::string& calledFrom);

void parseRuleParams(boost::optional<luaruleparams_t>& params, boost::uuids::uuid& uuid, std::string& name, uint64_t& creationOrder);
void checkParameterBound(const std::string& parameter, uint64_t value, size_t max = std::numeric_limits<uint16_t>::max());

void setupLua(LuaContext& luaCtx, bool client, bool configCheck, const std::string& config);
void setupLuaActions(LuaContext& luaCtx);
void setupLuaBindings(LuaContext& luaCtx, bool client, bool configCheck);
void setupLuaBindingsDNSCrypt(LuaContext& luaCtx, bool client);
void setupLuaBindingsDNSParser(LuaContext& luaCtx);
void setupLuaBindingsDNSQuestion(LuaContext& luaCtx);
void setupLuaBindingsKVS(LuaContext& luaCtx, bool client);
void setupLuaBindingsLogging(LuaContext& luaCtx);
void setupLuaBindingsNetwork(LuaContext& luaCtx, bool client);
void setupLuaBindingsPacketCache(LuaContext& luaCtx, bool client);
void setupLuaBindingsProtoBuf(LuaContext& luaCtx, bool client, bool configCheck);
void setupLuaBindingsRings(LuaContext& luaCtx, bool client);
void setupLuaRules(LuaContext& luaCtx);
void setupLuaInspection(LuaContext& luaCtx);
void setupLuaVars(LuaContext& luaCtx);
void setupLuaWeb(LuaContext& luaCtx);
void setupLuaLoadBalancingContext(LuaContext& luaCtx);

namespace dnsdist::lua
{
void setupLua(LuaContext& luaCtx, bool client, bool configCheck);
void setupLuaBindingsOnly(LuaContext& luaCtx, bool client, bool configCheck);
void setupLuaConfigurationOptions(LuaContext& luaCtx, bool client, bool configCheck);
void setupConfigurationItems(LuaContext& luaCtx);

template <class FunctionType>
std::optional<FunctionType> getFunctionFromLuaCode(const std::string& code, const std::string& context)
{
  try {
    auto function = g_lua.lock()->executeCode<FunctionType>(code);
    if (!function) {
      return std::nullopt;
    }
    return function;
  }
  catch (const std::exception& exp) {
    warnlog("Parsing Lua code '%s' in context '%s' failed: %s", code, context, exp.what());
  }

  return std::nullopt;
}
}

namespace dnsdist::configuration::lua
{
void loadLuaConfigurationFile(LuaContext& luaCtx, const std::string& config, bool configCheck);
}

/**
 * getOptionalValue(vars, key, value)
 *
 * Attempts to extract value for key in vars.
 * Erases the key from vars.
 *
 * returns: -1 if type wasn't compatible, 0 if not found or number of element(s) found
 */
template <class G, class T, class V>
static inline int getOptionalValue(boost::optional<V>& vars, const std::string& key, T& value, bool warnOnWrongType = true)
{
  /* nothing found, nothing to return */
  if (!vars) {
    return 0;
  }

  if (vars->count(key)) {
    try {
      value = boost::get<G>((*vars)[key]);
    }
    catch (const boost::bad_get& e) {
      /* key is there but isn't compatible */
      if (warnOnWrongType) {
        warnlog("Invalid type for key '%s' - ignored", key);
        vars->erase(key);
      }
      return -1;
    }
  }
  return vars->erase(key);
}

template <class T, class V>
static inline int getOptionalIntegerValue(const std::string& func, boost::optional<V>& vars, const std::string& key, T& value)
{
  std::string valueStr;
  auto ret = getOptionalValue<std::string>(vars, key, valueStr, true);
  if (ret == 1) {
    try {
      value = std::stoi(valueStr);
    }
    catch (const std::exception& e) {
      warnlog("Parameter '%s' of '%s' must be integer, not '%s' - ignoring", func, key, valueStr);
      return -1;
    }
  }
  return ret;
}

template <class V>
static inline void checkAllParametersConsumed(const std::string& func, const boost::optional<V>& vars)
{
  /* no vars */
  if (!vars) {
    return;
  }
  for (const auto& [key, value] : *vars) {
    warnlog("%s: Unknown key '%s' given - ignored", func, key);
  }
}
