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
#include "bpf-filter.hh"
#include "config.h"
#include "dnsdist-configuration.hh"
#include "dnsdist.hh"
#include "dnsdist-async.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-dynbpf.hh"
#include "dnsdist-frontend.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-resolver.hh"
#include "dnsdist-svc.hh"
#include "dnsdist-xsk.hh"

#include "dolog.hh"
#include "xsk.hh"
#include <variant>

void setupLuaBindingsLogging(LuaContext& luaCtx)
{
  luaCtx.writeFunction("vinfolog", [](const string& arg) {
    VERBOSESLOG(infolog("%s", arg),
                dnsdist::logging::getTopLogger("lua-message")->info(Logr::Info, arg));
  });
  luaCtx.writeFunction("infolog", [](const string& arg) {
    SLOG(infolog("%s", arg),
         dnsdist::logging::getTopLogger("lua-message")->info(Logr::Info, arg));
  });
  luaCtx.writeFunction("errlog", [](const string& arg) {
    SLOG(errlog("%s", arg),
         dnsdist::logging::getTopLogger("lua-message")->info(Logr::Error, arg));
  });
  luaCtx.writeFunction("warnlog", [](const string& arg) {
    SLOG(warnlog("%s", arg),
         dnsdist::logging::getTopLogger("lua-message")->info(Logr::Warning, arg));
  });
  luaCtx.writeFunction("show", [](const string& arg) {
    g_outputBuffer += arg;
    g_outputBuffer += "\n";
  });
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
void setupLuaBindings(LuaContext& luaCtx, bool client, bool configCheck)
{
  /* Exceptions */
  luaCtx.registerFunction<string (std::exception_ptr::*)() const>("__tostring", [](const std::exception_ptr& eptr) -> std::string {
    try {
      if (eptr) {
        std::rethrow_exception(eptr);
      }
    }
    catch (const std::exception& e) {
      return {e.what()};
    }
    catch (const PDNSException& e) {
      return e.reason;
    }
    catch (...) {
      return {"Unknown exception"};
    }
    return {"No exception"};
  });
#ifndef DISABLE_POLICIES_BINDINGS
  /* ServerPolicy */
  luaCtx.writeFunction("newServerPolicy", [](const string& name, const ServerPolicy::policyfunc_t& policy) { return std::make_shared<ServerPolicy>(name, policy, true); });
  luaCtx.registerMember("name", &ServerPolicy::d_name);
  luaCtx.registerMember("policy", &ServerPolicy::d_policy);
  luaCtx.registerMember("ffipolicy", &ServerPolicy::d_ffipolicy);
  luaCtx.registerMember("isLua", &ServerPolicy::d_isLua);
  luaCtx.registerMember("isFFI", &ServerPolicy::d_isFFI);
  luaCtx.registerMember("isPerThread", &ServerPolicy::d_isPerThread);
  luaCtx.registerFunction("toString", &ServerPolicy::toString);
  luaCtx.registerFunction("__tostring", &ServerPolicy::toString);

  for (const auto& policy : dnsdist::lbpolicies::getBuiltInPolicies()) {
    luaCtx.writeVariable(policy->d_name, policy);
  }

#endif /* DISABLE_POLICIES_BINDINGS */

  /* ServerPool */
  luaCtx.registerFunction<void (std::shared_ptr<dnsdist::lua::LuaServerPoolObject>::*)(std::shared_ptr<DNSDistPacketCache>)>("setCache", [](const std::shared_ptr<dnsdist::lua::LuaServerPoolObject>& pool, std::shared_ptr<DNSDistPacketCache> cache) {
    if (pool) {
      dnsdist::configuration::updateRuntimeConfiguration([&pool, &cache](dnsdist::configuration::RuntimeConfiguration& config) {
        auto poolIt = config.d_pools.find(pool->poolName);
        if (poolIt == config.d_pools.end()) {
          /* this might happen if the Server Pool has been removed in the meantime, let's gracefully ignore it */
          return;
        }
        poolIt->second.packetCache = std::move(cache);
      });
    }
  });
  luaCtx.registerFunction<std::shared_ptr<DNSDistPacketCache> (std::shared_ptr<dnsdist::lua::LuaServerPoolObject>::*)() const>("getCache", [](const std::shared_ptr<dnsdist::lua::LuaServerPoolObject>& pool) {
    std::shared_ptr<DNSDistPacketCache> cache;
    if (pool) {
      dnsdist::configuration::updateRuntimeConfiguration([&pool, &cache](dnsdist::configuration::RuntimeConfiguration& config) {
        auto poolIt = config.d_pools.find(pool->poolName);
        /* this might happen if the Server Pool has been removed in the meantime, let's gracefully ignore it */
        if (poolIt != config.d_pools.end()) {
          cache = poolIt->second.packetCache;
        }
      });
    }
    return cache;
  });
  luaCtx.registerFunction<void (std::shared_ptr<dnsdist::lua::LuaServerPoolObject>::*)()>("unsetCache", [](const std::shared_ptr<dnsdist::lua::LuaServerPoolObject>& pool) {
    if (pool) {
      dnsdist::configuration::updateRuntimeConfiguration([&pool](dnsdist::configuration::RuntimeConfiguration& config) {
        auto poolIt = config.d_pools.find(pool->poolName);
        if (poolIt == config.d_pools.end()) {
          /* this might happen if the Server Pool has been removed in the meantime, let's gracefully ignore it */
          return;
        }
        poolIt->second.packetCache.reset();
      });
    }
  });
  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::lua::LuaServerPoolObject>::*)() const>("getECS", [](const std::shared_ptr<dnsdist::lua::LuaServerPoolObject>& pool) {
    bool ecs = false;
    if (pool) {
      dnsdist::configuration::updateRuntimeConfiguration([&pool, &ecs](dnsdist::configuration::RuntimeConfiguration& config) {
        auto poolIt = config.d_pools.find(pool->poolName);
        /* this might happen if the Server Pool has been removed in the meantime, let's gracefully ignore it */
        if (poolIt != config.d_pools.end()) {
          ecs = poolIt->second.getECS();
        }
      });
    }
    return ecs;
  });
  luaCtx.registerFunction<void (std::shared_ptr<dnsdist::lua::LuaServerPoolObject>::*)(bool ecs)>("setECS", [](std::shared_ptr<dnsdist::lua::LuaServerPoolObject>& pool, bool ecs) {
    if (pool) {
      dnsdist::configuration::updateRuntimeConfiguration([&pool, ecs](dnsdist::configuration::RuntimeConfiguration& config) {
        auto poolIt = config.d_pools.find(pool->poolName);
        if (poolIt == config.d_pools.end()) {
          /* this might happen if the Server Pool has been removed in the meantime, let's gracefully ignore it */
          return;
        }
        poolIt->second.setECS(ecs);
      });
    }
  });
  luaCtx.registerFunction<bool (std::shared_ptr<dnsdist::lua::LuaServerPoolObject>::*)() const>("getZeroScope", [](const std::shared_ptr<dnsdist::lua::LuaServerPoolObject>& pool) {
    bool zeroScope = false;
    if (pool) {
      dnsdist::configuration::updateRuntimeConfiguration([&pool, &zeroScope](dnsdist::configuration::RuntimeConfiguration& config) {
        auto poolIt = config.d_pools.find(pool->poolName);
        /* this might happen if the Server Pool has been removed in the meantime, let's gracefully ignore it */
        if (poolIt != config.d_pools.end()) {
          zeroScope = poolIt->second.getZeroScope();
        }
      });
    }
    return zeroScope;
  });
  luaCtx.registerFunction<void (std::shared_ptr<dnsdist::lua::LuaServerPoolObject>::*)(bool enabled)>("setZeroScope", [](std::shared_ptr<dnsdist::lua::LuaServerPoolObject>& pool, bool enabled) {
    if (pool) {
      dnsdist::configuration::updateRuntimeConfiguration([&pool, enabled](dnsdist::configuration::RuntimeConfiguration& config) {
        auto poolIt = config.d_pools.find(pool->poolName);
        if (poolIt == config.d_pools.end()) {
          /* this might happen if the Server Pool has been removed in the meantime, let's gracefully ignore it */
          return;
        }
        poolIt->second.setZeroScope(enabled);
      });
    }
  });

#ifndef DISABLE_DOWNSTREAM_BINDINGS
  /* DownstreamState */
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)(int)>("setQPS", [](std::shared_ptr<DownstreamState>& state, int lim) {
    if (state) {
      if (lim > 0) {
        state->d_qpsLimiter = QPSLimiter(lim, lim);
      }
      else {
        state->d_qpsLimiter.reset();
      }
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)(string)>("addPool", [](const std::shared_ptr<DownstreamState>& state, const string& pool) {
    if (state) {
      addServerToPool(pool, state);
      state->d_config.pools.insert(pool);
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)(string)>("rmPool", [](const std::shared_ptr<DownstreamState>& state, const string& pool) {
    if (state) {
      removeServerFromPool(pool, state);
      state->d_config.pools.erase(pool);
    }
  });
  luaCtx.registerFunction<uint64_t (std::shared_ptr<DownstreamState>::*)() const>("getOutstanding", [](const std::shared_ptr<DownstreamState>& state) -> uint64_t {
    if (state) {
      return state->outstanding.load();
    }
    return 0U;
  });
  luaCtx.registerFunction<uint64_t (std::shared_ptr<DownstreamState>::*)() const>("getDrops", [](const std::shared_ptr<DownstreamState>& state) -> uint64_t {
    if (state) {
      return state->reuseds.load();
    }
    return 0U;
  });
  luaCtx.registerFunction<uint64_t (std::shared_ptr<DownstreamState>::*)() const>("getQueries", [](const std::shared_ptr<DownstreamState>& state) -> uint64_t {
    if (state) {
      return state->queries.load();
    }
    return 0U;
  });
  luaCtx.registerFunction<double (std::shared_ptr<DownstreamState>::*)() const>("getLatency", [](const std::shared_ptr<DownstreamState>& state) -> double {
    if (state) {
      return state->getRelevantLatencyUsec();
    }
    return 0.0;
  });
  luaCtx.registerFunction<bool (std::shared_ptr<DownstreamState>::*)() const>("isUp", [](const std::shared_ptr<DownstreamState>& state) -> bool {
    if (!state) {
      return false;
    }
    return state->isUp();
  });
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)()>("setDown", [](const std::shared_ptr<DownstreamState>& state) {
    if (state) {
      state->setDown();
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)()>("setUp", [](const std::shared_ptr<DownstreamState>& state) {
    if (state) {
      state->setUp();
    }
  });
  luaCtx.registerFunction<std::string (std::shared_ptr<DownstreamState>::*)() const>("getHealthCheckMode", [](const std::shared_ptr<DownstreamState>& state) -> std::string {
    if (!state) {
      return "";
    }
    if (state->d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active) {
      return "active";
    }
    return "lazy";
  });
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)(std::optional<bool> newStatus)>("setAuto", [](std::shared_ptr<DownstreamState>& state, std::optional<bool> newStatus) {
    if (!state) {
      return;
    }
    if (newStatus) {
      state->setUpStatus(*newStatus);
    }
    state->setAuto();
  });
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)(std::optional<bool> newStatus)>("setActiveAuto", [](std::shared_ptr<DownstreamState>& state, std::optional<bool> newStatus) {
    if (!state) {
      return;
    }
    if (newStatus) {
      state->setUpStatus(*newStatus);
    }
    state->setActiveAuto();
  });
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)(std::optional<bool> newStatus)>("setLazyAuto", [](std::shared_ptr<DownstreamState>& state, std::optional<bool> newStatus) {
    if (!state) {
      return;
    }
    if (newStatus) {
      state->setUpStatus(*newStatus);
    }
    state->setLazyAuto();
  });
  luaCtx.registerFunction<void (std::shared_ptr<DownstreamState>::*)(std::optional<LuaAssociativeTable<boost::variant<size_t>>>)>("setHealthCheckParams", [](std::shared_ptr<DownstreamState>& state, std::optional<LuaAssociativeTable<boost::variant<size_t>>> vars) {
    if (!state) {
      return;
    }
    size_t value = 0;
    getOptionalValue<size_t>(vars, "maxCheckFailures", value);
    if (value > 0) {
      state->d_config.maxCheckFailures.store(value);
    }
    getOptionalValue<size_t>(vars, "rise", value);
    if (value > 0) {
      state->d_config.minRiseSuccesses.store(value);
    }
    getOptionalValue<size_t>(vars, "checkTimeout", value);
    if (value > 0) {
      state->d_config.checkTimeout.store(value);
    }
    getOptionalValue<size_t>(vars, "checkInterval", value);
    if (value > 0) {
      state->d_config.checkInterval.store(value);
    }
  });
  luaCtx.registerFunction<std::string (std::shared_ptr<DownstreamState>::*)() const>("getName", [](const std::shared_ptr<DownstreamState>& state) -> const std::string& {
    static const std::string empty;
    if (!state) {
      return empty;
    }
    return state->getName();
  });
  luaCtx.registerFunction<std::string (std::shared_ptr<DownstreamState>::*)() const>("getNameWithAddr", [](const std::shared_ptr<DownstreamState>& state) -> const std::string& {
    static const std::string empty;
    if (!state) {
      return empty;
    }
    return state->getNameWithAddr();
  });
  luaCtx.registerMember<bool(std::shared_ptr<DownstreamState>::*)>(
    "upStatus",
    [](const std::shared_ptr<DownstreamState>& state) -> bool {
      if (!state) {
        return false;
      }
      return state->upStatus.load(std::memory_order_relaxed);
    },
    [](std::shared_ptr<DownstreamState>& state, bool newStatus) {
      if (state) {
        state->upStatus.store(newStatus);
      }
    });
  luaCtx.registerMember<int(std::shared_ptr<DownstreamState>::*)>(
    "weight",
    [](const std::shared_ptr<DownstreamState>& state) -> int {
      if (!state) {
        return 0;
      }
      return state->d_config.d_weight;
    },
    [](std::shared_ptr<DownstreamState>& state, int newWeight) {
      if (state) {
        state->setWeight(newWeight);
      }
    });
  luaCtx.registerMember<int(std::shared_ptr<DownstreamState>::*)>(
    "order",
    [](const std::shared_ptr<DownstreamState>& state) -> int {
      if (!state) {
        return 0;
      }
      return state->d_config.order;
    },
    [](std::shared_ptr<DownstreamState>& state, int newOrder) {
      if (state) {
        state->d_config.order = newOrder;
      }
    });
  luaCtx.registerMember<const std::string(std::shared_ptr<DownstreamState>::*)>(
    "name",
    [](const std::shared_ptr<DownstreamState>& backend) -> std::string {
      if (!backend) {
        return "";
      }
      return backend->getName();
    },
    [](std::shared_ptr<DownstreamState>& backend, const std::string& newName) {
      if (backend) {
        backend->setName(newName);
      }
    });
  luaCtx.registerFunction<std::string (std::shared_ptr<DownstreamState>::*)() const>("getID", [](const std::shared_ptr<DownstreamState>& state) -> std::string {
    if (!state) {
      return "";
    }
    return boost::uuids::to_string(*state->d_config.id);
  });
#endif /* DISABLE_DOWNSTREAM_BINDINGS */

#ifndef DISABLE_DNSHEADER_BINDINGS
  /* dnsheader */
  luaCtx.registerFunction<void (dnsheader::*)(bool)>("setRD", [](dnsheader& dnsHeader, bool value) {
    dnsHeader.rd = value;
  });

  luaCtx.registerFunction<bool (dnsheader::*)() const>("getRD", [](const dnsheader& dnsHeader) {
    return (bool)dnsHeader.rd;
  });

  luaCtx.registerFunction<void (dnsheader::*)(bool)>("setRA", [](dnsheader& dnsHeader, bool value) {
    dnsHeader.ra = value;
  });

  luaCtx.registerFunction<bool (dnsheader::*)() const>("getRA", [](const dnsheader& dnsHeader) {
    return (bool)dnsHeader.ra;
  });

  luaCtx.registerFunction<void (dnsheader::*)(bool)>("setAD", [](dnsheader& dnsHeader, bool value) {
    dnsHeader.ad = value;
  });

  luaCtx.registerFunction<bool (dnsheader::*)() const>("getAD", [](const dnsheader& dnsHeader) {
    return (bool)dnsHeader.ad;
  });

  luaCtx.registerFunction<void (dnsheader::*)(bool)>("setAA", [](dnsheader& dnsHeader, bool value) {
    dnsHeader.aa = value;
  });

  luaCtx.registerFunction<bool (dnsheader::*)() const>("getAA", [](const dnsheader& dnsHeader) {
    return (bool)dnsHeader.aa;
  });

  luaCtx.registerFunction<void (dnsheader::*)(bool)>("setCD", [](dnsheader& dnsHeader, bool value) {
    dnsHeader.cd = value;
  });

  luaCtx.registerFunction<bool (dnsheader::*)() const>("getCD", [](const dnsheader& dnsHeader) {
    return (bool)dnsHeader.cd;
  });

  luaCtx.registerFunction<uint16_t (dnsheader::*)() const>("getID", [](const dnsheader& dnsHeader) {
    return ntohs(dnsHeader.id);
  });

  luaCtx.registerFunction<bool (dnsheader::*)() const>("getTC", [](const dnsheader& dnsHeader) {
    return (bool)dnsHeader.tc;
  });

  luaCtx.registerFunction<void (dnsheader::*)(bool)>("setTC", [](dnsheader& dnsHeader, bool value) {
    dnsHeader.tc = value;
    if (value) {
      dnsHeader.ra = dnsHeader.rd; // you'll always need this, otherwise TC=1 gets ignored
    }
  });

  luaCtx.registerFunction<void (dnsheader::*)(bool)>("setQR", [](dnsheader& dnsHeader, bool value) {
    dnsHeader.qr = value;
  });
#endif /* DISABLE_DNSHEADER_BINDINGS */

#ifndef DISABLE_COMBO_ADDR_BINDINGS
  /* ComboAddress */
  luaCtx.writeFunction("newCA", [](const std::string& name) { return ComboAddress(name); });
  luaCtx.writeFunction("newCAFromRaw", [](const std::string& raw, std::optional<uint16_t> port) {
    if (raw.size() == 4) {
      sockaddr_in sin4{};
      memset(&sin4, 0, sizeof(sin4));
      sin4.sin_family = AF_INET;
      memcpy(&sin4.sin_addr.s_addr, raw.c_str(), raw.size());
      if (port) {
        sin4.sin_port = htons(*port);
      }
      return ComboAddress(&sin4);
    }
    if (raw.size() == 16) {
      sockaddr_in6 sin6{};
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
  luaCtx.registerFunction<string (ComboAddress::*)() const>("tostring", [](const ComboAddress& addr) { return addr.toString(); });
  luaCtx.registerFunction<string (ComboAddress::*)() const>("tostringWithPort", [](const ComboAddress& addr) { return addr.toStringWithPort(); });
  luaCtx.registerFunction<string (ComboAddress::*)() const>("__tostring", [](const ComboAddress& addr) { return addr.toString(); });
  luaCtx.registerFunction<string (ComboAddress::*)() const>("toString", [](const ComboAddress& addr) { return addr.toString(); });
  luaCtx.registerFunction<string (ComboAddress::*)() const>("toStringWithPort", [](const ComboAddress& addr) { return addr.toStringWithPort(); });
  luaCtx.registerFunction<string (ComboAddress::*)() const>("getRaw", [](const ComboAddress& addr) { return addr.toByteString(); });
  luaCtx.registerFunction<uint16_t (ComboAddress::*)() const>("getPort", [](const ComboAddress& addr) { return ntohs(addr.sin4.sin_port); });
  luaCtx.registerFunction<void (ComboAddress::*)(unsigned int)>("truncate", [](ComboAddress& addr, unsigned int bits) { addr.truncate(bits); });
  luaCtx.registerFunction<bool (ComboAddress::*)() const>("isIPv4", [](const ComboAddress& addr) { return addr.sin4.sin_family == AF_INET; });
  luaCtx.registerFunction<bool (ComboAddress::*)() const>("isIPv6", [](const ComboAddress& addr) { return addr.sin4.sin_family == AF_INET6; });
  luaCtx.registerFunction<bool (ComboAddress::*)() const>("isMappedIPv4", [](const ComboAddress& addr) { return addr.isMappedIPv4(); });
  luaCtx.registerFunction<ComboAddress (ComboAddress::*)() const>("mapToIPv4", [](const ComboAddress& addr) { return addr.mapToIPv4(); });
#ifndef DISABLE_DYNBLOCKS
  luaCtx.registerFunction<bool (ClientAddressDynamicRules::*)(const ComboAddress&) const>("match", [](const ClientAddressDynamicRules& set, const ComboAddress& addr) { return set.match(addr); });
#endif /* DISABLE_DYNBLOCKS */
#endif /* DISABLE_COMBO_ADDR_BINDINGS */

#ifndef DISABLE_DNSNAME_BINDINGS
  /* DNSName */
  luaCtx.registerFunction("isPartOf", &DNSName::isPartOf);
  luaCtx.registerFunction<bool (DNSName::*)()>("chopOff", [](DNSName& name) { return name.chopOff(); });
  luaCtx.registerFunction<void (DNSName::*)(const std::variant<DNSName, std::string>&)>("append", [](DNSName& name, const std::variant<DNSName, std::string>& labels) {
    if (std::holds_alternative<DNSName>(labels)) {
      name += std::get<DNSName>(labels);
    }
    if (std::holds_alternative<string>(labels)) {
      name += DNSName(std::get<std::string>(labels));
    }
  });
  luaCtx.registerFunction<void (DNSName::*)(const std::variant<DNSName, std::string>&)>("prepend", [](DNSName& name, const std::variant<DNSName, std::string>& labels) {
    if (std::holds_alternative<DNSName>(labels)) {
      name = std::get<DNSName>(labels) + name;
    }
    if (std::holds_alternative<string>(labels)) {
      name = DNSName(std::get<std::string>(labels)) + name;
    }
  });
  luaCtx.registerFunction<unsigned int (DNSName::*)() const>("countLabels", [](const DNSName& name) { return name.countLabels(); });
  luaCtx.registerFunction<size_t (DNSName::*)() const>("hash", [](const DNSName& name) { return name.hash(); });
  luaCtx.registerFunction<size_t (DNSName::*)() const>("wirelength", [](const DNSName& name) { return name.wirelength(); });
  luaCtx.registerFunction<string (DNSName::*)() const>("tostring", [](const DNSName& name) { return name.toString(); });
  luaCtx.registerFunction<string (DNSName::*)() const>("toString", [](const DNSName& name) { return name.toString(); });
  luaCtx.registerFunction<string (DNSName::*)() const>("toStringNoDot", [](const DNSName& name) { return name.toStringNoDot(); });
  luaCtx.registerFunction<string (DNSName::*)() const>("__tostring", [](const DNSName& name) { return name.toString(); });
  luaCtx.registerFunction<string (DNSName::*)() const>("toDNSString", [](const DNSName& name) { return name.toDNSString(); });
  luaCtx.registerFunction<DNSName (DNSName::*)(const DNSName&) const>("makeRelative", [](const DNSName& name, const DNSName& relTo) { return name.makeRelative(relTo); });
  luaCtx.writeFunction("newDNSName", [](const std::string& name) { return DNSName(name); });
  luaCtx.writeFunction("newDNSNameFromRaw", [](const std::string& name) { return DNSName(name.c_str(), name.size(), 0, false); });
  luaCtx.writeFunction("newSuffixMatchNode", []() { return SuffixMatchNode(); });
  luaCtx.writeFunction("newDNSNameSet", []() { return DNSNameSet(); });

  /* DNSNameSet */
  luaCtx.registerFunction<string (DNSNameSet::*)() const>("toString", [](const DNSNameSet& dns) { return dns.toString(); });
  luaCtx.registerFunction<string (DNSNameSet::*)() const>("__tostring", [](const DNSNameSet& dns) { return dns.toString(); });
  luaCtx.registerFunction<void (DNSNameSet::*)(DNSName&)>("add", [](DNSNameSet& dns, DNSName& name) { dns.insert(name); });
  luaCtx.registerFunction<bool (DNSNameSet::*)(DNSName&)>("check", [](DNSNameSet& dns, DNSName& name) { return dns.find(name) != dns.end(); });
  // clang-format off
  luaCtx.registerFunction("delete", (size_t (DNSNameSet::*)(const DNSName&)) &DNSNameSet::erase);
  luaCtx.registerFunction("size", (size_t (DNSNameSet::*)() const) &DNSNameSet::size);
  luaCtx.registerFunction("clear", (void (DNSNameSet::*)()) &DNSNameSet::clear);
  luaCtx.registerFunction("empty", (bool (DNSNameSet::*)() const) &DNSNameSet::empty);
  // clang-format on
#endif /* DISABLE_DNSNAME_BINDINGS */

#ifndef DISABLE_SUFFIX_MATCH_BINDINGS
  /* SuffixMatchNode */
  luaCtx.registerFunction<void (SuffixMatchNode::*)(const boost::variant<DNSName, std::string, LuaArray<DNSName>, LuaArray<std::string>>& name)>("add", [](SuffixMatchNode& smn, const boost::variant<DNSName, std::string, LuaArray<DNSName>, LuaArray<std::string>>& name) {
    if (name.type() == typeid(DNSName)) {
      const auto& actualName = boost::get<DNSName>(name);
      smn.add(actualName);
      return;
    }
    if (name.type() == typeid(std::string)) {
      const auto& actualName = boost::get<std::string>(name);
      smn.add(actualName);
      return;
    }
    if (name.type() == typeid(LuaArray<DNSName>)) {
      const auto& names = boost::get<LuaArray<DNSName>>(name);
      for (const auto& actualName : names) {
        smn.add(actualName.second);
      }
      return;
    }
    if (name.type() == typeid(LuaArray<std::string>)) {
      const auto& names = boost::get<LuaArray<string>>(name);
      for (const auto& actualName : names) {
        smn.add(actualName.second);
      }
      return;
    }
  });
  luaCtx.registerFunction<void (SuffixMatchNode::*)(const boost::variant<DNSName, string, LuaArray<DNSName>, LuaArray<std::string>>& name)>("remove", [](SuffixMatchNode& smn, const boost::variant<DNSName, string, LuaArray<DNSName>, LuaArray<std::string>>& name) {
    if (name.type() == typeid(DNSName)) {
      const auto& actualName = boost::get<DNSName>(name);
      smn.remove(actualName);
      return;
    }
    if (name.type() == typeid(string)) {
      const auto& actualName = boost::get<string>(name);
      DNSName dnsName(actualName);
      smn.remove(dnsName);
      return;
    }
    if (name.type() == typeid(LuaArray<DNSName>)) {
      const auto& names = boost::get<LuaArray<DNSName>>(name);
      for (const auto& actualName : names) {
        smn.remove(actualName.second);
      }
      return;
    }
    if (name.type() == typeid(LuaArray<std::string>)) {
      const auto& names = boost::get<LuaArray<std::string>>(name);
      for (const auto& actualName : names) {
        DNSName dnsName(actualName.second);
        smn.remove(dnsName);
      }
      return;
    }
  });

  // clang-format off
  luaCtx.registerFunction("check", (bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);
  // clang-format on
  luaCtx.registerFunction<std::optional<DNSName> (SuffixMatchNode::*)(const DNSName&) const>("getBestMatch", [](const SuffixMatchNode& smn, const DNSName& needle) {
    std::optional<DNSName> result{std::nullopt};
    auto res = smn.getBestMatch(needle);
    if (res) {
      result = *res;
    }
    return result;
  });
#endif /* DISABLE_SUFFIX_MATCH_BINDINGS */

#ifndef DISABLE_NETMASK_BINDINGS
  /* Netmask */
  luaCtx.writeFunction("newNetmask", [](boost::variant<std::string, ComboAddress> addrOrStr, std::optional<uint8_t> bits) {
    if (addrOrStr.type() == typeid(ComboAddress)) {
      const auto& comboAddr = boost::get<ComboAddress>(addrOrStr);
      if (bits) {
        return Netmask(comboAddr, *bits);
      }
      return Netmask(comboAddr);
    }
    if (addrOrStr.type() == typeid(std::string)) {
      const auto& str = boost::get<std::string>(addrOrStr);
      return Netmask(str);
    }
    throw std::runtime_error("Invalid parameter passed to 'newNetmask()'");
  });
  luaCtx.registerFunction("empty", &Netmask::empty);
  luaCtx.registerFunction("getBits", &Netmask::getBits);
  luaCtx.registerFunction<ComboAddress (Netmask::*)() const>("getNetwork", [](const Netmask& netmask) { return netmask.getNetwork(); }); // const reference makes this necessary
  luaCtx.registerFunction<ComboAddress (Netmask::*)() const>("getMaskedNetwork", [](const Netmask& netmask) { return netmask.getMaskedNetwork(); });
  luaCtx.registerFunction("isIpv4", &Netmask::isIPv4);
  luaCtx.registerFunction("isIPv4", &Netmask::isIPv4);
  luaCtx.registerFunction("isIpv6", &Netmask::isIPv6);
  luaCtx.registerFunction("isIPv6", &Netmask::isIPv6);
  // clang-format off
  luaCtx.registerFunction("match", (bool (Netmask::*)(const string&) const) &Netmask::match);
  // clang-format on
  luaCtx.registerFunction("toString", &Netmask::toString);
  luaCtx.registerFunction("__tostring", &Netmask::toString);
  luaCtx.registerEqFunction(&Netmask::operator==);
  luaCtx.registerToStringFunction(&Netmask::toString);

  /* NetmaskGroup */
  luaCtx.writeFunction("newNMG", []() { return NetmaskGroup(); });
  luaCtx.registerFunction<void (NetmaskGroup::*)(const std::string& mask)>("addMask", [](NetmaskGroup& nmg, const std::string& mask) {
    nmg.addMask(mask);
  });
  luaCtx.registerFunction<void (NetmaskGroup::*)(const NetmaskGroup& otherNMG)>("addNMG", [](NetmaskGroup& nmg, const NetmaskGroup& otherNMG) {
    /* this is not going to be very efficient, sorry */
    auto entries = otherNMG.toStringVector();
    for (const auto& entry : entries) {
      nmg.addMask(entry);
    }
  });
  luaCtx.registerFunction<void (NetmaskGroup::*)(const std::map<ComboAddress, int>& map)>("addMasks", [](NetmaskGroup& nmg, const std::map<ComboAddress, int>& map) {
    for (const auto& entry : map) {
      nmg.addMask(Netmask(entry.first));
    }
  });

  // clang-format off
  luaCtx.registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const) &NetmaskGroup::match);
  // clang-format on
  luaCtx.registerFunction("size", &NetmaskGroup::size);
  luaCtx.registerFunction("clear", &NetmaskGroup::clear);
  luaCtx.registerFunction<string (NetmaskGroup::*)() const>("toString", [](const NetmaskGroup& nmg) { return "NetmaskGroup " + nmg.toString(); });
  luaCtx.registerFunction<string (NetmaskGroup::*)() const>("__tostring", [](const NetmaskGroup& nmg) { return "NetmaskGroup " + nmg.toString(); });
#endif /* DISABLE_NETMASK_BINDINGS */

#ifndef DISABLE_QPS_LIMITER_BINDINGS
  /* QPSLimiter */
  luaCtx.writeFunction("newQPSLimiter", [](int rate, int burst) { return QPSLimiter(rate, burst); });
  luaCtx.registerFunction("check", &QPSLimiter::check);
#endif /* DISABLE_QPS_LIMITER_BINDINGS */

#ifndef DISABLE_CLIENT_STATE_BINDINGS
  /* ClientState */
  luaCtx.registerFunction<std::string (ClientState::*)() const>("toString", [](const ClientState& frontend) {
    setLuaNoSideEffect();
    return frontend.local.toStringWithPort();
  });
  luaCtx.registerFunction<std::string (ClientState::*)() const>("__tostring", [](const ClientState& frontend) {
    setLuaNoSideEffect();
    return frontend.local.toStringWithPort();
  });
  luaCtx.registerFunction<std::string (ClientState::*)() const>("getType", [](const ClientState& frontend) {
    setLuaNoSideEffect();
    return frontend.getType();
  });
  luaCtx.registerFunction<std::string (ClientState::*)() const>("getConfiguredTLSProvider", [](const ClientState& frontend) {
    setLuaNoSideEffect();
    if (frontend.doqFrontend != nullptr || frontend.doh3Frontend != nullptr) {
      return std::string("BoringSSL");
    }
    if (frontend.tlsFrontend != nullptr) {
      return frontend.tlsFrontend->getRequestedProvider();
    }
    if (frontend.dohFrontend != nullptr) {
      return std::string("openssl");
    }
    return std::string();
  });
  luaCtx.registerFunction<std::string (ClientState::*)() const>("getEffectiveTLSProvider", [](const ClientState& frontend) {
    setLuaNoSideEffect();
    if (frontend.doqFrontend != nullptr || frontend.doh3Frontend != nullptr) {
      return std::string("BoringSSL");
    }
    if (frontend.tlsFrontend != nullptr) {
      return frontend.tlsFrontend->getEffectiveProvider();
    }
    if (frontend.dohFrontend != nullptr) {
      return std::string("openssl");
    }
    return std::string();
  });
  luaCtx.registerMember("muted", &ClientState::muted);
#ifdef HAVE_EBPF
  luaCtx.registerFunction<void (ClientState::*)(std::shared_ptr<BPFFilter>)>("attachFilter", [](ClientState& frontend, std::shared_ptr<BPFFilter> bpf) {
    if (bpf) {
      frontend.attachFilter(bpf, frontend.getSocket());
    }
  });
  luaCtx.registerFunction<void (ClientState::*)()>("detachFilter", [](ClientState& frontend) {
    frontend.detachFilter(frontend.getSocket());
  });
#endif /* HAVE_EBPF */
#endif /* DISABLE_CLIENT_STATE_BINDINGS */

  /* BPF Filter */
#ifdef HAVE_EBPF
  using bpfopts_t = LuaAssociativeTable<boost::variant<bool, uint32_t, std::string>>;
  luaCtx.writeFunction("newBPFFilter", [client](bpfopts_t opts) {
    if (client) {
      return std::shared_ptr<BPFFilter>(nullptr);
    }
    std::unordered_map<std::string, BPFFilter::MapConfiguration> mapsConfig;

    const auto convertParamsToConfig = [&](const std::string& name, BPFFilter::MapType type) {
      BPFFilter::MapConfiguration config;
      config.d_type = type;
      if (const string key = name + "MaxItems"; opts.count(key)) {
        const auto& tmp = opts.at(key);
        if (tmp.type() != typeid(uint32_t)) {
          throw std::runtime_error("params is invalid");
        }
        const auto& params = boost::get<uint32_t>(tmp);
        config.d_maxItems = params;
      }

      if (const string key = name + "PinnedPath"; opts.count(key)) {
        auto& tmp = opts.at(key);
        if (tmp.type() != typeid(string)) {
          throw std::runtime_error("params is invalid");
        }
        auto& params = boost::get<string>(tmp);
        config.d_pinnedPath = std::move(params);
      }
      mapsConfig[name] = std::move(config);
    };

    convertParamsToConfig("ipv4", BPFFilter::MapType::IPv4);
    convertParamsToConfig("ipv6", BPFFilter::MapType::IPv6);
    convertParamsToConfig("qnames", BPFFilter::MapType::QNames);
    convertParamsToConfig("cidr4", BPFFilter::MapType::CIDR4);
    convertParamsToConfig("cidr6", BPFFilter::MapType::CIDR6);

    BPFFilter::MapFormat format = BPFFilter::MapFormat::Legacy;
    bool external = false;
    if (opts.count("external") != 0) {
      const auto& tmp = opts.at("external");
      if (tmp.type() != typeid(bool)) {
        throw std::runtime_error("params is invalid");
      }
      external = boost::get<bool>(tmp);
      if (external) {
        format = BPFFilter::MapFormat::WithActions;
      }
    }

    return std::make_shared<BPFFilter>(mapsConfig, format, external);
  });

  luaCtx.registerFunction<void (std::shared_ptr<BPFFilter>::*)(const ComboAddress& addr, std::optional<uint32_t> action)>("block", [](const std::shared_ptr<BPFFilter>& bpf, const ComboAddress& addr, std::optional<uint32_t> action) {
    if (bpf) {
      if (!action) {
        return bpf->block(addr, BPFFilter::MatchAction::Drop);
      }
      BPFFilter::MatchAction match{};

      switch (*action) {
      case 0:
        match = BPFFilter::MatchAction::Pass;
        break;
      case 1:
        match = BPFFilter::MatchAction::Drop;
        break;
      case 2:
        match = BPFFilter::MatchAction::Truncate;
        break;
      default:
        throw std::runtime_error("Unsupported action for BPFFilter::block");
      }
      return bpf->block(addr, match);
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<BPFFilter>::*)(const string& range, uint32_t action, std::optional<bool> force)>("addRangeRule", [](const std::shared_ptr<BPFFilter>& bpf, const string& range, uint32_t action, std::optional<bool> force) {
    if (!bpf) {
      return;
    }
    BPFFilter::MatchAction match{};
    switch (action) {
    case 0:
      match = BPFFilter::MatchAction::Pass;
      break;
    case 1:
      match = BPFFilter::MatchAction::Drop;
      break;
    case 2:
      match = BPFFilter::MatchAction::Truncate;
      break;
    default:
      throw std::runtime_error("Unsupported action for BPFFilter::block");
    }
    return bpf->addRangeRule(Netmask(range), force ? *force : false, match);
  });
  luaCtx.registerFunction<void (std::shared_ptr<BPFFilter>::*)(const DNSName& qname, std::optional<uint16_t> qtype, std::optional<uint32_t> action)>("blockQName", [](const std::shared_ptr<BPFFilter>& bpf, const DNSName& qname, std::optional<uint16_t> qtype, std::optional<uint32_t> action) {
    if (bpf) {
      if (!action) {
        return bpf->block(qname, BPFFilter::MatchAction::Drop, qtype ? *qtype : 65535);
      }
      BPFFilter::MatchAction match{};

      switch (*action) {
      case 0:
        match = BPFFilter::MatchAction::Pass;
        break;
      case 1:
        match = BPFFilter::MatchAction::Drop;
        break;
      case 2:
        match = BPFFilter::MatchAction::Truncate;
        break;
      default:
        throw std::runtime_error("Unsupported action for BPFFilter::blockQName");
      }
      return bpf->block(qname, match, qtype ? *qtype : 65535);
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<BPFFilter>::*)(const ComboAddress& addr)>("unblock", [](const std::shared_ptr<BPFFilter>& bpf, const ComboAddress& addr) {
    if (bpf) {
      return bpf->unblock(addr);
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<BPFFilter>::*)(const string& range)>("rmRangeRule", [](const std::shared_ptr<BPFFilter>& bpf, const string& range) {
    if (!bpf) {
      return;
    }
    bpf->rmRangeRule(Netmask(range));
  });
  luaCtx.registerFunction<std::string (std::shared_ptr<BPFFilter>::*)() const>("lsRangeRule", [](const std::shared_ptr<BPFFilter>& bpf) {
    setLuaNoSideEffect();
    std::string res;
    if (!bpf) {
      return res;
    }
    const auto rangeStat = bpf->getRangeRule();
    for (const auto& value : rangeStat) {
      if (value.first.isIPv4()) {
        res += BPFFilter::toString(value.second.action) + "\t " + value.first.toString() + "\n";
      }
      else if (value.first.isIPv6()) {
        res += BPFFilter::toString(value.second.action) + "\t[" + value.first.toString() + "]\n";
      }
    }
    return res;
  });
  luaCtx.registerFunction<void (std::shared_ptr<BPFFilter>::*)(const DNSName& qname, std::optional<uint16_t> qtype)>("unblockQName", [](const std::shared_ptr<BPFFilter>& bpf, const DNSName& qname, std::optional<uint16_t> qtype) {
    if (bpf) {
      return bpf->unblock(qname, qtype ? *qtype : 65535);
    }
  });

  luaCtx.registerFunction<std::string (std::shared_ptr<BPFFilter>::*)() const>("getStats", [](const std::shared_ptr<BPFFilter>& bpf) {
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
      const auto rangeStat = bpf->getRangeRule();
      for (const auto& value : rangeStat) {
        if (value.first.isIPv4()) {
          res += BPFFilter::toString(value.second.action) + "\t " + value.first.toString() + ": " + std::to_string(value.second.counter) + "\n";
        }
        else if (value.first.isIPv6()) {
          res += BPFFilter::toString(value.second.action) + "\t[" + value.first.toString() + "]: " + std::to_string(value.second.counter) + "\n";
        }
      }
      auto qstats = bpf->getQNameStats();
      for (const auto& value : qstats) {
        res += std::get<0>(value).toString() + " " + std::to_string(std::get<1>(value)) + ": " + std::to_string(std::get<2>(value)) + "\n";
      }
    }
    return res;
  });

  luaCtx.registerFunction<void (std::shared_ptr<BPFFilter>::*)()>("attachToAllBinds", [](std::shared_ptr<BPFFilter>& bpf) {
    std::string res;
    if (!dnsdist::configuration::isImmutableConfigurationDone()) {
      throw std::runtime_error("attachToAllBinds() cannot be used at configuration time!");
      return;
    }
    if (bpf) {
      for (const auto& frontend : dnsdist::getFrontends()) {
        frontend->attachFilter(bpf, frontend->getSocket());
      }
    }
  });

  luaCtx.writeFunction("newDynBPFFilter", [client](std::shared_ptr<BPFFilter>& bpf) {
    if (client) {
      return std::shared_ptr<DynBPFFilter>(nullptr);
    }
    return std::make_shared<DynBPFFilter>(bpf);
  });

  luaCtx.registerFunction<void (std::shared_ptr<DynBPFFilter>::*)(const ComboAddress& addr, std::optional<int> seconds)>("block", [](const std::shared_ptr<DynBPFFilter>& dbpf, const ComboAddress& addr, std::optional<int> seconds) {
    if (dbpf) {
      timespec until{};
      clock_gettime(CLOCK_MONOTONIC, &until);
      until.tv_sec += seconds ? *seconds : 10;
      dbpf->block(addr, until);
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<DynBPFFilter>::*)()>("purgeExpired", [](const std::shared_ptr<DynBPFFilter>& dbpf) {
    if (dbpf) {
      timespec now{};
      clock_gettime(CLOCK_MONOTONIC, &now);
      dbpf->purgeExpired(now);
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<DynBPFFilter>::*)(LuaTypeOrArrayOf<std::string>)>("excludeRange", [](const std::shared_ptr<DynBPFFilter>& dbpf, LuaTypeOrArrayOf<std::string> ranges) {
    if (!dbpf) {
      return;
    }

    if (ranges.type() == typeid(LuaArray<std::string>)) {
      for (const auto& range : *boost::get<LuaArray<std::string>>(&ranges)) {
        dbpf->excludeRange(Netmask(range.second));
      }
    }
    else {
      dbpf->excludeRange(Netmask(*boost::get<std::string>(&ranges)));
    }
  });

  luaCtx.registerFunction<void (std::shared_ptr<DynBPFFilter>::*)(LuaTypeOrArrayOf<std::string>)>("includeRange", [](const std::shared_ptr<DynBPFFilter>& dbpf, LuaTypeOrArrayOf<std::string> ranges) {
    if (!dbpf) {
      return;
    }

    if (ranges.type() == typeid(LuaArray<std::string>)) {
      for (const auto& range : *boost::get<LuaArray<std::string>>(&ranges)) {
        dbpf->includeRange(Netmask(range.second));
      }
    }
    else {
      dbpf->includeRange(Netmask(*boost::get<std::string>(&ranges)));
    }
  });
#endif /* HAVE_EBPF */
#ifdef HAVE_XSK
  using xskopt_t = LuaAssociativeTable<boost::variant<uint32_t, std::string>>;
  luaCtx.writeFunction("newXsk", [client](xskopt_t opts) {
    if (dnsdist::configuration::isImmutableConfigurationDone()) {
      throw std::runtime_error("newXsk() only can be used at configuration time!");
    }
    if (client) {
      return std::shared_ptr<XskSocket>(nullptr);
    }
    uint32_t queue_id{};
    uint32_t frameNums{65536};
    std::string ifName;
    std::string path("/sys/fs/bpf/dnsdist/xskmap");
    if (opts.count("ifName") == 1) {
      ifName = boost::get<std::string>(opts.at("ifName"));
    }
    else {
      throw std::runtime_error("ifName field is required!");
    }
    if (opts.count("NIC_queue_id") == 1) {
      queue_id = boost::get<uint32_t>(opts.at("NIC_queue_id"));
    }
    else {
      throw std::runtime_error("NIC_queue_id field is required!");
    }
    if (opts.count("frameNums") == 1) {
      frameNums = boost::get<uint32_t>(opts.at("frameNums"));
    }
    if (opts.count("xskMapPath") == 1) {
      path = boost::get<std::string>(opts.at("xskMapPath"));
    }
    auto socket = std::make_shared<XskSocket>(frameNums, ifName, queue_id, path);
    dnsdist::xsk::g_xsk.push_back(socket);
    return socket;
  });
  luaCtx.registerFunction<std::string (std::shared_ptr<XskSocket>::*)() const>("getMetrics", [](const std::shared_ptr<XskSocket>& xsk) -> std::string {
    if (!xsk) {
      return {};
    }
    return xsk->getMetrics();
  });
#endif /* HAVE_XSK */
  /* EDNSOptionView */
  luaCtx.registerFunction<size_t (EDNSOptionView::*)() const>("count", [](const EDNSOptionView& option) {
    return option.values.size();
  });
  luaCtx.registerFunction<std::vector<string> (EDNSOptionView::*)() const>("getValues", [](const EDNSOptionView& option) {
    std::vector<string> values;
    values.reserve(values.size());
    for (const auto& value : option.values) {
      values.emplace_back(value.content, value.size);
    }
    return values;
  });

  luaCtx.writeFunction("newDOHResponseMapEntry", [](const std::string& regex, uint64_t status, const std::string& content, std::optional<LuaAssociativeTable<std::string>> customHeaders) {
    checkParameterBound("newDOHResponseMapEntry", status, std::numeric_limits<uint16_t>::max());
    std::optional<LuaAssociativeTable<std::string>> headers{std::nullopt};
    if (customHeaders) {
      headers = LuaAssociativeTable<std::string>();
      for (const auto& header : *customHeaders) {
        (*headers)[boost::to_lower_copy(header.first)] = header.second;
      }
    }
    return std::make_shared<DOHResponseMapEntry>(regex, status, PacketBuffer(content.begin(), content.end()), headers);
  });

  luaCtx.writeFunction("newSVCRecordParameters", [](uint64_t priority, const std::string& target, std::optional<svcParamsLua_t> additionalParameters) {
    checkParameterBound("newSVCRecordParameters", priority, std::numeric_limits<uint16_t>::max());
    SVCRecordParameters parameters;
    if (additionalParameters) {
      parameters = parseSVCParameters(*additionalParameters);
    }
    parameters.priority = priority;
    parameters.target = DNSName(target);

    return parameters;
  });

  luaCtx.writeFunction("getListOfNetworkInterfaces", []() {
    LuaArray<std::string> result;
    auto itfs = getListOfNetworkInterfaces();
    int counter = 1;
    for (const auto& itf : itfs) {
      result.emplace_back(counter++, itf);
    }
    return result;
  });

  luaCtx.writeFunction("getListOfAddressesOfNetworkInterface", [](const std::string& itf) {
    LuaArray<std::string> result;
    auto addrs = getListOfAddressesOfNetworkInterface(itf);
    int counter = 1;
    for (const auto& addr : addrs) {
      result.emplace_back(counter++, addr.toString());
    }
    return result;
  });

  luaCtx.writeFunction("getListOfRangesOfNetworkInterface", [](const std::string& itf) {
    LuaArray<std::string> result;
    auto addrs = getListOfRangesOfNetworkInterface(itf);
    int counter = 1;
    for (const auto& addr : addrs) {
      result.emplace_back(counter++, addr.toString());
    }
    return result;
  });

  luaCtx.writeFunction("getMACAddress", [](const std::string& addr) {
    return getMACAddress(ComboAddress(addr));
  });

  luaCtx.writeFunction("getCurrentTime", []() -> timespec {
    timespec now{};
    if (gettime(&now, true) < 0) {
      unixDie("Getting timestamp");
    }
    return now;
  });

  luaCtx.writeFunction("getAddressInfo", [client, configCheck](std::string hostname, std::function<void(const std::string& hostname, const LuaArray<ComboAddress>& ips)> callback) {
    if (client || configCheck) {
      return;
    }
    std::thread newThread(dnsdist::resolver::asynchronousResolver, std::move(hostname), [callback = std::move(callback)](const std::string& resolvedHostname, std::vector<ComboAddress>& ips) mutable {
      LuaArray<ComboAddress> result;
      result.reserve(ips.size());
      for (const auto& entry : ips) {
        result.emplace_back(result.size() + 1, entry);
      }
      {
        auto lua = g_lua.lock();
        try {
          callback(resolvedHostname, result);
        }
        catch (const std::exception& exp) {
          VERBOSESLOG(infolog("Error during execution of getAddressInfo callback: %s", exp.what()),
                      dnsdist::logging::getTopLogger("getAddressInfo")->error(Logr::Error, exp.what(), "Error during execution of getAddressInfo callback"));
        }
        // this _needs_ to be done while we are holding the lock,
        // otherwise the destructor will corrupt the stack
        callback = nullptr;
        dnsdist::handleQueuedAsynchronousEvents();
      }
    });
    newThread.detach();
  });

  luaCtx.writeFunction("getServerID", []() -> std::string {
    return dnsdist::configuration::getCurrentRuntimeConfiguration().d_server_id;
  });

  luaCtx.writeFunction("refreshRuntimeConfiguration", []() {
    dnsdist::configuration::refreshLocalRuntimeConfiguration();
  });
}
