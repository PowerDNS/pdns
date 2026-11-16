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
#include "dnsdist-lua.hh"
#include "generic-cache.hh"
#include <memory>
#include <stdexcept>

using cache_t = GenericCacheInterface<std::string, std::optional<LuaAny>>;

void setupLuaBindingsCache(LuaContext& luaCtx)
{
  luaCtx.writeFunction("newObjectCache", [](const std::string& name, std::optional<LuaAssociativeTable<boost::variant<bool, std::string>>> vars) {
    unsigned int shardCount{1};
    unsigned int ttl{100};
    unsigned int maxEntries{100};
    unsigned int lruDeleteUpTo{0};
    bool ttlEnabled{false};
    bool lruEnabled{false};
    getOptionalValue<bool>(vars, "ttlEnabled", ttlEnabled);
    getOptionalValue<bool>(vars, "lruEnabled", lruEnabled);
    getOptionalIntegerValue<unsigned int>("newObjectCache", vars, "shardCount", shardCount);
    getOptionalIntegerValue<unsigned int>("newObjectCache", vars, "maxEntries", maxEntries);
    getOptionalIntegerValue<unsigned int>("newObjectCache", vars, "lruDeleteUpTo", lruDeleteUpTo);
    getOptionalIntegerValue<unsigned int>("newObjectCache", vars, "ttl", ttl);

    auto cache = std::shared_ptr<cache_t>(new GenericCache<std::string, std::optional<LuaAny>>({.d_ttlEnabled = ttlEnabled, .d_ttl = ttl, .d_lruEnabled = lruEnabled, .d_shardCount = shardCount, .d_maxEntries = maxEntries, .d_lruDeleteUpTo = lruDeleteUpTo}));

    dnsdist::configuration::updateRuntimeConfiguration([name, &cache](dnsdist::configuration::RuntimeConfiguration& config) {
      if (config.d_caches.count(name) > 0) {
        throw std::runtime_error("Duplicate cache name: " + name);
      }
      config.d_caches.emplace(name, cache);
    });
    return cache;
  });

  luaCtx.registerFunction<std::optional<LuaAny> (std::shared_ptr<cache_t>::*)(const std::string&)>("get", [](std::shared_ptr<cache_t>& cache, const std::string& key) {
    std::optional<LuaAny> result{std::nullopt};
    if (!cache) {
      return result;
    }

    cache->getValue(key, result);
    return result;
  });

  luaCtx.registerFunction<bool (std::shared_ptr<cache_t>::*)(const std::string&)>("remove", [](std::shared_ptr<cache_t>& cache, const std::string& key) {
    if (!cache) {
      return false;
    }

    return cache->remove(key);
  });

  luaCtx.registerFunction<bool (std::shared_ptr<cache_t>::*)(const std::string&)>("contains", [](std::shared_ptr<cache_t>& cache, const std::string& key) {
    if (!cache) {
      return false;
    }

    return cache->contains(key);
  });

  luaCtx.registerFunction<void (std::shared_ptr<cache_t>::*)(const std::string&, std::optional<LuaAny>)>("insert", [](std::shared_ptr<cache_t>& cache, const std::string& key, std::optional<LuaAny> value) {
    if (!cache) {
      return;
    }

    cache->insert(key, std::move(value));
  });

  luaCtx.registerFunction<void (std::shared_ptr<cache_t>::*)(const std::string&)>("insertKey", [](std::shared_ptr<cache_t>& cache, const std::string& key) {
    if (!cache) {
      return;
    }

    cache->insertKey(key);
  });

  luaCtx.registerFunction<void (std::shared_ptr<cache_t>::*)(const int&)>("purgeExpired", [](std::shared_ptr<cache_t>& cache, const int& upTo) {
    if (!cache) {
      return;
    }

    auto time = time_t(nullptr);
    cache->purgeExpired(upTo, time);
  });

  luaCtx.registerFunction<void (std::shared_ptr<cache_t>::*)(std::optional<int>)>("expunge", [](std::shared_ptr<cache_t>& cache, std::optional<int> upTo) {
    if (!cache) {
      return;
    }

    if (upTo) {
      cache->expunge(upTo.value());
    }
    else {
      cache->expunge();
    }
  });
}
