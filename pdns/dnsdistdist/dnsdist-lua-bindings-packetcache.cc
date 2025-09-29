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
#include "dnsdist-cache.hh"
#include "dnsdist-lua.hh"

void setupLuaBindingsPacketCache(LuaContext& luaCtx, bool client)
{
  /* PacketCache */
  luaCtx.writeFunction("newPacketCache", [client](size_t maxEntries, boost::optional<LuaAssociativeTable<boost::variant<bool, size_t, LuaArray<uint16_t>>>> vars) {

    DNSDistPacketCache::CacheSettings settings {
      .d_maxEntries = maxEntries,
      .d_shardCount = 20,
    };
    bool cookieHashing = false;
    LuaArray<uint16_t> skipOptions;
    LuaArray<uint16_t> payloadRanks;
    std::unordered_set<uint16_t> ranks;
    size_t maximumEntrySize{4096};

    getOptionalValue<bool>(vars, "deferrableInsertLock", settings.d_deferrableInsertLock);
    getOptionalValue<bool>(vars, "dontAge", settings.d_dontAge);
    getOptionalValue<bool>(vars, "keepStaleData", settings.d_keepStaleData);
    getOptionalValue<size_t>(vars, "maxNegativeTTL", settings.d_maxNegativeTTL);
    getOptionalValue<size_t>(vars, "maxTTL", settings.d_maxTTL);
    getOptionalValue<size_t>(vars, "minTTL", settings.d_minTTL);
    getOptionalValue<size_t>(vars, "numberOfShards", settings.d_shardCount);
    getOptionalValue<bool>(vars, "parseECS", settings.d_parseECS);
    getOptionalValue<size_t>(vars, "staleTTL", settings.d_staleTTL);
    getOptionalValue<size_t>(vars, "temporaryFailureTTL", settings.d_tempFailureTTL);
    getOptionalValue<size_t>(vars, "truncatedTTL", settings.d_truncatedTTL);
    getOptionalValue<bool>(vars, "cookieHashing", cookieHashing);
    getOptionalValue<size_t>(vars, "maximumEntrySize", maximumEntrySize);

    if (maximumEntrySize >= sizeof(dnsheader)) {
      settings.d_maximumEntrySize = maximumEntrySize;
    }

    if (getOptionalValue<decltype(skipOptions)>(vars, "skipOptions", skipOptions) > 0) {
      settings.d_optionsToSkip.clear();
      settings.d_optionsToSkip.insert(EDNSOptionCode::COOKIE);
      for (const auto& option : skipOptions) {
        settings.d_optionsToSkip.insert(option.second);
      }
    }

    if (getOptionalValue<decltype(payloadRanks)>(vars, "payloadRanks", payloadRanks) > 0) {
      for (const auto& rank : payloadRanks) {
        if (rank.second < 512 || rank.second > settings.d_maximumEntrySize) {
          continue;
        }
        ranks.insert(rank.second);
      }
      if (!ranks.empty()) {
        settings.d_payloadRanks.assign(ranks.begin(), ranks.end());
        std::sort(settings.d_payloadRanks.begin(), settings.d_payloadRanks.end());
      }
    }

    if (cookieHashing) {
      settings.d_optionsToSkip.erase(EDNSOptionCode::COOKIE);
    }

    checkAllParametersConsumed("newPacketCache", vars);

    if (maxEntries < settings.d_shardCount) {
      warnlog("The number of entries (%d) in the packet cache is smaller than the number of shards (%d), decreasing the number of shards to %d", maxEntries, settings.d_shardCount, maxEntries);
      g_outputBuffer += "The number of entries (" + std::to_string(maxEntries) + " in the packet cache is smaller than the number of shards (" + std::to_string(settings.d_shardCount) + "), decreasing the number of shards to " + std::to_string(maxEntries);
      settings.d_shardCount = maxEntries;
    }

    if (client) {
      settings.d_maxEntries = 1;
      settings.d_shardCount = 1;
    }

    return std::make_shared<DNSDistPacketCache>(settings);
  });

#ifndef DISABLE_PACKETCACHE_BINDINGS
  luaCtx.registerFunction<std::string(std::shared_ptr<DNSDistPacketCache>::*)()const>("toString", [](const std::shared_ptr<DNSDistPacketCache>& cache) {
      if (cache) {
        return cache->toString();
      }
      return std::string();
    });
  luaCtx.registerFunction<bool(std::shared_ptr<DNSDistPacketCache>::*)()const>("isFull", [](const std::shared_ptr<DNSDistPacketCache>& cache) {
      if (cache) {
        return cache->isFull();
      }
      return false;
    });
  luaCtx.registerFunction<size_t(std::shared_ptr<DNSDistPacketCache>::*)(size_t)>("purgeExpired", [](std::shared_ptr<DNSDistPacketCache>& cache, size_t upTo) {
      if (cache) {
        const time_t now = time(nullptr);

        return cache->purgeExpired(upTo, now);
      }
      return static_cast<size_t>(0);
    });
  luaCtx.registerFunction<size_t(std::shared_ptr<DNSDistPacketCache>::*)(size_t)>("expunge", [](std::shared_ptr<DNSDistPacketCache>& cache, size_t upTo) {
      if (cache) {
        return cache->expunge(upTo);
      }
      return static_cast<size_t>(0);
    });
  luaCtx.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const boost::variant<DNSName, string>& dname, boost::optional<uint16_t> qtype, boost::optional<bool> suffixMatch)>("expungeByName", [](
              std::shared_ptr<DNSDistPacketCache>& cache,
              const boost::variant<DNSName, string>& dname,
              boost::optional<uint16_t> qtype,
              boost::optional<bool> suffixMatch) {
                DNSName qname;
                if (dname.type() == typeid(DNSName)) {
                  qname = boost::get<DNSName>(dname);
                }
                if (dname.type() == typeid(string)) {
                  qname = DNSName(boost::get<string>(dname));
                }
                if (cache) {
                  g_outputBuffer+="Expunged " + std::to_string(cache->expungeByName(qname, qtype ? *qtype : QType(QType::ANY).getCode(), suffixMatch ? *suffixMatch : false)) + " records\n";
                }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)()const>("printStats", [](const std::shared_ptr<DNSDistPacketCache>& cache) {
      if (cache) {
        g_outputBuffer="Entries: " + std::to_string(cache->getEntriesCount()) + "/" + std::to_string(cache->getMaxEntries()) + "\n";
        g_outputBuffer+="Hits: " + std::to_string(cache->getHits()) + "\n";
        g_outputBuffer+="Misses: " + std::to_string(cache->getMisses()) + "\n";
        g_outputBuffer+="Deferred inserts: " + std::to_string(cache->getDeferredInserts()) + "\n";
        g_outputBuffer+="Deferred lookups: " + std::to_string(cache->getDeferredLookups()) + "\n";
        g_outputBuffer+="Lookup Collisions: " + std::to_string(cache->getLookupCollisions()) + "\n";
        g_outputBuffer+="Insert Collisions: " + std::to_string(cache->getInsertCollisions()) + "\n";
        g_outputBuffer+="TTL Too Shorts: " + std::to_string(cache->getTTLTooShorts()) + "\n";
        g_outputBuffer+="Cleanup Count: " + std::to_string(cache->getCleanupCount()) + "\n";
      }
    });
  luaCtx.registerFunction<LuaAssociativeTable<uint64_t>(std::shared_ptr<DNSDistPacketCache>::*)()const>("getStats", [](const std::shared_ptr<DNSDistPacketCache>& cache) {
      LuaAssociativeTable<uint64_t> stats;
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
        stats["cleanupCount"] = cache->getCleanupCount();
      }
      return stats;
    });

  luaCtx.registerFunction<LuaArray<DNSName>(std::shared_ptr<DNSDistPacketCache>::*)(const ComboAddress& addr)const>("getDomainListByAddress", [](const std::shared_ptr<DNSDistPacketCache>& cache, const ComboAddress& addr) {
      LuaArray<DNSName> results;
      if (!cache) {
        return results;
      }

      int counter = 1;
      auto domains = cache->getDomainsContainingRecords(addr);
      results.reserve(domains.size());
      for (auto& domain : domains) {
        results.emplace_back(counter, std::move(domain));
        counter++;
      }
      return results;
    });

  luaCtx.registerFunction<LuaArray<ComboAddress>(std::shared_ptr<DNSDistPacketCache>::*)(const DNSName& domain)const>("getAddressListByDomain", [](const std::shared_ptr<DNSDistPacketCache>& cache, const DNSName& domain) {
      LuaArray<ComboAddress> results;
      if (!cache) {
        return results;
      }

      int counter = 1;
      auto addresses = cache->getRecordsForDomain(domain);
      results.reserve(addresses.size());
      for (auto& address : addresses) {
        results.emplace_back(counter, std::move(address));
        counter++;
      }
      return results;
    });

  luaCtx.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const std::string& fname, boost::optional<bool> rawResponse)const>("dump", [](const std::shared_ptr<DNSDistPacketCache>& cache, const std::string& fname, boost::optional<bool> rawResponse) {
      if (cache) {

        int fd = open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
        if (fd < 0) {
          g_outputBuffer = "Error opening dump file for writing: " + stringerror() + "\n";
          return;
        }

        uint64_t records = 0;
        try {
          records = cache->dump(fd, rawResponse? *rawResponse : false);
        }
        catch (const std::exception& e) {
          close(fd);
          throw;
        }

        close(fd);

        g_outputBuffer += "Dumped " + std::to_string(records) + " records\n";
      }
    });
#endif /* DISABLE_PACKETCACHE_BINDINGS */
}
