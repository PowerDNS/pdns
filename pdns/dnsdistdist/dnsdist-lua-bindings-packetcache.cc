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
#include "dnsdist-lua.hh"

#include <boost/lexical_cast.hpp>

void setupLuaBindingsPacketCache(LuaContext& luaCtx, bool client)
{
  /* PacketCache */
  luaCtx.writeFunction("newPacketCache", [client](size_t maxEntries, boost::optional<LuaAssociativeTable<boost::variant<bool, size_t, LuaArray<uint16_t>>>> vars) {

    bool keepStaleData = false;
    size_t maxTTL = 86400;
    size_t minTTL = 0;
    size_t tempFailTTL = 60;
    size_t maxNegativeTTL = 3600;
    size_t staleTTL = 60;
    size_t numberOfShards = 20;
    bool dontAge = false;
    bool deferrableInsertLock = true;
    bool ecsParsing = false;
    bool cookieHashing = false;
    LuaArray<uint16_t> skipOptions;
    std::unordered_set<uint16_t> optionsToSkip{EDNSOptionCode::COOKIE};

    getOptionalValue<bool>(vars, "deferrableInsertLock", deferrableInsertLock);
    getOptionalValue<bool>(vars, "dontAge", dontAge);
    getOptionalValue<bool>(vars, "keepStaleData", keepStaleData);
    getOptionalValue<size_t>(vars, "maxNegativeTTL", maxNegativeTTL);
    getOptionalValue<size_t>(vars, "maxTTL", maxTTL);
    getOptionalValue<size_t>(vars, "minTTL", minTTL);
    getOptionalValue<size_t>(vars, "numberOfShards", numberOfShards);
    getOptionalValue<bool>(vars, "parseECS", ecsParsing);
    getOptionalValue<size_t>(vars, "staleTTL", staleTTL);
    getOptionalValue<size_t>(vars, "temporaryFailureTTL", tempFailTTL);
    getOptionalValue<bool>(vars, "cookieHashing", cookieHashing);

    if (getOptionalValue<decltype(skipOptions)>(vars, "skipOptions", skipOptions) > 0) {
      for (const auto& option : skipOptions) {
        optionsToSkip.insert(option.second);
      }
    }

    if (cookieHashing) {
      optionsToSkip.erase(EDNSOptionCode::COOKIE);
    }

    checkAllParametersConsumed("newPacketCache", vars);

    if (maxEntries < numberOfShards) {
      warnlog("The number of entries (%d) in the packet cache is smaller than the number of shards (%d), decreasing the number of shards to %d", maxEntries, numberOfShards, maxEntries);
      g_outputBuffer += "The number of entries (" + std::to_string(maxEntries) + " in the packet cache is smaller than the number of shards (" + std::to_string(numberOfShards) + "), decreasing the number of shards to " + std::to_string(maxEntries);
      numberOfShards = maxEntries;
    }

    if (client) {
      maxEntries = 1;
      numberOfShards = 1;
    }

    auto res = std::make_shared<DNSDistPacketCache>(maxEntries, maxTTL, minTTL, tempFailTTL, maxNegativeTTL, staleTTL, dontAge, numberOfShards, deferrableInsertLock, ecsParsing);

    res->setKeepStaleData(keepStaleData);
    res->setSkippedOptions(optionsToSkip);

    return res;
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

  luaCtx.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const std::string& fname)const>("dump", [](const std::shared_ptr<DNSDistPacketCache>& cache, const std::string& fname) {
      if (cache) {

        int fd = open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
        if (fd < 0) {
          g_outputBuffer = "Error opening dump file for writing: " + stringerror() + "\n";
          return;
        }

        uint64_t records = 0;
        try {
          records = cache->dump(fd);
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
