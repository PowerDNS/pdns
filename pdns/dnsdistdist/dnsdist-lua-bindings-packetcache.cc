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

void setupLuaBindingsPacketCache()
{
  /* PacketCache */
  g_lua.writeFunction("newPacketCache", [](size_t maxEntries, boost::optional<std::unordered_map<std::string, boost::variant<bool, size_t>>> vars) {

      bool keepStaleData = false;
      size_t maxTTL = 86400;
      size_t minTTL = 0;
      size_t tempFailTTL = 60;
      size_t maxNegativeTTL = 3600;
      size_t staleTTL = 60;
      size_t numberOfShards = 1;
      bool dontAge = false;
      bool deferrableInsertLock = true;
      bool ecsParsing = false;

      if (vars) {

        if (vars->count("deferrableInsertLock")) {
          deferrableInsertLock = boost::get<bool>((*vars)["deferrableInsertLock"]);
        }

        if (vars->count("dontAge")) {
          dontAge = boost::get<bool>((*vars)["dontAge"]);
        }

        if (vars->count("keepStaleData")) {
          keepStaleData = boost::get<bool>((*vars)["keepStaleData"]);
        }

        if (vars->count("maxNegativeTTL")) {
          maxNegativeTTL = boost::get<size_t>((*vars)["maxNegativeTTL"]);
        }

        if (vars->count("maxTTL")) {
          maxTTL = boost::get<size_t>((*vars)["maxTTL"]);
        }

        if (vars->count("minTTL")) {
          minTTL = boost::get<size_t>((*vars)["minTTL"]);
        }

        if (vars->count("numberOfShards")) {
          numberOfShards = boost::get<size_t>((*vars)["numberOfShards"]);
        }

        if (vars->count("parseECS")) {
          ecsParsing = boost::get<bool>((*vars)["parseECS"]);
        }

        if (vars->count("staleTTL")) {
          staleTTL = boost::get<size_t>((*vars)["staleTTL"]);
        }

        if (vars->count("temporaryFailureTTL")) {
          tempFailTTL = boost::get<size_t>((*vars)["temporaryFailureTTL"]);
        }
      }

      auto res = std::make_shared<DNSDistPacketCache>(maxEntries, maxTTL, minTTL, tempFailTTL, maxNegativeTTL, staleTTL, dontAge, numberOfShards, deferrableInsertLock, ecsParsing);

      res->setKeepStaleData(keepStaleData);

      return res;
    });
  g_lua.registerFunction("toString", &DNSDistPacketCache::toString);
  g_lua.registerFunction("isFull", &DNSDistPacketCache::isFull);
  g_lua.registerFunction("purgeExpired", &DNSDistPacketCache::purgeExpired);
  g_lua.registerFunction("expunge", &DNSDistPacketCache::expunge);
  g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const DNSName& dname, boost::optional<uint16_t> qtype, boost::optional<bool> suffixMatch)>("expungeByName", [](
              std::shared_ptr<DNSDistPacketCache> cache,
              const DNSName& dname,
              boost::optional<uint16_t> qtype,
              boost::optional<bool> suffixMatch) {
                if (cache) {
                  g_outputBuffer="Expunged " + std::to_string(cache->expungeByName(dname, qtype ? *qtype : QType(QType::ANY).getCode(), suffixMatch ? *suffixMatch : false)) + " records\n";
                }
    });
  g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)()>("printStats", [](const std::shared_ptr<DNSDistPacketCache> cache) {
      if (cache) {
        g_outputBuffer="Entries: " + std::to_string(cache->getEntriesCount()) + "/" + std::to_string(cache->getMaxEntries()) + "\n";
        g_outputBuffer+="Hits: " + std::to_string(cache->getHits()) + "\n";
        g_outputBuffer+="Misses: " + std::to_string(cache->getMisses()) + "\n";
        g_outputBuffer+="Deferred inserts: " + std::to_string(cache->getDeferredInserts()) + "\n";
        g_outputBuffer+="Deferred lookups: " + std::to_string(cache->getDeferredLookups()) + "\n";
        g_outputBuffer+="Lookup Collisions: " + std::to_string(cache->getLookupCollisions()) + "\n";
        g_outputBuffer+="Insert Collisions: " + std::to_string(cache->getInsertCollisions()) + "\n";
        g_outputBuffer+="TTL Too Shorts: " + std::to_string(cache->getTTLTooShorts()) + "\n";
      }
    });
  g_lua.registerFunction<std::unordered_map<std::string, uint64_t>(std::shared_ptr<DNSDistPacketCache>::*)()>("getStats", [](const std::shared_ptr<DNSDistPacketCache> cache) {
      std::unordered_map<std::string, uint64_t> stats;
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
      }
      return stats;
    });
  g_lua.registerFunction<void(std::shared_ptr<DNSDistPacketCache>::*)(const std::string& fname)>("dump", [](const std::shared_ptr<DNSDistPacketCache> cache, const std::string& fname) {
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
}
