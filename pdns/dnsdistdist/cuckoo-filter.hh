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

#ifdef HAVE_CUCKOO
#include "dnsdist-lua-types.hh"
#include "generic-cache-interface.hh"

#include "rust/lib.rs.h"
#include <optional>

class CuckooFilter : public GenericCacheInterface<std::string, std::optional<LuaAny>>
{
public:
  struct CuckooSettings
  {
    unsigned int d_maxKicks{500};
    uint32_t d_maxEntries{100000};
    uint32_t d_bucketSize{4};
    uint32_t d_fingerprintBits{8};
    bool d_ttlEnabled;
    uint32_t d_ttl;
    uint32_t d_ttlBits{32};
    uint32_t d_ttlResolution{1};
    bool d_lruEnabled;
    uint32_t d_lruBits{8};
  };

  CuckooFilter(CuckooSettings settings) :
    d_settings(settings), d_lastScan(time(nullptr)), d_filter(dnsdist::rust::cuckoo::new_filter(settings.d_maxEntries, settings.d_maxKicks, settings.d_bucketSize, settings.d_fingerprintBits, settings.d_ttlEnabled, settings.d_ttl / settings.d_ttlResolution, settings.d_ttlBits, settings.d_lruEnabled, settings.d_lruBits))
  {
  }
  CuckooFilter(const CuckooFilter&) = delete;
  CuckooFilter(CuckooFilter&&) = delete;
  CuckooFilter& operator=(const CuckooFilter&) = delete;
  CuckooFilter& operator=(CuckooFilter&&) = delete;
  ~CuckooFilter() override = default;
  void insert(
    const std::string& key, [[maybe_unused]] std::optional<LuaAny> value, [[maybe_unused]] const std::function<bool(const std::optional<LuaAny>&)>& replaceCondition = []([[maybe_unused]] const std::optional<LuaAny>& value) { return true; }) override
  {
    insertKey(key);
  }
  void insertKey(const std::string& key) override
  {
    dnsdist::rust::cuckoo::filter_insert(*d_filter, ::rust::String(key));
  }
  bool contains(const std::string& key, [[maybe_unused]] bool recordMiss = false) override
  {
    return dnsdist::rust::cuckoo::filter_contains(*d_filter, ::rust::String(key));
  }
  bool getValue(const std::string& key, [[maybe_unused]] std::optional<LuaAny>& value, [[maybe_unused]] bool recordMiss = false, [[maybe_unused]] uint32_t allowExpired = 0) override
  {
    return contains(key, recordMiss);
  }
  bool remove(const std::string& key) override
  {
    return dnsdist::rust::cuckoo::filter_remove(*d_filter, ::rust::String(key));
  }

  bool hasCapacityFor([[maybe_unused]] const std::string& key) override
  {
    return true;
  }

  size_t purgeExpired([[maybe_unused]] size_t upTo, time_t now) override
  {
    size_t scans = (now - d_lastScan) / d_settings.d_ttlResolution;
    d_lastScan = now;
    size_t removed = 0;
    for (size_t i = 0; i < scans; ++i) {
      removed += dnsdist::rust::cuckoo::filter_scan_and_update(*d_filter);
    }
    return removed;
  }

  size_t expunge([[maybe_unused]] size_t upTo = 0) override
  {
    // Unsupported
    return 0;
  }

  size_t expungeByCondition([[maybe_unused]] const std::function<bool(const std::optional<LuaAny>&)>& condition, [[maybe_unused]] size_t upTo = 0) override
  {
    // Unsupported
    return 0;
  }

  [[nodiscard]] uint64_t getSize() const override
  {
    return dnsdist::rust::cuckoo::filter_get_size(*d_filter);
  }

  [[nodiscard]] const typename GenericCacheInterface<std::string, std::optional<LuaAny>>::Stats& getStats() const override
  {
    return d_stats;
  }

private:
  CuckooSettings d_settings;
  time_t d_lastScan;
  ::rust::Box<dnsdist::rust::cuckoo::CuckooFilter> d_filter;
  GenericCacheInterface<std::string, std::optional<LuaAny>>::Stats d_stats{"filter=\"cuckoo\""};
};
#else
class CuckooFilter
{
};
#endif
