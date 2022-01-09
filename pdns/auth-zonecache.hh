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
#include <string>
#include <unordered_map>
#include <vector>
#include "dnsname.hh"
#include "lock.hh"
#include "misc.hh"

class AuthZoneCache : public boost::noncopyable
{
public:
  AuthZoneCache(size_t mapsCount = 1024);

  void replace(const vector<tuple<DNSName, int>>& zone);
  void add(const DNSName& zone, const int zoneId);
  void remove(const DNSName& zone);
  void setReplacePending(); //!< call this when data collection for the subsequent replace() call starts.

  bool getEntry(const DNSName& zone, int& zoneId);

  size_t size() { return *d_statnumentries; } //!< number of entries in the cache

  uint32_t getRefreshInterval() const
  {
    return d_refreshinterval;
  }

  void setRefreshInterval(uint32_t interval)
  {
    d_refreshinterval = interval;
  }

  bool isEnabled() const;

  void clear();

private:
  struct CacheValue
  {
    int zoneId{-1};
  };

  typedef std::unordered_map<DNSName, CacheValue, std::hash<DNSName>> cmap_t;

  struct MapCombo
  {
    MapCombo() {}
    ~MapCombo() {}
    MapCombo(const MapCombo&) = delete;
    MapCombo& operator=(const MapCombo&) = delete;

    SharedLockGuarded<cmap_t> d_map;
  };

  vector<MapCombo> d_maps;
  size_t getMapIndex(const DNSName& zone)
  {
    return zone.hash() % d_maps.size();
  }
  MapCombo& getMap(const DNSName& qname)
  {
    return d_maps[getMapIndex(qname)];
  }

  AtomicCounter* d_statnumhit;
  AtomicCounter* d_statnummiss;
  AtomicCounter* d_statnumentries;

  time_t d_refreshinterval{0};

  struct PendingData
  {
    std::vector<tuple<DNSName, int, bool>> d_pendingUpdates;
    bool d_replacePending{false};
  };
  LockGuarded<PendingData> d_pending;
};

extern AuthZoneCache g_zoneCache;
