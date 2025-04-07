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
#include "iputils.hh"

class AuthZoneCache : public boost::noncopyable
{
public:
  AuthZoneCache(size_t mapsCount = 1024);

  using ViewsMap = std::map<std::string, std::map<DNSName, std::string>>;

  // Zone maintainance
  void replace(const vector<std::tuple<ZoneName, int>>& zone);
  void replace(NetmaskTree<string> nettree);
  void replace(ViewsMap viewsmap);
  void add(const ZoneName& zone, const int zoneId);
  void remove(const ZoneName& zone);
  void setReplacePending(); //!< call this when data collection for the subsequent replace() call starts.

  // Views maintainance
  void addToView(const std::string& view, const ZoneName& zone);
  void removeFromView(const std::string& view, const ZoneName& zone);

  // Network maintainance
  void updateNetwork(const Netmask& network, const std::string& view);

  // Zone lookup
  bool getEntry(const ZoneName& zone, domainid_t& zoneId);

  // View lookup
  std::string getViewFromNetwork(Netmask* net);

  // Variant lookup
  std::string getVariantFromView(const ZoneName& zone, const std::string& view);
  void setZoneVariant(std::unique_ptr<DNSPacket>& packet);

  size_t size() { return *d_statnumentries; } //!< number of entries in the cache

  uint32_t getRefreshInterval() const
  {
    // coverity[store_truncates_time_t]
    return d_refreshinterval;
  }

  void setRefreshInterval(uint32_t interval)
  {
    d_refreshinterval = interval;
  }

  bool isEnabled() const;

  void clear();

private:
  SharedLockGuarded<NetmaskTree<string>> d_nets;
  SharedLockGuarded<ViewsMap> d_views;

  struct CacheValue
  {
    int zoneId{-1};
  };

  typedef std::unordered_map<ZoneName, CacheValue, std::hash<ZoneName>> cmap_t;

  struct MapCombo
  {
    MapCombo() = default;
    ~MapCombo() = default;
    MapCombo(const MapCombo&) = delete;
    MapCombo& operator=(const MapCombo&) = delete;

    SharedLockGuarded<cmap_t> d_map;
  };

  vector<MapCombo> d_maps;
  size_t getMapIndex(const ZoneName& zone)
  {
    return zone.hash() % d_maps.size();
  }
  MapCombo& getMap(const ZoneName& qname)
  {
    return d_maps[getMapIndex(qname)];
  }

  AtomicCounter* d_statnumhit;
  AtomicCounter* d_statnummiss;
  AtomicCounter* d_statnumentries;

  time_t d_refreshinterval{0};

  struct PendingData
  {
    std::vector<std::tuple<ZoneName, int, bool>> d_pendingUpdates;
    bool d_replacePending{false};
  };
  LockGuarded<PendingData> d_pending;
};

extern AuthZoneCache g_zoneCache;
