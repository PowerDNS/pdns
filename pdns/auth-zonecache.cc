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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "auth-zonecache.hh"
#include "logger.hh"
#include "statbag.hh"
#include "arguments.hh"
#include "cachecleaner.hh"
extern StatBag S;

AuthZoneCache::AuthZoneCache(size_t mapsCount) :
  d_maps(mapsCount)
{
  S.declare("zone-cache-hit", "Number of zone cache hits");
  S.declare("zone-cache-miss", "Number of zone cache misses");
  S.declare("zone-cache-size", "Number of entries in the zone cache", StatType::gauge);

  d_statnumhit = S.getPointer("zone-cache-hit");
  d_statnummiss = S.getPointer("zone-cache-miss");
  d_statnumentries = S.getPointer("zone-cache-size");
}

AuthZoneCache::~AuthZoneCache()
{
  try {
    vector<WriteLock> locks;
    for (auto& mc : d_maps) {
      locks.push_back(WriteLock(mc.d_mut));
    }
    locks.clear();
  }
  catch (...) {
  }
}

bool AuthZoneCache::getEntry(const DNSName& zone, int& zoneId)
{
  auto& mc = getMap(zone);
  bool found = false;
  {
    ReadLock rl(mc.d_mut);
    auto iter = mc.d_map.find(zone);
    if (iter != mc.d_map.end()) {
      found = true;
      zoneId = iter->second.zoneId;
    }
  }

  if (found) {
    (*d_statnumhit)++;
  }
  else {
    (*d_statnummiss)++;
  }
  return found;
}

bool AuthZoneCache::isEnabled() const
{
  return d_refreshinterval > 0;
}

void AuthZoneCache::clear()
{
  purgeLockedCollectionsVector(d_maps);
}

void AuthZoneCache::replace(const vector<tuple<DNSName, int>>& zone_indices)
{
  if (!d_refreshinterval)
    return;

  size_t count = zone_indices.size();
  vector<MapCombo> newMaps(d_maps.size());

  // build new maps
  for (const tuple<DNSName, int>& tup : zone_indices) {
    const DNSName& zone = tup.get<0>();
    CacheValue val;
    val.zoneId = tup.get<1>();
    auto& mc = newMaps[getMapIndex(zone)];
    auto iter = mc.d_map.find(zone);
    if (iter != mc.d_map.end()) {
      iter->second = std::move(val);
    }
    else {
      mc.d_map.emplace(zone, val);
    }
  }

  {
    WriteLock globalLock(d_mut);
    if (d_replacePending) {
      // add/replace all zones created while data collection for replace() was already in progress.
      for (const tuple<DNSName, int>& tup : d_pendingAdds) {
        const DNSName& zone = tup.get<0>();
        CacheValue val;
        val.zoneId = tup.get<1>();
        auto& mc = newMaps[getMapIndex(zone)];
        mc.d_map[zone] = val;
      }
    }

    for (size_t mapIndex = 0; mapIndex < d_maps.size(); mapIndex++) {
      auto& mc = d_maps[mapIndex];
      WriteLock mcLock(mc.d_mut);
      mc.d_map = std::move(newMaps[mapIndex].d_map);
    }

    d_pendingAdds.clear();
    d_replacePending = false;
  }

  d_statnumentries->store(count);
}

void AuthZoneCache::add(const DNSName& zone, const int zoneId)
{
  if (!d_refreshinterval)
    return;

  {
    WriteLock globalLock(d_mut);
    if (d_replacePending) {
      d_pendingAdds.push_back({zone, zoneId});
    }
  }

  CacheValue val;
  val.zoneId = zoneId;

  int mapIndex = getMapIndex(zone);
  {
    auto& mc = d_maps[mapIndex];
    WriteLock mcLock(mc.d_mut);
    auto iter = mc.d_map.find(zone);
    if (iter != mc.d_map.end()) {
      iter->second = std::move(val);
    }
    else {
      mc.d_map.emplace(zone, val);
    }
  }
}

void AuthZoneCache::setReplacePending()
{
  if (!d_refreshinterval)
    return;

  {
    WriteLock globalLock(d_mut);
    d_replacePending = true;
    d_pendingAdds.clear();
  }
}
