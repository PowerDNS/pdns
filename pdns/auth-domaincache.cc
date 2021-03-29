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

#include "auth-domaincache.hh"
#include "logger.hh"
#include "statbag.hh"
#include "arguments.hh"
#include "cachecleaner.hh"
extern StatBag S;

AuthDomainCache::AuthDomainCache(size_t mapsCount) :
  d_maps(mapsCount)
{
  S.declare("domain-cache-hit", "Number of hits on the domain cache");
  S.declare("domain-cache-miss", "Number of misses on the domain cache");
  S.declare("domain-cache-size", "Number of entries in the domain cache", StatType::gauge);

  d_statnumhit = S.getPointer("domain-cache-hit");
  d_statnummiss = S.getPointer("domain-cache-miss");
  d_statnumentries = S.getPointer("domain-cache-size");

  d_ttl = 0;
}

AuthDomainCache::~AuthDomainCache()
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

bool AuthDomainCache::getEntry(const DNSName& domain, int& zoneId)
{
  auto& mc = getMap(domain);
  bool found = false;
  {
    ReadLock rl(mc.d_mut);
    auto iter = mc.d_map.find(domain);
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

bool AuthDomainCache::isEnabled() const
{
  return d_ttl > 0;
}

void AuthDomainCache::clear()
{
  purgeLockedCollectionsVector(d_maps);
}

void AuthDomainCache::replace(const vector<tuple<DNSName, int>>& domain_indices)
{
  if (!d_ttl)
    return;

  size_t count = domain_indices.size();
  vector<MapCombo> newMaps(d_maps.size());

  // build new maps
  for (const tuple<DNSName, int>& tup : domain_indices) {
    const DNSName& domain = tup.get<0>();
    CacheValue val;
    val.zoneId = tup.get<1>();
    auto& mc = newMaps[getMapIndex(domain)];
    mc.d_map.emplace(domain, val);
  }

  {
    WriteLock globalLock(d_mut);
    if (d_replacePending) {
      // add/replace all domains created while data collection for replace() was already running.
      for (const tuple<DNSName, int>& tup : d_pendingAdds) {
        const DNSName& domain = tup.get<0>();
        CacheValue val;
        val.zoneId = tup.get<1>();
        auto& mc = newMaps[getMapIndex(domain)];
        mc.d_map[domain] = val;
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

void AuthDomainCache::add(const DNSName& domain, const int zoneId)
{
  if (!d_ttl)
    return;

  {
    WriteLock globalLock(d_mut);
    if (d_replacePending) {
      d_pendingAdds.push_back({domain, zoneId});
    }
  }

  CacheValue val;
  val.zoneId = zoneId;

  int mapIndex = getMapIndex(domain);
  {
    auto& mc = d_maps[mapIndex];
    WriteLock mcLock(mc.d_mut);
    mc.d_map.emplace(domain, val);
  }
}

void AuthDomainCache::setReplacePending()
{
  if (!d_ttl)
    return;

  WriteLock globalLock(d_mut);
  d_replacePending = true;
  d_pendingAdds.clear();
}
