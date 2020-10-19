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
#include <map>
#include "dns.hh"

#include <unordered_map>

#include "dns.hh"
#include "dnspacket.hh"
#include "lock.hh"

class AuthDomainCache : public boost::noncopyable
{
public:
  AuthDomainCache(size_t mapsCount=1024);
  ~AuthDomainCache();

  void replace(const vector<tuple<DNSName, int>> &domains);
  void add(const DNSName& domain, const int zoneId);

  bool getEntry(const DNSName &domain, int &zoneId);

  size_t size() { return *d_statnumentries; } //!< number of entries in the cache

  uint32_t getTTL() const {
    return d_ttl;
  }

  void setTTL(uint32_t ttl) {
    d_ttl = ttl;
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
    MapCombo() { }
    ~MapCombo() { }
    MapCombo(const MapCombo &) = delete;
    MapCombo & operator=(const MapCombo &) = delete;

    ReadWriteLock d_mut;
    cmap_t d_map;
  };

  vector<MapCombo> d_maps;
  size_t getMapIndex(const DNSName& domain)
  {
    return domain.hash() % d_maps.size();
  }
  MapCombo& getMap(const DNSName& qname)
  {
    return d_maps[getMapIndex(qname)];
  }

  AtomicCounter d_ops{0};
  AtomicCounter *d_statnumhit;
  AtomicCounter *d_statnummiss;
  AtomicCounter *d_statnumentries;

  time_t d_ttl;
};
