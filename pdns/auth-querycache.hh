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
#include <boost/version.hpp>
#include "namespaces.hh"
using namespace ::boost::multi_index;

#include <boost/multi_index/hashed_index.hpp> 

#include "dns.hh"
#include "dnspacket.hh"
#include "lock.hh"

class AuthQueryCache : public boost::noncopyable
{
public:
  AuthQueryCache(size_t mapsCount=1024);

  void insert(const DNSName &qname, const QType& qtype, vector<DNSZoneRecord>&& content, uint32_t ttl, int zoneID);

  bool getEntry(const DNSName &qname, const QType& qtype, vector<DNSZoneRecord>& entry, int zoneID);

  size_t size() { return *d_statnumentries; } //!< number of entries in the cache
  void cleanup(); //!< force the cache to preen itself from expired queries
  uint64_t purge();
  uint64_t purge(const std::string& match); // could be $ terminated. Is not a dnsname!
  uint64_t purgeExact(const DNSName& qname); // no wildcard matching here

  map<char,uint64_t> getCounts();

  void setMaxEntries(uint64_t maxEntries)
  {
    d_maxEntries = maxEntries;
    for (auto& shard : d_maps) {
      shard.reserve(maxEntries / d_maps.size());
    }
  }
private:

  struct CacheEntry
  {
    DNSName qname;
    mutable vector<DNSZoneRecord> drs;
    mutable time_t created{0};
    mutable time_t ttd{0};
    uint16_t qtype{0};
    int zoneID{-1};
  };

  struct HashTag{};
  struct NameTag{};
  struct SequencedTag{};
  typedef multi_index_container<
    CacheEntry,
    indexed_by <
      hashed_unique<tag<HashTag>, composite_key<CacheEntry,
                                                         member<CacheEntry,DNSName,&CacheEntry::qname>,
                                                         member<CacheEntry,uint16_t,&CacheEntry::qtype>,
                                                         member<CacheEntry,int, &CacheEntry::zoneID> > > ,
      ordered_non_unique<tag<NameTag>, member<CacheEntry,DNSName,&CacheEntry::qname>, CanonDNSNameCompare >,
      /* Note that this sequence holds 'least recently inserted or replaced', not least recently used.
         Making it a LRU would require taking a write-lock when fetching from the cache, making the RW-lock inefficient compared to a mutex */
      sequenced<tag<SequencedTag>>
                           >
  > cmap_t;


  struct MapCombo
  {
    MapCombo() {
    }
    ~MapCombo() {
    }
    MapCombo(const MapCombo &) = delete; 
    MapCombo & operator=(const MapCombo &) = delete;

    void reserve(size_t numberOfEntries);

    SharedLockGuarded<cmap_t> d_map;
  };

  vector<MapCombo> d_maps;
  MapCombo& getMap(const DNSName& qname)
  {
    return d_maps[qname.hash() % d_maps.size()];
  }

  bool getEntryLocked(const cmap_t& map, const DNSName &content, uint16_t qtype, vector<DNSZoneRecord>& entry, int zoneID, time_t now);
  void cleanupIfNeeded();

  AtomicCounter d_ops{0};
  AtomicCounter *d_statnumhit;
  AtomicCounter *d_statnummiss;
  AtomicCounter *d_statnumentries;

  uint64_t d_maxEntries{0};
  time_t d_lastclean; // doesn't need to be atomic
  unsigned long d_nextclean{4096};
  unsigned int d_cleaninterval{4096};
  bool d_cleanskipped{false};

  static const unsigned int s_mincleaninterval=1000, s_maxcleaninterval=300000;
};
