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
#include <unordered_map>
#include "dns.hh"
#include <boost/version.hpp>
#include "namespaces.hh"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp> 
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
using namespace ::boost::multi_index;

#include "dnspacket.hh"
#include "lock.hh"
#include "packetcache.hh"

/** This class performs 'whole packet caching'. Feed it a question packet and it will
    try to find an answer. If you have an answer, insert it to have it cached for later use. 
    Take care not to replace existing cache entries. While this works, it is wasteful. Only
    insert packets that were not found by get()

    Caches are indexed by views. When views are not used, all the data in the
    cache is associated to the empty string "" default view.

    Locking! 

    The cache itself is protected by a read/write lock. Because deleting is a two step process, which 
    first marks and then sweeps, a second lock is present to prevent simultaneous inserts and deletes.
*/

class AuthPacketCache : public PacketCache
{
public:
  AuthPacketCache(size_t mapsCount=1024);

  void insert(DNSPacket& query, DNSPacket& response, uint32_t maxTTL, const std::string& view);  //!< We copy the contents of *p into our cache. Do not needlessly call this to insert questions already in the cache as it wastes resources

  bool get(DNSPacket& pkt, DNSPacket& cached, const std::string& view = ""); //!< You need to spoof in the right ID with the DNSPacket.spoofID() method.

  void cleanup(); //!< force the cache to preen itself from expired packets
  uint64_t purge();
  uint64_t purge(const std::string& match); // could be $ terminated. Is not a dnsname!
  uint64_t purgeExact(const DNSName& qname); // no wildcard matching here
  uint64_t purgeExact(const std::string& view, const DNSName& qname); // same as above, but in the given view
  uint64_t purgeView(const std::string& view);

  uint64_t size() const { return *d_statnumentries; };

  void setMaxEntries(uint64_t maxEntries) 
  {
    d_maxEntries = maxEntries;
    {
      auto cache = d_cache.write_lock();
      for (auto& iter : *cache) {
        auto* map = iter.second.get();
      
        for (auto& shard : *map) {
          shard.reserve(maxEntries / map->size());
        }
      }
    }
  }
  void setTTL(uint32_t ttl)
  {
    d_ttl = ttl;
  }
  bool enabled() const
  {
    return (d_ttl > 0);
  }
private:

  struct CacheEntry
  {
    mutable string query;
    mutable string value;
    DNSName qname;

    mutable time_t created{0};
    mutable time_t ttd{0};
    uint32_t hash{0};
    uint16_t qtype{0};
    bool tcp{false};
  };

  struct HashTag{};
  struct NameTag{};
  struct SequencedTag{};
  typedef multi_index_container<
    CacheEntry,
    indexed_by <
      hashed_non_unique<tag<HashTag>, member<CacheEntry,uint32_t,&CacheEntry::hash> >,
      ordered_non_unique<tag<NameTag>, member<CacheEntry,DNSName,&CacheEntry::qname>, CanonDNSNameCompare >,
      /* Note that this sequence holds 'least recently inserted or replaced', not least recently used.
         Making it a LRU would require taking a write-lock when fetching from the cache, making the RW-lock inefficient compared to a mutex */
      sequenced<tag<SequencedTag>>
      >
    > cmap_t;

  struct MapCombo
  {
    MapCombo() = default;
    ~MapCombo() = default;
    MapCombo(const MapCombo&) = delete; 
    MapCombo& operator=(const MapCombo&) = delete;

    void reserve(size_t numberOfEntries);

    SharedLockGuarded<cmap_t> d_map;
  };

  using cache_t = std::unordered_map<std::string, std::unique_ptr<vector<MapCombo>>>;
  SharedLockGuarded<cache_t> d_cache;
  static MapCombo& getMap(const std::unique_ptr<vector<MapCombo>>& map, const DNSName& name)
  {
    return (*map)[name.hash() % map->size()];
  }

  cache_t::iterator createViewMap(cache_t& cache, const std::string& view);
  static bool entryMatches(cmap_t::index<HashTag>::type::iterator& iter, const std::string& query, const DNSName& qname, uint16_t qtype, bool tcp);
  static bool getEntryLocked(const cmap_t& map, const std::string& query, uint32_t hash, const DNSName &qname, uint16_t qtype, bool tcp, time_t now, string& value);
  void cleanupIfNeeded();

  AtomicCounter d_ops{0};
  AtomicCounter *d_statnumhit;
  AtomicCounter *d_statnummiss;
  AtomicCounter *d_statnumentries;

  uint64_t d_maxEntries{0};
  size_t d_mapscount;
  time_t d_lastclean; // doesn't need to be atomic
  unsigned long d_nextclean{4096};
  unsigned int d_cleaninterval{4096};
  uint32_t d_ttl{0};
  bool d_cleanskipped{false};

  static const unsigned int s_mincleaninterval=1000, s_maxcleaninterval=300000;
};
