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
#ifndef AUTH_PACKETCACHE_HH
#define AUTH_PACKETCACHE_HH

#include <string>
#include <map>
#include "dns.hh"
#include <boost/version.hpp>
#include "namespaces.hh"
using namespace ::boost::multi_index;

#include <boost/multi_index/hashed_index.hpp> 

#include "dnspacket.hh"
#include "lock.hh"
#include "packetcache.hh"

/** This class performs 'whole packet caching'. Feed it a question packet and it will
    try to find an answer. If you have an answer, insert it to have it cached for later use. 
    Take care not to replace existing cache entries. While this works, it is wasteful. Only
    insert packets that where not found by get()

    Locking! 

    The cache itself is protected by a read/write lock. Because deleting is a two step process, which 
    first marks and then sweeps, a second lock is present to prevent simultaneous inserts and deletes.
*/

class AuthPacketCache : public PacketCache
{
public:
  AuthPacketCache(size_t mapsCount=1024);
  ~AuthPacketCache();

  void insert(DNSPacket& q, DNSPacket& r, uint32_t maxTTL);  //!< We copy the contents of *p into our cache. Do not needlessly call this to insert questions already in the cache as it wastes resources

  bool get(DNSPacket& p, DNSPacket& q); //!< You need to spoof in the right ID with the DNSPacket.spoofID() method.

  void cleanup(); //!< force the cache to preen itself from expired packets
  uint64_t purge();
  uint64_t purge(const std::string& match); // could be $ terminated. Is not a dnsname!
  uint64_t purgeExact(const DNSName& qname); // no wildcard matching here

  uint64_t size() const { return *d_statnumentries; };

  void setMaxEntries(uint64_t maxEntries) 
  {
    d_maxEntries = maxEntries;
  }
  void setTTL(uint32_t ttl)
  {
    d_ttl = ttl;
  }
  bool enabled()
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
  struct SequenceTag{};
  typedef multi_index_container<
    CacheEntry,
    indexed_by <
      hashed_non_unique<tag<HashTag>, member<CacheEntry,uint32_t,&CacheEntry::hash> >,
      ordered_non_unique<tag<NameTag>, member<CacheEntry,DNSName,&CacheEntry::qname>, CanonDNSNameCompare >,
      sequenced<tag<SequenceTag>>
      >
    > cmap_t;

  struct MapCombo
  {
    pthread_rwlock_t d_mut;    
    cmap_t d_map;
  };

  vector<MapCombo> d_maps;
  MapCombo& getMap(const DNSName& name)
  {
    return d_maps[name.hash() % d_maps.size()];
  }

  static bool entryMatches(cmap_t::index<HashTag>::type::iterator& iter, const std::string& query, const DNSName& qname, uint16_t qtype, bool tcp);
  bool getEntryLocked(cmap_t& map, const std::string& query, uint32_t hash, const DNSName &qname, uint16_t qtype, bool tcp, time_t now, string& entry);
  void cleanupIfNeeded();

  AtomicCounter d_ops{0};
  AtomicCounter *d_statnumhit;
  AtomicCounter *d_statnummiss;
  AtomicCounter *d_statnumentries;

  uint64_t d_maxEntries{0};
  time_t d_lastclean; // doesn't need to be atomic
  unsigned long d_nextclean{4096};
  unsigned int d_cleaninterval{4096};
  uint32_t d_ttl{0};
  bool d_cleanskipped{false};

  static const unsigned int s_mincleaninterval=1000, s_maxcleaninterval=300000;
};

#endif /* AUTH_PACKETCACHE_HH */
