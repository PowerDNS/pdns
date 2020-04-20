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
#include <set>
#include <mutex>
#include "dns.hh"
#include "qtype.hh"
#include "misc.hh"
#include "dnsname.hh"
#include <iostream>
#include "dnsrecords.hh"
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/version.hpp>
#include "iputils.hh"
#include "validate.hh"
#undef max

#include "namespaces.hh"
using namespace ::boost::multi_index;

class MemRecursorCache : public boost::noncopyable //  : public RecursorCache
{
public:
  MemRecursorCache(size_t mapsCount = 1024);
  ~MemRecursorCache();

  size_t size();
  size_t bytes();
  pair<uint64_t,uint64_t> stats();
  size_t ecsIndexSize();

  typedef boost::optional<std::string> OptTag;

  int32_t get(time_t, const DNSName &qname, const QType& qt, bool requireAuth, vector<DNSRecord>* res, const ComboAddress& who, const OptTag& routingTag = boost::none, vector<std::shared_ptr<RRSIGRecordContent>>* signatures=nullptr, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs=nullptr, bool* variable=nullptr, vState* state=nullptr, bool* wasAuth=nullptr);

  void replace(time_t, const DNSName &qname, const QType& qt,  const vector<DNSRecord>& content, const vector<shared_ptr<RRSIGRecordContent>>& signatures, const std::vector<std::shared_ptr<DNSRecord>>& authorityRecs, bool auth, boost::optional<Netmask> ednsmask=boost::none, const OptTag& routingTag = boost::none, vState state=Indeterminate);

  void doPrune(size_t keep);
  uint64_t doDump(int fd);

  size_t doWipeCache(const DNSName& name, bool sub, uint16_t qtype=0xffff);
  bool doAgeCache(time_t now, const DNSName& name, uint16_t qtype, uint32_t newTTL);
  bool updateValidationStatus(time_t now, const DNSName &qname, const QType& qt, const ComboAddress& who, const OptTag& routingTag, bool requireAuth, vState newState, boost::optional<time_t> capTTD);

  std::atomic<uint64_t> cacheHits{0}, cacheMisses{0};

private:

  struct CacheEntry
  {
    CacheEntry(const boost::tuple<DNSName, uint16_t, OptTag, Netmask>& key, bool auth):
      d_qname(key.get<0>()), d_netmask(key.get<3>().getNormalized()), d_rtag(key.get<2>()), d_state(Indeterminate), d_ttd(0), d_qtype(key.get<1>()), d_auth(auth)
    {
    }

    typedef vector<std::shared_ptr<DNSRecordContent>> records_t;
    time_t getTTD() const
    {
      return d_ttd;
    }

    records_t d_records;
    std::vector<std::shared_ptr<RRSIGRecordContent>> d_signatures;
    std::vector<std::shared_ptr<DNSRecord>> d_authorityRecs;
    DNSName d_qname;
    Netmask d_netmask;
    OptTag d_rtag;
    mutable vState d_state;
    mutable time_t d_ttd;
    uint16_t d_qtype;
    bool d_auth;
  };

  /* The ECS Index (d_ecsIndex) keeps track of whether there is any ECS-specific
     entry for a given (qname,qtype) entry in the cache (d_map), and if so
     provides a NetmaskTree of those ECS entries.
     This allows figuring out quickly if we should look for an entry
     specific to the requestor IP, and if so which entry is the most
     specific one.
     Keeping the entries in the regular cache is currently necessary
     because of the way we manage expired entries (moving them to the
     front of the expunge queue to be deleted at a regular interval).
  */
  class ECSIndexEntry
  {
  public:
    ECSIndexEntry(const DNSName& qname, uint16_t qtype): d_nmt(), d_qname(qname), d_qtype(qtype)
    {
    }

    Netmask lookupBestMatch(const ComboAddress& addr) const
    {
      const auto best = d_nmt.lookup(addr);
      if (best != nullptr) {
        return best->first;
      }

      return Netmask();
    }

    void addMask(const Netmask& nm) const
    {
      d_nmt.insert(nm).second = true;
    }

    void removeNetmask(const Netmask& nm) const
    {
      d_nmt.erase(nm);
    }

    bool isEmpty() const
    {
      return d_nmt.empty();
    }

    mutable NetmaskTree<bool> d_nmt;
    DNSName d_qname;
    uint16_t d_qtype;
  };

  struct HashedTag {};
  struct SequencedTag {};
  struct NameAndRTagOnlyHashedTag {};
  struct OrderedTag {};

  typedef multi_index_container<
    CacheEntry,
    indexed_by <
                ordered_unique<tag<OrderedTag>,
                        composite_key<
                                CacheEntry,
                                member<CacheEntry,DNSName,&CacheEntry::d_qname>,
                                member<CacheEntry,uint16_t,&CacheEntry::d_qtype>,
                                member<CacheEntry,OptTag,&CacheEntry::d_rtag>,
                                member<CacheEntry,Netmask,&CacheEntry::d_netmask>
                          >,
                               composite_key_compare<CanonDNSNameCompare, std::less<uint16_t>, std::less<OptTag>, std::less<Netmask> >
                >,
                sequenced<tag<SequencedTag> >,
                hashed_non_unique<tag<NameAndRTagOnlyHashedTag>,
                    composite_key<
                      CacheEntry,
                      member<CacheEntry,DNSName,&CacheEntry::d_qname>,
                      member<CacheEntry,OptTag,&CacheEntry::d_rtag>
                    >
                >
               >
  > cache_t;

  typedef MemRecursorCache::cache_t::index<MemRecursorCache::OrderedTag>::type::iterator OrderedTagIterator_t;
  typedef MemRecursorCache::cache_t::index<MemRecursorCache::NameAndRTagOnlyHashedTag>::type::iterator NameAndRTagOnlyHashedTagIterator_t;

  typedef multi_index_container<
    ECSIndexEntry,
    indexed_by <
      hashed_unique <tag<HashedTag>,
        composite_key<
          ECSIndexEntry,
          member<ECSIndexEntry,DNSName,&ECSIndexEntry::d_qname>,
          member<ECSIndexEntry,uint16_t,&ECSIndexEntry::d_qtype>
        >
      >,
      ordered_unique<tag<OrderedTag>,
        composite_key<
          ECSIndexEntry,
          member<ECSIndexEntry,DNSName,&ECSIndexEntry::d_qname>,
          member<ECSIndexEntry,uint16_t,&ECSIndexEntry::d_qtype>
        >,
        composite_key_compare<CanonDNSNameCompare, std::less<uint16_t> >
      >
    >
  > ecsIndex_t;

  typedef std::pair<NameAndRTagOnlyHashedTagIterator_t, NameAndRTagOnlyHashedTagIterator_t> Entries;
  
  struct MapCombo
  {
    MapCombo() {}
    MapCombo(const MapCombo &) = delete;
    MapCombo & operator=(const MapCombo &) = delete;
    cache_t d_map;
    ecsIndex_t d_ecsIndex;
    DNSName d_cachedqname;
    OptTag d_cachedrtag;
    Entries d_cachecache;
    std::mutex mutex;
    bool d_cachecachevalid{false};
    std::atomic<uint64_t> d_entriesCount{0};
    uint64_t d_contended_count{0};
    uint64_t d_acquired_count{0};
  };

  vector<MapCombo> d_maps;
  MapCombo& getMap(const DNSName &qname)
  {
    return d_maps[qname.hash() % d_maps.size()];
  }

  bool entryMatches(OrderedTagIterator_t& entry, uint16_t qt, bool requireAuth, const ComboAddress& who);
  Entries getEntries(MapCombo& map, const DNSName &qname, const QType& qt, const OptTag& rtag);
  cache_t::const_iterator getEntryUsingECSIndex(MapCombo& map, time_t now, const DNSName &qname, uint16_t qtype, bool requireAuth, const ComboAddress& who);
  int32_t handleHit(MapCombo& map, OrderedTagIterator_t& entry, const DNSName& qname, vector<DNSRecord>* res, vector<std::shared_ptr<RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, vState* state, bool* wasAuth);

public:
  struct lock {
    lock(MapCombo& map) : m(map.mutex)
    {
      if (!m.try_lock()) {
        m.lock();
        map.d_contended_count++;
      }
      map.d_acquired_count++;
    }
    ~lock() {
      m.unlock();
    }
  private:
    std::mutex &m;
  };

  void preRemoval(const CacheEntry& entry)
  {
    if (entry.d_netmask.empty()) {
      return;
    }

    auto key = tie(entry.d_qname, entry.d_qtype);
    auto& map = getMap(entry.d_qname);
    auto ecsIndexEntry = map.d_ecsIndex.find(key);
    if (ecsIndexEntry != map.d_ecsIndex.end()) {
      ecsIndexEntry->removeNetmask(entry.d_netmask);
      if (ecsIndexEntry->isEmpty()) {
        map.d_ecsIndex.erase(ecsIndexEntry);
      }
    }
  }
};

namespace boost {
  size_t hash_value(const MemRecursorCache::OptTag& rtag);
}
