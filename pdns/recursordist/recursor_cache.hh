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
#include "dns.hh"
#include "qtype.hh"
#include "misc.hh"
#include "dnsname.hh"
#include "dnsrecords.hh"
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/version.hpp>
#include "iputils.hh"
#include "lock.hh"
#include "stat_t.hh"
#include "validate.hh"
#undef max

#include "namespaces.hh"
using namespace ::boost::multi_index;

class MemRecursorCache : public boost::noncopyable //  : public RecursorCache
{
public:
  MemRecursorCache(size_t mapsCount = 1024);

  // The number of times a stale cache entry is extended
  static uint16_t s_maxServedStaleExtensions;
  // The time a stale cache entry is extended
  static constexpr uint32_t s_serveStaleExtensionPeriod = 30;

  // Maximum size of RRSet we are willing to cache. If the RRSet is larger, we do create an entry,
  // but mark it as too big. Subsequent gets will cause an ImmediateServFailException to be thrown.
  static uint16_t s_maxRRSetSize;
  static bool s_limitQTypeAny;

  [[nodiscard]] size_t size() const;
  [[nodiscard]] size_t bytes();
  [[nodiscard]] pair<uint64_t, uint64_t> stats();
  [[nodiscard]] size_t ecsIndexSize();

  size_t getRecordSets(size_t perShard, size_t maxSize, std::string& ret);
  size_t putRecordSets(const std::string& pbuf);

  using OptTag = boost::optional<std::string>;

  using Flags = uint8_t;
  static constexpr Flags None = 0;
  static constexpr Flags RequireAuth = 1 << 0;
  static constexpr Flags Refresh = 1 << 1;
  static constexpr Flags ServeStale = 1 << 2;

  // The type used to pass auth record data to replace(); If the vector is non-empty, the cache will
  // store a shared pointer to the copied data. The shared pointer will be returned by get().  There
  // are optimizations: an empty vector will be stored as a nullptr, but get() will return a pointer
  // to an already existing empty vector in that case, this is more convenient for the caller, since
  // it avoid checking for nullptr, just iterate as for the non-empty case.
  //
  // get() will return a shared vector to a const vector of shared pointers. Only a single shared
  // pointer gets copied, while earlier code would copy all shared pointer in the vector.
  //
  // In the current SyncRes code, AuthRecs never get appended to a non-empty vector while SigRecs do
  // get appended in some cases; the handleHit() code will take measures. In the future we might
  // want a more specialized data structure than a vector, it would require another level of
  // indirection though, so for now we construct a new shared vector if appending is needed. See
  // handleHit() for details.
  using AuthRecsVec = std::vector<DNSRecord>;
  using AuthRecs = std::shared_ptr<const AuthRecsVec>; // const to avoid modifying the vector, which would be bad for shared data
  const static AuthRecs s_emptyAuthRecs;

  // Use same setup as AuthRecs.
  using SigRecsVec = std::vector<std::shared_ptr<const RRSIGRecordContent>>;
  using SigRecs = std::shared_ptr<const SigRecsVec>; // Also const as it is shared
  const static SigRecs s_emptySigRecs;

  struct Extra
  {
    ComboAddress d_address;
    bool d_tcp{false};
  };

  [[nodiscard]] time_t get(time_t, const DNSName& qname, QType qtype, Flags flags, vector<DNSRecord>* res, const ComboAddress& who, const OptTag& routingTag = boost::none, SigRecs* signatures = nullptr, AuthRecs* authorityRecs = nullptr, bool* variable = nullptr, vState* state = nullptr, bool* wasAuth = nullptr, DNSName* fromAuthZone = nullptr, Extra* extra = nullptr);

  void replace(time_t, const DNSName& qname, QType qtype, const vector<DNSRecord>& content, const SigRecsVec& signatures, const AuthRecsVec& authorityRecs, bool auth, const DNSName& authZone, const std::optional<Netmask>& ednsmask = std::nullopt, const OptTag& routingTag = boost::none, vState state = vState::Indeterminate, const std::optional<Extra>& extra = std::nullopt, bool refresh = false, time_t ttl_time = time(nullptr));

  void doPrune(time_t now, size_t keep);
  uint64_t doDump(int fileDesc, size_t maxCacheEntries);

  size_t doWipeCache(const DNSName& name, bool sub, QType qtype = 0xffff);
  bool doAgeCache(time_t now, const DNSName& name, QType qtype, uint32_t newTTL);
  bool updateValidationStatus(time_t now, const DNSName& qname, QType qtype, const ComboAddress& who, const OptTag& routingTag, bool requireAuth, vState newState, std::optional<time_t> capTTD);

  static void resetStaticsForTests();

  [[nodiscard]] auto getCacheHits() const
  {
    return cacheHits.load();
  }
  [[nodiscard]] auto getCacheMisses() const
  {
    return cacheMisses.load();
  }

  void incCacheHits()
  {
    ++cacheHits;
  }
  void incCacheMisses()
  {
    ++cacheMisses;
  }

private:
  pdns::stat_t cacheHits{0}, cacheMisses{0};

  struct CacheEntry
  {
    CacheEntry(const std::tuple<DNSName, QType, OptTag, Netmask>& key, bool auth) :
      d_rtag(std::get<2>(key)),
      d_netmask(std::get<3>(key).getNormalized()),
      d_qname(std::get<0>(key)),
      d_qtype(std::get<1>(key)),
      d_auth(auth)
    {
    }

    using records_t = vector<std::shared_ptr<const DNSRecordContent>>;

    bool isStale(time_t now) const
    {
      // We like to keep things in cache when we (potentially) should serve stale
      if (s_maxServedStaleExtensions > 0) {
        return d_ttd + static_cast<time_t>(s_maxServedStaleExtensions) * std::min(s_serveStaleExtensionPeriod, d_orig_ttl) < now;
      }
      return d_ttd < now;
    }

    bool isEntryUsable(time_t now, bool serveStale) const
    {
      // When serving stale, we consider expired records
      return d_ttd > now || serveStale || d_servedStale != 0;
    }

    bool shouldReplace(time_t now, bool auth, vState state, bool refresh);

    [[nodiscard]] size_t sizeEstimate() const;
    [[nodiscard]] size_t authRecsSizeEstimate() const;
    [[nodiscard]] size_t sigRecsSizeEstimate() const;

    OptTag d_rtag; // 40 (sizes for typical 64 bit system)
    Netmask d_netmask; // 36
    ComboAddress d_from; // 28
    records_t d_records; // 24
    DNSName d_qname; // 24
    DNSName d_authZone; // 24
    SigRecs d_signatures; // 16
    AuthRecs d_authorityRecs; // 16
    mutable time_t d_ttd{0}; // 8
    uint32_t d_orig_ttl{0}; // 4
    mutable uint16_t d_servedStale{0}; // 2
    QType d_qtype; // 2
    mutable vState d_state{vState::Indeterminate}; // 1
    bool d_auth; // 1
    mutable bool d_submitted{false}; // 1, whether this entry has been queued for refetch
    bool d_tooBig{false}; // 1
    bool d_tcp{false}; // 1 was entry received over TCP?
  };

  bool replace(CacheEntry&& entry);
  // Using templates to avoid exposing protozero types in this header file
  template <typename T>
  bool putRecordSet(T&);
  template <typename T, typename U>
  void getRecordSet(T&, U);

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
    ECSIndexEntry(DNSName qname, QType qtype) :
      d_qname(std::move(qname)), d_qtype(qtype)
    {
    }

    [[nodiscard]] Netmask lookupBestMatch(const ComboAddress& addr) const
    {
      const auto* best = d_nmt.lookup(addr);
      if (best != nullptr) {
        return best->first;
      }

      return {};
    }

    void addMask(const Netmask& netmask) const
    {
      d_nmt.insert(netmask).second = true;
    }

    void removeNetmask(const Netmask& netmask) const
    {
      d_nmt.erase(netmask);
    }

    [[nodiscard]] bool isEmpty() const
    {
      return d_nmt.empty();
    }

    mutable NetmaskTree<bool> d_nmt;
    DNSName d_qname;
    QType d_qtype;
  };

  struct HashedTag
  {
  };
  struct SequencedTag
  {
  };
  struct NameAndRTagOnlyHashedTag
  {
  };
  struct OrderedTag
  {
  };

  using cache_t = multi_index_container<
    CacheEntry,
    indexed_by<
      ordered_unique<tag<OrderedTag>,
                     composite_key<
                       CacheEntry,
                       member<CacheEntry, DNSName, &CacheEntry::d_qname>,
                       member<CacheEntry, QType, &CacheEntry::d_qtype>,
                       member<CacheEntry, OptTag, &CacheEntry::d_rtag>,
                       member<CacheEntry, Netmask, &CacheEntry::d_netmask>>,
                     composite_key_compare<CanonDNSNameCompare, std::less<>, std::less<>, std::less<>>>,
      sequenced<tag<SequencedTag>>,
      hashed_non_unique<tag<NameAndRTagOnlyHashedTag>,
                        composite_key<
                          CacheEntry,
                          member<CacheEntry, DNSName, &CacheEntry::d_qname>,
                          member<CacheEntry, OptTag, &CacheEntry::d_rtag>>>>>;

  using OrderedTagIterator_t = MemRecursorCache::cache_t::index<MemRecursorCache::OrderedTag>::type::iterator;
  using NameAndRTagOnlyHashedTagIterator_t = MemRecursorCache::cache_t::index<MemRecursorCache::NameAndRTagOnlyHashedTag>::type::iterator;

  using ecsIndex_t = multi_index_container<
    ECSIndexEntry,
    indexed_by<
      hashed_unique<tag<HashedTag>,
                    composite_key<
                      ECSIndexEntry,
                      member<ECSIndexEntry, DNSName, &ECSIndexEntry::d_qname>,
                      member<ECSIndexEntry, QType, &ECSIndexEntry::d_qtype>>>,
      ordered_unique<tag<OrderedTag>,
                     composite_key<
                       ECSIndexEntry,
                       member<ECSIndexEntry, DNSName, &ECSIndexEntry::d_qname>,
                       member<ECSIndexEntry, QType, &ECSIndexEntry::d_qtype>>,
                     composite_key_compare<CanonDNSNameCompare, std::less<>>>>>;

  using Entries = std::pair<NameAndRTagOnlyHashedTagIterator_t, NameAndRTagOnlyHashedTagIterator_t>;

  struct MapCombo
  {
    MapCombo() = default;
    ~MapCombo() = default;
    MapCombo(const MapCombo&) = delete;
    MapCombo& operator=(const MapCombo&) = delete;
    MapCombo(MapCombo&&) = delete;
    MapCombo& operator=(MapCombo&&) = delete;

    struct LockedContent
    {
      cache_t d_map;
      ecsIndex_t d_ecsIndex;
      DNSName d_cachedqname;
      OptTag d_cachedrtag;
      Entries d_cachecache;
      uint64_t d_contended_count{0};
      uint64_t d_acquired_count{0};
      bool d_cachecachevalid{false};

      void invalidate()
      {
        d_cachecachevalid = false;
      }

      void preRemoval(const CacheEntry& entry)
      {
        if (entry.d_netmask.empty()) {
          return;
        }

        auto key = std::tie(entry.d_qname, entry.d_qtype);
        auto ecsIndexEntry = d_ecsIndex.find(key);
        if (ecsIndexEntry != d_ecsIndex.end()) {
          ecsIndexEntry->removeNetmask(entry.d_netmask);
          if (ecsIndexEntry->isEmpty()) {
            d_ecsIndex.erase(ecsIndexEntry);
          }
        }
      }
    };

    LockGuardedTryHolder<LockedContent> lock()
    {
      auto locked = d_content.try_lock();
      if (!locked.owns_lock()) {
        locked.lock();
        ++locked->d_contended_count;
      }
      ++locked->d_acquired_count;
      return locked;
    }

    [[nodiscard]] auto getEntriesCount() const
    {
      return d_entriesCount.load();
    }

    void incEntriesCount()
    {
      ++d_entriesCount;
    }

    void decEntriesCount()
    {
      --d_entriesCount;
    }

    void clearEntriesCount()
    {
      d_entriesCount = 0;
    }

  private:
    LockGuarded<LockedContent> d_content;
    pdns::stat_t d_entriesCount{0};
  };

  vector<MapCombo> d_maps;
  MapCombo& getMap(const DNSName& qname)
  {
    return d_maps.at(qname.hash() % d_maps.size());
  }

  static time_t fakeTTD(OrderedTagIterator_t& entry, const DNSName& qname, QType qtype, time_t ret, time_t now, uint32_t origTTL, bool refresh);

  static bool entryMatches(OrderedTagIterator_t& entry, QType qtype, bool requireAuth, const ComboAddress& who);
  static Entries getEntries(MapCombo::LockedContent& map, const DNSName& qname, QType qtype, const OptTag& rtag);
  static cache_t::const_iterator getEntryUsingECSIndex(MapCombo::LockedContent& map, time_t now, const DNSName& qname, QType qtype, bool requireAuth, const ComboAddress& who, bool serveStale);

  static time_t handleHit(time_t now, MapCombo::LockedContent& content, OrderedTagIterator_t& entry, const DNSName& qname, uint32_t& origTTL, vector<DNSRecord>* res, SigRecs* signatures, AuthRecs* authorityRecs, bool* variable, std::optional<vState>& state, bool* wasAuth, DNSName* authZone, Extra* extra);
  static void updateStaleEntry(time_t now, OrderedTagIterator_t& entry);
  static void handleServeStaleBookkeeping(time_t, bool, OrderedTagIterator_t&);
};

namespace boost
{
size_t hash_value(const MemRecursorCache::OptTag& rtag);
}
