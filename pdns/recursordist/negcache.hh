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

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include "dnsparser.hh"
#include "dnsname.hh"
#include "dns.hh"
#include "lock.hh"
#include "stat_t.hh"
#include "validate.hh"

using namespace ::boost::multi_index;

/* FIXME should become part of the normal cache (I think) and should become more like
 * struct {
 *   vector<DNSRecord> records;
 *   vector<DNSRecord> signatures;
 * } recsig_t;
 *
 * typedef vector<recsig_t> recordsAndSignatures;
 */
struct recordsAndSignatures
{
  vector<DNSRecord> records;
  vector<DNSRecord> signatures;
};

class NegCache : public boost::noncopyable
{
public:
  NegCache(size_t mapsCount = 128);

  // For a description on how ServeStale works, see recursor_cache.cc, the general structure is the same.
  // The number of times a stale cache entry is extended
  static uint16_t s_maxServedStaleExtensions;
  // The time a stale cache entry is extended
  static constexpr uint32_t s_serveStaleExtensionPeriod = 30;

  struct NegCacheEntry
  {
    recordsAndSignatures authoritySOA; // The upstream SOA record and RRSIGs
    recordsAndSignatures DNSSECRecords; // The upstream NSEC(3) and RRSIGs
    DNSName d_name; // The denied name
    DNSName d_auth; // The denying name (aka auth)
    mutable time_t d_ttd; // Timestamp when this entry should die
    uint32_t d_orig_ttl;
    mutable uint16_t d_servedStale{0};
    mutable vState d_validationState{vState::Indeterminate};
    QType d_qtype; // The denied type

    bool isStale(time_t now) const
    {
      // We like to keep things in cache when we (potentially) should serve stale
      if (s_maxServedStaleExtensions > 0) {
        return d_ttd + static_cast<time_t>(s_maxServedStaleExtensions) * std::min(s_serveStaleExtensionPeriod, d_orig_ttl) < now;
      }
      return d_ttd < now;
    };

    bool isEntryUsable(time_t now, bool serveStale) const
    {
      // When serving stale, we consider expired records
      return d_ttd > now || serveStale || d_servedStale != 0;
    }
  };

  void add(const NegCacheEntry& negEntry);
  void updateValidationStatus(const DNSName& qname, QType qtype, vState newState, std::optional<time_t> capTTD);
  bool get(const DNSName& qname, QType qtype, const struct timeval& now, NegCacheEntry& negEntry, bool typeMustMatch = false, bool serveStale = false, bool refresh = false);
  bool getRootNXTrust(const DNSName& qname, const struct timeval& now, NegCacheEntry& negEntry, bool serveStale, bool refresh);
  size_t count(const DNSName& qname);
  size_t count(const DNSName& qname, QType qtype);
  void prune(time_t now, size_t maxEntries);
  void clear();
  size_t doDump(int fileDesc, size_t maxCacheEntries, time_t now = time(nullptr));
  size_t wipe(const DNSName& name, bool subtree = false);
  size_t wipeTyped(const DNSName& name, QType qtype);
  [[nodiscard]] size_t size() const;

private:
  struct CompositeKey
  {
  };
  struct SequenceTag
  {
  };
  using negcache_t = boost::multi_index_container<
    NegCacheEntry,
    indexed_by<
      ordered_unique<tag<CompositeKey>,
                     composite_key<
                       NegCacheEntry,
                       member<NegCacheEntry, DNSName, &NegCacheEntry::d_name>,
                       member<NegCacheEntry, QType, &NegCacheEntry::d_qtype>>,
                     composite_key_compare<
                       CanonDNSNameCompare, std::less<>>>,
      sequenced<tag<SequenceTag>>,
      hashed_non_unique<tag<NegCacheEntry>,
                        member<NegCacheEntry, DNSName, &NegCacheEntry::d_name>>>>;

  static void updateStaleEntry(time_t now, negcache_t::iterator& entry, QType qtype);

  struct MapCombo
  {
    MapCombo() = default;
    MapCombo(const MapCombo&) = delete;
    MapCombo& operator=(const MapCombo&) = delete;
    ~MapCombo() = default;
    MapCombo(MapCombo&&) = delete;
    MapCombo& operator=(MapCombo&&) = delete;
    struct LockedContent
    {
      negcache_t d_map;
      uint64_t d_contended_count{0};
      uint64_t d_acquired_count{0};
      void invalidate() {}
      void preRemoval(const NegCacheEntry& /* entry */) {}
    };

    LockGuardedTryHolder<MapCombo::LockedContent> lock()
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
  [[nodiscard]] const MapCombo& getMap(const DNSName& qname) const
  {
    return d_maps.at(qname.hash() % d_maps.size());
  }
};
