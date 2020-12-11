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

#include <mutex>
#include <vector>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/optional.hpp>
#include "dnsparser.hh"
#include "dnsname.hh"
#include "dns.hh"
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
typedef struct
{
  vector<DNSRecord> records;
  vector<DNSRecord> signatures;
} recordsAndSignatures;

class NegCache : public boost::noncopyable
{
public:
  NegCache(size_t mapsCount = 1024);
  ~NegCache();

  struct NegCacheEntry
  {
    recordsAndSignatures authoritySOA; // The upstream SOA record and RRSIGs
    recordsAndSignatures DNSSECRecords; // The upstream NSEC(3) and RRSIGs
    DNSName d_name; // The denied name
    DNSName d_auth; // The denying name (aka auth)
    mutable time_t d_ttd; // Timestamp when this entry should die
    mutable vState d_validationState{vState::Indeterminate};
    QType d_qtype; // The denied type
    time_t getTTD() const
    {
      return d_ttd;
    };
  };

  void add(const NegCacheEntry& ne);
  void updateValidationStatus(const DNSName& qname, const QType& qtype, const vState newState, boost::optional<time_t> capTTD);
  bool get(const DNSName& qname, const QType& qtype, const struct timeval& now, NegCacheEntry& ne, bool typeMustMatch = false);
  bool getRootNXTrust(const DNSName& qname, const struct timeval& now, NegCacheEntry& ne);
  size_t count(const DNSName& qname) const;
  size_t count(const DNSName& qname, const QType qtype) const;
  void prune(size_t maxEntries);
  void clear();
  size_t dumpToFile(FILE* fd, const struct timeval& now) const;
  size_t wipe(const DNSName& name, bool subtree = false);
  size_t size() const;

  void preRemoval(const NegCacheEntry& entry)
  {
  }

private:
  struct CompositeKey
  {
  };
  struct SequenceTag
  {
  };
  typedef boost::multi_index_container<
    NegCacheEntry,
    indexed_by<
      ordered_unique<tag<CompositeKey>,
        composite_key<
          NegCacheEntry,
          member<NegCacheEntry, DNSName, &NegCacheEntry::d_name>,
          member<NegCacheEntry, QType, &NegCacheEntry::d_qtype>>,
        composite_key_compare<
          CanonDNSNameCompare, std::less<QType>>>,
      sequenced<tag<SequenceTag>>,
      hashed_non_unique<tag<NegCacheEntry>,
        member<NegCacheEntry, DNSName, &NegCacheEntry::d_name>>>>
    negcache_t;

  struct MapCombo
  {
    MapCombo() { }
    MapCombo(const MapCombo&) = delete;
    MapCombo& operator=(const MapCombo&) = delete;
    negcache_t d_map;
    mutable std::mutex mutex;
    std::atomic<uint64_t> d_entriesCount{0};
    mutable uint64_t d_contended_count{0};
    mutable uint64_t d_acquired_count{0};
    void invalidate() {}
  };

  vector<MapCombo> d_maps;

  MapCombo& getMap(const DNSName& qname)
  {
    return d_maps[qname.hash() % d_maps.size()];
  }
  const MapCombo& getMap(const DNSName& qname) const
  {
    return d_maps[qname.hash() % d_maps.size()];
  }

public:
  struct lock
  {
    lock(const MapCombo& map) :
      m(map.mutex)
    {
      if (!m.try_lock()) {
        m.lock();
        map.d_contended_count++;
      }
      map.d_acquired_count++;
    }
    ~lock()
    {
      m.unlock();
    }

  private:
    std::mutex& m;
  };
};
