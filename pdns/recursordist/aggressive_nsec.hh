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

#include <atomic>
#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>

using namespace ::boost::multi_index;

#include "base32.hh"
#include "dnsname.hh"
#include "dnsrecords.hh"
#include "lock.hh"
#include "stat_t.hh"
#include "logger.hh"
#include "validate.hh"
#include "recursor_cache.hh"

class AggressiveNSECCache
{
public:
  static constexpr uint8_t s_default_maxNSEC3CommonPrefix = 10;
  static uint64_t s_nsec3DenialProofMaxCost;
  static uint8_t s_maxNSEC3CommonPrefix;

  AggressiveNSECCache(uint64_t entries) :
    d_maxEntries(entries)
  {
  }

  void setMaxEntries(uint64_t number)
  {
    d_maxEntries = number;
  }

  static bool nsec3Disabled()
  {
    return s_maxNSEC3CommonPrefix == 0;
  }

  void insertNSEC(const DNSName& zone, const DNSName& owner, const DNSRecord& record, const std::vector<std::shared_ptr<const RRSIGRecordContent>>& signatures, bool nsec3, const DNSName& qname = g_rootdnsname, QType qtype = QType::ENT);
  bool getDenial(time_t, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, const ComboAddress& who, const std::optional<std::string>& routingTag, bool doDNSSEC, pdns::validation::ValidationContext& validationContext, const OptLog& log = std::nullopt);

  void removeZoneInfo(const DNSName& zone, bool subzones);

  uint64_t getEntriesCount() const
  {
    return d_entriesCount;
  }

  uint64_t getNSECHits() const
  {
    return d_nsecHits;
  }

  uint64_t getNSEC3Hits() const
  {
    return d_nsec3Hits;
  }

  uint64_t getNSECWildcardHits() const
  {
    return d_nsecWildcardHits;
  }

  uint64_t getNSEC3WildcardHits() const
  {
    return d_nsec3WildcardHits;
  }

  // exported for unit test purposes
  static bool isSmallCoveringNSEC3(const DNSName& owner, const std::string& nextHash);

  void prune(time_t now);
  size_t dumpToFile(pdns::UniqueFilePtr& filePtr, const struct timeval& now);

private:
  struct ZoneEntry
  {
    ZoneEntry(const DNSName& zone) :
      d_zone(zone)
    {
    }

    ZoneEntry(const DNSName& zone, const std::string& salt, uint16_t iterations, bool nsec3) :
      d_zone(zone), d_salt(salt), d_iterations(iterations), d_nsec3(nsec3)
    {
    }

    struct HashedTag
    {
    };
    struct SequencedTag
    {
    };
    struct OrderedTag
    {
    };

    struct CacheEntry
    {
      std::shared_ptr<const DNSRecordContent> d_record;
      std::vector<std::shared_ptr<const RRSIGRecordContent>> d_signatures;

      DNSName d_owner;
      DNSName d_next;
      DNSName d_qname; // of the query data that lead to this entry being created/updated
      time_t d_ttd;
      QType d_qtype; // of the query data that lead to this entry being created/updated
    };

    typedef multi_index_container<
      CacheEntry,
      indexed_by<
        ordered_unique<tag<OrderedTag>,
                       member<CacheEntry, const DNSName, &CacheEntry::d_owner>,
                       CanonDNSNameCompare>,
        sequenced<tag<SequencedTag>>,
        hashed_non_unique<tag<HashedTag>,
                          member<CacheEntry, const DNSName, &CacheEntry::d_owner>>>>
      cache_t;

    cache_t d_entries;
    const DNSName d_zone;
    std::string d_salt;
    uint16_t d_iterations{0};
    bool d_nsec3{false};
  };

  std::shared_ptr<LockGuarded<ZoneEntry>> getZone(const DNSName& zone);
  std::shared_ptr<LockGuarded<ZoneEntry>> getBestZone(const DNSName& zone);
  bool getNSECBefore(time_t now, std::shared_ptr<LockGuarded<ZoneEntry>>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry);
  bool getNSEC3(time_t now, std::shared_ptr<LockGuarded<ZoneEntry>>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry);
  bool getNSEC3Denial(time_t now, std::shared_ptr<LockGuarded<ZoneEntry>>& zoneEntry, std::vector<DNSRecord>& soaSet, const MemRecursorCache::SigRecs& soaSignatures, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC, const OptLog&, pdns::validation::ValidationContext& validationContext);
  bool synthesizeFromNSEC3Wildcard(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC, ZoneEntry::CacheEntry& nextCloser, const DNSName& wildcardName, const OptLog&);
  bool synthesizeFromNSECWildcard(time_t now, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC, ZoneEntry::CacheEntry& nsec, const DNSName& wildcardName, const OptLog&);

  /* slowly updates d_entriesCount */
  void updateEntriesCount(SuffixMatchTree<std::shared_ptr<LockGuarded<ZoneEntry>>>& zones);

  SharedLockGuarded<SuffixMatchTree<std::shared_ptr<LockGuarded<ZoneEntry>>>> d_zones;
  pdns::stat_t d_nsecHits{0};
  pdns::stat_t d_nsec3Hits{0};
  pdns::stat_t d_nsecWildcardHits{0};
  pdns::stat_t d_nsec3WildcardHits{0};
  pdns::stat_t d_entriesCount{0};
  std::atomic<uint64_t> d_maxEntries{0};
};

extern std::unique_ptr<AggressiveNSECCache> g_aggressiveNSECCache;
