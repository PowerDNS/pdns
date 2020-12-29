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

#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>

#include "base32.hh"
#include "dnsname.hh"
#include "dnsrecords.hh"
#include "lock.hh"

class AggressiveNSECCache
{
public:
  void insertNSEC(const DNSName& zone, const DNSName& owner, const DNSRecord& record, const std::vector<std::shared_ptr<RRSIGRecordContent>>& signatures, bool nsec3);
  bool getDenial(time_t, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, const ComboAddress& who, const boost::optional<std::string>& routingTag, bool doDNSSEC);

  //bool getBestZoneInfo(DNSName& lookup, bool& nsec3, std::string& salt, uint16_t& iterations);
  //void removeZoneInfo(const DNSName& zone);

private:

  struct ZoneEntry
  {
    ZoneEntry()
    {
    }

    ZoneEntry(const DNSName& zone, const std::string& salt, uint16_t iterations, bool nsec3): d_zone(zone), d_salt(salt), d_iterations(iterations), d_nsec3(nsec3)
    {
    }

    struct HashedTag {};
    struct SequencedTag {};
    struct OrderedTag {};

    struct CacheEntry
    {
      std::shared_ptr<DNSRecordContent> d_record;
      std::vector<std::shared_ptr<RRSIGRecordContent>> d_signatures;

      DNSName d_owner;
      DNSName d_next;
      time_t d_ttd;
    };

    typedef multi_index_container<
      CacheEntry,
      indexed_by <
        ordered_unique<tag<OrderedTag>,
                       member<CacheEntry,DNSName,&CacheEntry::d_owner>,
                       CanonDNSNameCompare
                       >,
        sequenced<tag<SequencedTag> >,
        hashed_non_unique<tag<HashedTag>,
                          member<CacheEntry,DNSName,&CacheEntry::d_owner>
                          >
        >
      > cache_t;

    cache_t d_entries;
    DNSName d_zone;
    std::string d_salt;
    std::mutex d_lock;
    uint16_t d_iterations{0};
    bool d_nsec3{false};
  };

  std::shared_ptr<ZoneEntry> getZone(const DNSName& zone);
  std::shared_ptr<ZoneEntry> getBestZone(const DNSName& zone);
  bool getNSECBefore(time_t now, std::shared_ptr<ZoneEntry>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry);
  bool getNSEC3(time_t now, std::shared_ptr<ZoneEntry>& zoneEntry, const DNSName& name, ZoneEntry::CacheEntry& entry);
  bool getNSEC3Denial(time_t now, std::shared_ptr<ZoneEntry>& zoneEntry, std::vector<DNSRecord>& soaSet, std::vector<std::shared_ptr<RRSIGRecordContent>>& soaSignatures, const DNSName& name, const QType& type, std::vector<DNSRecord>& ret, int& res, bool doDNSSEC);

  SuffixMatchTree<std::shared_ptr<ZoneEntry>> d_zones;
  ReadWriteLock d_lock;
};


extern std::unique_ptr<AggressiveNSECCache> g_aggressiveNSECCache;
