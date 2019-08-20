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
#include <boost/multi_index/hashed_index.hpp>
#include "dnsparser.hh"
#include "dnsname.hh"
#include "dns.hh"
#include "validate.hh"

using namespace ::boost::multi_index;

/* FIXME should become part of the normal cache (I think) and shoudl become more like
 * struct {
 *   vector<DNSRecord> records;
 *   vector<DNSRecord> signatures;
 * } recsig_t;
 *
 * typedef vector<recsig_t> recordsAndSignatures;
 */
typedef struct {
  vector<DNSRecord> records;
  vector<DNSRecord> signatures;
} recordsAndSignatures;

class NegCache : public boost::noncopyable {
  public:
    struct NegCacheEntry {
      DNSName d_name;                     // The denied name
      QType d_qtype;                      // The denied type
      DNSName d_auth;                     // The denying name (aka auth)
      mutable uint32_t d_ttd;             // Timestamp when this entry should die
      recordsAndSignatures authoritySOA;  // The upstream SOA record and RRSIGs
      recordsAndSignatures DNSSECRecords; // The upstream NSEC(3) and RRSIGs
      mutable vState d_validationState{Indeterminate};
      uint32_t getTTD() const {
        return d_ttd;
      };
    };

    void add(const NegCacheEntry& ne);
    void updateValidationStatus(const DNSName& qname, const QType& qtype, const vState newState, boost::optional<uint32_t> capTTD);
    bool get(const DNSName& qname, const QType& qtype, const struct timeval& now, const NegCacheEntry** ne, bool typeMustMatch=false);
    bool getRootNXTrust(const DNSName& qname, const struct timeval& now, const NegCacheEntry** ne);
    uint64_t count(const DNSName& qname) const;
    uint64_t count(const DNSName& qname, const QType qtype) const;
    void prune(unsigned int maxEntries);
    void clear();
    uint64_t dumpToFile(FILE* fd);
    uint64_t wipe(const DNSName& name, bool subtree = false);

    uint64_t size() {
      return d_negcache.size();
    };

    void preRemoval(const NegCacheEntry& entry)
    {
    }

  private:
    typedef boost::multi_index_container <
      NegCacheEntry,
      indexed_by <
        ordered_unique <
          composite_key <
            NegCacheEntry,
            member<NegCacheEntry, DNSName, &NegCacheEntry::d_name>,
            member<NegCacheEntry, QType, &NegCacheEntry::d_qtype>
          >,
          composite_key_compare <
            CanonDNSNameCompare, std::less<QType>
          >
        >,
        sequenced<>,
        hashed_non_unique <
          member<NegCacheEntry, DNSName, &NegCacheEntry::d_name>
        >
      >
    > negcache_t;

    // Required for the cachecleaner
    typedef negcache_t::nth_index<1>::type negcache_sequence_t;

    // Stores the negative cache entries
    negcache_t d_negcache;
};
