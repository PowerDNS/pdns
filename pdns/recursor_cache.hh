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
#ifndef RECURSOR_CACHE_HH
#define RECURSOR_CACHE_HH
#include <string>
#include <set>
#include "dns.hh"
#include "qtype.hh"
#include "misc.hh"
#include "dnsname.hh"
#include <iostream>
#include "dnsrecords.hh"
#include <boost/utility.hpp>
#undef L
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

#define L theL()
#include "namespaces.hh"
using namespace ::boost::multi_index;

class MemRecursorCache : public boost::noncopyable //  : public RecursorCache
{
public:
  MemRecursorCache() : d_cachecachevalid(false)
  {
    cacheHits = cacheMisses = 0;
  }
  unsigned int size();
  unsigned int bytes();
  int32_t get(time_t, const DNSName &qname, const QType& qt, bool requireAuth, vector<DNSRecord>* res, const ComboAddress& who, vector<std::shared_ptr<RRSIGRecordContent>>* signatures=nullptr, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs=nullptr, bool* variable=nullptr, vState* state=nullptr, bool* wasAuth=nullptr);

  void replace(time_t, const DNSName &qname, const QType& qt,  const vector<DNSRecord>& content, const vector<shared_ptr<RRSIGRecordContent>>& signatures, const std::vector<std::shared_ptr<DNSRecord>>& authorityRecs, bool auth, boost::optional<Netmask> ednsmask=boost::none, vState state=Indeterminate);

  void doPrune(void);
  uint64_t doDump(int fd);

  int doWipeCache(const DNSName& name, bool sub, uint16_t qtype=0xffff);
  bool doAgeCache(time_t now, const DNSName& name, uint16_t qtype, uint32_t newTTL);
  bool updateValidationStatus(time_t now, const DNSName &qname, const QType& qt, const ComboAddress& who, bool requireAuth, vState newState);

  uint64_t cacheHits, cacheMisses;

private:

  struct CacheEntry
  {
    CacheEntry(const boost::tuple<DNSName, uint16_t, Netmask>& key, const vector<shared_ptr<DNSRecordContent>>& records, bool auth) : 
      d_records(records), d_qname(key.get<0>()), d_netmask(key.get<2>()), d_ttd(0), d_qtype(key.get<1>()), d_auth(auth)
    {}

    typedef vector<std::shared_ptr<DNSRecordContent>> records_t;
    time_t getTTD() const
    {
      return d_ttd;
    }

    records_t d_records;
    vector<std::shared_ptr<RRSIGRecordContent>> d_signatures;
    std::vector<std::shared_ptr<DNSRecord>> d_authorityRecs;
    DNSName d_qname;
    Netmask d_netmask;
    mutable vState d_state;
    time_t d_ttd;
    uint16_t d_qtype;
    bool d_auth;
  };

  class IndexEntry
  {
  public:
    IndexEntry(const DNSName& qname, uint16_t qtype): d_qname(qname), d_qtype(qtype)
    {
    }

    Netmask lookupBestMatch(const ComboAddress& addr) const
    {
      Netmask result = Netmask();

      const auto best = d_nmt.lookup(addr);
      if (best != nullptr) {
        result = best->first;
      }

      return result;
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

  typedef multi_index_container<
    CacheEntry,
    indexed_by <
                ordered_unique<
                      composite_key< 
                        CacheEntry,
                        member<CacheEntry,DNSName,&CacheEntry::d_qname>,
                        member<CacheEntry,uint16_t,&CacheEntry::d_qtype>,
                        member<CacheEntry,Netmask,&CacheEntry::d_netmask>
                      >,
		  composite_key_compare<CanonDNSNameCompare, std::less<uint16_t>, std::less<Netmask> >
                >,
               sequenced<>
               >
  > cache_t;
  typedef multi_index_container<
    IndexEntry,
    indexed_by <
      ordered_unique <
        composite_key<
          IndexEntry,
          member<IndexEntry,DNSName,&IndexEntry::d_qname>,
          member<IndexEntry,uint16_t,&IndexEntry::d_qtype>
        >
      >
    >
  > index_t;

  cache_t d_cache;
  index_t d_index;
  pair<cache_t::iterator, cache_t::iterator> d_cachecache;
  DNSName d_cachedqname;
  bool d_cachecachevalid;

  bool attemptToRefreshNSTTL(const QType& qt, const vector<DNSRecord>& content, const CacheEntry& stored);
  bool entryMatches(cache_t::const_iterator& entry, uint16_t qt, bool requireAuth, const ComboAddress& who);
  std::pair<cache_t::const_iterator, cache_t::const_iterator> getEntries(const DNSName &qname, const QType& qt);
  cache_t::const_iterator getEntryUsingIndex(time_t now, const DNSName &qname, uint16_t qtype, bool requireAuth, const ComboAddress& who);
  int32_t handleHit(cache_t::iterator entry, const DNSName& qname, const ComboAddress& who, vector<DNSRecord>* res, vector<std::shared_ptr<RRSIGRecordContent>>* signatures, std::vector<std::shared_ptr<DNSRecord>>* authorityRecs, bool* variable, vState* state, bool* wasAuth);

public:
  void preRemoval(const CacheEntry& entry)
  {
    if (entry.d_netmask.empty()) {
      return;
    }

    auto key = tie(entry.d_qname, entry.d_qtype);
    auto indexEntry = d_index.find(key);
    if (indexEntry != d_index.end()) {
      indexEntry->removeNetmask(entry.d_netmask);
      if (indexEntry->isEmpty()) {
        d_index.erase(indexEntry);
      }
    }
  }
};
#endif
