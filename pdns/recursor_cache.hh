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
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/version.hpp>
#include "iputils.hh"
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
  int32_t get(time_t, const DNSName &qname, const QType& qt, vector<DNSRecord>* res, const ComboAddress& who, vector<std::shared_ptr<RRSIGRecordContent>>* signatures=0);

  void replace(time_t, const DNSName &qname, const QType& qt,  const vector<DNSRecord>& content, const vector<shared_ptr<RRSIGRecordContent>>& signatures, bool auth, boost::optional<Netmask> ednsmask=boost::optional<Netmask>());
  void doPrune(void);
  uint64_t doDump(int fd);

  int doWipeCache(const DNSName& name, bool sub, uint16_t qtype=0xffff);
  bool doAgeCache(time_t now, const DNSName& name, uint16_t qtype, uint32_t newTTL);

  uint64_t cacheHits, cacheMisses;

private:

  struct CacheEntry
  {
    CacheEntry(const boost::tuple<DNSName, uint16_t, Netmask>& key, const vector<shared_ptr<DNSRecordContent>>& records, bool auth) : 
      d_qname(key.get<0>()), d_qtype(key.get<1>()), d_auth(auth), d_ttd(0), d_records(records), d_netmask(key.get<2>())
    {}

    typedef vector<std::shared_ptr<DNSRecordContent>> records_t;
    vector<std::shared_ptr<RRSIGRecordContent>> d_signatures;
    time_t getTTD() const
    {
      return d_ttd;
    }

    DNSName d_qname; 
    uint16_t d_qtype;
    bool d_auth;
    time_t d_ttd;
    records_t d_records;
    Netmask d_netmask;
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

  cache_t d_cache;
  pair<cache_t::iterator, cache_t::iterator> d_cachecache;
  DNSName d_cachedqname;
  bool d_cachecachevalid;
  bool attemptToRefreshNSTTL(const QType& qt, const vector<DNSRecord>& content, const CacheEntry& stored);
};
#endif
