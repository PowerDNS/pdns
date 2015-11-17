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
  int get(time_t, const DNSName &qname, const QType& qt, vector<DNSRecord>* res, const ComboAddress& who, vector<std::shared_ptr<RRSIGRecordContent>>* signatures=0);

  void replace(time_t, const DNSName &qname, const QType& qt,  const vector<DNSRecord>& content, const vector<shared_ptr<RRSIGRecordContent>>& signatures, bool auth, boost::optional<Netmask> ednsmask=boost::optional<Netmask>());
  void doPrune(void);
  void doSlash(int perc);
  uint64_t doDump(int fd);
  uint64_t doDumpNSSpeeds(int fd);

  int doWipeCache(const DNSName& name, bool sub, uint16_t qtype=0xffff);
  bool doAgeCache(time_t now, const DNSName& name, uint16_t qtype, int32_t newTTL);
  uint64_t cacheHits, cacheMisses;

private:

  struct CacheEntry
  {
    CacheEntry(const boost::tuple<DNSName, uint16_t, Netmask>& key, const vector<shared_ptr<DNSRecordContent>>& records, bool auth) : 
      d_qname(key.get<0>()), d_qtype(key.get<1>()), d_auth(auth), d_ttd(0), d_records(records), d_netmask(key.get<2>())
    {}

    typedef vector<std::shared_ptr<DNSRecordContent>> records_t;
    vector<std::shared_ptr<RRSIGRecordContent>> d_signatures;
    uint32_t getTTD() const
    {
      return d_ttd;
    }

    DNSName d_qname; 
    uint16_t d_qtype;
    bool d_auth;
    uint32_t d_ttd;
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
