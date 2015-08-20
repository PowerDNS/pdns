#ifndef RECURSOR_CACHE_HH
#define RECURSOR_CACHE_HH
#include <string>
#include <set>
#include "dns.hh"
#include "qtype.hh"
#include "misc.hh"
#include "dnsname.hh"
#include <iostream>

#include <boost/utility.hpp>
#undef L
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/version.hpp>

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
  int get(time_t, const DNSName &qname, const QType& qt, set<DNSResourceRecord>* res);

  int getDirect(time_t now, const char* qname, const QType& qt, uint32_t ttd[10], char* data[10], uint16_t len[10]);
  void replace(time_t, const DNSName &qname, const QType& qt,  const set<DNSResourceRecord>& content, bool auth);
  void doPrune(void);
  void doSlash(int perc);
  uint64_t doDump(int fd);
  uint64_t doDumpNSSpeeds(int fd);

  int doWipeCache(const DNSName& name, uint16_t qtype=0xffff);
  bool doAgeCache(time_t now, const DNSName& name, uint16_t qtype, int32_t newTTL);
  uint64_t cacheHits, cacheMisses;

private:
  struct StoredRecord
  {
    mutable uint32_t d_ttd;

    string d_string;

    bool operator<(const StoredRecord& rhs) const
    {
      return d_string < rhs.d_string;
    }

    unsigned int size() const
    {
      return sizeof(*this) + d_string.size();
    }

  };

  struct CacheEntry
  {
    CacheEntry(const boost::tuple<DNSName, uint16_t>& key, const vector<StoredRecord>& records, bool auth) : 
      d_qname(key.get<0>()), d_qtype(key.get<1>()), d_auth(auth), d_records(records)
    {}

    typedef vector<StoredRecord> records_t;

    uint32_t getTTD() const
    {
      if(d_records.size()==1)
        return d_records.begin()->d_ttd;

      uint32_t earliest=std::numeric_limits<uint32_t>::max();
      for(records_t::const_iterator i=d_records.begin(); i != d_records.end(); ++i)
        earliest=min(earliest, i->d_ttd);
      return earliest;
    }

    DNSName d_qname;
    uint16_t d_qtype;
    bool d_auth;
    records_t d_records;
  };

  typedef multi_index_container<
    CacheEntry,
    indexed_by <
                ordered_unique<
                      composite_key< 
                        CacheEntry,
                        member<CacheEntry,DNSName,&CacheEntry::d_qname>,
                        member<CacheEntry,uint16_t,&CacheEntry::d_qtype>
                      >,
                      composite_key_compare<std::less<DNSName>, std::less<uint16_t> >
                >,
               sequenced<>
               >
  > cache_t;

  cache_t d_cache;
  pair<cache_t::iterator, cache_t::iterator> d_cachecache;
  DNSName d_cachedqname;
  bool d_cachecachevalid;
  bool attemptToRefreshNSTTL(const QType& qt, const set<DNSResourceRecord>& content, const CacheEntry& stored);
};
string DNSRR2String(const DNSResourceRecord& rr);
DNSResourceRecord String2DNSRR(const DNSName& qname, const QType& qt, const string& serial, uint32_t ttd);

#endif
