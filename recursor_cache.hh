#ifndef RECURSOR_CACHE_HH
#define RECURSOR_CACHE_HH
#include <string>
#include <set>
#include "dns.hh"
#include "qtype.hh"
#include <iostream>
#include <boost/utility.hpp>
#undef L
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/version.hpp>
#if BOOST_VERSION >= 103300
#include <boost/multi_index/hashed_index.hpp>
#endif

#define L theL()
using namespace boost;
using namespace ::boost::multi_index;


class MemRecursorCache : public boost::noncopyable //  : public RecursorCache
{
public:
  MemRecursorCache() : d_cachecachevalid(false)
  {}
  unsigned int size();
  unsigned int bytes();
  int get(time_t, const string &qname, const QType& qt, set<DNSResourceRecord>* res);
  void replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content);
  void doPrune(void);
  void doDumpAndClose(int fd);
  void doWipeCache(const string& name);
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
      return 4+d_string.size();
    }

  };

  struct predicate
  {
    predicate(uint32_t limit) : d_limit(limit)
    {
    }
    
    bool operator()(const StoredRecord& sr) const
    {
      return sr.d_ttd <= d_limit;
    }
    uint32_t d_limit;
  };

  //   typedef __gnu_cxx::hash_map<string, vector<StoredRecord> > cache_t;
  struct CacheEntry
  {
    string d_qname;
    uint16_t d_qtype;

    CacheEntry(const tuple<string, uint16_t>& key, const vector<StoredRecord>& records) : 
      d_qname(key.get<0>()), d_qtype(key.get<1>()), d_records(records)
    {}

    typedef vector<StoredRecord> records_t;
    records_t d_records;
    uint32_t getTTD() const
    {
      if(d_records.size()==1)
	return d_records.begin()->d_ttd;

      uint32_t earliest=numeric_limits<uint32_t>::max();
      for(records_t::const_iterator i=d_records.begin(); i != d_records.end(); ++i)
	earliest=min(earliest, i->d_ttd);
      return earliest;
    }

  };

  typedef multi_index_container<
    CacheEntry,
    indexed_by <
                ordered_unique<
                      composite_key< 
                        CacheEntry,
                        member<CacheEntry,string,&CacheEntry::d_qname>,
                        member<CacheEntry,uint16_t,&CacheEntry::d_qtype>
                      >
                >,
                ordered_non_unique<const_mem_fun<CacheEntry,uint32_t,&CacheEntry::getTTD> >
               >
  > cache_t;

private:
  cache_t d_cache;
  pair<cache_t::const_iterator, cache_t::const_iterator> d_cachecache;
  string d_cachedqname;
  bool d_cachecachevalid;
};


#endif
