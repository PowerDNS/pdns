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
  unsigned int size();
  unsigned int bytes();
  int get(time_t, const string &qname, const QType& qt, set<DNSResourceRecord>* res);
  void replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content);
  void doPrune(void);
  int cacheHits, cacheMisses;

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
    CacheEntry(){}
    CacheEntry(const string& name, const vector<StoredRecord>& records) : d_name(name), d_records(records)
    {}
    string d_name;
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
#if BOOST_VERSION >= 103300
                hashed_unique<member<CacheEntry,string,&CacheEntry::d_name> >,
#else
                ordered_unique<member<CacheEntry,string,&CacheEntry::d_name> >,
#endif
                ordered_non_unique<const_mem_fun<CacheEntry,uint32_t,&CacheEntry::getTTD> >
               >
  > cache_t;

private:
  cache_t d_cache;

};


#endif
