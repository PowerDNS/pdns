#ifndef RECURSOR_CACHE_HH
#define RECURSOR_CACHE_HH
#include <ext/hash_map>
#include <string>
#include <set>
#include "dns.hh"
#include "qtype.hh"
#include <iostream>
#include <boost/utility.hpp>

namespace __gnu_cxx {
  template<>
  struct hash<string>
  {
    size_t
    operator()(const string& __s) const
    { 
      return __stl_hash_string(__s.c_str()); 
    }
  };
}

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
    //optString<> d_string;
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
    predicate(time_t limit) : d_limit(limit)
    {
    }
    
    bool operator()(const StoredRecord& sr) const
    {
      return sr.d_ttd < d_limit;
    }
    time_t d_limit;
  };

  typedef __gnu_cxx::hash_map<string, vector<StoredRecord> > cache_t;

private:
  cache_t d_cache;
};


#endif
