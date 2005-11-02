#ifndef RECURSOR_CACHE_HH
#define RECURSOR_CACHE_HH
#include <map>
#include <string>
#include <set>
#include "dns.hh"
#include "qtype.hh"
#include <iostream>
#include <boost/utility.hpp>

template<int N=14>
struct optString
{
  optString()
  {
    d_len=0;
    *buf=0;
  }

  optString(const optString& rhs) : d_len(rhs.d_len)
  {
    memcpy(buf, rhs.buf, N);
  }

  optString(const string& str)
  {
    if(str.size() < N-1) {
      memcpy(buf, str.c_str(), str.size()+1);
      d_len = str.size() + 1;
    }
    else {
      new(buf) string(str);
      d_len = 0;
    }
  }

  operator string() const
  {

    if(d_len) {
      return string(buf, buf + d_len - 1);
    }
    else {
      return *((string*)buf);
    }
  }

  void prune() const
  {
    //    cerr<<"did a prune!"<<endl;
    if(!d_len)
      ((string*)buf)->~string();
  }

  bool operator<(const optString& os) const
  {
    return (string)*this < (string) os;
  }

  char buf[N];
  uint8_t d_len;
} __attribute__((packed));


class MemRecursorCache : public boost::noncopyable //  : public RecursorCache
{
public:
  unsigned int size();
  int get(time_t, const string &qname, const QType& qt, set<DNSResourceRecord>* res);
  void replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content);
  void doPrune(void);
  int cacheHits, cacheMisses;

private:
  struct StoredRecord
  {
    mutable uint32_t d_ttd;
    //    optString<> d_string;
    string d_string;
    bool operator<(const StoredRecord& rhs) const
    {
      return d_string < rhs.d_string;
      //      return make_pair(d_ttd, d_string) < make_pair(rhs.d_ttd, rhs.d_string);
    }
  };
  typedef map<string, set<StoredRecord> > cache_t;
private:
  cache_t d_cache;
};


#endif
