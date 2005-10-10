#ifndef RECURSOR_CACHE_HH
#define RECURSOR_CACHE_HH
#include <map>
#include <string>
#include <set>
#include "dns.hh"
#include "qtype.hh"


class RecursorCache
{
public:
  virtual unsigned int size()=0;
  virtual int get(time_t now, const string &qname, const QType& qt, set<DNSResourceRecord>* res)=0;
  virtual void replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content)=0;
  virtual void doPrune(void)=0;
};


class MemRecursorCache //  : public RecursorCache
{
public:
  ~MemRecursorCache(){}
  unsigned int size();
  int get(time_t, const string &qname, const QType& qt, set<DNSResourceRecord>* res);
  void replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content);
  void doPrune(void);
  int cacheHits, cacheMisses;

private:
  struct StoredRecord
  {
    uint32_t d_ttd;
    string d_string;
    bool operator<(const StoredRecord& rhs) const
    {
      return make_pair(d_ttd, d_string) < make_pair(rhs.d_ttd, rhs.d_string);
    }
  };
  typedef map<string, set<StoredRecord> > cache_t;

  cache_t d_cache;
};


#endif
