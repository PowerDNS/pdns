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
  virtual int get(const string &qname, const QType& qt, set<DNSResourceRecord>* res)=0;
  virtual void replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content)=0;
  virtual void doPrune(void)=0;
  int cacheHits, cacheMisses;

};


class MemRecursorCache : public RecursorCache
{
public:
  virtual ~MemRecursorCache(){}
  virtual unsigned int size();
  virtual int get(const string &qname, const QType& qt, set<DNSResourceRecord>* res);
  virtual void replace(const string &qname, const QType& qt,  const set<DNSResourceRecord>& content);
  virtual void doPrune(void);
private:
  typedef map<string,set<DNSResourceRecord> > cache_t;

  cache_t d_cache;
};


#endif
