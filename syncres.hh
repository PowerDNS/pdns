#ifndef PDNS_SYNCRES_HH
#define PDNS_SYNCRES_HH
#include <string>
#include "dns.hh"
#include "qtype.hh"
#include <vector>
#include <set>
#include <map>
#include <cmath>
#include <iostream>
#include <utility>
#include "misc.hh"
#include "lwres.hh"
#include <boost/utility.hpp>
#include "recursor_cache.hh"

/* external functions, opaque to us */

void primeHints(void);

struct NegCacheEntry
{
  string name;
  time_t ttd;
};


template<class Thing> class Throttle
{
public:
  Throttle()
  {
    d_limit=3;
    d_ttl=60;
    d_last_clean=time(0);
  }
  bool shouldThrottle(time_t now, const Thing& t)
  {
    if(now > d_last_clean + 60 ) {
      d_last_clean=now;
      for(typename cont_t::iterator i=d_cont.begin();i!=d_cont.end();) 
	if( i->second.ttd > now) {
	  d_cont.erase(i++);
	}
	else
	  ++i;
    }

    typename cont_t::iterator i=d_cont.find(t);
    if(i==d_cont.end())
      return false;
    if(now > i->second.ttd || i->second.count-- < 0) {
      d_cont.erase(i);
    }

    return true; // still listed, still blocked
  }
  void throttle(time_t now, const Thing& t, unsigned int ttl=0, unsigned int tries=0) 
  {
    typename cont_t::iterator i=d_cont.find(t);
    entry e={ now+(ttl ? ttl : d_ttl), tries ? tries : d_limit};

    if(i==d_cont.end()) {
      d_cont[t]=e;
    } 
    else if(i->second.ttd > e.ttd || (i->second.count) < e.count) 
      d_cont[t]=e;
  }
  
  unsigned int size()
  {
    return d_cont.size();
  }
private:
  int d_limit;
  int d_ttl;
  time_t d_last_clean;
  struct entry 
  {
    time_t ttd;
    int count;
  };
  typedef map<Thing,entry> cont_t;
  cont_t d_cont;
};


/** Class that implements a decaying EWMA.
    This class keeps an exponentially weighted moving average which, additionally, decays over time.
    The decaying is only done on get.
*/
class DecayingEwma
{
public:
  DecayingEwma() : d_last(getTime()) , d_lastget(d_last),  d_val(0.0) {

  }

  DecayingEwma(const DecayingEwma& orig) : d_last(orig.d_last), d_lastget(orig.d_lastget), d_val(orig.d_val)
  {

  }

  void submit(int val, struct timeval*tv = 0)
  {
    float now;
    if(tv)
      now=tv->tv_sec + tv->tv_usec/1000000.0;
    else
      now=getTime();

    float diff=d_last-now;
    d_last=now;
    float factor=exp(diff)/2.0; // might be '0.5', or 0.0001
    d_val=(1-factor)*val+ factor*d_val; 
  }

  float get(struct timeval*tv = 0)
  {
    float now;
    if(tv)
      now=tv->tv_sec + tv->tv_usec/1000000.0;
    else
      now=getTime();

    float diff=d_lastget-now;
    d_lastget=now;
    float factor=exp(diff/60.0); // is 1.0 or less
    return d_val*=factor;
  }

  bool stale(time_t limit) 
  {
    return limit > d_lastget;
  }

private:
  DecayingEwma& operator=(const DecayingEwma&);
  float d_last;
  float d_lastget;
  float d_val;
};


class SyncRes
{
public:
  SyncRes() : d_outqueries(0), d_tcpoutqueries(0), d_throttledqueries(0), d_timeouts(0), d_cacheonly(false), d_nocache(false) { gettimeofday(&d_now, 0); }
  int beginResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret);
  void setId(int id)
  {
    if(s_log)
      d_prefix="["+itoa(id)+"] ";
  }
  static void setLog(bool log)
  {
    s_log=log;
  }
  void setCacheOnly(bool state=true)
  {
    d_cacheonly=state;
  }
  void setNoCache(bool state=true)
  {
    d_nocache=state;
  }
  static unsigned int s_queries;
  static unsigned int s_outgoingtimeouts;
  static unsigned int s_throttledqueries;
  static unsigned int s_outqueries;
  static unsigned int s_tcpoutqueries;
  static unsigned int s_nodelegated;
  unsigned int d_outqueries;
  unsigned int d_tcpoutqueries;
  unsigned int d_throttledqueries;
  unsigned int d_timeouts;
  typedef map<string,NegCacheEntry> negcache_t;
  static negcache_t s_negcache;    

  typedef map<string,DecayingEwma> nsspeeds_t;
  static nsspeeds_t s_nsSpeeds;

  static Throttle<string> s_throttle;
private:
  struct GetBestNSAnswer;
  int doResolveAt(set<string> nameservers, string auth, const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret,
		  int depth, set<GetBestNSAnswer>&beenthere);
  int doResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, set<GetBestNSAnswer>& beenthere);
  bool doCNAMECacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res);
  bool doCacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res);
  void getBestNSFromCache(const string &qname, set<DNSResourceRecord>&bestns, int depth, set<GetBestNSAnswer>& beenthere);
  void addCruft(const string &qname, vector<DNSResourceRecord>& ret);
  string getBestNSNamesFromCache(const string &qname,set<string>& nsset, int depth, set<GetBestNSAnswer>&beenthere);
  void addAuthorityRecords(const string& qname, vector<DNSResourceRecord>& ret, int depth);

  inline vector<string> shuffle(set<string> &nameservers, const string &prefix);
  bool moreSpecificThan(const string& a, const string &b);
  vector<string> getAs(const string &qname, int depth, set<GetBestNSAnswer>& beenthere);

  SyncRes(const SyncRes&);
  SyncRes& operator=(const SyncRes&);
private:
  string d_prefix;
  static bool s_log;
  bool d_cacheonly;
  bool d_nocache;
  LWRes d_lwr;
  struct timeval d_now;

  struct GetBestNSAnswer
  {
    string qname;
    set<DNSResourceRecord> bestns;
    bool operator<(const GetBestNSAnswer &b) const
    {
      if(qname<b.qname)
	return true;
      if(qname==b.qname)
	return bestns<b.bestns;
      return false;
    }
  };

};
class Socket;
int asendtcp(const string& data, Socket* sock);
int arecvtcp(string& data, int len, Socket* sock);
#endif
