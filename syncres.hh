#ifndef PDNS_SYNCRES_HH
#define PDNS_SYNCRES_HH
#include <string>
#include "dns.hh"
#include "qtype.hh"
#include <vector>
#include <set>
#include <map>
#include "misc.hh"
#include "lwres.hh"

/* external functions, opaque to us */
void replaceCache(const string &qname, const QType &qt, const set<DNSResourceRecord>& content);
int getCache(const string &qname, const QType& qt, set<DNSResourceRecord>* res=0);

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
  }
  bool shouldThrottle(const Thing& t)
  {
    time_t now=time(0);
    while(!d_dq.empty() && d_dq.back().ttd < now) // remove expired entries from the end
      d_dq.pop_back();

    for(typename cont_t::iterator i=d_dq.begin();i!=d_dq.end();++i) 
      if(i->T==t && i->count-- < 0)
	return true; 
    return false;
  }

  void throttle(const Thing& t, unsigned int ttl=0, unsigned int tries=0) 
  {
    entry e;
    e.ttd=time(0)+ (ttl ?: d_ttl) ; e.T=t; e.count=tries ?: d_limit;
    d_dq.push_front(e);

  }
private:
  int d_limit;
  int d_ttl;
  struct entry 
  {
    time_t ttd;
    Thing T;
    int count;
  };
  typedef deque<entry> cont_t;
  cont_t d_dq;
};

class SyncRes
{
public:
  SyncRes() : d_outqueries(0), d_throttledqueries(0), d_cacheonly(false), d_nocache(false){}
  int beginResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret);
  void setId(int id)
  {
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
  static unsigned int s_throttledqueries;
  static unsigned int s_outqueries;
  static unsigned int s_nodelegated;
  unsigned int d_outqueries;
  unsigned int d_throttledqueries;
  static map<string,NegCacheEntry> s_negcache;    
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

  vector<string> shuffle(set<string> &nameservers);
  bool moreSpecificThan(const string& a, const string &b);
  string getA(const string &qname, int depth, set<GetBestNSAnswer>& beenthere);

private:
  string d_prefix;
  static bool s_log;
  bool d_cacheonly;
  bool d_nocache;
  LWRes d_lwr;

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
#endif
