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
#include "sstuff.hh"
#include "recursor_cache.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/optional.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include "mtasker.hh"

/* external functions, opaque to us */

void primeHints(void);

struct NegCacheEntry
{
  pair<string, QType> d_key;
  QType d_qtype;
  string d_qname;
  uint32_t d_ttd;
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
    if(now > d_last_clean + 300 ) {
      d_last_clean=now;
      for(typename cont_t::iterator i=d_cont.begin();i!=d_cont.end();) {
	if( i->second.ttd < now) {
	  d_cont.erase(i++);
	}
	else
	  ++i;
      }
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
  DecayingEwma() :  d_val(0.0) 
  {
    d_needinit=true;
    d_lastget=d_last;
  }

  DecayingEwma(const DecayingEwma& orig) : d_last(orig.d_last),  d_lastget(orig.d_lastget), d_val(orig.d_val), d_needinit(orig.d_needinit)
  {
  }

  struct timeval getOrMakeTime(struct timeval* tv)
  {
    if(tv)
      return *tv;
    else {
      struct timeval ret;
      gettimeofday(&ret, 0);
      return ret;
    }
  }

  void submit(int val, struct timeval*tv = 0)
  {
    struct timeval now=getOrMakeTime(tv);

    if(d_needinit) {
      d_last=now;
      d_needinit=false;
    }

    float diff= makeFloat(d_last - now);

    d_last=now;
    double factor=exp(diff)/2.0; // might be '0.5', or 0.0001
    d_val=(1-factor)*val+ factor*d_val; 
  }


  double get(struct timeval*tv = 0)
  {
    struct timeval now=getOrMakeTime(tv);
    float diff=makeFloat(d_lastget-now);
    d_lastget=now;
    float factor=exp(diff/60.0); // is 1.0 or less
    return d_val*=factor;
  }

  bool stale(time_t limit) 
  {
    return limit > d_lastget.tv_sec;
  }

private:
  DecayingEwma& operator=(const DecayingEwma&);
  struct timeval d_last;          // stores time
  struct timeval d_lastget;       // stores time
  float d_val;
  bool d_needinit;
};


class PulseRate
{
public:
  PulseRate() :  d_val(0.0) 
  {
    gettimeofday(&d_last, 0);
  }

  PulseRate(const PulseRate& orig) : d_last(orig.d_last), d_val(orig.d_val)
  {
  }

  void pulse(const struct timeval& now)
  {
    //    cout<<"about to submit: "<< 1000.0*makeFloat(now - d_last)<<"\n";
    submit((int)(1000.0*(makeFloat(now-d_last))), now);
  }

  optional<float> get(struct timeval& now, unsigned int limit) const
  {
    optional<float> ret;
    float diff=makeFloat(now - d_last);
    if(diff < limit)
      ret=d_val;
    return ret;
  }

  bool stale(time_t limit) 
  {
    return limit > d_last.tv_sec;
  }

private:
  void submit(int val, const struct timeval& now)
  {
    float diff= makeFloat(d_last - now);

    d_last=now;
    double factor=exp(diff/2.0)/2.0; // might be '0.5', or 0.0001
    d_val=(1-factor)*val+ factor*d_val; 
  }

  PulseRate& operator=(const PulseRate&);
  struct timeval d_last;          // stores time
  float d_val;
};


class SyncRes
{
public:
  explicit SyncRes(const struct timeval& now) :  d_outqueries(0), d_tcpoutqueries(0), d_throttledqueries(0), d_timeouts(0), d_now(now),
						d_cacheonly(false), d_nocache(false) { }
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
  //  typedef map<string,NegCacheEntry> negcache_t;

  typedef multi_index_container <
    NegCacheEntry,
    indexed_by <
       ordered_unique<
           member<NegCacheEntry, pair<string,QType>, &NegCacheEntry::d_key>
       >,
       ordered_non_unique<
           member<NegCacheEntry, uint32_t, &NegCacheEntry::d_ttd>
       >
    >
  >negcache_t;
  static negcache_t s_negcache;    

  typedef map<string,DecayingEwma> nsspeeds_t;
  static nsspeeds_t s_nsSpeeds;

  typedef Throttle<tuple<uint32_t,string,uint16_t> > throttle_t;
  static throttle_t s_throttle;
  struct timeval d_now;
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
  vector<uint32_t> getAs(const string &qname, int depth, set<GetBestNSAnswer>& beenthere);

  SyncRes(const SyncRes&);
  SyncRes& operator=(const SyncRes&);


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
class Socket;
int asendtcp(const string& data, Socket* sock);
int arecvtcp(string& data, int len, Socket* sock);


struct PacketID
{
  PacketID() : sock(0), inNeeded(0), outPos(0)
  {}

  uint16_t id;  // wait for a specific id/remote pair
  struct sockaddr_in remote;  // this is the remote

  Socket* sock;  // or wait for an event on a TCP fd
  int inNeeded; // if this is set, we'll read until inNeeded bytes are read
  string inMSG; // they'll go here

  string outMSG; // the outgoing message that needs to be sent
  string::size_type outPos;    // how far we are along in the outMSG

  bool operator<(const PacketID& b) const
  {
    int ourSock= sock ? sock->getHandle() : 0;
    int bSock = b.sock ? b.sock->getHandle() : 0;
    return 
      tie(id, remote.sin_addr.s_addr, remote.sin_port, ourSock) <
      tie(b.id, b.remote.sin_addr.s_addr, b.remote.sin_port, bSock);
  }
};

extern MemRecursorCache RC;
extern MTasker<PacketID,string>* MT;

struct RecursorStats
{
  uint64_t servFails;
  uint64_t nxDomains;
  uint64_t noErrors;
  PulseRate queryrate;
  uint64_t answers0_1, answers1_10, answers10_100, answers100_1000, answersSlow;
  uint64_t avgLatencyUsec;
  uint64_t qcounter;
  uint64_t tcpqcounter;
};

extern RecursorStats g_stats;
#endif
