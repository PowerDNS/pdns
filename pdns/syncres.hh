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


template<class MultiPlexor=LWRes> class SyncRes
{
public:
  SyncRes() : d_outqueries(0), d_cacheonly(false), d_nocache(false){}
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
  static unsigned int s_outqueries;
  unsigned int d_outqueries;
  
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
  MultiPlexor d_lwr;
  static map<string,string> s_negcache;
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
