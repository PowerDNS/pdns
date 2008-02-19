/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2008  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published 
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <boost/algorithm/string.hpp>
#include "utility.hh"
#include "syncres.hh"
#include <iostream>
#include <map>
#include <algorithm>
#include <set>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <utility>
#include <deque>
#include "logger.hh"
#include "misc.hh"
#include "arguments.hh"
#include "lwres.hh"
#include "recursor_cache.hh"
#include "dnsparser.hh"

extern MemRecursorCache RC;

SyncRes::negcache_t SyncRes::s_negcache;    
SyncRes::nsspeeds_t SyncRes::s_nsSpeeds;    
unsigned int SyncRes::s_maxnegttl;
unsigned int SyncRes::s_queries;
unsigned int SyncRes::s_outgoingtimeouts;
unsigned int SyncRes::s_outqueries;
unsigned int SyncRes::s_tcpoutqueries;
unsigned int SyncRes::s_throttledqueries;
unsigned int SyncRes::s_nodelegated;
unsigned int SyncRes::s_unreachables;
bool SyncRes::s_doIPv6;

SyncRes::domainmap_t SyncRes::s_domainmap;
string SyncRes::s_serverID;
bool SyncRes::s_log;

#define LOG if(s_log) L<<Logger::Warning

SyncRes::throttle_t SyncRes::s_throttle;

/** everything begins here - this is the entry point just after receiving a packet */
int SyncRes::beginResolve(const string &qname, const QType &qtype, uint16_t qclass, vector<DNSResourceRecord>&ret)
{
  s_queries++;
  if( (qtype.getCode()==QType::PTR && !Utility::strcasecmp(qname.c_str(), "1.0.0.127.in-addr.arpa.")) ||
      (qtype.getCode()==QType::A && qname.length()==10 && !Utility::strcasecmp(qname.c_str(), "localhost."))) {
    ret.clear();
    DNSResourceRecord rr;
    rr.qname=qname;
    rr.qtype=qtype;
    rr.qclass=1;
    rr.ttl=86400;
    if(qtype.getCode()==QType::PTR)
      rr.content="localhost.";
    else
      rr.content="127.0.0.1";
    ret.push_back(rr);
    return 0;
  }

  if(qclass==3 && qtype.getCode()==QType::TXT && 
        (!Utility::strcasecmp(qname.c_str(), "version.bind.") || !Utility::strcasecmp(qname.c_str(), "id.server.") || !Utility::strcasecmp(qname.c_str(), "version.pdns.") ) 
     ) {
    ret.clear();
    DNSResourceRecord rr;
    rr.qname=qname;
    rr.qtype=qtype;
    rr.qclass=qclass;
    rr.ttl=86400;
    if(!Utility::strcasecmp(qname.c_str(),"version.bind.")  || !Utility::strcasecmp(qname.c_str(),"version.pdns."))
      rr.content="\""+::arg()["version-string"]+"\"";
    else
      rr.content="\""+s_serverID+"\"";
    ret.push_back(rr);
    return 0;
  }
  
  if(qclass==0xff)
    qclass=1;
  else if(qclass!=1)
    return -1;
  
  set<GetBestNSAnswer> beenthere;
  int res=doResolve(qname, qtype, ret, 0, beenthere);
  if(!res)
    addCruft(qname, ret);
  return res;
}

//! This is the 'out of band resolver', in other words, the authoritative server
bool SyncRes::doOOBResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int& res)
{
  string prefix;
  if(s_log) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  LOG<<prefix<<qname<<": checking auth storage for '"<<qname<<"|"<<qtype.getName()<<"'"<<endl;
  string authdomain(qname);

  domainmap_t::const_iterator iter=getBestAuthZone(&authdomain);
  if(iter==s_domainmap.end()) {
    LOG<<prefix<<qname<<": auth storage has no zone for this query!"<<endl;
    return false;
  }
  LOG<<prefix<<qname<<": auth storage has data, zone='"<<authdomain<<"'"<<endl;
  pair<AuthDomain::records_t::const_iterator, AuthDomain::records_t::const_iterator> range;

  range=iter->second.d_records.equal_range(tie(qname)); // partial lookup
  
  ret.clear();
  AuthDomain::records_t::const_iterator ziter;
  bool somedata=false;
  for(ziter=range.first; ziter!=range.second; ++ziter) {
    somedata=true;
    if(qtype.getCode()==QType::ANY || ziter->qtype==qtype || ziter->qtype.getCode()==QType::CNAME)  // let rest of nameserver do the legwork on this one
      ret.push_back(*ziter);
  }
  if(!ret.empty()) {
    LOG<<prefix<<qname<<": exact match in zone '"<<authdomain<<"'"<<endl;
    res=0;
    return true;
  }
  if(somedata) {
    LOG<<prefix<<qname<<": found record in '"<<authdomain<<"', but nothing of the right type, sending SOA"<<endl;
    ziter=iter->second.d_records.find(make_tuple(authdomain, QType(QType::SOA)));
    if(ziter!=iter->second.d_records.end()) {
      DNSResourceRecord rr=*ziter;
      rr.d_place=DNSResourceRecord::AUTHORITY;
      ret.push_back(rr);
    }
    else
      LOG<<prefix<<qname<<": can't find SOA record '"<<authdomain<<"' in our zone!"<<endl;
    res=RCode::NoError;
    return true;
  }

  string nsdomain(qname);

  while(chopOffDotted(nsdomain) && nsdomain!=iter->first) {
    range=iter->second.d_records.equal_range(make_tuple(nsdomain,QType(QType::NS))); 
    if(range.first==range.second)
      continue;

    for(ziter=range.first; ziter!=range.second; ++ziter) {
      DNSResourceRecord rr=*ziter;
      rr.d_place=DNSResourceRecord::AUTHORITY;
      ret.push_back(rr);
    }
  }
  if(ret.empty()) {
    LOG<<prefix<<qname<<": no NS match in zone '"<<authdomain<<"' either, handing out SOA"<<endl;
    ziter=iter->second.d_records.find(make_tuple(authdomain, QType(QType::SOA)));
    if(ziter!=iter->second.d_records.end()) {
      DNSResourceRecord rr=*ziter;
      rr.d_place=DNSResourceRecord::AUTHORITY;
      ret.push_back(rr);
    }
    else
      LOG<<prefix<<qname<<": can't find SOA record '"<<authdomain<<"' in our zone!"<<endl;
    res=RCode::NXDomain;
  }
  else 
    res=0;

  return true;
}

int SyncRes::doResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, set<GetBestNSAnswer>& beenthere)
{
  string prefix;
  if(s_log) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }
  
  int res=0;
  if(!(d_nocache && qtype.getCode()==QType::NS && qname==".")) {
    if(d_cacheonly) { // very limited OOB support
      LWResult lwr;
      LOG<<prefix<<qname<<": Recursion not requested for '"<<qname<<"|"<<qtype.getName()<<"', peeking at auth/forward zones"<<endl;
      string authname(qname);
      domainmap_t::const_iterator iter=getBestAuthZone(&authname);
      if(iter != s_domainmap.end()) {
	string server=iter->second.d_server;
	if(server.empty()) {
	  ret.clear();
	  doOOBResolve(qname, qtype, ret, depth, res);
	  return res;
	}
	else {
	  LOG<<prefix<<qname<<": forwarding query to hardcoded nameserver '"<<server<<"' for zone '"<<authname<<"'"<<endl;
	  ComboAddress remoteIP(server, 53);

	  res=asyncresolve(remoteIP, qname, qtype.getCode(), false, false, &d_now, &lwr);    
	  // filter out the good stuff from lwr.result()

	  for(LWResult::res_t::const_iterator i=lwr.d_result.begin();i!=lwr.d_result.end();++i) {
	    if(i->d_place == DNSResourceRecord::ANSWER)
	      ret.push_back(*i);
	  }
	  return res;
	}
      }
    }

    if(doCNAMECacheCheck(qname,qtype,ret,depth,res)) // will reroute us if needed
      return res;
    
    if(doCacheCheck(qname,qtype,ret,depth,res)) // we done
      return res;
  }

  if(d_cacheonly)
    return 0;
    
  LOG<<prefix<<qname<<": No cache hit for '"<<qname<<"|"<<qtype.getName()<<"', trying to find an appropriate NS record"<<endl;

  string subdomain(qname);

  set<string, CIStringCompare> nsset;
  bool flawedNSSet=false;
  for(int tries=0;tries<2 && nsset.empty();++tries) {
    subdomain=getBestNSNamesFromCache(subdomain, nsset, &flawedNSSet, depth, beenthere); //  pass beenthere to both occasions

    if(nsset.empty()) { // must've lost root records
      LOG<<prefix<<qname<<": our root expired, repriming from hints and retrying"<<endl;
      primeHints();
    }
  }

  if(!(res=doResolveAt(nsset, subdomain, flawedNSSet, qname, qtype, ret, depth, beenthere)))
    return 0;
  
  LOG<<prefix<<qname<<": failed (res="<<res<<")"<<endl;
  return res<0 ? RCode::ServFail : res;
}

/** This function explicitly goes out for A addresses, but if configured to use IPv6 as well, will also return any IPv6 addresses in the cache
    Additionally, it will return the 'best' address up front, and the rest shufled
*/
vector<ComboAddress> SyncRes::getAs(const string &qname, int depth, set<GetBestNSAnswer>& beenthere)
{
  typedef vector<DNSResourceRecord> res_t;
  res_t res;

  typedef vector<ComboAddress> ret_t;
  ret_t ret;

  if(!doResolve(qname, s_doIPv6 ? QType(QType::ADDR) : QType(QType::A), res,depth+1,beenthere) && !res.empty()) {  // this consults cache, OR goes out
    for(res_t::const_iterator i=res.begin(); i!= res.end(); ++i) {
      if(i->qtype.getCode()==QType::A || i->qtype.getCode()==QType::AAAA) {
	ret.push_back(ComboAddress(i->content, 53));
      }
    }
  }
  
  if(ret.size() > 1) {
    random_shuffle(ret.begin(), ret.end());

    // move 'best' address for this nameserver name up front
    nsspeeds_t::iterator best = s_nsSpeeds.find(qname);  

    if(best != s_nsSpeeds.end())
      for(ret_t::iterator i=ret.begin(); i != ret.end(); ++i) {  
	if(*i==best->second.d_best) {  // got the fastest one
	  if(i!=ret.begin()) {
	    *i=*ret.begin();
	    *ret.begin()=best->second.d_best;
	  }
	  break;
	}
      }
  }
    
  return ret;
}

void SyncRes::getBestNSFromCache(const string &qname, set<DNSResourceRecord>&bestns, bool* flawedNSSet, int depth, set<GetBestNSAnswer>& beenthere)
{
  string prefix, subdomain(qname);
  if(s_log) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }
  bestns.clear();

  do {
    LOG<<prefix<<qname<<": Checking if we have NS in cache for '"<<subdomain<<"'"<<endl;
    set<DNSResourceRecord> ns;
    *flawedNSSet = false;
    if(RC.get(d_now.tv_sec, subdomain, QType(QType::NS), &ns) > 0) {
      for(set<DNSResourceRecord>::const_iterator k=ns.begin();k!=ns.end();++k) {
	if(k->ttl > (unsigned int)d_now.tv_sec ) { 
	  set<DNSResourceRecord> aset;

	  DNSResourceRecord rr=*k;
	  rr.content=k->content;
	  if(!dottedEndsOn(rr.content, subdomain) || RC.get(d_now.tv_sec, rr.content, s_doIPv6 ? QType(QType::ADDR) : QType(QType::A),
							    s_log ? &aset : 0) > 5) {
	    bestns.insert(rr);
	    
	    LOG<<prefix<<qname<<": NS (with ip, or non-glue) in cache for '"<<subdomain<<"' -> '"<<rr.content<<"'"<<endl;
	    LOG<<prefix<<qname<<": within bailiwick: "<<dottedEndsOn(rr.content, subdomain);
	    if(!aset.empty()) {
	      LOG<<",  in cache, ttl="<<(unsigned int)(((time_t)aset.begin()->ttl- d_now.tv_sec ))<<endl;
	    }
	    else {
	      LOG<<", not in cache / did not look at cache"<<endl;
	    }
	  }
	  else {
	    *flawedNSSet=true;
	    LOG<<prefix<<qname<<": NS in cache for '"<<subdomain<<"', but needs glue ("<<k->content<<") which we miss or is expired"<<endl;
	  }
	}
      }
      if(!bestns.empty()) {
	GetBestNSAnswer answer;
	answer.qname=qname; answer.bestns=bestns;
	if(beenthere.count(answer)) {
	  LOG<<prefix<<qname<<": We have NS in cache for '"<<subdomain<<"' but part of LOOP! Trying less specific NS"<<endl;
	  if(s_log)
	    for( set<GetBestNSAnswer>::const_iterator j=beenthere.begin();j!=beenthere.end();++j)
	      LOG<<prefix<<qname<<": beenthere: "<<j->qname<<" ("<<(unsigned int)j->bestns.size()<<")"<<endl;
	  bestns.clear();
	}
	else {
	  beenthere.insert(answer);
	  LOG<<prefix<<qname<<": We have NS in cache for '"<<subdomain<<"' (flawedNSSet="<<*flawedNSSet<<")"<<endl;
	  return;
	}
      }
    }
    LOG<<prefix<<qname<<": no valid/useful NS in cache for '"<<subdomain<<"'"<<endl;
  }while(chopOffDotted(subdomain));
}

SyncRes::domainmap_t::const_iterator SyncRes::getBestAuthZone(string* qname)
{
  SyncRes::domainmap_t::const_iterator ret;
  do {
    ret=s_domainmap.find(*qname);
    if(ret!=s_domainmap.end()) 
      break;
  }while(chopOffDotted(*qname));
  return ret;
}

/** doesn't actually do the work, leaves that to getBestNSFromCache */
string SyncRes::getBestNSNamesFromCache(const string &qname, set<string, CIStringCompare>& nsset, bool* flawedNSSet, int depth, set<GetBestNSAnswer>&beenthere)
{
  string subdomain(qname);

  string authdomain(qname);
  
  domainmap_t::const_iterator iter=getBestAuthZone(&authdomain);
  if(iter!=s_domainmap.end()) {
    nsset.insert(iter->second.d_server); // this gets picked up in doResolveAt, if empty it means "we are auth", otherwise it denotes a forward
    return authdomain;
  }

  set<DNSResourceRecord> bestns;
  getBestNSFromCache(subdomain, bestns, flawedNSSet, depth, beenthere);

  for(set<DNSResourceRecord>::const_iterator k=bestns.begin();k!=bestns.end();++k) {
    nsset.insert(k->content);
    if(k==bestns.begin())
      subdomain=k->qname;
  }
  return subdomain;
}

bool SyncRes::doCNAMECacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res)
{
  string prefix;
  if(s_log) {
    prefix=d_prefix; 
    prefix.append(depth, ' ');
  }

  if(depth>10) {
    LOG<<prefix<<qname<<": CNAME loop too deep, depth="<<depth<<endl;
    res=RCode::ServFail;
    return true;
  }
  
  LOG<<prefix<<qname<<": Looking for CNAME cache hit of '"<<(qname+"|CNAME")<<"'"<<endl;
  set<DNSResourceRecord> cset;
  if(RC.get(d_now.tv_sec, qname,QType(QType::CNAME),&cset) > 0) {

    for(set<DNSResourceRecord>::const_iterator j=cset.begin();j!=cset.end();++j) {
      if(j->ttl>(unsigned int) d_now.tv_sec) {
	LOG<<prefix<<qname<<": Found cache CNAME hit for '"<< (qname+"|CNAME") <<"' to '"<<j->content<<"'"<<endl;    
	DNSResourceRecord rr=*j;
	rr.ttl-=d_now.tv_sec;
	ret.push_back(rr);
	if(!(qtype==QType(QType::CNAME))) { // perhaps they really wanted a CNAME!
	  set<GetBestNSAnswer>beenthere;
	  res=doResolve(j->content, qtype, ret, depth+1, beenthere);
	}
	else
	  res=0;
	return true;
      }
    }
  }
  LOG<<prefix<<qname<<": No CNAME cache hit of '"<< (qname+"|CNAME") <<"' found"<<endl;
  return false;
}

bool SyncRes::doCacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res)
{
  bool giveNegative=false;
  
  string prefix;
  if(s_log) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }

  string sqname(qname);
  QType sqt(qtype);
  uint32_t sttl=0;
  //  cout<<"Lookup for '"<<qname<<"|"<<qtype.getName()<<"'\n";

  pair<negcache_t::const_iterator, negcache_t::const_iterator> range=s_negcache.equal_range(tie(qname));
  negcache_t::iterator ni;
  for(ni=range.first; ni != range.second; ni++) {
    // we have something
    if(ni->d_qtype.getCode() == 0 || ni->d_qtype == qtype) {
      res=0;
      if((uint32_t)d_now.tv_sec < ni->d_ttd) {
	sttl=ni->d_ttd - d_now.tv_sec;
	if(ni->d_qtype.getCode()) {
	  LOG<<prefix<<qname<<": "<<qtype.getName()<<" is negatively cached via '"<<ni->d_qname<<"' for another "<<sttl<<" seconds"<<endl;
	  res = RCode::NoError;
	}
	else {
	  LOG<<prefix<<qname<<": Entire record '"<<qname<<"', is negatively cached via '"<<ni->d_qname<<"' for another "<<sttl<<" seconds"<<endl;
	  res= RCode::NXDomain; 
	}
	giveNegative=true;
	sqname=ni->d_qname;
	sqt=QType::SOA;
	break;
      }
      else {
	LOG<<prefix<<qname<<": Entire record '"<<qname<<"' was negatively cached, but entry expired"<<endl;
      }
    }
  }

  set<DNSResourceRecord> cset;
  bool found=false, expired=false;

  if(RC.get(d_now.tv_sec, sqname, sqt, &cset) > 0) {
    LOG<<prefix<<sqname<<": Found cache hit for "<<sqt.getName()<<": ";
    for(set<DNSResourceRecord>::const_iterator j=cset.begin();j!=cset.end();++j) {
      LOG<<j->content;
      if(j->ttl>(unsigned int) d_now.tv_sec) {
	DNSResourceRecord rr=*j;
	rr.ttl-=d_now.tv_sec;
	if(giveNegative) {
	  rr.d_place=DNSResourceRecord::AUTHORITY;
	  rr.ttl=sttl;
	}
	ret.push_back(rr);
	LOG<<"[ttl="<<rr.ttl<<"] ";
	found=true;
      }
      else {
	LOG<<"[expired] ";
	expired=true;
      }
    }
  
    LOG<<endl;
    if(found && !expired) {
      if(!giveNegative)
	res=0;
      return true;
    }
    else
      LOG<<prefix<<qname<<": cache had only stale entries"<<endl;
  }

  return false;
}

bool SyncRes::moreSpecificThan(const string& a, const string &b)
{
  static string dot(".");
  int counta=(a!=dot), countb=(b!=dot);
  
  for(string::size_type n=0;n<a.size();++n)
    if(a[n]=='.')
      counta++;
  for(string::size_type n=0;n<b.size();++n)
    if(b[n]=='.')
      countb++;
  return counta>countb;
}

struct speedOrder
{
  speedOrder(map<string,double> &speeds) : d_speeds(speeds) {}
  bool operator()(const string &a, const string &b) const
  {
    return d_speeds[a] < d_speeds[b];
  }
  map<string,double>& d_speeds;
};

inline vector<string> SyncRes::shuffleInSpeedOrder(set<string, CIStringCompare> &nameservers, const string &prefix)
{
  vector<string> rnameservers;
  rnameservers.reserve(nameservers.size());
  map<string,double> speeds;

  for(set<string, CIStringCompare>::const_iterator i=nameservers.begin();i!=nameservers.end();++i) {
    rnameservers.push_back(*i);
    speeds[*i]=s_nsSpeeds[*i].get(&d_now);
  }
  random_shuffle(rnameservers.begin(),rnameservers.end());
  speedOrder so(speeds);
  stable_sort(rnameservers.begin(),rnameservers.end(), so);
  
  if(s_log) {
    L<<Logger::Warning<<prefix<<"Nameservers: ";
    for(vector<string>::const_iterator i=rnameservers.begin();i!=rnameservers.end();++i) {
      if(i!=rnameservers.begin()) {
	L<<", ";
	if(!((i-rnameservers.begin())%3))
	  L<<endl<<Logger::Warning<<prefix<<"             ";
      }
      L<<*i<<"(" << (int)(speeds[*i]/1000.0) <<"ms)";
    }
    L<<endl;
  }
  return rnameservers;
}

struct TCacheComp
{
  bool operator()(const pair<string, QType>& a, const pair<string, QType>& b) const
  {
    int cmp=Utility::strcasecmp(a.first.c_str(), b.first.c_str());
    if(cmp < 0)
      return true;
    if(cmp > 0)
      return false;

    return a.second < b.second;
  }
};



/** returns -1 in case of no results, rcode otherwise */
int SyncRes::doResolveAt(set<string, CIStringCompare> nameservers, string auth, bool flawedNSSet, const string &qname, const QType &qtype, 
			 vector<DNSResourceRecord>&ret, 
			 int depth, set<GetBestNSAnswer>&beenthere)
{
  string prefix;
  if(s_log) {
    prefix=d_prefix;
    prefix.append(depth, ' ');
  }
  
  LOG<<prefix<<qname<<": Cache consultations done, have "<<(unsigned int)nameservers.size()<<" NS to contact"<<endl;

  for(;;) { // we may get more specific nameservers
    vector<string> rnameservers=shuffleInSpeedOrder(nameservers, s_log ? (prefix+qname+": ") : string() );

    for(vector<string>::const_iterator tns=rnameservers.begin();;++tns) { 
      if(tns==rnameservers.end()) {
	LOG<<prefix<<qname<<": Failed to resolve via any of the "<<(unsigned int)rnameservers.size()<<" offered NS at level '"<<auth<<"'"<<endl;
	if(auth!="." && flawedNSSet) {
	  g_stats.nsSetInvalidations++;
	  LOG<<prefix<<qname<<": Invalidating nameservers for level '"<<auth<<"', next query might succeed"<<endl;
	  RC.doWipeCache(auth, QType::NS);
	}
	return -1;
      }
      if(qname==*tns && qtype.getCode()==QType::A) {
	LOG<<prefix<<qname<<": Not using NS to resolve itself!"<<endl;
	continue;
      }

      typedef vector<ComboAddress> remoteIPs_t;
      remoteIPs_t remoteIPs;
      remoteIPs_t::const_iterator remoteIP;
      bool doTCP=false;
      int resolveret;

      LWResult lwr;
      if(tns->empty()) {
	LOG<<prefix<<qname<<": Domain is out-of-band"<<endl;
	doOOBResolve(qname, qtype, lwr.d_result, depth, lwr.d_rcode);
	lwr.d_tcbit=false;
	lwr.d_aabit=true;
      }
      else {
	LOG<<prefix<<qname<<": Trying to resolve NS '"<<*tns<<"' ("<<1+tns-rnameservers.begin()<<"/"<<(unsigned int)rnameservers.size()<<")"<<endl;
	if(!isCanonical(*tns)) {
	  LOG<<prefix<<qname<<": Domain has hardcoded nameserver"<<endl;
	  remoteIPs.push_back(ComboAddress(*tns, 53));
	}
	else
	  remoteIPs=getAs(*tns, depth+1, beenthere);

	if(remoteIPs.empty()) {
	  LOG<<prefix<<qname<<": Failed to get IP for NS "<<*tns<<", trying next if available"<<endl;
	  flawedNSSet=true;
	  continue;
	}
	else {
	  LOG<<prefix<<qname<<": Resolved '"+auth+"' NS "<<*tns<<" to: ";
	  for(remoteIP = remoteIPs.begin(); remoteIP != remoteIPs.end(); ++remoteIP) {
	    if(remoteIP != remoteIPs.begin())
	      LOG<<", ";
	    LOG<<remoteIP->toString();
	  }
	  LOG<<endl;

	}

	for(remoteIP = remoteIPs.begin(); remoteIP != remoteIPs.end(); ++remoteIP) {
	  LOG<<prefix<<qname<<": Trying IP "<< remoteIP->toString() <<", asking '"<<qname<<"|"<<qtype.getName()<<"'"<<endl;
	  extern NetmaskGroup* g_dontQuery;
	  
	  if(s_throttle.shouldThrottle(d_now.tv_sec, make_tuple(*remoteIP, qname, qtype.getCode()))) {
	    LOG<<prefix<<qname<<": query throttled "<<endl;
	    s_throttledqueries++; d_throttledqueries++;
	    continue;
	  } 
	  else if(g_dontQuery && g_dontQuery->match(&*remoteIP)) {
	    LOG<<prefix<<qname<<": not sending query to " << remoteIP->toString() << ", blocked by 'dont-query' setting" << endl;
	    continue;
	  }
	  else {
	    s_outqueries++; d_outqueries++;
	  TryTCP:
	    if(doTCP) {
	      s_tcpoutqueries++; d_tcpoutqueries++;
	    }
	    
	    resolveret=asyncresolve(*remoteIP, qname, 
				    (qtype.getCode() == QType::ADDR ? QType::ANY : qtype.getCode()), 
				    doTCP, d_doEDNS0, &d_now, &lwr);    // <- we go out on the wire!
	    if(resolveret != 1) {
	      if(resolveret==0) {
		LOG<<prefix<<qname<<": timeout resolving "<< (doTCP ? "over TCP" : "")<<endl;
		d_timeouts++;
		s_outgoingtimeouts++;
	      }
	      else if(resolveret==-2) {
		LOG<<prefix<<qname<<": hit a local resource limit resolving"<< (doTCP ? " over TCP" : "")<<", probable error: "<<stringerror()<<endl;
		g_stats.resourceLimits++;
	      }
	      else {
		s_unreachables++; d_unreachables++;
		LOG<<prefix<<qname<<": error resolving"<< (doTCP ? " over TCP" : "") <<", possible error: "<<strerror(errno)<< endl;
	      }
	      
	      if(resolveret!=-2) { // don't account for resource limits, they are our own fault
		s_nsSpeeds[*tns].submit(*remoteIP, 1000000, &d_now); // 1 sec
		if(resolveret==-1)
		  s_throttle.throttle(d_now.tv_sec, make_tuple(*remoteIP, qname, qtype.getCode()), 60, 100); // unreachable
		else
		  s_throttle.throttle(d_now.tv_sec, make_tuple(*remoteIP, qname, qtype.getCode()), 20, 5);  // timeout
	      }
	      continue;
	    }
	    
	    break;  // this IP address worked!
	  wasLame:; // well, it didn't
	    LOG<<prefix<<qname<<": status=NS "<<*tns<<" ("<< remoteIP->toString() <<") is lame for '"<<auth<<"', trying sibling IP or NS"<<endl;
	    s_throttle.throttle(d_now.tv_sec, make_tuple(*remoteIP, qname, qtype.getCode()), 60, 100);
	  }
	}
	
	if(remoteIP == remoteIPs.end())  // we tried all IP addresses, none worked
	  continue; 
	
	if(lwr.d_tcbit) {
	  if(!doTCP) {
	    doTCP=true;
	    LOG<<prefix<<qname<<": truncated bit set, retrying via TCP"<<endl;
	    goto TryTCP;
	  }
	  LOG<<prefix<<qname<<": truncated bit set, over TCP?"<<endl;
	  return RCode::ServFail;
	}
	
	if(lwr.d_rcode==RCode::ServFail) {
	  LOG<<prefix<<qname<<": "<<*tns<<" returned a ServFail, trying sibling IP or NS"<<endl;
	  s_throttle.throttle(d_now.tv_sec,make_tuple(*remoteIP, qname, qtype.getCode()),60,3);
	  continue;
	}
	LOG<<prefix<<qname<<": Got "<<(unsigned int)lwr.d_result.size()<<" answers from "<<*tns<<" ("<< remoteIP->toString() <<"), rcode="<<lwr.d_rcode<<", in "<<lwr.d_usec/1000<<"ms"<<endl;

	/*  // for you IPv6 fanatics :-)
	if(remoteIP->sin4.sin_family==AF_INET6)
	  lwr.d_usec/=3;
	*/

	s_nsSpeeds[*tns].submit(*remoteIP, lwr.d_usec, &d_now);
      }

      typedef map<pair<string, QType>, set<DNSResourceRecord>, TCacheComp > tcache_t;
      tcache_t tcache;

      // reap all answers from this packet that are acceptable
      for(LWResult::res_t::const_iterator i=lwr.d_result.begin();i != lwr.d_result.end();++i) {
	if(i->qtype.getCode() == QType::OPT) {
	  LOG<<prefix<<qname<<": skipping OPT answer '"<<i->qname<<"' from '"<<auth<<"' nameservers" <<endl;
	  continue;
	}
	LOG<<prefix<<qname<<": accept answer '"<<i->qname<<"|"<<i->qtype.getName()<<"|"<<i->content<<"' from '"<<auth<<"' nameservers? ";
	if(i->qtype.getCode()==QType::ANY) {
	  LOG<<"NO! - we don't accept 'ANY' data"<<endl;
	  continue;
	}
	  
	if(dottedEndsOn(i->qname, auth)) {
	  if(lwr.d_aabit && lwr.d_rcode==RCode::NoError && i->d_place==DNSResourceRecord::ANSWER && ::arg().contains("delegation-only",auth)) {
	    LOG<<"NO! Is from delegation-only zone"<<endl;
	    s_nodelegated++;
	    return RCode::NXDomain;
	  }
	  else {
	    LOG<<"YES!"<<endl;
	    
	    DNSResourceRecord rr=*i;
	    rr.d_place=DNSResourceRecord::ANSWER;

	    rr.ttl=min(86400*14U, rr.ttl); // limit TTL to two weeks
	    rr.ttl += d_now.tv_sec;

	    if(rr.qtype.getCode() == QType::NS) // people fiddle with the case
	      rr.content=toLower(rr.content); // this must stay! (the cache can't be case-insensitive on the RHS of records)
	    tcache[make_pair(i->qname,i->qtype)].insert(rr);
	  }
	}	  
	else
	  LOG<<"NO!"<<endl;
      }
    
      // supplant
      for(tcache_t::iterator i=tcache.begin();i!=tcache.end();++i) {
	if(i->second.size() > 1) {  // need to group the ttl to be the minimum of the RRSET (RFC 2181, 5.2)
	  uint32_t lowestTTL=numeric_limits<uint32_t>::max();
	  for(tcache_t::value_type::second_type::iterator j=i->second.begin(); j != i->second.end(); ++j)
	    lowestTTL=min(lowestTTL, j->ttl);
	  
	  for(tcache_t::value_type::second_type::iterator j=i->second.begin(); j != i->second.end(); ++j)
	    ((tcache_t::value_type::second_type::value_type*)&(*j))->ttl=lowestTTL;
	}

	RC.replace(d_now.tv_sec, i->first.first, i->first.second, i->second, lwr.d_aabit);
      }
      set<string, CIStringCompare> nsset;  
      LOG<<prefix<<qname<<": determining status after receiving this packet"<<endl;

      bool done=false, realreferral=false, negindic=false;
      string newauth, soaname, newtarget;

      for(LWResult::res_t::const_iterator i=lwr.d_result.begin();i!=lwr.d_result.end();++i) {
	if(i->d_place==DNSResourceRecord::AUTHORITY && dottedEndsOn(qname,i->qname) && i->qtype.getCode()==QType::SOA && 
	   lwr.d_rcode==RCode::NXDomain) {
	  LOG<<prefix<<qname<<": got negative caching indication for RECORD '"<<qname+"'"<<endl;
	  ret.push_back(*i);

	  NegCacheEntry ne;

	  ne.d_qname=i->qname;
	  ne.d_ttd=d_now.tv_sec + min(i->ttl, s_maxnegttl); // controversial
	  ne.d_name=qname;
	  ne.d_qtype=QType(0); // this encodes 'whole record'
	  
	  replacing_insert(s_negcache, ne);
	  negindic=true;
	}
	else if(i->d_place==DNSResourceRecord::ANSWER && i->qname==qname && i->qtype.getCode()==QType::CNAME && (!(qtype==QType(QType::CNAME)))) {
	  ret.push_back(*i);
	  newtarget=i->content;
	}
	// for ANY answers we *must* have an authoritive answer
	else if(i->d_place==DNSResourceRecord::ANSWER && !Utility::strcasecmp(i->qname.c_str(),qname.c_str()) && 
		(i->qtype==qtype || 
		 (
		  lwr.d_aabit && 
		     ( qtype == QType(QType::ADDR) && (i->qtype.getCode()==QType::A || i->qtype.getCode()==QType::AAAA) ) || qtype==QType(QType::ANY) 
		  )   
		 ) 
		)   {
	
	  LOG<<prefix<<qname<<": answer is in: resolved to '"<< i->content<<"|"<<i->qtype.getName()<<"'"<<endl;

	  done=true;
	  ret.push_back(*i);
	}
	else if(i->d_place==DNSResourceRecord::AUTHORITY && dottedEndsOn(qname,i->qname) && i->qtype.getCode()==QType::NS) { 
	  if(moreSpecificThan(i->qname,auth)) {
	    newauth=i->qname;
	    LOG<<prefix<<qname<<": got NS record '"<<i->qname<<"' -> '"<<i->content<<"'"<<endl;
	    realreferral=true;
	  }
	  else 
	    LOG<<prefix<<qname<<": got upwards/level NS record '"<<i->qname<<"' -> '"<<i->content<<"', had '"<<auth<<"'"<<endl;
	  nsset.insert(i->content);
	}
	else if(!done && i->d_place==DNSResourceRecord::AUTHORITY && dottedEndsOn(qname,i->qname) && i->qtype.getCode()==QType::SOA && 
	   lwr.d_rcode==RCode::NoError) {
	  LOG<<prefix<<qname<<": got negative caching indication for '"<< (qname+"|"+i->qtype.getName()+"'") <<endl;
	  ret.push_back(*i);
	  
	  NegCacheEntry ne;
	  ne.d_qname=i->qname;
	  ne.d_ttd=d_now.tv_sec + min(s_maxnegttl, i->ttl);
	  ne.d_name=qname;
	  ne.d_qtype=qtype;
	  if(qtype.getCode()) {  // prevents us from blacking out a whole domain
	    replacing_insert(s_negcache, ne);
	  }
	  negindic=true;
	}
      }

      if(done){ 
	LOG<<prefix<<qname<<": status=got results, this level of recursion done"<<endl;
	return 0;
      }
      if(lwr.d_rcode==RCode::NXDomain) {
	LOG<<prefix<<qname<<": status=NXDOMAIN, we are done "<<(negindic ? "(have negative SOA)" : "")<<endl;
	return RCode::NXDomain;
      }
      if(!newtarget.empty()) {
	if(iequals(newtarget,qname)) {
	  LOG<<prefix<<qname<<": status=got a CNAME referral to self, returning SERVFAIL"<<endl;
	  return RCode::ServFail;
	}
	if(depth > 10) {
	  LOG<<prefix<<qname<<": status=got a CNAME referral, but recursing too deep, returning SERVFAIL"<<endl;
	  return RCode::ServFail;
	}
	LOG<<prefix<<qname<<": status=got a CNAME referral, starting over with "<<newtarget<<endl;

	set<GetBestNSAnswer>beenthere2;
	return doResolve(newtarget, qtype, ret, depth + 1, beenthere2);
      }
      if(nsset.empty() && !lwr.d_rcode) {
	LOG<<prefix<<qname<<": status=noerror, other types may exist, but we are done "<<(negindic ? "(have negative SOA)" : "")<<endl;
	return 0;
      }
      else if(realreferral) {
	LOG<<prefix<<qname<<": status=did not resolve, got "<<(unsigned int)nsset.size()<<" NS, looping to them"<<endl;
	auth=newauth;
	nameservers=nsset;
	break; 
      }
      else if(isCanonical(*tns)) {
	goto wasLame;
      }
    }
  }
  return -1;
}

static bool uniqueComp(const DNSResourceRecord& a, const DNSResourceRecord& b)
{
  return(a.qtype==b.qtype && a.qname==b.qname && a.content==b.content);
}

void SyncRes::addCruft(const string &qname, vector<DNSResourceRecord>& ret)
{
  for(vector<DNSResourceRecord>::const_iterator k=ret.begin();k!=ret.end();++k)  // don't add stuff to an NXDOMAIN!
    if(k->d_place==DNSResourceRecord::AUTHORITY && k->qtype==QType(QType::SOA))
      return;

  //  LOG<<qname<<": Adding best authority records from cache"<<endl;
  // addAuthorityRecords(qname,ret,0);
  // LOG<<qname<<": Done adding best authority records."<<endl;

  LOG<<d_prefix<<qname<<": Starting additional processing"<<endl;
  vector<DNSResourceRecord> addit;
  static optional<bool> l_doIPv6AP;
  if(!l_doIPv6AP)
    l_doIPv6AP=::arg().mustDo("aaaa-additional-processing");

  for(vector<DNSResourceRecord>::const_iterator k=ret.begin();k!=ret.end();++k) 
    if( (k->d_place==DNSResourceRecord::ANSWER && (k->qtype==QType(QType::MX) || k->qtype==QType(QType::SRV)))  || 
       ((k->d_place==DNSResourceRecord::AUTHORITY || k->d_place==DNSResourceRecord::ANSWER) && k->qtype==QType(QType::NS))) {
      LOG<<d_prefix<<qname<<": record '"<<k->content<<"|"<<k->qtype.getName()<<"' needs IP for additional processing"<<endl;
      set<GetBestNSAnswer> beenthere;
      vector<pair<string::size_type, string::size_type> > fields;
      vstringtok(fields, k->content, " ");
      string host;
      if(k->qtype==QType(QType::MX) && fields.size()==2)
	host=string(k->content.c_str() + fields[1].first, fields[1].second - fields[1].first);
      else if(k->qtype==QType(QType::NS))
	host=k->content;
      else if(k->qtype==QType(QType::SRV) && fields.size()==4)
	host=string(k->content.c_str() + fields[3].first, fields[3].second - fields[3].first);
      else 
	continue;
      doResolve(host, *l_doIPv6AP ? QType(QType::ADDR) : QType(QType::A), addit, 1, beenthere);
    }
  
  sort(addit.begin(), addit.end());
  addit.erase(unique(addit.begin(), addit.end(), uniqueComp), addit.end());
  for(vector<DNSResourceRecord>::iterator k=addit.begin();k!=addit.end();++k) {
    if(k->qtype.getCode()==QType::A || k->qtype.getCode()==QType::AAAA) {
      k->d_place=DNSResourceRecord::ADDITIONAL;
      ret.push_back(*k);
    }
  }
  LOG<<d_prefix<<qname<<": Done with additional processing"<<endl;
}

void SyncRes::addAuthorityRecords(const string& qname, vector<DNSResourceRecord>& ret, int depth)
{
  set<DNSResourceRecord> bestns;
  set<GetBestNSAnswer> beenthere;
  bool dontcare;
  getBestNSFromCache(qname, bestns, &dontcare, depth, beenthere);

  for(set<DNSResourceRecord>::const_iterator k=bestns.begin();k!=bestns.end();++k) {
    DNSResourceRecord ns=*k;
    ns.d_place=DNSResourceRecord::AUTHORITY;
    ns.ttl-=d_now.tv_sec;
    ret.push_back(ns);
  }
}
