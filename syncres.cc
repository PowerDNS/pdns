/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003 - 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published 
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

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

unsigned int SyncRes::s_queries;
unsigned int SyncRes::s_outgoingtimeouts;
unsigned int SyncRes::s_outqueries;
unsigned int SyncRes::s_tcpoutqueries;
unsigned int SyncRes::s_throttledqueries;
unsigned int SyncRes::s_nodelegated;
bool SyncRes::s_log;

#define LOG if(s_log) L<<Logger::Warning

Throttle<string> SyncRes::s_throttle;

/** everything begins here - this is the entry point just after receiving a packet */
int SyncRes::beginResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret)
{
  set<GetBestNSAnswer> beenthere;
  s_queries++;
  int res=doResolve(qname, qtype, ret,0,beenthere);
  if(!res)
    addCruft(qname, ret);
  return res;
}

int SyncRes::doResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, set<GetBestNSAnswer>& beenthere)
{
  string prefix(d_prefix);
  prefix.append(depth, ' ');
  
  int res;
  if(!(d_nocache && qtype.getCode()==QType::NS && qname.empty())) {
    if(doCNAMECacheCheck(qname,qtype,ret,depth,res)) // will reroute us if needed
      return res;
    
    if(doCacheCheck(qname,qtype,ret,depth,res)) // we done
      return res;
  }

  if(d_cacheonly)
    return 0;

  LOG<<prefix<<qname<<": No cache hit for '"<<qname<<"|"<<qtype.getName()<<"', trying to find an appropriate NS record"<<endl;

  string subdomain(qname);

  set<string> nsset;
  for(int tries=0;tries<2 && nsset.empty();++tries) {
    subdomain=getBestNSNamesFromCache(subdomain,nsset,depth, beenthere); //  pass beenthere to both occasions

    if(nsset.empty()) { // must've lost root records
      LOG<<prefix<<qname<<": our root expired, repriming from hints and retrying"<<endl;
      primeHints();
    }
  }

  if(!(res=doResolveAt(nsset,subdomain,qname,qtype,ret,depth, beenthere)))
    return 0;
  
  LOG<<prefix<<qname<<": failed"<<endl;
  return res<0 ? RCode::ServFail : res;
}

string SyncRes::getA(const string &qname, int depth, set<GetBestNSAnswer>& beenthere)
{
  vector<DNSResourceRecord> res;
  string ret;

  if(!doResolve(qname,QType(QType::A), res,depth+1,beenthere) && !res.empty()) 
    ret=res[res.size()-1].content; // last entry, in case of CNAME in between

  return ret;
}

void SyncRes::getBestNSFromCache(const string &qname, set<DNSResourceRecord>&bestns, int depth, set<GetBestNSAnswer>& beenthere)
{
  string prefix(d_prefix), subdomain(qname);
  prefix.append(depth, ' ');
  bestns.clear();

  do {
    LOG<<prefix<<qname<<": Checking if we have NS in cache for '"<<subdomain<<"'"<<endl;
    set<DNSResourceRecord>ns;
    if(RC.get(d_now.tv_sec, subdomain, QType(QType::NS), &ns)>0) {

      for(set<DNSResourceRecord>::const_iterator k=ns.begin();k!=ns.end();++k) {
	if(k->ttl > (unsigned int)d_now.tv_sec ) { 
	  set<DNSResourceRecord>aset;

	  DNSResourceRecord rr=*k;
	  rr.content=toLowerCanonic(k->content);
	  if(!endsOn(rr.content,subdomain) || RC.get(d_now.tv_sec, rr.content ,QType(QType::A),&aset) > 5) {
	    bestns.insert(rr);
	    
	    LOG<<prefix<<qname<<": NS (with ip, or non-glue) in cache for '"<<subdomain<<"' -> '"<<rr.content<<"'"<<endl;
	    LOG<<prefix<<qname<<": within bailiwick: "<<endsOn(rr.content,subdomain);
	    if(!aset.empty()) {
	      LOG<<", in cache, ttl="<<(unsigned int)(((time_t)aset.begin()->ttl- d_now.tv_sec ))<<endl;
	    }
	    else {
	      LOG<<", not in cache"<<endl;
	    }
	  }
	  else
	    LOG<<prefix<<qname<<": NS in cache for '"<<subdomain<<"', but needs glue ("<<toLowerCanonic(k->content)<<") which we miss or is expired"<<endl;
	}
      }
      if(!bestns.empty()) {
	GetBestNSAnswer answer;
	answer.qname=toLower(qname); answer.bestns=bestns;
	if(beenthere.count(answer)) {
	  LOG<<prefix<<qname<<": We have NS in cache for '"<<subdomain<<"' but part of LOOP! Trying less specific NS"<<endl;
	  for( set<GetBestNSAnswer>::const_iterator j=beenthere.begin();j!=beenthere.end();++j)
	    LOG<<prefix<<qname<<": beenthere: "<<j->qname<<" ("<<j->bestns.size()<<")"<<endl;
	  bestns.clear();
	}
	else {
	  beenthere.insert(answer);
	  LOG<<prefix<<qname<<": We have NS in cache for '"<<subdomain<<"'"<<endl;
	  return;
	}
      }
    }
  }while(chopOff(subdomain));
}


/** doesn't actually do the work, leaves that to getBestNSFromCache */
string SyncRes::getBestNSNamesFromCache(const string &qname,set<string>& nsset, int depth, set<GetBestNSAnswer>&beenthere)
{
  string subdomain(qname);

  set<DNSResourceRecord> bestns;
  getBestNSFromCache(subdomain, bestns, depth, beenthere);

  for(set<DNSResourceRecord>::const_iterator k=bestns.begin();k!=bestns.end();++k) {
    nsset.insert(k->content);
    subdomain=k->qname;
  }
  return subdomain;
}

bool SyncRes::doCNAMECacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res)
{
  string prefix(d_prefix), tuple=toLowerCanonic(qname)+"|CNAME";
  prefix.append(depth, ' ');

  if(depth>10) {
    LOG<<prefix<<qname<<": CNAME loop too deep, depth="<<depth<<endl;
    res=RCode::ServFail;
    return true;
  }
  
  LOG<<prefix<<qname<<": Looking for CNAME cache hit of '"<<tuple<<"'"<<endl;
  set<DNSResourceRecord> cset;
  if(RC.get(d_now.tv_sec, qname,QType(QType::CNAME),&cset) > 0) {

    for(set<DNSResourceRecord>::const_iterator j=cset.begin();j!=cset.end();++j) {
      if(j->ttl>(unsigned int) d_now.tv_sec) {
	LOG<<prefix<<qname<<": Found cache CNAME hit for '"<<tuple<<"' to '"<<j->content<<"'"<<endl;    
	DNSResourceRecord rr=*j;
	rr.ttl-=d_now.tv_sec;
	ret.push_back(rr);
	if(!(qtype==QType(QType::CNAME))) { // perhaps they really wanted a CNAME!
	  set<GetBestNSAnswer>beenthere;
	  res=doResolve(toLowerCanonic(j->content), qtype, ret, depth+1, beenthere);
	}
	else
	  res=0;
	return true;
      }
    }
  }
  LOG<<prefix<<qname<<": No CNAME cache hit of '"<<tuple<<"' found"<<endl;
  return false;
}

bool SyncRes::doCacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res)
{
  bool giveNegative=false;
  string prefix(d_prefix), tuple;
  prefix.append(depth, ' ');

  string sqname(qname);
  QType sqt(qtype);
  uint32_t sttl=0;

  if(s_negcache.count(toLower(qname))) {
    res=0;
    negcache_t::const_iterator ni=s_negcache.find(toLower(qname));
    if(d_now.tv_sec < ni->second.ttd) {
      sttl=ni->second.ttd - d_now.tv_sec;
      LOG<<prefix<<qname<<": Entire record '"<<toLower(qname)<<"', is negatively cached for another "<<sttl<<" seconds"<<endl;
      res=RCode::NXDomain; 
      giveNegative=true;
      sqname=ni->second.name;
      sqt="SOA";
    }
    else {
      LOG<<prefix<<qname<<": Entire record '"<<toLower(qname)<<"' was negatively cached, but entry expired"<<endl;
      s_negcache.erase(toLower(qname));
    }
  }

  if(!giveNegative) { // let's try some more
    tuple=toLower(qname); tuple.append(1,'|'); tuple+=qtype.getName();
    LOG<<prefix<<qname<<": Looking for direct cache hit of '"<<tuple<<"', negative cached: "<<s_negcache.count(tuple)<<endl;

    res=0;
    negcache_t::const_iterator ni=s_negcache.find(tuple);
    if(ni!=s_negcache.end()) {
      if(d_now.tv_sec < ni->second.ttd) {
	sttl=ni->second.ttd - d_now.tv_sec;
	LOG<<prefix<<qname<<": "<<qtype.getName()<<" is negatively cached for another "<<sttl<<" seconds"<<endl;
	res=RCode::NoError; // only this record doesn't exist
	giveNegative=true;
	sqname=ni->second.name;
	sqt="SOA";
      }
      else {
	LOG<<prefix<<qname<<": "<<qtype.getName()<<" was negatively cached, but entry expired"<<endl;
	s_negcache.erase(toLower(tuple));
      }
    }
  }

  set<DNSResourceRecord> cset;
  bool found=false, expired=false;
  if(RC.get(d_now.tv_sec, sqname,sqt,&cset)>0) {
    LOG<<prefix<<qname<<": Found cache hit for "<<sqt.getName()<<": ";
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
    if(found && !expired) 
      return true;
    else
      LOG<<prefix<<qname<<": cache had only stale entries"<<endl;
  }
  return false;
}

bool SyncRes::moreSpecificThan(const string& a, const string &b)
{
  int counta=!a.empty(), countb=!b.empty();
  
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

inline vector<string> SyncRes::shuffle(set<string> &nameservers, const string &prefix)
{
  vector<string> rnameservers;
  rnameservers.reserve(nameservers.size());
  map<string,double> speeds;

  for(set<string>::const_iterator i=nameservers.begin();i!=nameservers.end();++i) {
    rnameservers.push_back(*i);
    DecayingEwma& temp=s_nsSpeeds[toLower(*i)];
    speeds[*i]=temp.get(&d_now);
  }
  random_shuffle(rnameservers.begin(),rnameservers.end());
  stable_sort(rnameservers.begin(),rnameservers.end(),speedOrder(speeds));
  
  if(s_log) {
    L<<Logger::Warning<<prefix<<"Nameservers: ";
    for(vector<string>::const_iterator i=rnameservers.begin();i!=rnameservers.end();++i) {
      if(i!=rnameservers.begin()) {
	L<<", ";
	if(!((i-rnameservers.begin())%4))
	  L<<endl<<Logger::Warning<<prefix<<"             ";
      }
      L<<*i<<"(" << (int)(speeds[*i]/1000.0) <<"ms)";
    }
    L<<endl;
  }
  return rnameservers;
}

/** returns -1 in case of no results, rcode otherwise */
int SyncRes::doResolveAt(set<string> nameservers, string auth, const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, 
		int depth, set<GetBestNSAnswer>&beenthere)
{
  string prefix(d_prefix);
  prefix.append(depth, ' ');
  
  LWRes::res_t result;

  LOG<<prefix<<qname<<": Cache consultations done, have "<<nameservers.size()<<" NS to contact"<<endl;

  for(;;) { // we may get more specific nameservers
    result.clear();

    vector<string> rnameservers=shuffle(nameservers, prefix+qname+": ");

    for(vector<string>::const_iterator tns=rnameservers.begin();;++tns) { 
      if(tns==rnameservers.end()) {
	LOG<<prefix<<qname<<": Failed to resolve via any of the "<<rnameservers.size()<<" offered NS"<<endl;
	return -1;
      }
      if(qname==*tns && qtype.getCode()==QType::A) {
	LOG<<prefix<<qname<<": Not using NS to resolve itself!"<<endl;
	continue;
      }
      LOG<<prefix<<qname<<": Trying to resolve NS "<<*tns<<" ("<<1+tns-rnameservers.begin()<<"/"<<rnameservers.size()<<")"<<endl;
      string remoteIP=getA(*tns, depth+1,beenthere);
      if(remoteIP.empty()) {
	LOG<<prefix<<qname<<": Failed to get IP for NS "<<*tns<<", trying next if available"<<endl;
	continue;
      }
      LOG<<prefix<<qname<<": Resolved '"+auth+"' NS "<<*tns<<" to "<<remoteIP<<", asking '"<<qname<<"|"<<qtype.getName()<<"'"<<endl;

      bool doTCP=false;

      if(s_throttle.shouldThrottle(d_now.tv_sec, remoteIP+"|"+qname+"|"+qtype.getName())) {
	LOG<<prefix<<qname<<": query throttled "<<endl;
	s_throttledqueries++;
	d_throttledqueries++;
	continue;
      }
      else {
	s_outqueries++;
	d_outqueries++;
      TryTCP:
	if(doTCP) {
	  s_tcpoutqueries++;
	  d_tcpoutqueries++;
	}

	int ret=d_lwr.asyncresolve(remoteIP, qname.c_str(), qtype.getCode(), doTCP);    // <- we go out on the wire!
	if(ret != 1) {
	  if(ret==0) {
	    LOG<<prefix<<qname<<": timeout resolving"<<endl;
	    d_timeouts++;
	    s_outgoingtimeouts++;
	  }
	  else
	    LOG<<prefix<<qname<<": error resolving"<<endl;

	  s_nsSpeeds[toLower(*tns)].submit(1000000, &d_now); // 1 sec
	  
	  s_throttle.throttle(d_now.tv_sec, remoteIP+"|"+qname+"|"+qtype.getName(),20,5);
	  continue;
	}
	gettimeofday(&d_now, 0);
      }

      result=d_lwr.result();
      
      if(d_lwr.d_tcbit) {
	if(!doTCP) {
	  doTCP=true;
	  LOG<<prefix<<qname<<": truncated bit set, retrying via TCP"<<endl;
	  goto TryTCP;
	}
	LOG<<prefix<<qname<<": truncated bit set, over TCP?"<<endl;
	return RCode::ServFail;
      }

      if(d_lwr.d_rcode==RCode::ServFail) {
	LOG<<prefix<<qname<<": "<<*tns<<" returned a ServFail, trying sibling NS"<<endl;
	s_throttle.throttle(d_now.tv_sec,remoteIP+"|"+qname+"|"+qtype.getName(),60,3);
	continue;
      }
      LOG<<prefix<<qname<<": Got "<<result.size()<<" answers from "<<*tns<<" ("<<remoteIP<<"), rcode="<<d_lwr.d_rcode<<", in "<<d_lwr.d_usec/1000<<"ms"<<endl;
      s_nsSpeeds[toLower(*tns)].submit(d_lwr.d_usec, &d_now);

      map<string,set<DNSResourceRecord> > tcache;
      // reap all answers from this packet that are acceptable
      for(LWRes::res_t::const_iterator i=result.begin();i!=result.end();++i) {
	if(i->qtype.getCode() < 1024) {
	  LOG<<prefix<<qname<<": accept answer '"<<i->qname<<"|"<<i->qtype.getName()<<"|"<<i->content<<"' from '"<<auth<<"' nameservers? ";
	}
	else {
	  LOG<<prefix<<qname<<": accept opaque answer '"<<i->qname<<"|"<<QType(i->qtype.getCode()-1024).getName()<<" from '"<<auth<<"' nameservers? ";
	}
	
	if(endsOn(i->qname, auth)) {
	  if(d_lwr.d_aabit && d_lwr.d_rcode==RCode::NoError && i->d_place==DNSResourceRecord::ANSWER && arg().contains("delegation-only",auth)) {
	    LOG<<"NO! Is from delegation-only zone"<<endl;
	    s_nodelegated++;
	    return RCode::NXDomain;
	  }
	  else {
	    LOG<<"YES!"<<endl;
	    
	    DNSResourceRecord rr=*i;
	    rr.d_place=DNSResourceRecord::ANSWER;
	    rr.ttl+=d_now.tv_sec;
	    //	  rr.ttl=time(0)+10+10*rr.qtype.getCode();
	    tcache[toLower(i->qname)+"|"+i->qtype.getName()].insert(rr);
	  }
	}	  
	else
	  LOG<<"NO!"<<endl;
      }
    
      // supplant
      for(map<string,set<DNSResourceRecord> >::const_iterator i=tcache.begin();i!=tcache.end();++i) {
	vector<string>parts;
	stringtok(parts,i->first,"|");
	QType qt;
	if(parts.size()==2) {
	  qt=parts[1];
	  RC.replace(parts[0],qt,i->second);
	}
	else {
	  qt=parts[0];
	  RC.replace("",qt,i->second);
	}
      }
      set<string> nsset;  
      LOG<<prefix<<qname<<": determining status after receiving this packet"<<endl;

      bool done=false, realreferral=false, negindic=false;
      string newauth, soaname, newtarget;

      for(LWRes::res_t::const_iterator i=result.begin();i!=result.end();++i) {
	if(i->d_place==DNSResourceRecord::AUTHORITY && endsOn(qname,i->qname) && i->qtype.getCode()==QType::SOA && 
	   d_lwr.d_rcode==RCode::NXDomain) {
	  LOG<<prefix<<qname<<": got negative caching indication for RECORD '"<<toLower(qname)+"'"<<endl;
	  ret.push_back(*i);

	  NegCacheEntry ne;
	  ne.name=i->qname;
	  ne.ttd=d_now.tv_sec + i->ttl;
	  s_negcache[toLower(qname)]=ne;
	  negindic=true;
	}
	else if(i->d_place==DNSResourceRecord::ANSWER && i->qname==qname && i->qtype.getCode()==QType::CNAME && (!(qtype==QType(QType::CNAME)))) {
	  ret.push_back(*i);
	  newtarget=toLowerCanonic(i->content);
	}
	// for ANY answers we *must* have an authoritive answer
	else if(i->d_place==DNSResourceRecord::ANSWER && toLower(i->qname)==toLower(qname) && 
		(((i->qtype==qtype) || (i->qtype.getCode()>1024 && i->qtype.getCode()-1024==qtype.getCode())) || ( qtype==QType(QType::ANY) && 
														   d_lwr.d_aabit)))  {
	  if(i->qtype.getCode() < 1024) {
	    LOG<<prefix<<qname<<": answer is in: resolved to '"<< i->content<<"|"<<i->qtype.getName()<<"'"<<endl;
	  }
	  else {
	    LOG<<prefix<<qname<<": answer is in: resolved to opaque record of type '"<<QType(i->qtype.getCode()-1024).getName()<<"'"<<endl;
	  }

	  done=true;
	  ret.push_back(*i);
	}
	else if(i->d_place==DNSResourceRecord::AUTHORITY && endsOn(qname,i->qname) && i->qtype.getCode()==QType::NS) { 
	  if(moreSpecificThan(i->qname,auth)) {
	    newauth=i->qname;
	    LOG<<prefix<<qname<<": got NS record '"<<i->qname<<"' -> '"<<i->content<<"'"<<endl;
	    realreferral=true;
	  }
	  else 
	    LOG<<prefix<<qname<<": got upwards/level NS record '"<<i->qname<<"' -> '"<<i->content<<"', had '"<<auth<<"'"<<endl;
	  nsset.insert(toLowerCanonic(i->content));
	}
	else if(i->d_place==DNSResourceRecord::AUTHORITY && endsOn(qname,i->qname) && i->qtype.getCode()==QType::SOA && 
	   d_lwr.d_rcode==RCode::NoError) {
	  LOG<<prefix<<qname<<": got negative caching indication for '"<<toLower(qname)+"|"+i->qtype.getName()+"'"<<endl;
	  ret.push_back(*i);
	  
	  NegCacheEntry ne;
	  ne.name=i->qname;
	  ne.ttd=d_now.tv_sec + i->ttl;
	  s_negcache[toLower(qname)+"|"+qtype.getName()]=ne;
	  negindic=true;
	}
      }

      if(done){ 
	LOG<<prefix<<qname<<": status=got results, this level of recursion done"<<endl;
	return 0;
      }
      if(d_lwr.d_rcode==RCode::NXDomain) {
	LOG<<prefix<<qname<<": status=NXDOMAIN, we are done "<<(negindic ? "(have negative SOA)" : "")<<endl;
	return RCode::NXDomain;
      }
      if(!newtarget.empty()) {
	LOG<<prefix<<qname<<": status=got a CNAME referral, starting over with "<<newtarget<<endl;
	set<GetBestNSAnswer>beenthere2;
	return doResolve(newtarget, qtype, ret,0,beenthere2);
      }
      if(nsset.empty() && !d_lwr.d_rcode) {
	LOG<<prefix<<qname<<": status=noerror, other types may exist, but we are done "<<(negindic ? "(have negative SOA)" : "")<<endl;
	return 0;
      }
      else if(realreferral) {
	LOG<<prefix<<qname<<": status=did not resolve, got "<<nsset.size()<<" NS, looping to them"<<endl;
	auth=newauth;
	nameservers=nsset;
	break; 
      }
      else {
	LOG<<prefix<<qname<<": status=NS "<<*tns<<" is lame for '"<<auth<<"', trying sibling NS"<<endl;
	s_throttle.throttle(d_now.tv_sec, remoteIP+"|"+qname+"|"+qtype.getName(),60,0);
      }
    }
  }
  return -1;
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
  bool doIPv6AP=arg().mustDo("aaaa-additional-processing");
  for(vector<DNSResourceRecord>::const_iterator k=ret.begin();k!=ret.end();++k) 
    if((k->d_place==DNSResourceRecord::ANSWER && k->qtype==QType(QType::MX)) || 
       ((k->d_place==DNSResourceRecord::AUTHORITY || k->d_place==DNSResourceRecord::ANSWER) && k->qtype==QType(QType::NS))) {
      LOG<<d_prefix<<qname<<": record '"<<k->content<<"|"<<k->qtype.getName()<<"' needs IP for additional processing"<<endl;
      set<GetBestNSAnswer>beenthere;
      if(k->qtype==QType(QType::MX)) {
	string::size_type pos=k->content.find_first_not_of(" \t0123456789"); // chop off the priority
	if(pos!=string::npos) {
	  doResolve(toLowerCanonic(k->content.substr(pos)), QType(QType::A),addit,1,beenthere);
	  if(doIPv6AP)
	    doResolve(toLowerCanonic(k->content.substr(pos)), QType(QType::AAAA),addit,1,beenthere);
	}
	else {
	  doResolve(toLowerCanonic(k->content), QType(QType::A),addit,1,beenthere);
	  if(doIPv6AP)
	    doResolve(toLowerCanonic(k->content.substr(pos)), QType(QType::AAAA),addit,1,beenthere);
	}
      }
      else {
	doResolve(k->content,QType(QType::A),addit,1,beenthere);
	if(doIPv6AP)
	  doResolve(k->content,QType(QType::AAAA),addit,1,beenthere);
      }
    }
  
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
  set<GetBestNSAnswer>beenthere;
  getBestNSFromCache(qname, bestns, depth,beenthere);

  for(set<DNSResourceRecord>::const_iterator k=bestns.begin();k!=bestns.end();++k) {
    DNSResourceRecord ns=*k;
    ns.d_place=DNSResourceRecord::AUTHORITY;
    ns.ttl-=d_now.tv_sec;
    ret.push_back(ns);
  }
}
