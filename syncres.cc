/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2003  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

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
#include "logger.hh"
#include "misc.hh"
#include "arguments.hh"
#include "lwres.hh"

map<string,string> SyncRes::s_negcache;
unsigned int SyncRes::s_queries;
unsigned int SyncRes::s_outqueries;
bool SyncRes::s_log;

#define LOG if(s_log)L<<Logger::Warning

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
  subdomain=getBestNSNamesFromCache(subdomain,nsset,depth, beenthere); //  pass beenthere to both occasions/
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
    if(getCache(subdomain,QType(QType::NS),&ns)>0) {
      for(set<DNSResourceRecord>::const_iterator k=ns.begin();k!=ns.end();++k) {
	if(k->ttl>(unsigned int)time(0)) { 
	  set<DNSResourceRecord>aset;
	  if(!endsOn(k->content,subdomain) || getCache(k->content,QType(QType::A),&aset) > 5) {
	    bestns.insert(*k);
	    LOG<<prefix<<qname<<": NS (with ip, or non-glue) in cache for '"<<subdomain<<"' -> '"<<k->content<<"'"<<endl;
	    LOG<<prefix<<qname<<": endson: "<<endsOn(k->content,subdomain);
	    if(!aset.empty())
	      LOG<<", in cache, ttl="<<((time_t)aset.begin()->ttl-time(0))<<endl;
	    else
	      LOG<<", not in cache"<<endl;
	  }
	  else
	    LOG<<prefix<<qname<<": NS in cache for '"<<subdomain<<"', but needs glue ("<<k->content<<") which we miss or is expired"<<endl;
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
  string prefix(d_prefix), tuple=toLower(qname)+"|CNAME";
  prefix.append(depth, ' ');

  if(depth>10) {
    LOG<<prefix<<qname<<": CNAME loop too deep, depth="<<depth<<endl;
    res=RCode::ServFail;
    return true;
  }
  
  LOG<<prefix<<qname<<": Looking for CNAME cache hit of '"<<tuple<<"'"<<endl;
  set<DNSResourceRecord> cset;
  if(getCache(qname,QType(QType::CNAME),&cset) > 0) {
    for(set<DNSResourceRecord>::const_iterator j=cset.begin();j!=cset.end();++j) {
      if(j->ttl>(unsigned int)time(0)) {
	LOG<<prefix<<qname<<": Found cache CNAME hit for '"<<tuple<<"' to '"<<j->content<<"'"<<endl;    
	DNSResourceRecord rr=*j;
	rr.ttl-=time(0);
	ret.push_back(rr);
	if(!(qtype==QType(QType::CNAME))) {// perhaps they really wanted a CNAME!
	  set<GetBestNSAnswer>beenthere;
	  res=doResolve(j->content, qtype, ret, depth, beenthere);
	}
	return true;
      }
    }
  }
  LOG<<prefix<<qname<<": No CNAME cache hit of '"<<tuple<<"' found"<<endl;
  return false;
}

bool SyncRes::doCacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res)
{
  string prefix(d_prefix), tuple;
  prefix.append(depth, ' ');

  tuple=toLower(qname)+"|"+qtype.getName();
  LOG<<prefix<<qname<<": Looking for direct cache hit of '"<<tuple<<"', "<<s_negcache.count(tuple)<<endl;

  string sqname(qname);
  QType sqt(qtype);

  res=0;
  map<string,string>::const_iterator ni=s_negcache.find(tuple);
  if(ni!=s_negcache.end()) {
    LOG<<prefix<<qname<<": "<<qtype.getName()<<" is negatively cached, will return immediately if we still have SOA ("<<ni->second<<") to prove it"<<endl;
    res=RCode::NXDomain;
    sqname=ni->second;
    sqt="SOA";
  }

  set<DNSResourceRecord> cset;
  bool found=false, expired=false;
  if(getCache(sqname,sqt,&cset)>0) {
    LOG<<prefix<<qname<<": Found cache hit for "<<sqt.getName()<<": ";
    for(set<DNSResourceRecord>::const_iterator j=cset.begin();j!=cset.end();++j) {
      LOG<<j->content;
      if(j->ttl>(unsigned int)time(0)) {
	DNSResourceRecord rr=*j;
	rr.ttl-=time(0);
	if(res==RCode::NXDomain)
	  rr.d_place=DNSResourceRecord::AUTHORITY;
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

vector<string> SyncRes::shuffle(set<string> &nameservers)
{
  vector<string> rnameservers;
  for(set<string>::const_iterator i=nameservers.begin();i!=nameservers.end();++i)
    rnameservers.push_back(*i);
  
  random_shuffle(rnameservers.begin(),rnameservers.end());
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
    bool aabit=false;
    result.clear();

    vector<string>rnameservers=shuffle(nameservers);

    // what if we don't have an A for an NS anymore, but do have an NS for that NS?

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
      LOG<<prefix<<qname<<": Resolved NS "<<*tns<<" to "<<remoteIP<<", asking '"<<qname<<"|"<<qtype.getName()<<"'"<<endl;

      s_outqueries++;
      d_outqueries++;
      if(d_lwr.asyncresolve(remoteIP,qname.c_str(),qtype.getCode())!=1) { // <- we go out on the wire!
	LOG<<prefix<<qname<<": error resolving (perhaps timeout?)"<<endl;
	continue;
      }

      result=d_lwr.result(aabit);
      if(d_lwr.d_rcode==RCode::ServFail) {
	LOG<<prefix<<qname<<": "<<*tns<<" returned a ServFail, trying sibling NS"<<endl;
	continue;
      }
      LOG<<prefix<<qname<<": Got "<<result.size()<<" answers from "<<*tns<<" ("<<remoteIP<<"), rcode="<<d_lwr.d_rcode<<endl;

      map<string,set<DNSResourceRecord> > tcache;
      // reap all answers from this packet that are acceptable
      for(LWRes::res_t::const_iterator i=result.begin();i!=result.end();++i) {
	LOG<<prefix<<qname<<": accept answer '"<<i->qname<<"|"<<i->qtype.getName()<<"|"<<i->content<<"' from '"<<auth<<"' nameservers? ";

	if(endsOn(i->qname, auth)) {
	  LOG<<"YES!"<<endl;

	  DNSResourceRecord rr=*i;
	  rr.d_place=DNSResourceRecord::ANSWER;
	  rr.ttl+=time(0);
	  //	  rr.ttl=time(0)+10+10*rr.qtype.getCode();
	  tcache[toLower(i->qname)+"|"+i->qtype.getName()].insert(rr);
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
	  replaceCache(parts[0],qt,i->second);
	}
	else {
	  qt=parts[0];
	  replaceCache("",qt,i->second);
	}
      }
      set<string> nsset;  
      LOG<<prefix<<qname<<": determining status after receiving this packet"<<endl;

      bool done=false, realreferral=false, negindic=false;
      string newauth, soaname, newtarget;

      for(LWRes::res_t::const_iterator i=result.begin();i!=result.end();++i) {
	if(i->d_place==DNSResourceRecord::AUTHORITY && endsOn(qname,i->qname) && i->qtype.getCode()==QType::SOA) {
	  LOG<<prefix<<qname<<": got negative caching indication for '"<<toLower(qname)+"|"+qtype.getName()<<"'"<<endl;
	  ret.push_back(*i);
	  s_negcache[toLower(qname)+"|"+qtype.getName()]=i->qname;
	  negindic=true;
	}
	else if(i->d_place==DNSResourceRecord::ANSWER && i->qname==qname && i->qtype.getCode()==QType::CNAME && (!(qtype==QType(QType::CNAME)))) {
	  ret.push_back(*i);
	  newtarget=i->content;
	}
	// for ANY answers we *must* have an authoritive answer
	else if(i->d_place==DNSResourceRecord::ANSWER && toLower(i->qname)==toLower(qname) && (i->qtype==qtype || ( qtype==QType(QType::ANY) && aabit)))  {
	  LOG<<prefix<<qname<<": answer is in: resolved to '"<<i->content<<"|"<<i->qtype.getName()<<"'"<<endl;
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
	  nsset.insert(toLower(i->content));
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
  for(vector<DNSResourceRecord>::const_iterator k=ret.begin();k!=ret.end();++k) 
    if((k->d_place==DNSResourceRecord::ANSWER && k->qtype==QType(QType::MX)) || 
       ((k->d_place==DNSResourceRecord::AUTHORITY || k->d_place==DNSResourceRecord::ANSWER) && k->qtype==QType(QType::NS))) {
      LOG<<qname<<": record '"<<k->content<<"|"<<k->qtype.getName()<<"' needs an IP address"<<endl;
      set<GetBestNSAnswer>beenthere;
      doResolve(k->content,QType(QType::A),addit,1,beenthere);
      if(arg().mustDo("aaaa-additional-processing"))
	doResolve(k->content,QType(QType::AAAA),addit,1,beenthere);
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
    ns.ttl-=time(0);
    ret.push_back(ns);
  }
}
