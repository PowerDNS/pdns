/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

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
#include <iostream>
#include <map>
#include <algorithm>
#include <set>

#include <cerrno>
#include <cstdio>
#include <cstdlib>

#include <utility>
#include "statbag.hh"
#include "arguments.hh"
#include "lwres.hh"


typedef map<string,set<DNSResourceRecord> > cache_t;
cache_t cache;

/** dramatis personae */
int doResolveAt(set<string> nameservers, string auth, const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret,int depth=0);
int doResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth=0);
bool doCNAMECacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res);
bool doCacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res);
void getBestNSFromCache(const string &qname, set<DNSResourceRecord>&bestns, int depth);
void addCruft(const string &qname, vector<DNSResourceRecord>& ret);
string getBestNSNamesFromCache(const string &qname,set<string>& nsset, int depth);
void addAuthorityRecords(const string& qname, vector<DNSResourceRecord>& ret, int depth);

/** everything begins here - this is the entry point just after receiving a packet */
int beginResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret)
{
  int res=doResolve(qname, qtype, ret,0);
  if(!res)
    addCruft(qname, ret);
  cout<<endl;
  return res;
}

int doResolve(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth)
{
  string prefix;
  prefix.assign(3*depth, ' ');
  
  int res;
  if(doCNAMECacheCheck(qname,qtype,ret,depth,res)) // will reroute us if needed
    return res;

  if(doCacheCheck(qname,qtype,ret,depth,res)) // we done
    return res;

  cout<<prefix<<qname<<": No cache hit for '"<<qname<<"|"<<qtype.getName()<<"', trying to find an appropriate NS record"<<endl;

  string subdomain(qname);

  set<string> nsset;
  subdomain=getBestNSNamesFromCache(subdomain,nsset,depth);
  if(!doResolveAt(nsset,subdomain,qname,qtype,ret,depth))
    return 0;
  
  cout<<prefix<<qname<<": failed"<<endl;
  return RCode::ServFail;
}

string getA(const string &qname, int depth=0)
{
  vector<DNSResourceRecord> res;
  string ret;

  if(!doResolve(qname,QType(QType::A), res,depth+1) && !res.empty()) 
    ret=res[res.size()-1].content; // last entry, in case of CNAME in between

  return ret;
}

void getBestNSFromCache(const string &qname, set<DNSResourceRecord>&bestns, int depth)
{
  string prefix;
  prefix.assign(3*depth, ' ');

  bestns.clear();

  string subdomain(qname);

  do {
    cout<<prefix<<qname<<": Checking if we have NS in cache for '"<<subdomain<<"'"<<endl;

    cache_t::const_iterator j=cache.find(toLower(subdomain)+"|NS");
    if(j!=cache.end() && j->first==toLower(subdomain)+"|NS") {

      for(set<DNSResourceRecord>::const_iterator k=j->second.begin();k!=j->second.end();++k) {
	if(k->ttl>(unsigned int)time(0)) {
	  bestns.insert(*k);
	}
      }
      if(!bestns.empty()) {
	cout<<prefix<<qname<<": We have NS in cache for '"<<subdomain<<"'"<<endl;
	return;
      }
    }
  }while(chopOff(subdomain));
}

void addAuthorityRecords(const string& qname, vector<DNSResourceRecord>& ret, int depth)
{
  set<DNSResourceRecord> bestns;
  getBestNSFromCache(qname, bestns, depth);
  for(set<DNSResourceRecord>::const_iterator k=bestns.begin();k!=bestns.end();++k) {
    DNSResourceRecord ns=*k;
    ns.d_place=DNSResourceRecord::AUTHORITY;
    ns.ttl-=time(0);
    ret.push_back(ns);
  }
}

string getBestNSNamesFromCache(const string &qname,set<string>& nsset, int depth)
{
  string subdomain(qname);

  set<DNSResourceRecord> bestns;
  getBestNSFromCache(subdomain, bestns, depth);

  for(set<DNSResourceRecord>::const_iterator k=bestns.begin();k!=bestns.end();++k) {
    nsset.insert(k->content);
    subdomain=k->qname;
  }
  return subdomain;
}

bool doCNAMECacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res)
{
  string prefix, tuple=toLower(qname)+"|CNAME";
  prefix.assign(3*depth, ' ');

  cout<<prefix<<qname<<": Looking for CNAME cache hit of '"<<tuple<<"'"<<endl;
  cache_t::const_iterator i=cache.find(tuple);
  if(i!=cache.end() && i->first==tuple) { // found it
    for(set<DNSResourceRecord>::const_iterator j=i->second.begin();j!=i->second.end();++j) {
      if(j->ttl>(unsigned int)time(0)) {
	cout<<prefix<<qname<<": Found cache CNAME hit for '"<<tuple<<"' to '"<<i->second.begin()->content<<"'"<<endl;    
	DNSResourceRecord rr=*j;
	rr.ttl-=time(0);
	ret.push_back(rr);
	if(!(qtype==QType(QType::CNAME))) // perhaps they really wanted a CNAME!
	  res=doResolve(i->second.begin()->content, qtype, ret, depth);
	return true;
      }
    }
  }
  cout<<prefix<<qname<<": No CNAME cache hit of '"<<tuple<<"' found"<<endl;
  return false;
}

bool doCacheCheck(const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth, int &res)
{
  string prefix, tuple;
  prefix.assign(3*depth, ' ');

  tuple=toLower(qname)+"|"+qtype.getName();
  cout<<prefix<<qname<<": Looking for direct cache hit of '"<<tuple<<"'"<<endl;

  cache_t::const_iterator i=cache.find(tuple);
  bool found=false, expired=false;
  if(i!=cache.end() && i->first==tuple) { // found it
    cout<<prefix<<qname<<": Found cache hit for "<<qtype.getName()<<": ";
    for(set<DNSResourceRecord>::const_iterator j=i->second.begin();j!=i->second.end();++j) {
      cout<<j->content;
      if(j->ttl>(unsigned int)time(0)) {
	DNSResourceRecord rr=*j;
	rr.ttl-=time(0);
	ret.push_back(rr);
	cout<<"[fresh] ";
	found=true;
      }
      else {
	cout<<"[expired] ";
	expired=true;
      }
    }
  
    cout<<endl;
    if(found && !expired) {
      res=0;
      return true;
    }
    else
      cout<<prefix<<qname<<": cache had no or only stale entries"<<endl;
  }
  return false;
}

inline bool moreSpecificThan(const string& a, const string &b)
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

inline vector<string>shuffle(set<string> &nameservers)
{
  vector<string> rnameservers;
  for(set<string>::const_iterator i=nameservers.begin();i!=nameservers.end();++i)
    rnameservers.push_back(*i);
  
  random_shuffle(rnameservers.begin(),rnameservers.end());
  return rnameservers;
}

/** returns -1 in case of no results, rcode otherwise */
int doResolveAt(set<string> nameservers, string auth, const string &qname, const QType &qtype, vector<DNSResourceRecord>&ret, int depth)
{
  string prefix;
  prefix.assign(3*depth, ' ');
  
  LWRes r;
  LWRes::res_t result;

  cout<<prefix<<qname<<": Cache consultations done, going on the wire!"<<endl;

  for(;;) { // we may get more specific nameservers
    bool aabit=false;
    result.clear();

    vector<string>rnameservers=shuffle(nameservers);

    for(vector<string>::const_iterator tns=rnameservers.begin();;++tns) { 
      if(tns==rnameservers.end()) {
	cout<<prefix<<qname<<": Failed to resolve via any of the "<<rnameservers.size()<<" offered NS"<<endl;
	return -1;
      }
      cout<<prefix<<qname<<": Trying to resolve NS "<<*tns<<endl;
      string remoteIP=getA(*tns, depth+1);
      if(remoteIP.empty()) {
	cout<<prefix<<qname<<": Failed to get IP for NS "<<*tns<<", trying next if available"<<endl;
	continue;
      }
      cout<<prefix<<qname<<": Resolved NS "<<*tns<<" to "<<remoteIP<<", asking '"<<qname<<"|"<<qtype.getName()<<"'"<<endl;

      if(r.asyncresolve(remoteIP,qname.c_str(),qtype.getCode())!=1) { // <- we go out on the wire!
	cout<<prefix<<qname<<": error resolving (perhaps timeout?)"<<endl;
	continue;
      }
      result=r.result(aabit);
      cout<<prefix<<qname<<": Got "<<result.size()<<" answers from "<<*tns<<" ("<<remoteIP<<")"<<endl;

      cache_t tcache;
      // reap all answers from this packet that are acceptable
      for(LWRes::res_t::const_iterator i=result.begin();i!=result.end();++i) {
	cout<<prefix<<qname<<": accept answer '"<<i->qname<<"|"<<i->qtype.getName()<<"|"<<i->content<<"' from '"<<auth<<"' nameservers? ";
	cout.flush();
	if(endsOn(i->qname, auth)) {
	  cout<<"YES!"<<endl;

	  DNSResourceRecord rr=*i;
	  rr.d_place=DNSResourceRecord::ANSWER;
	  rr.ttl+=time(0);
	  tcache[toLower(i->qname)+"|"+i->qtype.getName()].insert(rr);
	}
	else
	  cout<<"NO!"<<endl;
      }
    
      // supplant
      for(cache_t::const_iterator i=tcache.begin();i!=tcache.end();++i)
	cache[i->first]=i->second;
      
      set<string> nsset;  
      cout<<prefix<<qname<<": determining status after receiving this packet"<<endl;

      bool done=false, realreferral=false, negcache=false;
      string newauth;

      for(LWRes::res_t::const_iterator i=result.begin();i!=result.end();++i) {
	if(i->d_place==DNSResourceRecord::AUTHORITY && endsOn(qname,i->qname) && i->qtype.getCode()==QType::SOA) {
	  cout<<prefix<<qname<<": got negative caching indication"<<endl;
	  ret.push_back(*i);
	  negcache=true;
	}
	else if(i->d_place==DNSResourceRecord::ANSWER && i->qname==qname && i->qtype.getCode()==QType::CNAME && (!(qtype==QType(QType::CNAME)))) {
	  cout<<prefix<<qname<<": got a CNAME referral, starting over with "<<i->content<<endl<<endl;
	  ret.push_back(*i);
	  return doResolve(i->content, qtype, ret,0);
	}
	// for ANY answers we *must* have an authoritive answer
	else if(i->d_place==DNSResourceRecord::ANSWER && i->qname==qname && (i->qtype==qtype || ( qtype==QType(QType::ANY) && aabit)))  {
	  cout<<prefix<<qname<<": answer is in: resolved to '"<<i->content<<"|"<<i->qtype.getName()<<"'"<<endl;
	  done=true;
	  ret.push_back(*i);
	}
	else if(i->d_place==DNSResourceRecord::AUTHORITY && endsOn(qname,i->qname) && i->qtype.getCode()==QType::NS) { 
	  if(moreSpecificThan(i->qname,auth)) {
	    newauth=i->qname;
	    cout<<prefix<<qname<<": got NS record '"<<i->qname<<"' -> '"<<i->content<<"'"<<endl;
	    realreferral=true;
	  }
	  else {
	    cout<<prefix<<qname<<": got upwards NS record '"<<i->qname<<"' -> '"<<i->content<<"', already had '"<<auth<<"'"<<endl;
	  }
	  nsset.insert(toLower(i->content));
	}
      }

      if(done){ 
	cout<<prefix<<qname<<": status=got results, this level of recursion done"<<endl;
	return 0;
      }
      if(r.d_rcode==RCode::NXDomain) {
	cout<<prefix<<qname<<": status=NXDOMAIN, we are done "<<(negcache ? "(have negative SOA)" : "")<<endl;
	return RCode::NXDomain;
      }
      if(nsset.empty() && !r.d_rcode) {
	cout<<prefix<<qname<<": status=noerror, other types may exist, but we are done "<<(negcache ? "(have negative SOA)" : "")<<endl;
	return 0;
      }
      else if(realreferral) {
	cout<<prefix<<qname<<": status=did not resolve, got "<<nsset.size()<<" NS, looping to them"<<endl;
	auth=newauth;
	nameservers=nsset;
	break; 
      }
      else {
	cout<<prefix<<qname<<": status=NS "<<*tns<<" is lame for '"<<auth<<"', trying sibbling NS"<<endl;
      }
    }
  }
  return -1;
}

void addCruft(const string &qname, vector<DNSResourceRecord>& ret)
{
  for(vector<DNSResourceRecord>::const_iterator k=ret.begin();k!=ret.end();++k)  // don't add stuff to an NXDOMAIN!
    if(k->d_place==DNSResourceRecord::AUTHORITY && k->qtype==QType(QType::SOA))
      return;

  cout<<qname<<": Adding best authority records from cache"<<endl;
  addAuthorityRecords(qname,ret,0);
  cout<<qname<<": Done adding best authority records."<<endl;

  cout<<qname<<": Starting additional processing"<<endl;
  vector<DNSResourceRecord> addit;
  for(vector<DNSResourceRecord>::const_iterator k=ret.begin();k!=ret.end();++k) 
    if((k->d_place==DNSResourceRecord::ANSWER && k->qtype==QType(QType::MX)) || 
       (k->d_place==DNSResourceRecord::AUTHORITY && k->qtype==QType(QType::NS))) {
      cout<<qname<<": record '"<<k->content<<"|"<<k->qtype.getName()<<"' needs an IP address"<<endl;
      doResolve(k->content,QType(QType::A),addit,1);
    }
  
  for(vector<DNSResourceRecord>::iterator k=addit.begin();k!=addit.end();++k) {
    k->d_place=DNSResourceRecord::ADDITIONAL;
    ret.push_back(*k);
  }
  cout<<qname<<": Done with additional processing"<<endl;
}

void init(void)
{
  // prime root cache
  static char*ips[]={"198.41.0.4", "128.9.0.107", "192.33.4.12", "128.8.10.90", "192.203.230.10", "192.5.5.241", "192.112.36.4", "128.63.2.53", 
		     "192.36.148.17","198.41.0.10", "193.0.14.129", "198.32.64.12", "202.12.27.33"};
  DNSResourceRecord arr, nsrr;
  arr.qtype=QType::A;
  arr.ttl=time(0)+86400;
  nsrr.qtype=QType::NS;
  nsrr.ttl=time(0)+86400;
  
  for(char c='a';c<='m';++c) {
    static char templ[40];
    strncpy(templ,"a.root-servers.net", sizeof(templ) - 1);
    *templ=c;
    arr.qname=nsrr.content=templ;
    arr.content=ips[c-'a'];
    cache[string(templ)+"|A"].insert(arr);
    cache["|NS"].insert(nsrr);
  }
}
