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

#include <cerrno>
#include <cstdio>
#include <cstdlib>

#include <utility>
#include "statbag.hh"
#include "arguments.hh"
#include "lwres.hh"

typedef pair<vector<string>,vector<DNSResourceRecord> > CacheVal;
typedef multimap<string,CacheVal> cache_t;
cache_t cache;

vector<string>rootservers;
map<string,string> hints;

string doResolve(vector<string> nameservers, const string &qname, int depth=0);

string doResolve(const string &qname, int depth=0)
{
  if(hints.find(toLower(qname))!=hints.end()) {
    string prefix;
    prefix.assign(3*depth, ' ');

    cerr<<prefix<<qname<<": resolved via hint cache to "<<hints[toLower(qname)]<<endl;
    return hints[toLower(qname)];
  }
  
  return doResolve(rootservers, qname,depth);
}

string doResolve(vector<string> nameservers, const string &qname, int depth)
{
  string prefix;
  prefix.assign(3*depth, ' ');
  
  LWRes r;
  LWRes::res_t result;
  vector<DNSResourceRecord>usefulrrs;
  vector<string> nsset;  
  cerr<<prefix<<qname<<": start of recursion!"<<endl;

  for(;;) {
    result.clear();

    for(cache_t::const_iterator i=cache.find(qname);i!=cache.end() && i->first==qname;++i) {
      cerr<<prefix<<qname<<": potential cache hit!"<<endl;

      sort(nameservers.begin(),nameservers.end());
      if(nameservers==i->second.first) {
	cerr<<prefix<<qname<<": REAL cache hit, "<<i->second.second.size()<<" records"<<endl;
	result=i->second.second;

	break;
      }
    }
    if(result.empty()) {

      cerr<<prefix<<qname<<": no cache hit"<<endl;
  
      random_shuffle(nameservers.begin(),nameservers.end());
      for(vector<string>::const_iterator i=nameservers.begin();;++i){ 
	if(i==nameservers.end()) {
	  cerr<<prefix<<qname<<": failed to resolve via any of the "<<nameservers.size()<<" offered nameservers"<<endl;
	  return "";
	}
	cerr<<prefix<<qname<<": trying to resolve nameserver "<<*i<<endl;
	string remoteIP=doResolve(*i,depth+1);
	if(remoteIP.empty()) {
	  cerr<<prefix<<qname<<": failed to resolve nameserver "<<*i<<", trying next if available"<<endl;
	  continue;
	}
	cerr<<prefix<<qname<<": resolved nameserver "<<*i<<" to "<<remoteIP<<endl;

	if(r.asyncresolve(remoteIP,qname.c_str(),QType::A)!=1) {
	  cerr<<prefix<<qname<<": error resolving"<<endl;
	}
	else {
	  result=r.result();
	  
	  cerr<<prefix<<qname<<": got "<<result.size()<<" answers from "<<*i<<" ("<<remoteIP<<")"<<endl;
	  break;
	}
      }
      usefulrrs.clear();
      for(LWRes::res_t::const_iterator i=result.begin();i!=result.end();++i) 
	if(i->d_place==DNSResourceRecord::ANSWER || (i->d_place==DNSResourceRecord::AUTHORITY && i->qtype.getCode()==QType::NS))
	  usefulrrs.push_back(*i);
      
      if(!usefulrrs.empty()) {
	CacheVal cv;
	sort(nameservers.begin(),nameservers.end());
	cv.first=nameservers;
	cv.second=usefulrrs;
	cache.insert(make_pair(qname,cv));
      }
    }

    nsset.clear();
    for(LWRes::res_t::const_iterator i=result.begin();i!=result.end();++i) {
      //    cerr<<prefix<<(int)i->d_place<<" "<<i->qname<<" "<<i->qtype.getName()<<" "<<i->content<<endl;
      if(i->d_place==DNSResourceRecord::ANSWER && i->qname==qname && i->qtype.getCode()==QType::CNAME) {
	cerr<<prefix<<qname<<": got a CNAME referral, starting over with "<<i->content<<endl<<endl;
	return doResolve(i->content, 0);
      }
      if(i->d_place==DNSResourceRecord::ANSWER && i->qname==qname && i->qtype.getCode()==QType::A) {
	cerr<<prefix<<qname<<": resolved to "<<i->content<<endl;
	return i->content;
      }
      if(i->d_place==DNSResourceRecord::AUTHORITY && i->qtype.getCode()==QType::NS) {
	cerr<<prefix<<qname<<": got NS record "<<i->content<<endl;
	nsset.push_back(i->content);
      }
    }
    if(nsset.empty()) {
      cerr<<prefix<<qname<<": did not resolve "<<qname<<", did not get referral"<<endl;
      return "";
    }

    cerr<<prefix<<qname<<": did not resolve "<<qname<<", did get "<<nsset.size()<<" nameservers, looping to them"<<endl;
    nameservers=nsset;
  }
}

void init(void)
{
  // prime root cache
  static char*ips[]={"198.41.0.4", "128.9.0.107", "192.33.4.12", "128.8.10.90", "192.203.230.10",
		     "192.5.5.241", "192.112.36.4", "128.63.2.53", "192.36.148.17",
		     "198.41.0.10", "193.0.14.129", "198.32.64.12", "202.12.27.33"};

  for(char c='a';c<='m';++c) {
    static char templ[40];
    strncpy(templ,"a.root-servers.net", sizeof(templ) - 1);
    *templ=c;
    rootservers.push_back(templ);
    hints[templ]=ips[c-'a'];
  }
}
