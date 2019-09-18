/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* accepts a named.conf or a zone as parameter and outputs heaps of sql */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <unistd.h>
#include <string>
#include <map>

#include <iostream>
#include <stdio.h>
#include "namespaces.hh"

#include "dns.hh"
#include "arguments.hh"
#include "bindparserclasses.hh"
#include "statbag.hh"
#include "misc.hh"
#include "dnspacket.hh"
#include "zoneparser-tng.hh"
#include "dnsrecords.hh"
#include <boost/algorithm/string.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "json11.hpp"

using namespace json11;

StatBag S;
static int g_numRecords;

static Json::object emitRecord(const string& zoneName, const DNSName &DNSqname, const string &qtype, const string &ocontent, int ttl)
{
  int prio=0;
  string retval;
  g_numRecords++;
  string content(ocontent);
  if(qtype == "MX" || qtype == "SRV") { 
    prio=pdns_stou(content);
    
    string::size_type pos = content.find_first_not_of("0123456789");
    if(pos != string::npos)
      boost::erase_head(content, pos);
    trim_left(content);
  }

  Json::object dict;
 
  dict["name"] = DNSqname.toString();
  dict["type"] = qtype;
  dict["ttl"] = ttl;
  dict["prio"] = prio;
  dict["content"] = content;

  return dict;
}

/* 2 modes of operation, either --named or --zone (the latter needs $ORIGIN) 
   1 further mode: --mysql
*/

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}


int main(int argc, char **argv)
try
{
  vector<string> lines;

    reportAllTypes();
    std::ios_base::sync_with_stdio(false);
   
    ::arg().setSwitch("verbose","Verbose comments on operation")="no";
    ::arg().setSwitch("on-error-resume-next","Continue after errors")="no";
    ::arg().set("zone","Zonefile to parse")="";
    ::arg().set("zone-name","Specify an $ORIGIN in case it is not present")="";
    ::arg().set("named-conf","Bind 8/9 named.conf to parse")="";
    
    ::arg().set("soa-minimum-ttl","Do not change")="0";
    ::arg().set("soa-refresh-default","Do not change")="0";
    ::arg().set("soa-retry-default","Do not change")="0";
    ::arg().set("soa-expire-default","Do not change")="0";

    ::arg().setCmd("help","Provide a helpful message");
    ::arg().setCmd("version","Print the version");

    S.declare("logmessages");

    string namedfile="";
    string zonefile="";

    ::arg().parse(argc, argv);

    if(::arg().mustDo("version")){
      cerr<<"zone2json "<<VERSION<<endl;
      exit(0);
    }

    if(::arg().mustDo("help")) {
      cout<<"syntax:"<<endl<<endl;
      cout<<::arg().helpstring()<<endl;
      exit(0);
    }

    if(argc<2) {
      cerr<<"syntax:"<<endl<<endl;
      cerr<<::arg().helpstring()<<endl;
      exit(1);
    }
  
    namedfile=::arg()["named-conf"];
    zonefile=::arg()["zone"];

    int count=0, num_domainsdone=0;

    if(zonefile.empty()) {
      BindParser BP;
      BP.setVerbose(::arg().mustDo("verbose"));
      BP.parse(namedfile.empty() ? "./named.conf" : namedfile);
    
      vector<BindDomainInfo> domains=BP.getDomains();
      struct stat st;
      for(vector<BindDomainInfo>::iterator i=domains.begin(); i!=domains.end(); ++i) {
        if(stat(i->filename.c_str(), &st) == 0) {
          i->d_dev = st.st_dev;
          i->d_ino = st.st_ino;
        }
      }
      
      sort(domains.begin(), domains.end()); // put stuff in inode order

      int numdomains=domains.size();
      int tick=numdomains/100;
      cout << "[";

      for(vector<BindDomainInfo>::const_iterator i=domains.begin();
          i!=domains.end();
          ++i)
        {
          if(i->type!="master" && i->type!="slave") {
            cerr<<" Warning! Skipping '"<<i->type<<"' zone '"<<i->name<<"'"<<endl;
            continue;
          }
          lines.clear(); 
          try {
            Json::object obj;
            Json::array recs;
            ZoneParserTNG zpt(i->filename, i->name, BP.getDirectory());
            DNSResourceRecord rr;
            obj["name"] = i->name.toString();

            while(zpt.get(rr)) 
              recs.push_back(emitRecord(i->name.toString(), rr.qname, rr.qtype.getName(), rr.content, rr.ttl));
            obj["records"] = recs;
            Json tmp = obj;
            cout<<tmp.dump();
            if(i+1 < domains.end()) cout<<",";
            num_domainsdone++;
          }
          catch(std::exception &ae) {
            if(!::arg().mustDo("on-error-resume-next"))
              throw;
            else
              cerr<<endl<<ae.what()<<endl;
          }
          catch(PDNSException &ae) {
            if(!::arg().mustDo("on-error-resume-next"))
              throw;
            else
              cerr<<ae.reason<<endl;
          }
          if(!tick || !((count++)%tick))
            cerr<<"\r"<<count*100/numdomains<<"% done ("<<i->filename<<")\033\133\113";
        }
      cout << "]" << endl;
      cerr<<"\r100% done\033\133\113"<<endl;
    }
    else {
      ZoneParserTNG zpt(zonefile, DNSName(::arg()["zone-name"]));
      DNSResourceRecord rr;
      string zname;
      Json::object obj;
      Json::array records;

      obj["name"] = ::arg()["zone-name"];

      while(zpt.get(rr)) 
        records.push_back(emitRecord(::arg()["zone-name"], rr.qname, rr.qtype.getName(), rr.content, rr.ttl));
      obj["records"] = records;

      Json tmp = obj;

      cout<<tmp.dump()<<endl;

      num_domainsdone=1;
    }
    cerr<<num_domainsdone<<" domains were fully parsed, containing "<<g_numRecords<<" records\n";

  return 0;
    
}
catch(PDNSException &ae) {
  cerr<<"\nFatal error: "<<ae.reason<<endl;
  return 1;
}
catch(std::exception &e) {
  cerr<<"\ndied because of STL error: "<<e.what()<<endl;
  return 1;
}
catch(...) {
  cerr<<"\ndied because of unknown exception"<<endl;
  return 1;
}
