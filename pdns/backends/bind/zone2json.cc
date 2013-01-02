/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
/* accepts a named.conf or a zone as parameter and outputs heaps of sql */

#include <unistd.h>
#include <string>
#include <map>

#include <iostream>
#include <stdio.h>
#include "namespaces.hh"

#include "dns.hh"
#include "arguments.hh"
#include "bindparser.hh"
#include "statbag.hh"
#include "misc.hh"
#include "dnspacket.hh"
#include "zoneparser-tng.hh"
#include "dnsrecords.hh"
#include <boost/algorithm/string.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <boost/foreach.hpp>


StatBag S;
static int g_numRecords;

static void quoteValue(string &value) 
{
  string tmp;
  size_t opos,pos;

  // no point doing it if there isn't anything to do
  if (value.find_first_of("\\\\\"") == string::npos) return;

  pos = opos = 0;
  while((pos = value.find_first_of("\\\\\"", opos)) != string::npos) 
  {
     tmp += value.substr(opos, pos - opos);
     tmp += "\\";
     tmp += value[pos];
     opos = pos+1;
  }

  value = tmp;
}


static string emitRecord(const string& zoneName, const string &qname, const string &qtype, const string &ocontent, int ttl, int prio)
{
  string retval;
  g_numRecords++;
  string content(ocontent);
  if(qtype == "MX" || qtype == "SRV") { 
    prio=atoi(content.c_str());
    
    string::size_type pos = content.find_first_not_of("0123456789");
    if(pos != string::npos)
      boost::erase_head(content, pos);
    trim_left(content);
  }

  quoteValue(content);
 
  retval = "{";
  retval += "\"name\":\"";
  retval += qname;
  retval += "\",";
  retval += "\"type\":\"";
  retval += qtype;
  retval += "\",";
  retval += "\"ttl\":";
  retval += lexical_cast<string>(ttl);
  retval += ",";
  retval += "\"prio\":";
  retval += lexical_cast<string>(prio);
  retval += ",";
  retval += "\"content\":\"";
  retval += content;
  retval += "\"}";
 
  return retval;
}

static void emitJson(vector<string> &data)
{
   size_t l = data.size();
   cout << "[";
   for(size_t i=0;i<l-1;i++) 
      cout << data[i] << ",";
   cout << data[l-1] << "]";
}

/* 2 modes of operation, either --named or --zone (the latter needs $ORIGIN) 
   2 further modes: --mysql or --oracle 
*/

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}


int main(int argc, char **argv)
{
  vector<string> lines;

  try {
    reportAllTypes();
    reportFancyTypes();
#if __GNUC__ >= 3
    std::ios_base::sync_with_stdio(false);
#endif
   
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

    S.declare("logmessages");

    string namedfile="";
    string zonefile="";

    ::arg().parse(argc, argv);
  
    if(argc<2 || ::arg().mustDo("help")) {
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
      cout <<"[";
   
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
            ZoneParserTNG zpt(i->filename, i->name, BP.getDirectory());
            DNSResourceRecord rr;
            while(zpt.get(rr)) 
              lines.push_back(emitRecord(i->name, rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority));
            cout << "{\"name\":\"" << i->name << "\",\"records\": ";
            emitJson(lines);
            cout << "},";
            num_domainsdone++;
          } 
          catch(std::exception &ae) {
            if(!::arg().mustDo("on-error-resume-next"))
              throw;
            else
              cerr<<endl<<ae.what()<<endl;
          }
          catch(AhuException &ae) {
            if(!::arg().mustDo("on-error-resume-next"))
              throw;
            else
              cerr<<ae.reason<<endl;
          }
          if(!tick || !((count++)%tick))
            cerr<<"\r"<<count*100/numdomains<<"% done ("<<i->filename<<")\033\133\113";
        }
      cout << "]\n";
      cerr<<"\r100% done\033\133\113"<<endl;
    }
    else {
      ZoneParserTNG zpt(zonefile, ::arg()["zone-name"]);
      DNSResourceRecord rr;
      string zname; 
      cout << "{\"name\":\"" << ::arg()["zone-name"] << "\",\"records\":";
      while(zpt.get(rr)) 
        lines.push_back(emitRecord(::arg()["zone-name"], rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority));
      emitJson(lines);
      cout << "}\n";
      num_domainsdone=1;
    }
    cerr<<num_domainsdone<<" domains were fully parsed, containing "<<g_numRecords<<" records\n";
    
  }
  catch(AhuException &ae) {
    cerr<<"\nFatal error: "<<ae.reason<<endl;
    return 0;
  }
  catch(std::exception &e) {
    cerr<<"died because of STL error: "<<e.what()<<endl;
    exit(0);
  }
  catch(...) {
    cerr<<"died because of unknown exception"<<endl;
    exit(0);
  }
  
  return 1;

}
