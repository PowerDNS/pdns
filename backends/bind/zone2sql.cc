/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2007  PowerDNS.COM BV

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
/* accepts a named.conf as parameter and outputs heaps of sql */

// $Id$ 
#ifdef WIN32
# pragma warning ( disable: 4786 )

#endif // WIN32
#include <unistd.h>
#include <string>
#include <map>

#include <iostream>
#include <stdio.h>

using namespace std;

#include "dns.hh"
#include "arguments.hh"
#include "bindparser.hh"
#include "statbag.hh"
#include "misc.hh"
#include "dnspacket.hh"
#include "zoneparser-tng.hh"
#include "dnsrecords.hh"
#include <boost/algorithm/string.hpp>

using namespace boost;
StatBag S;

static const string sqlstr(const string &name)
{
  string a="\'";

  for(string::const_iterator i=name.begin();i!=name.end();++i)
    if(*i=='\'' || *i=='\\'){
      a+='\\';
      a+=*i;
    }
    else
      a+=*i;
  a+="\'";
  return a;
}

static int dirty_hack_num;

enum dbmode_t {MYSQL=0,ORACLE=1,BARE=2,POSTGRES=3};
dbmode_t mode;
bool g_intransaction;

static int num_records;
static string lastsoa_qname;

static void callback(unsigned int domain_id,const string &domain, const string &qtype, const string &ocontent, int ttl, int prio)
{
  static int lastsoa_domain_id=-1;
  string content(ocontent);

  num_records++;

  if(qtype=="SOA") {
    //    cerr<<"Juh: "<<dirty_hack_num<<", "<<lastsoa_domain_id<<", "<<lastsoa_qname<<", "<<domain<<endl;
    if(dirty_hack_num==lastsoa_domain_id && lastsoa_qname!=stripDot(domain)) {
      dirty_hack_num++;
      cerr<<"Second SOA in zone, raised domain_id"<<endl;
      if(mode==POSTGRES || mode==ORACLE) {
	if(g_intransaction && arg().mustDo("transactions")) {
	  cout<<"COMMIT WORK;"<<endl;
	}
	if(arg().mustDo("transactions")) {
	  if(mode==POSTGRES)
	    cout<<"BEGIN TRANSACTION;"<<endl;
	  g_intransaction=1;
	}
	
	if(mode==POSTGRES) {
	  cout<<"insert into domains (name,type) values ("<<toLower(sqlstr(stripDot(domain)))<<",'NATIVE');"<<endl;
	}
	else if(mode==ORACLE) {
	  cout<<"insert into domains (id,name,type) values (domains_id_sequence.nextval,"<<toLower(sqlstr(domain))<<",'NATIVE');"<<endl;
	}
      }
    }
    SOAData soadata;
    fillSOAData(content, soadata);
    soadata.hostmaster=stripDot(soadata.hostmaster);
    soadata.nameserver=stripDot(soadata.nameserver);
    content=serializeSOAData(soadata);

    lastsoa_qname=stripDot(domain);
  }
  
  if(qtype == "MX" || qtype == "SRV") { 
    prio=atoi(content.c_str());
    
    string::size_type pos = content.find_first_not_of("0123456789");
    if(pos != string::npos)
      erase_head(content, pos);
    trim_left(content);
  }


  lastsoa_domain_id=dirty_hack_num;

  if(mode==MYSQL) {
    cout<<"insert into records (domain_id, name,type,content,ttl,prio) values ("<< dirty_hack_num<<", "<<
      sqlstr(stripDot(domain))<<", "<<
      sqlstr(qtype)<<", "<<
      sqlstr(stripDot(content))<<", "<<ttl<<", "<<prio<<");\n";
  }
  if(mode==POSTGRES) {
    cout<<"insert into records (domain_id, name,type,content,ttl,prio) select id ,"<<
      sqlstr(toLower(stripDot(domain)))<<", "<<
      sqlstr(qtype)<<", "<<
      sqlstr(stripDot(content))<<", "<<ttl<<", "<<prio<< 
      " from domains where name="<<toLower(sqlstr(lastsoa_qname))<<";\n";
  }
  else if(mode==ORACLE) {
    cout<<"insert into Records (id,ZoneId, name,type,content,TimeToLive,Priority) select RECORDS_ID_SEQUENCE.nextval,id ,"<<
      sqlstr(toLower(stripDot(domain)))<<", "<<
      sqlstr(qtype)<<", "<<
      sqlstr(stripDot(content))<<", "<<ttl<<", "<<prio<< 
      " from Domains where name="<<toLower(sqlstr(lastsoa_qname))<<";\n";
  }
  else if(mode==BARE) {
    cout<< dirty_hack_num<<"\t"<<
      sqlstr(stripDot(domain))<<"\t"<<
      sqlstr(qtype)<<"\t"<<sqlstr(stripDot(content))<<"\t"<<prio<<"\t"<<ttl<<"\n";
  }

}


/* 2 modes of operation, either --named or --zone (the latter needs $ORIGIN) 
   2 further modes: --mysql or --oracle 
   and a parameter: --start-id
*/

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}


int main(int argc, char **argv)
{
  try {
    reportAllTypes();
#if __GNUC__ >= 3
    ios_base::sync_with_stdio(false);
#endif
    lastsoa_qname=" ";
    arg().setSwitch("mysql","Output in format suitable for mysqlbackend")="yes";
    arg().setCmd("gpgsql","Output in format suitable for default gpgsqlbackend");
    arg().setCmd("gmysql","Output in format suitable for default gmysqlbackend");
    arg().setCmd("oracle","Output in format suitable for the oraclebackend");
    arg().setCmd("bare","Output in a bare format, suitable for further parsing");
    arg().setSwitch("verbose","Verbose comments on operation")="no";
    arg().setSwitch("slave","Keep BIND slaves as slaves")="no";
    arg().setSwitch("transactions","If target SQL supports it, use transactions")="no";
    arg().setSwitch("on-error-resume-next","Continue after errors")="no";
    arg().set("start-id","Value of first domain-id")="0";
    arg().set("zone","Zonefile with $ORIGIN to parse")="";
    arg().set("zone-name","Specify an $ORIGIN in case it is not present")="";
    arg().set("named-conf","Bind 8/9 named.conf to parse")="";
    arg().set("soa-minimum-ttl","Do not change")="0";
    arg().set("soa-refresh-default","Do not change")="0";
    arg().set("soa-retry-default","Do not change")="0";
    arg().set("soa-expire-default","Do not change")="0";

    arg().setCmd("help","Provide a helpful message");

    S.declare("logmessages");

    string namedfile="";
    string zonefile="";

    arg().parse(argc, argv);
  
    if(argc<2 || arg().mustDo("help")) {
      cerr<<"syntax:"<<endl<<endl;
      cerr<<arg().helpstring()<<endl;
      exit(1);
    }
  
    if(arg().mustDo("mysql")) 
      mode=MYSQL;
    if(arg().mustDo("gpgsql") || arg().mustDo("gmysql"))
      mode=POSTGRES;
    if(arg().mustDo("bare"))
      mode=BARE;
    if(arg().mustDo("oracle")) {
      mode=ORACLE;
      if(!arg().mustDo("transactions"))
	cout<<"set autocommit on;"<<endl;
    }


    dirty_hack_num=arg().asNum("start-id");
    namedfile=arg()["named-conf"];
    zonefile=arg()["zone"];

    int count=0;

    if(zonefile.empty()) {
      BindParser BP;
      BP.setVerbose(arg().mustDo("verbose"));
      BP.parse(namedfile.empty() ? "./named.conf" : namedfile);
    
      const vector<BindDomainInfo> &domains=BP.getDomains();

      int numdomains=domains.size();
      int tick=numdomains/100;
      //      ZP.setDirectory(BP.getDirectory());
    
      for(vector<BindDomainInfo>::const_iterator i=domains.begin();
	  i!=domains.end();
	  ++i)
	{
	  try {
	    if(mode==POSTGRES || mode==ORACLE) {
	      if(g_intransaction && arg().mustDo("transactions")) {
		cout<<"COMMIT WORK;"<<endl;
	      }
	      if(arg().mustDo("transactions")) {
		if(mode==POSTGRES)
		  cout<<"BEGIN TRANSACTION;"<<endl;
		g_intransaction=1;
	      }

	      if(mode==POSTGRES) {
		if(arg().mustDo("slave")) {
		  if(i->master.empty())
		    cout<<"insert into domains (name,type) values ("<<sqlstr(i->name)<<",'NATIVE');"<<endl;
		  else
		    cout<<"insert into domains (name,type,master) values ("<<sqlstr(i->name)<<",'SLAVE'"<<", '"<<i->master<<"');"<<endl;
		}
		else
		  cout<<"insert into domains (name,type) values ("<<sqlstr(i->name)<<",'NATIVE');"<<endl;
	      }
	      else if(mode==ORACLE) {
		cout<<"insert into domains (id,name,type) values (domains_id_sequence.nextval,"<<toLower(sqlstr(i->name))<<",'NATIVE');"<<endl;
	      }
	      lastsoa_qname=i->name;
	    }
	    ZoneParserTNG zpt(i->filename, i->name, BP.getDirectory());
	    DNSResourceRecord rr;
	    while(zpt.get(rr)) 
	      callback(0, rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority);
	  }
	  catch(AhuException &ae) {
	    if(!arg().mustDo("on-error-resume-next"))
	      throw;
	    else
	      cerr<<ae.reason<<endl;
	  }

	  dirty_hack_num++;
	  if(!tick || !((count++)%tick))
	    cerr<<"\r"<<count*100/numdomains<<"% done ("<<i->filename<<")\033\133\113";
	}
      cerr<<"\r100% done\033\133\113"<<endl;
    }
    else {
      ZoneParserTNG zpt(zonefile, arg()["zone-name"]);
      DNSResourceRecord rr;
      dirty_hack_num=-1; // trigger first SOA output
      while(zpt.get(rr)) 
	callback(0, rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority);

    }
    cerr<<"Parsed "<<num_records<<" records"<<endl;
    
  }
  catch(AhuException &ae) {
    cerr<<"\nFatal error: "<<ae.reason<<endl;
    return 0;
  }
  catch(exception &e) {
    cerr<<"died because of STL error: "<<e.what()<<endl;
    exit(0);
  }
  catch(...) {
    cerr<<"died because of unknown exception"<<endl;
    exit(0);
  }
  
  if((mode==POSTGRES || mode==ORACLE) && arg().mustDo("transactions") && g_intransaction)
    cout<<"COMMIT WORK;"<<endl;
  return 1;

}
