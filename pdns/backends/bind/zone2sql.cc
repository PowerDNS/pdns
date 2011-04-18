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
static bool g_doDNSSEC;
static int g_domainid;

enum dbmode_t {MYSQL, ORACLE, POSTGRES, SQLITE};
static dbmode_t g_mode;
static bool g_intransaction;
static int g_numRecords;

static string sqlstr(const string &name)
{
  if(g_mode == SQLITE)
    return "'"+boost::replace_all_copy(name, "'", "''")+"'";
  
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i) {
    if(*i=='\'' || *i=='\\'){
      a+='\\';
      a+=*i;
    }
    else
      a+=*i;
  }
  return "'"+a+"'";
}

static void startNewTransaction()
{
  if(!::arg().mustDo("transactions"))
    return;
   
  if(g_intransaction) { 
    if(g_mode==POSTGRES || g_mode==ORACLE) {
      cout<<"COMMIT WORK;"<<endl;
    }
    else if(g_mode == MYSQL || g_mode == SQLITE) {
      cout<<"COMMIT;"<<endl;
    }
  }
  g_intransaction=1;
  
  if(g_mode == MYSQL)
    cout<<"BEGIN;"<<endl;
  else
    cout<<"BEGIN TRANSACTION;"<<endl;
}

static void emitRecord(const string& zoneName, const string &qname, const string &qtype, const string &ocontent, int ttl, int prio)
{
  g_numRecords++;
  string content(ocontent);
  if(qtype == "MX" || qtype == "SRV") { 
    prio=atoi(content.c_str());
    
    string::size_type pos = content.find_first_not_of("0123456789");
    if(pos != string::npos)
      boost::erase_head(content, pos);
    trim_left(content);
  }

  bool auth = true;
  if(qtype == "NS" && !pdns_iequals(stripDot(qname), zoneName)) {
    auth=false;
  }

  if(g_mode==MYSQL || g_mode==SQLITE) {
    if(!g_doDNSSEC) {
      cout<<"insert into records (domain_id, name,type,content,ttl,prio) select id ,"<<
        sqlstr(toLower(stripDot(qname)))<<", "<<
        sqlstr(qtype)<<", "<<
        sqlstr(stripDot(content))<<", "<<ttl<<", "<<prio<< 
        " from domains where name="<<toLower(sqlstr(zoneName))<<";\n";
    } else
    {
      cout<<"insert into records (domain_id, name, ordername, auth, type,content,ttl,prio) select id ,"<<
        sqlstr(toLower(stripDot(qname)))<<", "<<
        sqlstr(toLower(labelReverse(makeRelative(stripDot(qname), zoneName))))<<", "<<auth<<", "<<
        sqlstr(qtype)<<", "<<
        sqlstr(stripDot(content))<<", "<<ttl<<", "<<prio<< 
        " from domains where name="<<toLower(sqlstr(zoneName))<<";\n";
    }
  }
  else if(g_mode==POSTGRES) {
    if(!g_doDNSSEC) {
      cout<<"insert into records (domain_id, name,type,content,ttl,prio) select id ,"<<
        sqlstr(toLower(stripDot(qname)))<<", "<<
        sqlstr(qtype)<<", "<<
        sqlstr(stripDot(content))<<", "<<ttl<<", "<<prio<< 
        " from domains where name="<<toLower(sqlstr(zoneName))<<";\n";
    } else
    {
      cout<<"insert into records (domain_id, name, ordername, auth, type,content,ttl,prio) select id ,"<<
        sqlstr(toLower(stripDot(qname)))<<", "<<
        sqlstr(toLower(labelReverse(makeRelative(stripDot(qname), zoneName))))<<", '"<< (auth  ? 't' : 'f') <<"', "<<
        sqlstr(qtype)<<", "<<
        sqlstr(stripDot(content))<<", "<<ttl<<", "<<prio<< 
        " from domains where name="<<toLower(sqlstr(zoneName))<<";\n";
    }
  }
  else if(g_mode==ORACLE) {
    cout<<"insert into Records (id,ZoneId, name,type,content,TimeToLive,Priority) select RECORDS_ID_SEQUENCE.nextval,id ,"<<
      sqlstr(toLower(stripDot(qname)))<<", "<<
      sqlstr(qtype)<<", "<<
      sqlstr(stripDot(content))<<", "<<ttl<<", "<<prio<< 
      " from Domains where name="<<toLower(sqlstr(zoneName))<<";\n";
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
    reportFancyTypes();
#if __GNUC__ >= 3
    std::ios_base::sync_with_stdio(false);
#endif
   
    ::arg().setSwitch("gpgsql","Output in format suitable for default gpgsqlbackend")="no";
    ::arg().setSwitch("gmysql","Output in format suitable for default gmysqlbackend")="no";
    ::arg().setSwitch("oracle","Output in format suitable for the oraclebackend")="no";
    ::arg().setSwitch("gsqlite","Output in format suitable for default gsqlitebackend")="no";
    ::arg().setSwitch("verbose","Verbose comments on operation")="no";
    ::arg().setSwitch("dnssec","Add DNSSEC related data")="no";
    ::arg().setSwitch("slave","Keep BIND slaves as slaves")="no";
    ::arg().setSwitch("transactions","If target SQL supports it, use transactions")="no";
    ::arg().setSwitch("on-error-resume-next","Continue after errors")="no";
    ::arg().set("start-id","Value of first domain-id when not parsing named.conf")="0";
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
  
    if(::arg().mustDo("gmysql")) 
      g_mode=MYSQL;
    else if(::arg().mustDo("gpgsql"))
      g_mode=POSTGRES;
    else if(::arg().mustDo("gsqlite"))
      g_mode=SQLITE;
    else if(::arg().mustDo("oracle")) {
      g_mode=ORACLE;
      if(!::arg().mustDo("transactions"))
        cout<<"set autocommit on;"<<endl;
    }
    else {
      cerr<<"Unknown SQL mode!\n\n";
      cerr<<"syntax:"<<endl<<endl;
      cerr<<::arg().helpstring()<<endl;
      exit(1);
    }

    g_doDNSSEC=::arg().mustDo("dnssec");
      
    g_domainid=::arg().asNum("start-id");
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
    
      for(vector<BindDomainInfo>::const_iterator i=domains.begin();
          i!=domains.end();
          ++i)
        {
          if(i->type!="master" && i->type!="slave") {
            cerr<<" Warning! Skipping '"<<i->type<<"' zone '"<<i->name<<"'"<<endl;
            continue;
          }
          try {
            startNewTransaction();
            
            if(!::arg().mustDo("slave")) {
              if(g_mode==POSTGRES || g_mode==MYSQL || g_mode==SQLITE) {
                cout<<"insert into domains (name,type) values ("<<toLower(sqlstr(stripDot(i->name)))<<",'NATIVE');"<<endl;
              }
              else if(g_mode==ORACLE) {
                cout<<"insert into domains (id,name,type) values (domains_id_sequence.nextval,"<<toLower(sqlstr(i->name))<<",'NATIVE');"<<endl;
              }
              else if(g_mode==ORACLE) {
                cout<<"insert into domains (id,name,type) values (domains_id_sequence.nextval,"<<toLower(sqlstr(i->name))<<",'NATIVE');"<<endl;
              }
            }
            else 
            {
              if(g_mode==POSTGRES || g_mode==MYSQL || g_mode==SQLITE) {
                if(i->masters.empty())
                  cout<<"insert into domains (name,type) values ("<<sqlstr(i->name)<<",'NATIVE');"<<endl;
                else {
                  string masters;
                  BOOST_FOREACH(const string& mstr, i->masters) {
                    masters.append(mstr);
                    masters.append(1, ' ');
                  }                  
                  cout<<"insert into domains (name,type,master) values ("<<sqlstr(i->name)<<",'SLAVE'"<<", '"<<masters<<"');"<<endl;
                }
              }
            }
            
            
            ZoneParserTNG zpt(i->filename, i->name, BP.getDirectory());
            DNSResourceRecord rr;
            while(zpt.get(rr)) 
              emitRecord(i->name, rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority);
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
      cerr<<"\r100% done\033\133\113"<<endl;
    }
    else {
      ZoneParserTNG zpt(zonefile, ::arg()["zone-name"]);
      DNSResourceRecord rr;
      g_domainid=::arg().asNum("start-id"); // trigger first SOA output
      startNewTransaction();
      while(zpt.get(rr)) 
        emitRecord(::arg()["zone-name"], rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority);
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
  
  if(::arg().mustDo("transactions") && g_intransaction) {
    if(g_mode != SQLITE)
      cout<<"COMMIT WORK;"<<endl;
    else
      cout<<"COMMIT;"<<endl;
  }
  return 1;

}
