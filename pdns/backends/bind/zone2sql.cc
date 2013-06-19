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
#include <boost/foreach.hpp>


StatBag S;
static bool g_doDNSSEC;

enum dbmode_t {MYSQL, ORACLE, POSTGRES, SQLITE, MYDNS};
static dbmode_t g_mode;
static bool g_intransaction;
static int g_numRecords;


/* this is an official wart. We don't terminate domains on a . in PowerDNS,
   which is fine as it goes, except for encoding the root, it would end up as '', 
   which leads to ambiguities in the content field. Therefore, if we encounter
   the root as a . in a BIND zone, we leave it as a ., and don't replace it by 
   an empty string. Back in 1999 we made the wrong choice. */
   
static string stripDotContent(const string& content)
{
  if(boost::ends_with(content, " .") || content==".")
    return content;
  return stripDot(content);
}

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
  if(g_mode == POSTGRES)
    return "E'"+a+"'";
  else
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
    else if(g_mode == MYSQL || g_mode == SQLITE || g_mode == MYDNS) {
      cout<<"COMMIT;"<<endl;
    }
  }
  g_intransaction=1;
  
  if(g_mode == MYSQL || g_mode == MYDNS)
    cout<<"BEGIN;"<<endl;
  else
    cout<<"BEGIN TRANSACTION;"<<endl;
}

static void emitDomain(const string& domain, const vector<string> *masters = 0) {
  if(!::arg().mustDo("slave")) {
    if(g_mode==POSTGRES || g_mode==MYSQL || g_mode==SQLITE) {
      cout<<"insert into domains (name,type) values ("<<toLower(sqlstr(stripDot(domain)))<<",'NATIVE');"<<endl;
    }
    else if(g_mode==ORACLE) {
      cout<<"insert into domains (id,name,type) values (domains_id_sequence.nextval,"<<toLower(sqlstr(domain))<<",'NATIVE');"<<endl;
    }
  }
  else 
  {

    if(g_mode==POSTGRES || g_mode==MYSQL || g_mode==SQLITE) {
      string mstrs;
      if (masters != 0 && ! masters->empty()) {
        BOOST_FOREACH(const string& mstr, *masters) {
          mstrs.append(mstr);
          mstrs.append(1, ' ');
        }                  
      }
      if (mstrs.empty())
        cout<<"insert into domains (name,type) values ("<<sqlstr(domain)<<",'NATIVE');"<<endl;
      else
        cout<<"insert into domains (name,type,master) values ("<<sqlstr(domain)<<",'SLAVE'"<<", '"<<mstrs<<"');"<<endl;
    }
    else if (g_mode == ORACLE) {
      cerr<<"Slave import mode not supported with oracle."<<endl;
    }
  }
}

static void emitRecord(const string& zoneName, const string &qname, const string &qtype, const string &ocontent, int ttl, int prio)
{
  g_numRecords++;
  string content(ocontent);

  if(qtype == "NSEC" || qtype == "NSEC3")
    return; // NSECs do not go in the database

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
        sqlstr(stripDotContent(content))<<", "<<ttl<<", "<<prio<< 
        " from domains where name="<<toLower(sqlstr(zoneName))<<";\n";
    } else
    {
      cout<<"insert into records (domain_id, name, ordername, auth, type,content,ttl,prio) select id ,"<<
        sqlstr(toLower(stripDot(qname)))<<", "<<
        sqlstr(toLower(labelReverse(makeRelative(stripDot(qname), zoneName))))<<", "<<auth<<", "<<
        sqlstr(qtype)<<", "<<
        sqlstr(stripDotContent(content))<<", "<<ttl<<", "<<prio<< 
        " from domains where name="<<toLower(sqlstr(zoneName))<<";\n";
    }
  }
  else if(g_mode==POSTGRES) {
    if(!g_doDNSSEC) {
      cout<<"insert into records (domain_id, name,type,content,ttl,prio) select id ,"<<
        sqlstr(toLower(stripDot(qname)))<<", "<<
        sqlstr(qtype)<<", "<<
        sqlstr(stripDotContent(content))<<", "<<ttl<<", "<<prio<< 
        " from domains where name="<<toLower(sqlstr(zoneName))<<";\n";
    } else
    {
      cout<<"insert into records (domain_id, name, ordername, auth, type,content,ttl,prio) select id ,"<<
        sqlstr(toLower(stripDot(qname)))<<", "<<
        sqlstr(toLower(labelReverse(makeRelative(stripDot(qname), zoneName))))<<", '"<< (auth  ? 't' : 'f') <<"', "<<
        sqlstr(qtype)<<", "<<
        sqlstr(stripDotContent(content))<<", "<<ttl<<", "<<prio<< 
        " from domains where name="<<toLower(sqlstr(zoneName))<<";\n";
    }
  }
  else if(g_mode==ORACLE) {
    cout<<"insert into Records (id,ZoneId, name,type,content,TimeToLive,Priority) select RECORDS_ID_SEQUENCE.nextval,id ,"<<
      sqlstr(toLower(stripDot(qname)))<<", "<<
      sqlstr(qtype)<<", "<<
      sqlstr(stripDotContent(content))<<", "<<ttl<<", "<<prio<< 
      " from Domains where name="<<toLower(sqlstr(zoneName))<<";\n";
  }
  else if (g_mode == MYDNS) {
    string zoneNameDot = zoneName + ".";
    if (qtype == "A" || qtype == "AAAA" || qtype == "CNAME" || qtype == "HINFO" || qtype == "MX" || qtype == "NAPTR" || 
        qtype == "NS" || qtype == "PTR" || qtype == "RP" || qtype == "SRV" || qtype == "TXT")
    {
      if ((qtype == "MX" || qtype == "NS" || qtype == "SRV" || qtype == "CNAME") && content[content.size()-1] != '.')
        content.append(".");
      cout<<"INSERT INTO rr(zone, name, type, data, aux, ttl) VALUES("<<
      "(SELECT id FROM soa WHERE origin = "<< 
      sqlstr(toLower(zoneNameDot))<<"), "<<
      sqlstr(toLower(qname))<<", "<<
      sqlstr(qtype)<<", "<<sqlstr(content)<<", "<<prio<<", "<<ttl<<");\n";
    }
    else if (qtype == "SOA") {
      //pdns CONTENT = ns1.wtest.com. ahu.example.com. 2005092501 28800 7200 604800 86400 
      vector<string> parts;
      stringtok(parts, content);
 
      cout<<"INSERT INTO soa(origin, ns, mbox, serial, refresh, retry, expire, minimum, ttl) VALUES("<<
      sqlstr(toLower(zoneNameDot))<<", "<<sqlstr(parts[0])<<", "<<sqlstr(parts[1])<<", "<<atoi(parts[2].c_str())<<", "<<
      atoi(parts[3].c_str())<<", "<<atoi(parts[4].c_str())<<", "<<atoi(parts[5].c_str())<<", "<<atoi(parts[6].c_str())<<", "<<ttl<<");\n";
    }
    else
    {
      cerr<<"Record type "<<qtype<<" is not supported."<<endl;
    }
  }
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
  try {
    reportAllTypes();
    reportFancyTypes();
#if __GNUC__ >= 3
    std::ios_base::sync_with_stdio(false);
#endif
   
    ::arg().setSwitch("gpgsql","Output in format suitable for default gpgsqlbackend")="no";
    ::arg().setSwitch("gmysql","Output in format suitable for default gmysqlbackend")="no";
    ::arg().setSwitch("mydns","Output in format suitable for default mydnsbackend")="no";
    ::arg().setSwitch("oracle","Output in format suitable for the oraclebackend")="no";
    ::arg().setSwitch("gsqlite","Output in format suitable for default gsqlitebackend")="no";
    ::arg().setSwitch("verbose","Verbose comments on operation")="no";
    ::arg().setSwitch("dnssec","Add DNSSEC related data")="no";
    ::arg().setSwitch("slave","Keep BIND slaves as slaves. Only works with named-conf.")="no";
    ::arg().setSwitch("transactions","If target SQL supports it, use transactions")="no";
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
    else if(::arg().mustDo("mydns"))
      g_mode=MYDNS;
    else {
      cerr<<"Unknown SQL mode!\n\n";
      cerr<<"syntax:"<<endl<<endl;
      cerr<<::arg().helpstring()<<endl;
      exit(1);
    }

    g_doDNSSEC=::arg().mustDo("dnssec");
      
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
            
            emitDomain(i->name, &(i->masters));
            
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
      string zonename = ::arg()["zone-name"];
      ZoneParserTNG zpt(zonefile, zonename);
      DNSResourceRecord rr;
      startNewTransaction();
      emitDomain(zonename);
      while(zpt.get(rr)) 
        emitRecord(zonename, rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority);
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
