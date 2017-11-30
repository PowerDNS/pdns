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
#include "json11.hpp"
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



StatBag S;

enum dbmode_t {MYSQL, GORACLE, POSTGRES, SQLITE, MYDNS, ORACLE};
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
  if(g_mode == SQLITE || g_mode==GORACLE || g_mode==ORACLE)
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
    if(g_mode==POSTGRES) {
      cout<<"COMMIT WORK;"<<endl;
    }
    else if(g_mode == MYSQL || g_mode == SQLITE || g_mode == MYDNS) {
      cout<<"COMMIT;"<<endl;
    }
  }
  g_intransaction=1;
  
  if(g_mode == MYSQL || g_mode == MYDNS)
    cout<<"BEGIN;"<<endl;
  else if (g_mode!=GORACLE && g_mode!=ORACLE)
    cout<<"BEGIN TRANSACTION;"<<endl;
}

static void emitDomain(const DNSName& domain, const vector<ComboAddress> *masters = 0) {
  string iDomain = domain.toStringRootDot();
  if(!::arg().mustDo("slave")) {
    if(g_mode==POSTGRES || g_mode==MYSQL || g_mode==SQLITE) {
      cout<<"insert into domains (name,type) values ("<<toLower(sqlstr(iDomain))<<",'NATIVE');"<<endl;
    }
    else if(g_mode==GORACLE) {
      cout<<"insert into domains (id,name,type) values (domains_id_sequence.nextval,"<<toLower(sqlstr(iDomain))<<",'NATIVE');"<<endl;
    }
    else if(g_mode==ORACLE) {
      cout<<"INSERT INTO Zones (id, name, type) VALUES (zones_id_seq.nextval, "<<sqlstr(toLower(iDomain))<<", 'NATIVE');"<<endl;
    }
  }
  else 
  {

    if(g_mode==POSTGRES || g_mode==MYSQL || g_mode==SQLITE) {
      string mstrs;
      if (masters != 0 && ! masters->empty()) {
        for(const auto& mstr :  *masters) {
          mstrs.append(mstr.toStringWithPortExcept(53));
          mstrs.append(1, ' ');
        }
      }
      if (mstrs.empty())
        cout<<"insert into domains (name,type) values ("<<sqlstr(iDomain)<<",'NATIVE');"<<endl;
      else
        cout<<"insert into domains (name,type,master) values ("<<sqlstr(iDomain)<<",'SLAVE'"<<", '"<<mstrs<<"');"<<endl;
    }
    else if (g_mode == GORACLE || g_mode==ORACLE) {
      cerr<<"Slave import mode not supported with oracle."<<endl;
    }
  }
}

bool g_doJSONComments;
static void emitRecord(const DNSName& zoneName, const DNSName &DNSqname, const string &qtype, const string &ocontent, int ttl, const string& comment="")
{
  string qname = DNSqname.toStringRootDot();
  string zname = zoneName.toStringRootDot();
  int prio=0;
  int disabled=0;
  string recordcomment;

  if(g_doJSONComments & !comment.empty()) {
    string::size_type pos = comment.find("json={");
    if(pos!=string::npos) {
      string json = comment.substr(pos+5);
      string err;
      auto document = json11::Json::parse(json, err);
      if(document.is_null())
        throw runtime_error("Could not parse JSON '"+json+"': " + err);

      disabled=document["disabled"].bool_value();
      recordcomment=document["comment"].string_value();
    }
  }

  g_numRecords++;
  string content(ocontent);

  if(qtype == "NSEC" || qtype == "NSEC3")
    return; // NSECs do not go in the database

  if((qtype == "MX" || qtype == "SRV") && g_mode!=ORACLE) {
    prio=pdns_stou(content);
    
    string::size_type pos = content.find_first_not_of("0123456789");
    if(pos != string::npos)
      boost::erase_head(content, pos);
    trim_left(content);
  }

  bool auth = true;
  if(qtype == "NS" && !pdns_iequals(qname, zname)) {
    auth=false;
  }

  if(g_mode==MYSQL || g_mode==SQLITE) {
    cout<<"insert into records (domain_id, name, type,content,ttl,prio,disabled) select id ,"<<
      sqlstr(toLower(qname))<<", "<<
      sqlstr(qtype)<<", "<<
      sqlstr(stripDotContent(content))<<", "<<ttl<<", "<<prio<<", "<<disabled<<
      " from domains where name="<<toLower(sqlstr(zname))<<";\n";

    if(!recordcomment.empty()) {
      cout<<"insert into comments (domain_id,name,type,modified_at, comment) select id, "<<toLower(sqlstr(stripDot(qname)))<<", "<<sqlstr(qtype)<<", "<<time(0)<<", "<<sqlstr(recordcomment)<<" from domains where name="<<toLower(sqlstr(zname))<<";\n";
    }
  }
  else if(g_mode==POSTGRES) {
    cout<<"insert into records (domain_id, name, ordername, auth, type,content,ttl,prio,disabled) select id ,"<<
      sqlstr(toLower(qname))<<", "<<
      sqlstr(DNSName(qname).makeRelative(DNSName(zname)).makeLowerCase().labelReverse().toString(" ", false))<<", '"<< (auth  ? 't' : 'f') <<"', "<<
      sqlstr(qtype)<<", "<<
      sqlstr(stripDotContent(content))<<", "<<ttl<<", "<<prio<<", '"<<(disabled ? 't': 'f') <<
      "' from domains where name="<<toLower(sqlstr(zname))<<";\n";
  }
  else if(g_mode==GORACLE) {
    cout<<"insert into Records (id, domain_id, name, type, content, ttl, prio, disabled) select RECORDS_ID_SEQUENCE.nextval,id ,"<<
      sqlstr(toLower(qname))<<", "<<
      sqlstr(qtype)<<", "<<
      sqlstr(stripDotContent(content))<<", "<<ttl<<", "<<prio<<", "<<disabled<<
      " from Domains where name="<<toLower(sqlstr(zname))<<";\n";
  }
  else if(g_mode==ORACLE) {
    cout<<"INSERT INTO Records (id, zone_id, fqdn, ttl, type, content) SELECT records_id_seq.nextval, id, "<<
      sqlstr(toLower(qname))<<", "<<
      ttl<<", "<<sqlstr(qtype)<<", "<<
      sqlstr(stripDotContent(content))<<
      " FROM Zones WHERE name="<<toLower(sqlstr(zname))<<";"<<endl;
  }
  else if (g_mode == MYDNS) {
    string zoneNameDot = zname + ".";
    if (qtype == "A" || qtype == "AAAA" || qtype == "CNAME" || qtype == "HINFO" || qtype == "MX" || qtype == "NAPTR" || 
        qtype == "NS" || qtype == "PTR" || qtype == "RP" || qtype == "SRV" || qtype == "TXT")
    {
      if ((qtype == "MX" || qtype == "NS" || qtype == "SRV" || qtype == "CNAME") && content[content.size()-1] != '.')
        content.append(".");
      cout<<"INSERT INTO rr(zone, name, type, data, aux, ttl) VALUES("<<
      "(SELECT id FROM soa WHERE origin = "<< 
      sqlstr(toLower(zoneNameDot))<<"), "<<
      sqlstr(toLower(DNSqname.toString()))<<", "<<
      sqlstr(qtype)<<", "<<sqlstr(content)<<", "<<prio<<", "<<ttl<<");\n";
    }
    else if (qtype == "SOA") {
      //pdns CONTENT = ns1.wtest.com. ahu.example.com. 2005092501 28800 7200 604800 86400 
      vector<string> parts;
      stringtok(parts, content);
 
      cout<<"INSERT INTO soa(origin, ns, mbox, serial, refresh, retry, expire, minimum, ttl) VALUES("<<
      sqlstr(toLower(zoneNameDot))<<", "<<sqlstr(parts[0])<<", "<<sqlstr(parts[1])<<", "<<pdns_stou(parts[2])<<", "<<
      pdns_stou(parts[3])<<", "<<pdns_stou(parts[4])<<", "<<pdns_stou(parts[5])<<", "<<pdns_stou(parts[6])<<", "<<ttl<<");\n";
    }
    else
    {
      cerr<<"Record type "<<qtype<<" is not supported."<<endl;
    }
  }
}


/* 2 modes of operation, either --named or --zone (the latter needs $ORIGIN) 
   2 further modes: --mysql, --goracle or --oracle
*/

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}


int main(int argc, char **argv)
try
{
    reportAllTypes();
    std::ios_base::sync_with_stdio(false);
  
    ::arg().setSwitch("gpgsql","Output in format suitable for default gpgsqlbackend")="no";
    ::arg().setSwitch("gmysql","Output in format suitable for default gmysqlbackend")="no";
    ::arg().setSwitch("mydns","Output in format suitable for default mydnsbackend")="no";
    ::arg().setSwitch("goracle","Output in format suitable for the goraclebackend")="no";
    ::arg().setSwitch("oracle","Output in format suitable for the oraclebackend")="no";
    ::arg().setSwitch("gsqlite","Output in format suitable for default gsqlitebackend")="no";
    ::arg().setSwitch("verbose","Verbose comments on operation")="no";
    ::arg().setSwitch("slave","Keep BIND slaves as slaves. Only works with named-conf.")="no";
    ::arg().setSwitch("json-comments","Parse json={} field for disabled & comments")="no";
    ::arg().setSwitch("transactions","If target SQL supports it, use transactions")="no";
    ::arg().setSwitch("on-error-resume-next","Continue after errors")="no";
    ::arg().setSwitch("filter-duplicate-soa","Filter second SOA in zone")="yes";
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

    if(::arg().mustDo("version")) {
      cerr<<"zone2sql "<<VERSION<<endl;
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
  
    bool filterDupSOA = ::arg().mustDo("filter-duplicate-soa");

    g_doJSONComments=::arg().mustDo("json-comments");
      
    if(::arg().mustDo("gmysql")) 
      g_mode=MYSQL;
    else if(::arg().mustDo("gpgsql"))
      g_mode=POSTGRES;
    else if(::arg().mustDo("gsqlite"))
      g_mode=SQLITE;
    else if(::arg().mustDo("goracle"))
      g_mode=GORACLE;
    else if(::arg().mustDo("oracle"))
      g_mode=ORACLE;
    else if(::arg().mustDo("mydns"))
      g_mode=MYDNS;
    else {
      cerr<<"Unknown SQL mode!\n\n";
      cerr<<"syntax:"<<endl<<endl;
      cerr<<::arg().helpstring()<<endl;
      exit(1);
    }

    if((g_mode==GORACLE || g_mode==ORACLE) && !::arg().mustDo("transactions"))
      cout<<"set autocommit on;"<<endl;

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
            bool seenSOA=false;
            string comment;
            while(zpt.get(rr, &comment)) {
              if(filterDupSOA && seenSOA && rr.qtype.getCode() == QType::SOA)
                continue;
              if(rr.qtype.getCode() == QType::SOA)
                seenSOA=true;

              emitRecord(i->name, rr.qname, rr.qtype.getName(), rr.content, rr.ttl, comment);
            }
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
      cerr<<"\r100% done\033\133\113"<<endl;
    }
    else {
      DNSName zonename;
      if(!::arg()["zone-name"].empty())
        zonename = DNSName(::arg()["zone-name"]);

      ZoneParserTNG zpt(zonefile, zonename);
      DNSResourceRecord rr;
      startNewTransaction();
      string comment;
      bool seenSOA=false;
      bool haveEmittedZone = false;
      while(zpt.get(rr, &comment))  {
	if(filterDupSOA && seenSOA && rr.qtype.getCode() == QType::SOA)
	  continue;
	if(rr.qtype.getCode() == QType::SOA)
	  seenSOA=true;
        if(!haveEmittedZone) {
          if(!zpt.getZoneName().empty()){
            emitDomain(zpt.getZoneName());
            haveEmittedZone = true;
          } else {
            // We have no zonename yet, don't emit
            continue;
          }
        }

        emitRecord(zpt.getZoneName(), rr.qname, rr.qtype.getName(), rr.content, rr.ttl, comment);
      }
      num_domainsdone=1;
    }
    cerr<<num_domainsdone<<" domains were fully parsed, containing "<<g_numRecords<<" records\n";
    
  if(::arg().mustDo("transactions") && g_intransaction) {
    if(g_mode != SQLITE)
      cout<<"COMMIT WORK;"<<endl;
    else
      cout<<"COMMIT;"<<endl;
  }
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
