/*
 * PowerDNS backend module for MyDNS style databases
 * Author: Jonathan Oddy (Hostway UK) <jonathan@woaf.net>
 *
 * The schema used by MyDNS isn't suitable for retrieving results with a single
 * query. This means that existing PowerDNS backends are unable to make use of
 * the schema without lame hackery (or awful performance.) This module does
 * the nasty lookup logic required to make use of the schema, and should be as
 * tolerant as MyDNS when it comes to things being fully qualified or not.
 *
 * A known "bug" is that AXFRs will fail if your rr table contains invalid
 * junk. I'm not sure this is really a bug, if you've decided to put free-form
 * text in your data for an A record you have bigger issues.
 *
 * I'd advise avoiding the MyDNS schema if at all possible as the query count
 * for even simple lookups is daft. It's quite trivial to craft a request
 * that'll require 128 database queries to answer with a servfail!
 *
 * If you do not know what mydns is: http://mydns.bboy.net/
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>

#include "pdns/namespaces.hh"

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "mydnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ueberbackend.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"

#include <modules/gmysqlbackend/smysql.hh>

static string backendName="[MyDNSbackend]";

MyDNSBackend::MyDNSBackend(const string &suffix) {
  setArgPrefix("mydns"+suffix);
 
  d_domainIdQuery_stmt = NULL;
  d_domainNoIdQuery_stmt = NULL;
  d_listQuery_stmt = NULL;
  d_soaQuery_stmt = NULL;
  d_basicQuery_stmt = NULL;
  d_anyQuery_stmt = NULL;
  d_query_stmt = NULL;

  try {
    d_db = new SMySQL(getArg("dbname"),
      getArg("host"),
      getArgAsNum("port"),
      getArg("socket"),
      getArg("user"),
      getArg("password"));
    d_db->setLog(::arg().mustDo("query-logging"));
  }
  catch(SSqlException &e) {
    L<<Logger::Error<<backendName<<" Connection failed: "<<e.txtReason()<<endl;
    throw PDNSException(backendName+"Unable to launch connection: "+e.txtReason());
  }

  string rrtable=getArg("rr-table");
  string soatable=getArg("soa-table");
  string rrwhere=(mustDo("rr-active")?"(active = '1' or active = 'Y') and ":"")+getArg("rr-where");
  string soawhere=(mustDo("soa-active")?"(active = '1' or active = 'Y') and ":"")+getArg("soa-where");

  if (soatable.empty()) { throw PDNSException("SOA Table must not be empty"); }
  if (rrtable.empty()) { throw PDNSException("Records table must not be empty"); }

  d_useminimalttl=mustDo("use-minimal-ttl");
  d_minimum=0;

  L<<Logger::Warning<<backendName<<" Connection successful"<<endl;

  try {

    string domainIdQuery = "SELECT origin, minimum FROM `"+soatable+"` WHERE id = ?";
    string domainNoIdQuery = "SELECT id, origin, minimum FROM `"+soatable+"` WHERE origin = ?";
    string soaQuery = "SELECT id, mbox, serial, ns, refresh, retry, expire, minimum, ttl FROM `"+soatable+"` WHERE origin = ?";

    if (!soawhere.empty()) {
      domainIdQuery += " AND " + soawhere;  
      domainNoIdQuery += " AND " + soawhere;
      soaQuery += " AND "+soawhere;
    }

    d_domainIdQuery_stmt = d_db->prepare(domainIdQuery, 1);
    d_domainNoIdQuery_stmt = d_db->prepare(domainNoIdQuery, 1);
    d_soaQuery_stmt = d_db->prepare(soaQuery, 1);
  
    string listQuery = "SELECT type, data, aux, ttl, zone, name FROM `"+rrtable+"` WHERE zone = ?";
    string basicQuery = "SELECT type, data, aux, ttl, zone FROM `"+rrtable+"` WHERE zone = ? AND (name = ? OR name = ?) AND type = ?";
    string anyQuery = "(SELECT type, data, aux, ttl, zone FROM `"+rrtable+"` WHERE zone = ? AND (name = ? OR name = ?)";
 
   if (!rrwhere.empty()) {
     listQuery += " AND "+rrwhere;
     basicQuery += " AND " + rrwhere;
     anyQuery += " AND " + rrwhere;
    }

    d_listQuery_stmt = d_db->prepare(listQuery, 1);
  
    anyQuery += ") UNION (SELECT 'SOA' AS type, origin AS data, '0' AS aux, ttl, id AS zone FROM `"+soatable+"` WHERE id = ? AND origin = ?";

    if (!soawhere.empty())
      anyQuery += " AND "+soawhere;
  
    basicQuery += " ORDER BY type,aux,data";
    anyQuery += ") ORDER BY type,aux,data";
  
    d_basicQuery_stmt = d_db->prepare(basicQuery, 4);
    d_anyQuery_stmt = d_db->prepare(anyQuery, 5);
  } catch (SSqlException &e) {
    L<<Logger::Error<<"Cannot prepare statements: " << e.txtReason() <<endl;
    throw PDNSException("Cannot prepare statements: " + e.txtReason());
  }
}

MyDNSBackend::~MyDNSBackend() {
  delete d_domainIdQuery_stmt;
  d_domainIdQuery_stmt = NULL;
  delete d_domainNoIdQuery_stmt;
  d_domainNoIdQuery_stmt = NULL;
  delete d_listQuery_stmt;
  d_listQuery_stmt = NULL;
  delete d_soaQuery_stmt;
  d_soaQuery_stmt = NULL;
  delete d_basicQuery_stmt;
  d_basicQuery_stmt = NULL;
  delete d_anyQuery_stmt;
  d_anyQuery_stmt = NULL;
  delete(d_db);
}


bool MyDNSBackend::list(const string &target, int zoneId, bool include_disabled) {
  string query;
  string sname;
  SSqlStatement::row_t rrow;

  try {
    d_domainIdQuery_stmt->
      bind("domain_id", zoneId)->
      execute()->
      getResult(d_result)->
      reset();
  } 
  catch (SSqlException &e) {
    throw PDNSException("MyDNSBackend unable to list domain_id "+itoa(zoneId)+": "+e.txtReason());
  }
  
  if (d_result.empty())
    return false; // No such zone

  d_origin = d_result[0][0];
  if (d_origin[d_origin.length()-1] == '.')
    d_origin.erase(d_origin.length()-1);
  d_minimum = atol(d_result[0][1].c_str());

  if (d_result.size()>1) {
    L<<Logger::Warning<<backendName<<" Found more than one matching origin for zone ID: "<<zoneId<<endl;
  };

  try {
    d_query_stmt = d_listQuery_stmt;
    d_query_stmt->
      bind("domain_id", zoneId)->
      execute();
  }
  catch (SSqlException &e) {
    throw PDNSException("MyDNSBackend unable to list domain_id "+itoa(zoneId)+": "+e.txtReason());
  }

  d_qname = "";
  return true;
}

bool MyDNSBackend::getSOA(const string& name, SOAData& soadata, DNSPacket*) {
  string query;
  SSqlStatement::row_t rrow;

  if (name.empty())
    return false;

  string dotname = name+".";

  try {
    d_soaQuery_stmt->
      bind("origin", dotname)->
      execute()->
      getResult(d_result)->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("MyDNSBackend unable to get soa for domain "+name+": "+e.txtReason());
  }

  if (d_result.empty()) return false;

  rrow = d_result[0];

  soadata.qname = name;
  soadata.domain_id = atol(rrow[0].c_str());
  soadata.hostmaster = rrow[1];
  soadata.serial = atol(rrow[2].c_str());
  soadata.nameserver = rrow[3];
  soadata.refresh = atol(rrow[4].c_str());
  soadata.retry = atol(rrow[5].c_str());
  soadata.expire = atol(rrow[6].c_str());
  soadata.default_ttl = atol(rrow[7].c_str());
  soadata.ttl = atol(rrow[8].c_str());
  if (d_useminimalttl) {
    soadata.ttl = std::min(soadata.ttl, soadata.default_ttl);
  }
  soadata.db = this;

  if (d_result.size()>1) {
    L<<Logger::Warning<<backendName<<" Found more than one matching zone for: "+name<<endl;
  };

  return true;
}

void MyDNSBackend::lookup(const QType &qtype, const string &qname, DNSPacket *p, int zoneId) {
  string query;
  string sname;
  string zoneIdStr = itoa(zoneId);
  SSqlStatement::row_t rrow;
  bool found = false;

  d_origin = "";

  if (qname.empty())
    return;

  DLOG(L<<Logger::Debug<<"MyDNSBackend::lookup(" << qtype.getName() << "," << qname << ",p," << zoneId << ")" << endl);

  sname = qname;
  sname += ".";

  if (zoneId < 0) {
    // First off we need to work out what zone we're working with
    // MyDNS records aren't always fully qualified, so we need to work out the zone ID.

    size_t pos;
    string sdom;

    pos = 0;
    sdom = sname;
    while (!sdom.empty() && pos != string::npos) {
      try {
        d_domainNoIdQuery_stmt->
          bind("domain", sdom)->
          execute()->
          getResult(d_result)->
          reset();
      }
      catch (SSqlException &e) {
        throw PDNSException("MyDNSBackend unable to lookup "+qname+": "+e.txtReason());
      }

      if (d_result.empty() == false) {
        rrow = d_result[0];
        zoneId = boost::lexical_cast<int>(rrow[0]);
        d_origin = rrow[1];
        if (d_origin[d_origin.length()-1] == '.')
          d_origin.erase(d_origin.length()-1);
        d_minimum = atol(rrow[2].c_str());
        found = true;
        break;
      }

      pos = sname.find_first_of(".",pos+1);
      sdom = sname.substr(pos+1);
    }

  } else {
    try {
      d_domainIdQuery_stmt->
        bind("domain_id", zoneId)->
        execute()->
        getResult(d_result)->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("MyDNSBackend unable to lookup "+qname+": "+e.txtReason());
    }

    if(d_result.empty()) {
      throw PDNSException("lookup() passed zoneId = "+zoneIdStr+" but no such zone!");
    }

    rrow = d_result[0];

    found = true;
    d_origin = rrow[0];
    if (d_origin[d_origin.length()-1] == '.')
      d_origin.erase(d_origin.length()-1);
    d_minimum = atol(rrow[1].c_str());
  }


  if (found) {

    while (d_result.size()>1) {
      L<<Logger::Warning<<backendName<<" Found more than one matching zone for: "+d_origin<<endl;
    };
    // We found the zoneId, so we can work out how to find our rr
    string host;

    // The host part of the query is the name less the origin
    if (qname.length() == d_origin.length())
      host = "";
    else
      host = qname.substr(0, (qname.length() - d_origin.length())-1);

    try {

      if (qtype.getCode()==QType::ANY) {
        string dotqname = qname+".";
        d_query_stmt = d_anyQuery_stmt;
        d_query_stmt->
          bind("domain_id", zoneId)->
          bind("host", host)->
          bind("qname", sname)->
          bind("domain_id", zoneId)-> // this is because positional arguments
          bind("qname2", dotqname)->
          execute();
      } else {
        DLOG(L<<Logger::Debug<<"Running d_basicQuery_stmt with " << zoneId << ", " << host << ", " << sname << ", " << qtype.getName() << endl);
        d_query_stmt = d_basicQuery_stmt;
        d_query_stmt->
          bind("domain_id", zoneId)->
          bind("host", host)->
          bind("qname", sname)->
          bind("qtype", qtype.getName())->
          execute();
      }
    }
    catch (SSqlException &e) {
      throw PDNSException("MyDNSBackend unable to lookup "+qname+": "+e.txtReason());
    }

    d_qname = qname;
  }

}

bool MyDNSBackend::get(DNSResourceRecord &rr) {
  if (d_origin.empty()) {
    if (d_query_stmt) {
      try {
        d_query_stmt->reset();
      } catch (SSqlException &e) {
        throw PDNSException("MyDNSBackend unable to lookup "+d_qname+": "+e.txtReason());
      }
      d_query_stmt = NULL;
    }
    // This happens if lookup() couldn't find the zone
    return false;
  }

  SSqlStatement::row_t rrow;

  if (d_query_stmt->hasNextRow()) {
    try {
      d_query_stmt->nextRow(rrow);
    } catch (SSqlException &e) {
      throw PDNSException("MyDNSBackend unable to lookup "+d_qname+": "+e.txtReason());
    }
    rr.qtype=rrow[0];
    rr.content = rrow[1];
  
    if(!d_qname.empty()) {
      // use this to distinguish between select with 'name' field (list()) and one without
      rr.qname=d_qname;
    } else {
      rr.qname=rrow[5];
      if (!rr.qname.empty() && rr.qname[rr.qname.length()-1] == '.') {
        rr.qname.erase(rr.qname.length()-1); // Fully qualified, nuke the last .
      } else {
        if (!rr.qname.empty())
          rr.qname += ".";
        rr.qname += d_origin; // Not fully qualified
      }
    }
  
    if (rr.qtype.getCode() == QType::NS || rr.qtype.getCode()==QType::MX || 
          rr.qtype.getCode() == QType::CNAME || rr.qtype.getCode() == QType::PTR) {
      if (!rr.content.empty() && rr.content[rr.content.length()-1] == '.') {
        if (rr.content.length() > 1)
          rr.content.erase(rr.content.length()-1); // Fully qualified, nuke the last .
      } else {
        if (rr.content != ".")
          rr.content += ".";
        rr.content += d_origin;
      }
    }
 
    if (rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV)
      rr.content=rrow[2]+" "+rr.content;

    rr.ttl = atol(rrow[3].c_str());
    if (d_useminimalttl)
      rr.ttl = std::min(rr.ttl, d_minimum);
    rr.domain_id=atol(rrow[4].c_str());
  
    rr.last_modified=0;

    return true;
  }

  try {
    d_query_stmt->reset();
  } catch (SSqlException &e) {
    throw PDNSException("MyDNSBackend unable to lookup "+d_qname+": "+e.txtReason());
  }

  d_query_stmt = NULL;

  return false;
}

class MyDNSFactory : public BackendFactory {

public:
  MyDNSFactory() : BackendFactory("mydns") {}

  void declareArguments(const string &suffix = "") {
    declare(suffix,"dbname","Pdns backend database name to connect to","mydns");
    declare(suffix,"user","Pdns backend user to connect as","powerdns");
    declare(suffix,"host","Pdns backend host to connect to","");
    declare(suffix,"port","Pdns backend host to connect to","");
    declare(suffix,"password","Pdns backend password to connect with","");
    declare(suffix,"socket","Pdns backend socket to connect to","");
    declare(suffix,"rr-table","Name of RR table to use","rr");
    declare(suffix,"soa-table","Name of SOA table to use","soa");
    declare(suffix,"soa-where","Additional WHERE clause for SOA","1 = 1");
    declare(suffix,"rr-where","Additional WHERE clause for RR","1 = 1");
    declare(suffix,"soa-active","Use the active column in the SOA table","yes");
    declare(suffix,"rr-active","Use the active column in the RR table","yes");
    declare(suffix,"use-minimal-ttl","Setting this to 'yes' will make the backend behave like MyDNS on the TTL values. Setting it to 'no' will make it ignore the minimal-ttl of the zone.","yes");
  }

  MyDNSBackend *make(const string &suffix = "") {
    return new MyDNSBackend(suffix);
  }

};

class MyDNSLoader {

public:
  MyDNSLoader() {
    BackendMakers().report(new MyDNSFactory());
    L << Logger::Info << "[mydnsbackend] This is the mydns backend version " VERSION " (" __DATE__ ", " __TIME__ ") reporting" << endl;
  }
};

static MyDNSLoader mydnsloader;
