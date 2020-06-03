/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 * originally authored by Jonathan Oddy
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

/*
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
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"

#include <modules/gmysqlbackend/smysql.hh>

static string backendName="[MyDNSbackend]";

MyDNSBackend::MyDNSBackend(const string &suffix) {
  setArgPrefix("mydns"+suffix);
 
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
    g_log<<Logger::Error<<backendName<<" Connection failed: "<<e.txtReason()<<endl;
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

  g_log<<Logger::Warning<<backendName<<" Connection successful"<<endl;

  try {

    string domainIdQuery = "SELECT origin, minimum FROM `"+soatable+"` WHERE id = ?";
    string domainNoIdQuery = "SELECT id, origin, minimum FROM `"+soatable+"` WHERE origin = ?";
    string soaQuery = "SELECT id, mbox, serial, ns, refresh, retry, expire, minimum, ttl FROM `"+soatable+"` WHERE origin = ?";
    string allDomainsQuery = "SELECT id, origin, serial FROM `"+soatable+"`";

    if (!soawhere.empty()) {
      domainIdQuery += " AND " + soawhere;  
      domainNoIdQuery += " AND " + soawhere;
      soaQuery += " AND "+soawhere;
      allDomainsQuery += " WHERE "+soawhere;
    }

    d_domainIdQuery_stmt = d_db->prepare(domainIdQuery, 1);
    d_domainNoIdQuery_stmt = d_db->prepare(domainNoIdQuery, 1);
    d_soaQuery_stmt = d_db->prepare(soaQuery, 1);
    d_allDomainsQuery_stmt = d_db->prepare(allDomainsQuery, 0);

    string listQuery = "SELECT type, data, aux, ttl, zone, name FROM `"+rrtable+"` WHERE zone = ?";
    string basicQuery = "SELECT type, data, aux, ttl, zone FROM `"+rrtable+"` WHERE zone = ? AND (name = ? OR name = ?) AND type = ?";
    string anyQuery = "(SELECT type, data, aux, ttl, zone FROM `"+rrtable+"` WHERE zone = ? AND (name = ? OR name = ?)";
 
    if (!rrwhere.empty()) {
      listQuery += " AND "+rrwhere;
      basicQuery += " AND " + rrwhere;
      anyQuery += " AND " + rrwhere;
    }

    d_listQuery_stmt = d_db->prepare(listQuery, 1);
  
    anyQuery += ") UNION (SELECT 'SOA' AS type, CONCAT_WS(' ', ns, mbox,serial,refresh,retry,expire,minimum) AS data, '0' AS aux, ttl, id AS zone FROM `"+soatable+"` WHERE id = ? AND origin = ?";

    if (!soawhere.empty()) {
      anyQuery += " AND "+soawhere;
    }
  
    basicQuery += " ORDER BY type,aux,data";
    anyQuery += ") ORDER BY type,aux,data";
  
    d_basicQuery_stmt = d_db->prepare(basicQuery, 4);
    d_anyQuery_stmt = d_db->prepare(anyQuery, 5);
  } catch (SSqlException &e) {
    g_log<<Logger::Error<<"Cannot prepare statements: " << e.txtReason() <<endl;
    throw PDNSException("Cannot prepare statements: " + e.txtReason());
  }
  // keeps static analyzers happy
  d_query_stmt = nullptr;
}

MyDNSBackend::~MyDNSBackend() {
  d_domainIdQuery_stmt.release();
  d_domainNoIdQuery_stmt.release();
  d_listQuery_stmt.release();
  d_soaQuery_stmt.release();
  d_basicQuery_stmt.release();
  d_anyQuery_stmt.release();
  d_allDomainsQuery_stmt.release();
  delete(d_db);
}


bool MyDNSBackend::list(const DNSName &target, int zoneId, bool include_disabled) {
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
  d_minimum = pdns_stou(d_result[0][1]);

  if (d_result.size()>1) {
    g_log<<Logger::Warning<<backendName<<" Found more than one matching origin for zone ID: "<<zoneId<<endl;
  };

  if (!getSOA(target, d_SOA_for_list)) {
    throw PDNSException("MyDNSBackend unable to get SOA during list for zone "+target.toLogString());
  }

  d_send_SOA_first = true;

  try {
    d_query_stmt = &d_listQuery_stmt;
    (*d_query_stmt)->
      bind("domain_id", zoneId)->
      execute();
  }
  catch (SSqlException &e) {
    throw PDNSException("MyDNSBackend unable to list domain_id "+itoa(zoneId)+": "+e.txtReason());
  }

  d_qname = "";
  return true;
}

bool MyDNSBackend::getSOA(const DNSName& name, SOAData& soadata) {
  string query;
  SSqlStatement::row_t rrow;

  if (name.empty())
    return false;

  try {
    d_soaQuery_stmt->
      bind("origin", name.toString())->
      execute()->
      getResult(d_result)->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("MyDNSBackend unable to get soa for domain "+name.toLogString()+": "+e.txtReason());
  }

  if (d_result.empty()) {
    return false;
  }

  rrow = d_result[0];

  soadata.qname = name;
  soadata.domain_id = pdns_stou(rrow[0]);
  soadata.hostmaster = DNSName(rrow[1]);
  soadata.serial = pdns_stou(rrow[2]);
  soadata.nameserver = DNSName(rrow[3]);
  soadata.refresh = pdns_stou(rrow[4]);
  soadata.retry = pdns_stou(rrow[5]);
  soadata.expire = pdns_stou(rrow[6]);
  soadata.default_ttl = pdns_stou(rrow[7]);
  soadata.ttl = pdns_stou(rrow[8]);
  if (d_useminimalttl) {
    soadata.ttl = std::min(soadata.ttl, soadata.default_ttl);
  }
  soadata.db = this;

  if (d_result.size()>1) {
    g_log<<Logger::Warning<<backendName<<" Found more than one matching zone for: "<<name<<endl;
  };

  return true;
}

void MyDNSBackend::lookup(const QType &qtype, const DNSName &qname, DNSPacket *p, int zoneId) {
  SSqlStatement::row_t rrow;
  bool found = false;

  DNSName sdom(qname);
  d_origin = "";

  if (qname.empty()) {
    return;
  }

  DLOG(g_log<<Logger::Debug<<"MyDNSBackend::lookup(" << qtype.getName() << "," << qname << ",p," << zoneId << ")" << endl);

  if (zoneId < 0) {
    // First off we need to work out what zone we're working with
    // MyDNS records aren't always fully qualified, so we need to work out the zone ID.

    
    do {
      try {
        d_domainNoIdQuery_stmt->
          bind("domain", sdom.toString())->
          execute()->
          getResult(d_result)->
          reset();
      }
      catch (SSqlException &e) {
        throw PDNSException("MyDNSBackend unable to lookup "+qname.toLogString()+": "+e.txtReason());
      }

      if (d_result.empty() == false) {
        rrow = d_result[0];
        zoneId = pdns_stou(rrow[0]);
        d_origin = stripDot(rrow[1]);
        d_minimum = pdns_stou(rrow[2]);
        found = true;
        break;
      }

    } while(sdom.chopOff());

  } else {
    try {
      d_domainIdQuery_stmt->
        bind("domain_id", zoneId)->
        execute()->
        getResult(d_result)->
        reset();
    }
    catch (SSqlException &e) {
      throw PDNSException("MyDNSBackend unable to lookup "+qname.toLogString()+": "+e.txtReason());
    }

    if(d_result.empty()) {
      return; // just return if zone was not found instead of throwing an error
    }

    rrow = d_result[0];

    found = true;
    d_origin = stripDot(rrow[0]);
    d_minimum = pdns_stou(rrow[1]);
  }

  if (found) {

    if (d_result.size()>1) {
      g_log<<Logger::Warning<<backendName<<" Found more than one matching zone for: "+d_origin<<endl;
    };
    // We found the zoneId, so we can work out how to find our rr
    string host;

    // The host part of the query is the name less the origin
    DNSName origin(d_origin);
    host = qname.makeRelative(origin).toStringNoDot();    

    try {

      if (qtype.getCode()==QType::ANY) {
        DLOG(g_log<<Logger::Debug<<"Running d_anyQuery_stmt with " << zoneId << ", " << host << ", " << sdom  << ", " << zoneId <<" , "<< qname << ", " << qtype.getName() << endl);
        d_query_stmt = &d_anyQuery_stmt;
        (*d_query_stmt)->
          bind("domain_id", zoneId)->
          bind("host", host)->
          bind("qname", qname.toString())->
          bind("domain_id", zoneId)-> // this is because positional arguments
          bind("qname2", sdom.toString())->
          execute();
      } else {
        DLOG(g_log<<Logger::Debug<<"Running d_basicQuery_stmt with " << zoneId << ", " << host << ", " << qname << ", " << qtype.getName() << endl);
        d_query_stmt = &d_basicQuery_stmt;
        (*d_query_stmt)->
          bind("domain_id", zoneId)->
          bind("host", host)->
          bind("qname", qname.toString())->
          bind("qtype", qtype.getName())->
          execute();
      }
    }
    catch (SSqlException &e) {
      throw PDNSException("MyDNSBackend unable to lookup "+qname.toLogString()+": "+e.txtReason());
    }

    d_qname = qname.toString();
  }

}

bool MyDNSBackend::get(DNSResourceRecord &rr) {
  if (d_origin.empty()) {
    if (d_query_stmt) {
      try {
        (*d_query_stmt)->reset();
      } catch (SSqlException &e) {
        throw PDNSException("MyDNSBackend unable to lookup "+d_qname+": "+e.txtReason());
      }
      d_query_stmt = NULL;
    }
    // This happens if lookup() couldn't find the zone
    return false;
  }

  SSqlStatement::row_t rrow;

  if (d_send_SOA_first) {
    rr.qname = d_SOA_for_list.qname;
    rr.qtype = QType::SOA;
    rr.content =
      d_SOA_for_list.nameserver.toString() + " " +
      d_SOA_for_list.hostmaster.toString() + " " +
      uitoa(d_SOA_for_list.serial) + " " +
      uitoa(d_SOA_for_list.refresh) + " " +
      uitoa(d_SOA_for_list.retry) + " " +
      uitoa(d_SOA_for_list.expire) + " " +
      uitoa(d_SOA_for_list.default_ttl);
    rr.ttl = d_SOA_for_list.ttl;
    rr.domain_id = d_SOA_for_list.domain_id;
    rr.last_modified = 0;

    d_send_SOA_first = false;
    return true;
  }
  
  if ((*d_query_stmt)->hasNextRow()) {
    try {
      (*d_query_stmt)->nextRow(rrow);
    } catch (SSqlException &e) {
      throw PDNSException("MyDNSBackend unable to lookup "+d_qname+": "+e.txtReason());
    }
    rr.qtype=rrow[0];
    rr.content = rrow[1];
  
    if(!d_qname.empty()) {
      // use this to distinguish between select with 'name' field (list()) and one without
      rr.qname=DNSName(d_qname);
    } else {
      string tmpQname = rrow[5];

      //TODO: Refactor
      if (!tmpQname.empty() && tmpQname[tmpQname.length()-1] == '.') {
        tmpQname.erase(tmpQname.length()-1); // Fully qualified, nuke the last .
      } else {
        if (!tmpQname.empty()) {
          tmpQname += ".";
        }
        tmpQname += d_origin; // Not fully qualified
      }
      rr.qname = DNSName(tmpQname);
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

    rr.ttl = pdns_stou(rrow[3]);
    if (d_useminimalttl)
      rr.ttl = std::min(rr.ttl, d_minimum);
    rr.domain_id=pdns_stou(rrow[4]);
  
    rr.last_modified=0;

    return true;
  }

  try {
    (*d_query_stmt)->reset();
  } catch (SSqlException &e) {
    throw PDNSException("MyDNSBackend unable to lookup "+d_qname+": "+e.txtReason());
  }

  d_query_stmt = NULL;

  return false;
}

void MyDNSBackend::getAllDomains(vector<DomainInfo> *domains, bool include_disabled) {
  /* include_disabled is unfortunately ignored here */
  try {
    d_allDomainsQuery_stmt->
      execute();

    while(d_allDomainsQuery_stmt->hasNextRow()) {
      SSqlStatement::row_t row;
      DomainInfo di;
      d_allDomainsQuery_stmt->nextRow(row);

      di.id = pdns_stou(row[0]);
      di.zone = DNSName(row[1]);
      di.serial = pdns_stou(row[2]);
      di.kind = DomainInfo::Native;
      di.backend = this;

      domains->push_back(di);
    }

    d_allDomainsQuery_stmt->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("MyDNSBackend unable to list all domains: "+e.txtReason());
  }
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

  DNSBackend *make(const string &suffix="") {
    return new MyDNSBackend(suffix);
  }

};

class MyDNSLoader {

public:
  MyDNSLoader() {
    BackendMakers().report(new MyDNSFactory());
    g_log << Logger::Info << "[mydnsbackend] This is the mydns backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};

static MyDNSLoader mydnsloader;
