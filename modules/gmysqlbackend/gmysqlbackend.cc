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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string>
#include <map>
#include "pdns/namespaces.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "gmysqlbackend.hh"
#include "smysql.hh"
#include <sstream>

gMySQLBackend::gMySQLBackend(const string &mode, const string &suffix)  : GSQLBackend(mode,suffix)
{
  try {
    reconnect();
  }

  catch(SSqlException &e) {
    g_log<<Logger::Error<<mode<<" Connection failed: "<<e.txtReason()<<endl;
    throw PDNSException("Unable to launch "+mode+" connection: "+e.txtReason());
  }
  g_log<<Logger::Info<<mode<<" Connection successful. Connected to database '"<<getArg("dbname")<<"' on '"<<(getArg("host").empty() ? getArg("socket") : getArg("host"))<<"'."<<endl;
}

void gMySQLBackend::reconnect()
{
  setDB(new SMySQL(getArg("dbname"),
                   getArg("host"),
                   getArgAsNum("port"),
                   getArg("socket"),
                   getArg("user"),
                   getArg("password"),
                   getArg("group"),
                   mustDo("innodb-read-committed"),
                   getArgAsNum("timeout"),
                   mustDo("thread-cleanup"),
                   mustDo("ssl")));
}

class gMySQLFactory : public BackendFactory
{
public:
  gMySQLFactory(const string &mode) : BackendFactory(mode),d_mode(mode) {}

  void declareArguments(const string &suffix="")
  {
    declare(suffix,"dbname","Database name to connect to","powerdns");
    declare(suffix,"user","Database backend user to connect as","powerdns");
    declare(suffix,"host","Database backend host to connect to","");
    declare(suffix,"port","Database backend port to connect to","3306");
    declare(suffix,"socket","Database backend socket to connect to","");
    declare(suffix,"password","Database backend password to connect with","");
    declare(suffix,"group", "Database backend MySQL 'group' to connect as", "client");
    declare(suffix,"innodb-read-committed","Use InnoDB READ-COMMITTED transaction isolation level","yes");
    declare(suffix,"timeout", "The timeout in seconds for each attempt to read/write to the server", "10");
    declare(suffix,"thread-cleanup","Explicitly call mysql_thread_end() when threads end","no");
    declare(suffix,"ssl","Send the SSL capability flag to the server","no");

    declare(suffix,"dnssec","Enable DNSSEC processing","no");

    string record_query = "SELECT content,ttl,prio,type,domain_id,disabled,name,auth FROM records WHERE";

    declare(suffix, "basic-query", "Basic query", record_query+" disabled=0 and type=? and name=?");
    declare(suffix, "id-query", "Basic with ID query", record_query+" disabled=0 and type=? and name=? and domain_id=?");
    declare(suffix, "any-query", "Any query", record_query+" disabled=0 and name=?");
    declare(suffix, "any-id-query", "Any with ID query", record_query+" disabled=0 and name=? and domain_id=?");

    declare(suffix, "list-query", "AXFR query", record_query+" (disabled=0 OR ?) and domain_id=? order by name, type");
    declare(suffix, "list-subzone-query", "Subzone listing", record_query+" disabled=0 and (name=? OR name like ?) and domain_id=?");

    declare(suffix, "remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "delete from records where domain_id=? and type is null");
    declare(suffix, "delete-empty-non-terminal-query", "delete empty non-terminal from zone", "delete from records where domain_id=? and name=? and type is null");

    declare(suffix,"info-zone-query","","select id,name,master,last_check,notified_serial,type,account from domains where name=?");

    declare(suffix,"info-all-slaves-query","","select id,name,master,last_check from domains where type='SLAVE'");
    declare(suffix,"supermaster-query","", "select account from supermasters where ip=? and nameserver=?");
    declare(suffix,"supermaster-name-to-ips", "", "select ip,account from supermasters where nameserver=? and account=?");

    declare(suffix,"insert-zone-query","", "insert into domains (type,name,master,account,last_check,notified_serial) values(?,?,?,?,NULL,NULL)");

    declare(suffix, "insert-record-query", "", "insert into records (content,ttl,prio,type,domain_id,disabled,name,ordername,auth) values (?,?,?,?,?,?,?,?,?)");
    declare(suffix, "insert-empty-non-terminal-order-query", "insert empty non-terminal in zone", "insert into records (type,domain_id,disabled,name,ordername,auth,content,ttl,prio) values (null,?,0,?,?,?,NULL,NULL,NULL)");

    declare(suffix, "get-order-first-query", "DNSSEC Ordering Query, first", "select ordername from records where domain_id=? and disabled=0 and ordername is not null order by 1 asc limit 1");
    declare(suffix, "get-order-before-query", "DNSSEC Ordering Query, before", "select ordername, name from records where ordername <= ? and domain_id=? and disabled=0 and ordername is not null order by 1 desc limit 1");
    declare(suffix, "get-order-after-query", "DNSSEC Ordering Query, after", "select ordername from records where ordername > ? and domain_id=? and disabled=0 and ordername is not null order by 1 asc limit 1");
    declare(suffix, "get-order-last-query", "DNSSEC Ordering Query, last", "select ordername, name from records where ordername != '' and domain_id=? and disabled=0 and ordername is not null order by 1 desc limit 1");

    declare(suffix, "update-ordername-and-auth-query", "DNSSEC update ordername and auth for a qname query", "update records set ordername=?,auth=? where domain_id=? and name=? and disabled=0");
    declare(suffix, "update-ordername-and-auth-type-query", "DNSSEC update ordername and auth for a rrset query", "update records set ordername=?,auth=? where domain_id=? and name=? and type=? and disabled=0");
    declare(suffix, "nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth for a qname query", "update records set ordername=NULL,auth=? where domain_id=? and name=? and disabled=0");
    declare(suffix, "nullify-ordername-and-update-auth-type-query", "DNSSEC nullify ordername and update auth for a rrset query", "update records set ordername=NULL,auth=? where domain_id=? and name=? and type=? and disabled=0");

    declare(suffix,"update-master-query","", "update domains set master=? where name=?");
    declare(suffix,"update-kind-query","", "update domains set type=? where name=?");
    declare(suffix,"update-account-query","", "update domains set account=? where name=?");
    declare(suffix,"update-serial-query","", "update domains set notified_serial=? where id=?");
    declare(suffix,"update-lastcheck-query","", "update domains set last_check=? where id=?");
    declare(suffix,"info-all-master-query","", "select d.id, d.name, d.notified_serial, r.content from records r join domains d on r.name=d.name where r.type='SOA' and r.disabled=0 and d.type='MASTER'");
    declare(suffix,"delete-domain-query","", "delete from domains where name=?");
    declare(suffix,"delete-zone-query","", "delete from records where domain_id=?");
    declare(suffix,"delete-rrset-query","","delete from records where domain_id=? and name=? and type=?");
    declare(suffix,"delete-names-query","","delete from records where domain_id=? and name=?");

    declare(suffix,"add-domain-key-query","", "insert into cryptokeys (domain_id, flags, active, content) select id, ?, ?, ? from domains where name=?");
    declare(suffix,"get-last-inserted-key-id-query", "", "select LAST_INSERT_ID()");
    declare(suffix,"list-domain-keys-query","", "select cryptokeys.id, flags, active, content from domains, cryptokeys where cryptokeys.domain_id=domains.id and name=?");
    declare(suffix,"get-all-domain-metadata-query","", "select kind,content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name=?");
    declare(suffix,"get-domain-metadata-query","", "select content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name=? and domainmetadata.kind=?");
    declare(suffix,"clear-domain-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name=?) and domainmetadata.kind=?");
    declare(suffix,"clear-domain-all-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name=?)");
    declare(suffix,"set-domain-metadata-query","", "insert into domainmetadata (domain_id, kind, content) select id, ?, ? from domains where name=?");
    declare(suffix,"activate-domain-key-query","", "update cryptokeys set active=1 where domain_id=(select id from domains where name=?) and  cryptokeys.id=?");
    declare(suffix,"deactivate-domain-key-query","", "update cryptokeys set active=0 where domain_id=(select id from domains where name=?) and  cryptokeys.id=?");
    declare(suffix,"remove-domain-key-query","", "delete from cryptokeys where domain_id=(select id from domains where name=?) and cryptokeys.id=?");
    declare(suffix,"clear-domain-all-keys-query","", "delete from cryptokeys where domain_id=(select id from domains where name=?)");
    declare(suffix,"get-tsig-key-query","", "select algorithm, secret from tsigkeys where name=?");
    declare(suffix,"set-tsig-key-query","", "replace into tsigkeys (name,algorithm,secret) values(?,?,?)");
    declare(suffix,"delete-tsig-key-query","", "delete from tsigkeys where name=?");
    declare(suffix,"get-tsig-keys-query","", "select name,algorithm, secret from tsigkeys");

    declare(suffix, "get-all-domains-query", "Retrieve all domains", "select domains.id, domains.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check, domains.account from domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name WHERE records.disabled=0 OR ?");

    declare(suffix, "list-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE domain_id=?");
    declare(suffix, "insert-comment-query", "", "INSERT INTO comments (domain_id, name, type, modified_at, account, comment) VALUES (?, ?, ?, ?, ?, ?)");
    declare(suffix, "delete-comment-rrset-query", "", "DELETE FROM comments WHERE domain_id=? AND name=? AND type=?");
    declare(suffix, "delete-comments-query", "", "DELETE FROM comments WHERE domain_id=?");
    declare(suffix, "search-records-query", "", record_query+" name LIKE ? OR content LIKE ? LIMIT ?");
    declare(suffix, "search-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE name LIKE ? OR comment LIKE ? LIMIT ?");
  }

  DNSBackend *make(const string &suffix="")
  {
    return new gMySQLBackend(d_mode,suffix);
  }
private:
  const string d_mode;
};


//! Magic class that is activated when the dynamic library is loaded
class gMySQLLoader
{
public:
  //! This reports us to the main UeberBackend class
  gMySQLLoader()
  {
    BackendMakers().report(new gMySQLFactory("gmysql"));
    g_log << Logger::Info << "[gmysqlbackend] This is the gmysql backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};
static gMySQLLoader gmysqlloader;
