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
#include "pdns/utility.hh"
#include <map>
#include <unistd.h>
#include <sstream>
#include <string>

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/ssqlite3.hh"
#include "gsqlite3backend.hh"
#include <boost/algorithm/string.hpp>

// Connects to the database.
gSQLite3Backend::gSQLite3Backend( const std::string & mode, const std::string & suffix ) : GSQLBackend( mode, suffix )
{
  try
  {
    SSQLite3 *ptr = new SSQLite3( getArg( "database" ), getArg( "pragma-journal-mode") );
    setDB(ptr);
    if(!getArg("pragma-synchronous").empty()) {
      ptr->execute("PRAGMA synchronous="+getArg("pragma-synchronous"));
    }
    if (mustDo("pragma-foreign-keys")) {
      ptr->execute("PRAGMA foreign_keys = 1");
    }
  }  
  catch( SSqlException & e ) 
  {
    g_log << Logger::Error << mode << ": connection failed: " << e.txtReason() << std::endl;
    throw PDNSException( "Unable to launch " + mode + " connection: " + e.txtReason());
  }

  g_log << Logger::Info << mode << ": connection to '"<<getArg("database")<<"' successful" << std::endl;
}


//! Constructs a gSQLite3Backend
class gSQLite3Factory : public BackendFactory
{
public:
  //! Constructor.
  gSQLite3Factory( const std::string & mode ) : BackendFactory( mode ), d_mode( mode )
  {
  }
  
  //! Declares all needed arguments.
  void declareArguments( const std::string & suffix = "" )
  {
    declare(suffix, "database", "Filename of the SQLite3 database", "powerdns.sqlite");
    declare(suffix, "pragma-synchronous", "Set this to 0 for blazing speed", "");
    declare(suffix, "pragma-foreign-keys", "Enable foreign key constraints", "no" );
    declare(suffix, "pragma-journal-mode", "SQLite3 journal mode", "WAL");

    declare(suffix, "dnssec", "Enable DNSSEC processing","no");

    string record_query = "SELECT content,ttl,prio,type,domain_id,disabled,name,auth FROM records WHERE";

    declare(suffix, "basic-query", "Basic query", record_query+" disabled=0 and type=:qtype and name=:qname");
    declare(suffix, "id-query", "Basic with ID query", record_query+" disabled=0 and type=:qtype and name=:qname and domain_id=:domain_id");
    declare(suffix, "any-query", "Any query", record_query+" disabled=0 and name=:qname");
    declare(suffix, "any-id-query", "Any with ID query", record_query+" disabled=0 and name=:qname and domain_id=:domain_id");

    declare(suffix, "list-query", "AXFR query", record_query+" (disabled=0 OR :include_disabled) and domain_id=:domain_id order by name, type");
    declare(suffix, "list-subzone-query", "Subzone listing", record_query+" disabled=0 and (name=:zone OR name like :wildzone) and domain_id=:domain_id");

    declare(suffix, "remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "delete from records where domain_id=:domain_id and type is null");
    declare(suffix, "delete-empty-non-terminal-query", "delete empty non-terminal from zone", "delete from records where domain_id=:domain_id and name=:qname and type is null");

    declare(suffix, "info-zone-query", "","select id,name,master,last_check,notified_serial,type,account from domains where name=:domain");

    declare(suffix, "info-all-slaves-query", "","select id,name,master,last_check from domains where type='SLAVE'");
    declare(suffix, "supermaster-query", "", "select account from supermasters where ip=:ip and nameserver=:nameserver");
    declare(suffix, "supermaster-name-to-ips", "", "select ip,account from supermasters where nameserver=:nameserver and account=:account");

    declare(suffix, "insert-zone-query", "", "insert into domains (type,name,master,account,last_check,notified_serial) values(:type, :domain, :masters, :account, null, null)");

    declare(suffix, "insert-record-query", "", "insert into records (content,ttl,prio,type,domain_id,disabled,name,ordername,auth) values (:content,:ttl,:priority,:qtype,:domain_id,:disabled,:qname,:ordername,:auth)");
    declare(suffix, "insert-empty-non-terminal-order-query", "insert empty non-terminal in zone", "insert into records (type,domain_id,disabled,name,ordername,auth,ttl,prio,content) values (null,:domain_id,0,:qname,:ordername,:auth,null,null,null)");

    declare(suffix, "get-order-first-query", "DNSSEC Ordering Query, first", "select ordername from records where disabled=0 and domain_id=:domain_id and ordername is not null order by 1 asc limit 1");
    declare(suffix, "get-order-before-query", "DNSSEC Ordering Query, before", "select ordername, name from records where disabled=0 and ordername <= :ordername and domain_id=:domain_id and ordername is not null order by 1 desc limit 1");
    declare(suffix, "get-order-after-query", "DNSSEC Ordering Query, after", "select min(ordername) from records where disabled=0 and ordername > :ordername and domain_id=:domain_id and ordername is not null");
    declare(suffix, "get-order-last-query", "DNSSEC Ordering Query, last", "select ordername, name from records where disabled=0 and ordername != '' and domain_id=:domain_id and ordername is not null order by 1 desc limit 1");

    declare(suffix, "update-ordername-and-auth-query", "DNSSEC update ordername and auth for a qname query", "update records set ordername=:ordername,auth=:auth where domain_id=:domain_id and name=:qname and disabled=0");
    declare(suffix, "update-ordername-and-auth-type-query", "DNSSEC update ordername and auth for a rrset query", "update records set ordername=:ordername,auth=:auth where domain_id=:domain_id and name=:qname and type=:qtype and disabled=0");
    declare(suffix, "nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth for a qname query", "update records set ordername=NULL,auth=:auth where domain_id=:domain_id and name=:qname and disabled=0");
    declare(suffix, "nullify-ordername-and-update-auth-type-query", "DNSSEC nullify ordername and update auth for a rrset query", "update records set ordername=NULL,auth=:auth where domain_id=:domain_id and name=:qname and type=:qtype and disabled=0");

    declare(suffix, "update-master-query", "", "update domains set master=:master where name=:domain");
    declare(suffix, "update-kind-query", "", "update domains set type=:kind where name=:domain");
    declare(suffix, "update-account-query","", "update domains set account=:account where name=:domain");
    declare(suffix, "update-serial-query", "", "update domains set notified_serial=:serial where id=:domain_id");
    declare(suffix, "update-lastcheck-query", "", "update domains set last_check=:last_check where id=:domain_id");
    declare(suffix, "info-all-master-query", "", "select domains.id, domains.name, domains.notified_serial, records.content from records join domains on records.name=domains.name where records.type='SOA' and records.disabled=0 and domains.type='MASTER'");
    declare(suffix, "delete-domain-query","", "delete from domains where name=:domain");
    declare(suffix, "delete-zone-query", "", "delete from records where domain_id=:domain_id");
    declare(suffix, "delete-rrset-query", "", "delete from records where domain_id=:domain_id and name=:qname and type=:qtype");
    declare(suffix, "delete-names-query", "", "delete from records where domain_id=:domain_id and name=:qname");

    declare(suffix, "add-domain-key-query","", "insert into cryptokeys (domain_id, flags, active, content) select id, :flags,:active, :content from domains where name=:domain");
    declare(suffix, "get-last-inserted-key-id-query", "", "select last_insert_rowid()");
    declare(suffix, "list-domain-keys-query","", "select cryptokeys.id, flags, active, content from domains, cryptokeys where cryptokeys.domain_id=domains.id and name=:domain");
    declare(suffix, "get-all-domain-metadata-query","", "select kind,content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name=:domain");
    declare(suffix, "get-domain-metadata-query","", "select content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name=:domain and domainmetadata.kind=:kind");
    declare(suffix, "clear-domain-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name=:domain) and domainmetadata.kind=:kind");
    declare(suffix, "clear-domain-all-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name=:domain)");
    declare(suffix, "set-domain-metadata-query","", "insert into domainmetadata (domain_id, kind, content) select id, :kind, :content from domains where name=:domain");
    declare(suffix, "activate-domain-key-query","", "update cryptokeys set active=1 where domain_id=(select id from domains where name=:domain) and  cryptokeys.id=:key_id");
    declare(suffix, "deactivate-domain-key-query","", "update cryptokeys set active=0 where domain_id=(select id from domains where name=:domain) and  cryptokeys.id=:key_id");
    declare(suffix, "remove-domain-key-query","", "delete from cryptokeys where domain_id=(select id from domains where name=:domain) and cryptokeys.id=:key_id");
    declare(suffix, "clear-domain-all-keys-query","", "delete from cryptokeys where domain_id=(select id from domains where name=:domain)");
    declare(suffix, "get-tsig-key-query","", "select algorithm, secret from tsigkeys where name=:key_name");
    declare(suffix, "set-tsig-key-query","", "replace into tsigkeys (name,algorithm,secret) values(:key_name,:algorithm,:content)");
    declare(suffix, "delete-tsig-key-query","", "delete from tsigkeys where name=:key_name");
    declare(suffix, "get-tsig-keys-query","", "select name,algorithm, secret from tsigkeys");

    declare(suffix, "get-all-domains-query", "Retrieve all domains", "select domains.id, domains.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check, domains.account from domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name WHERE records.disabled=0 OR :include_disabled");

    declare(suffix, "list-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE domain_id=:domain_id");
    declare(suffix, "insert-comment-query", "", "INSERT INTO comments (domain_id, name, type, modified_at, account, comment) VALUES (:domain_id, :qname, :qtype, :modified_at, :account, :content)");
    declare(suffix, "delete-comment-rrset-query", "", "DELETE FROM comments WHERE domain_id=:domain_id AND name=:qname AND type=:qtype");
    declare(suffix, "delete-comments-query", "", "DELETE FROM comments WHERE domain_id=:domain_id");
    declare(suffix, "search-records-query", "", record_query+" name LIKE :value OR content LIKE :value2 LIMIT :limit");
    declare(suffix, "search-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE name LIKE :value OR comment LIKE :value2 LIMIT :limit");
  }

  //! Constructs a new gSQLite3Backend object.
  DNSBackend *make( const string & suffix = "" )
  {
    return new gSQLite3Backend( d_mode, suffix );
  }

private:
  const string d_mode;
};


//! Magic class that is activated when the dynamic library is loaded
class gSQLite3Loader
{
public:
  //! This reports us to the main UeberBackend class
  gSQLite3Loader()
  {
    BackendMakers().report( new gSQLite3Factory( "gsqlite3" ));
    g_log << Logger::Info << "[gsqlite3] This is the gsqlite3 backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};

//! Reports the backendloader to the UeberBackend.
static gSQLite3Loader gsqlite3loader;

