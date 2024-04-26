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
#include "gpgsqlbackend.hh"
#include "spgsql.hh"
#include <sys/time.h>
#include <sstream>

gPgSQLBackend::gPgSQLBackend(const string& mode, const string& suffix) :
  GSQLBackend(mode, suffix)
{
  try {
    setDB(std::unique_ptr<SSql>(new SPgSQL(getArg("dbname"),
                                           getArg("host"),
                                           getArg("port"),
                                           getArg("user"),
                                           getArg("password"),
                                           getArg("extra-connection-parameters"),
                                           mustDo("prepared-statements"))));
  }

  catch (SSqlException& e) {
    g_log << Logger::Error << mode << " Connection failed: " << e.txtReason() << endl;
    throw PDNSException("Unable to launch " + mode + " connection: " + e.txtReason());
  }
  allocateStatements();
  g_log << Logger::Info << mode << " Connection successful. Connected to database '" << getArg("dbname") << "' on '" << getArg("host") << "'." << endl;
}

void gPgSQLBackend::reconnect()
{
  freeStatements();

  if (d_db) {
    d_db->reconnect();

    allocateStatements();
  }
}

bool gPgSQLBackend::inTransaction()
{
  const auto* db = dynamic_cast<SPgSQL*>(d_db.get());
  if (db) {
    return db->in_trx();
  }
  return false;
}

class gPgSQLFactory : public BackendFactory
{
public:
  gPgSQLFactory(const string& mode) :
    BackendFactory(mode), d_mode(mode) {}

  void declareArguments(const string& suffix = "") override
  {
    declare(suffix, "dbname", "Backend database name to connect to", "");
    declare(suffix, "user", "Database backend user to connect as", "");
    declare(suffix, "host", "Database backend host to connect to", "");
    declare(suffix, "port", "Database backend port to connect to", "");
    declare(suffix, "password", "Database backend password to connect with", "");
    declare(suffix, "extra-connection-parameters", "Extra parameters to add to connection string", "");
    declare(suffix, "prepared-statements", "Use prepared statements instead of parameterized queries", "yes");

    declare(suffix, "dnssec", "Enable DNSSEC processing", "no");

    string record_query = "SELECT content,ttl,prio,type,domain_id,disabled::int,name,auth::int FROM records WHERE";

    declare(suffix, "basic-query", "Basic query", record_query + " disabled=false and type=$1 and name=$2");
    declare(suffix, "id-query", "Basic with ID query", record_query + " disabled=false and type=$1 and name=$2 and domain_id=$3");
    declare(suffix, "any-query", "Any query", record_query + " disabled=false and name=$1");
    declare(suffix, "any-id-query", "Any with ID query", record_query + " disabled=false and name=$1 and domain_id=$2");

    declare(suffix, "list-query", "AXFR query", "SELECT content,ttl,prio,type,domain_id,disabled::int,name,auth::int,ordername FROM records WHERE (disabled=false OR $1) and domain_id=$2 order by name, type");
    declare(suffix, "list-subzone-query", "Subzone listing", record_query + " disabled=false and (name=$1 OR name like $2) and domain_id=$3");

    declare(suffix, "remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "delete from records where domain_id=$1 and type is null");
    declare(suffix, "delete-empty-non-terminal-query", "delete empty non-terminal from zone", "delete from records where domain_id=$1 and name=$2 and type is null");

    declare(suffix, "info-zone-query", "", "select id,name,master,last_check,notified_serial,type,options,catalog,account from domains where name=$1");

    declare(suffix, "info-all-secondaries-query", "", "select domains.id, domains.name, domains.type, domains.master, domains.last_check, records.content from domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name where domains.type in ('SLAVE', 'CONSUMER')");
    declare(suffix, "autoprimary-query", "", "select account from supermasters where ip=$1 and nameserver=$2");
    declare(suffix, "autoprimary-name-to-ips", "", "select ip,account from supermasters where nameserver=$1 and account=$2");
    declare(suffix, "autoprimary-add", "", "insert into supermasters (ip, nameserver, account) values ($1,$2,$3)");
    declare(suffix, "autoprimary-remove", "", "delete from supermasters where ip = $1 and nameserver = $2");
    declare(suffix, "list-autoprimaries", "", "select ip,nameserver,account from supermasters");

    declare(suffix, "insert-zone-query", "", "insert into domains (type,name,master,account,last_check, notified_serial) values($1,$2,$3,$4,null,null)");

    declare(suffix, "insert-record-query", "", "insert into records (content,ttl,prio,type,domain_id,disabled,name,ordername,auth) values ($1,$2,$3,$4,$5,$6,$7,$8,$9)");
    declare(suffix, "insert-empty-non-terminal-order-query", "insert empty non-terminal in zone", "insert into records (type,domain_id,disabled,name,ordername,auth,ttl,prio,content) values (null,$1,false,$2,$3,$4,null,null,null)");

    declare(suffix, "get-order-first-query", "DNSSEC Ordering Query, first", "select ordername from records where disabled=false and domain_id=$1 and ordername is not null order by 1 using ~<~ limit 1");
    declare(suffix, "get-order-before-query", "DNSSEC Ordering Query, before", "select ordername, name from records where disabled=false and ordername ~<=~ $1 and domain_id=$2 and ordername is not null order by 1 using ~>~ limit 1");
    declare(suffix, "get-order-after-query", "DNSSEC Ordering Query, after", "select ordername from records where disabled=false and ordername ~>~ $1 and domain_id=$2 and ordername is not null order by 1 using ~<~ limit 1");
    declare(suffix, "get-order-last-query", "DNSSEC Ordering Query, last", "select ordername, name from records where disabled=false and ordername != '' and domain_id=$1 and ordername is not null order by 1 using ~>~ limit 1");

    declare(suffix, "update-ordername-and-auth-query", "DNSSEC update ordername and auth for a qname query", "update records set ordername=$1,auth=$2 where domain_id=$3 and name=$4 and disabled=false");
    declare(suffix, "update-ordername-and-auth-type-query", "DNSSEC update ordername and auth for a rrset query", "update records set ordername=$1,auth=$2 where domain_id=$3 and name=$4 and type=$5 and disabled=false");
    declare(suffix, "nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth for a qname query", "update records set ordername=NULL,auth=$1 where domain_id=$2 and name=$3 and disabled=false");
    declare(suffix, "nullify-ordername-and-update-auth-type-query", "DNSSEC nullify ordername and update auth for a rrset query", "update records set ordername=NULL,auth=$1 where domain_id=$2 and name=$3 and type=$4 and disabled=false");

    declare(suffix, "update-primary-query", "", "update domains set master=$1 where name=$2");
    declare(suffix, "update-kind-query", "", "update domains set type=$1 where name=$2");
    declare(suffix, "update-options-query", "", "update domains set options=$1 where name=$2");
    declare(suffix, "update-catalog-query", "", "update domains set catalog=$1 where name=$2");
    declare(suffix, "update-account-query", "", "update domains set account=$1 where name=$2");
    declare(suffix, "update-serial-query", "", "update domains set notified_serial=$1 where id=$2");
    declare(suffix, "update-lastcheck-query", "", "update domains set last_check=$1 where id=$2");
    declare(suffix, "info-all-primary-query", "", "select domains.id, domains.name, domains.type, domains.notified_serial, domains.options, domains.catalog, records.content from records join domains on records.domain_id=domains.id and records.name=domains.name where records.type='SOA' and records.disabled=false and domains.type in ('MASTER', 'PRODUCER')");
    declare(suffix, "info-producer-members-query", "", "select domains.id, domains.name, domains.options from records join domains on records.domain_id=domains.id and records.name=domains.name where domains.type='MASTER' and domains.catalog=$1 and records.type='SOA' and records.disabled=false");
    declare(suffix, "info-consumer-members-query", "", "select id, name, options, master from domains where type='SLAVE' and catalog=$1");
    declare(suffix, "delete-domain-query", "", "delete from domains where name=$1");
    declare(suffix, "delete-zone-query", "", "delete from records where domain_id=$1");
    declare(suffix, "delete-rrset-query", "", "delete from records where domain_id=$1 and name=$2 and type=$3");
    declare(suffix, "delete-names-query", "", "delete from records where domain_id=$1 and name=$2");

    declare(suffix, "add-domain-key-query", "", "insert into cryptokeys (domain_id, flags, active, published, content) select id, $1, $2, $3, $4 from domains where name=$5 returning id");
    declare(suffix, "get-last-inserted-key-id-query", "", "select pdns_bug_should_not_get_here('https://github.com/PowerDNS/pdns/pull/10392'), 1/0");
    declare(suffix, "list-domain-keys-query", "", "select cryptokeys.id, flags, case when active then 1 else 0 end as active, case when published then 1 else 0 end as published, content from domains, cryptokeys where cryptokeys.domain_id=domains.id and name=$1");
    declare(suffix, "get-all-domain-metadata-query", "", "select kind,content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name=$1");
    declare(suffix, "get-domain-metadata-query", "", "select content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name=$1 and domainmetadata.kind=$2");
    declare(suffix, "clear-domain-metadata-query", "", "delete from domainmetadata where domain_id=(select id from domains where name=$1) and domainmetadata.kind=$2");
    declare(suffix, "clear-domain-all-metadata-query", "", "delete from domainmetadata where domain_id=(select id from domains where name=$1)");
    declare(suffix, "set-domain-metadata-query", "", "insert into domainmetadata (domain_id, kind, content) select id, $1, $2 from domains where name=$3");
    declare(suffix, "activate-domain-key-query", "", "update cryptokeys set active=true where domain_id=(select id from domains where name=$1) and  cryptokeys.id=$2");
    declare(suffix, "deactivate-domain-key-query", "", "update cryptokeys set active=false where domain_id=(select id from domains where name=$1) and  cryptokeys.id=$2");
    declare(suffix, "publish-domain-key-query", "", "update cryptokeys set published=true where domain_id=(select id from domains where name=$1) and  cryptokeys.id=$2");
    declare(suffix, "unpublish-domain-key-query", "", "update cryptokeys set published=false where domain_id=(select id from domains where name=$1) and  cryptokeys.id=$2");
    declare(suffix, "remove-domain-key-query", "", "delete from cryptokeys where domain_id=(select id from domains where name=$1) and cryptokeys.id=$2");
    declare(suffix, "clear-domain-all-keys-query", "", "delete from cryptokeys where domain_id=(select id from domains where name=$1)");
    declare(suffix, "get-tsig-key-query", "", "select algorithm, secret from tsigkeys where name=$1");
    declare(suffix, "set-tsig-key-query", "", "insert into tsigkeys (name,algorithm,secret) values($1,$2,$3)");
    declare(suffix, "delete-tsig-key-query", "", "delete from tsigkeys where name=$1");
    declare(suffix, "get-tsig-keys-query", "", "select name,algorithm, secret from tsigkeys");

    declare(suffix, "get-all-domains-query", "Retrieve all domains", "select domains.id, domains.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check, domains.account, domains.catalog from domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name WHERE records.disabled=false OR $1");

    declare(suffix, "list-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE domain_id=$1");
    declare(suffix, "insert-comment-query", "", "INSERT INTO comments (domain_id, name, type, modified_at, account, comment) VALUES ($1, $2, $3, $4, $5, $6)");
    declare(suffix, "delete-comment-rrset-query", "", "DELETE FROM comments WHERE domain_id=$1 AND name=$2 AND type=$3");
    declare(suffix, "delete-comments-query", "", "DELETE FROM comments WHERE domain_id=$1");
    declare(suffix, "search-records-query", "", record_query + " name ILIKE $1 OR content ILIKE $2 LIMIT $3");
    declare(suffix, "search-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE name ILIKE $1 OR comment ILIKE $2 LIMIT $3");
  }

  DNSBackend* make(const string& suffix = "") override
  {
    return new gPgSQLBackend(d_mode, suffix);
  }

private:
  const string d_mode;
};

//! Magic class that is activated when the dynamic library is loaded
class gPgSQLLoader
{
public:
  //! This reports us to the main UeberBackend class
  gPgSQLLoader()
  {
    BackendMakers().report(std::make_unique<gPgSQLFactory>("gpgsql"));
    g_log << Logger::Info << "[gpgsqlbackend] This is the gpgsql backend version " VERSION
#ifndef REPRODUCIBLE
          << " (" __DATE__ " " __TIME__ ")"
#endif
          << " reporting" << endl;
  }
};
static gPgSQLLoader gpgsqlloader;
