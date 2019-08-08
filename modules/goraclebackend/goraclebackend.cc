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
#include "pdns/lock.hh"
#include "goraclebackend.hh"
#include "soracle.hh"
#include <sstream>

static OCIEnv* d_environmentHandle = 0;
static pthread_mutex_t s_goracle_lock=PTHREAD_MUTEX_INITIALIZER;

gOracleBackend::gOracleBackend(const string &mode, const string &suffix)  : GSQLBackend(mode, suffix)
{
  Lock gl(&s_goracle_lock);
  if (d_environmentHandle == 0) {
    setenv("ORACLE_HOME", getArg("home").c_str(), 1);
    setenv("ORACLE_SID", getArg("sid").c_str(), 1);
    setenv("NLS_LANG", getArg("nls-lang").c_str(), 1);
  
    int err = OCIEnvCreate(&d_environmentHandle, OCI_THREADED, NULL, NULL, NULL, NULL, 0, NULL); 

    if (err) {
      throw PDNSException("OCIEnvCreate failed");
    }
  }

  try {
    // set Oracle environment variables
    setDB(new SOracle(getArg("tnsname"),
                      getArg("user"),
                      getArg("password"), 
                      mustDo("release-statements"),
                      d_environmentHandle));
  }

  catch (SSqlException &e) {
    g_log<<Logger::Error << mode << " Connection failed: " << e.txtReason() << endl;
    throw PDNSException("Unable to launch " + mode + " connection: " + e.txtReason());
  }
  g_log<<Logger::Info << mode << " Connection successful" << endl;
}

class gOracleFactory : public BackendFactory
{
public:
  gOracleFactory(const string &mode) : BackendFactory(mode), d_mode(mode) {}

  void declareArguments(const string &suffix="") {
    declare(suffix,"home", "Oracle home path", "");
    declare(suffix,"sid", "Oracle sid", "XE");
    declare(suffix,"nls-lang", "Oracle language", "AMERICAN_AMERICA.AL32UTF8");

    declare(suffix,"tnsname","Generic Oracle backend TNSNAME to connect to","powerdns");
    declare(suffix,"user","Database backend user to connect as","powerdns");
    declare(suffix,"password","Pdns backend password to connect with","");

    declare(suffix,"dnssec","Enable DNSSEC processing","no");
    declare(suffix,"release-statements","Release statements between executions, uses less resources","no");

    string record_query = "SELECT content,ttl,prio,type,domain_id,disabled,name,auth FROM records WHERE";

    declare(suffix, "basic-query", "Basic query", record_query+" disabled=0 and type=:qtype and name=:qname");
    declare(suffix, "id-query", "Basic with ID query", record_query+" disabled=0 and type=:qtype and name=:qname and domain_id=:domain_id");
    declare(suffix, "any-query", "Any query", record_query+" disabled=0 and name=:qname");
    declare(suffix, "any-id-query", "Any with ID query", record_query+" disabled=0 and name=:qname and domain_id=:domain_id");

    declare(suffix, "list-query", "AXFR query", record_query+" (disabled=0 OR disabled=:include_disabled) and domain_id=:domain_id order by name, type");
    declare(suffix, "list-subzone-query", "Subzone listing", record_query+" disabled=0 and (name=:zone OR name like :wildzone) and domain_id=:domain_id");

    declare(suffix, "remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "delete from records where domain_id=:domain_id and type is null");
    declare(suffix, "delete-empty-non-terminal-query", "delete empty non-terminal from zone", "delete from records where domain_id=:domain_id and name=:qname and type is null");

    declare(suffix, "info-zone-query", "","select id,name,master,last_check,notified_serial,type,account from domains where name=:domain");

    declare(suffix, "info-all-slaves-query", "","select id,name,master,last_check from domains where type='SLAVE'");
    declare(suffix, "supermaster-query", "", "select account from supermasters where ip=:ip and nameserver=:nameserver");
    declare(suffix, "supermaster-name-to-ips", "", "select ip,account from supermasters where nameserver=:nameserver and account=:account");
    declare(suffix, "insert-zone-query", "", "insert into domains (id,type,name,master,account,last_check_notified_serial) values(domains_id_sequence.nextval,:type,:domain,:masters,:account, null, null)");
    declare(suffix, "insert-record-query", "", "insert into records (id,content,ttl,prio,type,domain_id,disabled,name,ordername,auth) values (records_id_sequence.nextval,:content,:ttl,:priority,:qtype,:domain_id,:disabled,:qname,:ordername || ' ',:auth)");
    declare(suffix, "insert-empty-non-terminal-order-query", "insert empty non-terminal in zone", "insert into records (id,type,domain_id,disabled,name,ordername,auth,ttl,prio,content) values (records_id_sequence.nextval,null,:domain_id,0,:qname,:ordername,:auth,null,null,null)");

    declare(suffix, "get-order-first-query", "DNSSEC Ordering Query, first", "select * FROM (select trim(ordername) from records where disabled=0 and domain_id=:domain_id and ordername is not null order by ordername asc) where rownum=1");
    declare(suffix, "get-order-before-query", "DNSSEC Ordering Query, before", "select * FROM (select trim(ordername), name from records where disabled=0 and ordername <= :ordername || ' ' and domain_id=:domain_id and ordername is not null order by ordername desc) where rownum=1");
    declare(suffix, "get-order-after-query", "DNSSEC Ordering Query, after", "select trim(min(ordername)) from records where disabled=0 and ordername > :ordername || ' ' and domain_id=:domain_id and ordername is not null");
    declare(suffix, "get-order-last-query", "DNSSEC Ordering Query, last", "select * from (select trim(ordername), name from records where disabled=0 and ordername != ' ' and domain_id=:domain_id and ordername is not null order by ordername desc) where rownum=1");

    declare(suffix, "update-ordername-and-auth-query", "DNSSEC update ordername and auth for a qname query", "update records set ordername=:ordername || ' ',auth=:auth where domain_id=:domain_id and name=:qname and disabled=0");
    declare(suffix, "update-ordername-and-auth-type-query", "DNSSEC update ordername and auth for a rrset query", "update records set ordername=:ordername || ' ',auth=:auth where domain_id=:domain_id and name=:qname and type=:qtype and disabled=0");
    declare(suffix, "nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth for a qname query", "update records set ordername=NULL,auth=:auth where domain_id=:domain_id and name=:qname and disabled=0");
    declare(suffix, "nullify-ordername-and-update-auth-type-query", "DNSSEC nullify ordername and update auth for a rrset query", "update records set ordername=NULL,auth=:auth where domain_id=:domain_id and name=:qname and type=:qtype and disabled=0");

    declare(suffix, "update-master-query", "", "update domains set master=:master where name=:domain");
    declare(suffix, "update-kind-query", "", "update domains set type=:kind where name=:domain");
    declare(suffix, "update-account-query", "", "update domains set account=:account where name=:domain");
    declare(suffix, "update-serial-query", "", "update domains set notified_serial=:serial where id=:domain_id");
    declare(suffix, "update-lastcheck-query", "", "update domains set last_check=:last_check where id=:domain_id");
    declare(suffix, "info-all-master-query", "", "select id,name,master,last_check,notified_serial,type from domains where type='MASTER'");
    declare(suffix, "delete-domain-query","", "delete from domains where name=:domain");
    declare(suffix, "delete-zone-query", "", "delete from records where domain_id=:domain_id");
    declare(suffix, "delete-rrset-query", "", "delete from records where domain_id=:domain_id and name=:qname and type=:qtype");
    declare(suffix, "delete-names-query", "", "delete from records where domain_id=:domain_id and name=:qname");

    declare(suffix, "add-domain-key-query","", "insert into cryptokeys (id, domain_id, flags, active, content) select cryptokeys_id_sequence.nextval, id, :flags,:active, :content from domains where name=:domain");
    declare(suffix, "get-last-inserted-key-id-query", "", "select cryptokeys_id_sequence.currval from DUAL");
    declare(suffix, "list-domain-keys-query","", "select cryptokeys.id, flags, active, content from domains, cryptokeys where cryptokeys.domain_id=domains.id and name=:domain");
    declare(suffix, "get-all-domain-metadata-query","", "select kind,content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name=:domain");
    declare(suffix, "get-domain-metadata-query","", "select content from domains, domainmetadata where domainmetadata.domain_id=domains.id and name=:domain and domainmetadata.kind=:kind");
    declare(suffix, "clear-domain-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name=:domain) and domainmetadata.kind=:kind");
    declare(suffix, "clear-domain-all-metadata-query","", "delete from domainmetadata where domain_id=(select id from domains where name=:domain)");
    declare(suffix, "set-domain-metadata-query","", "insert into domainmetadata (id, domain_id, kind, content) select domainmetadata_id_sequence.nextval, id, :kind, :content from domains where name=:domain");
    declare(suffix, "activate-domain-key-query","", "update cryptokeys set active=1 where domain_id=(select id from domains where name=:domain) and  cryptokeys.id=:key_id");
    declare(suffix, "deactivate-domain-key-query","", "update cryptokeys set active=0 where domain_id=(select id from domains where name=:domain) and  cryptokeys.id=:key_id");
    declare(suffix, "remove-domain-key-query","", "delete from cryptokeys where domain_id=(select id from domains where name=:domain) and cryptokeys.id=:key_id");
    declare(suffix, "clear-domain-all-keys-query","", "delete from cryptokeys where domain_id=(select id from domains where name=:domain)");
    declare(suffix, "get-tsig-key-query","", "select algorithm, secret from tsigkeys where name=:key_name");
    declare(suffix, "set-tsig-key-query","", "merge into tsigkeys tk using dual on (name = :key_name and algorithm = :algorithm) when not matched then insert (id, name, algorithm, secret) values(tsigkeys_id_sequence.nextval, :key_name, :algorithm, :content) when matched then update set secret = :content");
    declare(suffix, "delete-tsig-key-query","", "delete from tsigkeys where name=:key_name");
    declare(suffix, "get-tsig-keys-query","", "select name,algorithm, secret from tsigkeys");

    declare(suffix, "get-all-domains-query", "Retrieve all domains", "select domains.id, domains.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check, domain.account from domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name WHERE records.disabled=0 OR records.disabled=:include_disabled");

    declare(suffix, "list-comments-query", "", "SELECT domain_id,name,type,modified_at,account,\"comment\" FROM comments WHERE domain_id=:domain_id");
    declare(suffix, "insert-comment-query", "", "INSERT INTO comments (id, domain_id, name, type, modified_at, account, \"comment\") VALUES (comments_id_sequence.nextval, :domain_id, :qname, :qtype, :modified_at, :account, :content)");
    declare(suffix, "delete-comment-rrset-query", "", "DELETE FROM comments WHERE domain_id=:domain_id AND name=:qname AND type=:qtype");
    declare(suffix, "delete-comments-query", "", "DELETE FROM comments WHERE domain_id=:domain_id");
    declare(suffix, "search-records-query", "", record_query+" name LIKE :value OR content LIKE :value2 LIMIT :limit");
    declare(suffix, "search-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE name LIKE :value OR comment LIKE :value2 LIMIT :limit");

  }

  DNSBackend* make(const string &suffix="") {
    return new gOracleBackend(d_mode,suffix);
  }

private:
  const string d_mode;
};


//! Magic class that is activated when the dynamic library is loaded
class gOracleLoader
{
public:
  //! This reports us to the main UeberBackend class
  gOracleLoader() {
    BackendMakers().report(new gOracleFactory("goracle"));
    g_log << Logger::Info << "[goraclebackend] This is the goracle backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }
};

//! Reports the backendloader to the UeberBackend.
static gOracleLoader goracleloader;
