//
// SQLite backend for PowerDNS
// Copyright (C) 2003, Michel Stol <michel@powerdns.com>
// Copyright (C) 2011, PowerDNS.COM BV
//

#include "pdns/utility.hh"
#include <map>
#include <unistd.h>
#include <sstream>
#include <string>

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ueberbackend.hh"
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
    SSQLite3 *ptr = new SSQLite3( getArg( "database" ));
    setDB(ptr);
    if(!getArg("pragma-synchronous").empty()) {
      ptr->execute("PRAGMA synchronous="+getArg("pragma-synchronous"));
    }
    ptr->execute("PRAGMA foreign_keys = 1");
  }  
  catch( SSqlException & e ) 
  {
    L << Logger::Error << mode << ": connection failed: " << e.txtReason() << std::endl;
    throw PDNSException( "Unable to launch " + mode + " connection: " + e.txtReason());
  }

  L << Logger::Info << mode << ": connection to '"<<getArg("database")<<"' successful" << std::endl;
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

    declare(suffix, "dnssec", "Enable DNSSEC processing","no");

    string record_query = "SELECT content,ttl,prio,type,domain_id,disabled,name,auth FROM records WHERE";

    declare(suffix, "basic-query", "Basic query", record_query+" disabled=0 and type=:qtype and name=:qname");
    declare(suffix, "id-query", "Basic with ID query", record_query+" disabled=0 and type=:qtype and name=:qname and domain_id=:domain_id");
    declare(suffix, "any-query", "Any query", record_query+" disabled=0 and name=:qname");
    declare(suffix, "any-id-query", "Any with ID query", record_query+" disabled=0 and name=:qname and domain_id=:domain_id");

    declare(suffix, "list-query", "AXFR query", record_query+" (disabled=0 OR :include_disabled) and domain_id=:domain_id order by name, type");
    declare(suffix, "list-subzone-query", "Subzone listing", record_query+" disabled=0 and (name=:zone OR name like :wildzone) and domain_id=:domain_id");

    declare(suffix, "remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "delete from records where domain_id=:domain_id and type is null");
    declare(suffix, "insert-empty-non-terminal-query", "insert empty non-terminal in zone", "insert into records (domain_id,name,type,disabled,auth) values (:domain_id,:qname,null,0,'1')");
    declare(suffix, "delete-empty-non-terminal-query", "delete empty non-terminal from zone", "delete from records where domain_id=:domain_id and name=:qname and type is null");
    
    declare(suffix, "master-zone-query", "Data", "select master from domains where name=:domain and type='SLAVE'");

    declare(suffix, "info-zone-query", "","select id,name,master,last_check,notified_serial,type from domains where name=:domain");

    declare(suffix, "info-all-slaves-query", "","select id,name,master,last_check,type from domains where type='SLAVE'");
    declare(suffix, "supermaster-query", "", "select account from supermasters where ip=:ip and nameserver=:nameserver");
    declare(suffix, "supermaster-name-to-ips", "", "select ip,account from supermasters where nameserver=:nameserver and account=:account");

    declare(suffix, "insert-zone-query", "", "insert into domains (type,name) values('NATIVE',:domain)");
    declare(suffix, "insert-slave-query", "", "insert into domains (type,name,master,account) values('SLAVE',:domain,:masters,:account)");

    declare(suffix, "insert-record-query", "", "insert into records (content,ttl,prio,type,domain_id,disabled,name,auth) values (:content,:ttl,:priority,:qtype,:domain_id,:disabled,:qname,:auth)");
    declare(suffix, "insert-record-order-query", "", "insert into records (content,ttl,prio,type,domain_id,disabled,name,ordername,auth) values (:content,:ttl,:priority,:qtype,:domain_id,:disabled,:qname,:ordername,:auth)");
    declare(suffix, "insert-ent-query", "insert empty non-terminal in zone", "insert into records (type,domain_id,disabled,name,auth) values (null,:domain_id,0,:qname,:auth)");
    declare(suffix, "insert-ent-order-query", "insert empty non-terminal in zone", "insert into records (type,domain_id,disabled,name,ordername,auth) values (null,:domain_id,0,:qname,:ordername,:auth)");

    declare(suffix, "get-order-first-query", "DNSSEC Ordering Query, first", "select ordername, name from records where disabled=0 and domain_id=:domain_id and ordername is not null order by 1 asc limit 1");
    declare(suffix, "get-order-before-query", "DNSSEC Ordering Query, before", "select ordername, name from records where disabled=0 and ordername <= :ordername and domain_id=:domain_id and ordername is not null order by 1 desc limit 1");
    declare(suffix, "get-order-after-query", "DNSSEC Ordering Query, after", "select min(ordername) from records where disabled=0 and ordername > :ordername and domain_id=:domain_id and ordername is not null");
    declare(suffix, "get-order-last-query", "DNSSEC Ordering Query, last", "select ordername, name from records where disabled=0 and ordername != '' and domain_id=:domain_id and ordername is not null order by 1 desc limit 1");
    declare(suffix, "set-order-and-auth-query", "DNSSEC set ordering query", "update records set ordername=:ordername,auth=:auth where name=:qname and domain_id=:domain_id and disabled=0");
    declare(suffix, "set-auth-on-ds-record-query", "DNSSEC set auth on a DS record", "update records set auth=1 where domain_id=:domain_id and name=:qname and type='DS' and disabled=0");

    declare(suffix, "nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth query", "update records set ordername=NULL,auth=:auth where domain_id=:domain_id and name=:qname and disabled=0");
    declare(suffix, "nullify-ordername-and-auth-query", "DNSSEC nullify ordername and auth query", "update records set ordername=NULL,auth=0 where name=:qname and type=:qtype and domain_id=:domain_id and disabled=0");

    declare(suffix, "update-master-query", "", "update domains set master=:master where name=:domain");
    declare(suffix, "update-kind-query", "", "update domains set type=:kind where name=:domain");
    declare(suffix, "update-serial-query", "", "update domains set notified_serial=:serial where id=:domain_id");
    declare(suffix, "update-lastcheck-query", "", "update domains set last_check=:last_check where id=:domain_id");
    declare(suffix, "zone-lastchange-query", "", "select max(change_date) from records where domain_id=:domain_id");
    declare(suffix, "info-all-master-query", "", "select id,name,master,last_check,notified_serial,type from domains where type='MASTER'");
    declare(suffix, "delete-domain-query","", "delete from domains where name=:domain");
    declare(suffix, "delete-zone-query", "", "delete from records where domain_id=:domain_id");
    declare(suffix, "delete-rrset-query", "", "delete from records where domain_id=:domain_id and name=:qname and type=:qtype");
    declare(suffix, "delete-names-query", "", "delete from records where domain_id=:domain_id and name=:qname");

    declare(suffix, "add-domain-key-query","", "insert into cryptokeys (domain_id, flags, active, content) select id, :flags,:active, :content from domains where name=:domain");
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

    declare(suffix, "get-all-domains-query", "Retrieve all domains", "select domains.id, domains.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check from domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name WHERE records.disabled=0 OR :include_disabled");

    declare(suffix, "list-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE domain_id=:domain_id");
    declare(suffix, "insert-comment-query", "", "INSERT INTO comments (domain_id, name, type, modified_at, account, comment) VALUES (:domain_id, :qname, :qtype, :modified_at, :account, :content)");
    declare(suffix, "delete-comment-rrset-query", "", "DELETE FROM comments WHERE domain_id=:domain_id AND name=:qname AND type=:qtype");
    declare(suffix, "delete-comments-query", "", "DELETE FROM comments WHERE domain_id=:domain_id");
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
    L << Logger::Info << "[gsqlite3] This is the gsqlite3 backend version " VERSION " (" __DATE__ ", " __TIME__ ") reporting" << std::endl;
  }
};

//! Reports the backendloader to the UeberBackend.
static gSQLite3Loader gsqlite3loader;

