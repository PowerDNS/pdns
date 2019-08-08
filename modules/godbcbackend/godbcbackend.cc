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
#include "pdns/utility.hh"
#include <map>
#include <sstream>
#include <string>

#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "sodbc.hh"
#include "godbcbackend.hh"


// Connects to the database.
gODBCBackend::gODBCBackend (const std::string & mode, const std::string & suffix)  : GSQLBackend( mode, suffix )
{
  try
  {
    setDB( new SODBC( getArg( "datasource" ), getArg( "username" ), getArg( "password" )));
  }
  catch( SSqlException & e )
  {
    g_log<<Logger::Error<< mode << " Connection failed: " << e.txtReason() << std::endl;
    throw PDNSException( "Unable to launch " + mode + " connection: " + e.txtReason());
  }

  g_log << Logger::Warning << mode << " Connection successful" << std::endl;
}


//! Constructs a gODBCBackend
class gODBCFactory : public BackendFactory
{
public:
  //! Constructor.
  gODBCFactory( const std::string & mode ) : BackendFactory( mode ), d_mode( mode )
  {
  }

  //! Declares all needed arguments.
  void declareArguments( const std::string & suffix = "" )
  {
    declare( suffix, "datasource", "Datasource (DSN) to use","PowerDNS");
    declare( suffix, "username", "User to connect as","powerdns");
    declare( suffix, "password", "Password to connect with","");
    declare(suffix,"dnssec","Enable DNSSEC processing","no");

    string record_query = "SELECT content,ttl,prio,type,domain_id,disabled,name,auth FROM records WHERE";

    declare(suffix, "basic-query", "Basic query", record_query+" disabled=0 and type=? and name=?");
    declare(suffix, "id-query", "Basic with ID query", record_query+" disabled=0 and type=? and name=? and domain_id=?");
    declare(suffix, "any-query", "Any query", record_query+" disabled=0 and name=?");
    declare(suffix, "any-id-query", "Any with ID query", record_query+" disabled=0 and name=? and domain_id=?");

    declare(suffix, "list-query", "AXFR query", record_query+" (disabled=0 OR disabled=?) and domain_id=? order by name, type");
    declare(suffix, "list-subzone-query", "Subzone listing", record_query+" disabled=0 and (name=? OR name like ?) and domain_id=?");

    declare(suffix, "remove-empty-non-terminals-from-zone-query", "remove all empty non-terminals from zone", "delete from records where domain_id=? and type is null");
    declare(suffix, "delete-empty-non-terminal-query", "delete empty non-terminal from zone", "delete from records where domain_id=? and name=? and type is null");

    declare(suffix,"info-zone-query","","select id,name,master,last_check,notified_serial,type,account from domains where name=?");

    declare(suffix,"info-all-slaves-query","","select id,name,master,last_check from domains where type='SLAVE'");
    declare(suffix,"supermaster-query","", "select account from supermasters where ip=? and nameserver=?");
    declare(suffix,"supermaster-name-to-ips", "", "select ip,account from supermasters where nameserver=? and account=?");

    declare(suffix,"insert-zone-query","", "insert into domains (type,name,master,account,last_check,notified_serial) values(?,?,?,?,null,null)");

    declare(suffix, "insert-record-query", "", "insert into records (content,ttl,prio,type,domain_id,disabled,name,ordername,auth) values (?,?,?,?,?,?,?,convert(varbinary(255),?),?)");
    declare(suffix, "insert-empty-non-terminal-order-query", "insert empty non-terminal in zone", "insert into records (type,domain_id,disabled,name,ordername,auth,ttl,prio,content) values (null,?,0,?,convert(varbinary(255),?),?,null,null,null)");

    declare(suffix, "get-order-first-query", "DNSSEC Ordering Query, first", "select top 1 convert(varchar(255), ordername) from records where domain_id=? and disabled=0 and ordername is not null order by 1 asc");
    declare(suffix, "get-order-before-query", "DNSSEC Ordering Query, before", "select top 1 convert(varchar(255), ordername), name from records where ordername <= convert(varbinary(255),?) and domain_id=? and disabled=0 and ordername is not null order by 1 desc");
    declare(suffix, "get-order-after-query", "DNSSEC Ordering Query, after", "select convert(varchar(255), min(ordername)) from records where ordername > convert(varbinary(255),?) and domain_id=? and disabled=0 and ordername is not null");
    declare(suffix, "get-order-last-query", "DNSSEC Ordering Query, last", "select top 1 convert(varchar(255), ordername), name from records where ordername != convert(varbinary(255),'') and domain_id=? and disabled=0 and ordername is not null order by 1 desc");

    declare(suffix, "update-ordername-and-auth-query", "DNSSEC update ordername and auth for a qname query", "update records set ordername=convert(varbinary(255),?),auth=? where domain_id=? and name=? and disabled=0");
    declare(suffix, "update-ordername-and-auth-type-query", "DNSSEC update ordername and auth for a rrset query", "update records set ordername=convert(varbinary(255),?),auth=? where domain_id=? and name=? and type=? and disabled=0");
    declare(suffix, "nullify-ordername-and-update-auth-query", "DNSSEC nullify ordername and update auth for a qname query", "update records set ordername=NULL,auth=? where domain_id=? and name=? and disabled=0");
    declare(suffix, "nullify-ordername-and-update-auth-type-query", "DNSSEC nullify ordername and update auth for a rrset query", "update records set ordername=NULL,auth=? where domain_id=? and name=? and type=? and disabled=0");

    declare(suffix,"update-master-query","", "update domains set master=? where name=?");
    declare(suffix,"update-kind-query","", "update domains set type=? where name=?");
    declare(suffix,"update-account-query","", "update domains set account=? where name=?");
    declare(suffix,"update-serial-query","", "update domains set notified_serial=? where id=?");
    declare(suffix,"update-lastcheck-query","", "update domains set last_check=? where id=?");
    declare(suffix,"info-all-master-query","", "select domains.id, domains.name, domains.notified_serial, records.content from records join domains on records.name=domains.name where records.type='SOA' and records.disabled=0 and domains.type='MASTER'");
    declare(suffix,"delete-domain-query","", "delete from domains where name=?");
    declare(suffix,"delete-zone-query","", "delete from records where domain_id=?");
    declare(suffix,"delete-rrset-query","","delete from records where domain_id=? and name=? and type=?");
    declare(suffix,"delete-names-query","","delete from records where domain_id=? and name=?");

    declare(suffix,"add-domain-key-query","", "insert into cryptokeys (domain_id, flags, active, content) select id, ?, ?, ? from domains where name=?");
    declare(suffix,"get-last-inserted-key-id-query", "", "select ident_current('cryptokeys')");
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
    /* FIXME: set-tsig-key-query only works on an empty database right now. For MySQL we use the "update into" statement..
       According to the internet, we need to construct a pretty hefty "merge" query: https://msdn.microsoft.com/en-us/library/bb510625.aspx
    */
    declare(suffix,"set-tsig-key-query","", "insert into tsigkeys (name,algorithm,secret) values(?,?,?)");
    declare(suffix,"delete-tsig-key-query","", "delete from tsigkeys where name=?");
    declare(suffix,"get-tsig-keys-query","", "select name,algorithm, secret from tsigkeys");

    declare(suffix, "get-all-domains-query", "Retrieve all domains", "select domains.id, domains.name, records.content, domains.type, domains.master, domains.notified_serial, domains.last_check, domains.account from domains LEFT JOIN records ON records.domain_id=domains.id AND records.type='SOA' AND records.name=domains.name WHERE records.disabled=0 OR records.disabled=?");

    declare(suffix, "list-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE domain_id=?");
    declare(suffix, "insert-comment-query", "", "INSERT INTO comments (domain_id, name, type, modified_at, account, comment) VALUES (?, ?, ?, ?, ?, ?)");
    declare(suffix, "delete-comment-rrset-query", "", "DELETE FROM comments WHERE domain_id=? AND name=? AND type=?");
    declare(suffix, "delete-comments-query", "", "DELETE FROM comments WHERE domain_id=?");
    declare(suffix, "search-records-query", "", record_query+" name LIKE ? OR content LIKE ? LIMIT ?");
    declare(suffix, "search-comments-query", "", "SELECT domain_id,name,type,modified_at,account,comment FROM comments WHERE name LIKE ? OR comment LIKE ? LIMIT ?");
  }

  //! Constructs a new gODBCBackend object.
  DNSBackend *make(const string & suffix = "" )
  {
    return new gODBCBackend( d_mode, suffix );
  }

private:
  const string d_mode;
};


//! Magic class that is activated when the dynamic library is loaded
class gODBCLoader
{
public:
  //! This reports us to the main UeberBackend class
  gODBCLoader()
  {
    BackendMakers().report( new gODBCFactory("godbc"));
    g_log<<Logger::Warning << "This is module godbcbackend reporting" << std::endl;
  }
};

//! Reports the backendloader to the UeberBackend.
static gODBCLoader godbcloader;
