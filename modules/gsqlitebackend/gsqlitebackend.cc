
//
// SQLite backend for PowerDNS
// Copyright (C) 2003, Michel Stol <michel@powerdns.com>
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
#include "pdns/ahuexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "ssqlite.hh"
#include "gsqlitebackend.hh"
#include <boost/algorithm/string.hpp>

// Connects to the database.
gSQLiteBackend::gSQLiteBackend( const std::string & mode, const std::string & suffix ) : GSQLBackend( mode, suffix )
{
  try 
  {
    setDB( new SSQLite( getArg( "database" )));    
  }  
  catch( SSqlException & e ) 
  {
    L << Logger::Error << mode << ": connection failed: " << e.txtReason() << std::endl;
    throw AhuException( "Unable to launch " + mode + " connection: " + e.txtReason());
  }

  L << Logger::Warning << mode << ": connection to '"<<getArg("database")<<"' successful" << std::endl;
}


//! Constructs a gSQLiteBackend
class gSQLiteFactory : public BackendFactory
{
public:
  //! Constructor.
  gSQLiteFactory( const std::string & mode ) : BackendFactory( mode ), d_mode( mode )
  {
  }
  
  //! Declares all needed arguments.
  void declareArguments( const std::string & suffix = "" )
  {
    declare( suffix, "database", "Filename of the SQLite database", "powerdns.sqlite" );
    
    declare( suffix, "basic-query", "Basic query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s'");
    declare( suffix, "id-query", "Basic with ID query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s' and domain_id=%d");
    declare( suffix, "wildcard-query", "Wildcard query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s'");
    declare( suffix, "wildcard-id-query", "Wildcard with ID query","select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s' and domain_id=%d");

    declare( suffix, "any-query", "Any query","select content,ttl,prio,type,domain_id,name from records where name='%s'");
    declare( suffix, "any-id-query", "Any with ID query","select content,ttl,prio,type,domain_id,name from records where name='%s' and domain_id=%d");
    declare( suffix, "wildcard-any-query", "Wildcard ANY query","select content,ttl,prio,type,domain_id,name from records where name like '%s'");
    declare( suffix, "wildcard-any-id-query", "Wildcard ANY with ID query","select content,ttl,prio,type,domain_id,name from records where name like '%s' and domain_id=%d");

    declare( suffix, "list-query", "AXFR query", "select content,ttl,prio,type,domain_id,name from records where domain_id=%d");
    declare( suffix, "master-zone-query", "Data", "select master from domains where name='%s' and type='SLAVE'");

    declare( suffix, "info-zone-query", "","select id,name,master,last_check,notified_serial,type from domains where name='%s'");

    declare( suffix, "info-all-slaves-query", "","select id,name,master,last_check,type from domains where type='SLAVE'");
    declare( suffix, "supermaster-query", "", "select account from supermasters where ip='%s' and nameserver='%s'");
    declare( suffix, "insert-slave-query", "", "insert into domains (type,name,master,account) values('SLAVE','%s','%s','%s')");
    declare( suffix, "insert-record-query", "", "insert into records (content,ttl,prio,type,domain_id,name) values ('%s',%d,%d,'%s',%d,'%s')");
    declare( suffix, "update-serial-query", "", "update domains set notified_serial=%d where id=%d");
    declare( suffix, "update-lastcheck-query", "", "update domains set last_check=%d where id=%d");
    declare( suffix, "info-all-master-query", "", "select id,name,master,last_check,notified_serial,type from domains where type='MASTER'");
    declare( suffix, "delete-zone-query", "", "delete from records where domain_id=%d");
    declare(suffix,"check-acl-query","", "select value from acls where acl_type='%s' and acl_key='%s'");
  }
  
  //! Constructs a new gSQLiteBackend object.
  DNSBackend *make( const string & suffix = "" )
  {
    return new gSQLiteBackend( d_mode, suffix );
  }

private:
  const string d_mode;
};


//! Magic class that is activated when the dynamic library is loaded
class gSQLiteLoader
{
public:
  //! This reports us to the main UeberBackend class
  gSQLiteLoader()
  {
    BackendMakers().report( new gSQLiteFactory( "gsqlite" ));
    L<<Logger::Warning << "This is module gsqlite reporting" << std::endl;
  }
};

string gSQLiteBackend::sqlEscape(const string &name)
{
  return boost::replace_all_copy(name, "'", "''");
}


//! Reports the backendloader to the UeberBackend.
static gSQLiteLoader gsqliteloader;

