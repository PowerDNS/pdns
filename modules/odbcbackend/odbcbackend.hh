/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

// ODBC backend by Michel Stol (michel@powerdns.com)
// For use with PowerDNS - The powerfull and versatile nameserver.

#ifndef ODBCBACKEND_H
#define ODBCBACKEND_H

#include <utility.hh>
#include <string>
#include <sql.h>
#include <sqlext.h>
#include <dnsbackend.hh>
#include <dns.hh>
#include <dnsbackend.hh>
#include <dnspacket.hh>
#include <ahuexception.hh>
#include <logger.hh>

#define ODBCBACKEND_VERSION "0.0.1"


//! PowerDNS backend for ODBC.
/*!
This is a backend that gives pdns the ability to retrieve
information from any ODBC source.
*/
class ODBCBackend : public DNSBackend
{
private:
  //! Handle used for the SQL connection.
  SQLHDBC m_connection;

  //! Handle used for the environment.
  SQLHENV m_env;

  //! Name of last question.
  std::string m_name;

  //! Type of last question.
  QType m_type;

  //! Variables for data retrieval.
  struct QueryRR
  {
    //! Handle used for a SQL statement.
    SQLHSTMT  m_statement;

    long int  m_ttl;
    long int  m_priority;
    long int  m_domain_id;
    long int  m_modified;
    long int  m_nullResult[ 2 ];

    char      m_content[ 256 ];
    char      m_name[ 256 ];
    char      m_type[ 6 ];
  };

  QueryRR m_rrQuery;

  struct QueryDI 
  {
    SQLHSTMT  m_statement;

    long int  m_id;
    long int  m_last_check;
    long int  m_notified_serial;
    long int  m_nullResult[ 6 ];
    
    char      m_name    [ 256 ];
    char      m_master  [ 21 ];
    char      m_type    [ 7 ];        
    char      m_account [ 41 ];
  };

  QueryDI m_diQuery;

  struct QuerySM
  {
    SQLHSTMT  m_statement;
    char      m_ip[ 26 ];
    char      m_account[ 41 ];
    char      m_nameserver[ 256 ];

    long int  m_nullResult[ 3 ];
  };

  QuerySM m_smQuery;

protected:
  //! Escape string.
  std::string ODBCBackend::sqlEscape( const std::string & name );

public:
  //! Default constructor.
  ODBCBackend( const std::string & suffix = "" );
  
  //! Destructor.
  ~ODBCBackend( void );
  
  //! List, used for AXFR.
  bool list( int domain_id );

  //! Lookup a domain.
  void lookup( const QType & type, const std::string & name, DNSPacket *pPacket = NULL, int zoneId = -1 );

  //! Fill a resource record with the result.
  bool get( DNSResourceRecord & rr );
  

  // Master/slave functionality.
  //! Returns true if this backend is a slave of name/ip.
  bool isMaster( const std::string & name, const std::string & ip );

  //! Checks the domainlist for unfresh domains.
  void getUnfreshSlaveInfos( std::vector< DomainInfo > *pDomains );

  //! Checks the domainlist for updated domains.
  void getUpdatedMasters( std::vector< DomainInfo > *pDomains );

  //! Checks one domain.
  bool getDomainInfo( const std::string & domain, DomainInfo & di );

  //! Starts the transaction.
  bool startTransaction( const std::string & qname, int id = -1 );

  //! Inserts a record.
  bool feedRecord( const DNSResourceRecord & rr );

  //! Commit transaction.
  bool commitTransaction( void );

  //! Aborts transaction.
  bool abortTransaction( void );

  //! Mark as fresh.
  void setFresh( u_int32_t domain_id );
  
  //! Super master/slave functionality.
  bool superMasterBackend( const std::string & ip, const std::string & domain, const std::vector< DNSResourceRecord > & nsset, std::string *pAccount, DNSBackend **ppDB );
  
  //! Inserts a new slave domain.
  bool createSlaveDomain( const std::string & ip, const std::string & domain, const std::string & account );
  
};


//! ODBCBackend's factory class.
class ODBCBackendFactory : public BackendFactory
{
private:
protected:
public:
  //! Constructor.
  ODBCBackendFactory( void ) : BackendFactory( "odbc" )
  {
  }

  
  //! Returns a new ODBC backend object.
  DNSBackend *make( const std::string & suffix )
  {
    return new ODBCBackend();
  }

  //! Declare our supported arguments.
  void declareArguments( const string & suffix = "" )
  {
    declare( suffix, "datasource", "ODBC data source to connect to", "powerdns" );
    declare( suffix, "user", "ODBC user to connect as", "powerdns" );
    declare( suffix, "pass", "ODBC password to connect with", "powerdns" );
    declare( suffix, "table", "Name of the table containing zone information", "records" );
  } 
  
};


//! Adds the ODBCBackend to the Ueberbackend.
class ODBCBackendLoader
{
private:
protected:
public:
  //! Constructor that adds ourself to the Ueberbeckend.
  ODBCBackendLoader( void )
  {
    BackendMakers().report( new ODBCBackendFactory );
  }
  
};


// Hey you, ueberbackend.
static ODBCBackendLoader odbcBackendLoader;


#endif // ODBCBACKEND_H
