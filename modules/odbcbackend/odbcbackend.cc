/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

// ODBC backend by Michel Stol (michel@powerdns.com)
// For use with PowerDNS - The powerful and versatile nameserver.

#include "odbcbackend.hh"


static std::string backendName = "[ODBCBackend]";


// Default constructor.
ODBCBackend::ODBCBackend( const std::string & suffix )
{
  SQLRETURN rc;
  char buf1[ 512 ], buf2[ 512 ], buf3[ 512 ];
  long len = 0;

  m_name = "";
  
  setArgPrefix( "odbc" + suffix );
  
  // Allocate neccessary handles.
  rc = SQLAllocHandle( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_env );
  if ( rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO )
    throw AhuException( backendName + std::string( " Failed to initialize." ));

  // Set environment.
  // HAHAHA, geez, this API really sux, see that reinterpret_cast? Ieuw!!
  rc = SQLSetEnvAttr( m_env, SQL_ATTR_ODBC_VERSION, reinterpret_cast< void * >( SQL_OV_ODBC3 ), len );
  if ( rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO )
    throw AhuException( backendName + std::string( " Failed to initialize." ));

  rc = SQLAllocHandle( SQL_HANDLE_DBC, m_env, &m_connection );
  if ( rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO )
    throw AhuException( backendName + std::string( " Failed to initialize." ));

  // Try to connect.
  strncpy( buf1, getArg( "datasource" ).c_str(), sizeof( buf1 ));
  strncpy( buf2, getArg( "user" ).c_str(), sizeof( buf2 ));
  strncpy( buf3, getArg( "pass" ).c_str(), sizeof( buf3 ));

  rc = SQLConnect( 
    m_connection, 
    reinterpret_cast< unsigned char * >( buf1 ),
    strlen( buf1 ),
    reinterpret_cast< unsigned char * >( buf2 ),
    strlen( buf2 ),
    reinterpret_cast< unsigned char * >( buf3 ),
    strlen( buf3 ));

  if ( rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO )
    throw AhuException( backendName + std::string( " Could not connect to ODBC source." ));

  rc = SQLAllocHandle( SQL_HANDLE_STMT, m_connection, &m_rrQuery.m_statement );
  if ( rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO )
    throw AhuException( " Failed to initialize." );


  // Bind columns.
  SQLBindCol( m_rrQuery.m_statement, 1, SQL_C_SLONG, &m_rrQuery.m_ttl, sizeof( m_rrQuery.m_ttl ), NULL );
  SQLBindCol( m_rrQuery.m_statement, 2, SQL_C_CHAR, m_rrQuery.m_content, sizeof( m_rrQuery.m_content ), NULL );
  SQLBindCol( m_rrQuery.m_statement, 3, SQL_C_SLONG, &m_rrQuery.m_priority, sizeof( m_rrQuery.m_priority ), &m_rrQuery.m_nullResult[ 0 ] );
  SQLBindCol( m_rrQuery.m_statement, 4, SQL_C_CHAR,  m_rrQuery.m_type, sizeof( m_rrQuery.m_type ), NULL );
  SQLBindCol( m_rrQuery.m_statement, 5, SQL_C_SLONG, &m_rrQuery.m_domain_id, sizeof( m_rrQuery.m_domain_id ), NULL );
  SQLBindCol( m_rrQuery.m_statement, 6, SQL_C_CHAR, m_rrQuery.m_name, sizeof( m_rrQuery.m_name ), NULL );


  rc = SQLAllocHandle( SQL_HANDLE_STMT, m_connection, &m_diQuery.m_statement );
  if ( rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO )
    throw AhuException( " Failed to initialize." );


  // Bind columns.
  SQLBindCol( m_diQuery.m_statement, 1, SQL_C_SLONG, &m_diQuery.m_id, sizeof( m_diQuery.m_id ), &m_diQuery.m_nullResult[ 0 ] );
  SQLBindCol( m_diQuery.m_statement, 2, SQL_C_CHAR, m_diQuery.m_name, sizeof( m_diQuery.m_name ), &m_diQuery.m_nullResult[ 1 ] );
  SQLBindCol( m_diQuery.m_statement, 3, SQL_C_CHAR, m_diQuery.m_master, sizeof( m_diQuery.m_master ), &m_diQuery.m_nullResult[ 2 ] );
  SQLBindCol( m_diQuery.m_statement, 4, SQL_C_SLONG, &m_diQuery.m_last_check, sizeof( m_diQuery.m_last_check ), &m_diQuery.m_nullResult[ 3 ] );
  SQLBindCol( m_diQuery.m_statement, 5, SQL_C_CHAR, m_diQuery.m_type, sizeof( m_diQuery.m_type ), &m_diQuery.m_nullResult[ 4 ] );
  SQLBindCol( m_diQuery.m_statement, 6, SQL_C_SLONG, &m_diQuery.m_notified_serial, sizeof( m_diQuery.m_notified_serial ), &m_diQuery.m_nullResult[ 5 ] );


  rc = SQLAllocHandle( SQL_HANDLE_STMT, m_connection, &m_smQuery.m_statement );
  if ( rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO )
    throw AhuException( " Failed to initialize." );


  // Bind columns.
  SQLBindCol( m_smQuery.m_statement, 1, SQL_C_CHAR, m_smQuery.m_ip, sizeof( m_smQuery.m_ip ), &m_smQuery.m_nullResult[ 0 ] );
  SQLBindCol( m_smQuery.m_statement, 2, SQL_C_CHAR, m_smQuery.m_nameserver, sizeof( m_smQuery.m_nameserver ), &m_smQuery.m_nullResult[ 1 ] );
  SQLBindCol( m_smQuery.m_statement, 3, SQL_C_CHAR, m_smQuery.m_account, sizeof( m_smQuery.m_account ), &m_smQuery.m_nullResult[ 2 ] );
  
  // We have a connection!
  L << Logger::Info << backendName << " ODBC connected." << endl;
  
}


// Destructor.
ODBCBackend::~ODBCBackend( void )
{
  // Shut this thing down properly.
  abortTransaction();
  
  SQLFreeHandle( SQL_HANDLE_STMT, m_rrQuery.m_statement );
  SQLFreeHandle( SQL_HANDLE_STMT, m_diQuery.m_statement );
  SQLFreeHandle( SQL_HANDLE_STMT, m_smQuery.m_statement );

  SQLDisconnect( m_connection );

  SQLFreeHandle( SQL_HANDLE_DBC, m_connection );
  SQLFreeHandle( SQL_HANDLE_ENV, m_env );

  L << Logger::Info << backendName << " ODBC disconnected." << endl;
}


std::string ODBCBackend::sqlEscape( const std::string & name )
{
  std::string a;

  for( string::const_iterator i = name.begin(); i != name.end(); ++i )

    if( *i == '\'' || *i == '\\' ) {
      a += '\\';
      a += *i;
    }
    else
      a += *i;

  return a;      
}


// Return results.
bool ODBCBackend::get( DNSResourceRecord & rr )
{
  SQLRETURN rc;
   
  rc = SQLFetch( m_rrQuery.m_statement );
  if ( rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO )
  {
    rr.ttl        = m_rrQuery.m_ttl;
    rr.content    = m_rrQuery.m_content;
    rr.qtype      = m_rrQuery.m_type;
    rr.domain_id  = m_rrQuery.m_domain_id;

    if ( !m_name.empty())
      rr.qname = m_name;
    else
      rr.qname = m_rrQuery.m_name;

    if ( m_rrQuery.m_nullResult[ 0 ] == SQL_NULL_DATA )
      rr.priority = 0;
    else
      rr.priority = m_rrQuery.m_priority;

    if ( m_rrQuery.m_nullResult[ 1 ] == SQL_NULL_DATA )
      rr.last_modified = 0;
    else
      rr.last_modified = m_rrQuery.m_modified;

    return true;
  }

  SQLFreeStmt( m_rrQuery.m_statement, SQL_CLOSE );  
  return false;
}


// List a domain.
bool ODBCBackend::list( int domain_id )
{
  SQLRETURN           res;
  std::ostringstream  query;
  char                buf[ 512 ];

  query << "SELECT ttl,content,prio,type,domain_id,name FROM " << getArg( "table" ) << " WHERE domain_id=" << domain_id; 
  
  strncpy( buf, query.str().c_str(), sizeof( buf ));

  res = SQLExecDirect( m_rrQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
  {
    unsigned char state[ 7 ], msg[ 512 ];
    short len;
    long error;

    SQLGetDiagRec( SQL_HANDLE_STMT, m_rrQuery.m_statement, 1, state, &error, msg, sizeof( msg ), &len );

    DLOG( L << reinterpret_cast< char * >( state ) << "-" << reinterpret_cast< char * >( msg ) << endl );

    throw AhuException( backendName + " Failed to list." );
  }
  
  m_name = "";

  return true;
}


// Lookup a question.
void ODBCBackend::lookup( const QType & type, const std::string & name, DNSPacket *pPacket, int zoneId )
{
  SQLRETURN           res;
  std::ostringstream  query;
  char                buf[ 512 ];
  long                len = SQL_NULL_DATA;
  
  if ( name[ 0 ] != '%' )
    query << "SELECT ttl,content,prio,type,domain_id,name FROM " << getArg( "table" ) << " WHERE name='";
  else
    query << "SELECT ttl,content,prio,type,domain_id,name FROM " << getArg( "table" ) << " WHERE name LIKE '";

  if( name.find_first_of( "'\\" ) != string::npos )
    query << sqlEscape( name );
  else
    query << name;

  query << "'";
  
  if ( type.getCode() != 255 )
  {
    // This is not an ANY question.
    query << " AND type='";
    query << type.getName();
    query << "'";
  }
  
  if ( zoneId > 0 )
    query << " AND domain_id=" << zoneId;

  strncpy( buf, query.str().c_str(), sizeof( buf ));

  res = SQLExecDirect( m_rrQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf )); 
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
  {
    unsigned char state[ 7 ], msg[ 512 ];
    short len;
    long error;

    SQLGetDiagRec( SQL_HANDLE_STMT, m_rrQuery.m_statement, 1, state, &error, msg, sizeof( msg ), &len );

    DLOG( L << reinterpret_cast< char * >( state ) << "-" << reinterpret_cast< char * >( msg ) << endl );
    throw AhuException( backendName + " Failed to execute question." );
  }

  m_name = name;
  m_type = type;

}


// Master/slave functionality.
// Returns the domain info of a specific domain.
bool ODBCBackend::getDomainInfo( const std::string & domain, DomainInfo & di )
{
  SQLRETURN           res;
  char                buf[ 512 ];
  std::ostringstream  query;

  query << "SELECT id,name,master,last_check,type,notified_serial FROM domains WHERE name='" << sqlEscape( domain ) << "'";
  strncpy( buf, query.str().c_str(), sizeof( buf ));
  
  res = SQLExecDirect( m_diQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to retrieve list of slave domains." );

  res = SQLFetch( m_diQuery.m_statement );
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to retrieve list of slave domains." );

  if ( res != SQL_NO_DATA )
  {
    if ( m_diQuery.m_nullResult[ 0 ] == SQL_NULL_DATA )
      di.id = 0;
    else
      di.id = m_diQuery.m_id;

    if ( m_diQuery.m_nullResult[ 1 ] == SQL_NULL_DATA )
      di.zone = "";
    else
      di.zone = m_diQuery.m_name;

    if ( m_diQuery.m_nullResult[ 2 ] == SQL_NULL_DATA )
      di.master = "";
    else
      di.master = m_diQuery.m_master;

    if ( m_diQuery.m_nullResult[ 3 ] == SQL_NULL_DATA )
      di.last_check = 0;
    else
      di.last_check = m_diQuery.m_last_check;


    if ( m_diQuery.m_type == "SLAVE" )
      di.kind = DomainInfo::Slave;
    else if ( m_diQuery.m_type == "MASTER" )
      di.kind = DomainInfo::Master;
    else
      di.kind = DomainInfo::Native;

    di.backend= this;

    SQLFreeStmt( m_diQuery.m_statement, SQL_CLOSE );

    return true;
  }
  else
  {
    SQLFreeStmt( m_diQuery.m_statement, SQL_CLOSE );
    return false;
  }
  
  return false;
}


// Returns the unfresh slave zones.
void ODBCBackend::getUnfreshSlaveInfos( std::vector< DomainInfo > *pDomains )
{
  SQLRETURN           res;
  char                buf[ 512 ];
  std::ostringstream  query;
  DomainInfo          di;
  std::vector< DomainInfo > allSlaves;

  query << "SELECT id,name,master,last_check,type,notified_serial FROM domains WHERE type='SLAVE'";
  strncpy( buf, query.str().c_str(), sizeof( buf ));
  
  res = SQLExecDirect( m_diQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to retrieve list of slave domains." );

  res = SQLFetch( m_diQuery.m_statement );
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to retrieve list of slave domains." );

  while ( res != SQL_NO_DATA )
  {
    if ( m_diQuery.m_nullResult[ 0 ] == SQL_NULL_DATA )
      di.id = 0;
    else
      di.id = m_diQuery.m_id;

    if ( m_diQuery.m_nullResult[ 1 ] == SQL_NULL_DATA )
      di.zone = "";
    else
      di.zone = m_diQuery.m_name;

    if ( m_diQuery.m_nullResult[ 2 ] == SQL_NULL_DATA )
      di.masters.clear();
    else {
      stringtok(di.masters, m_diQuery.m_master, " \t");
    }

    if ( m_diQuery.m_nullResult[ 3 ] == SQL_NULL_DATA )
      di.last_check = 0;
    else
      di.last_check = m_diQuery.m_last_check;

    di.backend  = this;
    di.kind     = DomainInfo::Slave;

    allSlaves.push_back( di );
    
    res = SQLFetch( m_diQuery.m_statement );
    if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA)
      throw AhuException( backendName + " Failed to retrieve list of slave domains." );
  }

  for ( std::vector< DomainInfo >::iterator i = allSlaves.begin(); i != allSlaves.end(); ++i )
  {
    SOAData sd;
    
    sd.serial   = 0;
    sd.refresh  = 0;
    getSOA( i->zone, sd );

    if( i->last_check + sd.refresh < time( NULL ))
    {
      i->serial = sd.serial;
      pDomains->push_back( *i );
    }
  }

  SQLFreeStmt( m_diQuery.m_statement, SQL_CLOSE );

}


// Returns the unfresh slave zones.
void ODBCBackend::getUpdatedMasters( std::vector< DomainInfo > *pDomains )
{
  SQLRETURN           res;
  char                buf[ 512 ];
  std::ostringstream  query;
  DomainInfo          di;
  std::vector< DomainInfo > allMasters;

  query << "SELECT id,name,master,last_check,type,notified_serial FROM domains WHERE type='MASTER'";
  strncpy( buf, query.str().c_str(), sizeof( buf ));
  
  res = SQLExecDirect( m_diQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to retrieve list of master domains." );

  res = SQLFetch( m_diQuery.m_statement );
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to retrieve list of master domains." );

  while ( res != SQL_NO_DATA )
  {
    if ( m_diQuery.m_nullResult[ 0 ] == SQL_NULL_DATA )
      di.id = 0;
    else
      di.id = m_diQuery.m_id;

    if ( m_diQuery.m_nullResult[ 1 ] == SQL_NULL_DATA )
      di.zone = "";
    else
      di.zone = m_diQuery.m_name;

    if ( m_diQuery.m_nullResult[ 2 ] == SQL_NULL_DATA )
      di.master = "";
    else
      di.master = m_diQuery.m_master;

    if ( m_diQuery.m_nullResult[ 3 ] == SQL_NULL_DATA )
      di.last_check = 0;
    else
      di.last_check = m_diQuery.m_last_check;

    if ( m_diQuery.m_nullResult[ 5 ] == SQL_NULL_DATA )
      di.notified_serial = 0;
    else
      di.notified_serial = m_diQuery.m_notified_serial;

    di.backend  = this;
    di.kind     = DomainInfo::Master;

    allMasters.push_back( di );
    
    res = SQLFetch( m_diQuery.m_statement );
    if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA)
      throw AhuException( backendName + " Failed to retrieve list of master domains." );
  }

  for ( std::vector< DomainInfo >::iterator i = allMasters.begin(); i != allMasters.end(); ++i )
  {
    SOAData sd;
    
    sd.serial   = 0;
    sd.refresh  = 0;
    getSOA( i->zone, sd );

    if( i->notified_serial != sd.serial )
    {
      i->serial = sd.serial;
      pDomains->push_back( *i );
    }
  }

  SQLFreeStmt( m_diQuery.m_statement, SQL_CLOSE );

}


// Returns true if this our master and we are his slave, and we do everything he wants, whenever he wants it, and... erhm, nevermind.
bool ODBCBackend::isMaster( const std::string & name, const std::string & ip )
{
  //SQLHSTMT            statement;
  SQLRETURN           res;
  char                buf[ 512 ];
  char                resName[ 21 ];
  std::ostringstream  query;

  //res = SQLAllocHandle( SQL_HANDLE_STMT, m_connection, &statement );
  //if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO )
  //  throw AhuException( backendName + " Failed to retrieve slave domains." );

  query << "SELECT id,name,master,last_check,type,notified_serial FROM domains WHERE name='" << sqlEscape( name ) << "' and type='SLAVE'";
  strncpy( buf, query.str().c_str(), sizeof( buf ));

  res = SQLExecDirect( m_diQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to retrieve slave domains." );

  //SQLBindCol( statement, 1, SQL_C_CHAR, resName, sizeof( resName ), NULL );

  res = SQLFetch( m_diQuery.m_statement );
  if (( res != SQL_SUCCESS  && res != SQL_SUCCESS_WITH_INFO ) || res == SQL_NO_DATA )
  {
    SQLFreeStmt( m_diQuery.m_statement, SQL_CLOSE );
    return false;
  }

  SQLFreeStmt( m_diQuery.m_statement, SQL_CLOSE );  

  if ( !strcmp( resName, ip.c_str()))
    return true;

  return false;
}


// Start the transaction.
bool ODBCBackend::startTransaction( const std::string & qname, int id )
{
  SQLRETURN           res;
  std::ostringstream  query;
  char                buf[ 512 ];

  query << "DELETE FROM " << getArg( "table" ) << " WHERE domain_id=" << id;
  strncpy( buf, query.str().c_str(), sizeof( buf ));
  
  res = SQLSetConnectAttr( m_connection, SQL_ATTR_AUTOCOMMIT, reinterpret_cast< void * >( SQL_AUTOCOMMIT_ON ), 0 );
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO )
    throw AhuException( backendName + " Failed to start transaction." );

  res = SQLExecDirect( m_rrQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to start transaction." );

  return true;
}


// Feeds a record to the database.
bool ODBCBackend::feedRecord( const DNSResourceRecord & rr )
{
  SQLRETURN           res;
  std::ostringstream  query;
  char                buf[ 512 ];

  query << "INSERT INTO " << getArg( "table" ) << " (content,ttl,prio,type,domain_id,name) VALUES ("
    << "'" << sqlEscape( rr.content ) << "', "
    << rr.ttl << ", "
    // FIXME: << rr.priority << ", "
    << 0 << ", "
    << "'" << sqlEscape( rr.qtype.getName()) << "', "
    << rr.domain_id << ", "
    << "'" << sqlEscape( rr.qname ) << "')";

  strncpy( buf, query.str().c_str(), sizeof( buf ));

  res = SQLExecDirect( m_rrQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
  {
    unsigned char state[ 7 ], msg[ 512 ];
    short len;
    long error;

    SQLGetDiagRec( SQL_HANDLE_STMT, m_rrQuery.m_statement, 1, state, &error, msg, sizeof( msg ), &len );

    DLOG( L << reinterpret_cast< char * >( state ) << "-" << reinterpret_cast< char * >( msg ) << endl );

    throw AhuException( backendName + " Failed to feed record into the database." );
  }
  
  return true;
}


// Commits the transaction.
bool ODBCBackend::commitTransaction( void )
{
  SQLRETURN res;

  res = SQLEndTran( SQL_HANDLE_DBC, m_connection, SQL_COMMIT );
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO )
    throw AhuException( backendName + " Failed to commit changes." );

  SQLFreeStmt( m_rrQuery.m_statement, SQL_CLOSE );

  SQLSetConnectAttr( m_connection, SQL_ATTR_AUTOCOMMIT, reinterpret_cast< void * >( SQL_AUTOCOMMIT_OFF ), 0 );

  return true;
}


// Aborts the transaction.
bool ODBCBackend::abortTransaction( void )
{
  SQLRETURN res;

  res = SQLEndTran( SQL_HANDLE_DBC, m_connection, SQL_ROLLBACK );
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO )
    throw AhuException( backendName + " Failed to rollback changes." );

  SQLFreeStmt( m_rrQuery.m_statement, SQL_CLOSE );

  SQLSetConnectAttr( m_rrQuery.m_statement, SQL_ATTR_AUTOCOMMIT, reinterpret_cast< void * >( SQL_AUTOCOMMIT_OFF ), 0 );

  return true;
}


// Marks a domain as fresh.
void ODBCBackend::setFresh( uint32_t domain_id )
{
  SQLRETURN           res;
  char                buf[512];
  std::ostringstream  query;

  query << "UPDATE domains SET last_check=" << time( NULL ) << " WHERE id=" << domain_id;
  strncpy( buf, query.str().c_str(), sizeof( buf ));
  
  res = SQLExecDirect( m_diQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to mark domain as fresh." );

  SQLFreeStmt( m_diQuery.m_statement, SQL_CLOSE );
}

// Supermaster support.
bool ODBCBackend::superMasterBackend( const std::string & ip, const std::string & domain, const std::vector< DNSResourceRecord > & nsset, std::string *pAccount, DNSBackend **ppDB )
{
  SQLRETURN           res;
  char                buf[512];
  std::ostringstream  query;
  
  for ( std::vector< DNSResourceRecord >::const_iterator i = nsset.begin(); i != nsset.end(); ++i )
  {
    query.str( "" );

    query << "SELECT ip,nameserver,account FROM supermasters WHERE ip='" << sqlEscape( ip ) << "' AND nameserver='" << sqlEscape( i->content ) << "'";
    strncpy( buf, query.str().c_str(), sizeof( buf ));

    res = SQLExecDirect( m_smQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
    if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
      throw AhuException( backendName + " Failed to search for domain." );

    *pAccount = m_smQuery.m_account;
    *ppDB     = this;
    
    SQLFreeStmt( m_smQuery.m_statement, SQL_CLOSE );

    return true;
  }

  SQLFreeStmt( m_smQuery.m_statement, SQL_CLOSE );
  return false;
}


// Inserts a new slave domain.
bool ODBCBackend::createSlaveDomain( const std::string & ip, const std::string & domain, const std::string & account )
{
  SQLRETURN           res;
  char                buf[512];
  std::ostringstream  query;

  query << "INSERT INTO domains (type,name,master,account) values('SLAVE', "
    << "'" << sqlEscape( domain ) << "', "
    << "'" << sqlEscape( ip ) << "', "
    << "'" << sqlEscape( account ) << "')";

  strncpy( buf, query.str().c_str(), sizeof( buf ));

  res = SQLExecDirect( m_diQuery.m_statement, reinterpret_cast< unsigned char * >( buf ), strlen( buf ));
  if ( res != SQL_SUCCESS && res != SQL_SUCCESS_WITH_INFO && res != SQL_NO_DATA )
    throw AhuException( backendName + " Failed to insert slave domain." );

  SQLFreeStmt( m_diQuery.m_statement, SQL_CLOSE );

  return true;
}
