// The Generic ODBC Backend
// By Michel Stol <michel@powerdns.com>

#include "pdns/utility.hh"
#include <sstream>
#include "sodbc.hh"
#include <malloc.h>
#include <string.h>

// Constructor.
SODBC::SODBC(
             const std::string & dsn,
             const std::string & username,
             const std::string & password
            )
{
  SQLRETURN     result;

  // Allocate an environment handle.
  result = SQLAllocHandle( SQL_HANDLE_ENV, SQL_NULL_HANDLE, &m_environment );
  testResult( result, "Could not allocate an environment handle." );

  // Set ODBC version. (IEUW!)
  result = SQLSetEnvAttr( m_environment, SQL_ATTR_ODBC_VERSION, reinterpret_cast< void * >( SQL_OV_ODBC3 ), 0 );
  testResult( result, "Could not set the ODBC version." );

  // Allocate connection handle.
  result = SQLAllocHandle( SQL_HANDLE_DBC, m_environment, &m_connection );
  testResult( result, "Could not allocate a connection handle." );

  // Connect to the database.
  char *l_dsn       = strdup( dsn.c_str());
  char *l_username  = strdup( username.c_str());
  char *l_password  = strdup( password.c_str());

  result = SQLConnect( m_connection,
    reinterpret_cast< SQLTCHAR * >( l_dsn ), dsn.length(),
    reinterpret_cast< SQLTCHAR * >( l_username ), username.length(),
    reinterpret_cast< SQLTCHAR * >( l_password ), password.length());

  free( l_dsn );
  free( l_username );
  free( l_password );

  testResult( result, "Could not connect to ODBC datasource." );

  // Allocate statement handle.
  result = SQLAllocHandle( SQL_HANDLE_STMT, m_connection, &m_statement );
  testResult( result, "Could not allocate a statement handle." );

  m_busy  = false;
  m_log   = false;
}


// Destructor.
SODBC::~SODBC( void )
{
  // Disconnect from database and free all used resources.
  SQLFreeHandle( SQL_HANDLE_STMT, m_statement );

  SQLDisconnect( m_connection );

  SQLFreeHandle( SQL_HANDLE_DBC, m_connection );
  SQLFreeHandle( SQL_HANDLE_ENV, m_environment );

  // Free all allocated column memory.
  for ( int i = 0; i < m_columnInfo.size(); i++ )
  {
    if ( m_columnInfo[ i ].m_pData )
      delete m_columnInfo[ i ].m_pData;
  }
}


// Executes a query.
int SODBC::doQuery( const std::string & query )
{
  SQLRETURN   result;
  char        *tmp;

  if ( m_busy )
    throw SSqlException( "Tried to execute another query while being busy." );

  tmp = strdup( query.c_str());

  // Execute query.
  result = SQLExecDirect( m_statement, reinterpret_cast< SQLTCHAR * >( tmp ), query.length());
  free( tmp );

  testResult( result, "Could not execute query." );

  // We are now busy.
  m_busy = true;

  // Determine the number of columns.
  SQLSMALLINT numColumns;
  SQLNumResultCols( m_statement, &numColumns );

  if ( numColumns == 0 )
    throw SSqlException( "Could not determine the number of columns." );

  // Fill m_columnInfo.
  m_columnInfo.clear();

  column_t    column;
  SQLSMALLINT nullable;
  SQLSMALLINT type;

  for ( SQLSMALLINT i = 1; i <= numColumns; i++ )
  {
    SQLDescribeCol( m_statement, i, NULL, 0, NULL, &type, &column.m_size, NULL, &nullable );

    if ( nullable == SQL_NULLABLE )
      column.m_canBeNull = true;
    else
      column.m_canBeNull = false;

    // Allocate memory.
    switch ( type )
    {
    case SQL_CHAR:
    case SQL_VARCHAR:
    case SQL_LONGVARCHAR:
      column.m_type   = SQL_C_CHAR;
      column.m_pData  = new SQLCHAR[ column.m_size ];
      break;

    case SQL_SMALLINT:
    case SQL_INTEGER:
      column.m_type  = SQL_C_SLONG;
      column.m_size  = sizeof( long int );
      column.m_pData = new long int;
      break;

    case SQL_REAL:
    case SQL_FLOAT:
    case SQL_DOUBLE:
      column.m_type   = SQL_C_DOUBLE;
      column.m_size   = sizeof( double );
      column.m_pData  = new double;
      break;

    default:
      column.m_pData = NULL;

    }

    m_columnInfo.push_back( column );
  }

  return 0;
}


// Executes a query.
int SODBC::doQuery( const std::string & query, result_t & result )
{
  result.clear();

  doQuery( query );

  row_t row;
  while ( getRow( row ))
    result.push_back( row );

  return result.size();
}


// Executes a command.
int SODBC::doCommand( const std::string & command )
{
  SQLRETURN   result;
  char        *tmp;

  if ( m_busy )
    throw SSqlException( "Tried to execute another query while being busy." );

  tmp = strdup( command.c_str());

  // Execute query.
  result = SQLExecDirect( m_statement, reinterpret_cast< SQLTCHAR * >( tmp ), command.length());
  free( tmp );

  testResult( result, "Could not execute query." );

  SQLFreeStmt( m_statement, SQL_CLOSE );

  return 0;
}

// Escapes a SQL string.
std::string SODBC::escape( const std::string & name )
{
  std::string a;

  for( std::string::const_iterator i = name.begin(); i != name.end(); ++i )
  {
    if( *i == '\'' || *i == '\\' )
      a += '\\';
    a += *i;
  }

  return a;
}


// Returns the content of a row.
bool SODBC::getRow( row_t & row )
{
  SQLRETURN result;

  row.clear();

  result = SQLFetch( m_statement );
  if ( result == SQL_SUCCESS || result == SQL_SUCCESS_WITH_INFO )
  {
    // We've got a data row, now lets get the results.
    SQLLEN len;
    for ( int i = 0; i < m_columnInfo.size(); i++ )
    {
      if ( m_columnInfo[ i ].m_pData == NULL )
        continue;

      // Clear buffer.
      memset( m_columnInfo[ i ].m_pData, 0, m_columnInfo[ i ].m_size );

      SQLGetData( m_statement, i + 1, m_columnInfo[ i ].m_type, m_columnInfo[ i ].m_pData, m_columnInfo[ i ].m_size, &len );

      if ( len == SQL_NULL_DATA )
      {
        // Column is NULL, so we can skip the converting part.
        row.push_back( "" );
        continue;
      }

      // Convert the data into strings.
      std::ostringstream str;

      switch ( m_columnInfo[ i ].m_type )
      {
      case SQL_C_CHAR:
        row.push_back( reinterpret_cast< char * >( m_columnInfo[ i ].m_pData ));
        break;

      case SQL_C_SSHORT:
      case SQL_C_SLONG:
        str << *( reinterpret_cast< long * >( m_columnInfo[ i ].m_pData ));
        row.push_back( str.str());

        break;

      case SQL_C_DOUBLE:
        str << *( reinterpret_cast< double * >( m_columnInfo[ i ].m_pData ));
        row.push_back( str.str());

        break;

      default:
        // Eh?
        row.push_back( "" );

      }
    }

    // Done!
    return true;
  }

  // No further results, or error.
  m_busy = false;

  // Free all allocated column memory.
  for ( int i = 0; i < m_columnInfo.size(); i++ )
  {
    if ( m_columnInfo[ i ].m_pData )
      delete m_columnInfo[ i ].m_pData;
  }

  SQLFreeStmt( m_statement, SQL_CLOSE );

  return false;
}


// Sets the log state.
void SODBC::setLog( bool state )
{
  m_log = state;
}


// Returns an exception.
SSqlException SODBC::sPerrorException( const std::string & reason )
{
  return SSqlException( reason );
}


// Tests the result.
void SODBC::testResult( SQLRETURN result, const std::string & message )
{
  if ( result != SQL_SUCCESS && result != SQL_SUCCESS_WITH_INFO )
    throw SSqlException( message );
}
