
//
// SQLite backend for PowerDNS
// Copyright (C) 2003, Michel Stol <michel@powerdns.com>
//

#include "pdns/utility.hh"
#include <string>
#include "ssqlite.hh"
#include <iostream>

#ifdef WIN32
# include <io.h>
# define access _access
# define F_OK 0
#endif // WIN32

// Constructor.
SSQLite::SSQLite( const std::string & database )
{
  // Open the database connection.
  if ( access( database.c_str(), F_OK ) == -1 )
    throw sPerrorException( "SQLite database does not exist yet" );

  m_pDB = sqlite_open( database.c_str(), 0, NULL );
  if ( !m_pDB )
    throw sPerrorException( "Could not connect to the SQLite database '" + database + "'" );
}


// Destructor.
SSQLite::~SSQLite( void )
{
  sqlite_close( m_pDB );
}


// Constructs a SSqlException object.
SSqlException SSQLite::sPerrorException( const std::string & reason )
{
  return SSqlException( reason );
}


// Performs a query.
int SSQLite::doQuery( const std::string & query, result_t & result )
{
  result.clear();
  
  doQuery( query );
  
  row_t row;
  while( getRow( row ))
    result.push_back( row );
    
  return result.size();
}


// Performs a query.
int SSQLite::doQuery( const std::string & query )
{
  const char *pOut;

  // Execute the query.
  char *pError = NULL;
  if ( sqlite_compile( m_pDB, query.c_str(), &pOut, &m_pVM, &pError ) != SQLITE_OK )
    sPerrorException( "Could not create SQLite VM for query" );
  
  if ( !m_pVM ) {
    std::string report( "Unable to compile SQLite statement" );

    if( pError ) 
    {
      report += string( ": " ) + pError;
      sqlite_freemem( pError );
    }

    sPerrorException( report );
  }
  return 0;
}


// Returns a row from the result set.
bool SSQLite::getRow( row_t & row )
{
  int  numCols;
  int  rc;
  const char **ppData;
  const char **ppColumnNames;

  row.clear();

  do
  {
    rc = sqlite_step( m_pVM, &numCols, &ppData, &ppColumnNames );
    
    if ( rc == SQLITE_BUSY )
      Utility::usleep( 250 ); // FIXME: Should this be increased, decreased, or is it Just Right? :)
    else
      break;

  } while ( true );
  
  if ( rc == SQLITE_ROW )
  {
    // Another row received, process it.
    for ( int i = 0; i < numCols; i++ )
    {
      if ( ppData[ i ] )
        row.push_back( ppData[ i ] );
      else
        row.push_back( "" ); // NULL value.
    }
    
    return true;
  }
  
  if ( rc == SQLITE_DONE )
  {
    // We're done, clean up.
    sqlite_finalize( m_pVM, NULL );
    m_pVM = NULL;
    
    return false;
  }
  
  // Something went wrong, complain.
  throw sPerrorException( "Error while retrieving SQLite query results" );
  
  // Prevent some compilers from complaining.
  return false;
}


// Escape a SQL query.
std::string SSQLite::escape( const std::string & name)
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

