
//
// SQLite backend for PowerDNS
// Copyright (C) 2003, Michel Stol <michel@powerdns.com>
//

#include <string>
#include "ssqlite.hh"


// Constructor.
SSQLite::SSQLite( const std::string & database )
{
  // Open the database connection.
  m_pDB = sqlite_open( database.c_str(), 0, NULL );
  if ( m_pDB == NULL )
    throw sPerrorException( "Could not connect to the SQLite database" );

  m_pVM = NULL;
}


// Destructor.
SSQLite::~SSQLite( void )
{
  if ( m_pDB )
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
  if ( sqlite_compile( m_pDB, query.c_str(), &pOut, &m_pVM, NULL ) != SQLITE_OK )
    sPerrorException( "Could not create SQLite VM for query" );
    
  return 0;
}


// Returns a row from the result set.
bool SSQLite::getRow( row_t & row )
{
  int  numCols;
  int  rc;
  const char **ppData;
  const char **ppColumnNames;

  do
  {
    rc = sqlite_step( m_pVM, &numCols, &ppData, &ppColumnNames );
    
    if ( rc == SQLITE_BUSY )
    {
      usleep( 250 ); // FIXME: Should this be increased, decreased, or is it Just Right? :)
      continue;
    }   
  } while ( false );
  
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

