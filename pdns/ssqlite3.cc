
//
// SQLite backend for PowerDNS
// Copyright (C) 2003, Michel Stol <michel@powerdns.com>
//

#include <string>
#include <sstream>
#include "ssqlite3.hh"
#include <iostream>
#include <fstream>
#include "pdns/logger.hh"
#include "misc.hh"
#include <unistd.h>

// Constructor.
SSQLite3::SSQLite3( const std::string & database, bool creat )
{
  // Open the database connection.
  if(!creat) 
    if ( access( database.c_str(), F_OK ) == -1 )
      throw sPerrorException( "SQLite database '"+database+"' does not exist yet" );

  if ( sqlite3_open( database.c_str(), &m_pDB)!=SQLITE_OK )
    throw sPerrorException( "Could not connect to the SQLite database '" + database + "'" );
  m_pStmt = 0;
  m_dolog = 0;
  sqlite3_busy_handler(m_pDB, busyHandler, 0);
}

void SSQLite3::setLog(bool state)
{
  m_dolog=state;
}

// Destructor.
SSQLite3::~SSQLite3()
{
  int ret;
  for(int n = 0; n < 2 ; ++n) {
    if((ret =sqlite3_close( m_pDB )) != SQLITE_OK) {
      if(n || !m_pStmt || ret != SQLITE_BUSY) { // if we have SQLITE_BUSY, and a working m_Pstmt, try finalize
        cerr<<"Unable to close down sqlite connection: "<<ret<<endl;
        abort();
      }
      else {
        sqlite3_finalize(m_pStmt);
      }
    }
    else
      break;
  }
}


// Constructs a SSqlException object.
SSqlException SSQLite3::sPerrorException( const std::string & reason )
{
  return SSqlException( reason );
}


// Performs a query.
int SSQLite3::doQuery( const std::string & query, result_t & result )
{
  result.clear();

  doQuery( query );

  row_t row;
  while( getRow( row ))
    result.push_back( row );

  return result.size();
}


// Performs a query.
int SSQLite3::doQuery( const std::string & query )
{
  const char *pTail;

  if(m_dolog)
    L<<Logger::Warning<<"Query: "<<query<<endl;
  
  // Execute the query.

#if SQLITE_VERSION_NUMBER >=  3003009
  if ( sqlite3_prepare_v2( m_pDB, query.c_str(), -1, &m_pStmt, &pTail ) != SQLITE_OK )
#else
  if ( sqlite3_prepare( m_pDB, query.c_str(), -1, &m_pStmt, &pTail ) != SQLITE_OK )   
#endif
    throw sPerrorException( string("Unable to compile SQLite statement : ")+ sqlite3_errmsg( m_pDB ) );

  return 0;
}

int SSQLite3::busyHandler(void*, int)
{
  usleep(1000);
  return 1;
}

// Returns a row from the result set.
bool SSQLite3::getRow( row_t & row )
{
  int  numCols;
  int  rc;
  const char *pData;

  row.clear();

  rc = sqlite3_step( m_pStmt );

  if ( rc == SQLITE_ROW )
  {
    numCols = sqlite3_column_count( m_pStmt );
    // Another row received, process it.
    for ( int i = 0; i < numCols; i++ )
    {
      pData = (const char*) sqlite3_column_text( m_pStmt, i );
      row.push_back( pData ? pData : "" ); // NULL value to "".
    }

    return true;
  }

  if ( rc == SQLITE_DONE )
  {
    // We're done, clean up.
    sqlite3_finalize( m_pStmt );
    m_pStmt = NULL;
    return false;
  }
  
  if(rc == SQLITE_CANTOPEN) {
    string error ="CANTOPEN error in sqlite3, often caused by unwritable sqlite3 db *directory*: "+string(sqlite3_errmsg(m_pDB));
    sqlite3_finalize(m_pStmt);
    m_pStmt = 0;
    throw sPerrorException(error);
  }
  
  // Something went wrong, complain.
  throw sPerrorException( "Error while retrieving SQLite query results: "+string(sqlite3_errmsg(m_pDB) ));

  // Prevent some compilers from complaining.
  return false;
}


// Escape a SQL query.
std::string SSQLite3::escape( const std::string & name)
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

