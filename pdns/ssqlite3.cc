
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

/*
** Set all the parameters in the compiled SQL statement to NULL.
*
* copied from sqlite 3.3.6 // cmouse 
*/
int pdns_sqlite3_clear_bindings(sqlite3_stmt *pStmt){
  int i;
  int rc = SQLITE_OK;
  for(i=1; rc==SQLITE_OK && i<=sqlite3_bind_parameter_count(pStmt); i++){
    rc = sqlite3_bind_null(pStmt, i);
  }
  return rc;
}

void my_trace(void *foo, const char *sql) {
  L<<Logger::Warning<< "Query: " << sql << endl;
}

class SSQLite3Statement: public SSqlStatement 
{
public:
  SSQLite3Statement(SSQLite3 *db, bool dolog, const string& query) 
  {
    const char *pTail;
    this->d_query = query;
    this->d_dolog = dolog;
    d_db = db;
#if SQLITE_VERSION_NUMBER >= 3003009
    if (sqlite3_prepare_v2(d_db->db(), query.c_str(), -1, &d_stmt, &pTail ) != SQLITE_OK)
#else
    if (sqlite3_prepare(d_db->db(), query.c_str(), -1, &d_stmt, &pTail ) != SQLITE_OK)
#endif
      throw SSqlException(string("Unable to compile SQLite statement : ")+sqlite3_errmsg(d_db->db()));
    if (pTail && strlen(pTail)>0)
      L<<Logger::Warning<<"Sqlite3 command partially processed. Unprocessed part: "<<pTail<<endl;
  }

  int name2idx(const string& name) {
    string zName = string(":")+name;
    return sqlite3_bind_parameter_index(d_stmt, zName.c_str());
    // XXX: support @ and $?    
  }

  SSqlStatement* bind(const string& name, bool value) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_int(d_stmt, idx, value ? 1 : 0); }; return this; }
  SSqlStatement* bind(const string& name, int value) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_int(d_stmt, idx, value); }; return this; }
  SSqlStatement* bind(const string& name, uint32_t value) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_int64(d_stmt, idx, value); }; return this; }
  SSqlStatement* bind(const string& name, long value) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_int64(d_stmt, idx, value); }; return this; }
  SSqlStatement* bind(const string& name, unsigned long value) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_int64(d_stmt, idx, value); }; return this; }
  SSqlStatement* bind(const string& name, long long value) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_int64(d_stmt, idx, value); }; return this; };
  SSqlStatement* bind(const string& name, unsigned long long value) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_int64(d_stmt, idx, value); }; return this; }
  SSqlStatement* bind(const string& name, const std::string& value) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_text(d_stmt, idx, value.c_str(), value.size(), SQLITE_TRANSIENT); }; return this; }
  SSqlStatement* bindNull(const string& name) { int idx = name2idx(name); if (idx>0) { sqlite3_bind_null(d_stmt, idx); }; return this; }

  SSqlStatement* execute() {
    int attempts = d_db->inTransaction(); // try only once
    while(attempts < 2 && (d_rc = sqlite3_step(d_stmt)) == SQLITE_BUSY) attempts++;

    if (d_rc != SQLITE_ROW && d_rc != SQLITE_DONE) {
      // failed.
      if (d_rc == SQLITE_CANTOPEN) 
        throw SSqlException(string("CANTOPEN error in sqlite3, often caused by unwritable sqlite3 db *directory*: ")+string(sqlite3_errmsg(d_db->db())));
      throw SSqlException(string("Error while retrieving SQLite query results: ")+string(sqlite3_errmsg(d_db->db())));
    }
    return this;
  }
  bool hasNextRow() { return d_rc == SQLITE_ROW; }

  SSqlStatement* nextRow(row_t& row) {
    row.clear();
    int numCols = sqlite3_column_count(d_stmt);
    row.reserve(numCols); // preallocate memory
    // Another row received, process it.
    for ( int i=0; i<numCols; i++)
    {
      if (sqlite3_column_type(d_stmt,i) == SQLITE_NULL) {
        row.push_back("");
      } else {
        const char *pData = (const char*) sqlite3_column_text(d_stmt, i);
        row.push_back(string(pData, sqlite3_column_bytes(d_stmt, i))); 
      }
    }
    d_rc = sqlite3_step(d_stmt);
    return this;
  }

  SSqlStatement* getResult(result_t& result) {
    result.clear();
    while(hasNextRow()) {
      row_t row;
      nextRow(row);
      result.push_back(row);
    }
    return this;
  }

  SSqlStatement* reset() {
    sqlite3_reset(d_stmt);
#if SQLITE_VERSION_NUMBER >= 3003009
    sqlite3_clear_bindings(d_stmt);
#else
    pdns_sqlite3_clear_bindings(d_stmt);
#endif
    return this;
  }

  ~SSQLite3Statement() {
    // deallocate if necessary
    if (d_stmt) 
      sqlite3_finalize(d_stmt);
  }

  const string& getQuery() { return d_query; };
private:
  string d_query;
  sqlite3_stmt* d_stmt;
  int d_rc;
  SSQLite3* d_db;
  bool d_dolog;
};

// Constructor.
SSQLite3::SSQLite3( const std::string & database, bool creat )
{
  // Open the database connection.
  if(!creat) 
    if ( access( database.c_str(), F_OK ) == -1 )
      throw sPerrorException( "SQLite database '"+database+"' does not exist yet" );

  if ( sqlite3_open( database.c_str(), &m_pDB)!=SQLITE_OK )
    throw sPerrorException( "Could not connect to the SQLite database '" + database + "'" );
  m_dolog = 0;
  m_in_transaction = false;
  sqlite3_busy_handler(m_pDB, busyHandler, 0);
}

void SSQLite3::setLog(bool state)
{ 
  if (state)
      sqlite3_trace(m_pDB, my_trace, NULL);
  m_dolog=state;
}

// Destructor.
SSQLite3::~SSQLite3()
{
  int ret;
  for(int n = 0; n < 2 ; ++n) {
    if((ret =sqlite3_close( m_pDB )) != SQLITE_OK) {
      if(n || ret != SQLITE_BUSY) { // if we have SQLITE_BUSY, and a working m_Pstmt, try finalize
        cerr<<"Unable to close down sqlite connection: "<<ret<<endl;
        abort();
      }
    }
    else
      break;
  }
}

SSqlStatement* SSQLite3::prepare(const string& query, int nparams __attribute__((unused))) {
  return new SSQLite3Statement(this, m_dolog, query);
}

void SSQLite3::execute(const string& query) {
  char *errmsg;
  int rc;
  if (sqlite3_exec(m_pDB, query.c_str(), NULL, NULL, &errmsg) == SQLITE_BUSY) {
    if (m_in_transaction) {
        throw("Failed to execute query: " + string(errmsg));
    } else {
      if ((rc = sqlite3_exec(m_pDB, query.c_str(), NULL, NULL, &errmsg) != SQLITE_OK) && rc != SQLITE_DONE && rc != SQLITE_ROW)
        throw("Failed to execute query: " + string(errmsg));
    }
  }
}

int SSQLite3::busyHandler(void*, int)
{
  Utility::usleep(1000);
  return 1;
}

void SSQLite3::startTransaction() {
  execute("begin");
  m_in_transaction = true;
}

void SSQLite3::rollback() {
  execute("rollback");
  m_in_transaction = false;
}

void SSQLite3::commit() {
  execute("commit");
  m_in_transaction = false;
}

// Constructs a SSqlException object.
SSqlException SSQLite3::sPerrorException( const std::string & reason )
{
  return SSqlException( reason );
}
