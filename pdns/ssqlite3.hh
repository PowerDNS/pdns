
//
// SQLite backend for PowerDNS
// Copyright (C) 2003, Michel Stol <michel@powerdns.com>
//

#ifndef SSQLITE3_HH
#define SSQLITE3_HH

#include <sqlite3.h>
#include "pdns/backends/gsql/ssql.hh"

class SSQLite3 : public SSql
{
private:
  //! Pointer to the SQLite database instance.
  sqlite3 *m_pDB;

  //! Pointer to the SQLite virtual machine executing a query.
  sqlite3_stmt *m_pStmt;

  bool m_dolog;

  static int busyHandler(void*, int);
protected:
public:
  //! Constructor.
  SSQLite3( const std::string & database, bool creat=false );

  //! Destructor.
  ~SSQLite3();

  //! Performs a query and puts answers in result
  int doQuery( const std::string & query, result_t & result );

  //! Performs a query, caller can retrieve answers with getRow
  int doQuery( const std::string & query );

  //! Performs a command that does not return rows
  int doCommand( const std::string & query )
  {
    result_t result;
    return doQuery(query, result); // 'result' is necessary to force doQuery to do the work, closing Debian bug 280359
  }

  //! Returns a row from a result set.
  bool getRow( row_t & row );

  //! Escapes the SQL query.
  std::string escape( const std::string & query );

  void setLog(bool state);

  //! Used to create an backend specific exception message.
  SSqlException sPerrorException( const std::string & reason );
};

#endif // SSQLITE3_HH

