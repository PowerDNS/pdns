
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

  bool m_dolog;
  bool m_in_transaction;
  static int busyHandler(void*, int);
protected:
public:
  //! Constructor.
  SSQLite3( const std::string & database, bool creat=false );

  //! Destructor.
  ~SSQLite3();

  SSqlStatement* prepare(const string& query, int nparams);
  void execute(const string& query);
  void setLog(bool state);

  void startTransaction();
  void commit();
  void rollback();

  sqlite3 *db() { return this->m_pDB; };

  bool inTransaction() { return m_in_transaction; };

  //! Used to create an backend specific exception message.
  SSqlException sPerrorException( const std::string & reason );
};

#endif // SSQLITE3_HH

