
//
// SQLite backend for PowerDNS
// Copyright (C) 2003, Michel Stol <michel@powerdns.com>
//

#ifndef SSQLITE_HH
#define SSQLITE_HH

#include <sqlite.h>
#include "pdns/backends/gsql/ssql.hh"

class SSQLite : public SSql
{
private:
  //! Pointer to the SQLite database instance.
  sqlite *m_pDB;

  //! Pointer to the SQLite virtual machine executing a query.
  sqlite_vm *m_pVM;
  
protected:
public:
  //! Constructor.
  SSQLite( const std::string & database );
  
  //! Destructor.
  ~SSQLite( void );
  
  //! Performs a query.
  int doQuery( const std::string & query, result_t & result );
  
  //! Performs a query.
  int doQuery( const std::string & query );
  
  //! Returns a row from a result set.
  bool getRow( row_t & row );
  
  //! Escapes the SQL query.
  std::string escape( const std::string & query );
  
  //! Used to create an backend specific exception message.
  SSqlException sPerrorException( const std::string & reason );
  
};

#endif // SSQLITE_HH

