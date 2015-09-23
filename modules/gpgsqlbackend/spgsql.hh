/* Copyright 2001 - 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information. */
#ifndef SPGSQL_HH
#define SPGSQL_HH
#include "pdns/namespaces.hh"
#include "pdns/backends/gsql/ssql.hh"

#include <libpq-fe.h>
class SPgSQL : public SSql
{
public:
  SPgSQL(const string &database, const string &host="", const string& port="",
         const string &user="", const string &password="");

  ~SPgSQL();
  
  SSqlException sPerrorException(const string &reason);
  void setLog(bool state);
  SSqlStatement* prepare(const string& query, int nparams);
  void execute(const string& query);

  void startTransaction();
  void rollback();
  void commit();

  PGconn* db() { return d_db; }
  bool in_trx() { return d_in_trx; }

private:
  PGconn* d_db;
  string d_connectstr;
  string d_connectlogstr;
  static bool s_dolog;
  bool d_in_trx;
};
      
#endif /* SPGSQL_HH */
