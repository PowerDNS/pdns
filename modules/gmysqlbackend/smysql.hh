/* Copyright 2001 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information.
   $Id$  */
#ifndef SMYSQL_HH
#define SMYSQL_HH

#include <mysql.h>
#include "pdns/backends/gsql/ssql.hh"
#include "pdns/utility.hh"

class SMySQL : public SSql
{
public:
  SMySQL(const string &database, const string &host="", uint16_t port=0,
         const string &msocket="",const string &user="",
         const string &password="", const string &group="",
         bool setIsolation=false, unsigned int timeout=10);

  ~SMySQL();

  SSqlException sPerrorException(const string &reason);
  void setLog(bool state);
  SSqlStatement* prepare(const string& query, int nparams);
  void execute(const string& query);

  void startTransaction();
  void commit();
  void rollback();

private:
  MYSQL d_db;
  static bool s_dolog;
  static pthread_mutex_t s_myinitlock;
};

#endif /* SSMYSQL_HH */
