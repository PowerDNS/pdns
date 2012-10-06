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
         const string &password="", const string &group="");

  ~SMySQL();
  
  SSqlException sPerrorException(const string &reason);
  int doQuery(const string &query, result_t &result);
  int doQuery(const string &query);
  int doCommand(const string &query);
  bool getRow(row_t &row);
  string escape(const string &str);    
  void setLog(bool state);
private:
  MYSQL d_db;
  MYSQL_RES *d_rres;
  static bool s_dolog;
  static pthread_mutex_t s_myinitlock;
};
      
#endif /* SSMYSQL_HH */
