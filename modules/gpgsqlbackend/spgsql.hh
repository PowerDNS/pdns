/* Copyright 2001 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information.
   $Id: spgsql.hh,v 1.1 2002/12/16 18:02:09 ahu Exp $  */
#ifndef SPGSQL_HH
#define SPGSQL_HH
#include <libpq++.h>
#include "pdns/backends/gsql/ssql.hh"

class SPgSQL : public SSql
{
public:
  SPgSQL(const string &database, const string &host="", 
	 const string &msocket="",const string &user="", 
	 const string &password="");

  ~SPgSQL();
  
  SSqlException sPerrorException(const string &reason);
  int doQuery(const string &query, result_t &result);
  int doQuery(const string &query);
  bool getRow(row_t &row);
  string escape(const string &str);    
  void setLog(bool state);
private:
  PgDatabase *d_db; 
  int d_count;
  static bool s_dolog;
};
      
#endif /* SPGSQL_HH */
