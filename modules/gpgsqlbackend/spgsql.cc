/* Copyright 2003 - 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information. */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string>
#include "spgsql.hh"

#include <iostream>
#include "pdns/logger.hh"
#include "pdns/dns.hh"
#include "pdns/namespaces.hh"
#include <algorithm>
#include <boost/foreach.hpp>

class SPgSQLStatement: public SSqlStatement
{
public:
  SPgSQLStatement(const string& query, bool dolog, int nparams, PGconn* db) {
    struct timeval tv;

    d_query = query;
    d_dolog = dolog;
    d_db = db;

    // prepare a statement
    gettimeofday(&tv,NULL);
    this->d_stmt = string("stmt") + boost::lexical_cast<string>(tv.tv_sec) + boost::lexical_cast<string>(tv.tv_usec);

    d_nparams = nparams;
 
    PGresult* res = PQprepare(d_db, d_stmt.c_str(), d_query.c_str(), d_nparams, NULL);
    ExecStatusType status = PQresultStatus(res);
    string errmsg(PQresultErrorMessage(res));
    PQclear(res);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK && status != PGRES_NONFATAL_ERROR) {
      throw SSqlException("Fatal error during prepare: " + d_query + string(": ") + errmsg);
    } 
    paramValues=NULL;
    d_paridx=d_residx=d_resnum=0;
    paramLengths=NULL;
    d_res=NULL;
  }

  SSqlStatement* bind(const string& name, bool value) { return bind(name, string(value ? "t" : "f")); }
  SSqlStatement* bind(const string& name, int value) { return bind(name, boost::lexical_cast<string>(value)); }
  SSqlStatement* bind(const string& name, uint32_t value) { return bind(name, boost::lexical_cast<string>(value)); }
  SSqlStatement* bind(const string& name, long value) { return bind(name, boost::lexical_cast<string>(value)); }
  SSqlStatement* bind(const string& name, unsigned long value) { return bind(name, boost::lexical_cast<string>(value)); }
  SSqlStatement* bind(const string& name, long long value) { return bind(name, boost::lexical_cast<string>(value)); }
  SSqlStatement* bind(const string& name, unsigned long long value) { return bind(name, boost::lexical_cast<string>(value)); }
  SSqlStatement* bind(const string& name, const std::string& value) {
    allocate();
    if (d_paridx>=d_nparams) 
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    paramValues[d_paridx] = new char[value.size()+1];
    memset(paramValues[d_paridx], 0, sizeof(char)*(value.size()+1));
    value.copy(paramValues[d_paridx], value.size());
    paramLengths[d_paridx] = value.size();
    d_paridx++;
    return this;
  }
  SSqlStatement* bindNull(const string& name) { d_paridx++; return this; } // these are set null in allocate()
  SSqlStatement* execute() {
    if (d_dolog) {
      L<<Logger::Warning<<"Query: "<<d_query<<endl;
    }
    d_res = PQexecPrepared(d_db, d_stmt.c_str(), d_nparams, paramValues, paramLengths, NULL, 0);
    ExecStatusType status = PQresultStatus(d_res);
    string errmsg(PQresultErrorMessage(d_res));
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK && status != PGRES_NONFATAL_ERROR) {
      string errmsg(PQresultErrorMessage(d_res));
      PQclear(d_res);
      d_res = NULL;
      throw SSqlException("Fatal error during query: " + d_query + string(": ") + errmsg);
    }
    d_resnum = PQntuples(d_res);
    return this;
  }

  bool hasNextRow() 
  {
    return d_residx<d_resnum;
  }

  SSqlStatement* nextRow(row_t& row) {
    int i;
    row.clear();
    if (d_residx>=d_resnum || !d_res) return this;
    row.reserve(PQnfields(d_res));
    for(i=0;i<PQnfields(d_res);i++) {
      if (PQgetisnull(d_res, d_residx, i)) {
        row.push_back("");
      } else {
        row.push_back(string(PQgetvalue(d_res, d_residx, i)));
      }
    }
    d_residx++;
    if (d_residx >= d_resnum) {
      PQclear(d_res);
      d_res = NULL;
    }
    return this;
  }

  SSqlStatement* getResult(result_t& result) {
    result.clear();
    if (d_res == NULL) return this;
    result.reserve(d_resnum);
    row_t row;
    while(hasNextRow()) { nextRow(row); result.push_back(row); }
    return this;
  }

  SSqlStatement* reset() {
     int i;
     if (d_res) 
       PQclear(d_res);
     d_res = NULL;
     d_paridx = d_residx = d_resnum = 0;
     if (paramValues) 
       for(i=0;i<d_nparams;i++) 
         if (paramValues[i]) delete [] paramValues[i];
     delete [] paramValues;
     paramValues = NULL;
     delete [] paramLengths;
     paramLengths = NULL;
     return this;
  }

  const std::string& getQuery() { return d_query; }

  ~SPgSQLStatement() {
    reset();
  }
private:
  void allocate() {
     if (paramValues != NULL) return;
     paramValues = new char*[d_nparams];
     paramLengths = new int[d_nparams];
     memset(paramValues, 0, sizeof(char*)*d_nparams);
     memset(paramLengths, 0, sizeof(int)*d_nparams);
  }

  string d_query;
  string d_stmt;
  PGconn *d_db;
  PGresult *d_res;
  bool d_dolog;
  int d_nparams;
  int d_paridx;
  char **paramValues;
  int *paramLengths;
  int d_residx;
  int d_resnum;
};

bool SPgSQL::s_dolog;

SPgSQL::SPgSQL(const string &database, const string &host, const string& port, const string &user, 
               const string &password)
{
  d_db=0;
  d_connectstr="";

  if (!database.empty())
    d_connectstr+="dbname="+database;

  if (!user.empty())
    d_connectstr+=" user="+user;

  if(!host.empty())
    d_connectstr+=" host="+host;

  if(!port.empty())
    d_connectstr+=" port="+port;

  d_connectlogstr=d_connectstr;

  if(!password.empty()) {
    d_connectlogstr+=" password=<HIDDEN>";
    d_connectstr+=" password="+password;
  }
  
  d_db=PQconnectdb(d_connectstr.c_str());

  if (!d_db || PQstatus(d_db)==CONNECTION_BAD) {
    try {
      throw sPerrorException("Unable to connect to database, connect string: "+d_connectlogstr);
    }
    catch(...) {
      if(d_db)
        PQfinish(d_db);
      d_db = 0;
      throw;
    }
  }
}

void SPgSQL::setLog(bool state)
{
  s_dolog=state;
}

SPgSQL::~SPgSQL()
{
  PQfinish(d_db);
}

SSqlException SPgSQL::sPerrorException(const string &reason)
{
  return SSqlException(reason+string(": ")+(d_db ? PQerrorMessage(d_db) : "no connection"));
}

void SPgSQL::execute(const string& query) 
{
  PGresult* res = PQexec(d_db, query.c_str());
  ExecStatusType status = PQresultStatus(res);
  string errmsg(PQresultErrorMessage(res));
  PQclear(res);
  if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK && status != PGRES_NONFATAL_ERROR) {
    throw sPerrorException("Fatal error during query: " + errmsg);
  }
}

SSqlStatement* SPgSQL::prepare(const string& query, int nparams) 
{
  return new SPgSQLStatement(query, s_dolog, nparams, d_db);
}

void SPgSQL::startTransaction() {
  execute("begin");
}

void SPgSQL::commit() {
  execute("commit");
}

void SPgSQL::rollback() {
  execute("rollback");
}
