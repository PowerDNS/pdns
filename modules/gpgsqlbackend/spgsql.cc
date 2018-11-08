/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <string>
#include "spgsql.hh"
#include <sys/time.h>
#include <iostream>
#include "pdns/logger.hh"
#include "pdns/dns.hh"
#include "pdns/namespaces.hh"
#include <algorithm>

class SPgSQLStatement: public SSqlStatement
{
public:
  SPgSQLStatement(const string& query, bool dolog, int nparams, SPgSQL* db, unsigned int nstatement) {
    d_query = query;
    d_dolog = dolog;
    d_parent = db;
    d_prepared = false;
    d_nparams = nparams;
    d_res = NULL;
    d_res_set = NULL;
    paramValues = NULL;
    paramLengths = NULL;
    d_nstatement = nstatement;
    d_paridx = 0;
    d_residx = 0;
    d_resnum = 0;
    d_fnum = 0;
    d_cur_set = 0;
  }

  SSqlStatement* bind(const string& name, bool value) { return bind(name, string(value ? "t" : "f")); }
  SSqlStatement* bind(const string& name, int value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, uint32_t value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, long value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, unsigned long value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, long long value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, unsigned long long value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, const std::string& value) {
    prepareStatement();
    allocate();
    if (d_paridx>=d_nparams) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    paramValues[d_paridx] = new char[value.size()+1];
    memset(paramValues[d_paridx], 0, sizeof(char)*(value.size()+1));
    value.copy(paramValues[d_paridx], value.size());
    paramLengths[d_paridx] = value.size();
    d_paridx++;
    return this;
  }
  SSqlStatement* bindNull(const string& name) { prepareStatement(); d_paridx++; return this; } // these are set null in allocate()
  SSqlStatement* execute() {
    prepareStatement();
    if (d_dolog) {
      g_log<<Logger::Warning<< "Query "<<((long)(void*)this)<<": " << d_query << endl;
      d_dtime.set();
    }
    d_res_set = PQexecPrepared(d_db(), d_stmt.c_str(), d_nparams, paramValues, paramLengths, NULL, 0);
    ExecStatusType status = PQresultStatus(d_res_set);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK && status != PGRES_NONFATAL_ERROR) {
      string errmsg(PQresultErrorMessage(d_res_set));
      releaseStatement();
      throw SSqlException("Fatal error during query: " + d_query + string(": ") + errmsg);
    }
    d_cur_set = 0;
    if(d_dolog) {
      auto diff = d_dtime.udiffNoReset();
      g_log<<Logger::Warning<< "Query "<<((long)(void*)this)<<": "<< diff <<" usec to execute"<<endl;
    }

    nextResult();
    return this;
  }

  void nextResult() {
    if (d_res_set == NULL) return; // no refcursor
    if (d_cur_set >= PQntuples(d_res_set)) {
      PQclear(d_res_set);
      d_res_set = NULL;
      return;
    }
    // this code handles refcursors if they are returned
    // by stored procedures. you can return more than one
    // if you return SETOF refcursor.
    if (PQftype(d_res_set, 0) == 1790) { // REFCURSOR
#if PG_VERSION_NUM > 90000
      // PQescapeIdentifier was added to libpq in postgresql 9.0
      char *val = PQgetvalue(d_res_set, d_cur_set++, 0);
      char *portal =  PQescapeIdentifier(d_db(), val, strlen(val));
      string cmd = string("FETCH ALL FROM \"") + string(portal) + string("\"");
      PQfreemem(portal);
#else
      string portal = string(PQgetvalue(d_res_set, d_cur_set++, 0));
      string cmd = string("FETCH ALL FROM \"") + portal + string("\"");
#endif
      // execute FETCH
      if (d_dolog)
         g_log<<Logger::Warning<<"Query: "<<cmd<<endl;
      d_res = PQexec(d_db(),cmd.c_str());
      d_resnum = PQntuples(d_res);
      d_fnum = PQnfields(d_res);
      d_residx = 0;
    } else {
      d_res = d_res_set;
      d_res_set = NULL;
      d_resnum = PQntuples(d_res);
      d_fnum = PQnfields(d_res);
    }
  }

  bool hasNextRow()
  {
    if(d_dolog && d_residx == d_resnum) {
      g_log<<Logger::Warning<< "Query "<<((long)(void*)this)<<": "<<d_dtime.udiff()<<" total usec to last row"<<endl;
    }

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
      } else if (PQftype(d_res, i) == 16) { // BOOLEAN
        char *val = PQgetvalue(d_res, d_residx, i);
        row.push_back(val[0] == 't' ? "1" : "0");
      } else {
        row.push_back(string(PQgetvalue(d_res, d_residx, i)));
      }
    }
    d_residx++;
    if (d_residx >= d_resnum) {
      PQclear(d_res);
      d_res = NULL;
      nextResult();
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
     if (d_res_set)
       PQclear(d_res_set);
     d_res_set = NULL;
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
    releaseStatement();
  }
private:
  PGconn* d_db() {
    return d_parent->db();
  }

  void releaseStatement() {
    d_prepared = false;
    reset();
    if (!d_stmt.empty()) {
      string cmd = string("DEALLOCATE " + d_stmt);
      PGresult *res = PQexec(d_db(), cmd.c_str());
      PQclear(res);
      d_stmt.clear();
    }
  }

  void prepareStatement() {
    if (d_prepared) return;
    // prepare a statement; name must be unique per session (using d_nstatement to ensure this).
    this->d_stmt = string("stmt") + std::to_string(d_nstatement);
    PGresult* res = PQprepare(d_db(), d_stmt.c_str(), d_query.c_str(), d_nparams, NULL);
    ExecStatusType status = PQresultStatus(res);
    string errmsg(PQresultErrorMessage(res));
    PQclear(res);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK && status != PGRES_NONFATAL_ERROR) {
      releaseStatement();
      throw SSqlException("Fatal error during prepare: " + d_query + string(": ") + errmsg);
    }
    paramValues=NULL;
    d_cur_set=d_paridx=d_residx=d_resnum=d_fnum=0;
    paramLengths=NULL;
    d_res=NULL;
    d_res_set=NULL;
    d_prepared = true;
  }

  void allocate() {
     if (paramValues != NULL) return;
     paramValues = new char*[d_nparams];
     paramLengths = new int[d_nparams];
     memset(paramValues, 0, sizeof(char*)*d_nparams);
     memset(paramLengths, 0, sizeof(int)*d_nparams);
  }

  string d_query;
  string d_stmt;
  SPgSQL *d_parent;
  PGresult *d_res_set;
  PGresult *d_res;
  bool d_dolog;
  DTime d_dtime; // only used if d_dolog is set
  bool d_prepared;
  int d_nparams;
  int d_paridx;
  char **paramValues;
  int *paramLengths;
  int d_residx;
  int d_resnum;
  int d_fnum;
  int d_cur_set;
  unsigned int d_nstatement;
};

bool SPgSQL::s_dolog;

SPgSQL::SPgSQL(const string &database, const string &host, const string& port, const string &user,
               const string &password, const string &extra_connection_parameters)
{
  d_db=0;
  d_in_trx = false;
  d_connectstr="";
  d_nstatement = 0;

  if (!database.empty())
    d_connectstr+="dbname="+database;

  if (!user.empty())
    d_connectstr+=" user="+user;

  if(!host.empty())
    d_connectstr+=" host="+host;

  if(!port.empty())
    d_connectstr+=" port="+port;

  if(!extra_connection_parameters.empty())
    d_connectstr+=" " + extra_connection_parameters;

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

std::unique_ptr<SSqlStatement> SPgSQL::prepare(const string& query, int nparams)
{
  d_nstatement++;
  return std::unique_ptr<SSqlStatement>(new SPgSQLStatement(query, s_dolog, nparams, this, d_nstatement));
}

void SPgSQL::startTransaction() {
  execute("begin");
  d_in_trx = true;
}

void SPgSQL::commit() {
  execute("commit");
  d_in_trx = false;
}

void SPgSQL::rollback() {
  execute("rollback");
  d_in_trx = false;
}

bool SPgSQL::isConnectionUsable()
{
  if (PQstatus(d_db) != CONNECTION_OK) {
    return false;
  }

  bool usable = false;
  int sd = PQsocket(d_db);
  bool wasNonBlocking = isNonBlocking(sd);

  if (!wasNonBlocking) {
    if (!setNonBlocking(sd)) {
      return usable;
    }
  }

  usable = isTCPSocketUsable(sd);

  if (!wasNonBlocking) {
    if (!setBlocking(sd)) {
      usable = false;
    }
  }

  return usable;
}

void SPgSQL::reconnect()
{
  PQreset(d_db);
}
