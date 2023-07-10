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

class SPgSQLStatement : public SSqlStatement
{
public:
  SPgSQLStatement(const string& query, bool dolog, int nparams, SPgSQL* db, unsigned int nstatement)
  {
    d_query = query;
    d_dolog = dolog;
    d_parent = db;
    d_nparams = nparams;
    d_nstatement = nstatement;
  }

  SSqlStatement* bind(const string& name, bool value) { return bind(name, string(value ? "t" : "f")); }
  SSqlStatement* bind(const string& name, int value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, uint32_t value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, long value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, unsigned long value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, long long value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& name, unsigned long long value) { return bind(name, std::to_string(value)); }
  SSqlStatement* bind(const string& /* name */, const std::string& value)
  {
    prepareStatement();
    allocate();
    if (d_paridx >= d_nparams) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    paramValues[d_paridx] = new char[value.size() + 1];
    memset(paramValues[d_paridx], 0, sizeof(char) * (value.size() + 1));
    value.copy(paramValues[d_paridx], value.size());
    paramLengths[d_paridx] = value.size();
    d_paridx++;
    return this;
  }
  SSqlStatement* bindNull(const string& /* name */)
  {
    prepareStatement();
    d_paridx++;
    return this;
  } // these are set null in allocate()
  SSqlStatement* execute()
  {
    prepareStatement();
    if (d_dolog) {
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": Statement: " << d_query << endl;
      if (d_paridx) {
        // Log message is similar, but not exactly the same as the postgres server log.
        std::stringstream log_message;
        log_message << "Query " << ((long)(void*)this) << ": Parameters: ";
        for (int i = 0; i < d_paridx; i++) {
          if (i != 0) {
            log_message << ", ";
          }
          log_message << "$" << (i + 1) << " = ";
          if (paramValues[i] == nullptr) {
            log_message << "NULL";
          }
          else {
            log_message << "'" << paramValues[i] << "'";
          }
        }
        g_log << Logger::Warning << log_message.str() << endl;
      }
      d_dtime.set();
    }
    if (!d_stmt.empty()) {
      d_res_set = PQexecPrepared(d_db(), d_stmt.c_str(), d_nparams, paramValues, paramLengths, nullptr, 0);
    }
    else {
      d_res_set = PQexecParams(d_db(), d_query.c_str(), d_nparams, nullptr, paramValues, paramLengths, nullptr, 0);
    }
    ExecStatusType status = PQresultStatus(d_res_set);
    if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK && status != PGRES_NONFATAL_ERROR) {
      string errmsg(PQresultErrorMessage(d_res_set));
      releaseStatement();
      throw SSqlException("Fatal error during query: " + d_query + string(": ") + errmsg);
    }
    d_cur_set = 0;
    if (d_dolog) {
      auto diff = d_dtime.udiffNoReset();
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << diff << " us to execute" << endl;
    }

    nextResult();
    return this;
  }

  void nextResult()
  {
    if (d_res_set == nullptr)
      return;
    if (d_cur_set >= PQntuples(d_res_set)) {
      PQclear(d_res_set);
      d_res_set = nullptr;
      return;
    }
    if (PQftype(d_res_set, 0) == 1790) { // REFCURSOR
      g_log << Logger::Error << "Postgres query returned a REFCURSOR and we do not support those - see https://github.com/PowerDNS/pdns/pull/10259" << endl;
      PQclear(d_res_set);
      d_res_set = nullptr;
    }
    else {
      d_res = d_res_set;
      d_res_set = nullptr;
      d_resnum = PQntuples(d_res);
    }
  }

  bool hasNextRow()
  {
    if (d_dolog && d_residx == d_resnum) {
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiff() << " us total to last row" << endl;
    }

    return d_residx < d_resnum;
  }

  SSqlStatement* nextRow(row_t& row)
  {
    int i;
    row.clear();
    if (d_residx >= d_resnum || !d_res)
      return this;
    row.reserve(PQnfields(d_res));
    for (i = 0; i < PQnfields(d_res); i++) {
      if (PQgetisnull(d_res, d_residx, i)) {
        row.emplace_back("");
      }
      else if (PQftype(d_res, i) == 16) { // BOOLEAN
        char* val = PQgetvalue(d_res, d_residx, i);
        row.emplace_back(val[0] == 't' ? "1" : "0");
      }
      else {
        row.emplace_back(PQgetvalue(d_res, d_residx, i));
      }
    }
    d_residx++;
    if (d_residx >= d_resnum) {
      PQclear(d_res);
      d_res = nullptr;
      nextResult();
    }
    return this;
  }

  SSqlStatement* getResult(result_t& result)
  {
    result.clear();
    if (d_res == nullptr)
      return this;
    result.reserve(d_resnum);
    row_t row;
    while (hasNextRow()) {
      nextRow(row);
      result.push_back(std::move(row));
    }
    return this;
  }

  SSqlStatement* reset()
  {
    int i;
    if (d_res) {
      PQclear(d_res);
    }
    if (d_res_set) {
      PQclear(d_res_set);
    }
    d_res_set = nullptr;
    d_res = nullptr;
    d_paridx = d_residx = d_resnum = 0;
    if (paramValues) {
      for (i = 0; i < d_nparams; i++) {
        if (paramValues[i]) {
          delete[] paramValues[i];
        }
      }
    }
    delete[] paramValues;
    paramValues = nullptr;
    delete[] paramLengths;
    paramLengths = nullptr;
    return this;
  }

  const std::string& getQuery() { return d_query; }

  ~SPgSQLStatement()
  {
    releaseStatement();
  }

private:
  PGconn* d_db()
  {
    return d_parent->db();
  }

  void releaseStatement()
  {
    d_prepared = false;
    reset();
    if (!d_stmt.empty()) {
      string cmd = string("DEALLOCATE " + d_stmt);
      PGresult* res = PQexec(d_db(), cmd.c_str());
      PQclear(res);
      d_stmt.clear();
    }
  }

  void prepareStatement()
  {
    if (d_prepared)
      return;
    if (d_parent->usePrepared()) {
      // prepare a statement; name must be unique per session (using d_nstatement to ensure this).
      this->d_stmt = string("stmt") + std::to_string(d_nstatement);
      PGresult* res = PQprepare(d_db(), d_stmt.c_str(), d_query.c_str(), d_nparams, nullptr);
      ExecStatusType status = PQresultStatus(res);
      string errmsg(PQresultErrorMessage(res));
      PQclear(res);
      if (status != PGRES_COMMAND_OK && status != PGRES_TUPLES_OK && status != PGRES_NONFATAL_ERROR) {
        releaseStatement();
        throw SSqlException("Fatal error during prePQpreparepare: " + d_query + string(": ") + errmsg);
      }
    }
    paramValues = nullptr;
    paramLengths = nullptr;
    d_cur_set = d_paridx = d_residx = d_resnum = 0;
    d_res = nullptr;
    d_res_set = nullptr;
    d_prepared = true;
  }

  void allocate()
  {
    if (paramValues != nullptr)
      return;
    paramValues = new char*[d_nparams];
    paramLengths = new int[d_nparams];
    memset(paramValues, 0, sizeof(char*) * d_nparams);
    memset(paramLengths, 0, sizeof(int) * d_nparams);
  }

  string d_query;
  string d_stmt;
  SPgSQL* d_parent;
  PGresult* d_res_set{nullptr};
  PGresult* d_res{nullptr};
  bool d_dolog;
  DTime d_dtime; // only used if d_dolog is set
  bool d_prepared{false};
  int d_nparams;
  int d_paridx{0};
  char** paramValues{nullptr};
  int* paramLengths{nullptr};
  int d_residx{0};
  int d_resnum{0};
  int d_cur_set{0};
  unsigned int d_nstatement;
};

bool SPgSQL::s_dolog;

static string escapeForPQparam(const string& v)
{
  string ret = v;
  boost::replace_all(ret, "\\", "\\\\");
  boost::replace_all(ret, "'", "\\'");

  return string("'") + ret + string("'");
}

SPgSQL::SPgSQL(const string& database, const string& host, const string& port, const string& user,
               const string& password, const string& extra_connection_parameters, const bool use_prepared)
{
  d_db = nullptr;
  d_in_trx = false;
  d_connectstr = "";
  d_nstatements = 0;

  if (!database.empty())
    d_connectstr += "dbname=" + escapeForPQparam(database);

  if (!user.empty())
    d_connectstr += " user=" + escapeForPQparam(user);

  if (!host.empty())
    d_connectstr += " host=" + escapeForPQparam(host);

  if (!port.empty())
    d_connectstr += " port=" + escapeForPQparam(port);

  if (!extra_connection_parameters.empty())
    d_connectstr += " " + extra_connection_parameters;

  d_connectlogstr = d_connectstr;

  if (!password.empty()) {
    d_connectlogstr += " password=<HIDDEN>";
    d_connectstr += " password=" + escapeForPQparam(password);
  }

  d_use_prepared = use_prepared;

  d_db = PQconnectdb(d_connectstr.c_str());

  if (!d_db || PQstatus(d_db) == CONNECTION_BAD) {
    try {
      throw sPerrorException("Unable to connect to database, connect string: " + d_connectlogstr);
    }
    catch (...) {
      if (d_db)
        PQfinish(d_db);
      d_db = 0;
      throw;
    }
  }
}

void SPgSQL::setLog(bool state)
{
  s_dolog = state;
}

SPgSQL::~SPgSQL()
{
  PQfinish(d_db);
}

SSqlException SPgSQL::sPerrorException(const string& reason)
{
  return SSqlException(reason + string(": ") + (d_db ? PQerrorMessage(d_db) : "no connection"));
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
  d_nstatements++;
  return std::make_unique<SPgSQLStatement>(query, s_dolog, nparams, this, d_nstatements);
}

void SPgSQL::startTransaction()
{
  execute("begin");
  d_in_trx = true;
}

void SPgSQL::commit()
{
  execute("commit");
  d_in_trx = false;
}

void SPgSQL::rollback()
{
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
