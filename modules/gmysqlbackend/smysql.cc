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
#include "smysql.hh"
#include <string>
#include <iostream>
#include "pdns/misc.hh"
#include "pdns/logger.hh"
#include "pdns/dns.hh"
#include "pdns/namespaces.hh"
#include "pdns/lock.hh"

#include <errmsg.h>

#if MYSQL_VERSION_ID >= 80000 && !defined(MARIADB_BASE_VERSION)
// Need to keep this for compatibility with MySQL < 8.0.0, which used typedef char my_bool;
// MariaDB up to 10.4 also always define it.
typedef bool my_bool;
#endif

/*
 * Older versions of the MySQL and MariaDB client leak memory
 * because they expect the application to call mysql_thread_end()
 * when a thread ends. This thread_local static object provides
 * that closure, but only when the user has asked for it
 * by setting gmysql-thread-cleanup.
 * For more discussion, see https://github.com/PowerDNS/pdns/issues/6231
 */
class MySQLThreadCloser
{
public:
  ~MySQLThreadCloser()
  {
    if (d_enabled) {
      mysql_thread_end();
    }
  }
  void enable()
  {
    d_enabled = true;
  }

private:
  bool d_enabled = false;
};

static thread_local MySQLThreadCloser threadcloser;

bool SMySQL::s_dolog;
std::mutex SMySQL::s_myinitlock;

class SMySQLStatement : public SSqlStatement
{
public:
  SMySQLStatement(const string& query, bool dolog, int nparams, MYSQL* db) :
    d_prepared(false)
  {
    d_db = db;
    d_dolog = dolog;
    d_query = query;
    d_paridx = d_fnum = d_resnum = d_residx = 0;
    d_parnum = nparams;
    d_req_bind = d_res_bind = nullptr;
    d_stmt = nullptr;

    if (query.empty()) {
      return;
    }
  }

  SSqlStatement* bind(const string& /* name */, bool value) override
  {
    prepareStatement();
    if (d_paridx >= d_parnum) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_TINY;
    d_req_bind[d_paridx].buffer = new char[1];
    *((char*)d_req_bind[d_paridx].buffer) = (value ? 1 : 0);
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, int value) override
  {
    return bind(name, (long)value);
  }
  SSqlStatement* bind(const string& name, uint32_t value) override
  {
    return bind(name, (unsigned long)value);
  }
  SSqlStatement* bind(const string& /* name */, long value) override
  {
    prepareStatement();
    if (d_paridx >= d_parnum) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    if constexpr (sizeof(long) == 4) {
      d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONG; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    else {
      d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONGLONG; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    d_req_bind[d_paridx].buffer = new long[1];
    *((long*)d_req_bind[d_paridx].buffer) = value;
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& /* name */, unsigned long value) override
  {
    prepareStatement();
    if (d_paridx >= d_parnum) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    if constexpr (sizeof(long) == 4) {
      d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONG; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    else {
      d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONGLONG; // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
    d_req_bind[d_paridx].buffer = new unsigned long[1];
    d_req_bind[d_paridx].is_unsigned = 1;
    *((unsigned long*)d_req_bind[d_paridx].buffer) = value;
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& /* name */, long long value) override
  {
    prepareStatement();
    if (d_paridx >= d_parnum) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONGLONG;
    d_req_bind[d_paridx].buffer = new long long[1];
    *((long long*)d_req_bind[d_paridx].buffer) = value;
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& /* name */, unsigned long long value) override
  {
    prepareStatement();
    if (d_paridx >= d_parnum) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONGLONG;
    d_req_bind[d_paridx].buffer = new unsigned long long[1];
    d_req_bind[d_paridx].is_unsigned = 1;
    *((unsigned long long*)d_req_bind[d_paridx].buffer) = value;
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& /* name */, const std::string& value) override
  {
    prepareStatement();
    if (d_paridx >= d_parnum) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_STRING;
    d_req_bind[d_paridx].buffer = new char[value.size() + 1];
    d_req_bind[d_paridx].length = new unsigned long[1];
    *d_req_bind[d_paridx].length = value.size();
    d_req_bind[d_paridx].buffer_length = *d_req_bind[d_paridx].length + 1;
    memset(d_req_bind[d_paridx].buffer, 0, value.size() + 1);
    value.copy((char*)d_req_bind[d_paridx].buffer, value.size());
    d_paridx++;
    return this;
  }
  SSqlStatement* bindNull(const string& /* name */) override
  {
    prepareStatement();
    if (d_paridx >= d_parnum) {
      releaseStatement();
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    }
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_NULL;
    d_paridx++;
    return this;
  }

  SSqlStatement* execute() override
  {
    prepareStatement();

    if (!d_stmt)
      return this;

    if (d_dolog) {
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_query << endl;
      d_dtime.set();
    }

    if (mysql_stmt_bind_param(d_stmt, d_req_bind) != 0) {
      string error(mysql_stmt_error(d_stmt));
      releaseStatement();
      throw SSqlException("Could not bind mysql statement: " + d_query + string(": ") + error);
    }

    if (mysql_stmt_execute(d_stmt) != 0) {
      auto errorcode = mysql_errno(d_db);
      bool shouldReconnect = errorcode == CR_SERVER_GONE_ERROR || errorcode == CR_SERVER_LOST;
      string error(mysql_stmt_error(d_stmt));
      releaseStatement();
      throw SSqlException("Could not execute mysql statement: " + d_query + string(": ") + error, shouldReconnect);
    }

    // MySQL documentation says you can call this safely for all queries
    if (mysql_stmt_store_result(d_stmt) != 0) {
      string error(mysql_stmt_error(d_stmt));
      releaseStatement();
      throw SSqlException("Could not store mysql statement: " + d_query + string(": ") + error);
    }

    if ((d_fnum = static_cast<int>(mysql_stmt_field_count(d_stmt))) > 0) {
      // prepare for result
      d_resnum = mysql_stmt_num_rows(d_stmt);

      if (d_resnum > 0 && d_res_bind == nullptr) {
        MYSQL_RES* meta = mysql_stmt_result_metadata(d_stmt);
        d_fnum = static_cast<int>(mysql_num_fields(meta)); // ensure correct number of fields
        d_res_bind = new MYSQL_BIND[d_fnum];
        memset(d_res_bind, 0, sizeof(MYSQL_BIND) * d_fnum);
        MYSQL_FIELD* fields = mysql_fetch_fields(meta);

        for (int i = 0; i < d_fnum; i++) {
          unsigned long len = std::max(fields[i].max_length, fields[i].length) + 1;
          if (len > 128 * 1024)
            len = 128 * 1024; // LONGTEXT may tell us it needs 4GB!
          d_res_bind[i].is_null = new my_bool[1];
          d_res_bind[i].error = new my_bool[1];
          d_res_bind[i].length = new unsigned long[1];
          d_res_bind[i].buffer = new char[len];
          d_res_bind[i].buffer_length = len;
          d_res_bind[i].buffer_type = MYSQL_TYPE_STRING;
        }

        mysql_free_result(meta);
      }

      /* we need to bind the results array again because a call to mysql_stmt_next_result() followed
         by a call to mysql_stmt_store_result() might have invalidated it (the first one sets
         stmt->bind_result_done to false, causing the second to reset the existing binding),
         and we can't bind it right after the call to mysql_stmt_store_result() if it returned
         no rows, because then the statement 'contains no metadata' */
      if (d_res_bind != nullptr && mysql_stmt_bind_result(d_stmt, d_res_bind) != 0) {
        string error(mysql_stmt_error(d_stmt));
        releaseStatement();
        throw SSqlException("Could not bind parameters to mysql statement: " + d_query + string(": ") + error);
      }
    }

    if (d_dolog)
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiffNoReset() << " us to execute" << endl;

    return this;
  }

  bool hasNextRow() override
  {
    if (d_dolog && d_residx == d_resnum) {
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiffNoReset() << " us total to last row" << endl;
    }
    return d_residx < d_resnum;
  }

  SSqlStatement* nextRow(row_t& row) override
  {
    int err;
    row.clear();
    if (!hasNextRow()) {
      return this;
    }

    if ((err = mysql_stmt_fetch(d_stmt))) {
      if (err != MYSQL_DATA_TRUNCATED) {
        string error(mysql_stmt_error(d_stmt));
        releaseStatement();
        throw SSqlException("Could not fetch result: " + d_query + string(": ") + error);
      }
    }

    row.reserve(d_fnum);

    for (int i = 0; i < d_fnum; i++) {
      if (err == MYSQL_DATA_TRUNCATED && *d_res_bind[i].error) {
        g_log << Logger::Warning << "Result field at row " << d_residx << " column " << i << " has been truncated, we allocated " << d_res_bind[i].buffer_length << " bytes but at least " << *d_res_bind[i].length << " was needed" << endl;
      }
      if (*d_res_bind[i].is_null) {
        row.emplace_back("");
        continue;
      }
      else {
        row.emplace_back((char*)d_res_bind[i].buffer, std::min(d_res_bind[i].buffer_length, *d_res_bind[i].length));
      }
    }

    d_residx++;
#if MYSQL_VERSION_ID >= 50500
    if (d_residx >= d_resnum) {
      mysql_stmt_free_result(d_stmt);
      while (!mysql_stmt_next_result(d_stmt)) {
        if (mysql_stmt_store_result(d_stmt) != 0) {
          string error(mysql_stmt_error(d_stmt));
          releaseStatement();
          throw SSqlException("Could not store mysql statement while processing additional sets: " + d_query + string(": ") + error);
        }
        d_resnum = mysql_stmt_num_rows(d_stmt);
        // XXX: For some reason mysql_stmt_result_metadata returns NULL here, so we cannot
        // ensure row field count matches first result set.
        // We need to check the field count as stored procedure return the final values of OUT and INOUT parameters
        // as an extra single-row result set following any result sets produced by the procedure itself.
        // mysql_stmt_field_count() will return 0 for those.
        if (mysql_stmt_field_count(d_stmt) > 0 && d_resnum > 0) { // ignore empty result set
          if (d_res_bind != nullptr && mysql_stmt_bind_result(d_stmt, d_res_bind) != 0) {
            string error(mysql_stmt_error(d_stmt));
            releaseStatement();
            throw SSqlException("Could not bind parameters to mysql statement: " + d_query + string(": ") + error);
          }
          d_residx = 0;
          break;
        }
        mysql_stmt_free_result(d_stmt);
      }
    }
#endif
    return this;
  }

  SSqlStatement* getResult(result_t& result) override
  {
    result.clear();
    result.reserve(d_resnum);
    row_t row;

    while (hasNextRow()) {
      nextRow(row);
      result.push_back(std::move(row));
    }

    return this;
  }

  SSqlStatement* reset() override
  {
    if (!d_stmt)
      return this;
    int err = 0;
    mysql_stmt_free_result(d_stmt);
#if MYSQL_VERSION_ID >= 50500
    while ((err = mysql_stmt_next_result(d_stmt)) == 0) {
      mysql_stmt_free_result(d_stmt);
    }
#endif
    if (err > 0) {
      string error(mysql_stmt_error(d_stmt));
      releaseStatement();
      throw SSqlException("Could not get next result from mysql statement: " + d_query + string(": ") + error);
    }
    mysql_stmt_reset(d_stmt);
    if (d_req_bind) {
      for (int i = 0; i < d_parnum; i++) {
        if (d_req_bind[i].buffer)
          delete[] (char*)d_req_bind[i].buffer;
        if (d_req_bind[i].length)
          delete[] d_req_bind[i].length;
      }
      memset(d_req_bind, 0, sizeof(MYSQL_BIND) * d_parnum);
    }
    d_residx = d_resnum = 0;
    d_paridx = 0;
    return this;
  }

  const std::string& getQuery() override { return d_query; }

  ~SMySQLStatement() override
  {
    releaseStatement();
  }

private:
  void prepareStatement()
  {
    if (d_prepared)
      return;
    if (d_query.empty()) {
      d_prepared = true;
      return;
    }

    if ((d_stmt = mysql_stmt_init(d_db)) == nullptr)
      throw SSqlException("Could not initialize mysql statement, out of memory: " + d_query);

    if (mysql_stmt_prepare(d_stmt, d_query.c_str(), d_query.size()) != 0) {
      string error(mysql_stmt_error(d_stmt));
      releaseStatement();
      throw SSqlException("Could not prepare statement: " + d_query + string(": ") + error);
    }

    if (static_cast<int>(mysql_stmt_param_count(d_stmt)) != d_parnum) {
      releaseStatement();
      throw SSqlException("Provided parameter count does not match statement: " + d_query);
    }

    if (d_parnum > 0) {
      d_req_bind = new MYSQL_BIND[d_parnum];
      memset(d_req_bind, 0, sizeof(MYSQL_BIND) * d_parnum);
    }

    d_prepared = true;
  }

  void releaseStatement()
  {
    d_prepared = false;
    if (d_stmt)
      mysql_stmt_close(d_stmt);
    d_stmt = nullptr;
    if (d_req_bind) {
      for (int i = 0; i < d_parnum; i++) {
        if (d_req_bind[i].buffer)
          delete[] (char*)d_req_bind[i].buffer;
        if (d_req_bind[i].length)
          delete[] d_req_bind[i].length;
      }
      delete[] d_req_bind;
      d_req_bind = nullptr;
    }
    if (d_res_bind) {
      for (int i = 0; i < d_fnum; i++) {
        if (d_res_bind[i].buffer)
          delete[] (char*)d_res_bind[i].buffer;
        if (d_res_bind[i].length)
          delete[] d_res_bind[i].length;
        if (d_res_bind[i].error)
          delete[] d_res_bind[i].error;
        if (d_res_bind[i].is_null)
          delete[] d_res_bind[i].is_null;
      }
      delete[] d_res_bind;
      d_res_bind = nullptr;
    }
    d_paridx = d_fnum = d_resnum = d_residx = 0;
  }
  MYSQL* d_db;

  MYSQL_STMT* d_stmt;
  MYSQL_BIND* d_req_bind;
  MYSQL_BIND* d_res_bind;

  string d_query;

  bool d_prepared;
  bool d_dolog;
  DTime d_dtime; // only used if d_dolog is set
  int d_parnum;
  int d_paridx;
  int d_fnum;
  int d_resnum;
  int d_residx;
};

void SMySQL::connect()
{
  int retry = 1;

  {
    auto lock = std::scoped_lock(s_myinitlock);
    if (d_threadCleanup) {
      threadcloser.enable();
    }

    if (!mysql_init(&d_db)) {
      throw sPerrorException("Unable to initialize mysql driver");
    }
  }

  do {

#if MYSQL_VERSION_ID >= 50100
    if (d_timeout) {
      mysql_options(&d_db, MYSQL_OPT_READ_TIMEOUT, &d_timeout);
      mysql_options(&d_db, MYSQL_OPT_WRITE_TIMEOUT, &d_timeout);
      mysql_options(&d_db, MYSQL_OPT_CONNECT_TIMEOUT, &d_timeout);
    }
#endif

    if (d_setIsolation && (retry == 1))
      mysql_options(&d_db, MYSQL_INIT_COMMAND, "SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED");

    mysql_options(&d_db, MYSQL_READ_DEFAULT_GROUP, d_group.c_str());

    if (!mysql_real_connect(&d_db, d_host.empty() ? nullptr : d_host.c_str(),
                            d_user.empty() ? nullptr : d_user.c_str(),
                            d_password.empty() ? nullptr : d_password.c_str(),
                            d_database.empty() ? nullptr : d_database.c_str(),
                            d_port,
                            d_msocket.empty() ? nullptr : d_msocket.c_str(),
                            CLIENT_MULTI_RESULTS)) {

      if (retry == 0)
        throw sPerrorException("Unable to connect to database");
      --retry;
    }
    else {
      if (retry == 0) {
        mysql_close(&d_db);
        throw sPerrorException("Please add '(gmysql-)innodb-read-committed=no' to your PowerDNS configuration, and reconsider your storage engine if it does not support transactions.");
      }
      retry = -1;
    }
  } while (retry >= 0);
}

SMySQL::SMySQL(string database, string host, uint16_t port, string msocket, string user,
               string password, string group, bool setIsolation, unsigned int timeout, bool threadCleanup) :
  d_database(std::move(database)), d_host(std::move(host)), d_msocket(std::move(msocket)), d_user(std::move(user)), d_password(std::move(password)), d_group(std::move(group)), d_timeout(timeout), d_port(port), d_setIsolation(setIsolation), d_threadCleanup(threadCleanup)
{
  connect();
}

void SMySQL::setLog(bool state)
{
  s_dolog = state;
}

SMySQL::~SMySQL()
{
  mysql_close(&d_db);
}

SSqlException SMySQL::sPerrorException(const string& reason)
{
  return SSqlException(reason + string(": ERROR ") + std::to_string(mysql_errno(&d_db)) + " (" + string(mysql_sqlstate(&d_db)) + "): " + mysql_error(&d_db));
}

std::unique_ptr<SSqlStatement> SMySQL::prepare(const string& query, int nparams)
{
  return std::make_unique<SMySQLStatement>(query, s_dolog, nparams, &d_db);
}

void SMySQL::execute(const string& query)
{
  if (s_dolog)
    g_log << Logger::Warning << "Query: " << query << endl;

  int err;
  if ((err = mysql_query(&d_db, query.c_str())))
    throw sPerrorException("Failed to execute mysql_query '" + query + "' Err=" + std::to_string(err));
}

void SMySQL::startTransaction()
{
  execute("begin");
}

void SMySQL::commit()
{
  execute("commit");
}

void SMySQL::rollback()
{
  execute("rollback");
}

bool SMySQL::isConnectionUsable()
{
  bool usable = false;
  int sd = d_db.net.fd;
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
