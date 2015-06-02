/* Copyright 2001 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE
   for more information.
   $Id$  */
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

bool SMySQL::s_dolog;
pthread_mutex_t SMySQL::s_myinitlock = PTHREAD_MUTEX_INITIALIZER;

class SMySQLStatement: public SSqlStatement
{
public:
  SMySQLStatement(const string& query, bool dolog, int nparams, MYSQL* db) 
  {
    int err;
    d_db = db;
    d_dolog = dolog;
    d_query = query;
    d_parnum = d_paridx = d_fnum = d_resnum = d_residx = 0;
    d_req_bind = d_res_bind = NULL;
    d_stmt = NULL;

    if (query.empty()) {
      return;
    }

    if ((d_stmt = mysql_stmt_init(d_db))==NULL) 
      throw SSqlException("Could not initialize mysql statement, out of memory: " + d_query);
    
    if ((err = mysql_stmt_prepare(d_stmt, query.c_str(), query.size()))) {
      string error(mysql_stmt_error(d_stmt));
      throw SSqlException("Could not prepare statement: " + d_query + string(": ") + error);
    }

    if (static_cast<int>(mysql_stmt_param_count(d_stmt)) != nparams) 
      throw SSqlException("Provided parameter count does not match statement: " + d_query);
   
    d_parnum = nparams;
    if (d_parnum>0) {
      d_req_bind = new MYSQL_BIND[d_parnum];
      memset(d_req_bind, 0, sizeof(MYSQL_BIND)*d_parnum);
    }
  }

  SSqlStatement* bind(const string& name, bool value) {
    if (d_paridx >= d_parnum) 
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_TINY;
    d_req_bind[d_paridx].buffer = new char[1];
    *((char*)d_req_bind[d_paridx].buffer) = (value?1:0);
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, int value) {
    return bind(name, (long)value);
  }
  SSqlStatement* bind(const string& name, uint32_t value) {
    return bind(name, (unsigned long)value);
  }
  SSqlStatement* bind(const string& name, long value) {
    if (d_paridx >= d_parnum)
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONG;
    d_req_bind[d_paridx].buffer = new long[1];
    *((long*)d_req_bind[d_paridx].buffer) = value;
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, unsigned long value) {
    if (d_paridx >= d_parnum)
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONG;
    d_req_bind[d_paridx].buffer = new unsigned long[1];
    d_req_bind[d_paridx].is_unsigned = 1;
    *((unsigned long*)d_req_bind[d_paridx].buffer) = value;
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, long long value) {
    if (d_paridx >= d_parnum)
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONGLONG;
    d_req_bind[d_paridx].buffer = new long long[1];
    *((long long*)d_req_bind[d_paridx].buffer) = value;
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, unsigned long long value) {
    if (d_paridx >= d_parnum)
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_LONGLONG;
    d_req_bind[d_paridx].buffer = new unsigned long long[1];
    d_req_bind[d_paridx].is_unsigned = 1;
    *((unsigned long long*)d_req_bind[d_paridx].buffer) = value;
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, const std::string& value) {
    if (d_paridx >= d_parnum)
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_STRING;
    d_req_bind[d_paridx].buffer = new char[value.size()+1];
    d_req_bind[d_paridx].length = new unsigned long[1];
    *d_req_bind[d_paridx].length = value.size();
    d_req_bind[d_paridx].buffer_length = *d_req_bind[d_paridx].length+1;
    memset(d_req_bind[d_paridx].buffer, 0, value.size()+1);
    value.copy((char*)d_req_bind[d_paridx].buffer, value.size());
    d_paridx++;
    return this;
  }
  SSqlStatement* bindNull(const string& name) { 
    if (d_paridx >= d_parnum)
      throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    d_req_bind[d_paridx].buffer_type = MYSQL_TYPE_NULL;
    d_paridx++;
    return this;
  }

  SSqlStatement* execute() {
    int err;

    if (!d_stmt) return this;

    if (d_dolog) {
      L<<Logger::Warning<<"Query: " << d_query <<endl;
    }

    if ((err = mysql_stmt_bind_param(d_stmt, d_req_bind))) {
      string error(mysql_stmt_error(d_stmt));
      throw SSqlException("Could not bind mysql statement: " + d_query + string(": ") + error);
    }

    if ((err = mysql_stmt_execute(d_stmt))) {
      string error(mysql_stmt_error(d_stmt));
      throw SSqlException("Could not execute mysql statement: " + d_query + string(": ") + error);
    }

    if ((d_fnum = static_cast<int>(mysql_stmt_field_count(d_stmt)))>0) {
      // prepare for result
      if ((err = mysql_stmt_store_result(d_stmt))) {
        string error(mysql_stmt_error(d_stmt));
        throw SSqlException("Could not store mysql statement: " + d_query + string(": ") + error);
      }
      d_resnum = mysql_stmt_num_rows(d_stmt);
      
      if (d_resnum>0 && d_res_bind == NULL) {
        d_res_bind = new MYSQL_BIND[d_fnum];
        memset(d_res_bind, 0, sizeof(MYSQL_BIND)*d_fnum);
        MYSQL_RES* meta = mysql_stmt_result_metadata(d_stmt);
        MYSQL_FIELD* fields = mysql_fetch_fields(meta);

        for(int i = 0; i < d_fnum; i++) {
          unsigned long len = std::max(fields[i].max_length, fields[i].length)+1;
          d_res_bind[i].is_null = new my_bool[1];
          d_res_bind[i].error = new my_bool[1];
          d_res_bind[i].length = new unsigned long[1];
          d_res_bind[i].buffer = new char[len];
          d_res_bind[i].buffer_length = len;
          d_res_bind[i].buffer_type = MYSQL_TYPE_STRING;
        }
  
        mysql_free_result(meta);
  
        if ((err = mysql_stmt_bind_result(d_stmt, d_res_bind))) {
          string error(mysql_stmt_error(d_stmt));
          throw SSqlException("Could not bind parameters to mysql statement: " + d_query + string(": ") + error);
        }
      }
    }

    return this;
  }

  bool hasNextRow() {
    return d_residx < d_resnum;
  }

  SSqlStatement* nextRow(row_t& row) {
    int err;
    row.clear();
    if (d_residx >= d_resnum) return this;

    if ((err =mysql_stmt_fetch(d_stmt))) {
      if (err != MYSQL_DATA_TRUNCATED) {
        string error(mysql_stmt_error(d_stmt));
        throw SSqlException("Could not fetch result: " + d_query + string(": ") + error);
      }
    }

    row.reserve(d_fnum);

    for(int i=0;i<d_fnum;i++) {
      if (*d_res_bind[i].error) {
        L<<Logger::Warning<<"Result field at row " << d_residx << " column " << i << " has errno " << *d_res_bind[i].error << endl;
      }
      if (*d_res_bind[i].is_null) {
        row.push_back("");
        continue;
      } else {
        row.push_back(string((char*)d_res_bind[i].buffer, std::min(d_res_bind[i].buffer_length, *d_res_bind[i].length)));
      }
    }

    d_residx++;
    return this; 
  }

  SSqlStatement* getResult(result_t& result) { 
    result.clear();
    result.reserve(d_resnum);
    row_t row;

    while(hasNextRow()) {
      nextRow(row);
      result.push_back(row); 
    }

    return this; 
  }

  SSqlStatement* reset() {
    if (!d_stmt) return this;

    mysql_stmt_reset(d_stmt);
    if (d_req_bind) {
      for(int i=0;i<d_parnum;i++) {
        if (d_req_bind[i].buffer) delete [] (char*)d_req_bind[i].buffer;
        if (d_req_bind[i].length) delete [] d_req_bind[i].length;
      }
      memset(d_req_bind, 0, sizeof(MYSQL_BIND)*d_parnum);
    }
    d_residx = d_resnum = 0;
    d_paridx = 0;
    return this;
  }

  const std::string& getQuery() { return d_query; }

  ~SMySQLStatement() {
    if (d_stmt)
      mysql_stmt_close(d_stmt);
    d_stmt = NULL;
    if (d_req_bind) {
      for(int i=0;i<d_parnum;i++) {
        if (d_req_bind[i].buffer) delete [] (char*)d_req_bind[i].buffer;
        if (d_req_bind[i].length) delete [] d_req_bind[i].length;
      }
      delete [] d_req_bind;
      d_req_bind = NULL;
    }
    if (d_res_bind) {
      for(int i=0;i<d_fnum;i++) {
        if (d_res_bind[i].buffer) delete [] (char*)d_res_bind[i].buffer;
        if (d_res_bind[i].length) delete [] d_res_bind[i].length;
        if (d_res_bind[i].is_null) delete [] d_res_bind[i].is_null;
      }
      delete [] d_res_bind;
      d_res_bind = NULL;
    }
  }
private:
  MYSQL* d_db;

  MYSQL_STMT* d_stmt;
  MYSQL_BIND* d_req_bind;
  MYSQL_BIND* d_res_bind;

  string d_query;
  
  bool d_dolog;
  int d_parnum;
  int d_paridx;
  int d_fnum;
  int d_resnum;
  int d_residx;
};

SMySQL::SMySQL(const string &database, const string &host, uint16_t port, const string &msocket, const string &user,
               const string &password, const string &group, bool setIsolation)
{
  int retry=1;

  Lock l(&s_myinitlock);
  if (!mysql_init(&d_db))
    throw sPerrorException("Unable to initialize mysql driver");

  do {

#if MYSQL_VERSION_ID >= 50013
    my_bool reconnect = 1;
    mysql_options(&d_db, MYSQL_OPT_RECONNECT, &reconnect);
#endif

#if MYSQL_VERSION_ID >= 50100
    unsigned int timeout = 10;
    mysql_options(&d_db, MYSQL_OPT_READ_TIMEOUT, &timeout);
    mysql_options(&d_db, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
#endif

#if MYSQL_VERSION_ID >= 50500
    mysql_options(&d_db, MYSQL_SET_CHARSET_NAME, MYSQL_AUTODETECT_CHARSET_NAME);
#endif

    if (setIsolation && (retry == 1))
      mysql_options(&d_db, MYSQL_INIT_COMMAND,"SET SESSION tx_isolation='READ-COMMITTED'");

    mysql_options(&d_db, MYSQL_READ_DEFAULT_GROUP, group.c_str());

    if (!mysql_real_connect(&d_db, host.empty() ? NULL : host.c_str(),
                          user.empty() ? NULL : user.c_str(),
                          password.empty() ? NULL : password.c_str(),
                          database.empty() ? NULL : database.c_str(),
                          port,
                          msocket.empty() ? NULL : msocket.c_str(),
                          CLIENT_MULTI_RESULTS)) {

      if (retry == 0)
        throw sPerrorException("Unable to connect to database");
      --retry;
    } else {
      if (retry == 0) {
        mysql_close(&d_db);
        throw sPerrorException("Please add '(gmysql-)innodb-read-committed=no' to your PowerDNS configuration, and reconsider your storage engine if it does not support transactions.");
      }
      retry=-1;
    }
  } while (retry >= 0);
}

void SMySQL::setLog(bool state)
{
  s_dolog=state;
}

SMySQL::~SMySQL()
{
  mysql_close(&d_db);
}

SSqlException SMySQL::sPerrorException(const string &reason)
{
  return SSqlException(reason+string(": ")+mysql_error(&d_db));
}

SSqlStatement* SMySQL::prepare(const string& query, int nparams)
{
  return new SMySQLStatement(query, s_dolog, nparams, &d_db);
}

void SMySQL::execute(const string& query)
{
  if(s_dolog)
    L<<Logger::Warning<<"Query: "<<query<<endl;

  int err;
  if((err=mysql_query(&d_db,query.c_str())))
    throw sPerrorException("Failed to execute mysql_query '" + query + "', perhaps connection died? Err="+itoa(err));
}

void SMySQL::startTransaction() {
  execute("begin");
}

void SMySQL::commit() {
  execute("commit");
}

void SMySQL::rollback() {
  execute("rollback");
}
