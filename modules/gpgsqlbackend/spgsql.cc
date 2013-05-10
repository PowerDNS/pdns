/* Copyright 2003 - 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE
   for more information. */
#include <string>
#include "spgsql.hh"

#include <iostream>
#include "pdns/logger.hh"
#include "pdns/dns.hh"
#include "pdns/namespaces.hh"

bool SPgSQL::s_dolog;

SPgSQL::SPgSQL(const string &database, const string &host, const string& port, const string &msocket, const string &user,
               const string &password)
{
  d_db=0;

  d_connectstr="dbname=";
  d_connectstr+=database;
  d_connectstr+=" user=";
  d_connectstr+=user;

  if(!host.empty())
    d_connectstr+=" host="+host;

  if(!port.empty())
    d_connectstr+=" port="+port;

  d_connectlogstr=d_connectstr;

  if(!password.empty()) {
    d_connectlogstr+=" password=<HIDDEN>";
    d_connectstr+=" password="+password;
  }

  ensureConnect();
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

void SPgSQL::ensureConnect()
{
  if(d_db)
    PQfinish(d_db);
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

int SPgSQL::doCommand(const string &query)
{
  if(s_dolog)
    L<<Logger::Warning<<"Command: "<<query<<endl;

  bool first = true;

  retry:

  if(!(d_result=PQexec(d_db,query.c_str())) || PQresultStatus(d_result)!=PGRES_COMMAND_OK) {
    string error("unknown reason");
    if(d_result) {
      error=PQresultErrorMessage(d_result);
      PQclear(d_result);
    }

    if(PQstatus(d_db)==CONNECTION_BAD) {
      ensureConnect();
      if(first) {
        first = false;
        goto retry;
      }
    }

    throw SSqlException("PostgreSQL failed to execute command: "+error);
  }
  if(d_result)
    PQclear(d_result);
  d_count=0;
  return 0;
}


int SPgSQL::doQuery(const string &query)
{
  if(s_dolog)
    L<<Logger::Warning<<"Query: "<<query<<endl;

  bool first = true;
retry:
  if(!(d_result=PQexec(d_db,query.c_str())) || PQresultStatus(d_result)!=PGRES_TUPLES_OK) {
    string error("unknown reason");
    if(d_result) {
      error=PQresultErrorMessage(d_result);
      PQclear(d_result);
    }
    if(PQstatus(d_db)==CONNECTION_BAD) {
      ensureConnect();
      if(first) {
        first = false;
        goto retry;
      }
    }

    throw SSqlException("PostgreSQL failed to execute command: "+error);
  }

  d_count=0;
  return 0;
}

int SPgSQL::doQuery(const string &query, result_t &result)
{
  result.clear();
  if(s_dolog)
    L<<Logger::Warning<<"Query: "<<query<<endl;

  if(!(d_result=PQexec(d_db,query.c_str())) || PQresultStatus(d_result)!=PGRES_TUPLES_OK) {
    string error("unknown reason");
    if(d_result) {
      error=PQresultErrorMessage(d_result);
      PQclear(d_result);
    }
    throw SSqlException("PostgreSQL failed to execute command: "+error);
  }

  d_count=0;

  row_t row;
  while(getRow(row))
    result.push_back(row);

  return result.size();
}

bool SPgSQL::getRow(row_t &row)
{
  row.clear();

  if(d_count >= PQntuples(d_result)) {
    PQclear(d_result);
    return false;
  }

  for(int i=0;i<PQnfields(d_result);i++)
    row.push_back(PQgetvalue(d_result,d_count,i) ?: "");
  d_count++;
  return true;
}

string SPgSQL::escape(const string &name)
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i) {
    if(*i=='\'' || *i=='\\')
      a+='\\';
    a+=*i;
  }
  return a;
}
