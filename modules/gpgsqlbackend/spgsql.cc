/* Copyright 2003 - 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information. */
#include <string>
#include "spgsql.hh"

#include <iostream>
#include "pdns/logger.hh"
#include "pdns/dns.hh"

using namespace std;

bool SPgSQL::s_dolog;

SPgSQL::SPgSQL(const string &database, const string &host, const string& port, const string &msocket, const string &user, 
	       const string &password)
{
  d_db=0;
  string connectstr;

  connectstr="dbname=";
  connectstr+=database;
  connectstr+=" user=";
  connectstr+=user;

  if(!host.empty())
    connectstr+=" host="+host;

  if(!port.empty())
    connectstr+=" port="+port;

  if(!password.empty())
    connectstr+=" password="+password;

  d_db=PQconnectdb(connectstr.c_str());

  if (!d_db || PQstatus(d_db)==CONNECTION_BAD) {
    try {
      throw sPerrorException("Unable to connect to database, connect string: "+connectstr);
    }
    catch(...) {
      if(d_db)
	PQfinish(d_db);
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

int SPgSQL::doCommand(const string &query)
{
  if(s_dolog)
    L<<Logger::Warning<<"Command: "<<query<<endl;

  if(!(d_result=PQexec(d_db,query.c_str())) || PQresultStatus(d_result)!=PGRES_COMMAND_OK) { 
    string error("unknown reason");
    if(d_result) {
      error=PQresultErrorMessage(d_result);
      PQclear(d_result);
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

  if(!(d_result=PQexec(d_db,query.c_str())) || PQresultStatus(d_result)!=PGRES_TUPLES_OK) {
    string error("unknown reason");
    if(d_result) {
      error=PQresultErrorMessage(d_result);
      PQclear(d_result);
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

  if(d_count>=PQntuples(d_result)) {
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
