/* Copyright 200w Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information.
   $Id: spgsql.cc,v 1.2 2002/12/16 18:02:24 ahu Exp $  */
#include "spgsql.hh"
#include <string>
#include <iostream>
#include "pdns/logger.hh"
#include "pdns/dns.hh"
using namespace std;

bool SPgSQL::s_dolog;

SPgSQL::SPgSQL(const string &database, const string &host, const string &msocket, const string &user, 
	       const string &password)
{
  string connectstr;

  connectstr="dbname=";
  connectstr+=database;
  connectstr+=" user=";
  connectstr+=user;

  if(!host.empty())
    connectstr+=" host="+host;

  if(!password.empty())
    connectstr+=" password="+password;

  d_db=new PgDatabase(connectstr.c_str());
  
  // Check to see that the backend connection was successfully made
  if (d_db->ConnectionBad() ) {
    throw sPerrorException("Unable to connect to database");
  }

}

void SPgSQL::setLog(bool state)
{
  s_dolog=state;
}

SPgSQL::~SPgSQL()
{
  delete d_db;
}

SSqlException SPgSQL::sPerrorException(const string &reason)
{
  return SSqlException(reason+string(": ")+d_db->ErrorMessage());
}

int SPgSQL::doQuery(const string &query)
{
  if(s_dolog)
    L<<Logger::Warning<<"Query: "<<query<<endl;

  if(!d_db->Exec(query.c_str())) {
    throw sPerrorException("PostgreSQL failed to execute command");
  }
  d_count=0;
  return 0;
}

int SPgSQL::doQuery(const string &query, result_t &result)
{
  result.clear();
  if(s_dolog)
    L<<Logger::Warning<<"Query: "<<query<<endl;

  if(!d_db->ExecTuplesOk(query.c_str()))
    throw sPerrorException("gPgSQLBackend failed to execute command that expected results");
  d_count=0;

  row_t row;
  while(getRow(row))
    result.push_back(row);

  return result.size();
}

bool SPgSQL::getRow(row_t &row)
{
  row.clear();
 
  if(d_count>=d_db->Tuples())
    return false;
  
  for(int i=0;i<d_db->Fields();i++)
    row.push_back(d_db->GetValue(d_count,i) ?: "");
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
