/* Copyright 2001 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information.
   $Id: smysql.cc,v 1.5 2003/12/17 18:05:10 ahu Exp $  */
#include "smysql.hh"
#include <string>
#include <iostream>
#include "pdns/misc.hh"
#include "pdns/logger.hh"
#include "pdns/dns.hh"
using namespace std;

bool SMySQL::s_dolog;

SMySQL::SMySQL(const string &database, const string &host, const string &msocket, const string &user, 
	       const string &password)
{
  mysql_init(&d_db);
  if (!mysql_real_connect(&d_db, host.empty() ? 0 : host.c_str(), 
			  user.empty() ? 0 : user.c_str(), 
			  password.empty() ? 0 : password.c_str(),
			  database.c_str(), 0,
			  msocket.empty() ? 0 : msocket.c_str(),
			  0)) {
    throw sPerrorException("Unable to connect to database");
  }
  d_rres=0;
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

int SMySQL::doCommand(const string &query)
{
  return doQuery(query);
}

int SMySQL::doQuery(const string &query)
{
  if(d_rres)
    throw SSqlException("Attempt to start new MySQL query while old one still in progress");

  if(s_dolog)
    L<<Logger::Warning<<"Query: "<<query<<endl;

  int err;
  if((err=mysql_query(&d_db,query.c_str()))) 
    throw sPerrorException("Failed to execute mysql_query, perhaps connection died? Err="+itoa(err));


  return 0;
}

int SMySQL::doQuery(const string &query, result_t &result)
{
  result.clear();
  doQuery(query);

  row_t row;
  while(getRow(row))
    result.push_back(row);

  return result.size();
}

bool SMySQL::getRow(row_t &row)
{
  row.clear();
  if(!d_rres) 
    if(!(d_rres = mysql_use_result(&d_db)))
      throw sPerrorException("Failed on mysql_use_result");

  MYSQL_ROW rrow;

  if((rrow = mysql_fetch_row(d_rres))) {
    for(unsigned int i=0;i<mysql_num_fields(d_rres);i++)
      row.push_back(rrow[i] ?: "");
    return true;
  }
  mysql_free_result(d_rres);  
  d_rres=0;
  return false;
}

string SMySQL::escape(const string &name)
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i) {
    if(*i=='\'' || *i=='\\')
      a+='\\';
    a+=*i;
  }
  return a;
}


#if 0
int main()
{
  try {
    SMySQL s("kkfnetmail","127.0.0.1","readonly");
    SSql::result_t juh;
    
    int num=s.doQuery("select *, from mboxes", juh);
    cout<<num<<" responses"<<endl;
    
    for(int i=0;i<num;i++) {
      const SSql::row_t &row=juh[i];

      for(SSql::row_t::const_iterator j=row.begin();j!=row.end();++j)
	cout <<"'"<< *j<<"', ";
      cout<<endl;
    }
  }
  catch(SSqlException &e) {
    cerr<<e.txtReason()<<endl;
  }
}


#endif
