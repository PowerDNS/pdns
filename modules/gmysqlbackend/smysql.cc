/* Copyright 2001 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information.
   $Id$  */
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

SMySQL::SMySQL(const string &database, const string &host, uint16_t port, const string &msocket, const string &user, 
               const string &password, const string &group)
{
  {
    Lock l(&s_myinitlock);
    mysql_init(&d_db);

  #if MYSQL_VERSION_ID >= 50013
    my_bool reconnect = 1;
    mysql_options(&d_db, MYSQL_OPT_RECONNECT, &reconnect);
  #endif

  #if MYSQL_VERSION_ID > 51000
    unsigned int timeout = 10;
    mysql_options(&d_db, MYSQL_OPT_READ_TIMEOUT, &timeout);
    mysql_options(&d_db, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
  #endif

    mysql_options(&d_db, MYSQL_READ_DEFAULT_GROUP, &group);
    
    if (!mysql_real_connect(&d_db, host.empty() ? NULL : host.c_str(), 
          		  user.empty() ? NULL : user.c_str(), 
          		  password.empty() ? NULL : password.c_str(),
          		  database.empty() ? NULL : database.c_str(),
          		  port,
          		  msocket.empty() ? NULL : msocket.c_str(),
          		  CLIENT_MULTI_RESULTS)) {

      throw sPerrorException("Unable to connect to database");
    }

    d_rres=0;
  }
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

  while (mysql_next_result(&d_db) == 0) {
    if ((d_rres = mysql_use_result(&d_db))) {
      mysql_free_result(d_rres);
    }
  }

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
