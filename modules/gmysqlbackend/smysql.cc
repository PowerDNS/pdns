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
               const string &password, const string &group, unsigned int timeout, bool setIsolation)
{
  int retry=1;

  Lock l(&s_myinitlock);
  mysql_init(&d_db);

  d_database = database;
  d_host = host;
  d_port = port;
  d_msocket = msocket;
  d_user = user;
  d_password = password;
  d_group = group;
  d_timeout = timeout;

  d_connected=false;
  
  d_rres=0;

  // ensureConnect();
}

void SMySQL::ensureConnect()
{
  if(d_connected)
    return;

  do {
    Lock l(&s_myinitlock);
    mysql_init(&d_db);
    mysql_options(&d_db, MYSQL_READ_DEFAULT_GROUP, "client");

#if MYSQL_VERSION_ID >= 50013
    my_bool reconnect = 1;
      mysql_options(&d_db, MYSQL_OPT_RECONNECT, &reconnect);
#endif

    cerr<<"about to set mysql timeouts"<<endl;
    cerr<<"MYSQL_VERSION_ID: "<<MYSQL_VERSION_ID<<endl;
#if MYSQL_VERSION_ID >= 50100
    cerr<<"setting mysql timeouts!"<<endl;
    mysql_options(&d_db, MYSQL_OPT_CONNECT_TIMEOUT, &d_timeout);
    mysql_options(&d_db, MYSQL_OPT_READ_TIMEOUT, &d_timeout);
    mysql_options(&d_db, MYSQL_OPT_WRITE_TIMEOUT, &d_timeout);
#endif
  
#if MYSQL_VERSION_ID >= 50500
    mysql_options(&d_db, MYSQL_SET_CHARSET_NAME, MYSQL_AUTODETECT_CHARSET_NAME);
#endif

    if (setIsolation && (retry == 1))
      mysql_options(&d_db, MYSQL_INIT_COMMAND,"SET SESSION tx_isolation='READ-COMMITTED'");

    mysql_options(&d_db, MYSQL_READ_DEFAULT_GROUP, group.c_str());

    if (!mysql_real_connect(&d_db, d_host.empty() ? NULL : d_host.c_str(),
              d_user.empty() ? NULL : d_user.c_str(),
              d_password.empty() ? NULL : d_password.c_str(),
              d_database.c_str(), d_port,
              d_msocket.empty() ? NULL : d_msocket.c_str(),
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

  d_rres=0;
  d_connected=true;
}

void SMySQL::setLog(bool state)
{
  s_dolog=state;
}

SMySQL::~SMySQL()
{
  if(d_connected)
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
  if(!d_connected)
    ensureConnect();

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
