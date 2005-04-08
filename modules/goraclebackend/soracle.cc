/* Copyright 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information. */

#include "soracle.hh"
#include <string>
#include <iostream>
#include "pdns/misc.hh"
#include "pdns/logger.hh"
#include "pdns/dns.hh"
using namespace std;

bool SOracle::s_dolog;

SOracle::SOracle(const string &database, const string &host, u_int16_t port, 
		 const string &msocket, const string &user, 
		 const string &password)
{
   d_environmentHandle = NULL;
   d_errorHandle = NULL;
   d_serviceContextHandle = NULL;
   
   int err = OCIInitialize(OCI_THREADED, 0,  NULL, NULL, NULL);
   if (err) {
     throw sPerrorException("OCIInitialize");
   }
   
   err = OCIEnvInit(&d_environmentHandle, OCI_DEFAULT, 0, 0);
   if (err) {
     throw sPerrorException("OCIEnvInit");
   }
  
   // Allocate an error handle
   
   err = OCIHandleAlloc(d_environmentHandle, (dvoid**) &d_errorHandle, OCI_HTYPE_ERROR, 0, NULL);
   if (err) {
     throw sPerrorException("OCIHandleAlloc");
   }
  
   // Logon to the database
   
   const char *username = user.c_str();



   err = OCILogon(d_environmentHandle, d_errorHandle, &d_serviceContextHandle, (OraText*) username, strlen(username),
		  (OraText*) password.c_str(),  strlen(password.c_str()), (OraText*) database.c_str(), strlen(database.c_str()));
   
   if (err) {
     throw sPerrorException("oops"); // mErrorHandle);
   }


}

void SOracle::setLog(bool state)
{
  s_dolog=state;
}

SOracle::~SOracle()
{

}

SSqlException SOracle::sPerrorException(const string &reason)
{
  return SSqlException(reason);
}

int SOracle::doCommand(const string &query)
{
  return doQuery(query);
}

int SOracle::doQuery(const string &query)
{

  return 0;
}

int SOracle::doQuery(const string &query, result_t &result)
{
  result.clear();
  doQuery(query);

  row_t row;
  while(getRow(row))
    result.push_back(row);

  return result.size();
}

bool SOracle::getRow(row_t &row)
{
  row.clear();

  return false;
}

string SOracle::escape(const string &name)
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i) {
    if(*i=='\'' || *i=='\\')
      a+='\\';
    a+=*i;
  }
  return a;
}


int main()
{
  try {
    SOracle s("kkfnetmail","127.0.0.1");
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



