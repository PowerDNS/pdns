/* Copyright 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information. */

#include "soracle.hh"
#include <string>
#include <iostream>
#include "pdns/misc.hh"
#include "pdns/logger.hh"
#include "pdns/dns.hh"
#include <regex.h>
using namespace std;

bool SOracle::s_dolog;


string SOracle::getOracleError()
{
  string mReason = "ORA-UNKNOWN";

  if (d_errorHandle != NULL) {
    text  msg[512];
    sb4   errcode = 0;
    
    memset((void *) msg, (int)'\0', (size_t)512);
    
    OCIErrorGet((dvoid *) d_errorHandle,1, NULL, &errcode, msg, sizeof(msg), OCI_HTYPE_ERROR);
    if (errcode) {
      char *p = (char*) msg;
      while (*p++ != 0x00) {
	if (*p == '\n' || *p == '\r') {
	  *p = ';';
	}
      }
      
      mReason = (char*) msg;
    }
  }
  return mReason;
}

SOracle::SOracle(const string &database, 
		 const string &user, 
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
     throw sPerrorException("Loging in to Oracle gave error: " + getOracleError());
   }


}

void SOracle::setLog(bool state)
{
  s_dolog=state;
}

SOracle::~SOracle()
{
  if(d_handle) {
    OCIHandleFree(d_handle, OCI_HTYPE_STMT);
    d_handle=0;
  }

  int err;
  if (d_serviceContextHandle != NULL) {
    err=OCILogoff(d_serviceContextHandle, d_errorHandle); 
    if(err) {
      cerr<<"Problems logging out: "+getOracleError()<<endl;
    }
  }
   
  if (d_errorHandle != NULL) {
    OCIHandleFree(d_errorHandle, OCI_HTYPE_ERROR);
    d_errorHandle = NULL;
  }
  
  if (d_environmentHandle != NULL) {
    OCIHandleFree(d_environmentHandle, OCI_HTYPE_ENV);
    d_environmentHandle = NULL;
  }
  
}

SSqlException SOracle::sPerrorException(const string &reason)
{
  return SSqlException(reason);
}

int SOracle::doCommand(const string &query)
{
  return doQuery(query);
}

int getNumFields(const string& query)
{
  string lquery=toLower(query);
  char* delim[]={" from ", "\tfrom\t", "\tfrom ", " from\t"};
  int n=0;
  string::size_type pos;
  for(n=0; n < 4 && (pos=lquery.find(delim[n]))==string::npos; ++n)
    ;

  if(n==4)
    return -1;

  unsigned int num=1;

  for(unsigned int n=0; n < pos; ++n)
    if(lquery[n]==',')
      num++;

  return num;
}

int SOracle::doQuery(const string &query)
{
  if(query=="begin") // oracle does this implicitly
    return 0;

  int err = OCIHandleAlloc(d_environmentHandle, (dvoid **) &d_handle, OCI_HTYPE_STMT, 0, NULL);
	 
  if (err) {
    throw sPerrorException("Allocating a query handle: "+getOracleError());
  }

  err = OCIStmtPrepare(d_handle, d_errorHandle, (text*) query.c_str(), strlen(query.c_str()),
		       OCI_NTV_SYNTAX, OCI_DEFAULT);
  
  if (err) {
    throw sPerrorException("Preparing statement: "+getOracleError());
  }

  ub4 prefetch=1000;
  err=OCIAttrSet(d_handle, (ub4) OCI_HTYPE_STMT,
	     (dvoid *) &prefetch, (ub4) sizeof(ub4), 
	     (ub4) OCI_ATTR_PREFETCH_ROWS, d_errorHandle);

  if (err) {
    throw sPerrorException("setting prefetch: "+getOracleError());
  }


  //  cerr<<"Done preparing '"<<query<<"'"<<endl;

  d_numfields=getNumFields(query);

  for(int n=0; n < d_numfields ; ++n) {
    //    cerr<<"bind: "<<n<<endl;
    OCIDefine *theDefineHandle = NULL; 
    err = OCIDefineByPos(d_handle, &theDefineHandle, d_errorHandle, n+1, d_fields[n].content,
			 sizeof(d_fields[n].content) - 1, SQLT_STR, (dvoid*) &d_fields[n].indicator, NULL, NULL, OCI_DEFAULT);
    
    if (err) {
      throw sPerrorException("Error binding returns: "+getOracleError());
    }
  }

  //  cerr<<"Done binding fields"<<endl;

  d_queryResult = OCIStmtExecute(d_serviceContextHandle, d_handle, d_errorHandle, 1, 0,
				 (OCISnapshot *)NULL, (OCISnapshot*) NULL, OCI_DEFAULT);
  
  if (d_queryResult != OCI_SUCCESS && d_queryResult != OCI_SUCCESS_WITH_INFO && d_queryResult != OCI_NO_DATA) {
    throw sPerrorException("executing oracle query: "+getOracleError());
  }

  //  cerr<<"Done executing: "<<d_queryResult<<endl;



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

  if (d_queryResult == OCI_NO_DATA) {
    OCIHandleFree(d_handle, OCI_HTYPE_STMT);
    d_handle=0;
    return false;
  }
  else {
    for(int n=0;n < d_numfields ;++n)
      if(!d_fields[n].indicator)
	row.push_back(d_fields[n].content);
      else
	row.push_back("");
  }

  d_queryResult = OCIStmtFetch(d_handle, d_errorHandle, 1, 0, 0);
  if (d_queryResult != OCI_SUCCESS && d_queryResult != OCI_SUCCESS_WITH_INFO && d_queryResult != OCI_NO_DATA) {
    throw sPerrorException("fetching next row of oracle query: "+getOracleError());
  }
  

  return true;
}

string SOracle::escape(const string &name)
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i) {
    if(*i=='\'')
      a+='\'';
    a+=*i;
  }
  return a;
}

#if 0

int main(int argc, char **argv)
{
  for(int outer=0;outer<2; ++outer) {
  try {
    SOracle s(argv[1],"",0,"",argv[2],argv[3]);

    cerr<<"Ready to do queries"<<endl;
    time_t then=time(0);
    
    int loops;
    for(loops=0;loops < 6; ++loops) {
      s.doQuery("select id, content from records");
      
      SSql::row_t row;
      
      while(s.getRow(row)) {
	for(SSql::row_t::const_iterator j=row.begin();j!=row.end();++j)
	  cout <<"'"<< *j<<"', ";
	cout<<"\n";
      }
    }
    time_t spent=time(0)-then;
    if(spent)
      cerr<<"Loops per second: "<< loops/spent<<endl;
  }
  catch(string &e) {
    cerr<<"fatal: "<<e<<endl;
  }
  catch(SSqlException &e) {
    cerr<<e.txtReason()<<endl;
  }
  }
}

#endif
