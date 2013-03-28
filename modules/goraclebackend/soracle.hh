/* Copyright 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information. */

#ifndef SORACLE_HH
#define SORACLE_HH

#include "pdns/backends/gsql/ssql.hh"
#include "pdns/utility.hh" 
#include <oci.h>

#ifndef dsword
typedef sb4 dsword;
#endif

class SOracle : public SSql
{
public:
  SOracle(const string &database, 
          const string &user="", 
          const string &password="");
  
  ~SOracle();
  
  SSqlException sPerrorException(const string &reason);
  int doQuery(const string &query, result_t &result);
  int doQuery(const string &query);
  int doCommand(const string &query);
  bool getRow(row_t &row);
  string escape(const string &str);    
  void setLog(bool state);
private:
  OCIEnv    *d_environmentHandle;
  OCIError  *d_errorHandle;
  OCISvcCtx *d_serviceContextHandle;
  OCIStmt   *d_statementHandles[10];

  struct oresult {
    char content[256];
    sb2 indicator;
  } d_fields[10];
  OCIStmt* d_handle;

  dsword d_queryResult;

  string getOracleError();

  static bool s_dolog;
  int d_numfields;
  //  int getNumFields(const string& query);
};
      
#endif /* SSORACLE_HH */
