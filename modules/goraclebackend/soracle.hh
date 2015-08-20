/* Copyright 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE
   for more information. */

#ifndef SORACLE_HH
#define SORACLE_HH

#include "pdns/backends/gsql/ssql.hh"
#include "pdns/utility.hh"
#include <oci.h>
#include <oratypes.h>
#include "pdns/misc.hh"

#ifndef dsword
typedef sb4 dsword;
#endif

class SOracle : public SSql
{
public:
  SOracle(const string &database,
          const string &user="",
          const string &password="", 
          bool releaseStatements=false,
          OCIEnv* oraenv=NULL);

  ~SOracle();

  SSqlException sPerrorException(const string &reason);
  void setLog(bool state);
  SSqlStatement* prepare(const string& query, int nparams);
  void execute(const string& query);

  void startTransaction();
  void commit();
  void rollback();
private:
  OCIEnv*    d_environmentHandle;
  OCIError*  d_errorHandle;
  OCISvcCtx* d_serviceContextHandle;

  string getOracleError();
  static bool s_dolog;
  bool d_release_stmt;
};

#endif /* SSORACLE_HH */
