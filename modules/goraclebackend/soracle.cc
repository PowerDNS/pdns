/* Copyright 2005 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE
   for more information. */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "soracle.hh"
#include <string>
#include <iostream>
#include "pdns/misc.hh"
#include "pdns/logger.hh"
#include "pdns/dns.hh"
#include "pdns/namespaces.hh"
#include "pdns/md5.hh"

bool SOracle::s_dolog;

class SOracleStatement: public SSqlStatement {
public:
  SOracleStatement(const string& query, bool dolog, int nparams, OCIEnv *ctx, OCISvcCtx *svc_ctx, bool release_stmt) {
    d_query = query;
    d_ctx = ctx;
    d_svcctx = svc_ctx;
    d_dolog = dolog;
    d_res = NULL;
    d_bind = NULL;
    d_stmt = NULL;
    d_err = NULL;
    d_queryResult = OCI_NO_DATA;
    d_paridx = d_parnum = d_resnum = d_residx = 0;
    d_release_stmt = release_stmt;
    d_non_null_ind = 0;
    d_null_ind = -1;
    d_init = false;

    if (query.size() == 0) return;

    // create a key
    string key = pdns_md5sum(query);
    d_stmt_keysize = std::min(key.size()*2, sizeof(d_stmt_key));
    for(string::size_type i = 0; i < key.size() && i*2 < d_stmt_keysize; i++)
      snprintf((char*)&(d_stmt_key[i*2]), 3, "%02x", (unsigned char)key[i]);
    d_stmt_key[d_stmt_keysize] = 0;

    if (OCIHandleAlloc(d_ctx, (dvoid**)&d_err, OCI_HTYPE_ERROR, 0, NULL)) 
      throw SSqlException("Cannot allocate statement error handle");

    if (d_release_stmt) {
      if (OCIStmtPrepare2(d_svcctx, &d_stmt, d_err, (text*)query.c_str(), query.size(), NULL, 0, OCI_NTV_SYNTAX, OCI_DEFAULT) != OCI_SUCCESS) {
        // failed.
        throw SSqlException("Cannot prepare statement: " + d_query + string(": ") + OCIErrStr());
      }
      d_init = true;
    } else d_init = false;
    
    d_parnum = nparams;
    d_bind = new struct obind[d_parnum];
    memset(d_bind, 0, sizeof(struct obind)*d_parnum);
    // and we are done.
  }

  void prepareStatement() {
    if (d_stmt) return; // no-op 
    if (d_query.size()==0) return;
    if (d_init == false) {
      if (OCIStmtPrepare2(d_svcctx, &d_stmt, d_err, (text*)d_query.c_str(), d_query.size(), NULL, 0, OCI_NTV_SYNTAX, OCI_DEFAULT) != OCI_SUCCESS) {
        throw SSqlException("Cannot prepare statement: " + d_query + string(": ") + OCIErrStr());
      }
      d_init = true;
    } else {
      if (OCIStmtPrepare2(d_svcctx, &d_stmt, d_err, (text*)d_query.c_str(), d_query.size(), d_stmt_key, d_stmt_keysize, OCI_NTV_SYNTAX, OCI_DEFAULT) != OCI_SUCCESS) {
        throw SSqlException("Cannot prepare statement: " + d_query + string(": ") + OCIErrStr());
      }
    }
  }

  SSqlStatement* bind(const string& name, bool value) 
  {  
    return bind(name, (int)value);
  }
  SSqlStatement* bind(const string& name, int value) 
  {
    if (d_paridx >= d_parnum)
     throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    prepareStatement();
    string zName = string(":") + name;
    d_bind[d_paridx].val4 = value;
    if (OCIBindByName(d_stmt, &(d_bind[d_paridx].handle), d_err, (text*)zName.c_str(), zName.size(), &(d_bind[d_paridx].val4), sizeof(sb4), SQLT_INT, &d_non_null_ind,0,0,0,0,OCI_DEFAULT) != OCI_SUCCESS) {
      throw SSqlException(string("Cannot bind parameter ") + name + string(": ") + OCIErrStr());
    }
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, uint32_t value)
  {
    if (d_paridx >= d_parnum)
     throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    prepareStatement();
    string zName = string(":") + name;
    d_bind[d_paridx].val4 = value;
    if (OCIBindByName(d_stmt, &(d_bind[d_paridx].handle), d_err, (text*)zName.c_str(), zName.size(), (ub4*)&(d_bind[d_paridx].val4), sizeof(ub4), SQLT_UIN, &d_non_null_ind,0,0,0,0,OCI_DEFAULT) != OCI_SUCCESS) {
      throw SSqlException(string("Cannot bind parameter ") + name + string(": ") + OCIErrStr());
    }
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, long value)
  {
    if (d_paridx >= d_parnum)
     throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    prepareStatement();
    string zName = string(":") + name;
    d_bind[d_paridx].val4 = value;
    if (OCIBindByName(d_stmt, &(d_bind[d_paridx].handle), d_err, (text*)zName.c_str(), zName.size(), (ub4*)&(d_bind[d_paridx].val4), sizeof(sb4), SQLT_INT, &d_non_null_ind,0,0,0,0,OCI_DEFAULT) != OCI_SUCCESS) {
      throw SSqlException(string("Cannot bind parameter ") + name + string(": ") + OCIErrStr());
    }
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, unsigned long value) 
  {
    if (d_paridx >= d_parnum)
     throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    prepareStatement();
    string zName = string(":") + name;
    d_bind[d_paridx].val4 = value;
    if (OCIBindByName(d_stmt, &(d_bind[d_paridx].handle), d_err, (text*)zName.c_str(), zName.size(), (ub4*)&(d_bind[d_paridx].val4), sizeof(ub4), SQLT_UIN, &d_non_null_ind,0,0,0,0,OCI_DEFAULT) != OCI_SUCCESS) {
      throw SSqlException(string("Cannot bind parameter ") + name + string(": ") + OCIErrStr());
    }
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, long long value)
  {
    if (d_paridx >= d_parnum)
     throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    prepareStatement();
    string zName = string(":") + name;
    d_bind[d_paridx].val8 = value;
    if (OCIBindByName(d_stmt, &(d_bind[d_paridx].handle), d_err, (text*)zName.c_str(), zName.size(), (orasb8*)&(d_bind[d_paridx].val8), sizeof(orasb8), SQLT_INT, &d_non_null_ind,0,0,0,0,OCI_DEFAULT) != OCI_SUCCESS) {
      throw SSqlException(string("Cannot bind parameter ") + name + string(": ") + OCIErrStr());
    }
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, unsigned long long value)
  {
    if (d_paridx >= d_parnum)
     throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    prepareStatement();
    string zName = string(":") + name;
    d_bind[d_paridx].val8 = value;
    if (OCIBindByName(d_stmt, &(d_bind[d_paridx].handle), d_err, (text*)zName.c_str(), zName.size(), (oraub8*)&(d_bind[d_paridx].val8), sizeof(oraub8), SQLT_UIN, &d_non_null_ind,0,0,0,0,OCI_DEFAULT) != OCI_SUCCESS) {
      throw SSqlException(string("Cannot bind parameter ") + name + string(": ") + OCIErrStr());
    }
    d_paridx++;
    return this;
  }
  SSqlStatement* bind(const string& name, const std::string& value) 
  {
    if (d_paridx >= d_parnum)
     throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    prepareStatement();
    string zName = string(":") + name;
    d_bind[d_paridx].vals = new text[value.size()+1];
    memset(d_bind[d_paridx].vals, 0, value.size()+1);
    value.copy((char*)d_bind[d_paridx].vals, value.size());
    if (OCIBindByName(d_stmt, &(d_bind[d_paridx].handle), d_err, (text*)zName.c_str(), zName.size(), (text*)d_bind[d_paridx].vals, value.size()+1, SQLT_STR, &d_non_null_ind,0,0,0,0,OCI_DEFAULT) != OCI_SUCCESS) {
      throw SSqlException(string("Cannot bind parameter ") + name + string(": ") + OCIErrStr());
    }
    d_paridx++;
    return this;
  }
  SSqlStatement* bindNull(const string& name) 
  { 
    if (d_paridx >= d_parnum)
     throw SSqlException("Attempt to bind more parameters than query has: " + d_query);
    prepareStatement();
    string zName = string(":") + name;
    if (OCIBindByName(d_stmt, &(d_bind[d_paridx].handle), d_err, (text*)zName.c_str(), zName.size(), NULL, 0, SQLT_STR, &d_null_ind, 0, 0, 0, 0, OCI_DEFAULT) != OCI_SUCCESS) {
      throw SSqlException(string("Cannot bind parameter ") + name + string(": ") + OCIErrStr());
    }
    d_bind[d_paridx].release = true; // remember to free this
    d_paridx++;
    return this;
  }
  SSqlStatement* execute() 
  {
    if (d_query.size() == 0) return this; // do not execute empty queries
    prepareStatement();

    if (d_dolog) 
      L<<Logger::Warning<<"Query: "<<d_query<<endl;
    ub2 fntype;
    ub4 iters;

    if (OCIAttrGet(d_stmt, OCI_HTYPE_STMT, (dvoid*)&fntype, 0, OCI_ATTR_STMT_TYPE, d_err))
      throw SSqlException("Cannot get statement type: " + d_query + string(": ") + OCIErrStr());

    if (fntype == OCI_STMT_SELECT) iters = 0;
    else iters = 1;

    d_queryResult = OCIStmtExecute(d_svcctx, d_stmt, d_err, iters, 0, NULL, NULL, OCI_DEFAULT);
    if (d_queryResult != OCI_NO_DATA && d_queryResult != OCI_SUCCESS && d_queryResult != OCI_SUCCESS_WITH_INFO) {
      throw SSqlException("Cannot execute statement: " + d_query + string(": ") + OCIErrStr());
    }

    d_resnum = d_residx = 0; 

    if (fntype == OCI_STMT_SELECT) {
      ub4 o_fnum;
      ub4 o_resnum;

      // figure out what the result looks like
      if (OCIAttrGet(d_stmt, OCI_HTYPE_STMT, (dvoid*)&o_resnum, 0, OCI_ATTR_ROW_COUNT, d_err)) 
        throw SSqlException("Cannot get statement result row count: " + d_query + string(": ") + OCIErrStr()); // this returns 0 
      if (OCIAttrGet(d_stmt, OCI_HTYPE_STMT, (dvoid*)&o_fnum, 0, OCI_ATTR_PARAM_COUNT, d_err)) 
        throw SSqlException("Cannot get statement result column count: " + d_query + string(": ") + OCIErrStr());

      d_residx = 0;
      d_resnum = o_resnum;
      d_fnum = o_fnum;

      if (d_res == NULL && d_fnum > 0) {
        ub2 o_attrtype;
        OCIParam *parms = NULL;
        d_res = new struct oresult[d_fnum];
        memset(d_res, 0, sizeof(struct oresult)*d_fnum);

        for(int i=0; i < d_fnum; i++) {
          if (OCIParamGet(d_stmt, OCI_HTYPE_STMT, d_err, (dvoid**)&parms, (ub4)i+1) != OCI_SUCCESS) {
            throw SSqlException("Cannot get statement result column information: " + d_query + string(": ") + OCIErrStr());
          }

          if (OCIAttrGet(parms, OCI_DTYPE_PARAM, (dvoid*)&(d_res[i].colsize), 0, OCI_ATTR_DATA_SIZE, d_err) != OCI_SUCCESS) {
            throw SSqlException("Cannot get statement result column information: " + d_query + string(": ") + OCIErrStr());
          }
          
          if (d_res[i].colsize == 0) {
            if (OCIAttrGet(parms, OCI_DTYPE_PARAM, (dvoid*)&o_attrtype, 0, OCI_ATTR_DATA_TYPE, d_err) != OCI_SUCCESS) {
              throw SSqlException("Cannot get statement result column information: " + d_query + string(": ") + OCIErrStr());
            }

            // oracle 11g returns 0 for integer fields - we know oracle should return 22.
            if (o_attrtype == OCI_TYPECODE_INTEGER ||
                o_attrtype == OCI_TYPECODE_SMALLINT ||
                o_attrtype == OCI_TYPECODE_REAL ||
                o_attrtype == OCI_TYPECODE_DOUBLE ||
                o_attrtype == OCI_TYPECODE_FLOAT ||
                o_attrtype == OCI_TYPECODE_NUMBER ||
                o_attrtype == OCI_TYPECODE_DECIMAL) d_res[i].colsize = 22;
          }
          d_res[i].content = new char[d_res[i].colsize+1];
        }
      }

      if (d_fnum > 0) {
        for(int i=0;i<d_fnum;i++) {
          if (OCIDefineByPos(d_stmt, &(d_res[i].handle), d_err, i+1, d_res[i].content, d_res[i].colsize+1, SQLT_STR, (dvoid*)&(d_res[i].ind), NULL, NULL, OCI_DEFAULT)) 
            throw SSqlException("Cannot bind result column: " + d_query + string(": ") + OCIErrStr());
        }
      }

      d_queryResult = OCIStmtFetch2(d_stmt, d_err, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);
    }

    return this;
  }

  string OCIErrStr() 
  {
    string mReason = "ORA-UNKNOWN";
    if (d_err != NULL) {
      text  msg[512];
      sb4   errcode = 0;
      memset(msg, 0, 512);
      OCIErrorGet((dvoid*) d_err,1, NULL, &errcode, msg, sizeof(msg), OCI_HTYPE_ERROR);
      if (errcode) {
        char* p = (char*) msg;
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

  bool hasNextRow() {
    if (d_queryResult == OCI_NO_DATA) return false;
    return true;
  }

  SSqlStatement* nextRow(row_t& row) {
    row.clear();

    if (d_stmt == NULL) return this;

    if (d_queryResult == OCI_NO_DATA) return this;

    if (d_queryResult != OCI_SUCCESS && d_queryResult != OCI_SUCCESS_WITH_INFO) {
      throw SSqlException("Cannot get next row: " + d_query + string(": ") + OCIErrStr());
    }

    row.reserve(d_fnum);

    for (int i=0; i < d_fnum ; i++) {

      if (d_res[i].ind>=0) {
        row.push_back(d_res[i].content);
      } else {
        row.push_back("");
      }
    }

    d_queryResult = OCIStmtFetch2(d_stmt, d_err, 1, OCI_FETCH_NEXT, 0, OCI_DEFAULT);

    d_residx++;
    return this;
  }

  SSqlStatement* getResult(result_t& result) {
    row_t row;

    result.reserve(d_resnum);
    while(hasNextRow()) {
      nextRow(row);
      result.push_back(row);
    }

    return this;
  }

  SSqlStatement* reset() {
    d_paridx = 0;
    d_residx = d_resnum = 0;

    if (d_bind) {
      for(int i=0;i<d_parnum;i++) {
        if (d_bind[i].vals && d_bind[i].release) delete [] (text*)d_bind[i].vals;
      }
    }
    d_bind = new struct obind[d_parnum];
    memset(d_bind, 0, sizeof(struct obind)*d_parnum);
  
    if (d_release_stmt) {
      if (OCIStmtRelease(d_stmt, d_err, (text*)d_stmt_key, d_stmt_keysize, OCI_DEFAULT) != OCI_SUCCESS)
        throw SSqlException("Could not release statement: " + d_query + string(": ") + OCIErrStr());
      d_stmt = NULL;
    }
    return this;
  }

  const std::string& getQuery() {
    return d_query;
  }

  ~SOracleStatement() { 
    if (d_stmt)
      OCIStmtRelease(d_stmt, d_err, d_stmt_key, d_stmt_keysize, OCI_STRLS_CACHE_DELETE);
    if (d_err) 
      OCIHandleFree(d_err, OCI_HTYPE_ERROR);
    if (d_res) {
      for(int i=0;i<d_fnum;i++)
        if (d_res[i].content) delete [] d_res[i].content;
      delete [] d_res;
    }
    if (d_bind) {
      for(int i=0;i<d_parnum;i++) {
        if (d_bind[i].vals && d_bind[i].release) delete [] (text*)d_bind[i].vals;
      }
    }
  }

private:
  string d_query;
  OCIEnv *d_ctx;
  OCISvcCtx *d_svcctx;
  bool d_dolog;
  bool d_release_stmt;
  bool d_init;
  OCIStmt* d_stmt;
  OCIError* d_err;
  int d_parnum;
  int d_paridx;
  int d_resnum;
  int d_residx;
  int d_fnum;
  dsword d_queryResult;
  struct oresult {
    OCIDefine *handle;
    char* content;
    sb4 ind;
    ub4 colsize;
  }* d_res;
  struct obind {
    OCIBind *handle;
    ub4 val4;
    oraub8 val8;
    void* vals;
    bool release;
  }* d_bind;

  sb4 d_non_null_ind;
  sb4 d_null_ind;
  text d_stmt_key[64];
  size_t d_stmt_keysize;
};


SOracle::SOracle(const string &database,
                 const string &user,
                 const string &password,
                 bool releaseStatements,
                 OCIEnv* oraenv)
{
  d_environmentHandle = oraenv;
  d_errorHandle = NULL;
  d_serviceContextHandle = NULL;
  d_release_stmt = releaseStatements;

  // Allocate an error handle

  int err = OCIHandleAlloc(d_environmentHandle, (dvoid**) &d_errorHandle, OCI_HTYPE_ERROR, 0, NULL);
  if (err) {
    throw sPerrorException("OCIHandleAlloc(errorHandle)");
  }

  err = OCILogon2(d_environmentHandle, d_errorHandle, &d_serviceContextHandle, (OraText*)user.c_str(), user.size(), 
                 (OraText*) password.c_str(),  strlen(password.c_str()), (OraText*) database.c_str(), strlen(database.c_str()), OCI_LOGON2_STMTCACHE);
  // increase statement cache to 100
  if (err) {
    throw sPerrorException("OCILogon2");
  }

  ub4 cacheSize = 100;
  err = OCIAttrSet(d_serviceContextHandle, OCI_HTYPE_SVCCTX, &cacheSize, sizeof(ub4), OCI_ATTR_STMTCACHESIZE, d_errorHandle);
  if (err) {
    throw sPerrorException("OCIAttrSet(stmtcachesize)");
  }

}

void SOracle::setLog(bool state)
{
  s_dolog=state;
}

SOracle::~SOracle()
{
  int err;
  if (d_serviceContextHandle != NULL) {
    err=OCILogoff(d_serviceContextHandle, d_errorHandle);
    if (err) {
      L<<Logger::Warning<<"Problems logging out: "+getOracleError()<<endl;
    }
  }

  if (d_errorHandle != NULL) {
    OCIHandleFree(d_errorHandle, OCI_HTYPE_ERROR);
    d_errorHandle = NULL;
  }
}

SSqlException SOracle::sPerrorException(const string &reason)
{
  return SSqlException(reason);
}

SSqlStatement* SOracle::prepare(const string& query, int nparams) {
  return new SOracleStatement(query, s_dolog, nparams, d_environmentHandle, d_serviceContextHandle, d_release_stmt);
}

void SOracle::execute(const string& query) {
  SOracleStatement(query, s_dolog, 0, d_environmentHandle, d_serviceContextHandle, true).execute();
}

string SOracle::getOracleError()
{
  string mReason = "ORA-UNKNOWN";
  if (d_errorHandle != NULL) {
    text  msg[512];
    sb4   errcode = 0;
    memset(msg, 0, 512);
    OCIErrorGet((dvoid*) d_errorHandle,1, NULL, &errcode, msg, sizeof(msg), OCI_HTYPE_ERROR);
    if (errcode) {
      char* p = (char*) msg;
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
