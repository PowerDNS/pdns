/* Copyright 2001 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information.

   Additionally, the license of this program contains a special
   exception which allows to distribute the program in binary form when
   it is linked against OpenSSL.

   $Id$  */
#ifndef SSQL_HH
#define SSQL_HH

#include <string>
#include <vector>
#include <inttypes.h>
#include "../../dnsname.hh"
#include "../../namespaces.hh"
#include "../../misc.hh"

class SSqlException 
{
public: 
  SSqlException(const string &reason) 
  {
      d_reason=reason;
  }
  
  string txtReason()
  {
    return d_reason;
  }
private:
  string d_reason;
};
 
class SSqlStatement
{
public:
  typedef vector<string> row_t;
  typedef vector<row_t> result_t;

  virtual SSqlStatement* bind(const string& name, bool value)=0;
  virtual SSqlStatement* bind(const string& name, int value)=0;
  virtual SSqlStatement* bind(const string& name, uint32_t value)=0;
  virtual SSqlStatement* bind(const string& name, long value)=0;
  virtual SSqlStatement* bind(const string& name, unsigned long value)=0;
  virtual SSqlStatement* bind(const string& name, long long value)=0;;
  virtual SSqlStatement* bind(const string& name, unsigned long long value)=0;
  virtual SSqlStatement* bind(const string& name, const std::string& value)=0;
  SSqlStatement* bind(const string& name, const DNSName& value) {
    return bind(name, toLower(value.toStringRootDot()));
  }
  virtual SSqlStatement* bindNull(const string& name)=0;
  virtual SSqlStatement* execute()=0;;
  virtual bool hasNextRow()=0;
  virtual SSqlStatement* nextRow(row_t& row)=0;
  virtual SSqlStatement* getResult(result_t& result)=0;
  virtual SSqlStatement* reset()=0;
  virtual const std::string& getQuery()=0;
  virtual ~SSqlStatement();
};

class SSql
{
public:
  virtual SSqlException sPerrorException(const string &reason)=0;
  virtual SSqlStatement* prepare(const string& query, int nparams)=0;
  virtual void execute(const string& query)=0;
  virtual void startTransaction()=0;
  virtual void rollback()=0;
  virtual void commit()=0;
  virtual void setLog(bool state){}
  virtual ~SSql(){};
};

#endif /* SSQL_HH */
