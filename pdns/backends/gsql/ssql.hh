/* Copyright 2001 Netherlabs BV, bert.hubert@netherlabs.nl. See LICENSE 
   for more information.
   $Id$  */
#ifndef SSQL_HH
#define SSQL_HH

#ifdef WIN32
# pragma warning ( disable: 4786 )
#endif // WIN32

#include <string>
#include <vector>
#include "../../namespaces.hh"


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

class SSql
{
public:
  typedef vector<string> row_t;
  typedef vector<row_t> result_t;
  virtual SSqlException sPerrorException(const string &reason)=0;
  virtual int doQuery(const string &query, result_t &result)=0;
  virtual int doQuery(const string &query)=0;
  virtual int doCommand(const string &query)=0;
  virtual bool getRow(row_t &row)=0;
  virtual string escape(const string &name)=0;
  virtual void setLog(bool state){}
  virtual ~SSql(){};
};

#endif /* SSQL_HH */
