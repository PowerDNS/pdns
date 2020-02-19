/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include <string>
#include <vector>
#include <inttypes.h>
#include "../../dnsname.hh"
#include "../../namespaces.hh"
#include "../../misc.hh"

class SSqlException
{
public:
  SSqlException(const string& reason) :
    d_reason(reason)
  {
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

  virtual SSqlStatement* bind(const string& name, bool value) = 0;
  virtual SSqlStatement* bind(const string& name, int value) = 0;
  virtual SSqlStatement* bind(const string& name, uint32_t value) = 0;
  virtual SSqlStatement* bind(const string& name, long value) = 0;
  virtual SSqlStatement* bind(const string& name, unsigned long value) = 0;
  virtual SSqlStatement* bind(const string& name, long long value) = 0;
  ;
  virtual SSqlStatement* bind(const string& name, unsigned long long value) = 0;
  virtual SSqlStatement* bind(const string& name, const std::string& value) = 0;
  SSqlStatement* bind(const string& name, const DNSName& value)
  {
    return bind(name, value.makeLowerCase().toStringRootDot());
  }
  virtual SSqlStatement* bindNull(const string& name) = 0;
  virtual SSqlStatement* execute() = 0;
  ;
  virtual bool hasNextRow() = 0;
  virtual SSqlStatement* nextRow(row_t& row) = 0;
  virtual SSqlStatement* getResult(result_t& result) = 0;
  virtual SSqlStatement* reset() = 0;
  virtual const std::string& getQuery() = 0;
  virtual ~SSqlStatement();
};

class SSql
{
public:
  virtual SSqlException sPerrorException(const string& reason) = 0;
  virtual std::unique_ptr<SSqlStatement> prepare(const string& query, int nparams) = 0;
  virtual void execute(const string& query) = 0;
  virtual void startTransaction() = 0;
  virtual void rollback() = 0;
  virtual void commit() = 0;
  virtual void setLog(bool state) {}
  virtual bool isConnectionUsable()
  {
    return true;
  }
  virtual void reconnect(){};
  virtual ~SSql(){};
};
