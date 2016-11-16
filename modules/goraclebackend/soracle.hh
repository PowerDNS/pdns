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
  std::unique_ptr<SSqlStatement> prepare(const string& query, int nparams);
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
