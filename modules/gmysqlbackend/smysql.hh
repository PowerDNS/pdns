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
#ifndef SMYSQL_HH
#define SMYSQL_HH

#include <mysql.h>
#include "pdns/backends/gsql/ssql.hh"
#include "pdns/utility.hh"

class SMySQL : public SSql
{
public:
  SMySQL(const string &database, const string &host="", uint16_t port=0,
         const string &msocket="",const string &user="",
         const string &password="", const string &group="",
         bool setIsolation=false, unsigned int timeout=10);

  ~SMySQL();

  SSqlException sPerrorException(const string &reason);
  void setLog(bool state);
  SSqlStatement* prepare(const string& query, int nparams);
  void execute(const string& query);

  void startTransaction();
  void commit();
  void rollback();

private:
  MYSQL d_db;
  static bool s_dolog;
  static pthread_mutex_t s_myinitlock;
};

#endif /* SSMYSQL_HH */
