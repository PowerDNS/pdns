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
         bool setIsolation=false, unsigned int timeout=10,
         bool threadCleanup=false, bool clientSSL=false);

  ~SMySQL();

  SSqlException sPerrorException(const string &reason) override;
  void setLog(bool state) override;
  std::unique_ptr<SSqlStatement> prepare(const string& query, int nparams) override;
  void execute(const string& query) override;

  void startTransaction() override;
  void commit() override;
  void rollback() override;
  bool isConnectionUsable() override;
private:
  void connect();

  static bool s_dolog;
  static pthread_mutex_t s_myinitlock;

  MYSQL d_db;
  std::string d_database;
  std::string d_host;
  std::string d_msocket;
  std::string d_user;
  std::string d_password;
  std::string d_group;
  unsigned int d_timeout;
  uint16_t d_port;
  bool d_setIsolation;
  bool d_threadCleanup;
  bool d_clientSSL;
};

#endif /* SSMYSQL_HH */
