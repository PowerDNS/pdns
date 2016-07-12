/*
 *  PowerDNS gpgsql backend
 *  By PowerDNS.COM BV
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  Additionally, the license of this program contains a special
 *  exception which allows to distribute the program in binary form when
 *  it is linked against OpenSSL.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef SPGSQL_HH
#define SPGSQL_HH
#include "pdns/namespaces.hh"
#include "pdns/backends/gsql/ssql.hh"

#include <libpq-fe.h>
class SPgSQL : public SSql
{
public:
  SPgSQL(const string &database, const string &host="", const string& port="",
         const string &user="", const string &password="");

  ~SPgSQL();
  
  SSqlException sPerrorException(const string &reason);
  void setLog(bool state);
  SSqlStatement* prepare(const string& query, int nparams);
  void execute(const string& query);

  void startTransaction();
  void rollback();
  void commit();

  PGconn* db() { return d_db; }
  bool in_trx() { return d_in_trx; }

private:
  PGconn* d_db;
  string d_connectstr;
  string d_connectlogstr;
  static bool s_dolog;
  bool d_in_trx;
};
      
#endif /* SPGSQL_HH */
