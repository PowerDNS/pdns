/*  SQLite backend for PowerDNS
 *  Copyright (C) 2003, Michel Stol <michel@powerdns.com>
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

#ifndef SSQLITE3_HH
#define SSQLITE3_HH

#include <sqlite3.h>
#include "pdns/backends/gsql/ssql.hh"

class SSQLite3 : public SSql
{
private:
  //! Pointer to the SQLite database instance.
  sqlite3 *m_pDB;

  bool m_dolog;
  bool m_in_transaction;
  static int busyHandler(void*, int);
protected:
public:
  //! Constructor.
  SSQLite3( const std::string & database, bool creat=false );

  //! Destructor.
  ~SSQLite3();

  SSqlStatement* prepare(const string& query, int nparams);
  void execute(const string& query);
  void setLog(bool state);

  void startTransaction();
  void commit();
  void rollback();

  sqlite3 *db() { return this->m_pDB; };

  bool inTransaction() { return m_in_transaction; };

  //! Used to create an backend specific exception message.
  SSqlException sPerrorException( const std::string & reason );
};

#endif // SSQLITE3_HH

