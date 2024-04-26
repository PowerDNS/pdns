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
#include <sqlite3.h>
#include "pdns/backends/gsql/ssql.hh"

class SSQLite3 : public SSql
{
private:
  //! Pointer to the SQLite database instance.
  sqlite3* m_pDB{nullptr};

  bool m_dolog;
  bool m_in_transaction;
  static int busyHandler(void*, int);

  void executeImpl(const string& query);

public:
  //! Constructor.
  SSQLite3(const std::string& database, const std::string& journalmode, bool creat = false);

  //! Destructor.
  ~SSQLite3() override;

  std::unique_ptr<SSqlStatement> prepare(const string& query, int nparams) override;
  void execute(const string& query) override;
  void setLog(bool state) override;

  void startTransaction() override;
  void commit() override;
  void rollback() override;

  sqlite3* db() { return this->m_pDB; };

  [[nodiscard]] bool inTransaction() const { return m_in_transaction; };

  //! Used to create an backend specific exception message.
  SSqlException sPerrorException(const std::string& reason) override;
};
