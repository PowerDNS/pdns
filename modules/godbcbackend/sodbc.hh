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

#include <sql.h>
#include <sqlext.h>

#include "pdns/backends/gsql/ssql.hh"

//! ODBC SSql implementation for use with the Generic ODBC Backend.
class SODBC : public SSql
{
private:
  bool m_log; //!< Should we log?
  bool m_busy; //!< Are we busy executing a query?

  SQLHDBC m_connection; //!< Database connection handle.
  SQLHENV m_environment; //!< Database environment handle

  void testResult(SQLRETURN result, SQLSMALLINT type, SQLHANDLE handle, const std::string& message);

public:
  //! Default constructor.
  /*!
  This constructor connects to an ODBC datasource and makes sure it's ready to use.

  \param dsn The ODBC DSN to use.
  \param username Username to use.
  \param password Password to use.
  */
  SODBC(
    const std::string& dsn,
    const std::string& username,
    const std::string& password);

  //! Destructor.
  virtual ~SODBC(void);

  //! Sets the logging state.
  void setLog(bool state) override;

  std::unique_ptr<SSqlStatement> prepare(const string& query, int nparams) override;
  void execute(const string& query) override;
  void startTransaction() override;
  void rollback() override;
  void commit() override;

  //! Returns an exception.
  SSqlException sPerrorException(const std::string& reason) override;
};
