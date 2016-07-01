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

#ifndef GSQLITEBACKEND_HH
#define GSQLITEBACKEND_HH

#include <string>
#include "pdns/backends/gsql/gsqlbackend.hh"

//! The gSQLiteBackend retrieves it's data from a SQLite database (http://www.sqlite.org/)
class gSQLite3Backend : public GSQLBackend
{
public:
  //! Constructs the backend, throws an exception if it failed..
  gSQLite3Backend( const std::string & mode, const std::string & suffix );
};

#endif // GSQLITEBACKEND_HH
