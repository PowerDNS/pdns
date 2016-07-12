/*
 *  PowerDNS gMySQL backend
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
#ifndef PDNS_GMYSQLBACKEND_HH
#define PDNS_GMYSQLBACKEND_HH

#include <string>
#include <map>
#include "pdns/backends/gsql/gsqlbackend.hh"

#include "pdns/namespaces.hh"

/** The gMySQLBackend is a DNSBackend that can answer DNS related questions. It looks up data
    in MySQL */
class gMySQLBackend : public GSQLBackend
{
public:
  gMySQLBackend(const string &mode, const string &suffix); //!< Makes our connection to the database. Throws an exception if it fails.
};

#endif /* PDNS_GMYSQLBACKEND_HH */
