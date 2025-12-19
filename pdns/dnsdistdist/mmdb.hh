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

#include "iputils.hh"
#include <maxminddb.h>
#include <string>

class MMDB
{
public:
  MMDB(const std::string& fname, const std::string& modeStr);

  bool queryCountry(std::string& ret, const ComboAddress& ip);
  bool queryContinent(std::string& ret, const ComboAddress& ip);
  bool queryAS(std::string& ret, const ComboAddress& ip);
  bool queryASN(std::string& ret, const ComboAddress& ip);
  bool queryRegion(std::string& ret, const ComboAddress& ip);
  bool queryCity(std::string& ret, const ComboAddress& ip, const std::string& language);
  bool queryLocation(double& latitude, double& longitude, int& prec, const ComboAddress& ip);
  bool exists(const ComboAddress& ip)
  {
    MMDB_lookup_result_s res;
    return mmdbLookup(ip, res);
  }

  ~MMDB() { MMDB_close(&d_db); };

private:
  MMDB_s d_db;

  bool mmdbLookup(const ComboAddress& ip, MMDB_lookup_result_s& res);
};
