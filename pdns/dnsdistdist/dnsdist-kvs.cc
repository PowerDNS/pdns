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

#include "dnsdist-kvs.hh"
#include "dolog.hh"

#ifdef HAVE_LMDB

bool LMDBKVStore::getValue(const std::string& key, std::string& value)
{
  string_view result;
  try {
    auto transaction = d_env.getROTransaction();
    auto dbi = transaction.openDB(d_dbName, 0);
    int rc = transaction.get(dbi, MDBInVal(key), result);
    if (rc == 0) {
      value = result.to_string();
      return true;
    }
    else if (rc == MDB_NOTFOUND) {
      return false;
    }
  }
  catch(const std::exception& e) {
    warnlog("Error while looking up key '%s' from LMDB file '%s', database '%s': %s", key, d_fname, d_dbName);
  }
  return false;
}

#endif /* HAVE_LMDB */

#ifdef HAVE_CDB

bool CDBKVStore::getValue(const std::string& key, std::string& value)
{
  try {
    if (d_cdb.findOne(key, value)) {
      return true;
    }
  }
  catch(const std::exception& e) {
    warnlog("Error while looking up key '%s' from CDB file '%s': %s", key, d_fname);
  }
  return false;
}

#endif /* HAVE_CDB */
