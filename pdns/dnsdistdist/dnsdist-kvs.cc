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

std::vector<std::string> KeyValueLookupKeySourceIP::getKeys(const DNSQuestion& dq)
{
  std::vector<std::string> result;

  if (dq.remote->sin4.sin_family == AF_INET) {
    result.emplace_back(reinterpret_cast<const char*>(&dq.remote->sin4.sin_addr.s_addr), sizeof(dq.remote->sin4.sin_addr.s_addr));
  }
  else if (dq.remote->sin4.sin_family == AF_INET6) {
    result.emplace_back(reinterpret_cast<const char*>(&dq.remote->sin6.sin6_addr.s6_addr), sizeof(dq.remote->sin6.sin6_addr.s6_addr));
  }

  return result;
}

std::vector<std::string> KeyValueLookupKeySuffix::getKeys(const DNSName& qname)
{
  if (qname.empty() || qname.isRoot()) {
    return {};
  }

  auto lowerQName = qname.makeLowerCase();
  std::vector<std::string> result;
  result.reserve(lowerQName.countLabels() - 1);

  while(!lowerQName.isRoot()) {
    result.emplace_back(lowerQName.toDNSString());
    if (!lowerQName.chopOff()) {
      break;
    }
  }

  return result;
}

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
    warnlog("Error while looking up key '%s' from LMDB file '%s', database '%s': %s", key, d_fname, d_dbName, e.what());
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
