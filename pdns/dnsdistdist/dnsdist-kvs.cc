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

#include <sys/stat.h>

std::vector<std::string> KeyValueLookupKeySourceIP::getKeys(const ComboAddress& addr)
{
  std::vector<std::string> result;

  if (addr.sin4.sin_family == AF_INET) {
    result.emplace_back(reinterpret_cast<const char*>(&addr.sin4.sin_addr.s_addr), sizeof(addr.sin4.sin_addr.s_addr));
  }
  else if (addr.sin4.sin_family == AF_INET6) {
    result.emplace_back(reinterpret_cast<const char*>(&addr.sin6.sin6_addr.s6_addr), sizeof(addr.sin6.sin6_addr.s6_addr));
  }

  return result;
}

std::vector<std::string> KeyValueLookupKeySuffix::getKeys(const DNSName& qname)
{
  if (qname.empty() || qname.isRoot()) {
    return {};
  }

  auto lowerQName = qname.makeLowerCase();
  size_t labelsCount = lowerQName.countLabels();
  if (d_minLabels != 0) {
    if (labelsCount < d_minLabels) {
      return {};
    }
    labelsCount -= (d_minLabels - 1);
  }

  std::vector<std::string> result;
  result.reserve(labelsCount);

  while(!lowerQName.isRoot()) {
    result.emplace_back(d_wireFormat ? lowerQName.toDNSString() : lowerQName.toStringRootDot());
    labelsCount--;
    if (!lowerQName.chopOff() || labelsCount == 0) {
      break;
    }
  }

  return result;
}

#ifdef HAVE_LMDB

bool LMDBKVStore::getValue(const std::string& key, std::string& value)
{
  try {
    auto transaction = d_env.getROTransaction();
    auto dbi = transaction.openDB(d_dbName, 0);
    MDBOutVal result;
    int rc = transaction.get(dbi, MDBInVal(key), result);
    if (rc == 0) {
      value = result.get<std::string>();
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

bool LMDBKVStore::keyExists(const std::string& key)
{
  try {
    auto transaction = d_env.getROTransaction();
    auto dbi = transaction.openDB(d_dbName, 0);
    MDBOutVal result;
    int rc = transaction.get(dbi, MDBInVal(key), result);
    if (rc == 0) {
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

CDBKVStore::CDBKVStore(const std::string& fname, time_t refreshDelay): d_fname(fname), d_refreshDelay(refreshDelay)
{
  pthread_rwlock_init(&d_lock, nullptr);
  d_refreshing.clear();

  time_t now = time(nullptr);
  if (d_refreshDelay > 0) {
    d_nextCheck = now + d_refreshDelay;
  }

  refreshDBIfNeeded(now);
}

bool CDBKVStore::reload(const struct stat& st)
{
  auto newCDB = std::unique_ptr<CDB>(new CDB(d_fname));
  {
    WriteLock wl(&d_lock);
    d_cdb = std::move(newCDB);
  }
  d_mtime = st.st_mtime;
  return true;
}

bool CDBKVStore::reload()
{
  struct stat st;
  if (stat(d_fname.c_str(), &st) == 0) {
    return reload(st);
  }
  else {
    warnlog("Error while retrieving the last modification time of CDB database '%s': %s", d_fname, stringerror());
    return false;
  }
}

void CDBKVStore::refreshDBIfNeeded(time_t now)
{
  if (d_refreshing.test_and_set()) {
    /* someone else is already refreshing */
    return;
  }

  try {
    struct stat st;
    if (stat(d_fname.c_str(), &st) == 0) {
      if (st.st_mtime > d_mtime) {
        reload(st);
      }
    }
    else {
      warnlog("Error while retrieving the last modification time of CDB database '%s': %s", d_fname, stringerror());
    }
    d_nextCheck = now + d_refreshDelay;
    d_refreshing.clear();
  }
  catch(...) {
    d_refreshing.clear();
    throw;
  }
}

bool CDBKVStore::getValue(const std::string& key, std::string& value)
{
  time_t now = time(nullptr);

  try {
    if (d_nextCheck != 0 && now >= d_nextCheck) {
      refreshDBIfNeeded(now);
    }

    {
      ReadLock rl(&d_lock);
      if (d_cdb && d_cdb->findOne(key, value)) {
        return true;
      }
    }
  }
  catch(const std::exception& e) {
    warnlog("Error while looking up key '%s' from CDB file '%s': %s", key, d_fname);
  }
  return false;
}

bool CDBKVStore::keyExists(const std::string& key)
{
  time_t now = time(nullptr);

  try {
    if (d_nextCheck != 0 && now >= d_nextCheck) {
      refreshDBIfNeeded(now);
    }

    {
      ReadLock rl(&d_lock);
      if (!d_cdb) {
        return false;
      }

      return d_cdb->keyExists(key);
    }
  }
  catch(const std::exception& e) {
    warnlog("Error while looking up key '%s' from CDB file '%s': %s", key, d_fname);
  }
  return false;
}

#endif /* HAVE_CDB */
