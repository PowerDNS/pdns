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
  ComboAddress truncated(addr);

  std::string key;
  if (truncated.isIPv4()) {
    truncated.truncate(d_v4Mask);
    key.reserve(sizeof(truncated.sin4.sin_addr.s_addr) + (d_includePort ? sizeof(truncated.sin4.sin_port) : 0));
    key.append(reinterpret_cast<const char*>(&truncated.sin4.sin_addr.s_addr), sizeof(truncated.sin4.sin_addr.s_addr));
  }
  else if (truncated.isIPv6()) {
    truncated.truncate(d_v6Mask);
    key.reserve(sizeof(truncated.sin6.sin6_addr.s6_addr) + (d_includePort ? sizeof(truncated.sin4.sin_port) : 0));
    key.append(reinterpret_cast<const char*>(&truncated.sin6.sin6_addr.s6_addr), sizeof(truncated.sin6.sin6_addr.s6_addr));
  }

  if (d_includePort) {
    key.append(reinterpret_cast<const char*>(&truncated.sin4.sin_port), sizeof(truncated.sin4.sin_port));
  }

  result.push_back(std::move(key));

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

  while (!lowerQName.isRoot()) {
    result.emplace_back(d_wireFormat ? lowerQName.toDNSString() : lowerQName.toStringRootDot());
    labelsCount--;
    if (!lowerQName.chopOff() || labelsCount == 0) {
      break;
    }
  }

  return result;
}

#ifdef HAVE_LMDB
std::shared_ptr<const Logr::Logger> LMDBKVStore::getLogger() const
{
  return dnsdist::logging::getTopLogger("lmdb-key-value-store")->withValues("path", Logging::Loggable(d_fname), "database", Logging::Loggable(d_dbName));
}

bool LMDBKVStore::getValue(const std::string& key, std::string& value)
{
  try {
    auto transaction = d_env->getROTransaction();
    MDBOutVal result;
    int rc = transaction->get(d_dbi, MDBInVal(key), result);
    if (rc == 0) {
      value = result.get<std::string>();
      return true;
    }
    else if (rc == MDB_NOTFOUND) {
      return false;
    }
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Error while looking up key '%s' from LMDB file '%s', database '%s': %s", key, d_fname, d_dbName, e.what()),
                getLogger()->error(Logr::Info, e.what(), "Error while looking up key", "key", Logging::Loggable(key)));
  }
  return false;
}

bool LMDBKVStore::keyExists(const std::string& key)
{
  try {
    auto transaction = d_env->getROTransaction();
    MDBOutVal result;
    int rc = transaction->get(d_dbi, MDBInVal(key), result);
    if (rc == 0) {
      return true;
    }
    else if (rc == MDB_NOTFOUND) {
      return false;
    }
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Error while looking up key '%s' from LMDB file '%s', database '%s': %s", key, d_fname, d_dbName, e.what()),
                getLogger()->error(Logr::Info, e.what(), "Error while looking up key", "key", Logging::Loggable(key)));
  }
  return false;
}

bool LMDBKVStore::getRangeValue(const std::string& key, std::string& value)
{
  try {
    auto transaction = d_env->getROTransaction();
    auto cursor = transaction->getROCursor(d_dbi);
    MDBOutVal actualKey;
    MDBOutVal result;
    // for range-based lookups, we expect the data in LMDB
    // to be stored with the last value of the range as key
    // and the first value of the range as data, sometimes
    // followed by any other content we don't care about
    // range-based lookups are mostly useful for network ranges,
    // for which we expect addresses to be stored in network byte
    // order

    // retrieve the first key greater or equal to our key
    int rc = cursor.lower_bound(MDBInVal(key), actualKey, result);

    if (rc == 0) {
      auto last = actualKey.get<std::string>();
      if (last.size() != key.size() || key > last) {
        return false;
      }

      value = result.get<std::string>();
      if (value.size() < key.size()) {
        return false;
      }

      // take the first part of the data, which should be
      // the first address of the range
      auto first = value.substr(0, key.size());
      if (first.size() != key.size() || key < first) {
        return false;
      }

      return true;
    }
    else if (rc == MDB_NOTFOUND) {
      return false;
    }
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Error while looking up a range from LMDB file '%s', database '%s': %s", d_fname, d_dbName, e.what()),
                getLogger()->error(Logr::Info, e.what(), "Error while looking up a range", "key", Logging::Loggable(key)));
  }
  return false;
}

#endif /* HAVE_LMDB */

#ifdef HAVE_CDB
std::shared_ptr<const Logr::Logger> CDBKVStore::getLogger() const
{
  return dnsdist::logging::getTopLogger("cdb-key-value-store")->withValues("path", Logging::Loggable(d_fname));
}

CDBKVStore::CDBKVStore(const std::string& fname, time_t refreshDelay) :
  d_fname(fname), d_refreshDelay(refreshDelay)
{
  d_refreshing.clear();

  time_t now = time(nullptr);
  if (d_refreshDelay > 0) {
    d_nextCheck = now + d_refreshDelay;
  }

  refreshDBIfNeeded(now);
}

CDBKVStore::~CDBKVStore()
{
}

bool CDBKVStore::reload(const struct stat& st)
{
  auto newCDB = std::make_unique<CDB>(d_fname);
  {
    *(d_cdb.write_lock()) = std::move(newCDB);
  }
  d_mtime = st.st_mtime;
  return true;
}

bool CDBKVStore::reload()
{
  struct stat st{};
  if (stat(d_fname.c_str(), &st) == 0) {
    return reload(st);
  }
  else {
    int savederrno = errno;
    SLOG(warnlog("Error while retrieving the last modification time of CDB database '%s': %s", d_fname, stringerror(savederrno)),
         getLogger()->error(Logr::Warning, savederrno, "Error while retrieving the last modification time of the database"));
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
    struct stat st{};
    if (stat(d_fname.c_str(), &st) == 0) {
      if (st.st_mtime > d_mtime) {
        reload(st);
      }
    }
    else {
      int savederrno = errno;
      SLOG(warnlog("Error while retrieving the last modification time of CDB database '%s': %s", d_fname, stringerror(savederrno)),
           getLogger()->error(Logr::Warning, savederrno, "Error while retrieving the last modification time of the database"));
    }
    d_nextCheck = now + d_refreshDelay;
    d_refreshing.clear();
  }
  catch (...) {
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
      auto cdb = d_cdb.read_lock();
      if (*cdb && (*cdb)->findOne(key, value)) {
        return true;
      }
    }
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Error while looking up key '%s' from CDB file '%s': %s", key, d_fname, e.what()),
                getLogger()->error(Logr::Info, e.what(), "Error while looking up a key", "key", Logging::Loggable(key)));
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
      auto cdb = d_cdb.read_lock();
      if (!*cdb) {
        return false;
      }

      return (*cdb)->keyExists(key);
    }
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Error while looking up key '%s' from CDB file '%s': %s", key, d_fname, e.what()),
                getLogger()->error(Logr::Info, e.what(), "Error while looking up a key", "key", Logging::Loggable(key)));
  }
  return false;
}

#endif /* HAVE_CDB */
