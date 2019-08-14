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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "cdb.hh"

CDB::CDB(const string &cdbfile)
{
  d_fd = open(cdbfile.c_str(), O_RDONLY);
  if (d_fd < 0)
  {
    throw std::runtime_error("Failed to open cdb database file '"+cdbfile+"': " + stringerror());
  }

  memset(&d_cdbf,0,sizeof(struct cdb_find));
  int cdbinit = cdb_init(&d_cdb, d_fd);
  if (cdbinit < 0)
  {
    close(d_fd);
    d_fd = -1;
    throw std::runtime_error("Failed to initialize cdb structure for database '+cdbfile+': '" + std::to_string(cdbinit) + "'");
  }
}

CDB::~CDB() {
  cdb_free(&d_cdb);
  close(d_fd);
}

int CDB::searchKey(const string &key) {
  d_searchType = SearchKey;

  // A 'bug' in tinycdb (the lib used for reading the CDB files) means we have to copy the key because the cdb_find struct
  // keeps a pointer to it.
  d_key = key;
  return cdb_findinit(&d_cdbf, &d_cdb, d_key.c_str(), d_key.size());
}

bool CDB::searchSuffix(const string &key) {
  d_searchType = SearchSuffix;

  //See CDB::searchKey()
  d_key = key;

  // We are ok with a search on things, but we do want to know if a record with that key exists.........
  bool hasDomain = (cdb_find(&d_cdb, d_key.c_str(), d_key.size()) == 1);
  if (hasDomain) {
    cdb_seqinit(&d_seqPtr, &d_cdb);
  }

  return hasDomain;
}

void CDB::searchAll() {
  d_searchType = SearchAll;
  cdb_seqinit(&d_seqPtr, &d_cdb);
}

bool CDB::moveToNext() {
  int hasNext = 0;
  if (d_searchType == SearchKey) {
    hasNext = cdb_findnext(&d_cdbf);
  } else {
    hasNext = cdb_seqnext(&d_seqPtr, &d_cdb);
  }
  return (hasNext > 0);
}

bool CDB::readNext(pair<string, string> &value) {
  while (moveToNext()) {
    unsigned int pos;
    unsigned int len;

    pos = cdb_keypos(&d_cdb);
    len = cdb_keylen(&d_cdb);

    std::string key;
    key.resize(len);
    int ret = cdb_read(&d_cdb, &key[0], len, pos);
    if (ret < 0) {
      throw std::runtime_error("Error while reading key for key '" + key + "' from CDB database: " + std::to_string(ret));
    }

    if (d_searchType == SearchSuffix) {
      char *p = strstr(const_cast<char*>(key.c_str()), d_key.c_str());
      if (p == nullptr) {
        continue;
      }
    }

    pos = cdb_datapos(&d_cdb);
    len = cdb_datalen(&d_cdb);
    std::string val;
    val.resize(len);
    ret = cdb_read(&d_cdb, &val[0], len, pos);
    if (ret < 0) {
      throw std::runtime_error("Error while reading value for key '" + key + "' from CDB database: " + std::to_string(ret));
    }

    value = make_pair(std::move(key), std::move(val));
    return true;
  }

  // We're done searching, so we can clean up d_key
  if (d_searchType != SearchAll) {
    d_key.clear();
  }

  return false;
}

vector<string> CDB::findall(string &key)
{
  vector<string> ret;
  struct cdb_find cdbf;

  int res = cdb_findinit(&cdbf, &d_cdb, key.c_str(), key.size());
  if (res < 0) {
    throw std::runtime_error("Error looking up key '" + key + "' from CDB database: " + std::to_string(res));
  }

  int x=0;
  while(cdb_findnext(&cdbf) > 0) {
    x++;
    unsigned int vpos = cdb_datapos(&d_cdb);
    unsigned int vlen = cdb_datalen(&d_cdb);
    std::string val;
    val.resize(vlen);
    res = cdb_read(&d_cdb, &val[0], vlen, vpos);
    if (res < 0) {
      throw std::runtime_error("Error while reading value for key '" + key + "' from CDB database: " + std::to_string(res));
    }
    ret.push_back(std::move(val));
  }

  return ret;
}

bool CDB::keyExists(const string& key)
{
  int ret = cdb_find(&d_cdb, key.c_str(), key.size());
  if (ret < 0) {
    throw std::runtime_error("Error while looking up key '" + key + "' from CDB database: " + std::to_string(ret));
  }
  if (ret == 0) {
    /* no such key */
    return false;
  }

  return true;
}

bool CDB::findOne(const string& key, string& value)
{
  if (!keyExists(key)) {
    return false;
  }

  unsigned int vpos = cdb_datapos(&d_cdb);
  unsigned int vlen = cdb_datalen(&d_cdb);
  value.resize(vlen);
  int ret = cdb_read(&d_cdb, &value[0], vlen, vpos);
  if (ret < 0) {
    throw std::runtime_error("Error while reading value for key '" + key + "' from CDB database: " + std::to_string(ret));
  }

  return true;
}

CDBWriter::CDBWriter(int fd): d_fd(fd)
{
  cdb_make_start(&d_cdbm, d_fd);
}

CDBWriter::~CDBWriter()
{
  close();
}

void CDBWriter::close()
{
  if (d_fd >= 0) {
    cdb_make_finish(&d_cdbm);
    ::close(d_fd);
    d_fd = -1;
  }
}

bool CDBWriter::addEntry(const std::string& key, const std::string& value)
{
  if (d_fd < 0) {
    throw std::runtime_error("Can't add an entry to a closed CDB database");
  }

  int ret = cdb_make_add(&d_cdbm, key.c_str(), key.size(), value.c_str(), value.size());
  if (ret != 0) {
    throw std::runtime_error("Error adding key '" + key + "' to CDB database: " + std::to_string(ret));
  }

  return true;
}
