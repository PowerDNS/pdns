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
    throw std::runtime_error("Failed to open cdb database file '"+cdbfile+"'. Error: " + stringerror());
  }

  memset(&d_cdbf,0,sizeof(struct cdb_find));
  int cdbinit = cdb_init(&d_cdb, d_fd);
  if (cdbinit < 0)
  {
    close(d_fd);
    d_fd = -1;
    throw std::runtime_error("Failed to initialize cdb structure. ErrorNt: '" + std::to_string(cdbinit) + "'");
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
    cdb_read(&d_cdb, &key[0], len, pos);

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
    cdb_read(&d_cdb, &val[0], len, pos);

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

  cdb_findinit(&cdbf, &d_cdb, key.c_str(), key.size());
  int x=0;
  while(cdb_findnext(&cdbf) > 0) {
    x++;
    unsigned int vpos = cdb_datapos(&d_cdb);
    unsigned int vlen = cdb_datalen(&d_cdb);
    std::string val;
    val.resize(vlen);
    cdb_read(&d_cdb, &val[0], vlen, vpos);
    ret.push_back(std::move(val));
  }

  return ret;
}
