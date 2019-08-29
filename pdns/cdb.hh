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
#ifndef CDB_HH
#define CDB_HH

#include <cdb.h>

#include "misc.hh"

// This class is responsible for the reading of a CDB file.
// The constructor opens the CDB file, the destructor closes it, so make sure you call that.
class CDB
{
public:
  CDB(const string &cdbfile);
  ~CDB();

  /* Return negative value on error or non-negative value on success.
     Values can be retrieved via readNext() */
  int searchKey(const string &key);
  bool searchSuffix(const string &key);
  void searchAll();
  bool readNext(pair<string, string> &value);
  vector<string> findall(string &key);
  bool keyExists(const string& key);
  bool findOne(const string& key, string& value);

private:
  bool moveToNext();

  int d_fd{-1};
  struct cdb d_cdb;
  struct cdb_find d_cdbf;
  std::string d_key;
  unsigned d_seqPtr{0};
  enum SearchType { SearchSuffix, SearchKey, SearchAll } d_searchType{SearchKey};
};

class CDBWriter
{
public:
  /* we own the fd after this call, don't ever touch it */
  CDBWriter(int fd);
  ~CDBWriter();

  bool addEntry(const std::string& key, const std::string& value);
  /* finalize the database and close the fd, the only thing you can do now is to call the destructor */
  void close();

private:
  struct cdb_make d_cdbm;
  int d_fd{-1};
};

#endif // CDB_HH
