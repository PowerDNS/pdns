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

#include "pdns/logger.hh"
#include <cdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

// This class is responsible for the reading of a CDB file.
// The constructor opens the CDB file, the destructor closes it, so make sure you call that.
class CDB
{
public:
  CDB(const string &cdbfile);
  ~CDB();

  int searchKey(const string &key);
  bool searchSuffix(const string &key);
  void searchAll();
  bool readNext(pair<string, string> &value);
  vector<string> findall(string &key);

private:
  int d_fd;
  bool moveToNext();
  struct cdb d_cdb;
  struct cdb_find d_cdbf;
  char *d_key;
  unsigned d_seqPtr;
  enum SearchType { SearchSuffix, SearchKey, SearchAll } d_searchType;
};

#endif // CDB_HH
