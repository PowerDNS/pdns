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

#include "config.h"
#ifdef HAVE_MMDB
#include "dnsdist-lua-types.hh"
#include "iputils.hh"
#include <maxminddb.h>
#include <memory>
#include <string>

class MMDBEntryList;
class MMDBQueryParams;

class MMDB
{
public:
  MMDB(const std::string& fname, const std::string& modeStr);
  MMDB(const MMDB&) = delete;
  MMDB(MMDB&&) = delete;
  MMDB& operator=(const MMDB&) = delete;
  MMDB& operator=(MMDB&&) = delete;

  bool query(LuaAny& ret, const MMDBQueryParams& queryParams, const ComboAddress& address) const;
  [[nodiscard]] bool exists(const ComboAddress& address) const
  {
    MMDB_lookup_result_s res{};
    return mmdbLookup(address, res);
  }
  [[nodiscard]] const std::string& file_name() const
  {
    return d_fname;
  }

  ~MMDB() { MMDB_close(&d_db); };

private:
  std::string d_fname;
  MMDB_s d_db{};

  // Decodes one of the basic types (no arrays and maps)
  static bool mmdbDecode(MMDB_entry_data_s* data, LuaAny& ret);
  static std::optional<MMDBEntryList> getEntryList(MMDB_entry_s* entry);

  [[nodiscard]] std::shared_ptr<const Logr::Logger> getLogger() const;
  // Decodes whole entry data list (supports arrays and maps too)
  bool mmdbDecodeEntryList(MMDB_entry_data_list_s** data, LuaAny& ret) const;
  bool mmdbDecodeMap(MMDB_entry_data_list_s** data, LuaAny& ret) const;
  bool mmdbDecodeArray(MMDB_entry_data_list_s** data, LuaAny& ret) const;
  bool mmdbLookup(const ComboAddress& address, MMDB_lookup_result_s& res) const;
};

class MMDBQueryParams
{
public:
  MMDBQueryParams(const LuaTypeOrArrayOf<std::string>& queryParams);

  // libmaxmind takes params (path) as a pointer to a const char*,
  // representing a const char* array, which should end with nullptr
  // This returns a pointer to the first element of the vector,
  // which still works because vector has contiguous storage
  [[nodiscard]] const char* const* get() const;

private:
  std::vector<const char*> d_params;
};

class MMDBEntryList
{
public:
  MMDBEntryList(MMDB_entry_data_list_s* first) :
    d_entry_list_first(first, MMDB_free_entry_data_list) {}

  [[nodiscard]] MMDB_entry_data_list_s* getFirst() const
  {
    return d_entry_list_first.get();
  }

private:
  std::unique_ptr<MMDB_entry_data_list_s, decltype(&MMDB_free_entry_data_list)> d_entry_list_first;
};
#else
class MMDB
{
};
#endif
