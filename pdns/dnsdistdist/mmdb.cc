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

#include "dnsdist-lua-types.hh"
#include <boost/variant/get.hpp>
#include <memory>
#include <string>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dolog.hh"
#include "iputils.hh"
#include "mmdb.hh"
#include <maxminddb.h>

MMDB::MMDB(const std::string& fname, const std::string& modeStr) :
  d_fname(fname)
{
  int ec;
  int flags = 0;
  if (modeStr == "") {
    /* for the benefit of ifdef */
  }
#ifdef HAVE_MMAP
  else if (modeStr == "mmap") {
    flags |= MMDB_MODE_MMAP;
  }
#endif
  else {
    throw std::runtime_error(std::string("Unsupported mode ") + modeStr + ("for mmdb"));
  }
  memset(&d_db, 0, sizeof(d_db));
  if ((ec = MMDB_open(fname.c_str(), flags, &d_db)) < 0)
    throw std::runtime_error(std::string("Cannot open ") + fname + std::string(": ") + std::string(MMDB_strerror(ec)));
  VERBOSESLOG(infolog("Opened MMDB database %s (type: %s version: %d.%d)", fname, d_db.metadata.database_type, d_db.metadata.binary_format_major_version, d_db.metadata.binary_format_minor_version),
              dnsdist::logging::getTopLogger("mmdb")->info(Logr::Info, "Opened MMDB database", "path", Logging::Loggable(fname), "type", Logging::Loggable(d_db.metadata.database_type), "version", Logging::Loggable(std::to_string(d_db.metadata.binary_format_major_version) + "." + std::to_string(d_db.metadata.binary_format_minor_version))));
}

bool MMDB::query(LuaAny& ret, const boost::variant<const char*, std::vector<const char*>>& queryParams, const ComboAddress& ip) const
{
  MMDB_entry_data_s data;
  MMDB_lookup_result_s res;
  if (!mmdbLookup(ip, res)) {
    return false;
  }

  if (auto q = boost::get<const char*>(&queryParams)) {
    if (MMDB_get_value(&res.entry, &data, q, NULL) != MMDB_SUCCESS || !data.has_data)
      return false;
  }
  else if (auto params = boost::get<std::vector<const char*>>(&queryParams)) {
    if (MMDB_aget_value(&res.entry, &data, &params->at(0)) != MMDB_SUCCESS || !data.has_data)
      return false;
  }

  if (mmdbDecode(&data, ret)) {
    return true;
  }

  MMDB_entry_s data_entry{&d_db, data.offset};
  auto elistopt = getEntryList(&data_entry);
  if (!elistopt) {
    return false;
  }
  auto elist = std::move(*elistopt);
  auto first = elist.getFirst();
  return mmdbDecodeEntryList(&first, ret);
}

const boost::variant<const char*, std::vector<const char*>> MMDB::convertParams(const LuaTypeOrArrayOf<std::string>& queryParams)
{
  if (auto param = boost::get<std::string>(&queryParams)) {
    return param->c_str();
  }
  else if (auto params = boost::get<std::vector<std::pair<int, std::string>>>(&queryParams)) {
    auto paramsArray = std::vector<const char*>(params->size() + 1);
    for (size_t i = 0; i < params->size(); ++i) {
      paramsArray.at(i) = params->at(i).second.c_str();
    }
    paramsArray.at(params->size()) = NULL;
    return paramsArray;
  }
  else {
    return "";
  }
}

std::shared_ptr<const Logr::Logger> MMDB::getLogger() const
{
  return dnsdist::logging::getTopLogger("mmdb")->withValues("path", Logging::Loggable(d_fname));
}

bool MMDB::mmdbDecode(MMDB_entry_data_s* data, LuaAny& ret) const
{
  switch (data->type) {
  case MMDB_DATA_TYPE_BOOLEAN:
    ret = data->boolean;
    break;
  case MMDB_DATA_TYPE_UTF8_STRING:
    ret = string(data->utf8_string, data->data_size);
    break;
  case MMDB_DATA_TYPE_DOUBLE:
    ret = data->double_value;
    break;
  case MMDB_DATA_TYPE_FLOAT:
    ret = data->float_value;
    break;
  case MMDB_DATA_TYPE_INT32:
    ret = static_cast<int64_t>(data->int32);
    break;
  case MMDB_DATA_TYPE_UINT16:
    ret = static_cast<uint64_t>(data->uint16);
    break;
  case MMDB_DATA_TYPE_UINT32:
    ret = static_cast<uint64_t>(data->uint32);
    break;
  case MMDB_DATA_TYPE_UINT64:
    ret = static_cast<uint64_t>(data->uint64);
    break;
  default:
    return false;
  }
  return true;
}

bool MMDB::mmdbDecodeEntryList(MMDB_entry_data_list_s** data, LuaAny& ret) const
{
  switch ((*data)->entry_data.type) {
  case MMDB_DATA_TYPE_BOOLEAN:
  case MMDB_DATA_TYPE_UTF8_STRING:
  case MMDB_DATA_TYPE_DOUBLE:
  case MMDB_DATA_TYPE_FLOAT:
  case MMDB_DATA_TYPE_INT32:
  case MMDB_DATA_TYPE_UINT16:
  case MMDB_DATA_TYPE_UINT32:
  case MMDB_DATA_TYPE_UINT64:
    return mmdbDecode(&((*data)->entry_data), ret);
  case MMDB_DATA_TYPE_ARRAY:
    return mmdbDecodeArray(data, ret);
    break;
  case MMDB_DATA_TYPE_MAP:
    return mmdbDecodeMap(data, ret);
    break;
  default:
    return false;
  }
}

bool MMDB::mmdbDecodeMap(MMDB_entry_data_list_s** data, LuaAny& ret) const
{
  LuaAssociativeTable<LuaAny> result;

  MMDB_entry_data_list_s* this_data = *data;

  for (auto size = this_data->entry_data.data_size; size > 0; --size) {
    *data = (*data)->next;

    if (!*data) {
      break;
    }

    if ((*data)->entry_data.type != MMDB_DATA_TYPE_UTF8_STRING) {
      // Invalid key, stop decoding
      return false;
    }

    std::string key{(*data)->entry_data.utf8_string, (*data)->entry_data.data_size};

    *data = (*data)->next;
    if (!*data) {
      break;
    }

    LuaAny value;
    if (!mmdbDecodeEntryList(data, value)) {
      // Failed value decoding, stop decoding
      return false;
    }

    result.emplace(std::move(key), std::move(value));
  }

  ret = result;
  return true;
}

bool MMDB::mmdbDecodeArray(MMDB_entry_data_list_s** data, LuaAny& ret) const
{
  LuaArray<LuaAny> result;

  MMDB_entry_data_list_s* this_data = *data;

  for (uint32_t i = 0; i < this_data->entry_data.data_size; ++i) {
    *data = (*data)->next;

    if (!*data) {
      break;
    }

    LuaAny value;
    if (!mmdbDecodeEntryList(data, value)) {
      // Failed value decoding, stop decoding
      return false;
    }

    result.emplace_back(i + 1, std::move(value));
  }

  ret = result;
  return true;
}

bool MMDB::mmdbLookup(const ComboAddress& ip, MMDB_lookup_result_s& res) const
{
  int mmdb_ec = 0;
  res = MMDB_lookup_sockaddr(&d_db, reinterpret_cast<const struct sockaddr*>(&ip), &mmdb_ec);

  if (mmdb_ec != MMDB_SUCCESS) {
    VERBOSESLOG(infolog("mmdbLookup(%s) failed: %s", ip.toString(), MMDB_strerror(mmdb_ec)), getLogger()->error(Logr::Info, MMDB_strerror(mmdb_ec), "mmdbLookup failed", "ip", Logging::Loggable(ip)));
  }
  else if (res.found_entry) {
    return true;
  }
  return false;
}

std::optional<MMDBEntryList> MMDB::getEntryList(MMDB_entry_s* entry) const
{
  MMDB_entry_data_list_s* entry_data_list;
  int status = MMDB_get_entry_data_list(entry, &entry_data_list);

  if (status != MMDB_SUCCESS) {
    return std::nullopt;
  }
  return {entry_data_list};
}
