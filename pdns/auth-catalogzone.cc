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

#include "auth-catalogzone.hh"

void CatalogInfo::fromJson(const std::string& json, CatalogType type)
{
  d_type = type;
  if (d_type == CatalogType::None) {
    throw std::runtime_error("CatalogType is set to None");
  }
  if (json.empty()) {
    return;
  }
  std::string err;
  d_doc = json11::Json::parse(json, err);
  if (!d_doc.is_null()) {
    if (!d_doc[getTypeString(d_type)].is_null()) {
      auto items = d_doc[getTypeString(type)].object_items();
      if (items["coo"].is_string()) {
        if (!items["coo"].string_value().empty()) {
          this->coo = DNSName(items["coo"].string_value());
        }
      }
      else {
        throw std::out_of_range("Key 'coo' is not a string");
      }
      if (items["unique"].is_string()) {
        if (!items["uniq"].string_value().empty()) {
          this->unique = DNSName(items["unique"].string_value());
        }
      }
      else {
        throw std::out_of_range("Key 'unique' is not a string");
      }
    }
  }
  else {
    throw std::runtime_error("Parsing of JSON options failed: " + err);
  }
}

std::string CatalogInfo::toJson() const
{
  if (d_type == CatalogType::None) {
    throw std::runtime_error("CatalogType is set to None");
  }
  json11::Json::object object;
  if (!coo.empty()) {
    object["coo"] = coo.toString();
  }
  if (!unique.empty()) {
    object["unique"] = unique.toString();
  }
  auto tmp = d_doc.object_items();
  tmp[getTypeString(d_type)] = object;
  const json11::Json ret = tmp;
  return ret.dump();
}

void CatalogInfo::updateHash(CatalogHashMap& hashes, const DomainInfo& di) const
{
  hashes[di.catalog].process(static_cast<char>(di.id) + di.zone.toLogString() + "\0" + this->coo.toLogString() + "\0" + this->unique.toLogString());
}
