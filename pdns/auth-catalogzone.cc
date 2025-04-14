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

#include "dnsbackend.hh"

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
      if (!items["coo"].is_null()) {
        if (items["coo"].is_string()) {
          if (!items["coo"].string_value().empty()) {
            d_coo = DNSName(items["coo"].string_value());
          }
        }
        else {
          throw std::out_of_range("Key 'coo' is not a string");
        }
      }
      if (!items["unique"].is_null()) {
        if (items["unique"].is_string()) {
          if (!items["unique"].string_value().empty()) {
            d_unique = DNSName(items["unique"].string_value());
          }
        }
        else {
          throw std::out_of_range("Key 'unique' is not a string");
        }
      }
      if (!items["group"].is_null()) {
        if (items["group"].is_array()) {
          for (const auto& value : items["group"].array_items()) {
            d_group.insert(value.string_value());
          }
        }
        else {
          throw std::out_of_range("Key 'group' is not an array");
        }
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
  if (!d_coo.empty()) {
    object["coo"] = d_coo.toString();
  }
  if (!d_unique.empty()) {
    if (d_unique.countLabels() > 1) {
      throw std::out_of_range("Multiple labels in a unique value are not allowed");
    }
    object["unique"] = d_unique.toString();
  }
  if (!d_group.empty()) {
    json11::Json::array entries;
    for (const auto& group : d_group) {
      entries.push_back(group);
    }
    object["group"] = entries;
  }
  auto tmp = d_doc.object_items();
  tmp[getTypeString(d_type)] = object;
  const json11::Json ret = tmp;
  return ret.dump();
}

void CatalogInfo::updateHash(CatalogHashMap& hashes, const DomainInfo& di) const
{
  hashes[di.catalog].process(std::to_string(di.id) + di.zone.toLogString() + string("\0", 1) + d_coo.toLogString() + string("\0", 1) + d_unique.toLogString());
  for (const auto& group : d_group) {
    hashes[di.catalog].process(std::to_string(group.length()) + group);
  }
}

DNSZoneRecord CatalogInfo::getCatalogVersionRecord(const ZoneName& zone)
{
  DNSZoneRecord dzr;
  dzr.dr.d_name = DNSName("version") + zone;
  dzr.dr.d_ttl = 0;
  dzr.dr.d_type = QType::TXT;
  dzr.dr.setContent(std::make_shared<TXTRecordContent>("2"));
  return dzr;
}

void CatalogInfo::toDNSZoneRecords(const ZoneName& zone, vector<DNSZoneRecord>& dzrs) const
{
  DNSName prefix;
  if (d_unique.empty()) {
    prefix = getUnique();
  }
  else {
    prefix = d_unique;
  }
  prefix += DNSName("zones") + zone;

  DNSZoneRecord dzr;
  dzr.dr.d_name = prefix;
  dzr.dr.d_ttl = 0;
  dzr.dr.d_type = QType::PTR;
  dzr.dr.setContent(std::make_shared<PTRRecordContent>(d_zone.toString()));
  dzrs.emplace_back(dzr);

  if (!d_coo.empty()) {
    dzr.dr.d_name = DNSName("coo") + prefix;
    dzr.dr.d_ttl = 0;
    dzr.dr.d_type = QType::PTR;
    dzr.dr.setContent(std::make_shared<PTRRecordContent>(d_coo));
    dzrs.emplace_back(dzr);
  }

  for (const auto& group : d_group) {
    dzr.dr.d_name = DNSName("group") + prefix;
    dzr.dr.d_ttl = 0;
    dzr.dr.d_type = QType::TXT;
    dzr.dr.setContent(std::make_shared<TXTRecordContent>("\"" + group + "\""));
    dzrs.emplace_back(dzr);
  }
}
