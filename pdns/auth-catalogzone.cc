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
#include "json.hh"

bool CatalogInfo::parseJson(const std::string& json, CatalogType type)
{
  if (type == CatalogType::None) {
    throw std::runtime_error("CatalogType is set to None");
  }

  d_type = type;

  if (json.empty()) {
    d_doc = nullptr;
    return false;
  }

  std::string err;
  d_doc = json11::Json::parse(json, err);
  if (d_doc.is_null()) {
    throw std::runtime_error("Parsing of JSON options failed: " + err);
  }

  return !d_doc[getTypeString(d_type)].is_null();
}

void CatalogInfo::fromJson(const std::string& json, CatalogType type)
{
  if (parseJson(json, type)) {
    auto items = d_doc[getTypeString(type)].object_items();

    // coo property
    if (!items["coo"].is_null()) {
      d_coo = DNSName(stringFromJson(items, "coo"));
    }

    // unique property
    if (!items["unique"].is_null()) {
      d_unique = DNSName(stringFromJson(items, "unique"));
      if (d_unique.countLabels() != 1) {
        throw std::out_of_range("Invalid number of labels in unique value");
      }
    }

    // group properties
    if (!items["group"].is_null()) {
      if (!items["group"].is_array()) {
        throw std::out_of_range("Key 'group' is not an array");
      }
      for (const auto& value : items["group"].array_items()) {
        d_group.insert(value.string_value());
      }
    }
  }
}

std::string CatalogInfo::toJson() const
{
  if (d_type == CatalogType::None) {
    throw std::runtime_error("CatalogType is set to None");
  }
  json11::Json::object object;

  // coo property
  if (!d_coo.empty()) {
    object["coo"] = d_coo.toString();
  }

  // unique property
  if (!d_unique.empty()) {
    if (d_unique.countLabels() != 1) {
      throw std::out_of_range("Invalid number of labels in unique value");
    }
    object["unique"] = d_unique.toString();
  }

  // group properties
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

void CatalogInfo::updateCatalogHash(CatalogHashMap& hashes, const DomainInfo& di)
{
  CatalogInfo ci;
  hashes[di.catalog].process(std::to_string(di.id) + di.zone.toLogString());
  if (ci.parseJson(di.options, CatalogType::Producer)) {
    hashes[di.catalog].process(ci.d_doc["producer"].dump());
  }
}

DNSZoneRecord CatalogInfo::getCatalogVersionRecord(const DNSName& zone)
{
  DNSZoneRecord dzr;
  dzr.dr.d_name = DNSName("version") + zone;
  dzr.dr.d_type = QType::TXT;
  dzr.dr.setContent(std::make_shared<TXTRecordContent>("2"));
  return dzr;
}

void CatalogInfo::toDNSZoneRecords(const DNSName& zone, vector<DNSZoneRecord>& dzrs) const
{
  DNSName prefix;
  if (d_unique.empty()) {
    prefix = getUnique();
  }
  else {
    prefix = d_unique;
  }
  prefix += DNSName("zones") + zone;

  // member zone
  DNSZoneRecord dzr;
  dzr.dr.d_name = prefix;
  dzr.dr.d_type = QType::PTR;
  dzr.dr.setContent(std::make_shared<PTRRecordContent>(d_zone.toString()));
  dzrs.emplace_back(dzr);

  // coo property
  if (!d_coo.empty()) {
    dzr.dr.d_name = DNSName("coo") + prefix;
    dzr.dr.d_type = QType::PTR;
    dzr.dr.setContent(std::make_shared<PTRRecordContent>(d_coo));
    dzrs.emplace_back(dzr);
  }

  // group properties
  for (const auto& group : d_group) {
    dzr.dr.d_name = DNSName("group") + prefix;
    dzr.dr.d_type = QType::TXT;
    dzr.dr.setContent(std::make_shared<TXTRecordContent>("\"" + group + "\""));
    dzrs.emplace_back(dzr);
  }
}
