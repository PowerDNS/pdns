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

#include "ext/json11/json11.hpp"
#include "base32.hh"
#include "dnssecinfra.hh"

struct DomainInfo;

typedef map<ZoneName, pdns::SHADigest> CatalogHashMap;

class CatalogInfo
{
public:
  enum CatalogType : uint8_t
  {
    None,
    Producer,
    Consumer
  };

  static const string& getTypeString(enum CatalogType type)
  {
    static const std::array<const string, 3> types = {"none", "producer", "consumer"};
    return types.at(type);
  }

  CatalogInfo() :
    d_id(0), d_type(CatalogType::None) {}
  CatalogInfo(uint32_t id, const ZoneName& zone, const std::string& options, CatalogType type)
  {
    d_id = id;
    d_zone = zone;
    fromJson(options, type);
  }

  void fromJson(const std::string& json, CatalogType type);
  std::string toJson() const;
  void setType(CatalogType type) { d_type = type; }

  void updateHash(CatalogHashMap& hashes, const DomainInfo& di) const;
  DNSName getUnique() const { return DNSName(toBase32Hex(hashQNameWithSalt(std::to_string(d_id), 0, DNSName(d_zone)))); } // salt with domain id to detect recreated zones
  static DNSZoneRecord getCatalogVersionRecord(const ZoneName& zone);
  void toDNSZoneRecords(const ZoneName& zone, vector<DNSZoneRecord>& dzrs) const;

  bool operator<(const CatalogInfo& rhs) const
  {
    return d_zone < rhs.d_zone;
  }

  uint32_t d_id;
  ZoneName d_zone;
  DNSName d_coo, d_unique;
  std::set<std::string> d_group;
  vector<ComboAddress> d_primaries;

private:
  CatalogType d_type;
  json11::Json d_doc;
};
