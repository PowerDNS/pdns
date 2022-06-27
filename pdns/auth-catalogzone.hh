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
#include "dnsbackend.hh"

class CatalogInfo
{
public:
  enum CatalogType : uint8_t
  {
    None,
    Producer,
    Consumer
  };

  static const char* getTypeString(enum CatalogType type)
  {
    const char* types[] = {"none", "producer", "consumer"};
    return types[type];
  }

  CatalogInfo() :
    d_type(CatalogType::None) {}
  CatalogInfo(const DNSName& zone, CatalogType type)
  {
    this->zone = zone;
    d_type = type;
  }

  void setType(CatalogType type) { d_type = type; }

  void fromJson(const std::string& json, CatalogType type);
  std::string toJson() const;

  void updateHash(CatalogHashMap& hashes, const DomainInfo& di) const;

  bool operator<(const CatalogInfo& rhs) const
  {
    return zone < rhs.zone;
  }

  DNSName coo, unique, zone;

private:
  CatalogType d_type;
  json11::Json d_doc;
};
