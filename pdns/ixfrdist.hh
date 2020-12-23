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
#include "yaml-cpp/yaml.h"
#include "ixfr.hh"
#include "ixfrutils.hh"


struct ixfrdiff_t {
  shared_ptr<SOARecordContent> oldSOA;
  shared_ptr<SOARecordContent> newSOA;
  vector<DNSRecord> removals;
  vector<DNSRecord> additions;
  uint32_t oldSOATTL;
  uint32_t newSOATTL;
};

struct ixfrinfo_t {
  shared_ptr<SOARecordContent> soa; // The SOA of the latest AXFR
  records_t latestAXFR;             // The most recent AXFR
  vector<std::shared_ptr<ixfrdiff_t>> ixfrDiffs;
  uint32_t soaTTL;
};

// Why a struct? This way we can add more options to a domain in the future
struct ixfrdistdomain_t {
  set<ComboAddress> masters; // A set so we can do multiple master addresses in the future
};
bool operator==(const ixfrdistdomain_t& lhs, const ixfrdistdomain_t& rhs);

bool operator==(const ixfrdistdomain_t& lhs, const ixfrdistdomain_t& rhs)
{
    return lhs.masters == rhs.masters;
}

typedef map<DNSName, ixfrdistdomain_t> ixfrdistDomainConfig;

namespace YAML {
template<>
struct convert<ixfrdistDomainConfig> {
  static Node encode(const ixfrdistDomainConfig& rhs) {
      YAML::Node ret;
      for (auto const &domainConfig : rhs) {
          YAML::Node domain;
          domain["domain"] = domainConfig.first;
          domain["master"] = domainConfig.second.masters.begin()->toStringWithPortExcept(53);
          ret.push_back(domain);
      }
      return ret;
  }

  static bool decode(const Node& node, ixfrdistDomainConfig& rhs)
  {
      if (!node.IsSequence()) {
          return false;
      }
      for (auto const &n : node) {
          if (!n.IsMap()) {
              return false;
          }
          if (!n["domain"]) {
              return false;
          }
          if (!n["master"]) {
              return false;
          }
          auto domainName = n["domain"].as<DNSName>();
          set<ComboAddress> masters({n["master"].as<ComboAddress>()});
          rhs[domainName].masters = masters;
      }
      return true;
  }
};
}