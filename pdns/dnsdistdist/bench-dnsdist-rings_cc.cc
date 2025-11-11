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
#include <string>
#define CATCH_CONFIG_NO_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include "dnsdist-rings.hh"
#include "gettime.hh"

struct ringInfo
{
  size_t maxEntries;
  size_t numberOfShards;
  size_t nbLockTries;
};

auto simpleRings = std::vector<ringInfo>{
  {5, 1, 0},
  {500, 10, 0},
  {500, 100, 5},
  {5000, 100, 5},
  {1000000, 5000, 5},
  {1000000, 5000, 20},
};

TEST_CASE("Rings/insert")
{
  for (auto const ringInfo : simpleRings) {
    Rings rings;
    rings.init(ringInfo.maxEntries, ringInfo.numberOfShards, ringInfo.nbLockTries);

    dnsheader dnsheader{};
    memset(&dnsheader, 0, sizeof(dnsheader));
    DNSName qname("rings.powerdns.com.");
    ComboAddress requestor1("192.0.2.1");
    uint16_t qtype = QType::AAAA;
    uint16_t size = 42;
    dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
    struct timespec now{};
    gettime(&now);

    string benchName = "max=" + std::to_string(ringInfo.maxEntries) + ",shards=" + std::to_string(ringInfo.numberOfShards) + ",locktries=" + std::to_string(ringInfo.nbLockTries);

    BENCHMARK(benchName.c_str())
    {
      rings.insertQuery(now, requestor1, qname, qtype, size, dnsheader, protocol);
    };
  }
}
