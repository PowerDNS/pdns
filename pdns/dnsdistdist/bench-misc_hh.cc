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
#include "misc.hh"

#define CATCH_CONFIG_NO_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/benchmark/catch_chronometer.hpp>

TEST_CASE("misc.hh/stringtok", "[misc.hh]")
{
  std::vector<pair<uint8_t, string>> inStrings{
    {0, ""},
    {1, "the"},
    {3, "the quick brown"},
    {5, "the quick brown fox jumped"},
    {7, "the quick brown fox jumped over the"},
    {9, "the quick brown fox jumped over the lazy fox"},
  };

  vector<std::string> tokParts;
  vector<pair<unsigned int, unsigned>> vtokParts;

  for (auto const& inStr : inStrings) {
    string benchmarkNameSuffix("stringtok " + std::to_string(inStr.first) + " words");
    BENCHMARK_ADVANCED(benchmarkNameSuffix.c_str())(Catch::Benchmark::Chronometer meter)
    {
      // SetUp
      tokParts.clear();
      meter.measure([&inStr, &tokParts] {
        stringtok(tokParts, inStr.second);
      });
    };

    string vtokBenchmarkName("v" + benchmarkNameSuffix);
    BENCHMARK_ADVANCED(vtokBenchmarkName.c_str())(Catch::Benchmark::Chronometer meter)
    {
      // SetUp
      vtokParts.clear();
      meter.measure([&inStr, &vtokParts] {
        vstringtok(vtokParts, inStr.second);
      });
    };
  }
}

TEST_CASE("misc.hh/pdns_iequals", "[misc.hh]")
{
  static string first("www.powerdns.com");
  static string second("www.example.com");

  BENCHMARK("std::string")
  {
    return pdns_iequals(first, second);
  };

  static const char* first_cstr = first.c_str();
  static const char* second_cstr = second.c_str();

  BENCHMARK("const char*")
  {
    return pdns_iequals(first_cstr, second_cstr);
  };
}
