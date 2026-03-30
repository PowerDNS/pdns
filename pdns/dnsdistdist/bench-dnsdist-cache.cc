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
#include <vector>
#include <thread>

#define CATCH_CONFIG_NO_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include "dnsdist-cache.hh"
#include "dnsdist.hh"
#include "dnswriter.hh"

static PacketBuffer getQuery(const InternalQueryState& ids)
{
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, ids.qtype, ids.qclass, 0);
  pwQ.getHeader()->id = 42U;
  pwQ.getHeader()->rd = 1;
  return query;
}

static PacketBuffer getResponse(const InternalQueryState& ids)
{
  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, ids.qtype, ids.qclass, 0);
  pwR.getHeader()->rd = 1;
  pwR.getHeader()->ra = 1;
  pwR.getHeader()->qr = 1;
  pwR.getHeader()->id = 42U;
  pwR.startRecord(ids.qname, ids.qtype, 7200, ids.qclass, DNSResourceRecord::ANSWER);
  pwR.xfr32BitInt(0x01020304);
  pwR.commit();
  return response;
}

TEST_CASE("Cache/Lookup")
{
  DNSDistPacketCache::CacheSettings settings;
  settings.d_maxEntries = 100000U;
  settings.d_shardCount = 10U;

  DNSDistPacketCache cache(settings);
  InternalQueryState ids{};
  const DNSName qname{"dnsdist.org."};
  ids.qname = qname;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;

  auto query = getQuery(ids);
  auto response = getResponse(ids);
  auto dnsQuestion = DNSQuestion(ids, query);

  std::optional<Netmask> subnet{};
  uint32_t cacheKey = 0;
  cache.get(dnsQuestion, 42U, &cacheKey, subnet, true, true);
  cache.insert(cacheKey, std::nullopt, 0U, true, qname, ids.qtype, ids.qclass, response, true, RCode::NoError, std::nullopt);

  const size_t iterations = 100000U;
  auto testCode = [&](size_t iterationsPerThread) {
    for (size_t idx = 0U; idx < iterationsPerThread; idx++) {
      cache.get(dnsQuestion, 42U, &cacheKey, subnet, true, true);
    }
  };

  for (size_t threadsCount : std::vector<size_t>{1, 10, 20}) {
    std::vector<std::thread> threads;
    threads.reserve(threadsCount);

    BENCHMARK(std::to_string(threadsCount))
    {
      for (size_t idx = 0U; idx < threadsCount; idx++) {
        threads.emplace_back(std::thread(testCode, iterations / threadsCount));
      }
      for (auto& thread : threads) {
        thread.join();
      }
      return threads.size();
    };
  }
}

TEST_CASE("Cache/Insertion")
{
  DNSDistPacketCache::CacheSettings settings;
  settings.d_maxEntries = 100000U;
  settings.d_shardCount = 10U;

  DNSDistPacketCache cache(settings);
  InternalQueryState ids{};
  const DNSName qname{"dnsdist.org."};
  ids.qname = qname;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;

  auto query = getQuery(ids);
  auto response = getResponse(ids);
  auto dnsQuestion = DNSQuestion(ids, query);

  std::optional<Netmask> subnet{};
  uint32_t cacheKey = 0;
  cache.get(dnsQuestion, 42U, &cacheKey, subnet, true, true);

  const size_t iterations = 100000U;
  auto testCode = [&](size_t iterationsPerThread) {
    for (size_t idx = 0U; idx < iterationsPerThread; idx++) {
      cache.insert(cacheKey, std::nullopt, 0U, true, qname, ids.qtype, ids.qclass, response, true, RCode::NoError, std::nullopt);
    }
  };

  for (size_t threadsCount : std::vector<size_t>{1, 10, 20}) {
    std::vector<std::thread> threads;
    threads.reserve(threadsCount);

    BENCHMARK(std::to_string(threadsCount))
    {
      for (size_t idx = 0U; idx < threadsCount; idx++) {
        threads.emplace_back(std::thread(testCode, iterations / threadsCount));
      }
      for (auto& thread : threads) {
        thread.join();
      }
      return threads.size();
    };
  }
}

TEST_CASE("Cache/Cleanup")
{
  DNSDistPacketCache::CacheSettings settings;
  settings.d_maxEntries = 100000U;
  settings.d_shardCount = 10U;

  DNSDistPacketCache cache(settings);

  /* insert entries */
  for (size_t idx = 0; idx < settings.d_maxEntries; idx++) {
    InternalQueryState ids{};
    const DNSName qname{"dnsdist" + std::to_string(idx) + ".org."};
    ids.qname = qname;
    ids.qtype = QType::A;
    ids.qclass = QClass::IN;

    auto query = getQuery(ids);
    auto response = getResponse(ids);
    auto dnsQuestion = DNSQuestion(ids, query);

    std::optional<Netmask> subnet{};
    uint32_t cacheKey = 0;
    cache.get(dnsQuestion, 42U, &cacheKey, subnet, true, true);
    cache.insert(cacheKey, std::nullopt, 0U, true, qname, ids.qtype, ids.qclass, response, true, RCode::NoError, std::nullopt);
  }
  auto before = cache.getSize();

  const auto now = time(nullptr);
  BENCHMARK("cleanup")
  {
    return cache.purgeExpired(0U, now);
  };

  CHECK(cache.getSize() == before);
}
