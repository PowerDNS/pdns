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
#include <memory>
#include <deque>
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

static PacketBuffer getResponse(const InternalQueryState& ids, uint32_t ttl)
{
  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, ids.qtype, ids.qclass, 0);
  pwR.getHeader()->rd = 1;
  pwR.getHeader()->ra = 1;
  pwR.getHeader()->qr = 1;
  pwR.getHeader()->id = 42U;
  pwR.startRecord(ids.qname, ids.qtype, ttl, ids.qclass, DNSResourceRecord::ANSWER);
  pwR.xfr32BitInt(0x01020304);
  pwR.commit();
  return response;
}

TEST_CASE("Cache/Lookup")
{
  DNSDistPacketCache::CacheSettings settings;
  settings.d_maxEntries = 100000U;
  settings.d_shardCount = 10U;

  const DNSDistPacketCache::Time now;
  DNSDistPacketCache cache(settings, now);
  InternalQueryState ids{};
  const DNSName qname{"dnsdist.org."};
  ids.qname = qname;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;

  auto query = getQuery(ids);
  auto response = getResponse(ids, 7200);
  auto dnsQuestion = DNSQuestion(ids, query);

  std::optional<Netmask> subnet{};
  uint32_t cacheKey = 0;

  cache.get(dnsQuestion, 42U, &cacheKey, subnet, true, true, now);
  cache.insert(cacheKey, std::nullopt, 0U, true, qname, ids.qtype, ids.qclass, response, true, RCode::NoError, std::nullopt, now);

  const size_t iterations = 100000U;
  auto testCode = [&](size_t iterationsPerThread) {
    for (size_t idx = 0U; idx < iterationsPerThread; idx++) {
      cache.get(dnsQuestion, 42U, &cacheKey, subnet, true, true, now);
    }
  };

  for (size_t threadsCount : std::vector<size_t>{1, 10, 20}) {
    std::vector<std::thread> threads;
    threads.reserve(threadsCount);

    BENCHMARK(std::to_string(threadsCount))
    {
      threads.clear();
      for (size_t idx = 0U; idx < threadsCount; idx++) {
        threads.emplace_back(testCode, iterations / threadsCount);
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
  // this bench doesn't *really* insert; the insertion fails
  DNSDistPacketCache::CacheSettings settings;
  settings.d_maxEntries = 100000U;
  settings.d_shardCount = 10U;

  const DNSDistPacketCache::Time now;

  DNSDistPacketCache cache(settings, now);
  InternalQueryState ids{};
  const DNSName qname{"dnsdist.org."};
  ids.qname = qname;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;

  auto query = getQuery(ids);
  auto response = getResponse(ids, 7200);
  auto dnsQuestion = DNSQuestion(ids, query);

  std::optional<Netmask> subnet{};
  uint32_t cacheKey = 0;
  cache.get(dnsQuestion, 42U, &cacheKey, subnet, true, true, now);

  const size_t iterations = 100000U;
  auto testCode = [&](size_t iterationsPerThread) {
    for (size_t idx = 0U; idx < iterationsPerThread; idx++) {
      cache.insert(cacheKey, std::nullopt, 0U, true, qname, ids.qtype, ids.qclass, response, true, RCode::NoError, std::nullopt, now);
    }
  };

  for (size_t threadsCount : std::vector<size_t>{1, 10, 20}) {
    std::vector<std::thread> threads;
    threads.reserve(threadsCount);

    BENCHMARK(std::to_string(threadsCount))
    {
      threads.clear();
      for (size_t idx = 0U; idx < threadsCount; idx++) {
        threads.emplace_back(testCode, iterations / threadsCount);
      }
      for (auto& thread : threads) {
        thread.join();
      }
      return threads.size();
    };
  }
}

TEST_CASE("Cache/DisctinctGetAndInsert")
{
  // this bench actually inserts several times
  const size_t entries = 100000U;

  struct Packet
  {
    DNSName d_qname;
    PacketBuffer d_query;
    PacketBuffer d_response;
    InternalQueryState d_iqs;
  };
  std::vector<Packet> packets;
  packets.reserve(entries);

  DNSDistPacketCache::CacheSettings settings;
  settings.d_maxEntries = 2 * entries;
  settings.d_shardCount = 10U;
  settings.d_deferrableInsertLock = false; // to actually test contention
  const DNSDistPacketCache::Time now;

  {
    for (size_t idx = 0; idx < entries; idx++) {
      InternalQueryState ids{};
      ids.qname = DNSName("dnsdist" + std::to_string(idx) + ".org.");
      ids.qtype = QType::A;
      ids.qclass = QClass::IN;

      auto q = getQuery(ids);
      auto r = getResponse(ids, 7200);

      packets.push_back(Packet{ids.qname, std::move(q), std::move(r), std::move(ids)});
    }
  }

  for (size_t threadsCount : std::vector<size_t>{1, 10, 20}) {
    BENCHMARK_ADVANCED(std::to_string(threadsCount))(Catch::Benchmark::Chronometer meter)
    {
      std::deque<DNSDistPacketCache> caches;
      for (int i = 0; i < meter.runs(); i++) {
        caches.emplace_back(settings);
      }

      const size_t perThread = entries / threadsCount;

      auto testCode = [&now, &caches, &packets, perThread](int run, size_t thr) {
        DNSDistPacketCache& cache = caches[run];
        size_t start = thr * perThread;
        size_t end = (thr + 1) * perThread;
        for (size_t i = start; i < end; i++) {
          auto& packet = packets[i];

          uint32_t cacheKey = 0;
          std::optional<Netmask> subnet{};
          DNSQuestion dnsq(packet.d_iqs, packet.d_query);
          cache.get(dnsq, 42U, &cacheKey, subnet, true, true, now);
          cache.insert(cacheKey, std::nullopt, 0U, true, packet.d_qname, QType::A, QClass::IN, packet.d_response, true, RCode::NoError, std::nullopt, now);
        }
      };

      meter.measure([&](int run) {
        DNSDistPacketCache& cache = caches[run];
        std::vector<std::thread> threads;
        threads.reserve(threadsCount);
        for (size_t thr = 0; thr < threadsCount; thr++) {
          threads.emplace_back(testCode, run, thr);
        }
        for (auto& thread : threads) {
          thread.join();
        }
        return cache.getSize();
      });
    };
  }
}

TEST_CASE("Cache/Cleanup")
{
  DNSDistPacketCache::CacheSettings settings;
  settings.d_maxEntries = 100000U;
  settings.d_shardCount = 10U;

  const DNSDistPacketCache::Time now;

  DNSDistPacketCache cache(settings, now);

  /* insert entries */
  for (size_t idx = 0; idx < settings.d_maxEntries; idx++) {
    InternalQueryState ids{};
    const DNSName qname{"dnsdist" + std::to_string(idx) + ".org."};
    ids.qname = qname;
    ids.qtype = QType::A;
    ids.qclass = QClass::IN;

    auto query = getQuery(ids);
    auto response = getResponse(ids, 7200);
    auto dnsQuestion = DNSQuestion(ids, query);

    std::optional<Netmask> subnet{};
    uint32_t cacheKey = 0;
    cache.get(dnsQuestion, 42U, &cacheKey, subnet, true, true, now);
    cache.insert(cacheKey, std::nullopt, 0U, true, qname, ids.qtype, ids.qclass, response, true, RCode::NoError, std::nullopt, now);
  }
  auto before = cache.getSize();

  const DNSDistPacketCache::Time now2;

  BENCHMARK("cleanup")
  {
    return cache.purgeExpired(0U, now2);
  };

  CHECK(cache.getSize() == before);
}

TEST_CASE("Cache/CleanupRealistic")
{
  DNSDistPacketCache::CacheSettings settings;
  auto entries = 100000U;
  settings.d_maxEntries = 2 * entries;
  settings.d_shardCount = 10U;

  DNSDistPacketCache::Time now;

  BENCHMARK_ADVANCED("cleanup")(Catch::Benchmark::Chronometer meter)
  {
    std::deque<DNSDistPacketCache> caches;
    for (int i = 0; i < meter.runs(); i++) {
      caches.emplace_back(settings, now);
      // insert entries with random TTLs
      for (size_t idx = 0; idx < entries; idx++) {
        InternalQueryState ids{};
        const DNSName qname{"dnsdist" + std::to_string(idx) + ".org."};
        ids.qname = qname;
        ids.qtype = QType::A;
        ids.qclass = QClass::IN;

        auto query = getQuery(ids);
        auto response = getResponse(ids, 1 + (idx * 2654435761U % 7200));
        auto dnsQuestion = DNSQuestion(ids, query);

        std::optional<Netmask> subnet{};
        uint32_t cacheKey = 0;
        caches[i].get(dnsQuestion, 42U, &cacheKey, subnet, true, true, now);
        caches[i].insert(cacheKey, std::nullopt, 0U, true, qname, ids.qtype, ids.qclass, response, true, RCode::NoError, std::nullopt, now);
      }
    }
    meter.measure([&caches, &now](int run) {
      size_t expired = 0;

      DNSDistPacketCache::Time now2 = now; // copy time which we will move
      DNSDistPacketCache& cache = caches[run];
      auto const before = cache.getSize();

      // 60 is the default delay
      for (time_t s = 0; s < 7200; s += 60) {
        now2.d_real += 60;
        now2.d_monotonic += 60;
        auto add = cache.purgeExpired(0U, now2);
        expired += add;
      }

      CHECK(cache.getSize() + expired == before);
    });
  };
}
