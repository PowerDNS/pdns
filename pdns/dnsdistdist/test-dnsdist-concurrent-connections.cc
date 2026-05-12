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
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist-concurrent-connections.hh"
#include "dnsdist-configuration.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdist_concurrent_connections)

static void initConfiguration(uint64_t maxTCPConnectionsRatePerClient, uint64_t tcpConnectionsRatePerClientInterval, uint64_t maxTCPConnectionsPerClient, uint32_t banDuration, uint64_t maxTLSNewSessionsRatePerClient = 0U, uint64_t maxTLSResumedSessionsRatePerClient = 0U, uint32_t maxTCPReadIOsPerQuery = 50U)
{
  dnsdist::configuration::updateImmutableConfiguration([&](dnsdist::configuration::ImmutableConfiguration& config) {
    config.d_maxTCPConnectionsPerClient = maxTCPConnectionsPerClient;
    config.d_maxTCPConnectionsRatePerClient = maxTCPConnectionsRatePerClient;
    config.d_tcpConnectionsRatePerClientInterval = tcpConnectionsRatePerClientInterval;
    config.d_tcpBanDurationForExceedingTCPTLSRate = banDuration;
    config.d_maxTLSNewSessionsRatePerClient = maxTLSNewSessionsRatePerClient;
    config.d_maxTLSResumedSessionsRatePerClient = maxTLSResumedSessionsRatePerClient;
    config.d_maxTCPReadIOsPerQuery = maxTCPReadIOsPerQuery;
  });
}

struct TestFixture
{
  TestFixture()
  {
    dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  }
  ~TestFixture()
  {
    dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  }
};

BOOST_FIXTURE_TEST_CASE(test_No_Rate_Limiting, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 0U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 0U;
  const uint32_t banDuration = 10U;
  /* disable this to completely disable tracking */
  const uint32_t maxTCPReadIOsPerQuery = 0U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration, 0U, 0U, maxTCPReadIOsPerQuery);
  const ComboAddress client{"192.0.2.1"};
  time_t now = time(nullptr);

  BOOST_REQUIRE_EQUAL(dnsdist::IncomingConcurrentTCPConnectionsManager::getNumberOfEntries(), 0U);

  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
  dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
  BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

  BOOST_REQUIRE_EQUAL(dnsdist::IncomingConcurrentTCPConnectionsManager::getNumberOfEntries(), 0U);
}

BOOST_FIXTURE_TEST_CASE(test_Below_Rate, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 10U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 1U;
  const uint32_t banDuration = 10U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration);
  time_t now = time(nullptr);

  /* simulate a client sending up to maxTCPConnectionsRatePerClient every second, for 120 seconds (so 2 buckets) */
  for (size_t elapsed = 0; elapsed < 120U; elapsed++) {
    const ComboAddress client{"192.0.2.1"};
    for (size_t idx = 0; idx < maxTCPConnectionsRatePerClient; idx++) {
      auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
      BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
      dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    }
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

    /* one second later */
    now++;
  }

  BOOST_REQUIRE_EQUAL(dnsdist::IncomingConcurrentTCPConnectionsManager::getNumberOfEntries(), 1U);

  /* should not remove anything */
  dnsdist::IncomingConcurrentTCPConnectionsManager::cleanup(now);
  BOOST_REQUIRE_EQUAL(dnsdist::IncomingConcurrentTCPConnectionsManager::getNumberOfEntries(), 1U);

  /* more than the 60s between two cleanups, but entries should still be valid */
  now += 120U;
  dnsdist::IncomingConcurrentTCPConnectionsManager::cleanup(now);
  BOOST_REQUIRE_EQUAL(dnsdist::IncomingConcurrentTCPConnectionsManager::getNumberOfEntries(), 1U);

  /* now we should be after interval * 60s, entries should no longer be valid */
  now += 180U;
  dnsdist::IncomingConcurrentTCPConnectionsManager::cleanup(now);
  BOOST_REQUIRE_EQUAL(dnsdist::IncomingConcurrentTCPConnectionsManager::getNumberOfEntries(), 0U);

}

BOOST_FIXTURE_TEST_CASE(test_Below_Rate_Skipping_Bucket, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 10U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 1U;
  const uint32_t banDuration = 10U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration);

  dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  time_t now = time(nullptr);

  /* simulate a client sending up to maxTCPConnectionsRatePerClient for 60 seconds */
  for (size_t elapsed = 0; elapsed < 60U; elapsed++) {
    const ComboAddress client{"192.0.2.1"};
    for (size_t idx = 0; idx < maxTCPConnectionsRatePerClient; idx++) {
      auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
      BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
      dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    }
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

    /* one second later */
    now++;
  }

  /* nothing for one minute */
  now += 60U;

  /* than twice maxTCPConnectionsRatePerClient for 60 seconds, should be OK since it is averaged over 3 minutes */
  for (size_t elapsed = 0; elapsed < 60U; elapsed++) {
    const ComboAddress client{"192.0.2.1"};
    for (size_t idx = 0; idx < (maxTCPConnectionsRatePerClient * 2U); idx++) {
      auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
      BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
      dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    }
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

    /* one second later */
    now++;
  }
}

BOOST_FIXTURE_TEST_CASE(test_Above_Rate_After_Being_Below, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 10U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 1U;
  const uint32_t banDuration = 10U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration);

  dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  time_t now = time(nullptr);
  const ComboAddress client{"192.0.2.1"};

  /* simulate a client creating only one connection per minute for tcpConnectionsRatePerClientInterval minutes */
  for (size_t elapsed = 0; elapsed < tcpConnectionsRatePerClientInterval; elapsed++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

    /* one MINUTE later */
    now += 60U;
  }

  /* now 4 * maxTCPConnectionsRatePerClient connections per second for 60 seconds */
  for (size_t elapsed = 0; elapsed < 60U; elapsed++) {
    for (size_t idx = 0; idx < (4U * maxTCPConnectionsRatePerClient); idx++) {
      auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
      BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
      dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    }
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

    /* one second later */
    now++;
  }

  /* go back to the last second of the last bucket */
  now--;

  /* 596 new connections should bring us over the top, since the first bucket of one connection per minute
     is no longer valid, so we have 4 buckets at 1 connection per minute + 1 bucket at 4 * maxTCPConnectionsRatePerClient connections per second
     so 4 + (4 * maxTCPConnectionsRatePerClient * 60) = 2404, and the budget is maxTCPConnectionsRatePerClient * 60 * interval = 3000
  */
  for (size_t count = 0; count < (maxTCPConnectionsRatePerClient * 60U * tcpConnectionsRatePerClientInterval) - (tcpConnectionsRatePerClientInterval - 1U + (4U * maxTCPConnectionsRatePerClient * 60U)); count++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
  }
  /* the last one */
  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Denied);

  /* check that the ban properly expires (takes a while to go below the rate, though, because we opened a lot of connections during the last minute ) */
  result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now + std::max(tcpConnectionsRatePerClientInterval * 60U, static_cast<uint64_t>(banDuration)) + 1U);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
}

BOOST_FIXTURE_TEST_CASE(test_Above_Max_Concurrent_Connections, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 10U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 1U;
  const uint32_t banDuration = 10U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration);

  dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  const time_t now = time(nullptr);

  const ComboAddress client{"192.0.2.1"};
  for (size_t idx = 0; idx < maxTCPConnectionsPerClient; idx++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
  }
  BOOST_REQUIRE(dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

  /* now go over the top */
  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Denied);
  BOOST_REQUIRE(dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

  /* now check that we are correctly allowed once at least one existing connections has been closed */
  dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
  result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
  dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
  BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
}

BOOST_FIXTURE_TEST_CASE(test_Max_Concurrent_Connections_Overload_Threshold, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 0U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 100U;
  const uint32_t banDuration = 10U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration);
  const auto overloadThreshold = dnsdist::configuration::getImmutableConfiguration().d_tcpConnectionsOverloadThreshold;
  BOOST_REQUIRE_GT(overloadThreshold, 0U);

  dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  const time_t now = time(nullptr);

  const ComboAddress client{"192.0.2.1"};
  for (size_t idx = 0; idx < maxTCPConnectionsPerClient * overloadThreshold / 100.0; idx++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
  }

  /* now go over the top */
  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Restricted);
  BOOST_REQUIRE(dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
  dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);

  /* now check that we are correctly allowed once at least one existing connections has been closed */
  dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
  result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
  dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
  BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
}

BOOST_FIXTURE_TEST_CASE(test_Above_Max_Connection_Rate, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 10U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 1U;
  const uint32_t banDuration = 10U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration);

  dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  const time_t now = time(nullptr);

  const ComboAddress client{"192.0.2.1"};
  for (size_t idx = 0; idx < maxTCPConnectionsRatePerClient; idx++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
  }
  BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

  /* now go over the top */
  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Denied);

  /* check that the ban properly expires (takes a while to go below the rate) */
  result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now + std::max(60U, banDuration) + 1U);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
}

BOOST_FIXTURE_TEST_CASE(test_TLS_New_Without_TCP_Rate_Limiting, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 0U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 0U;
  const uint64_t maxTLSNewSessionsRatePerClient = 1U;
  const uint32_t banDuration = 10U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration, maxTLSNewSessionsRatePerClient);
  const ComboAddress client{"192.0.2.1"};
  time_t now = time(nullptr);

  /* TCP (not TLS) connections should not be rate-limited */
  for (size_t counter = 0U; counter < 20U; counter++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
  }

  /* TLS ones should be rate-limited, but resumed sessions are OK */
  for (size_t counter = 0U; counter < 20U; counter++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, true, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountTLSResumedSession(client);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
  }

  /* TLS ones should be rate-limited, only two NEW sessions allowed (because we need to establish the connection to see if it is resumed or not, we are off by one) */
  for (size_t counter = 0U; counter < 2U; counter++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, true, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountTLSNewSession(client);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
  }
  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, true, false, now);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Denied);
}

BOOST_FIXTURE_TEST_CASE(test_TLS_Resumed_Without_TCP_Rate_Limiting, TestFixture)
{
  const uint64_t maxTCPConnectionsRatePerClient = 0U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 0U;
  const uint64_t maxTLSNewSessionsRatePerClient = 0U;
  const uint64_t maxTLSResumedSessionsRatePerClient = 1U;
  const uint32_t banDuration = 10U;
  initConfiguration(maxTCPConnectionsRatePerClient, tcpConnectionsRatePerClientInterval, maxTCPConnectionsPerClient, banDuration, maxTLSNewSessionsRatePerClient, maxTLSResumedSessionsRatePerClient);
  const ComboAddress client{"192.0.2.1"};
  time_t now = time(nullptr);

  /* TCP (not TLS) connections should not be rate-limited */
  for (size_t counter = 0U; counter < 20U; counter++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
  }

  /* TLS ones should be rate-limited, but NEW sessions are OK (don't ask) */
  for (size_t counter = 0U; counter < 20U; counter++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, true, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountTLSNewSession(client);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
  }

  /* only two resumed sessions allowed (because we need to establish the connection to see if it is resumed or not, we are off by one) */
  for (size_t counter = 0U; counter < 2U; counter++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, true, false, now);
    BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountTLSResumedSession(client);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    BOOST_REQUIRE(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
  }
  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, true, false, now);
  BOOST_REQUIRE(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Denied);
}

BOOST_AUTO_TEST_SUITE_END();
