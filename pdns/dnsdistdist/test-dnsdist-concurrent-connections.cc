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

BOOST_AUTO_TEST_CASE(test_Below_Rate)
{
  const uint64_t maxTCPConnectionsRatePerClient = 10U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 1U;
  dnsdist::configuration::updateImmutableConfiguration([&](dnsdist::configuration::ImmutableConfiguration& config) {
    config.d_maxTCPConnectionsPerClient = maxTCPConnectionsPerClient;
    config.d_maxTCPConnectionsRatePerClient = maxTCPConnectionsRatePerClient;
    config.d_tcpConnectionsRatePerClientInterval = tcpConnectionsRatePerClientInterval;
  });

  dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  time_t now = time(nullptr);

  /* simulate a client sending up to maxTCPConnectionsRatePerClient every second, for 120 seconds (so 2 buckets) */
  for (size_t elapsed = 0; elapsed < 120U; elapsed++) {
    const ComboAddress client{"192.0.2.1"};
    for (size_t idx = 0; idx < maxTCPConnectionsRatePerClient; idx++) {
      auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
      BOOST_CHECK(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
      dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
    }
    BOOST_CHECK(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

    /* one second later */
    now++;
  }
}
BOOST_AUTO_TEST_CASE(test_Above_Max_Concurrent_Connections)
{
  const uint64_t maxTCPConnectionsRatePerClient = 10U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 1U;
  dnsdist::configuration::updateImmutableConfiguration([&](dnsdist::configuration::ImmutableConfiguration& config) {
    config.d_maxTCPConnectionsPerClient = maxTCPConnectionsPerClient;
    config.d_maxTCPConnectionsRatePerClient = maxTCPConnectionsRatePerClient;
    config.d_tcpConnectionsRatePerClientInterval = tcpConnectionsRatePerClientInterval;
  });

  dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  const time_t now = time(nullptr);

  const ComboAddress client{"192.0.2.1"};
  for (size_t idx = 0; idx < maxTCPConnectionsPerClient; idx++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_CHECK(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
  }
  BOOST_CHECK(dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

  /* now go over the top */
  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false);
  BOOST_CHECK(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Denied);
  BOOST_CHECK(dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));
}

BOOST_AUTO_TEST_CASE(test_Above_Max_Connection_Rate)
{
  const uint64_t maxTCPConnectionsRatePerClient = 10U;
  const uint64_t tcpConnectionsRatePerClientInterval = 5U;
  const uint64_t maxTCPConnectionsPerClient = 1U;
  dnsdist::configuration::updateImmutableConfiguration([&](dnsdist::configuration::ImmutableConfiguration& config) {
    config.d_maxTCPConnectionsPerClient = maxTCPConnectionsPerClient;
    config.d_maxTCPConnectionsRatePerClient = maxTCPConnectionsRatePerClient;
    config.d_tcpConnectionsRatePerClientInterval = tcpConnectionsRatePerClientInterval;
  });

  dnsdist::IncomingConcurrentTCPConnectionsManager::clear();
  const time_t now = time(nullptr);

  const ComboAddress client{"192.0.2.1"};
  for (size_t idx = 0; idx < maxTCPConnectionsRatePerClient; idx++) {
    auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
    BOOST_CHECK(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Allowed);
    dnsdist::IncomingConcurrentTCPConnectionsManager::accountClosedTCPConnection(client);
  }
  BOOST_CHECK(!dnsdist::IncomingConcurrentTCPConnectionsManager::isClientOverThreshold(client));

  /* now go over the top */
  auto result = dnsdist::IncomingConcurrentTCPConnectionsManager::accountNewTCPConnection(client, false, false, now);
  BOOST_CHECK(result == dnsdist::IncomingConcurrentTCPConnectionsManager::NewConnectionResult::Denied);
}

BOOST_AUTO_TEST_SUITE_END();
