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

#include "dnsdist-server-pool.hh"
#include "dnsdist.hh"

BOOST_AUTO_TEST_SUITE(dnsdistserverpool)

BOOST_AUTO_TEST_CASE(test_ServerPoolBasics)
{
  ServerPool pool{};
  BOOST_CHECK(!pool.getCache());

  BOOST_CHECK(!pool.getECS());
  /* will be ignored because there is no server with ECS
     in the pool at this point */
  pool.setECS(true);
  BOOST_CHECK(!pool.getECS());
  pool.setECS(false);
  BOOST_CHECK(!pool.getECS());

  BOOST_CHECK(pool.getZeroScope());
  /* will be ignored because there is no server with the
     zero scope feature disabled in the pool at this point */
  pool.setZeroScope(false);
  BOOST_CHECK(pool.getZeroScope());
  pool.setZeroScope(true);
  BOOST_CHECK(pool.getZeroScope());

  BOOST_CHECK(!pool.isTCPOnly());
  BOOST_CHECK(pool.isConsistent());
  BOOST_CHECK(!pool.hasAtLeastOneServerAvailable());
  BOOST_CHECK_EQUAL(pool.countServers(true), 0U);
  BOOST_CHECK_EQUAL(pool.countServers(false), 0U);
  BOOST_CHECK_EQUAL(pool.poolLoad(), 0U);
  BOOST_CHECK(!pool.shouldKeepStaleData());

  {
    const auto& servers = pool.getServers();
    BOOST_CHECK(servers.empty());
  }

  {
    /* add one server */
    DownstreamState::Config config;
    auto ds = std::make_shared<DownstreamState>(std::move(config), nullptr, false);
    pool.addServer(ds);
    BOOST_CHECK(!pool.isTCPOnly());
    BOOST_CHECK(pool.isConsistent());
    /* the server is unavailable by default */
    BOOST_CHECK(!pool.hasAtLeastOneServerAvailable());
    BOOST_CHECK_EQUAL(pool.countServers(true), 0U);
    BOOST_CHECK_EQUAL(pool.countServers(false), 1U);
    BOOST_CHECK(pool.shouldKeepStaleData());

    BOOST_CHECK_EQUAL(pool.poolLoad(), 0U);
    {
      const auto& servers = pool.getServers();
      BOOST_CHECK(!servers.empty());
    }

    /* let's make it available */
    ds->setUp();
    BOOST_CHECK(pool.hasAtLeastOneServerAvailable());
    BOOST_CHECK_EQUAL(pool.countServers(true), 1U);
    BOOST_CHECK_EQUAL(pool.countServers(false), 1U);
    BOOST_CHECK(!pool.shouldKeepStaleData());

    /* now remove it */
    pool.removeServer(ds);
    BOOST_CHECK_EQUAL(pool.countServers(true), 0U);
    BOOST_CHECK_EQUAL(pool.countServers(false), 0U);
    BOOST_CHECK(!pool.shouldKeepStaleData());
    {
      const auto& servers = pool.getServers();
      BOOST_CHECK(servers.empty());
    }
  }
}

BOOST_AUTO_TEST_CASE(test_ServerPoolECSConsistency)
{
  ServerPool pool{};

  /* one server with ECS */
  DownstreamState::Config config1;
  config1.useECS = true;
  auto ds1 = std::make_shared<DownstreamState>(std::move(config1), nullptr, false);
  pool.addServer(ds1);
  BOOST_CHECK_EQUAL(pool.countServers(false), 1U);
  BOOST_CHECK(!pool.isTCPOnly());
  BOOST_CHECK(pool.isConsistent());
  BOOST_CHECK(pool.getECS());
  /* should be ignored */
  pool.setECS(false);
  BOOST_CHECK(pool.getECS());

  /* and now one without ECS */
  DownstreamState::Config config2;
  config2.useECS = false;
  auto ds2 = std::make_shared<DownstreamState>(std::move(config2), nullptr, false);
  pool.addServer(ds2);
  BOOST_CHECK_EQUAL(pool.countServers(false), 2U);
  BOOST_CHECK(!pool.isTCPOnly());
  BOOST_CHECK(!pool.isConsistent());
  /* the first backend has ECS so the pool automatically picked up
     ECS-enabled, and after that the inconsistency meant the state
     was not longer automatically updated */
  BOOST_CHECK(pool.getECS());
  /* should NOT be ignored */
  pool.setECS(false);
  BOOST_CHECK(!pool.getECS());
  /* should NOT be ignored */
  pool.setECS(true);
  BOOST_CHECK(pool.getECS());

  /* remove the server with ECS */
  pool.removeServer(ds1);
  BOOST_CHECK_EQUAL(pool.countServers(false), 1U);
  BOOST_CHECK(!pool.isTCPOnly());
  BOOST_CHECK(pool.isConsistent());
  BOOST_CHECK(!pool.getECS());

  /* re-add the server with ECS */
  pool.addServer(ds1);
  BOOST_CHECK_EQUAL(pool.countServers(false), 2U);
  BOOST_CHECK(!pool.isTCPOnly());
  BOOST_CHECK(!pool.isConsistent());
  /* the pool was in a consistent state without ECS,
     and now is in an inconsistent state so it not automatically
     updated */
  BOOST_CHECK(!pool.getECS());
}

BOOST_AUTO_TEST_CASE(test_ServerPoolTCPOnlyConsistency)
{
  ServerPool pool{};

  DownstreamState::Config config1;
  config1.d_tcpOnly = true;
  auto ds1 = std::make_shared<DownstreamState>(std::move(config1), nullptr, false);
  pool.addServer(ds1);
  BOOST_CHECK_EQUAL(pool.countServers(false), 1U);
  BOOST_CHECK(pool.isTCPOnly());
  BOOST_CHECK(pool.isConsistent());
  BOOST_CHECK(!pool.getECS());

  DownstreamState::Config config2;
  config2.d_tcpOnly = false;
  auto ds2 = std::make_shared<DownstreamState>(std::move(config2), nullptr, false);
  pool.addServer(ds2);
  BOOST_CHECK_EQUAL(pool.countServers(false), 2U);
  BOOST_CHECK(!pool.isTCPOnly());
  BOOST_CHECK(!pool.isConsistent());

  /* remove the TCP-only server */
  pool.removeServer(ds1);
  BOOST_CHECK_EQUAL(pool.countServers(false), 1U);
  BOOST_CHECK(!pool.isTCPOnly());
  BOOST_CHECK(pool.isConsistent());

  /* re-add the server with TCP-only */
  pool.addServer(ds1);
  BOOST_CHECK_EQUAL(pool.countServers(false), 2U);
  BOOST_CHECK(!pool.isTCPOnly());
  BOOST_CHECK(!pool.isConsistent());
}

BOOST_AUTO_TEST_SUITE_END()
