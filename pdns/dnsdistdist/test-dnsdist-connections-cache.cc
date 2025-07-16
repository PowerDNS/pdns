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

#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-downstream-connection.hh"

class MockupConnection
{
public:
  MockupConnection(const std::shared_ptr<DownstreamState>& ds, std::unique_ptr<FDMultiplexer>&, const struct timeval&, std::string&&) :
    d_ds(ds)
  {
  }

  bool canBeReused() const
  {
    return d_reusable;
  }

  bool isUsable() const
  {
    return d_usable;
  }

  bool willBeReusable(bool) const
  {
    return d_reusable;
  }

  void setReused()
  {
  }

  struct timeval getLastDataReceivedTime() const
  {
    return d_lastDataReceivedTime;
  }

  bool isIdle() const
  {
    return d_idle;
  }

  void stopIO()
  {
  }

  static void release(bool removeFromCache)
  {
    (void)removeFromCache;
  }

  std::shared_ptr<DownstreamState> getDS() const
  {
    return d_ds;
  }

  std::shared_ptr<DownstreamState> d_ds;
  struct timeval d_lastDataReceivedTime{
    0, 0};
  bool d_reusable{true};
  bool d_usable{true};
  bool d_idle{false};
};

BOOST_AUTO_TEST_SUITE(test_dnsdist_connections_cache)

BOOST_AUTO_TEST_CASE(test_ConnectionsCache)
{
  DownstreamConnectionsManager<MockupConnection> manager;
  const size_t maxIdleConnPerDownstream = 5;
  const uint16_t cleanupInterval = 1;
  const uint16_t maxIdleTime = 5;
  manager.setMaxIdleConnectionsPerDownstream(maxIdleConnPerDownstream);
  manager.setCleanupInterval(cleanupInterval);
  manager.setMaxIdleTime(maxIdleTime);

  auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());
  auto downstream1 = std::make_shared<DownstreamState>(ComboAddress("192.0.2.1"));
  auto downstream2 = std::make_shared<DownstreamState>(ComboAddress("192.0.2.2"));
  struct timeval now;
  gettimeofday(&now, nullptr);

  auto conn = manager.getConnectionToDownstream(mplexer, downstream1, now, std::string());
  BOOST_REQUIRE(conn != nullptr);
  BOOST_CHECK_EQUAL(manager.count(), 1U);
  BOOST_CHECK_EQUAL(manager.getActiveCount(), 1U);
  BOOST_CHECK_EQUAL(manager.getIdleCount(), 0U);

  /* since the connection can be reused, we should get the same one */
  {
    auto conn1 = manager.getConnectionToDownstream(mplexer, downstream1, now, std::string());
    BOOST_CHECK(conn.get() == conn1.get());
    BOOST_CHECK_EQUAL(manager.count(), 1U);
    BOOST_CHECK_EQUAL(manager.getActiveCount(), 1U);
  }

  /* if we mark it non-usable, we should get a new one */
  conn->d_usable = false;
  auto conn2 = manager.getConnectionToDownstream(mplexer, downstream1, now, std::string());
  BOOST_CHECK(conn.get() != conn2.get());
  BOOST_CHECK_EQUAL(manager.count(), 2U);
  BOOST_CHECK_EQUAL(manager.getActiveCount(), 2U);

  /* since the second connection can be reused, we should get it */
  {
    auto conn3 = manager.getConnectionToDownstream(mplexer, downstream1, now, std::string());
    BOOST_CHECK(conn3.get() == conn2.get());
    BOOST_CHECK_EQUAL(manager.count(), 2U);
    BOOST_CHECK_EQUAL(manager.getActiveCount(), 2U);
  }

  /* different downstream so different connection */
  auto differentConn = manager.getConnectionToDownstream(mplexer, downstream2, now, std::string());
  BOOST_REQUIRE(differentConn != nullptr);
  BOOST_CHECK(differentConn.get() != conn.get());
  BOOST_CHECK(differentConn.get() != conn2.get());
  BOOST_CHECK_EQUAL(manager.count(), 3U);
  BOOST_CHECK_EQUAL(manager.getActiveCount(), 3U);
  {
    /* but we should be able to reuse it */
    auto sameConn = manager.getConnectionToDownstream(mplexer, downstream2, now, std::string());
    BOOST_CHECK(sameConn.get() == differentConn.get());
    BOOST_CHECK_EQUAL(manager.count(), 3U);
    BOOST_CHECK_EQUAL(manager.getActiveCount(), 3U);
  }

  struct timeval later = now;
  later.tv_sec += cleanupInterval + 1;

  /* mark the second connection as no longer usable */
  conn2->d_usable = false;
  /* first one as well but still fresh so it will not get checked */
  conn->d_usable = true;
  conn->d_lastDataReceivedTime = later;
  /* third one is usable but idle for too long */
  differentConn->d_idle = true;
  differentConn->d_lastDataReceivedTime = later;
  differentConn->d_lastDataReceivedTime.tv_sec -= (maxIdleTime + 1);

  /* we should not do an actual cleanup attempt since the last cleanup was done recently */
  manager.cleanupClosedConnections(now);
  BOOST_CHECK_EQUAL(manager.count(), 3U);

  manager.cleanupClosedConnections(later);
  BOOST_CHECK_EQUAL(manager.count(), 1U);

  /* mark the remaining conn as non-usable, to get new ones */
  conn->d_usable = false;
  conn->d_lastDataReceivedTime.tv_sec = 0;

  std::vector<std::shared_ptr<MockupConnection>> conns = {conn};
  while (conns.size() < maxIdleConnPerDownstream) {
    auto newConn = manager.getConnectionToDownstream(mplexer, downstream1, now, std::string());
    newConn->d_usable = false;
    conns.push_back(newConn);
    BOOST_CHECK_EQUAL(manager.count(), conns.size());
  }

  /* if we add a new one, the oldest should NOT get expunged because they are all active ones! */
  auto newConn = manager.getConnectionToDownstream(mplexer, downstream1, now, std::string());
  BOOST_CHECK_GT(manager.count(), maxIdleConnPerDownstream);

  {
    /* mark all connections as not usable anymore */
    for (auto& c : conns) {
      c->d_usable = false;
    }

    /* except the last one */
    newConn->d_usable = true;

    BOOST_CHECK_EQUAL(manager.count(), conns.size() + 1);
    later.tv_sec += cleanupInterval + 1;
    manager.cleanupClosedConnections(later);
    BOOST_CHECK_EQUAL(manager.count(), 1U);
  }

  conns.clear();
  auto cleared = manager.clear();
  BOOST_CHECK_EQUAL(cleared, 1U);

  /* add 10 actives connections */
  while (conns.size() < 10) {
    newConn = manager.getConnectionToDownstream(mplexer, downstream1, now, std::string());
    newConn->d_usable = false;
    conns.push_back(newConn);
    BOOST_CHECK_EQUAL(manager.count(), conns.size());
    BOOST_CHECK_EQUAL(manager.getActiveCount(), conns.size());
  }
  /* now we mark them as idle */
  for (auto& c : conns) {
    /* use a different shared_ptr to make sure that the comparison is done on the actual raw pointer */
    auto shared = c;
    shared->d_idle = true;
    BOOST_CHECK(manager.moveToIdle(shared));
  }
  BOOST_CHECK_EQUAL(manager.count(), maxIdleConnPerDownstream);
  BOOST_CHECK_EQUAL(manager.getActiveCount(), 0U);
  BOOST_CHECK_EQUAL(manager.getIdleCount(), maxIdleConnPerDownstream);

  {
    /* if we ask for a connection, one of these should become active and no longer idle */
    /* but first we need to mark them as usable again */
    for (const auto& c : conns) {
      c->d_usable = true;
    }
    auto got = manager.getConnectionToDownstream(mplexer, downstream1, now, std::string());
    BOOST_CHECK_EQUAL(manager.count(), maxIdleConnPerDownstream);
    BOOST_CHECK_EQUAL(manager.getActiveCount(), 1U);
    BOOST_CHECK_EQUAL(manager.getIdleCount(), maxIdleConnPerDownstream - 1U);
  }
}

BOOST_AUTO_TEST_SUITE_END();
