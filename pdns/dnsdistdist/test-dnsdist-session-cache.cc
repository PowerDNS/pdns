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

#include "dnsdist-session-cache.hh"
#include "dnsdist-configuration.hh"

class MockTLSSession : public TLSSession
{
public:
  ~MockTLSSession() override = default;
};

BOOST_AUTO_TEST_SUITE(test_dnsdist_session_cache)

BOOST_AUTO_TEST_CASE(test_No_Rate_Limiting)
{
  TLSSessionCache cache{};
  const auto backendID1 = getUniqueID();
  const auto backendID2 = getUniqueID();
  auto now = time(nullptr);

  BOOST_REQUIRE_EQUAL(cache.getSize(), 0U);

  /* store one session */
  std::vector<std::unique_ptr<TLSSession>> sessions;
  sessions.push_back(std::make_unique<MockTLSSession>());
  cache.putSessions(backendID1, now, std::move(sessions));
  BOOST_REQUIRE_EQUAL(cache.getSize(), 1U);

  /* we can retrieve it */
  auto session = cache.getSession(backendID1, now);
  BOOST_REQUIRE(session != nullptr);
  BOOST_REQUIRE_EQUAL(cache.getSize(), 0U);

  /* but only once */
  session = cache.getSession(backendID1, now);
  BOOST_REQUIRE(session == nullptr);
  BOOST_REQUIRE_EQUAL(cache.getSize(), 0U);

  /* add a new session */
  sessions.clear();
  sessions.push_back(std::make_unique<MockTLSSession>());
  cache.putSessions(backendID1, now, std::move(sessions));
  BOOST_REQUIRE_EQUAL(cache.getSize(), 1U);

  /* wait until the session expires */
  const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  now += std::max(runtimeConfig.d_tlsSessionCacheSessionValidity, runtimeConfig.d_tlsSessionCacheCleanupDelay) + 1;

  /* trigger cache cleaning by inserting a session for a different backend */
  sessions.clear();
  sessions.push_back(std::make_unique<MockTLSSession>());
  cache.putSessions(backendID2, now, std::move(sessions));
  BOOST_REQUIRE_EQUAL(cache.getSize(), 1U);

  session = cache.getSession(backendID1, now);
  BOOST_REQUIRE(session == nullptr);
}

BOOST_AUTO_TEST_SUITE_END();
