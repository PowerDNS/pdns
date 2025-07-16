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

#include "dnsdist-backoff.hh"

BOOST_AUTO_TEST_SUITE(dnsdistbackoff)

BOOST_AUTO_TEST_CASE(test_ExponentialBackOffTimer)
{
  const unsigned int maxBackOff = 10 * 60;
  const ExponentialBackOffTimer ebot(maxBackOff);
  const std::vector<std::pair<size_t, unsigned int>> testVector{
    {0U, 1U},
    {1U, 2U},
    {2U, 4U},
    {3U, 8U},
    {4U, 16U},
    {5U, 32U},
    {6U, 64U},
    {7U, 128U},
    {8U, 256U},
    {9U, 512U},
    {10U, maxBackOff}};
  for (const auto& entry : testVector) {
    BOOST_CHECK_EQUAL(ebot.get(entry.first), entry.second);
  }

  /* the behaviour is identical after 32 but let's go to 1024 to be safe */
  for (size_t consecutiveFailures = testVector.size(); consecutiveFailures < 1024; consecutiveFailures++) {
    BOOST_CHECK_EQUAL(ebot.get(consecutiveFailures), maxBackOff);
  }
}

BOOST_AUTO_TEST_SUITE_END()
