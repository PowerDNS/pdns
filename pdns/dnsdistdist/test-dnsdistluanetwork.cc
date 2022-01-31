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
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist-lua-network.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdistluanetwork)

BOOST_AUTO_TEST_CASE(test_Basic)
{
  dnsdist::NetworkListener listener;
  bool received = false;

  std::string payload = {'h', 'e', 'l', 'l', 'o'};
  char socketPath[] = "/tmp/test_dnsdistluanetwork.XXXXXX";
  int fd = mkstemp(socketPath);
  BOOST_REQUIRE(fd >= 0);

  listener.addUnixListeningEndpoint(socketPath, 0, [&received, payload](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
    BOOST_CHECK_EQUAL(endpoint, 0U);
    BOOST_CHECK(dgram == payload);
    received = true;
  });

  dnsdist::NetworkEndpoint client(socketPath);
  BOOST_CHECK(client.send(payload));

  struct timeval now;
  listener.runOnce(now, 1000);
  BOOST_CHECK(received);

  unlink(socketPath);
  close(fd);
}

#ifdef __linux__
BOOST_AUTO_TEST_CASE(test_Abstract)
{
  dnsdist::NetworkListener listener;
  bool received = false;

  std::string payload = {'h', 'e', 'l', 'l', 'o'};
  std::string socketPath("test_dnsdistluanetwork");
  socketPath.insert(0, 1, 0);

  listener.addUnixListeningEndpoint(socketPath, 0, [&received, payload](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
    BOOST_CHECK_EQUAL(endpoint, 0U);
    BOOST_CHECK(dgram == payload);
    received = true;
  });

  dnsdist::NetworkEndpoint client(socketPath);
  BOOST_CHECK(client.send(payload));

  struct timeval now;
  listener.runOnce(now, 1000);
  BOOST_CHECK(received);
}
#endif /* __linux__ */

BOOST_AUTO_TEST_SUITE_END();
