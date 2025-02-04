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
    (void)from;
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

BOOST_AUTO_TEST_CASE(test_Exceptions)
{
  std::string payload = {'h', 'e', 'l', 'l', 'o'};
  char socketPath[] = "/tmp/test_dnsdistluanetwork.XXXXXX";
  int fd = mkstemp(socketPath);
  BOOST_REQUIRE(fd >= 0);

  {
    dnsdist::NetworkListener listener;
    /* try running while empty */
    struct timeval now;
    BOOST_CHECK_THROW(listener.runOnce(now, 1000), std::runtime_error);
  }

  {
    /* invalid path */
    dnsdist::NetworkListener listener;
    BOOST_CHECK_THROW(listener.addUnixListeningEndpoint(std::string(), 0,
                                                        [](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
                                                          (void)endpoint;
                                                          (void)dgram;
                                                          (void)from;
                                                        }),
                      std::runtime_error);

    bool caught = false;
    try {
      std::string empty;
      dnsdist::NetworkEndpoint endpoint(empty);
    }
    catch (const std::runtime_error& e) {
      caught = true;
    }
    BOOST_CHECK(caught);
  }

  {
    dnsdist::NetworkListener listener;
    bool received = false;
    listener.addUnixListeningEndpoint(socketPath, 0, [&received](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
      (void)endpoint;
      (void)dgram;
      (void)from;
      received = true;
    });

    dnsdist::NetworkEndpoint client(socketPath);
    BOOST_CHECK(client.send(payload));

    struct timeval now;
    listener.runOnce(now, 1000);
    BOOST_CHECK(received);

    char otherSocketPath[] = "/tmp/test_dnsdistluanetworkOtherPath";
    /* try binding when already running */
    bool raised = false;
    try {
      listener.addUnixListeningEndpoint(otherSocketPath, 0,
                                        [](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
                                          (void)endpoint;
                                          (void)dgram;
                                          (void)from;
                                        });
    }
    catch (const std::runtime_error& e) {
      raised = true;
      BOOST_CHECK_EQUAL(e.what(), "NetworkListener should not be altered at runtime");
    }
    BOOST_CHECK(raised);
  }

  {
    dnsdist::NetworkListener listener;
    bool received = false;
    listener.addUnixListeningEndpoint(socketPath, 0, [&received](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
      (void)endpoint;
      (void)dgram;
      (void)from;
      received = true;
      throw std::runtime_error("Test exception");
    });

    dnsdist::NetworkEndpoint client(socketPath);
    BOOST_CHECK(client.send(payload));

    struct timeval now;
    listener.runOnce(now, 1000);
    BOOST_CHECK(received);
  }

  {
    class UnexpectedException
    {
    };

    dnsdist::NetworkListener listener;
    bool received = false;
    listener.addUnixListeningEndpoint(socketPath, 0, [&received](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
      (void)endpoint;
      (void)dgram;
      (void)from;
      received = true;
      throw UnexpectedException();
    });

    dnsdist::NetworkEndpoint client(socketPath);
    BOOST_CHECK(client.send(payload));

    struct timeval now;
    listener.runOnce(now, 1000);
    BOOST_CHECK(received);
  }

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
    (void)from;
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

BOOST_AUTO_TEST_CASE(test_Abstract_Exceptions)
{
  dnsdist::NetworkListener listener;
  std::string socketPath("test_dnsdistluanetwork");
  socketPath.insert(0, 1, 0);
  bool received = false;
  listener.addUnixListeningEndpoint(socketPath, 0, [&received](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
    (void)endpoint;
    (void)dgram;
    (void)from;
    received = true;
  });

  /* try binding twice to the same path */
  bool raised = false;
  try {
    listener.addUnixListeningEndpoint(socketPath, 0, [](dnsdist::NetworkListener::EndpointID endpoint, std::string&& dgram, const std::string& from) {
      (void)endpoint;
      (void)dgram;
      (void)from;
    });
  }
  catch (const std::runtime_error& e) {
    raised = true;
    BOOST_CHECK(boost::starts_with(e.what(), "Error binding Unix socket to path"));
  }
  BOOST_CHECK(raised);

  {
    /* try connecting to a non-existing path */
    raised = false;
    std::string nonExistingPath("test_dnsdistluanetwork_non_existing");
    nonExistingPath.insert(0, 1, 0);
    try {
      dnsdist::NetworkEndpoint endpoint(nonExistingPath);
    }
    catch (const std::runtime_error& e) {
      raised = true;
    }
    BOOST_CHECK(raised);
  }
}

#endif /* __linux__ */

BOOST_AUTO_TEST_SUITE_END();
