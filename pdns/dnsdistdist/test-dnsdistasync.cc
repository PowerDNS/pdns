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

#include "dnsdist-async.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdistasync)

class DummyQuerySender : public TCPQuerySender
{
public:
  bool active() const override
  {
    return true;
  }

  void handleResponse([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
  }

  void handleXFRResponse([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
  }

  void notifyIOError([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
    errorRaised = true;
  }

  std::atomic<bool> errorRaised{false};
};

struct DummyCrossProtocolQuery : public CrossProtocolQuery
{
  DummyCrossProtocolQuery() :
    CrossProtocolQuery()
  {
    d_sender = std::make_shared<DummyQuerySender>();
  }

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    return d_sender;
  }

  std::shared_ptr<DummyQuerySender> d_sender;
};

BOOST_AUTO_TEST_CASE(test_Basic)
{
  auto holder = std::make_unique<dnsdist::AsynchronousHolder>();
  BOOST_CHECK(holder->empty());

  {
    auto query = holder->get(0, 0);
    BOOST_CHECK(query == nullptr);
  }

  {
    uint16_t asyncID = 1;
    uint16_t queryID = 42;
    struct timeval ttd;
    gettimeofday(&ttd, nullptr);
    // timeout in 100 ms
    const timeval add{0, 100000};
    ttd = ttd + add;

    holder->push(asyncID, queryID, ttd, std::make_unique<DummyCrossProtocolQuery>());
    BOOST_CHECK(!holder->empty());

    auto query = holder->get(0, 0);
    BOOST_CHECK(query == nullptr);

    query = holder->get(asyncID, queryID);
    BOOST_CHECK(holder->empty());

    query = holder->get(asyncID, queryID);
    BOOST_CHECK(query == nullptr);

    // sleep for 200 ms, to be sure the main thread has
    // been awakened
    usleep(200000);
  }

  holder->stop();
}

BOOST_AUTO_TEST_CASE(test_TimeoutFailClose)
{
  auto holder = std::make_unique<dnsdist::AsynchronousHolder>(false);
  uint16_t asyncID = 1;
  uint16_t queryID = 42;
  struct timeval ttd{};

  std::shared_ptr<DummyQuerySender> sender{nullptr};
  {
    // timeout in 10 ms
    const timeval add{0, 10000};
    auto query = std::make_unique<DummyCrossProtocolQuery>();
    sender = query->d_sender;
    BOOST_REQUIRE(sender != nullptr);
    gettimeofday(&ttd, nullptr);
    ttd = ttd + add;
    holder->push(asyncID, queryID, ttd, std::move(query));
    BOOST_CHECK(!holder->empty());
  }

  // the event should be triggered after 10 ms, but we have seen
  // many spurious failures on our CI, likely because the box is
  // overloaded, so sleep for up to 100 ms to be sure
  for (size_t counter = 0; counter < 10; counter++) {
    if (holder->empty() && sender->errorRaised.load()) {
      break;
    }
    usleep(10000);
  }

  BOOST_CHECK(holder->empty());
  BOOST_CHECK(sender->errorRaised.load());

  holder->stop();
}

BOOST_AUTO_TEST_CASE(test_AddingExpiredEvent)
{
  auto holder = std::make_unique<dnsdist::AsynchronousHolder>(false);
  uint16_t asyncID = 1;
  uint16_t queryID = 42;
  struct timeval ttd;
  gettimeofday(&ttd, nullptr);
  // timeout was 10 ms ago, for some reason (long processing time, CPU starvation...)
  const timeval sub{0, 10000};
  ttd = ttd - sub;

  std::shared_ptr<DummyQuerySender> sender{nullptr};
  {
    auto query = std::make_unique<DummyCrossProtocolQuery>();
    sender = query->d_sender;
    BOOST_REQUIRE(sender != nullptr);
    holder->push(asyncID, queryID, ttd, std::move(query));
  }

  // the expired event should be triggered almost immediately,
  // but we have seen many spurious failures on our CI,
  // likely because the box is overloaded, so sleep for up to
  // 100 ms to be sure
  for (size_t counter = 0; counter < 10; counter++) {
    if (holder->empty() && sender->errorRaised.load()) {
      break;
    }
    usleep(10000);
  }

  BOOST_CHECK(holder->empty());
  BOOST_CHECK(sender->errorRaised.load());

  holder->stop();
}

BOOST_AUTO_TEST_SUITE_END();
