#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include <stdio.h>

#include "dnsname.hh"
#include "qtype.hh"
#include "taskqueue.hh"
#include "rec-taskqueue.hh"
#include "test-syncres_cc.hh"

BOOST_AUTO_TEST_SUITE(rec_taskqueue)

BOOST_AUTO_TEST_CASE(test_almostexpired_queue_no_dups)
{
  taskQueueClear();
  pushAlmostExpiredTask(DNSName("foo"), QType::AAAA, 0, Netmask());
  pushAlmostExpiredTask(DNSName("foo"), QType::AAAA, 0, Netmask());
  pushAlmostExpiredTask(DNSName("foo"), QType::A, 0, Netmask());

  BOOST_CHECK_EQUAL(getTaskSize(), 2U);
  taskQueuePop();
  taskQueuePop();
  BOOST_CHECK_EQUAL(getTaskSize(), 0U);
  // AE queue is not rate limited
  pushAlmostExpiredTask(DNSName("foo"), QType::A, 0, Netmask());
  BOOST_CHECK_EQUAL(getTaskSize(), 1U);
}

BOOST_AUTO_TEST_CASE(test_resolve_queue_rate_limit)
{
  taskQueueClear();
  pushResolveTask(DNSName("foo"), QType::AAAA, 0, 1, false);
  BOOST_CHECK_EQUAL(getTaskSize(), 1U);
  taskQueuePop();
  BOOST_CHECK_EQUAL(getTaskSize(), 0U);

  // Should hit rate limiting
  pushResolveTask(DNSName("foo"), QType::AAAA, 0, 1, false);
  BOOST_CHECK_EQUAL(getTaskSize(), 0U);

  // Should not hit rate limiting as time has passed
  pushResolveTask(DNSName("foo"), QType::AAAA, 61, 62, false);
  BOOST_CHECK_EQUAL(getTaskSize(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
