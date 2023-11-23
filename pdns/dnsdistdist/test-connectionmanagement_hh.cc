#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "connection-management.hh"

BOOST_AUTO_TEST_SUITE(connectionmanagement_hh)

BOOST_AUTO_TEST_CASE(test_ConnectionManagementEnabled) {
  size_t maxConns = 10;

  ConcurrentConnectionManager manager(maxConns);

  for (size_t idx = 0; idx < maxConns; idx++) {
    BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  }

  /* we are full */
  BOOST_CHECK_EQUAL(manager.registerConnection(), false);

  manager.releaseConnection();
  /* we can register one additional connection now that we released one */
  BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  /* but not two */
  BOOST_CHECK_EQUAL(manager.registerConnection(), false);

  /* raise the number of slots */
  maxConns = 12;
  manager.setMaxConcurrentConnections(maxConns);
  BOOST_CHECK_EQUAL(manager.getMaxConcurrentConnections(), maxConns);
  BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  BOOST_CHECK_EQUAL(manager.registerConnection(), false);

  /* release everything */
  for (size_t idx = 0; idx < maxConns; idx++) {
    manager.releaseConnection();
  }

  /* decrease the number of slots */
  maxConns = 2;
  manager.setMaxConcurrentConnections(maxConns);
  BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  BOOST_CHECK_EQUAL(manager.registerConnection(), false);

  /* decrease the number of slots with some connections still registered */
  maxConns = 1;
  manager.setMaxConcurrentConnections(maxConns);

  BOOST_CHECK_EQUAL(manager.registerConnection(), false);
  for (size_t idx = 0; idx < 2; idx++) {
    manager.releaseConnection();
  }

  BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  BOOST_CHECK_EQUAL(manager.registerConnection(), false);
}

BOOST_AUTO_TEST_CASE(test_ConnectionManagementDisabledThenEnabled) {
  /* 0 means no limit */
  size_t maxConns = 0;
  ConcurrentConnectionManager manager(maxConns);

  for (size_t idx = 0; idx < 10; idx++) {
    BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  }

  /* set a limit to 5 connections */
  maxConns = 5;
  manager.setMaxConcurrentConnections(maxConns);
  /* we can no longer register new sessions */
  BOOST_CHECK_EQUAL(manager.registerConnection(), false);

  /* release all of them */
  for (size_t idx = 0; idx < 10; idx++) {
    manager.releaseConnection();
  }

  /* register as many as we now can */
  for (size_t idx = 0; idx < maxConns; idx++) {
    BOOST_CHECK_EQUAL(manager.registerConnection(), true);
  }

  BOOST_CHECK_EQUAL(manager.registerConnection(), false);

  manager.releaseConnection();

  BOOST_CHECK_EQUAL(manager.registerConnection(), true);
}

BOOST_AUTO_TEST_SUITE_END()
