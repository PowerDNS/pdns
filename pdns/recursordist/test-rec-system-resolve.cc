#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include "rec-system-resolve.hh"

BOOST_AUTO_TEST_SUITE(rec_system_resolve)

BOOST_AUTO_TEST_CASE(test_basic_resolve)
{

  pdns::RecResolve::setInstanceParameters("foo", 60, 10, false, nullptr);
  auto& sysResolve = pdns::RecResolve::getInstance();

  auto address = sysResolve.lookupAndRegister("localhost", time(nullptr));
  BOOST_CHECK(address.toString() == "127.0.0.1" || address.toString() == "::1");
  address = sysResolve.lookup("localhost");
  BOOST_CHECK(address.toString() == "127.0.0.1" || address.toString() == "::1");
  sysResolve.wipe("localhost");
  BOOST_CHECK_THROW(sysResolve.lookup("localhost"), PDNSException);
}

BOOST_AUTO_TEST_SUITE_END()
