#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include "iputils.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(iputils_hh)

BOOST_AUTO_TEST_CASE(test_ComboAddress) {
  ComboAddress local("127.0.0.1", 53);
  BOOST_CHECK(local==local);
  BOOST_CHECK_EQUAL(local.sin4.sin_family, AF_INET);
  BOOST_CHECK_EQUAL(local.sin4.sin_port, htons(53));
  BOOST_CHECK_EQUAL(local.sin4.sin_addr.s_addr, htonl(0x7f000001UL));

  ComboAddress remote("130.161.33.15", 53);
  BOOST_CHECK(!(local == remote));
}

BOOST_AUTO_TEST_SUITE_END()
