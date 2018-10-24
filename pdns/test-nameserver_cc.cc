#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "iputils.hh"
#include "nameserver.hh"
#include "statbag.hh"
#include <utility>

extern vector<ComboAddress> g_localaddresses;

BOOST_AUTO_TEST_SUITE(test_nameserver_cc)

BOOST_AUTO_TEST_CASE(test_AddressIsUs4) {
  ComboAddress local1("127.0.0.1", 53);
  ComboAddress local2("127.0.0.2", 53);
  ComboAddress Remote("192.168.255.255", 53);

  g_localaddresses.push_back(ComboAddress("0.0.0.0", 53));
    
  BOOST_CHECK_EQUAL(AddressIsUs(local1), true);
//  BOOST_CHECK_EQUAL(AddressIsUs(local2), false);
  BOOST_CHECK_EQUAL(AddressIsUs(Remote), false);
  
  g_localaddresses.clear();
  g_localaddresses.push_back(ComboAddress("192.168.255.255", 53));
  BOOST_CHECK_EQUAL(AddressIsUs(Remote), true);
  Remote.sin4.sin_port = 1;
  BOOST_CHECK_EQUAL(AddressIsUs(Remote), false);
}

BOOST_AUTO_TEST_CASE(test_AddressIsUs6) {
  ComboAddress local1("127.0.0.1", 53);
  ComboAddress local2("127.0.0.2", 53);
  ComboAddress local3("::1", 53);
  ComboAddress Remote("192.168.255.255", 53);
  
  g_localaddresses.clear();
  g_localaddresses.push_back(ComboAddress("::", 53));
  
  BOOST_CHECK_EQUAL(AddressIsUs(local1), true);
//  BOOST_CHECK_EQUAL(AddressIsUs(local2), false);
  if(!getenv("PDNS_TEST_NO_IPV6")) BOOST_CHECK_EQUAL(AddressIsUs(local3), true);
  BOOST_CHECK_EQUAL(AddressIsUs(Remote), false);
  Remote.sin4.sin_port = 1;
  BOOST_CHECK_EQUAL(AddressIsUs(Remote), false);
}

BOOST_AUTO_TEST_SUITE_END()
