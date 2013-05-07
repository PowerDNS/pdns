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

BOOST_AUTO_TEST_CASE(test_Netmask) {
  ComboAddress local("127.0.0.1", 53);
  ComboAddress remote("130.161.252.29", 53);
  
  Netmask nm("127.0.0.1/24");
  BOOST_CHECK(nm.match(local));
  BOOST_CHECK(!nm.match(remote));

  Netmask nm6("fe80::92fb:a6ff:fe4a:51da/64");
  BOOST_CHECK(nm6.match("fe80::92fb:a6ff:fe4a:51db"));
  BOOST_CHECK(!nm6.match("fe81::92fb:a6ff:fe4a:51db"));

  Netmask nmp("130.161.252.29/32");
  BOOST_CHECK(nmp.match(remote));

  Netmask nmp6("fe80::92fb:a6ff:fe4a:51da/128");
  BOOST_CHECK(nmp6.match("fe80::92fb:a6ff:fe4a:51da"));
  BOOST_CHECK(!nmp6.match("fe81::92fb:a6ff:fe4a:51db"));

  Netmask all("0.0.0.0/0");
  BOOST_CHECK(all.match(local) && all.match(remote));

  Netmask all6("::/0");
  BOOST_CHECK(all6.match("::1") && all6.match("fe80::92fb:a6ff:fe4a:51da"));
}

BOOST_AUTO_TEST_CASE(test_NetmaskGroup) {
  NetmaskGroup ng;
  ng.addMask("127.0.0.0/8");
  ng.addMask("10.0.0.0/24");
  BOOST_CHECK(ng.match(ComboAddress("127.0.0.1")));
  BOOST_CHECK(ng.match(ComboAddress("10.0.0.3")));
  BOOST_CHECK(!ng.match(ComboAddress("128.1.2.3")));
  BOOST_CHECK(!ng.match(ComboAddress("10.0.1.0")));
  BOOST_CHECK(!ng.match(ComboAddress("::1")));
  ng.addMask("::1");
  BOOST_CHECK(ng.match(ComboAddress("::1")));
  BOOST_CHECK(!ng.match(ComboAddress("::2")));
  ng.addMask("fe80::/16");
  BOOST_CHECK(ng.match(ComboAddress("fe80::1")));
  BOOST_CHECK(!ng.match(ComboAddress("fe81::1")));
}


BOOST_AUTO_TEST_SUITE_END()
