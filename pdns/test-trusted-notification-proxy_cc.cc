#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include "trusted-notification-proxy.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_trusted_notification_proxy_cc)

BOOST_AUTO_TEST_CASE(test_trusted_notification_proxy_bad_addrs) {
  string addrs = "127.0.0.1111";
  BOOST_CHECK_THROW(pdns::parseTrustedNotificationProxy(addrs), PDNSException);
  addrs = "127.0.0.1,:::2";
  BOOST_CHECK_THROW(pdns::parseTrustedNotificationProxy(addrs), PDNSException);
}

BOOST_AUTO_TEST_CASE(test_trusted_notification_proxy_addresses_only) {
  string addrs = "127.0.0.1";
  BOOST_CHECK_NO_THROW(pdns::parseTrustedNotificationProxy(addrs));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.2")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("::1")));

  addrs = "::1";
  BOOST_CHECK_NO_THROW(pdns::parseTrustedNotificationProxy(addrs));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.1")));

  addrs = "::1,192.0.2.4";
  BOOST_CHECK_NO_THROW(pdns::parseTrustedNotificationProxy(addrs));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("::1")));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.4")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.1")));
}

BOOST_AUTO_TEST_CASE(test_trusted_notification_proxy_with_netmasks) {
  string addrs = "127.0.0.0/8";
  BOOST_CHECK_NO_THROW(pdns::parseTrustedNotificationProxy(addrs));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.1")));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.2")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("128.0.0.2")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("::1")));

  addrs = "192.0.2.0/25";
  BOOST_CHECK_NO_THROW(pdns::parseTrustedNotificationProxy(addrs));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.2")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("128.0.0.2")));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.128")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8::1")));

  addrs = "2001:db8:15::/64";
  BOOST_CHECK_NO_THROW(pdns::parseTrustedNotificationProxy(addrs));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8::1")));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8:15::fee:1:2")));

  addrs = "192.0.2.0/24,2001:db8:16::/64";
  BOOST_CHECK_NO_THROW(pdns::parseTrustedNotificationProxy(addrs));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8:15::fee:1:2")));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.1")));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8:16::5353")));
}

BOOST_AUTO_TEST_CASE(test_trusted_notification_proxy_with_netmasks_and_addresses) {
  string addrs = "192.0.2.1,2001:db8:16::/64";
  BOOST_CHECK_NO_THROW(pdns::parseTrustedNotificationProxy(addrs));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("127.0.0.1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8::1")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8:15::fee:1:2")));
  BOOST_CHECK(!pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.2")));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("192.0.2.1")));
  BOOST_CHECK(pdns::isAddressTrustedNotificationProxy(ComboAddress("2001:db8:16::5353")));
}

BOOST_AUTO_TEST_SUITE_END()
