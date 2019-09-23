#define BOOST_TEST_RPZ_LOADER
#define BOOST_TEST_RPZ_LOADER
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rpzloader.hh"
#include <boost/test/unit_test.hpp>

// Provide stubs for some symbols
bool g_logRPZChanges{false};
ComboAddress getQueryLocalAddress(int family, uint16_t port) {
  cerr << "getQueryLocalAddress() STUBBED IN TEST!" << endl;
  BOOST_ASSERT(false);
  return ComboAddress();
}

BOOST_AUTO_TEST_SUITE(rpzloader_cc)

BOOST_AUTO_TEST_CASE(test_rpz_loader) {

  string tests[][2] = {
      {"32.3.2.168.192", "192.168.2.3/32"},
      {"27.73.2.168.192", "192.168.2.73/27"},
      {"24.0.2.168.192", "192.168.2.0/24"},
      {"128.57.zz.1.0.db8.2001", "2001:db8:0:1::57/128"},
      {"48.zz.1.0.db8.2001", "2001:db8:0:1::/48"},
      {"128.5.C0A8.FFFF.0.1.0.db8.2001", "2001:db8:0:1:0:ffff:c0a8:5/128"},

      {"21.0.248.44.5", "5.44.248.0/21"},
      {"64.0.0.0.0.0.1.0.0.", "0:0:1::/64"},
      {"64.zz.2.0.0", "0:0:2::/64"},
      {"80.0.0.0.1.0.0.0.0", "::1:0:0:0/80"},
      {"80.0.0.0.1.zz", "::1:0:0:0/80"}};

  for (auto &test : tests) {
    Netmask n = makeNetmaskFromRPZ(DNSName(test[0]));
    BOOST_CHECK_EQUAL(n.toString(), test[1]);
  }
}

BOOST_AUTO_TEST_SUITE_END()
