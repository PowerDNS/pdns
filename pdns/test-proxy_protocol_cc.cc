#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>

#include "iputils.hh"
#include "proxy-protocol.hh"

using namespace boost;
using std::string;


BOOST_AUTO_TEST_SUITE(test_proxy_protocol_cc)

#define BINARY(s) (std::string(s, sizeof(s) - 1))

#define PROXYMAGIC "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define PROXYMAGICLEN sizeof(PROXYMAGIC)-1

static string proxymagic(PROXYMAGIC, PROXYMAGICLEN);

BOOST_AUTO_TEST_CASE(test_roundtrip) {
  std::vector<ProxyProtocolValue> values;
  string proxyheader;

  bool ptcp = true;
  ComboAddress src("65.66.67.68:18762");  // 18762 = 0x494a = "IJ"
  ComboAddress dest("69.70.71.72:19276"); // 19276 = 0x4b4c = "KL"
  proxyheader = makeProxyHeader(ptcp, src, dest, values);

  BOOST_CHECK_EQUAL(proxyheader, BINARY(
    PROXYMAGIC
    "\x21"          // version | command
    "\x11"          // ipv4=0x10 | TCP=0x1
    "\x00\x0c"      // 4 bytes IPv4 * 2 + 2 port numbers = 8 + 2 * 2 =12 = 0xc
    "ABCD"          // 65.66.67.68
    "EFGH"          // 69.70.71.72
    "IJ"            // src port
    "KL"            // dst port
    ));

  bool proxy;
  bool ptcp2;
  ComboAddress src2, dest2;

  BOOST_CHECK_EQUAL(parseProxyHeader(proxyheader, proxy, src2, dest2, ptcp2, values), 28);

  BOOST_CHECK_EQUAL(proxy, true);
  BOOST_CHECK_EQUAL(ptcp2, true);
  BOOST_CHECK(src2 == ComboAddress("65.66.67.68:18762"));
  BOOST_CHECK(dest2 == ComboAddress("69.70.71.72:19276"));
}

BOOST_AUTO_TEST_SUITE_END()
