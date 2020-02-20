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
  BOOST_CHECK(src2 == src);
  BOOST_CHECK(dest2 == dest);
}

BOOST_AUTO_TEST_CASE(test_local_proxy_header) {
  auto payload = makeLocalProxyHeader();

  BOOST_CHECK_EQUAL(payload, BINARY(
    PROXYMAGIC
    "\x20"          // version | command
    "\x00"          // protocol family and address are set to 0
    "\x00\x00"      // no content
    ));

  bool proxy;
  bool tcp = false;
  ComboAddress src, dest;
  std::vector<ProxyProtocolValue> values;

  BOOST_CHECK_EQUAL(parseProxyHeader(payload, proxy, src, dest, tcp, values), 16);

  BOOST_CHECK_EQUAL(proxy, false);
  BOOST_CHECK_EQUAL(tcp, false);
  BOOST_CHECK_EQUAL(values.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_tlv_values_content_len_signedness) {
  std::string largeValue;
  /* this value will make the content length parsing fail in case of signedness mistake */
  largeValue.resize(65128, 'A');
  const std::vector<ProxyProtocolValue> values = { { "foo", 0 }, { largeValue, 255 }};

  const bool tcp = false;
  const ComboAddress src("[2001:db8::1]:0");
  const ComboAddress dest("[::1]:65535");
  const auto payload = makeProxyHeader(tcp, src, dest, values);

  bool proxy;
  bool tcp2;
  ComboAddress src2;
  ComboAddress dest2;
  std::vector<ProxyProtocolValue> parsedValues;

  BOOST_CHECK_EQUAL(parseProxyHeader(payload, proxy, src2, dest2, tcp2, parsedValues), 16 + 36 + 6 + 65131);
  BOOST_CHECK_EQUAL(proxy, true);
  BOOST_CHECK_EQUAL(tcp2, tcp);
  BOOST_CHECK(src2 == src);
  BOOST_CHECK(dest2 == dest);
  BOOST_REQUIRE_EQUAL(parsedValues.size(), values.size());
  for (size_t idx = 0; idx < values.size(); idx++) {
    BOOST_CHECK_EQUAL(parsedValues.at(idx).type, values.at(idx).type);
    BOOST_CHECK_EQUAL(parsedValues.at(idx).content, values.at(idx).content);
  }
}

BOOST_AUTO_TEST_CASE(test_tlv_values_length_signedness) {
  std::string largeValue;
  /* this value will make the TLV length parsing fail in case of signedness mistake */
  largeValue.resize(65000, 'A');
  const std::vector<ProxyProtocolValue> values = { { "foo", 0 }, { largeValue, 255 }};

  const bool tcp = false;
  const ComboAddress src("[2001:db8::1]:0");
  const ComboAddress dest("[::1]:65535");
  const auto payload = makeProxyHeader(tcp, src, dest, values);

  bool proxy;
  bool tcp2;
  ComboAddress src2;
  ComboAddress dest2;
  std::vector<ProxyProtocolValue> parsedValues;

  BOOST_CHECK_EQUAL(parseProxyHeader(payload, proxy, src2, dest2, tcp2, parsedValues), 16 + 36 + 6 + 65003);
  BOOST_CHECK_EQUAL(proxy, true);
  BOOST_CHECK_EQUAL(tcp2, tcp);
  BOOST_CHECK(src2 == src);
  BOOST_CHECK(dest2 == dest);
  BOOST_REQUIRE_EQUAL(parsedValues.size(), values.size());
  for (size_t idx = 0; idx < values.size(); idx++) {
    BOOST_CHECK_EQUAL(parsedValues.at(idx).type, values.at(idx).type);
    BOOST_CHECK_EQUAL(parsedValues.at(idx).content, values.at(idx).content);
  }
}

BOOST_AUTO_TEST_CASE(test_parsing_invalid_headers) {
  const std::vector<ProxyProtocolValue> noValues;

  const bool tcp = false;
  const ComboAddress src("[2001:db8::1]:0");
  const ComboAddress dest("[::1]:65535");
  const auto payload = makeProxyHeader(tcp, src, dest, noValues);

  bool proxy;
  bool tcp2;
  ComboAddress src2;
  ComboAddress dest2;
  std::vector<ProxyProtocolValue> values;

  {
    /* just checking that everything works */
    BOOST_CHECK_EQUAL(parseProxyHeader(payload, proxy, src2, dest2, tcp2, values), 52);
    BOOST_CHECK_EQUAL(proxy, true);
    BOOST_CHECK_EQUAL(tcp2, tcp);
    BOOST_CHECK(src2 == src);
    BOOST_CHECK(dest2 == dest);
    BOOST_CHECK_EQUAL(values.size(), 0U);
  }

  {
    /* too short (not even full header) */
    std::string truncated = payload;
    truncated.resize(15);
    BOOST_CHECK_EQUAL(parseProxyHeader(truncated, proxy, src2, dest2, tcp2, values), -1);
  }

  {
    /* too short (missing address part) */
    std::string truncated = payload;
    truncated.resize(/* full header */ 16 + /* two IPv6s + port */ 36 - /* truncation */ 1);
    BOOST_CHECK_EQUAL(parseProxyHeader(truncated, proxy, src2, dest2, tcp2, values), -1);
  }

  {
    /* too short (missing TLV) */
    values = { { "foo", 0 }, { "bar", 255 }} ;
    const auto payloadWithValues = makeProxyHeader(tcp, src, dest, values);

    std::string truncated = payloadWithValues;
    truncated.resize(/* full header */ 16 + /* two IPv6s + port */ 36 + /* TLV 1 */ 6 + /* TLV 2 */ 6 - /* truncation */ 2);
    BOOST_CHECK_EQUAL(parseProxyHeader(truncated, proxy, src2, dest2, tcp2, values), -2);
  }

  {
    /* invalid magic */
    std::string invalid = payload;
    invalid.at(4) = 42;
    BOOST_CHECK_EQUAL(parseProxyHeader(invalid, proxy, src2, dest2, tcp2, values), 0);
  }

  {
    /* invalid version */
    std::string invalid = payload;
    invalid.at(12) = 0x10 | 0x01;
    BOOST_CHECK_EQUAL(parseProxyHeader(invalid, proxy, src2, dest2, tcp2, values), 0);
  }

  {
    /* invalid command */
    std::string invalid = payload;
    invalid.at(12) = 0x20 | 0x02;
    BOOST_CHECK_EQUAL(parseProxyHeader(invalid, proxy, src2, dest2, tcp2, values), 0);
  }

  {
    /* invalid family */
    std::string invalid = payload;
    invalid.at(13) = (0x04 << 4) | 0x01 /* STREAM */;
    BOOST_CHECK_EQUAL(parseProxyHeader(invalid, proxy, src2, dest2, tcp2, values), 0);
  }

  {
    /* invalid address */
    std::string invalid = payload;
    invalid.at(13) = (0x02 /* AF_INET */ << 4) | 0x03;
    BOOST_CHECK_EQUAL(parseProxyHeader(invalid, proxy, src2, dest2, tcp2, values), 0);
  }

  {
    /* TLV advertised len gets out of bounds */
    values = { { "foo", 0 }, { "bar", 255 }} ;
    const auto payloadWithValues = makeProxyHeader(tcp, src, dest, values);
    std::string invalid = payloadWithValues;
    /* full header (16) + two IPv6s + port (36) + TLV (6) TLV 2 (6) */
    invalid.at(59) += 1;
    BOOST_CHECK_EQUAL(parseProxyHeader(invalid, proxy, src2, dest2, tcp2, values), 0);
  }
}

BOOST_AUTO_TEST_SUITE_END()
