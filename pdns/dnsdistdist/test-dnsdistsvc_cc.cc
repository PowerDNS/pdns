
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist-svc.hh"
#include "svc-records.hh"
#include "dnsparser.hh"

BOOST_AUTO_TEST_SUITE(dnsdistsvc_cc)

BOOST_AUTO_TEST_CASE(test_Basic)
{
  DNSName target("powerdns.com.");

  {
    // invalid priority of 0 + parameters
    std::vector<uint8_t> payload;
    const uint16_t priority = 0;
    BOOST_CHECK(!generateSVCPayload(payload, priority, target, {SvcParam::SvcParamKey::port}, {"dot"}, false, 853, std::string(), {ComboAddress("192.0.2.1")}, {ComboAddress("2001:db8::1")}, {}));
  }

  {
    std::vector<uint8_t> payload;
    const uint16_t priority = 1;
    BOOST_CHECK(generateSVCPayload(payload, priority, target, {SvcParam::SvcParamKey::port}, {"dot"}, false, 853, std::string(), {ComboAddress("192.0.2.1")}, {ComboAddress("2001:db8::1")}, {}));
    /* 2 octet field for SvcPriority as an integer in network byte order */
    /* uncompressed, fully-qualified TargetName */
    /* list of SvcParams as:
       - 2 octet field containing the SvcParamKey as an integer in network byte order
       - 2 octet field containing the length of the SvcParamValue as an integer between 0 and 65535 in network byte order (but constrained by the RDATA and DNS message sizes)
       - an octet string of this length whose contents are in a format determined by the SvcParamKey
       SvcParamKeys SHALL appear in increasing numeric order
    */
    size_t expectedSize = (/* priority */ 2) + target.wirelength() + (/* mandatory */ 2 + 2 + 2) + (/* alpns with 1-byte length field for each value */ 2 + 2 + 4) + (/* no-alpn-default is false */ 0) + (/* port */ 2 + 2 + 2) + (/* ech */ 0) + (/* v4 hints */ 2 + 2 + 9) + (/* v6 hints */ 2 + 2 + 11);
    BOOST_CHECK_EQUAL(payload.size(), expectedSize);

    std::set<SvcParam> params;
    PacketReader pr(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()), 0);
    BOOST_CHECK_EQUAL(pr.get16BitInt(), priority);

    /* we can't use getName() directly because it assumes that there has to be a dnsheader before the name */
    DNSName parsedTarget(reinterpret_cast<const char*>(payload.data()), payload.size(), pr.getPosition(), false /* uncompress */, nullptr /* qtype */, nullptr /* qclass */, nullptr /* consumed */, 0);
    pr.skip(parsedTarget.wirelength());
    BOOST_CHECK_EQUAL(target.toString(), parsedTarget.toString());

    pr.xfrSvcParamKeyVals(params);
    BOOST_REQUIRE_EQUAL(params.size(), 5U);
    auto param = params.begin();
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::mandatory);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::alpn);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::port);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::ipv4hint);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::ipv6hint);
  }

  {
    std::vector<uint8_t> payload;
    const uint16_t priority = 2;
    const std::string ech("whatever");
    const std::string dohParam("/dns-query{?dns}");

    BOOST_CHECK(generateSVCPayload(payload, priority, target, {SvcParam::SvcParamKey::port}, {"h2"}, true, 443, ech, {ComboAddress("192.0.2.2")}, {ComboAddress("2001:db8::2")}, {std::pair<uint16_t, std::string>(42, dohParam)}));

    size_t expectedSize = (/* priority */ 2) + target.wirelength() + (/* mandatory */ 2 + 2 + 2) + (/* alpns */ 2 + 2 + 3) + (/* no-alpn-default is true */ 2 + 2) + (/* port */ 2 + 2 + 2) + (/* ech */ 2 + 2 + ech.size()) + (/* v4 hints */ 2 + 2 + 9) + (/* v6 hints */ 2 + 2 + 11) + (/* doh parameter */ 2 + 2 + dohParam.size());
    BOOST_CHECK_EQUAL(payload.size(), expectedSize);

    std::set<SvcParam> params;
    PacketReader pr(std::string_view(reinterpret_cast<const char*>(payload.data()), payload.size()), 0);
    BOOST_CHECK_EQUAL(pr.get16BitInt(), priority);

    /* we can't use getName() directly because it assumes that there has to be a dnsheader before the name */
    DNSName parsedTarget(reinterpret_cast<const char*>(payload.data()), payload.size(), pr.getPosition(), false /* uncompress */, nullptr /* qtype */, nullptr /* qclass */, nullptr /* consumed */, 0);
    pr.skip(parsedTarget.wirelength());
    BOOST_CHECK_EQUAL(target.toString(), parsedTarget.toString());

    pr.xfrSvcParamKeyVals(params);
    BOOST_REQUIRE_EQUAL(params.size(), 8U);
    auto param = params.begin();
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::mandatory);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::alpn);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::no_default_alpn);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::port);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::ipv4hint);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::ech);
    ++param;
    BOOST_CHECK(param->getKey() == SvcParam::SvcParamKey::ipv6hint);
    ++param;
    BOOST_CHECK_EQUAL(static_cast<uint16_t>(param->getKey()), 42U);
  }
}

BOOST_AUTO_TEST_CASE(test_Parsing)
{
  svcParamsLua_t params;
  params["mandatory"] = std::vector<std::pair<int, std::string>>({
    {1, "port"},
  });
  params["alpn"] = std::vector<std::pair<int, std::string>>({
    {1, "h2"},
  });
  params["noDefaultAlpn"] = static_cast<bool>(true);
  params["port"] = static_cast<uint16_t>(443);
  params["ipv4hint"] = std::vector<std::pair<int, std::string>>({
    {1, "192.0.2.1"},
  });
  params["ipv6hint"] = std::vector<std::pair<int, std::string>>({
    {1, "2001:db8::1"},
  });
  params["ech"] = std::string("test");

  auto parsed = parseSVCParameters(params);
  BOOST_CHECK(parsed.mandatoryParams == std::set<uint16_t>{SvcParam::SvcParamKey::port});
  BOOST_CHECK(parsed.alpns == std::vector<std::string>{"h2"});
  BOOST_CHECK(parsed.ipv4hints == std::vector<ComboAddress>{ComboAddress("192.0.2.1")});
  BOOST_CHECK(parsed.ipv6hints == std::vector<ComboAddress>{ComboAddress("2001:db8::1")});
  BOOST_CHECK_EQUAL(parsed.ech, "test");
  BOOST_CHECK_EQUAL(*parsed.port, 443);
  BOOST_CHECK_EQUAL(parsed.noDefaultAlpn, true);
}

BOOST_AUTO_TEST_SUITE_END()
