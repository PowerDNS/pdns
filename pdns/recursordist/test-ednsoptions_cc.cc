#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <utility>

#include "dnsname.hh"
#include "dnswriter.hh"
#include "ednscookies.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "iputils.hh"

BOOST_AUTO_TEST_SUITE(ednsoptions_cc)

static void getRawQueryWithECSAndCookie(const DNSName& name, const Netmask& ecs, const std::string& clientCookie, const std::string& serverCookie, std::vector<uint8_t>& query)
{
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.commit();

  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = clientCookie;
  cookiesOpt.server = serverCookie;
  string cookiesOptionStr = makeEDNSCookiesOptString(cookiesOpt);
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = ecs;
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();
}

BOOST_AUTO_TEST_CASE(test_getEDNSOption) {
  DNSName name("www.powerdns.com.");
  Netmask ecs("127.0.0.1/32");
  vector<uint8_t> query;

  getRawQueryWithECSAndCookie(name, ecs, "deadbeef", "deadbeef", query);

  const struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query.data());
  size_t questionLen = query.size();
  unsigned int consumed = 0;
  DNSName dnsname = DNSName(reinterpret_cast<const char*>(query.data()), questionLen, sizeof(dnsheader), false, nullptr, nullptr, &consumed);

  size_t pos = sizeof(dnsheader) + consumed + 4;
  /* at least OPT root label (1), type (2), class (2) and ttl (4) + OPT RR rdlen (2) = 11 */
  BOOST_REQUIRE_EQUAL(ntohs(dh->arcount), 1);
  BOOST_REQUIRE(questionLen > pos + 11);
  /* OPT root label (1) followed by type (2) */
  BOOST_REQUIRE_EQUAL(query.at(pos), 0);
  BOOST_REQUIRE(query.at(pos+2) == QType::OPT);

  char* ecsStart = nullptr;
  size_t ecsLen = 0;
  int res = getEDNSOption(reinterpret_cast<char*>(query.data())+pos+9, questionLen - pos - 9, EDNSOptionCode::ECS, &ecsStart, &ecsLen);
  BOOST_CHECK_EQUAL(res, 0);

  EDNSSubnetOpts eso;
  BOOST_REQUIRE(getEDNSSubnetOptsFromString(ecsStart + 4, ecsLen - 4, &eso));

  BOOST_CHECK(eso.source == ecs);
}

BOOST_AUTO_TEST_CASE(test_getEDNSOptions) {
  DNSName name("www.powerdns.com.");
  Netmask ecs("127.0.0.1/32");
  vector<uint8_t> query;

  getRawQueryWithECSAndCookie(name, ecs, "deadbeef", "deadbeef", query);

  const struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query.data());
  size_t questionLen = query.size();
  unsigned int consumed = 0;
  DNSName dnsname = DNSName(reinterpret_cast<const char*>(query.data()), questionLen, sizeof(dnsheader), false, nullptr, nullptr, &consumed);

  size_t pos = sizeof(dnsheader) + consumed + 4;
  /* at least OPT root label (1), type (2), class (2) and ttl (4) + OPT RR rdlen (2) = 11 */
  BOOST_REQUIRE_EQUAL(ntohs(dh->arcount), 1);
  BOOST_REQUIRE(questionLen > pos + 11);
  /* OPT root label (1) followed by type (2) */
  BOOST_REQUIRE_EQUAL(query.at(pos), 0);
  BOOST_REQUIRE(query.at(pos+2) == QType::OPT);

  EDNSOptionViewMap options;
  int res = getEDNSOptions(reinterpret_cast<char*>(query.data())+pos+9, questionLen - pos - 9, options);
  BOOST_REQUIRE_EQUAL(res, 0);

  /* 3 EDNS options but two of them are EDNS Cookie, so we only have two entries in the map */
  BOOST_CHECK_EQUAL(options.size(), 2U);

  auto it = options.find(EDNSOptionCode::ECS);
  BOOST_REQUIRE(it != options.end());
  BOOST_REQUIRE_EQUAL(it->second.values.size(), 1U);
  BOOST_REQUIRE(it->second.values.at(0).content != nullptr);
  BOOST_REQUIRE_GT(it->second.values.at(0).size, 0U);

  EDNSSubnetOpts eso;
  BOOST_REQUIRE(getEDNSSubnetOptsFromString(it->second.values.at(0).content, it->second.values.at(0).size, &eso));
  BOOST_CHECK(eso.source == ecs);

  it = options.find(EDNSOptionCode::COOKIE);
  BOOST_REQUIRE(it != options.end());
  BOOST_REQUIRE_EQUAL(it->second.values.size(), 2U);
  BOOST_REQUIRE(it->second.values.at(0).content != nullptr);
  BOOST_REQUIRE_GT(it->second.values.at(0).size, 0U);
  BOOST_REQUIRE(it->second.values.at(1).content != nullptr);
  BOOST_REQUIRE_GT(it->second.values.at(1).size, 0U);
}

static void checkECSOptionValidity(const std::string& sourceStr, uint8_t sourceMask, uint8_t scopeMask)
{
  ComboAddress source(sourceStr);
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(source, sourceMask);

  string ecsOptionStr = makeEDNSSubnetOptsString(ecsOpts);

  /* 2 bytes for family, one for source mask and one for scope mask */
  const size_t ecsHeaderSize = 4;
  uint8_t sourceBytes = ((sourceMask - 1) >> 3) + 1;
  BOOST_REQUIRE_EQUAL(ecsOptionStr.size(), (ecsHeaderSize + sourceBytes));
  /* family */
  uint16_t u;
  memcpy(&u, ecsOptionStr.c_str(), sizeof(u));
  BOOST_REQUIRE_EQUAL(ntohs(u), source.isIPv4() ? 1 : 2);
  /* source mask */
  BOOST_REQUIRE_EQUAL(static_cast<uint8_t>(ecsOptionStr.at(2)), sourceMask);
  BOOST_REQUIRE_EQUAL(static_cast<uint8_t>(ecsOptionStr.at(3)), scopeMask);
  ComboAddress truncated(source);
  truncated.truncate(sourceMask);

  if (sourceMask > 0) {
    ComboAddress res;

    if (source.isIPv4()) {
      memset(&res.sin4, 0, sizeof(res.sin4));
      res.sin4.sin_family = AF_INET;
      memcpy(&res.sin4.sin_addr.s_addr, &ecsOptionStr.at(4), sourceBytes);
      BOOST_REQUIRE(res == truncated);
    }
    else {
      memset(&res.sin6, 0, sizeof(res.sin6));
      res.sin6.sin6_family = AF_INET6;
      memcpy(&res.sin6.sin6_addr.s6_addr, &ecsOptionStr.at(4), sourceBytes);
      BOOST_REQUIRE(res == truncated);
    }
  }

  EDNSSubnetOpts parsed;
  BOOST_REQUIRE(getEDNSSubnetOptsFromString(ecsOptionStr, &parsed));
  BOOST_REQUIRE(parsed.source == Netmask(truncated, sourceMask));
  BOOST_REQUIRE_EQUAL(ecsOpts.scope.getBits(), parsed.scope.getBits());
}

BOOST_AUTO_TEST_CASE(test_makeEDNSSubnetOptsString) {

  checkECSOptionValidity("192.0.2.255", 0, 0);
  checkECSOptionValidity("192.0.2.255", 8, 0);
  checkECSOptionValidity("255.255.255.255", 9, 0);
  checkECSOptionValidity("192.0.2.255", 31, 0);
  checkECSOptionValidity("192.0.2.255", 32, 0);
  checkECSOptionValidity("2001:DB8::FFFF", 0, 0);
  checkECSOptionValidity("2001:DB8::FFFF", 32, 0);
  checkECSOptionValidity("2001:DB8::FFFF", 127, 0);
  checkECSOptionValidity("2001:DB8::FFFF", 128, 0);
}

BOOST_AUTO_TEST_SUITE_END()
