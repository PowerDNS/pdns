#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>

#include <arpa/inet.h>

#include "dns.hh"
#include "iputils.hh"
#include "misc.hh"
#include "utility.hh"

using std::string;

BOOST_AUTO_TEST_SUITE(test_misc_hh)
typedef pair<std::string, uint16_t> typedns_t;

BOOST_AUTO_TEST_CASE(test_CIStringCompare) {
        set<std::string, CIStringCompare> nsset;
        nsset.insert("abc");
        nsset.insert("ns.example.com");
        nsset.insert("");
        nsset.insert("def");
        nsset.insert("aBc");
        nsset.insert("ns.example.com");
        BOOST_CHECK_EQUAL(nsset.size(), 4U);

        ostringstream s;
        for(set<std::string, CIStringCompare>::const_iterator i=nsset.begin();i!=nsset.end();++i) {
                s<<"("<<*i<<")";
        }
        BOOST_CHECK_EQUAL(s.str(), "()(abc)(def)(ns.example.com)");
}

BOOST_AUTO_TEST_CASE(test_CIStringPairCompare) {
        set<typedns_t, CIStringPairCompare> nsset2;
        nsset2.emplace("ns.example.com", 1);
        nsset2.emplace("abc", 1);
        nsset2.emplace("", 1);
        nsset2.emplace("def", 1);
        nsset2.emplace("abc", 2);
        nsset2.emplace("abc", 1);
        nsset2.emplace("ns.example.com", 0);
        nsset2.emplace("abc", 2);
        nsset2.emplace("ABC", 2);
        BOOST_CHECK_EQUAL(nsset2.size(), 6U);

        ostringstream s;
        for(set<typedns_t, CIStringPairCompare>::const_iterator i=nsset2.begin();i!=nsset2.end();++i) {
                s<<"("<<i->first<<"|"<<i->second<<")";
        }
        BOOST_CHECK_EQUAL(s.str(), "(|1)(abc|1)(abc|2)(def|1)(ns.example.com|0)(ns.example.com|1)");
}

BOOST_AUTO_TEST_CASE(test_pdns_ilexicographical_compare) {
  typedef boost::tuple<const std::string, const std::string, bool> case_t;
  typedef std::list<case_t> cases_t;

  cases_t cases = boost::assign::list_of
    (case_t(std::string(""), std::string(""), false))
    (case_t(std::string(""), std::string("abc"), true))
    (case_t(std::string("abc"), std::string(""), false))
    (case_t(std::string("abc"), std::string("abcd"), true))
    (case_t(std::string("abcd"), std::string("abc"), false))
    (case_t(std::string("abd"), std::string("abc"), false))
    (case_t(std::string("abc"), std::string("abd"), true))
    (case_t(std::string("abc"), std::string("Abc"), false))
    (case_t(std::string("Abc"), std::string("abc"), false))
  ;

  for(const case_t& val :  cases) {
    bool res;
    res = pdns_ilexicographical_compare(val.get<0>(), val.get<1>());
    BOOST_CHECK_EQUAL(res, val.get<2>());
  }
}

BOOST_AUTO_TEST_CASE(test_pdns_iequals) {
  typedef boost::tuple<const std::string, const std::string, bool> case_t;
  typedef std::list<case_t> cases_t;

  cases_t cases = boost::assign::list_of
    (case_t(std::string(""), std::string(""), true))
    (case_t(std::string(""), std::string("abc"), false))
    (case_t(std::string("abc"), std::string(""), false))
    (case_t(std::string("abc"), std::string("abcd"), false))
    (case_t(std::string("abcd"), std::string("abc"), false))
    (case_t(std::string("abd"), std::string("abc"), false))
    (case_t(std::string("abc"), std::string("abd"), false))
    (case_t(std::string("abc"), std::string("Abc"), true))
    (case_t(std::string("Abc"), std::string("abc"), true))
  ;

  for(const case_t& val :  cases) {
    bool res;
    res = pdns_iequals(val.get<0>(), val.get<1>());
    BOOST_CHECK_EQUAL(res, val.get<2>());
  }
}

BOOST_AUTO_TEST_CASE(test_stripDot) {
  BOOST_CHECK_EQUAL(stripDot("."), "");
  BOOST_CHECK_EQUAL(stripDot(""), "");
  BOOST_CHECK_EQUAL(stripDot("www.powerdns.com."), "www.powerdns.com");
  BOOST_CHECK_EQUAL(stripDot("www.powerdns.com"), "www.powerdns.com");
}

BOOST_AUTO_TEST_CASE(test_labelReverse) {
  BOOST_CHECK_EQUAL(DNSName("www.powerdns.com").labelReverse().toString(" ", false), "com powerdns www");
}


BOOST_AUTO_TEST_CASE(test_AtomicCounter) {
    AtomicCounter ac(0);
    ++ac;
    ++ac;
    BOOST_CHECK_EQUAL(ac, 2U);
}

BOOST_AUTO_TEST_CASE(test_endianness) {
  uint32_t i = 1;
#if BYTE_ORDER == BIG_ENDIAN
  BOOST_CHECK_EQUAL(i, htonl(i));
#elif BYTE_ORDER == LITTLE_ENDIAN 
  uint32_t j=0x01000000;
  BOOST_CHECK_EQUAL(i, ntohl(j));
#else
  BOOST_FAIL("Did not detect endianness at all");
#endif
}

BOOST_AUTO_TEST_CASE(test_parseService) {
    ServiceTuple tp;
    parseService("smtp.powerdns.com:25", tp);
    BOOST_CHECK_EQUAL(tp.host, "smtp.powerdns.com");
    BOOST_CHECK_EQUAL(tp.port, 25);
    parseService("smtp.powerdns.com", tp);    
    BOOST_CHECK_EQUAL(tp.port, 25);
}

BOOST_AUTO_TEST_CASE(test_ternary) {
  int maxqps=1024;
  BOOST_CHECK_EQUAL(defTer(maxqps, 16384), maxqps);
  BOOST_CHECK_EQUAL(defTer(0, 16384), 16384);

  int* qps=0;
  BOOST_CHECK_EQUAL(*defTer(qps, &maxqps), 1024);
}

BOOST_AUTO_TEST_CASE(test_SimpleMatch) {
  BOOST_CHECK_EQUAL(SimpleMatch("").match(std::string("")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("?").match(std::string("")), false);
  BOOST_CHECK_EQUAL(SimpleMatch("*").match(std::string("")), true);

  BOOST_CHECK_EQUAL(SimpleMatch("abc").match(std::string("abc")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("abc").match(std::string("ab")), false);
  BOOST_CHECK_EQUAL(SimpleMatch("abc").match(std::string("bc")), false);

  BOOST_CHECK_EQUAL(SimpleMatch("?").match(std::string("a")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("a?c").match(std::string("abc")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("a?c").match(std::string("ab")), false);
  BOOST_CHECK_EQUAL(SimpleMatch("a?c").match(std::string("bc")), false);

  BOOST_CHECK_EQUAL(SimpleMatch("*").match(std::string("*")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("a*c").match(std::string("abc")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("a*c").match(std::string("ab")), false);
  BOOST_CHECK_EQUAL(SimpleMatch("a*c").match(std::string("bc")), false);

  BOOST_CHECK_EQUAL(SimpleMatch("*").match(std::string("abcdefghj")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("*a").match(std::string("abca")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("*a").match(std::string("abcb")), false);
  BOOST_CHECK_EQUAL(SimpleMatch("abc*").match(std::string("abcabcabcabacabac")), true);
  BOOST_CHECK_EQUAL(SimpleMatch("abc*").match(std::string("abc")), true);
}

template<typename T> bool rfc1982check(T x, T y) {
  return rfc1982LessThan(x, y);
}

BOOST_AUTO_TEST_CASE(test_rfc1982LessThan) {
  // The test cases from rfc1982 section 5.2
  BOOST_CHECK(rfc1982check<uint8_t>(0, 1));
  BOOST_CHECK(rfc1982check<uint8_t>(0, 44));
  BOOST_CHECK(rfc1982check<uint8_t>(0, 100));
  BOOST_CHECK(rfc1982check<uint8_t>(44, 100));
  BOOST_CHECK(rfc1982check<uint8_t>(100, 200));
  BOOST_CHECK(rfc1982check<uint8_t>(200, 255));
  BOOST_CHECK(rfc1982check<uint8_t>(255, 0));
  BOOST_CHECK(rfc1982check<uint8_t>(255, 100));
  BOOST_CHECK(rfc1982check<uint8_t>(200, 0));
  BOOST_CHECK(rfc1982check<uint8_t>(200, 44));

  BOOST_CHECK(rfc1982check<uint32_t>(0, 1));
  BOOST_CHECK(rfc1982check<uint32_t>(UINT32_MAX-10, 1));
  BOOST_CHECK(rfc1982check<uint32_t>(UINT32_MAX/2, UINT32_MAX-10));

  BOOST_CHECK(rfc1982check<uint64_t>(0, 1));
  BOOST_CHECK(rfc1982check<uint64_t>(UINT64_MAX-10, 1));
  BOOST_CHECK(rfc1982check<uint64_t>(UINT64_MAX/2, UINT64_MAX-10));
}

BOOST_AUTO_TEST_CASE(test_reverse_name_to_ip)
{
  static const ComboAddress v4("192.0.2.1");
  static const ComboAddress v6("2001:DB8::42");
  BOOST_CHECK_EQUAL(reverseNameFromIP(v4).toString(), "1.2.0.192.in-addr.arpa.");
  BOOST_CHECK_EQUAL(reverseNameFromIP(v6).toString(), "2.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.");
}

BOOST_AUTO_TEST_CASE(test_getCarbonHostName)
{
  char buffer[4096];

  BOOST_CHECK_EQUAL(gethostname(buffer, sizeof buffer), 0);
  std::string my_hostname(buffer);
  boost::replace_all(my_hostname, ".", "_");

  std::string hostname = getCarbonHostName();
  // ensure it matches what we get
  BOOST_CHECK_EQUAL(my_hostname, hostname);
  BOOST_CHECK_EQUAL(my_hostname.size(), hostname.size());
}

BOOST_AUTO_TEST_CASE(test_parseRFC1035CharString)
{
  string in;
  string out;
  string expected;
  size_t amount;

  in = "foobar123";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, "foobar123");

  in = "foobar123\\,bazquux456";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, "foobar123,bazquux456");

  in = string("\"")+string(16262, 'A')+string("\"");
  expected = string(16262, 'A');
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, expected);

  in = "hello\\044world\\002";
  expected = "hello,world\x02";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, expected);

  in = "\"hello\\044world\"";
  expected = "hello,world";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, expected);

  // Here we'll only read until the space
  in = "hello world";
  expected = "hello";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, 5U);
  BOOST_CHECK_EQUAL(out, expected);

  // \032 is a space, but it is read because it is escaped
  in = "hello\\032world";
  expected = "hello world";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, expected);

  in = "\"hello\\032world\"";
  expected = "hello world";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, expected);

  in = "\"hello\\032world XXXX\"";
  expected = "hello world XXXX";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, expected);

  // From draft-ietf-dnsop-svcb-https-03
  expected = R"FOO(part1,part2,part3\,part4\\)FOO";
  in = R"FOO("part1,part2,part3\\,part4\\\\)FOO";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, expected);

  in = R"FOO(part1\,\p\a\r\t2\044part3\092,part4\092\\)FOO";
  amount = parseRFC1035CharString(in, out);
  BOOST_CHECK_EQUAL(amount, in.size());
  BOOST_CHECK_EQUAL(out, expected);
}

BOOST_AUTO_TEST_CASE(test_parseSVCBValueList)
{
  vector<string> out;

  // From draft-ietf-dnsop-svcb-https-03
  vector<string> expected = {"part1", "part2", "part3,part4\\"};
  parseSVCBValueList(R"FOO("part1,part2,part3\\,part4\\\\)FOO", out);
  BOOST_CHECK_EQUAL(out.size(), expected.size());
  BOOST_CHECK_EQUAL(out[0], expected[0]);
  BOOST_CHECK_EQUAL(out[1], expected[1]);
  BOOST_CHECK_EQUAL(out[2], expected[2]);

  parseSVCBValueList(R"FOO(part1\,\p\a\r\t2\044part3\092,part4\092\\)FOO", out);
  BOOST_CHECK_EQUAL(out.size(), expected.size());
  BOOST_CHECK_EQUAL(out[0], expected[0]);
  BOOST_CHECK_EQUAL(out[1], expected[1]);
  BOOST_CHECK_EQUAL(out[2], expected[2]);

  // Our tests
  parseSVCBValueList("foobar123", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123");

  parseSVCBValueList("h2,h3", out);
  BOOST_CHECK_EQUAL(out.size(), 2U);
  BOOST_CHECK_EQUAL(out[0], "h2");
  BOOST_CHECK_EQUAL(out[1], "h3");

  parseSVCBValueList("h2,h3-19,h3-20,h3-22", out);
  BOOST_CHECK_EQUAL(out.size(), 4U);
  BOOST_CHECK_EQUAL(out[0], "h2");
  BOOST_CHECK_EQUAL(out[1], "h3-19");
  BOOST_CHECK_EQUAL(out[2], "h3-20");
  BOOST_CHECK_EQUAL(out[3], "h3-22");

  parseSVCBValueList("foobar123,bazquux456", out);
  BOOST_CHECK_EQUAL(out.size(), 2U);
  BOOST_CHECK_EQUAL(out[0], "foobar123");
  BOOST_CHECK_EQUAL(out[1], "bazquux456");

  parseSVCBValueList(R"FOO(foobar123\\,bazquux456)FOO", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123,bazquux456");

  parseSVCBValueList(R"FOO(foobar123\\\044bazquux456)FOO", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123,bazquux456");

  // Again, but quoted
  parseSVCBValueList("\"foobar123\"", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123");

  parseSVCBValueList("\"foobar123,bazquux456\"", out);
  BOOST_CHECK_EQUAL(out.size(), 2U);
  BOOST_CHECK_EQUAL(out[0], "foobar123");
  BOOST_CHECK_EQUAL(out[1], "bazquux456");

  parseSVCBValueList(R"FOO("foobar123\\,bazquux456")FOO", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123,bazquux456");

  parseSVCBValueList(R"FOO("foobar123\\\044bazquux456")FOO", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123,bazquux456");

  // Quoted, with some whitespace
  parseSVCBValueList("\"foobar123 \"", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123 ");

  parseSVCBValueList("\"foobar123 blabla bla,baz quux456\"", out);
  BOOST_CHECK_EQUAL(out.size(), 2U);
  BOOST_CHECK_EQUAL(out[0], "foobar123 blabla bla");
  BOOST_CHECK_EQUAL(out[1], "baz quux456");

  parseSVCBValueList("\"foobar123,baz quux456\"", out);
  BOOST_CHECK_EQUAL(out.size(), 2U);
  BOOST_CHECK_EQUAL(out[0], "foobar123");
  BOOST_CHECK_EQUAL(out[1], "baz quux456");

  parseSVCBValueList(R"FOO("foobar123 blabla bla\\,baz quux456")FOO", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123 blabla bla,baz quux456");

  parseSVCBValueList(R"FOO("foobar123 blabla bla\\\044baz quux456")FOO", out);
  BOOST_CHECK_EQUAL(out.size(), 1U);
  BOOST_CHECK_EQUAL(out[0], "foobar123 blabla bla,baz quux456");
}

BOOST_AUTO_TEST_CASE(test_makeBytesFromHex) {
  string out = makeBytesFromHex("1234567890abcdef");
  BOOST_CHECK_EQUAL(out, "\x12\x34\x56\x78\x90\xab\xcd\xef");

  BOOST_CHECK_THROW(makeBytesFromHex("123"), std::range_error);
}

BOOST_AUTO_TEST_SUITE_END()
