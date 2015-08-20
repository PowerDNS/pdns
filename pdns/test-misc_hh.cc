#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include "misc.hh"
#include "dns.hh"
#include <arpa/inet.h>
#include <utility>

using std::string;

BOOST_AUTO_TEST_SUITE(misc_hh)
typedef pair<std::string, uint16_t> typedns_t;

BOOST_AUTO_TEST_CASE(test_CIStringCompare) {
        set<std::string, CIStringCompare> nsset;
        nsset.insert("abc");
        nsset.insert("ns.example.com");
        nsset.insert("");
        nsset.insert("def");
        nsset.insert("aBc");
        nsset.insert("ns.example.com");
        BOOST_CHECK_EQUAL(nsset.size(), 4);

        ostringstream s;
        for(set<std::string, CIStringCompare>::const_iterator i=nsset.begin();i!=nsset.end();++i) {
                s<<"("<<*i<<")";
        }
        BOOST_CHECK_EQUAL(s.str(), "()(abc)(def)(ns.example.com)");
}

BOOST_AUTO_TEST_CASE(test_CIStringPairCompare) {
        set<typedns_t, CIStringPairCompare> nsset2;
        nsset2.insert(make_pair("ns.example.com", 1));
        nsset2.insert(make_pair("abc", 1));
        nsset2.insert(make_pair("", 1));
        nsset2.insert(make_pair("def", 1));
        nsset2.insert(make_pair("abc", 2));
        nsset2.insert(make_pair("abc", 1));
        nsset2.insert(make_pair("ns.example.com", 0));
        nsset2.insert(make_pair("abc", 2));
        nsset2.insert(make_pair("ABC", 2));
        BOOST_CHECK_EQUAL(nsset2.size(), 6);

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

  BOOST_FOREACH(const case_t& val, cases) {
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

  BOOST_FOREACH(const case_t& val, cases) {
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
    BOOST_CHECK_EQUAL(labelReverse("www.powerdns.com"), "com powerdns www");
}

BOOST_AUTO_TEST_CASE(test_makeRelative) {
    BOOST_CHECK_EQUAL(makeRelative("www.powerdns.com", "powerdns.com"), "www");
    BOOST_CHECK_EQUAL(makeRelative("PoWeRdNs.CoM", "powerdns.com"), "");
}

BOOST_AUTO_TEST_CASE(test_AtomicCounter) {
    AtomicCounter ac;
    ++ac;
    ++ac;
    BOOST_CHECK_EQUAL(ac, 2);
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

BOOST_AUTO_TEST_SUITE_END()

