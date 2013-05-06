#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include "misc.hh"
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

BOOST_AUTO_TEST_CASE(test_stripDot) {
    BOOST_CHECK_EQUAL(stripDot("www.powerdns.com."), "www.powerdns.com");
}

BOOST_AUTO_TEST_CASE(test_labelReverse) {
    BOOST_CHECK_EQUAL(labelReverse("www.powerdns.com"), "com powerdns www");
}

BOOST_AUTO_TEST_CASE(test_makeRelative) {
    BOOST_CHECK_EQUAL(makeRelative("www.powerdns.com", "powerdns.com"), "www");
}

BOOST_AUTO_TEST_CASE(test_AtomicConter) {
    AtomicCounter ac;
    ++ac;
    ++ac;
    BOOST_CHECK_EQUAL(ac, 2);
}


BOOST_AUTO_TEST_CASE(test_parseService) {
    ServiceTuple tp;
    parseService("smtp.powerdns.com:25", tp);
    BOOST_CHECK_EQUAL(tp.host, "smtp.powerdns.com");
    BOOST_CHECK_EQUAL(tp.port, 25);
    parseService("smtp.powerdns.com", tp);    
    BOOST_CHECK_EQUAL(tp.port, 25);
}

BOOST_AUTO_TEST_SUITE_END()

