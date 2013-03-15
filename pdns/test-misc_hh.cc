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
	nsset.insert("ns.example.com");
	BOOST_CHECK_EQUAL(nsset.size(), 3);

	ostringstream s;
	for(set<std::string, CIStringCompare>::const_iterator i=nsset.begin();i!=nsset.end();++i) {
		s<<"["<<*i<<"]";
	}
	BOOST_CHECK_EQUAL(s.str(), "[][abc][ns.example.com]");
}

BOOST_AUTO_TEST_CASE(test_CIStringPairCompare) {
	set<typedns_t, CIStringPairCompare> nsset2;  
	nsset2.insert(make_pair("ns.example.com", 1));
	nsset2.insert(make_pair("abc", 1));
	nsset2.insert(make_pair("", 1));
	nsset2.insert(make_pair("abc", 2));
	nsset2.insert(make_pair("abc", 1));
	nsset2.insert(make_pair("ns.example.com", 0));
	BOOST_CHECK_EQUAL(nsset2.size(), 5);

	ostringstream s;
	for(set<typedns_t, CIStringPairCompare>::const_iterator i=nsset2.begin();i!=nsset2.end();++i) {
		s<<"["<<i->first<<"|"<<i->second<<"]";
	}
	BOOST_CHECK_EQUAL(s.str(), "[|1][abc|1][abc|2][ns.example.com|0][ns.example.com|1]");
}

BOOST_AUTO_TEST_SUITE_END()

