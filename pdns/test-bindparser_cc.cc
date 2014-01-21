#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include "bindparserclasses.hh"
#include "misc.hh"
#include "pdnsexception.hh"
#include <utility>
#include <boost/foreach.hpp>

using std::string;

BOOST_AUTO_TEST_SUITE(bindparser_cc)

BOOST_AUTO_TEST_CASE(test_parser) {
        BindParser BP;
        BOOST_CHECK_THROW( BP.parse("../regression-tests/named.confx"), PDNSException);
        BP.parse("../pdns/named.conf.parsertest"); // indirect path because Jenkins runs us from ../regression-tests/

        vector<BindDomainInfo> domains=BP.getDomains();
        BOOST_CHECK_EQUAL(domains.size(), 11);

#define checkzone(i, dname, fname, ztype, nmasters) { \
                BOOST_CHECK_EQUAL(domains[i].name, #dname); \
                BOOST_CHECK_EQUAL(domains[i].filename, fname); \
                BOOST_CHECK_EQUAL(domains[i].type, #ztype); \
                BOOST_CHECK_EQUAL(domains[i].masters.size(), nmasters); \
        }

        checkzone(0, example.com, "./zones//example.com", master, 0);
        checkzone(1, test.com, "./zones//test.com", slave, 1);
        BOOST_CHECK_EQUAL(domains[1].masters[0], "1.2.3.4:5678");
        checkzone(2, test.dyndns, "./zones//test.dyndns", garblewarble, 0);
        checkzone(3, wtest.com, "./zones//wtest.com", master, 0);
        checkzone(4, nztest.com, "./zones//nztest.com", master, 0);
        checkzone(5, dnssec-parent.com, "./zones//dnssec-parent.com", master, 0);
        checkzone(6, delegated.dnssec-parent.com, "./zones//delegated.dnssec-parent.com", master, 0);
        checkzone(7, secure-delegated.dnssec-parent.com, "./zones//secure-delegated.dnssec-parent.com", master, 0);
        checkzone(8, minimal.com, "./zones//minimal.com", master, 0);
        checkzone(9, tsig.com, "./zones//tsig.com", master, 0);
        checkzone(10, stest.com, "./zones//stest.com", master, 0);
}

BOOST_AUTO_TEST_SUITE_END()

