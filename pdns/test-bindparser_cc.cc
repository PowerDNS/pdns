#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "misc.hh"
#include "pdnsexception.hh"
#include <utility>

#include <sstream>
#include <cstdlib>
#include "dnsname.hh"
#include "bindparserclasses.hh"
#include "iputils.hh"

using std::string;

BOOST_AUTO_TEST_SUITE(test_bindparser_cc)

BOOST_AUTO_TEST_CASE(test_parser) {
        const char *srcdir;
        std::ostringstream pathbuf;
        BindParser BP;
        BOOST_CHECK_THROW( BP.parse("../regression-tests/named.confx"), PDNSException);
        BP.setVerbose(true);
        srcdir = std::getenv("SRCDIR");
        if(!srcdir)
                srcdir="."; // assume no shenanigans

        pathbuf << srcdir << "/../pdns/named.conf.parsertest";
        BP.parse(pathbuf.str());

        vector<BindDomainInfo> domains=BP.getDomains();
        BOOST_CHECK_EQUAL(domains.size(), 11U);

#define checkzone(i, dname, fname, ztype, nmasters) { \
	        BOOST_CHECK(domains[i].name == DNSName(#dname));     \
                BOOST_CHECK_EQUAL(domains[i].filename, fname); \
                BOOST_CHECK_EQUAL(domains[i].type, #ztype); \
                BOOST_CHECK_EQUAL(domains[i].masters.size(), nmasters); \
        }

        checkzone(0, example.com, "./zones//example.com", master, 0U);
        checkzone(1, test.com, "./zones//test.com", slave, 1U);
        BOOST_CHECK_EQUAL(domains[1].masters[0].toString(), ComboAddress("1.2.3.4", 5678).toString());
        checkzone(2, test.dyndns, "./zones//test.dyndns", garblewarble, 0U);
        checkzone(3, wtest.com, "./zones//wtest.com", master, 0U);
        checkzone(4, nztest.com, "./zones//nztest.com", master, 0U);
        checkzone(5, dnssec-parent.com, "./zones//dnssec-parent.com", master, 0U);
        checkzone(6, delegated.dnssec-parent.com, "./zones//delegated.dnssec-parent.com", master, 0U);
        checkzone(7, secure-delegated.dnssec-parent.com, "./zones//secure-delegated.dnssec-parent.com", master, 0U);
        checkzone(8, minimal.com, "./zones//minimal.com", master, 0U);
        checkzone(9, tsig.com, "./zones//tsig.com", master, 0U);
        checkzone(10, stest.com, "./zones//stest.com", master, 0U);
}

BOOST_AUTO_TEST_SUITE_END()

