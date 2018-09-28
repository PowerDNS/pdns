#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "rcpgenerator.hh"
#include "misc.hh"
#include <utility>

using std::string;

BOOST_AUTO_TEST_SUITE(test_rcpgenerator_cc)

BOOST_AUTO_TEST_CASE(test_xfrIP6) {
        RecordTextReader rtr("::1");
        string rawIPv6;
        rtr.xfrIP6(rawIPv6);
        string loopback6;
        loopback6.append(15, 0);
        loopback6.append(1,1);
        BOOST_CHECK_EQUAL(makeHexDump(rawIPv6), makeHexDump(loopback6));
        
        RecordTextReader rtr2("2a01:4f8:d12:1880::5");
        rtr2.xfrIP6(rawIPv6);
        string ip6("\x2a\x01\x04\xf8\x0d\x12\x18\x80\x00\x00\x00\x00\x00\x00\x00\x05", 16);
        BOOST_CHECK_EQUAL(makeHexDump(rawIPv6), makeHexDump(ip6));
        
        
}

BOOST_AUTO_TEST_SUITE_END()

