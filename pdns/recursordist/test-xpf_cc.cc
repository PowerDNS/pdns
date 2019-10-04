#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "xpf.hh"

BOOST_AUTO_TEST_SUITE(xpf_cc)

BOOST_AUTO_TEST_CASE(test_generateXPFPayload) {

  /* Mixing v4 with v6 should throw */
  BOOST_CHECK_THROW(generateXPFPayload(false, ComboAddress("192.0.2.1"), ComboAddress("2001:db8::1")), std::runtime_error);
  BOOST_CHECK_THROW(generateXPFPayload(false, ComboAddress("2001:db8::1"), ComboAddress("192.0.2.1")), std::runtime_error);

  {
    /* v4 payload over UDP */
    ComboAddress source("192.0.2.1:53");
    ComboAddress destination("192.0.2.2:65535");

    auto payload = generateXPFPayload(false, source, destination);
    BOOST_CHECK_EQUAL(payload.size(), 14U);
    BOOST_CHECK_EQUAL(payload.at(0), 4);
    BOOST_CHECK_EQUAL(payload.at(1), 17);

    ComboAddress parsedSource;
    ComboAddress parsedDestination;
    BOOST_CHECK(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, &parsedDestination));
    BOOST_CHECK_EQUAL(parsedSource.toStringWithPort(), source.toStringWithPort());
    BOOST_CHECK_EQUAL(parsedDestination.toStringWithPort(), destination.toStringWithPort());
  }

  {
    /* v4 payload over TCP */
    ComboAddress source("192.0.2.1:53");
    ComboAddress destination("192.0.2.2:65535");

    auto payload = generateXPFPayload(true, source, destination);
    BOOST_CHECK_EQUAL(payload.size(), 14U);
    BOOST_CHECK_EQUAL(payload.at(0), 4);
    BOOST_CHECK_EQUAL(payload.at(1), 6);

    ComboAddress parsedSource;
    ComboAddress parsedDestination;
    BOOST_CHECK(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, &parsedDestination));
    BOOST_CHECK_EQUAL(parsedSource.toStringWithPort(), source.toStringWithPort());
    BOOST_CHECK_EQUAL(parsedDestination.toStringWithPort(), destination.toStringWithPort());
  }

  {
    /* v6 payload over UDP */
    ComboAddress source("[2001:db8::1]:42");
    ComboAddress destination("[::1]:65535");

    auto payload = generateXPFPayload(false, source, destination);
    BOOST_CHECK_EQUAL(payload.size(), 38U);
    BOOST_CHECK_EQUAL(payload.at(0), 6);
    BOOST_CHECK_EQUAL(payload.at(1), 17);

    ComboAddress parsedSource;
    ComboAddress parsedDestination;
    BOOST_CHECK(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, &parsedDestination));
    BOOST_CHECK_EQUAL(parsedSource.toStringWithPort(), source.toStringWithPort());
    BOOST_CHECK_EQUAL(parsedDestination.toStringWithPort(), destination.toStringWithPort());
  }

  {
    /* v6 payload over TCP */
    ComboAddress source("[2001:db8::1]:42");
    ComboAddress destination("[::1]:65535");

    auto payload = generateXPFPayload(true, source, destination);
    BOOST_CHECK_EQUAL(payload.size(), 38U);
    BOOST_CHECK_EQUAL(payload.at(0), 6);
    BOOST_CHECK_EQUAL(payload.at(1), 6);

    ComboAddress parsedSource;
    ComboAddress parsedDestination;
    BOOST_CHECK(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, &parsedDestination));
    BOOST_CHECK_EQUAL(parsedSource.toStringWithPort(), source.toStringWithPort());
    BOOST_CHECK_EQUAL(parsedDestination.toStringWithPort(), destination.toStringWithPort());
  }

}

BOOST_AUTO_TEST_CASE(test_parseXPFPayload) {

  /* invalid sizes */
  {
    ComboAddress source;
    ComboAddress destination;

    BOOST_CHECK_EQUAL(parseXPFPayload(nullptr, 0, source, &destination), false);
    BOOST_CHECK_EQUAL(parseXPFPayload(nullptr, 13, source, &destination), false);
    BOOST_CHECK_EQUAL(parseXPFPayload(nullptr, 15, source, &destination), false);
    BOOST_CHECK_EQUAL(parseXPFPayload(nullptr, 37, source, &destination), false);
    BOOST_CHECK_EQUAL(parseXPFPayload(nullptr, 39, source, &destination), false);
  }


  {
    /* invalid protocol */
    ComboAddress source("[2001:db8::1]:42");
    ComboAddress destination("[::1]:65535");

    auto payload = generateXPFPayload(true, source, destination);
    /* set protocol to 0 */
    payload.at(1) = 0;

    ComboAddress parsedSource;
    ComboAddress parsedDestination;
    BOOST_CHECK_EQUAL(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, &parsedDestination), false);
  }

  {
    /* invalid version */
    ComboAddress source("[2001:db8::1]:42");
    ComboAddress destination("[::1]:65535");

    auto payload = generateXPFPayload(true, source, destination);
    /* set version to 0 */
    payload.at(0) = 0;

    ComboAddress parsedSource;
    ComboAddress parsedDestination;
    BOOST_CHECK_EQUAL(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, &parsedDestination), false);
  }

  {
    /* payload too short (v6 size with v4 payload) */
    ComboAddress source("192.0.2.1:53");
    ComboAddress destination("192.0.2.2:65535");


    auto payload = generateXPFPayload(true, source, destination);
    /* set version to 6 */
    payload.at(0) = 6;

    ComboAddress parsedSource;
    ComboAddress parsedDestination;
    BOOST_CHECK_EQUAL(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, &parsedDestination), false);
  }

  {
    /* payload too long (v6 size with v4 payload) */
    ComboAddress source("[2001:db8::1]:42");
    ComboAddress destination("[::1]:65535");


    auto payload = generateXPFPayload(true, source, destination);
    /* set version to 4 */
    payload.at(0) = 4;

    ComboAddress parsedSource;
    ComboAddress parsedDestination;
    BOOST_CHECK_EQUAL(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, &parsedDestination), false);
  }

  {
    /* v4 payload over UDP */
    ComboAddress source("192.0.2.1:53");
    ComboAddress destination("192.0.2.2:65535");

    auto payload = generateXPFPayload(false, source, destination);
    BOOST_CHECK_EQUAL(payload.size(), 14U);
    BOOST_CHECK_EQUAL(payload.at(0), 4);
    BOOST_CHECK_EQUAL(payload.at(1), 17);

    ComboAddress parsedSource;
    BOOST_CHECK(parseXPFPayload(payload.c_str(), payload.size(), parsedSource, nullptr));
    BOOST_CHECK_EQUAL(parsedSource.toStringWithPort(), source.toStringWithPort());
  }

}


BOOST_AUTO_TEST_SUITE_END()
