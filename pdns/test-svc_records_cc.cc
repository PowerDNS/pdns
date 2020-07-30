#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <bitset>
#include "svc-records.hh"
#include "base64.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_svc_records_cc)
BOOST_AUTO_TEST_CASE(test_SvcParam_keyFromString) {
    SvcParam::SvcParamKey k;

    k = SvcParam::keyFromString("mandatory");
    BOOST_CHECK_EQUAL(k, 0);
    BOOST_CHECK_EQUAL(k, SvcParam::mandatory);

    k = SvcParam::keyFromString("alpn");
    BOOST_CHECK_EQUAL(k, 1);
    BOOST_CHECK_EQUAL(k, SvcParam::alpn);

    k = SvcParam::keyFromString("no-default-alpn");
    BOOST_CHECK_EQUAL(k, 2);
    BOOST_CHECK_EQUAL(k, SvcParam::no_default_alpn);

    k = SvcParam::keyFromString("port");
    BOOST_CHECK_EQUAL(k, 3);
    BOOST_CHECK_EQUAL(k, SvcParam::port);

    k = SvcParam::keyFromString("ipv4hint");
    BOOST_CHECK_EQUAL(k, 4);
    BOOST_CHECK_EQUAL(k, SvcParam::ipv4hint);

    k = SvcParam::keyFromString("echconfig");
    BOOST_CHECK_EQUAL(k, 5);
    BOOST_CHECK_EQUAL(k, SvcParam::echconfig);

    k = SvcParam::keyFromString("ipv6hint");
    BOOST_CHECK_EQUAL(k, 6);
    BOOST_CHECK_EQUAL(k, SvcParam::ipv6hint);

    k = SvcParam::keyFromString("key0");
    BOOST_CHECK_EQUAL(k, 0);
    BOOST_CHECK_EQUAL(k, SvcParam::mandatory);

    k = SvcParam::keyFromString("key666");
    BOOST_CHECK_EQUAL(k, 666);

    BOOST_CHECK_THROW(SvcParam::keyFromString("MANDATORY"), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_keyToString) {
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::mandatory), "mandatory");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::alpn), "alpn");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::no_default_alpn), "no-default-alpn");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::port), "port");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::ipv4hint), "ipv4hint");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::echconfig), "echconfig");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::ipv6hint), "ipv6hint");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::SvcParamKey(7)), "key7");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::SvcParamKey(666)), "key666");
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_no_value) {
    BOOST_CHECK_NO_THROW(SvcParam(SvcParam::no_default_alpn));
    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::keyFromString("key666")), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_value) {
    string val = "foobar";
    auto base64val = Base64Encode(val);
    SvcParam param;

    BOOST_CHECK_THROW(SvcParam(SvcParam::mandatory, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::port, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, val), std::invalid_argument);

    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::echconfig, base64val));
    BOOST_CHECK_EQUAL(param.getEchConfig(), base64val);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);

    // TODO test bad base64 value
    // BOOST_CHECK_THROW(SvcParam(SvcParam::echconfig, val), std::invalid_argument);

    // Any string is allowed.....
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::keyFromString("key666"), base64val));
    BOOST_CHECK_EQUAL(param.getValue(), base64val);
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::keyFromString("key666"), val));
    BOOST_CHECK_EQUAL(param.getValue(), val);

    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getEchConfig(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_set_string_value) {
    set<string> val({"foo", "bar", "baz"});

    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::port, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::echconfig, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, val), std::invalid_argument);

    SvcParam param;
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::keyFromString("mandatory"), val)); // TODO this will fail once we start checking the contents

    auto retval = param.getMandatory();
    BOOST_CHECK_EQUAL_COLLECTIONS(retval.begin(), retval.end(), val.begin(), val.end());
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getEchConfig(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);

    retval.clear();
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::keyFromString("alpn"), val));
    retval = param.getALPN();
    BOOST_CHECK_EQUAL_COLLECTIONS(retval.begin(), retval.end(), val.begin(), val.end());
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getEchConfig(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_set_comboaddress_value) {
    ComboAddress ca1("192.0.2.1");
    ComboAddress ca2("192.0.2.2");
    ComboAddress ca3("2001:db8::1");
    ComboAddress ca4("2001:db8::2");

    set<ComboAddress> mixedVal({ca1, ca3});
    set<ComboAddress> v4Val({ca1, ca2});
    set<ComboAddress> v6Val({ca3, ca4});

    BOOST_CHECK_THROW(SvcParam(SvcParam::mandatory, v4Val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn, v4Val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, v4Val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::port, v4Val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::echconfig, v4Val), std::invalid_argument);

    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, v4Val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, v6Val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, mixedVal), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, mixedVal), std::invalid_argument);

    SvcParam param;
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::ipv4hint, v4Val));

    auto retval = param.getIPHints();
    BOOST_CHECK(retval == v4Val);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getEchConfig(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);

    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::ipv6hint, v6Val));
    retval.clear();
    retval = param.getIPHints();
    BOOST_CHECK(retval == v6Val);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getEchConfig(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_uint16_value) {
    uint16_t port(53);

    BOOST_CHECK_THROW(SvcParam(SvcParam::mandatory, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::echconfig, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, port), std::invalid_argument);

    SvcParam param;
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::port, port));
    BOOST_CHECK_EQUAL(param.getPort(), port);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getEchConfig(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
}

BOOST_AUTO_TEST_SUITE_END()