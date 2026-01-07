#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "svc-records.hh"
#include "base64.hh"
#include "iputils.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_svc_records_cc)
BOOST_AUTO_TEST_CASE(test_SvcParam_keyFromString) {
    SvcParam::SvcParamKey k;

    k = SvcParam::keyFromString("mandatory");
    BOOST_CHECK(k == 0);
    BOOST_CHECK(k == SvcParam::mandatory);

    k = SvcParam::keyFromString("alpn");
    BOOST_CHECK(k == 1);
    BOOST_CHECK(k == SvcParam::alpn);

    k = SvcParam::keyFromString("no-default-alpn");
    BOOST_CHECK(k == 2);
    BOOST_CHECK(k == SvcParam::no_default_alpn);

    k = SvcParam::keyFromString("port");
    BOOST_CHECK(k == 3);
    BOOST_CHECK(k == SvcParam::port);

    k = SvcParam::keyFromString("ipv4hint");
    BOOST_CHECK(k == 4);
    BOOST_CHECK(k == SvcParam::ipv4hint);

    k = SvcParam::keyFromString("ech");
    BOOST_CHECK(k == 5);
    BOOST_CHECK(k == SvcParam::ech);

    k = SvcParam::keyFromString("ipv6hint");
    BOOST_CHECK(k == 6);
    BOOST_CHECK(k == SvcParam::ipv6hint);

    k = SvcParam::keyFromString("dohpath");
    BOOST_CHECK(k == 7);
    BOOST_CHECK(k == SvcParam::dohpath);

    k = SvcParam::keyFromString("ohttp");
    BOOST_CHECK(k == 8);
    BOOST_CHECK(k == SvcParam::ohttp);

    k = SvcParam::keyFromString("tls-supported-groups");
    BOOST_CHECK(k == 9);
    BOOST_CHECK(k == SvcParam::tls_supported_groups);

    k = SvcParam::keyFromString("key0");
    BOOST_CHECK(k == 0);
    BOOST_CHECK(k == SvcParam::mandatory);

    k = SvcParam::keyFromString("key666");
    BOOST_CHECK(k == 666);

    k = SvcParam::keyFromString("key00666");
    BOOST_CHECK(k == 666);

    BOOST_CHECK_THROW(SvcParam::keyFromString("MANDATORY"), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_keyToString) {
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::mandatory), "mandatory");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::alpn), "alpn");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::no_default_alpn), "no-default-alpn");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::port), "port");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::ipv4hint), "ipv4hint");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::ech), "ech");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::ipv6hint), "ipv6hint");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::dohpath), "dohpath");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::ohttp), "ohttp");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::tls_supported_groups), "tls-supported-groups");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::SvcParamKey(10)), "key10");
    BOOST_CHECK_EQUAL(SvcParam::keyToString(SvcParam::SvcParamKey(666)), "key666");
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_no_value) {
    BOOST_CHECK_NO_THROW(SvcParam(SvcParam::keyFromString("no-default-alpn")));
    BOOST_CHECK_THROW(SvcParam(SvcParam::keyFromString("alpn")), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::keyFromString("key666")), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_value) {
    string val = "foobar";
    auto base64val = Base64Encode(val);

    BOOST_CHECK_THROW(SvcParam(SvcParam::mandatory, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::port, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ohttp, val), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::tls_supported_groups, val), std::invalid_argument);

    SvcParam param(SvcParam::keyFromString("no-default-alpn"));
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::ech, base64val));
    BOOST_CHECK_EQUAL(param.getECH(), base64val);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getTLSSupportedGroups(), std::invalid_argument);

    // TODO test bad base64 value
    // BOOST_CHECK_THROW(SvcParam(SvcParam::ech, val), std::invalid_argument);

    // Any string is allowed.....
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::keyFromString("key666"), base64val));
    BOOST_CHECK_EQUAL(param.getValue(), base64val);
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::keyFromString("key666"), val));
    BOOST_CHECK_EQUAL(param.getValue(), val);

    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getECH(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getTLSSupportedGroups(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_set_string_value) {
    set<string> val({"foo", "bar", "baz"});

    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn, set<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, set<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::port, set<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, set<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ech, set<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, set<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::dohpath, set<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ohttp, set<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::tls_supported_groups, set<string>(val)), std::invalid_argument);

    set<string> mandatoryVal = {"alpn", "ohttp", "key666"};
    set<SvcParam::SvcParamKey> mandatoryExpected = {SvcParam::alpn, SvcParam::ohttp, (SvcParam::SvcParamKey)666};
    SvcParam param(SvcParam::keyFromString("no-default-alpn"));
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::keyFromString("mandatory"), std::move(mandatoryVal)));

    auto retval = param.getMandatory();
    BOOST_CHECK(retval == mandatoryExpected);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getECH(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getTLSSupportedGroups(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_vector_string_value) {
    auto val = vector<string>({"h3, h2"});
    auto checkVal = val;

    BOOST_CHECK_THROW(SvcParam(SvcParam::mandatory, vector<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, vector<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::port, vector<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, vector<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ech, vector<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, vector<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::dohpath, vector<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ohttp, vector<string>(val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::tls_supported_groups, vector<string>(val)), std::invalid_argument);

    SvcParam param(SvcParam::keyFromString("no-default-alpn"));
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::keyFromString("alpn"), std::move(val)));
    auto alpns = param.getALPN();

    BOOST_CHECK_EQUAL_COLLECTIONS(alpns.begin(), alpns.end(), checkVal.begin(), checkVal.end());
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getECH(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getTLSSupportedGroups(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_set_comboaddress_value) {
    ComboAddress ca1("192.0.2.1");
    ComboAddress ca2("192.0.2.2");
    ComboAddress ca3("2001:db8::1");
    ComboAddress ca4("2001:db8::2");

    vector<ComboAddress> mixedVal({ca1, ca3});
    vector<ComboAddress> v4Val({ca1, ca2});
    auto v4CheckVal = v4Val;
    vector<ComboAddress> v6Val({ca3, ca4});
    auto v6CheckVal = v6Val;

    BOOST_CHECK_THROW(SvcParam(SvcParam::mandatory, std::move(v4Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn, std::move(v4Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, std::move(v4Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::port, std::move(v4Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ech, std::move(v4Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::dohpath, vector<ComboAddress>(v4Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ohttp, vector<ComboAddress>(v4Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::tls_supported_groups, vector<ComboAddress>(v4Val)), std::invalid_argument);

    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, std::move(v4Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, std::move(v6Val)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, std::move(mixedVal)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, std::move(mixedVal)), std::invalid_argument);

    SvcParam param(SvcParam::keyFromString("no-default-alpn"));
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::ipv4hint, std::move(v4Val)));

    auto retval = param.getIPHints();
    BOOST_CHECK(retval == v4CheckVal);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getECH(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getTLSSupportedGroups(), std::invalid_argument);

    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::ipv6hint, std::move(v6Val)));
    retval.clear();
    retval = param.getIPHints();
    BOOST_CHECK(retval == v6CheckVal);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getECH(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getPort(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getTLSSupportedGroups(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_uint16_value) {
    uint16_t port(53);

    BOOST_CHECK_THROW(SvcParam(SvcParam::mandatory, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ech, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::dohpath, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ohttp, port), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::tls_supported_groups, port), std::invalid_argument);

    SvcParam param(SvcParam::keyFromString("no-default-alpn"));
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::port, port));
    BOOST_CHECK_EQUAL(param.getPort(), port);
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getECH(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getTLSSupportedGroups(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_ctor_vector_uint16_value) {
    vector<uint16_t> groups({29, 23});
    auto checkVal = groups;

    BOOST_CHECK_THROW(SvcParam(SvcParam::mandatory, vector<uint16_t>(groups)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::alpn, vector<uint16_t>(groups)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::no_default_alpn, vector<uint16_t>(groups)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv4hint, vector<uint16_t>(groups)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ech, vector<uint16_t>(groups)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ipv6hint, vector<uint16_t>(groups)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::dohpath, vector<uint16_t>(groups)), std::invalid_argument);
    BOOST_CHECK_THROW(SvcParam(SvcParam::ohttp, vector<uint16_t>(groups)), std::invalid_argument);

    SvcParam param(SvcParam::keyFromString("no-default-alpn"));
    BOOST_CHECK_NO_THROW(param = SvcParam(SvcParam::tls_supported_groups, vector<uint16_t>(groups)));
    auto retval = param.getTLSSupportedGroups();
    BOOST_CHECK_EQUAL_COLLECTIONS(checkVal.begin(), checkVal.end(), retval.begin(), retval.end());
    BOOST_CHECK_THROW(param.getMandatory(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getALPN(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getECH(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getIPHints(), std::invalid_argument);
    BOOST_CHECK_THROW(param.getValue(), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(test_SvcParam_comparison) {
    // Test the SvcParam::operator== and operator!= behaviour

    {
        std::set<SvcParam::SvcParamKey> set1{SvcParam::ech};
        std::set<SvcParam::SvcParamKey> same_as_set1 = set1;
        std::set<SvcParam::SvcParamKey> set2{SvcParam::alpn};

        SvcParam mandatory(SvcParam::SvcParamKey::mandatory, std::move(set1));
        SvcParam mandatory2(SvcParam::SvcParamKey::mandatory, std::move(same_as_set1));
        SvcParam mandatory3(SvcParam::SvcParamKey::mandatory, std::move(set2));

        BOOST_CHECK(mandatory == mandatory2);
        BOOST_CHECK(mandatory != mandatory3);
        BOOST_CHECK(mandatory2 != mandatory3);
    }

    {
        std::vector<std::string> first{"h2", "h3"};
        std::vector<std::string> same_as_first = first;
        std::vector<std::string> different{"h3", "h2"};

        SvcParam alpn(SvcParam::SvcParamKey::alpn, std::move(first));
        SvcParam alpn2(SvcParam::SvcParamKey::alpn, std::move(same_as_first));
        SvcParam alpn3(SvcParam::SvcParamKey::alpn, std::move(different));

        BOOST_CHECK(alpn == alpn2);
        BOOST_CHECK(alpn != alpn3);
        BOOST_CHECK(alpn2 != alpn3);
    }

    {
        // ohttps uses the same logic
        SvcParam nda(SvcParam::SvcParamKey::no_default_alpn);
        SvcParam nda2(SvcParam::SvcParamKey::no_default_alpn);

        BOOST_CHECK(nda == nda2);
    }

    {
        uint16_t port = 1337;
        uint16_t other_port = 1338;
        SvcParam param1(SvcParam::SvcParamKey::port, port);
        SvcParam param2(SvcParam::SvcParamKey::port, port);
        SvcParam param3(SvcParam::SvcParamKey::port, other_port);

        BOOST_CHECK(param1 == param1);
        BOOST_CHECK(param1 != param3);
        BOOST_CHECK(param2 != param3);
    }

    {
        // Uses the same logic as ipv6hint
        ComboAddress ca1{"192.0.2.1"};
        ComboAddress ca2{"192.0.2.2"};
        ComboAddress ca3{"192.0.2.3"};

        std::vector<ComboAddress> first{ca1};
        auto same_as_first = first;

        std::vector<ComboAddress> different_order{ca1, ca2};
        std::vector<ComboAddress> different_order2{ca2, ca1};

        std::vector<ComboAddress> all{ca1, ca2, ca3};

        SvcParam param1(SvcParam::SvcParamKey::ipv4hint, std::move(first));
        SvcParam param2(SvcParam::SvcParamKey::ipv4hint, std::move(same_as_first));

        SvcParam param3(SvcParam::SvcParamKey::ipv4hint, std::move(different_order));
        SvcParam param4(SvcParam::SvcParamKey::ipv4hint, std::move(different_order2));

        SvcParam param5(SvcParam::SvcParamKey::ipv4hint, std::move(all));

        BOOST_CHECK(param1 == param2);

        BOOST_CHECK(param2 != param3);
        BOOST_CHECK(param2 != param4);
        BOOST_CHECK(param2 != param5);

        BOOST_CHECK(param3 != param4);
        BOOST_CHECK(param3 != param5);

        BOOST_CHECK(param4 != param5);
    }

    {
        std::string first{"somefakeechvalue"};
        std::string same_as_first = first;
        std::string different{"someotherfakeechvalue"};

        SvcParam ech(SvcParam::SvcParamKey::ech, std::move(first));
        SvcParam ech2(SvcParam::SvcParamKey::ech, std::move(same_as_first));
        SvcParam ech3(SvcParam::SvcParamKey::ech, std::move(different));

        BOOST_CHECK(ech == ech2);
        BOOST_CHECK(ech != ech3);
        BOOST_CHECK(ech2 != ech3);
    }

    {
        std::string first{"/foo"};
        std::string same_as_first = first;
        std::string different{"/bar"};

        SvcParam dohpath(SvcParam::SvcParamKey::dohpath, std::move(first));
        SvcParam dohpath2(SvcParam::SvcParamKey::dohpath, std::move(same_as_first));
        SvcParam dohpath3(SvcParam::SvcParamKey::dohpath, std::move(different));

        BOOST_CHECK(dohpath == dohpath2);
        BOOST_CHECK(dohpath != dohpath3);
        BOOST_CHECK(dohpath2 != dohpath3);
    }

    {
        std::vector<uint16_t> first{0, 1, 2};
        std::vector<uint16_t> same_as_first = first;
        std::vector<uint16_t> different{2, 3};

        SvcParam tls_supported_groups(SvcParam::SvcParamKey::tls_supported_groups, std::move(first));
        SvcParam tls_supported_groups2(SvcParam::SvcParamKey::tls_supported_groups, std::move(same_as_first));
        SvcParam tls_supported_groups3(SvcParam::SvcParamKey::tls_supported_groups, std::move(different));

        BOOST_CHECK(tls_supported_groups == tls_supported_groups2);
        BOOST_CHECK(tls_supported_groups != tls_supported_groups3);
        BOOST_CHECK(tls_supported_groups2 != tls_supported_groups3);
    }

    {
        std::string first{"somegenericvalue"};
        std::string same_as_first = first;
        std::string different{"anothergenericvalue"};
        auto key = "key6666";

        SvcParam generic(SvcParam::keyFromString(key), std::move(first));
        SvcParam generic2(SvcParam::keyFromString(key), std::move(same_as_first));
        SvcParam generic3(SvcParam::keyFromString(key), std::move(different));

        BOOST_CHECK(generic == generic2);
        BOOST_CHECK(generic != generic3);
        BOOST_CHECK(generic2 != generic3);
    }
}

BOOST_AUTO_TEST_SUITE_END()
