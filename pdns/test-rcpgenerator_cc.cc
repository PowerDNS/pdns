#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

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

        RecordTextReader rtr3("::FFFF:192.0.2.0");
        rtr3.xfrIP6(rawIPv6);
        string ip62("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xc0\x00\x02\x00", 16);
        BOOST_CHECK_EQUAL(makeHexDump(rawIPv6), makeHexDump(ip62));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_alpn) {
        string source("alpn=h2");
        RecordTextReader rtr(source);
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        auto alpn = v.begin()->getALPN();
        BOOST_CHECK_EQUAL(alpn.size(), 1U);
        auto val = alpn.begin();
        BOOST_CHECK_EQUAL(*val, "h2");

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        v.clear();
        source = "alpn=h2,h3";
        RecordTextReader rtr2(source);
        rtr2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        alpn = v.begin()->getALPN();
        BOOST_CHECK_EQUAL(alpn.size(), 2U);
        val = alpn.begin();
        BOOST_CHECK_EQUAL(*val, "h2");
        val++;
        BOOST_CHECK_EQUAL(*val, "h3");

        // Check the writer
        target.clear();
        RecordTextWriter rtw2(target);
        rtw2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        // Check generic
        v.clear();
        source="key1=\\002h2\\002h3";
        RecordTextReader rtr3(source);
        rtr3.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        alpn = v.begin()->getALPN();
        BOOST_CHECK_EQUAL(alpn.size(), 2U);
        val = alpn.begin();
        BOOST_CHECK_EQUAL(*val, "h2");
        val++;
        BOOST_CHECK_EQUAL(*val, "h3");

        // Error conditions
        source="key1=\\002h2\\003h3"; // Wrong length for 2nd argument
        RecordTextReader rtr4(source);
        BOOST_CHECK_THROW(rtr4.xfrSvcParamKeyVals(v), RecordTextException);

        source="key1=\\002h2\\002h3foobar"; // extra data
        RecordTextReader rtr5(source);
        BOOST_CHECK_THROW(rtr5.xfrSvcParamKeyVals(v), RecordTextException);

        source="key1"; // no data
        RecordTextReader rtr6(source);
        BOOST_CHECK_THROW(rtr6.xfrSvcParamKeyVals(v), RecordTextException);

        source="key1=\\000"; // no data
        RecordTextReader rtr7(source);
        BOOST_CHECK_THROW(rtr7.xfrSvcParamKeyVals(v), RecordTextException);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_mandatory) {
        string source("mandatory=alpn");
        RecordTextReader rtr(source);
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        auto m = v.begin()->getMandatory();
        BOOST_CHECK_EQUAL(m.size(), 1U);
        auto val = m.begin();
        BOOST_CHECK(*val == SvcParam::alpn);

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        v.clear();
        source = "mandatory=alpn,ipv4hint";
        RecordTextReader rtr2("mandatory=alpn,ipv4hint");
        rtr2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        m = v.begin()->getMandatory();
        BOOST_CHECK_EQUAL(m.size(), 2U);
        val = m.begin();
        BOOST_CHECK(*val == SvcParam::alpn);
        val++;
        BOOST_CHECK(*val ==  SvcParam::ipv4hint);

        // Check the writer
        target.clear();
        RecordTextWriter rtw2(target);
        rtw2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        // Generic parsing
        v.clear();
        source = "key0=\\000\\001\\000\\004";
        RecordTextReader rtr3(source);
        rtr3.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        m = v.begin()->getMandatory();
        BOOST_CHECK_EQUAL(m.size(), 2U);
        val = m.begin();
        BOOST_CHECK(*val == SvcParam::alpn);
        val++;
        BOOST_CHECK(*val ==  SvcParam::ipv4hint);

        // Broken
        v.clear();
        source = "key0=\\000\\001\\000";
        RecordTextReader rtr4(source);
        BOOST_CHECK_THROW(rtr4.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        source = "key0=";
        RecordTextReader rtr5(source);
        BOOST_CHECK_THROW(rtr5.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        source = "key0";
        RecordTextReader rtr6(source);
        BOOST_CHECK_THROW(rtr6.xfrSvcParamKeyVals(v), RecordTextException);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_no_default_alpn) {
        string source("no-default-alpn");
        RecordTextReader rtr(source);
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        auto k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::no_default_alpn);

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        RecordTextReader rtr2("no-default-alpn=");
        v.clear();
        BOOST_CHECK_THROW(rtr2.xfrSvcParamKeyVals(v), RecordTextException);

        // Generic
        v.clear();
        RecordTextReader rtr3("key2");
        rtr3.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::no_default_alpn);

        v.clear();
        RecordTextReader rtr4("key2=");
        BOOST_CHECK_THROW(rtr4.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr5("key2 ipv4hint=1.2.3.4");
        rtr5.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 2U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::no_default_alpn);

        v.clear();
        RecordTextReader rtr6("ipv4hint=1.2.3.4 key2");
        rtr6.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 2U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::no_default_alpn);

        v.clear();
        RecordTextReader rtr7("key2=port=123 ipv4hint=1.2.3.4");
        BOOST_CHECK_THROW(rtr7.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr8("key2=port=123");
        BOOST_CHECK_THROW(rtr8.xfrSvcParamKeyVals(v), RecordTextException);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_ipv4hint) {
        string source("ipv4hint=192.0.2.1");
        RecordTextReader rtr(source);
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        auto k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv4hint);
        auto val = v.begin()->getIPHints();
        BOOST_CHECK_EQUAL(val.size(), 1U);
        BOOST_CHECK_EQUAL(val.begin()->toString(), "192.0.2.1");

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        v.clear();
        source = "ipv4hint=192.0.2.1,192.0.2.2,192.0.2.3";
        RecordTextReader rtr2(source);
        rtr2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv4hint);

        val = v.begin()->getIPHints();
        BOOST_CHECK_EQUAL(val.size(), 3U);
        auto valit = val.begin();
        BOOST_CHECK_EQUAL(valit->toString(), "192.0.2.1");
        valit++;
        BOOST_CHECK_EQUAL(valit->toString(), "192.0.2.2");
        valit++;
        BOOST_CHECK_EQUAL(valit->toString(), "192.0.2.3");

        // Check the writer
        target.clear();
        RecordTextWriter rtw2(target);
        rtw2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        v.clear();
        RecordTextReader rtr3("ipv4hint=2001:db8::1");
        BOOST_CHECK_THROW(rtr3.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr4("ipv4hint=192.0.2.1,2001:db8::1");
        BOOST_CHECK_THROW(rtr4.xfrSvcParamKeyVals(v), RecordTextException);

        // Check if we can parse the generic format
        v.clear();
        source = "key4=\\192\\000\\002\\015";
        RecordTextReader rtr5(source);
        rtr5.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv4hint);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().begin()->toString(), "192.0.2.15");

        v.clear();
        source = "key4=\\192\\000\\002\\015\\192\\000\\002\\222";
        RecordTextReader rtr6(source);
        rtr6.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().size(), 2U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv4hint);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().begin()->toString(), "192.0.2.15");
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().at(1).toString(), "192.0.2.222");

        v.clear();
        source = "key4=\\192\\000\\222"; // Wrong number of octets
        RecordTextReader rtr7(source);
        BOOST_CHECK_THROW(rtr7.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr8("key4=");  // must have a value
        BOOST_CHECK_THROW(rtr8.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr9("ipv4hint=");  // must have a value
        BOOST_CHECK_THROW(rtr9.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr10("ipv4hint=auto");  // special value
        rtr10.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv4hint);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().size(), 0U);
        BOOST_CHECK_EQUAL(v.begin()->getAutoHint(), true);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_ipv6hint) {
        string source("ipv6hint=2001:db8::1");
        RecordTextReader rtr(source);
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        auto k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv6hint);
        auto val = v.begin()->getIPHints();
        BOOST_CHECK_EQUAL(val.size(), 1U);
        BOOST_CHECK_EQUAL(val.begin()->toString(), "2001:db8::1");

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        v.clear();
        source = "ipv6hint=2001:db8::1,2001:db8::2,2001:db8::3";
        RecordTextReader rtr2(source);
        rtr2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv6hint);

        val = v.begin()->getIPHints();
        BOOST_CHECK_EQUAL(val.size(), 3U);
        auto valit = val.begin();
        BOOST_CHECK_EQUAL(valit->toString(), "2001:db8::1");
        valit++;
        BOOST_CHECK_EQUAL(valit->toString(), "2001:db8::2");
        valit++;
        BOOST_CHECK_EQUAL(valit->toString(), "2001:db8::3");

        // Check the writer
        target.clear();
        RecordTextWriter rtw2(target);
        rtw2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        v.clear();
        RecordTextReader rtr3("ipv6hint=192.0.2.1");
        BOOST_CHECK_THROW(rtr3.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr4("ipv6hint=192.0.2.1,2001:db8::1");
        BOOST_CHECK_THROW(rtr4.xfrSvcParamKeyVals(v), RecordTextException);

        // Check if we can parse the generic format
        v.clear();
        RecordTextReader rtr5("key6=\\032\\001\\013\\184\\000\\083\\000\\000\\000\\000\\000\\000\\000\\000\\000\\021");
        rtr5.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv6hint);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().begin()->toString(), "2001:db8:53::15");

        v.clear();
        source = "key6=\\032\\001\\013\\184\\000\\083\\000\\000\\000\\000\\000\\000\\000\\000\\000\\021\\032\\001\\013\\184\\000\\083\\000\\000\\000\\000\\000\\000\\000\\000\\000\\022";
        RecordTextReader rtr6(source);
        rtr6.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().size(), 2U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ipv6hint);
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().begin()->toString(), "2001:db8:53::15");
        BOOST_CHECK_EQUAL(v.begin()->getIPHints().at(1).toString(), "2001:db8:53::16");

        v.clear();
        source = "key6=\\040\\001\\015\\270\\000\\123\\000\\000\\000\\000\\000\\000\\000\\000\\000"; // wrong number of octets
        RecordTextReader rtr7(source);
        BOOST_CHECK_THROW(rtr7.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr8("key6="); // must have a value
        BOOST_CHECK_THROW(rtr8.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr9("ipv6hint=");  // must have a value
        BOOST_CHECK_THROW(rtr9.xfrSvcParamKeyVals(v), RecordTextException);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_port) {
        string source("port=53");
        RecordTextReader rtr(source);
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        auto k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::port);
        auto val = v.begin()->getPort();
        BOOST_CHECK_EQUAL(val, 53);

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        v.clear();
        RecordTextReader rtr2("port=100000");
        BOOST_CHECK_THROW(rtr2.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr3("port=foo");
        BOOST_CHECK_THROW(rtr3.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr4("port=");
        BOOST_CHECK_THROW(rtr4.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr5("port");
        BOOST_CHECK_THROW(rtr5.xfrSvcParamKeyVals(v), RecordTextException);

        // Generic
        v.clear();
        RecordTextReader rtr6("key3");
        BOOST_CHECK_THROW(rtr6.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr7("key3=\\000\\053");
        rtr7.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::port);
        val = v.begin()->getPort();
        BOOST_CHECK_EQUAL(val, 53);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_generic) {
        string source("key666=foobar");
        RecordTextReader rtr(source);
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        auto k = v.begin()->getKey();
        BOOST_CHECK(k == 666);
        auto val = v.begin()->getValue();
        BOOST_CHECK_EQUAL(val, "foobar");

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, "key666=\"foobar\"");

        v.clear();
        RecordTextReader rtr2("key666=");
        BOOST_CHECK_THROW(rtr2.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr3("key666");
        BOOST_CHECK_NO_THROW(rtr3.xfrSvcParamKeyVals(v));
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::keyFromString("key666"));

        v.clear();
        source = "key666=\"blablabla\"";
        RecordTextReader rtr4(source);
        rtr4.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::keyFromString("key666"));
        val = v.begin()->getValue();
        BOOST_CHECK_EQUAL(val, "blablabla");

        // Check the writer
        target.clear();
        RecordTextWriter rtw2(target);
        rtw2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, source);

        v.clear();
        source = "key666=\"foo\\123 bar\"";
        RecordTextReader rtr5(source);
        rtr5.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::keyFromString("key666"));
        val = v.begin()->getValue();
        BOOST_CHECK_EQUAL(val, "foo{ bar");

        // Check the writer
        target.clear();
        RecordTextWriter rtw3(target);
        rtw3.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL("key666=\"foo{ bar\"", target);

        v.clear();
        RecordTextReader rtr6("key665= blabla");
        BOOST_CHECK_THROW(rtr6.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr7("key665=bla bla");
        BOOST_CHECK_THROW(rtr7.xfrSvcParamKeyVals(v), RecordTextException);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_multiple) {
        RecordTextReader rtr("key666=foobar ech=\"dG90YWxseSBib2d1cyBlY2hjb25maWcgdmFsdWU=\" ipv6hint=2001:db8::1 alpn=h2,h3 mandatory=alpn ipv4hint=192.0.2.1,192.0.2.2"); // out of order, resulting set should be in-order
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 6U);
        auto vit = v.begin();

        // Check ordering
        for (size_t i = 0; i < v.size(); i++) {
                if (i == 0) {
                        BOOST_CHECK(vit->getKey() == SvcParam::mandatory);
                }
                if (i == 1) {
                        BOOST_CHECK(vit->getKey() == SvcParam::alpn);
                }
                if (i == 2) {
                        BOOST_CHECK(vit->getKey() == SvcParam::ipv4hint);
                }
                if (i == 3) {
                        BOOST_CHECK(vit->getKey() == SvcParam::ech);
                }
                if (i == 4) {
                        BOOST_CHECK(vit->getKey() == SvcParam::ipv6hint);
                }
                if (i == 5) {
                        BOOST_CHECK(vit->getKey() == SvcParam::keyFromString("key666"));
                }
                vit++;
        }

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(target, "mandatory=alpn alpn=h2,h3 ipv4hint=192.0.2.1,192.0.2.2 ech=\"dG90YWxseSBib2d1cyBlY2hjb25maWcgdmFsdWU=\" ipv6hint=2001:db8::1 key666=\"foobar\"");

        v.clear();
        RecordTextReader rtr2("mandatory=alpn key666"); // generic key without value at the end of the string
        BOOST_CHECK_NO_THROW(rtr2.xfrSvcParamKeyVals(v));
        BOOST_CHECK_EQUAL(v.size(), 2U);

        v.clear();
        RecordTextReader rtr3("key666 key677=\"foo\" mandatory=alpn"); // generic key without value -not- at the end of the string
        BOOST_CHECK_NO_THROW(rtr3.xfrSvcParamKeyVals(v));
        BOOST_CHECK_EQUAL(v.size(), 3U);

        v.clear();
        RecordTextReader rtr4("mandatory= key666"); // non-generic key without value -not- at the end of the string
        BOOST_CHECK_THROW(rtr4.xfrSvcParamKeyVals(v), RecordTextException);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_ech) {
        string source("ech=\"dG90YWxseSBib2d1cyBlY2hjb25maWcgdmFsdWU=\"");
        RecordTextReader rtr(source);
        set<SvcParam> v;
        rtr.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        auto k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ech);
        auto val = v.begin()->getECH();
        BOOST_CHECK_EQUAL(val, "totally bogus echconfig value"); // decoded!

        // Check the writer
        string target;
        RecordTextWriter rtw(target);
        rtw.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(source, target);

        // Generic
        v.clear();
        source = "key5=echconfig";
        RecordTextReader rtr2(source);
        rtr2.xfrSvcParamKeyVals(v);
        BOOST_CHECK_EQUAL(v.size(), 1U);
        k = v.begin()->getKey();
        BOOST_CHECK(k == SvcParam::ech);
        val = v.begin()->getECH();
        BOOST_CHECK_EQUAL(val, "echconfig");

        v.clear();
        RecordTextReader rtr3("key5");
        BOOST_CHECK_THROW(rtr3.xfrSvcParamKeyVals(v), RecordTextException);

        v.clear();
        RecordTextReader rtr4("ech=\"\"");
        BOOST_CHECK_THROW(rtr4.xfrSvcParamKeyVals(v), RecordTextException);
}

BOOST_AUTO_TEST_CASE(test_xfrNodeOrLocatorID) {
  string source("0000:0000:0000:0001");
  RecordTextReader rtr(source);
  NodeOrLocatorID v;
  rtr.xfrNodeOrLocatorID(v);
  BOOST_CHECK_EQUAL(v.content[0], 0);
  BOOST_CHECK_EQUAL(v.content[1], 0);
  BOOST_CHECK_EQUAL(v.content[2], 0);
  BOOST_CHECK_EQUAL(v.content[3], 0);
  BOOST_CHECK_EQUAL(v.content[4], 0);
  BOOST_CHECK_EQUAL(v.content[5], 0);
  BOOST_CHECK_EQUAL(v.content[6], 0);
  BOOST_CHECK_EQUAL(v.content[7], 1);

  string target;
  RecordTextWriter rtw(target);
  rtw.xfrNodeOrLocatorID(v);
  BOOST_CHECK_EQUAL(source, target);
}

BOOST_AUTO_TEST_SUITE_END()
