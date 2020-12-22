#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "pdns-yaml.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_pdns_yaml_hh)

BOOST_AUTO_TEST_CASE(test_ComboAddress_single)
{
    std::string ipStr = "192.0.2.1";
    ComboAddress ipCA(ipStr, 53);
    auto node = YAML::Load(ipStr);
    BOOST_CHECK(ipCA == node.as<ComboAddress>());
    node = YAML::Load("notanIP");
    BOOST_CHECK_THROW(node.as<ComboAddress>(), YAML::BadConversion);

    ComboAddress ipAltPort(ipStr, 5300);
    node = YAML::Load(ipStr + ":5300");
    BOOST_CHECK(ipAltPort == node.as<ComboAddress>());


    // Now the other way around
    node = YAML::Node(ipCA);
    YAML::Emitter e;
    e<<node;
    BOOST_CHECK_EQUAL(e.c_str(), ipStr);

    node = YAML::Node(ipAltPort);
    YAML::Emitter e2;
    e2<<node;
    BOOST_CHECK_EQUAL(e2.c_str(), ipStr + ":5300");
}

BOOST_AUTO_TEST_CASE(test_DNSName_single)
{
    std::string domain = "www.example.com";
    DNSName domainDNS(domain);
    auto node = YAML::Load(domain);
    BOOST_CHECK_EQUAL(domainDNS, node.as<DNSName>());
    node = YAML::Load("badname-badname-badname-badname-badname-badname-badname-badname-badname.example.com");
    BOOST_CHECK_THROW(node.as<DNSName>(), YAML::BadConversion);

    // And the other way around
    node = YAML::Node(domainDNS);
    YAML::Emitter e;
    e<<node;
    BOOST_CHECK_EQUAL(e.c_str(), domain);

    node = YAML::Node(DNSName("."));
    YAML::Emitter e2;
    e2<<node;
    BOOST_CHECK_EQUAL(e2.c_str(), ".");
}

BOOST_AUTO_TEST_CASE(test_Netmask_single)
{
    std::string maskStr = "192.0.2.0/24";
    Netmask mask(maskStr);
    auto node = YAML::Load(maskStr);
    BOOST_CHECK(mask == node.as<Netmask>());

    node = YAML::Load("192.0.2.0/-1");
    BOOST_CHECK_THROW(node.as<Netmask>(), YAML::BadConversion);

    // And the other way around
    node = YAML::Node(mask);
    YAML::Emitter e;
    e<<node;
    BOOST_CHECK_EQUAL(e.c_str(), maskStr);
}

BOOST_AUTO_TEST_CASE(test_NetmaskGroup)
{
    std::string nmgStr = R"(- '192.0.2.0/24'
- '!192.0.2.1'
- '2001:db8:50::/64')";

    auto node = YAML::Load(nmgStr);
    auto nmgFromNode = node.as<NetmaskGroup>();
    BOOST_CHECK(nmgFromNode.match(ComboAddress("192.0.2.15")));
    BOOST_CHECK(!nmgFromNode.match(ComboAddress("192.0.2.1")));
    BOOST_CHECK(nmgFromNode.match(ComboAddress("2001:db8:50::1")));
    BOOST_CHECK(!nmgFromNode.match(ComboAddress("2001:db8:51::1")));

    node = YAML::Load("192.0.2.0/24");
    BOOST_CHECK_THROW(node.as<NetmaskGroup>(), YAML::BadConversion);
    node = YAML::Load("- 192.0.2.444/24");
    BOOST_CHECK_THROW(node.as<NetmaskGroup>(), YAML::BadConversion);

    // And the other way around
    NetmaskGroup nmg;
    nmg.addMask("192.0.2.0/24");
    nmg.addMask("!192.0.2.1");
    nmg.addMask("2001:db8:50::/64");
    node = YAML::Node(nmg);
    YAML::Emitter e;
    e<<node;
    BOOST_CHECK_EQUAL(e.c_str(), R"(- "!192.0.2.1/32"
- 192.0.2.0/24
- 2001:db8:50::/64)");
    auto newNode = YAML::Load(e.c_str());
    auto newNMG = newNode.as<NetmaskGroup>();
    BOOST_CHECK(newNMG.match(ComboAddress("192.0.2.15")));
    BOOST_CHECK(!newNMG.match(ComboAddress("192.0.2.1")));
    BOOST_CHECK(newNMG.match(ComboAddress("2001:db8:50::1")));
    BOOST_CHECK(!newNMG.match(ComboAddress("2001:db8:51::1")));
}



BOOST_AUTO_TEST_SUITE_END()