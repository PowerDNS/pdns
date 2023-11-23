#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>
#include <fstream>

#include "dnswriter.hh"
#include "dnsparser.hh"

BOOST_AUTO_TEST_SUITE(test_dnswriter_cc)

BOOST_AUTO_TEST_CASE(test_compressionBool) {
  auto testCompressionBool = [](bool compress, size_t size1, size_t size2) {
    DNSName name("powerdns.com.");

    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;

    pwR.startRecord(DNSName("mediumsizedlabel.example.net"), QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, compress);
    pwR.xfrIP('P'<<24 |
              'Q'<<16 |
              'R'<<8  |
              'S');
    pwR.commit();
    BOOST_CHECK_EQUAL(pwR.size(), size1);

    pwR.startRecord(DNSName("adifferentlabel.example.net"), QType::NS, 3600, QClass::IN, DNSResourceRecord::ANSWER, compress);
    pwR.xfrName(DNSName("target.example.net"), true);
    pwR.commit();
    BOOST_CHECK_EQUAL(pwR.size(), size2);

    string spacket(packet.begin(), packet.end());

    BOOST_CHECK_NO_THROW(MOADNSParser mdp(false, spacket));
  };

  testCompressionBool(true, 74, 111);
  testCompressionBool(false, 74, 133);
}

BOOST_AUTO_TEST_CASE(test_compressionBoundary) {
  DNSName name("powerdns.com.");

  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  /* record we want to see altered */
  pwR.startRecord(name, QType::TXT, 3600, QClass::IN, DNSResourceRecord::ANSWER);
  auto txt = string("\"")+string(16262, 'A')+string("\"");
  pwR.xfrText(txt);
  pwR.commit();
  BOOST_CHECK_EQUAL(pwR.size(), 16368U);

  pwR.startRecord(DNSName("mediumsizedlabel.example.net"), QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
  pwR.xfrIP('P'<<24 |
            'Q'<<16 |
            'R'<<8  |
            'S');
  pwR.commit();
  BOOST_CHECK_EQUAL(pwR.size(), 16412U); // 16412 (0x401c) puts '7example3net' at 0x4001

  pwR.startRecord(DNSName("adifferentlabel.example.net"), QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
  pwR.xfrIP('D'<<24 |
            'E'<<16 |
            'F'<<8  |
            'G');
  pwR.commit();
  BOOST_CHECK_EQUAL(pwR.size(), 16455U);

  string spacket(packet.begin(), packet.end());

  BOOST_CHECK_NO_THROW(MOADNSParser mdp(false, spacket));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_mandatory) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  set<string> keys({"alpn", "ipv6hint"});
  set<SvcParam> params({SvcParam(SvcParam::mandatory, std::move(keys))});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({0,0,0,4,0,1,0,6}));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_alpn) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  vector<string> alpns({"h2", "h2c", "h3"});
  set<SvcParam> params({SvcParam(SvcParam::alpn, std::move(alpns))});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({
    0,1,0,10,
    2,'h','2',
    3,'h','2','c',
    2,'h','3'}));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_no_default_alpn) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  set<SvcParam> params({SvcParam(SvcParam::no_default_alpn)});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({0,2,0,0}));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_port) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  set<SvcParam> params({SvcParam(SvcParam::port, 53)});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({0,3,0,2,0,53}));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_ipv4hint) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  vector<ComboAddress> addrs({ComboAddress("192.0.2.1"), ComboAddress("192.0.2.2")});
  set<SvcParam> params({SvcParam(SvcParam::ipv4hint, std::move(addrs))});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({0,4,0,8,192,0,2,1,192,0,2,2}));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_ech) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  set<SvcParam> params({SvcParam(SvcParam::ech, "a very bogus echconfig value")});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({0,5,0,28,
  'a',' ','v','e','r','y',' ','b','o','g','u','s',' ',
  'e','c','h','c','o','n','f','i','g',' ','v','a','l','u','e'
  }));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_ipv6hint) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  vector<ComboAddress> addrs({ComboAddress("2001:db8::1"), ComboAddress("2001:db8::2")});
  set<SvcParam> params({SvcParam(SvcParam::ipv6hint, std::move(addrs))});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({0,6,0,32,
  32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,
  32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2}));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_generic) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  set<SvcParam> params({SvcParam(SvcParam::keyFromString("key666"), "mycoolvalue")});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({2,154,0,11,
  'm','y','c','o','o','l','v','a','l','u','e'
  }));
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_multiple) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;
  DNSPacketWriter pwR(packet, name, QType::SVCB, QClass::IN, 0);
  pwR.getHeader()->qr = 1;

  vector<ComboAddress> addrs({ComboAddress("2001:db8::1"), ComboAddress("2001:db8::2")});
  vector<string> alpns({"h2", "h2c", "h3"});
  set<SvcParam> params({SvcParam(SvcParam::alpn, std::move(alpns)), SvcParam(SvcParam::ipv6hint, std::move(addrs)), SvcParam(SvcParam::port, 53)});

  pwR.startRecord(name, QType::SVCB);
  pwR.commit();
  auto start = pwR.getContent().size();

  pwR.xfrSvcParamKeyVals(params);
  pwR.commit();
  auto cit = pwR.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, pwR.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({
  0,1,0,10,2,'h','2',3,'h','2','c',2,'h','3',  // alpn
  0,3,0,2,0,53,                                // port    
  0,6,0,32,                                    // ipv6
  32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,1,
  32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,2}));
}

BOOST_AUTO_TEST_CASE(test_NodeOrLocatorID) {
  DNSName name("powerdns.com.");
  vector<uint8_t> packet;

  NodeOrLocatorID in = {0, 0, 0, 0, 0, 0, 0, 1};

  DNSPacketWriter writer(packet, name, QType::NID, QClass::IN, 0);
  writer.getHeader()->qr = 1;

  writer.startRecord(name, QType::NID);
  writer.commit();
  auto start = writer.getContent().size();

  writer.xfrNodeOrLocatorID(in);
  writer.commit();
  auto cit = writer.getContent().begin();
  for (size_t i = 0; i<start; i++)
    cit++;

  vector<uint8_t> c(cit, writer.getContent().end());
  BOOST_CHECK(c == vector<uint8_t>({
    0, 0, 0, 0,
    0, 0, 0, 1}));
}

BOOST_AUTO_TEST_SUITE_END()
