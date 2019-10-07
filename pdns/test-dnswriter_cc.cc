#define BOOST_TEST_DYN_LINK
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

BOOST_AUTO_TEST_SUITE_END()
