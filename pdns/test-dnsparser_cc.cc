#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>

#include "dnsparser.hh"
#include "dnswriter.hh"
#include "svc-records.hh"

BOOST_AUTO_TEST_SUITE(test_dnsparser_cc)

BOOST_AUTO_TEST_CASE(test_editDNSPacketTTL) {

  auto generatePacket = [](uint32_t ttl) {
    DNSName name("powerdns.com.");
    ComboAddress v4("1.2.3.4");
    ComboAddress v6("2001:db8::1");

    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;

    /* record we want to see altered */
    pwR.startRecord(name, QType::A, ttl, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    /* same record but different TTL (yeah, don't do that but it's just a test) */
    pwR.startRecord(name, QType::A, 100, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    /* different type */
    pwR.startRecord(name, QType::AAAA, 42, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP6(std::string(reinterpret_cast<const char*>(v6.sin6.sin6_addr.s6_addr), 16));
    pwR.commit();

    /* different class */
    pwR.startRecord(name, QType::A, 42, QClass::CHAOS, DNSResourceRecord::ANSWER);
    pwR.commit();

    /* different section */
    pwR.startRecord(name, QType::A, 42, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    return packet;
  };

  auto firstPacket = generatePacket(42);
  auto expectedAlteredPacket = generatePacket(84);

  size_t called = 0;
  editDNSPacketTTL(reinterpret_cast<char*>(firstPacket.data()), firstPacket.size(), [&called](uint8_t section, uint16_t class_, uint16_t type, uint32_t ttl) {

      called++;

      /* only updates the TTL of IN/A, in answer, with an existing ttl of 42 */
      if (section == 1 && class_ == QClass::IN && type == QType::A && ttl == 42) {
        return 84;
      }
      return 0;
    });

  /* check that we have been for all records */
  BOOST_CHECK_EQUAL(called, 5U);

  BOOST_REQUIRE_EQUAL(firstPacket.size(), expectedAlteredPacket.size());
  for (size_t idx = 0; idx < firstPacket.size(); idx++) {
    BOOST_CHECK_EQUAL(firstPacket.at(idx), expectedAlteredPacket.at(idx));
  }
  BOOST_CHECK(firstPacket == expectedAlteredPacket);

  /* now call it with a truncated packet, missing the last TTL and rdata,
     we should only be called 4 times but everything else should be fine. */
  called = 0;
  editDNSPacketTTL(reinterpret_cast<char*>(firstPacket.data()), firstPacket.size() - sizeof(uint32_t) - /* rdata length */ sizeof (uint16_t) - /* IPv4 payload in rdata */ 4, [&called](uint8_t section, uint16_t class_, uint16_t type, uint32_t ttl) {

      called++;

      /* only updates the TTL of IN/A, in answer, with an existing ttl of 42 */
      if (section == 1 && class_ == QClass::IN && type == QType::A && ttl == 42) {
        return 84;
      }
      return 0;
    });

  /* check that we have been for all records */
  BOOST_CHECK_EQUAL(called, 4U);
  BOOST_CHECK(firstPacket == expectedAlteredPacket);
}

BOOST_AUTO_TEST_CASE(test_ageDNSPacket) {

  auto generatePacket = [](uint32_t ttl) {
    DNSName name("powerdns.com.");
    ComboAddress v4("1.2.3.4");
    ComboAddress v6("2001:db8::1");

    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;

    /* record we want to see altered */
    pwR.startRecord(name, QType::A, ttl, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    return packet;
  };

  auto firstPacket = generatePacket(3600);
  auto expectedAlteredPacket = generatePacket(1800);

  dnsheader_aligned dh_aligned(firstPacket.data());
  ageDNSPacket(reinterpret_cast<char*>(firstPacket.data()), firstPacket.size(), 1800, dh_aligned);

  BOOST_REQUIRE_EQUAL(firstPacket.size(), expectedAlteredPacket.size());
  for (size_t idx = 0; idx < firstPacket.size(); idx++) {
    BOOST_CHECK_EQUAL(firstPacket.at(idx), expectedAlteredPacket.at(idx));
  }
  BOOST_CHECK(firstPacket == expectedAlteredPacket);

  /* now call it with a truncated packet, missing the last TTL and rdata,
     the packet should not be altered. */
  ageDNSPacket(reinterpret_cast<char*>(firstPacket.data()), firstPacket.size() - sizeof(uint32_t) - /* rdata length */ sizeof (uint16_t) - /* IPv4 payload in rdata */ 4 - /* size of OPT record */ 11, 900, dh_aligned);

  BOOST_CHECK(firstPacket == expectedAlteredPacket);

  /* now remove more than the remaining TTL. We expect ageDNSPacket
     to cap this at zero and not cause an unsigned underflow into
     the 2^32-1 neighbourhood */
  ageDNSPacket(reinterpret_cast<char*>(firstPacket.data()), firstPacket.size(), 1801, dh_aligned);

  uint32_t ttl = 0;

  expectedAlteredPacket = generatePacket(ttl);
  BOOST_REQUIRE_EQUAL(firstPacket.size(), expectedAlteredPacket.size());
  for (size_t idx = 0; idx < firstPacket.size(); idx++) {
    BOOST_CHECK_EQUAL(firstPacket.at(idx), expectedAlteredPacket.at(idx));
  }
  BOOST_CHECK(firstPacket == expectedAlteredPacket);
}

BOOST_AUTO_TEST_CASE(test_getDNSPacketMinTTL) {

  const DNSName name("powerdns.com.");
  const ComboAddress v4("1.2.3.4");
  const ComboAddress v6("2001:db8::1");

  {
    /* no records */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), nullptr);
    BOOST_CHECK_EQUAL(result, std::numeric_limits<uint32_t>::max());
  }

  {
    /* only one record, not an OPT one */
    uint32_t ttl = 42;
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, ttl, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), nullptr);
    BOOST_CHECK_EQUAL(result, ttl);
  }

  {
    /* only one record, an OPT one */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), nullptr);
    BOOST_CHECK_EQUAL(result, std::numeric_limits<uint32_t>::max());
  }

  {
    /* records with different TTLs, should return the lower */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 257, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), nullptr);
    BOOST_CHECK_EQUAL(result, 255U);
  }

  {
    /* SOA record in answer, seenAuthSOA should not be set */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 257, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.commit();

    pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    bool seenAuthSOA = false;
    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), &seenAuthSOA);
    BOOST_CHECK_EQUAL(result, 255U);
    BOOST_CHECK_EQUAL(seenAuthSOA, false);
  }

  {
    /* one SOA record in auth, seenAuthSOA should be set */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 257, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();

    pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    bool seenAuthSOA = false;
    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), &seenAuthSOA);
    BOOST_CHECK_EQUAL(result, 255U);
    BOOST_CHECK_EQUAL(seenAuthSOA, true);
  }

  {
    /* one SOA record of the wrong qclass in auth, seenAuthSOA should not be set */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 257, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 255, QClass::CHAOS, DNSResourceRecord::AUTHORITY);
    pwR.commit();

    pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    bool seenAuthSOA = false;
    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), &seenAuthSOA);
    BOOST_CHECK_EQUAL(result, 255U);
    BOOST_CHECK_EQUAL(seenAuthSOA, false);
  }

  {
    /* one A record in auth, seenAuthSOA should not be set */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 257, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    bool seenAuthSOA = false;
    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), &seenAuthSOA);
    BOOST_CHECK_EQUAL(result, 257U);
    BOOST_CHECK_EQUAL(seenAuthSOA, false);
  }

  {
    /* one SOA record in additional, seenAuthSOA should not be set */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 255, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.commit();

    bool seenAuthSOA = false;
    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size(), &seenAuthSOA);
    BOOST_CHECK_EQUAL(result, 255U);
    BOOST_CHECK_EQUAL(seenAuthSOA, false);
  }

  {
    /* truncated packet, no exception should be raised */
    /* one SOA record in auth, seenAuthSOA should be set */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 257, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();

    pwR.startRecord(name, QType::A, 254, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    bool seenAuthSOA = false;
    auto result = getDNSPacketMinTTL(reinterpret_cast<char*>(packet.data()), packet.size() - sizeof(uint32_t) - /* rdata length */ sizeof (uint16_t) - /* IPv4 payload in rdata */ 4, &seenAuthSOA);
    BOOST_CHECK_EQUAL(result, 255U);
    BOOST_CHECK_EQUAL(seenAuthSOA, true);
  }
}

BOOST_AUTO_TEST_CASE(test_getDNSPacketLength) {

  const DNSName name("powerdns.com.");
  const ComboAddress v4("1.2.3.4");
  const ComboAddress v6("2001:db8::1");

  {
    /* no records */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    auto result = getDNSPacketLength(reinterpret_cast<char*>(packet.data()), packet.size());
    BOOST_CHECK_EQUAL(result, packet.size());
  }

  {
    /* several records */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 257, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();

    pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    auto result = getDNSPacketLength(reinterpret_cast<char*>(packet.data()), packet.size());
    BOOST_CHECK_EQUAL(result, packet.size());
  }

  {
    /* trailing data */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 257, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();

    pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    auto realSize = packet.size();
    packet.resize(realSize + 512);
    auto result = getDNSPacketLength(reinterpret_cast<char*>(packet.data()), packet.size());
    BOOST_CHECK_EQUAL(result, realSize);
  }

  {
    /* truncated packet, should return the full size */
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 257, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();

    pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    size_t fakeSize = packet.size()-1;
    auto result = getDNSPacketLength(reinterpret_cast<char*>(packet.data()), fakeSize);
    BOOST_CHECK_EQUAL(result, fakeSize);
  }

}

BOOST_AUTO_TEST_CASE(test_getRecordsOfTypeCount) {
  const DNSName name("powerdns.com.");
  const ComboAddress v4("1.2.3.4");
  const ComboAddress v6("2001:db8::1");

  {
    vector<uint8_t> packet;
    DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.commit();

    pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.startRecord(name, QType::SOA, 257, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();

    pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
    pwR.xfrIP(v4.sin4.sin_addr.s_addr);
    pwR.commit();

    pwR.addOpt(4096, 0, 0);
    pwR.commit();

     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 0, QType::A), 1);
     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 0, QType::SOA), 0);
     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 1);
     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::SOA), 0);
     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 2, QType::A), 0);
     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 2, QType::SOA), 1);
     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 1);
     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::SOA), 0);

     BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 4, QType::SOA), 0);
  }

}

BOOST_AUTO_TEST_CASE(test_clearDNSPacketRecordTypes) {
  {
    auto generatePacket = []() {
      const DNSName name("powerdns.com.");
      const ComboAddress v4("1.2.3.4");
      const ComboAddress v6("2001:db8::1");

      vector<uint8_t> packet;
      DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
      pwR.getHeader()->qr = 1;
      pwR.commit();

      pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfrIP(v4.sin4.sin_addr.s_addr);
      pwR.commit();

      /* different type */
      pwR.startRecord(name, QType::AAAA, 42, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfrIP6(std::string(reinterpret_cast<const char*>(v6.sin6.sin6_addr.s6_addr), 16));
      pwR.commit();

      pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
      pwR.xfrIP(v4.sin4.sin_addr.s_addr);
      pwR.commit();

      pwR.addOpt(4096, 0, 0);
      pwR.commit();
      return packet;
    };

    auto packet = generatePacket();

    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::AAAA), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 1);

    std::unordered_set<QType> toremove{QType::AAAA};
    clearDNSPacketRecordTypes(packet, toremove);

    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::AAAA), 0);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 1);

    toremove = {QType::A};
    clearDNSPacketRecordTypes(packet, toremove);

    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 0);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::AAAA), 0);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 0);

    packet = generatePacket();

    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::AAAA), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 1);

    toremove = {QType::A, QType::AAAA};
    clearDNSPacketRecordTypes(packet, toremove);

    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 0);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::AAAA), 0);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 0);
  }

}

BOOST_AUTO_TEST_CASE(test_clearDNSPacketUnsafeRecordTypes) {
  {
    auto generatePacket = []() {
      const DNSName name("powerdns.com.");
      const DNSName mxname("mx.powerdns.com.");
      const ComboAddress v4("1.2.3.4");
      const ComboAddress v6("2001:db8::1");

      vector<uint8_t> packet;
      DNSPacketWriter pwR(packet, name, QType::A, QClass::IN, 0);
      pwR.getHeader()->qr = 1;
      pwR.commit();

      pwR.startRecord(name, QType::A, 255, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfrIP(v4.sin4.sin_addr.s_addr);
      pwR.commit();

      /* different type */
      pwR.startRecord(name, QType::AAAA, 42, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfrIP6(std::string(reinterpret_cast<const char*>(v6.sin6.sin6_addr.s6_addr), 16));
      pwR.commit();

      pwR.startRecord(name, QType::A, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
      pwR.xfrIP(v4.sin4.sin_addr.s_addr);
      pwR.commit();

      pwR.startRecord(name, QType::MX, 256, QClass::IN, DNSResourceRecord::ADDITIONAL);
      pwR.xfrName(mxname, false);
      pwR.commit();

      pwR.addOpt(4096, 0, 0);
      pwR.commit();
      return packet;
    };

    auto packet = generatePacket();

    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::AAAA), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::MX), 1);

    std::unordered_set<QType> toremove{QType::AAAA};
    clearDNSPacketRecordTypes(packet, toremove);

    // nothing should have been removed as an "unsafe" MX RR is in the packet
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::AAAA), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::MX), 1);

    toremove = {QType::MX, QType::AAAA};
    clearDNSPacketRecordTypes(packet, toremove);

    // MX is unsafe, but we asked to remove it
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 1, QType::AAAA), 0);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::A), 1);
    BOOST_CHECK_EQUAL(getRecordsOfTypeCount(reinterpret_cast<char*>(packet.data()), packet.size(), 3, QType::MX), 0);
  }

}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_alpn_length_wrong) {
  vector<uint8_t> fakePacket {
    0x00, 0x01, // Key 1 (ALPN)
    0x00, 0x04, // length 3
    0x01,           // ALPN length, too short
                        // This means '2' is the length for the next ALPN
    'h', '2'
  };

  PacketReader pr(std::string_view(reinterpret_cast<const char*>(fakePacket.data()), fakePacket.size()), 0);

  std::set<SvcParam> svcParams;

  BOOST_CHECK_THROW(pr.xfrSvcParamKeyVals(svcParams), std::out_of_range);

  fakePacket = {
    0x00, 0x01, // Key 1 (ALPN)
    0x00, 0x03, // length 3
    0x03,           // ALPN length 3 (too long, i.e. after end of SVC Params)
    'h', '2'
  };

  BOOST_CHECK_THROW(pr.xfrSvcParamKeyVals(svcParams), std::out_of_range);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_multiple) {
  vector<uint8_t> fakePacket {
    0x00, 0x01, // Key 1 (ALPN)
    0x00, 0x03, // length 3
    0x02,           // ALPN length 2
    'h', '2',

    // A (forbidden) second ALPN
    0x00, 0x01, // Key 1 (ALPN)
    0x00, 0x03, // length 3
    0x02,           // ALPN length 2
    'h', '3'
  };

  PacketReader pr(std::string_view(reinterpret_cast<const char*>(fakePacket.data()), fakePacket.size()), 0);

  std::set<SvcParam> svcParams;

  BOOST_CHECK_THROW(pr.xfrSvcParamKeyVals(svcParams), std::out_of_range);
}

BOOST_AUTO_TEST_CASE(test_xfrSvcParamKeyVals_bad_ordering) {
  vector<uint8_t> fakePacket {
    0x00, 0x04, // Key 4 (IPv4 Hint)
    0x04,           // length 4 (1 address)
    192, 168,
    0, 1,

    0x00, 0x01,  // Key 1 (ALPN)
    0x00, 0x03, // length 3
    0x02,           // ALPN length 2
    'h', '2',
  };

  PacketReader pr(std::string_view(reinterpret_cast<const char*>(fakePacket.data()), fakePacket.size()), 0);

  std::set<SvcParam> svcParams;

  BOOST_CHECK_THROW(pr.xfrSvcParamKeyVals(svcParams), std::out_of_range);
}

BOOST_AUTO_TEST_SUITE_END()
