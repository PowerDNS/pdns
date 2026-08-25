#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>

#include "dnsparser.hh"

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

BOOST_AUTO_TEST_CASE(test_compressionBudget)
{
  const std::vector<uint8_t> data = {
  0x37, 0xa5,
  0x84, 0x00, 0x00, 0x01, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00,
  0x02, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00,
  0x00, 0x14, 0x01, 0x61, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65,
  0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x00,
  0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x14, 0x01, 0x62, 0x0c,
  0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73,
  0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07,
  0xe9, 0x00, 0x00, 0x14, 0x01, 0x63, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d,
  0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00,
  0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x14, 0x01,
  0x64, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65,
  0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01,
  0x00, 0x07, 0xe9, 0x00, 0x00, 0x14, 0x01, 0x65, 0x0c, 0x72, 0x6f, 0x6f,
  0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65,
  0x74, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00,
  0x14, 0x01, 0x66, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72,
  0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x00, 0x02,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x14, 0x01, 0x67, 0x0c, 0x72,
  0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03,
  0x6e, 0x65, 0x74, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9,
  0x00, 0x00, 0x14, 0x01, 0x68, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73,
  0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00,
  0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x14, 0x01, 0x69,
  0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
  0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00,
  0x07, 0xe9, 0x00, 0x00, 0x14, 0x01, 0x6a, 0x0c, 0x72, 0x6f, 0x6f, 0x74,
  0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74,
  0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x14,
  0x01, 0x6b, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76,
  0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x00, 0x02, 0x00,
  0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x14, 0x01, 0x6c, 0x0c, 0x72, 0x6f,
  0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e,
  0x65, 0x74, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00,
  0x00, 0x14, 0x01, 0x6d, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65,
  0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x00,
  0x2e, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x01, 0x13, 0x00, 0x02, 0x08,
  0x00, 0x00, 0x07, 0xe9, 0x00, 0x6a, 0xbc, 0x97, 0x50, 0x6a, 0xab, 0x65,
  0xc0, 0xe1, 0xb4, 0x00, 0x06, 0x1c, 0xde, 0x4c, 0xe4, 0x37, 0xa9, 0x47,
  0xe4, 0xf5, 0x16, 0xfb, 0xb2, 0xd3, 0x8b, 0x2d, 0x96, 0xe5, 0xd3, 0x47,
  0x4b, 0xbe, 0xc1, 0x54, 0x05, 0xd6, 0x06, 0x23, 0xf0, 0x06, 0x8b, 0x25,
  0x01, 0x01, 0x74, 0x6a, 0xca, 0x5e, 0xc9, 0xef, 0x55, 0x2b, 0x97, 0x24,
  0x70, 0x0c, 0xd4, 0xc9, 0xe8, 0x93, 0x51, 0x65, 0xc0, 0xa6, 0xbf, 0x48,
  0xd8, 0xf7, 0xc5, 0xbf, 0xb5, 0xcd, 0xbe, 0x05, 0x77, 0x18, 0x45, 0xc0,
  0xbb, 0xf7, 0xe3, 0xdb, 0x6c, 0x27, 0x62, 0x73, 0xb6, 0xe7, 0x7e, 0xb7,
  0x94, 0xed, 0x7a, 0x77, 0x45, 0x9f, 0x42, 0x27, 0x0e, 0x40, 0x83, 0xe7,
  0x63, 0xcd, 0x61, 0xed, 0x1c, 0x46, 0x3c, 0x97, 0x52, 0x33, 0xbd, 0xb9,
  0xb4, 0x56, 0xe4, 0xe8, 0xb1, 0x7b, 0xeb, 0xe3, 0x9c, 0x05, 0xba, 0xcf,
  0xe0, 0x0a, 0x70, 0x1e, 0x5d, 0x1f, 0xb0, 0x84, 0xad, 0x8d, 0x53, 0x0d,
  0x9e, 0x8c, 0x33, 0x6e, 0xff, 0x37, 0x86, 0xd2, 0xf2, 0xd2, 0x1f, 0x7f,
  0x4e, 0xc9, 0xd7, 0x05, 0x8e, 0x6e, 0xcc, 0x47, 0x75, 0x36, 0x72, 0x23,
  0xee, 0xdb, 0x75, 0x28, 0x79, 0xd1, 0x37, 0x47, 0xdc, 0x6c, 0x78, 0xb5,
  0x92, 0x23, 0xb3, 0xaa, 0x86, 0x57, 0x53, 0x49, 0xa5, 0x36, 0xff, 0x97,
  0x0c, 0x7f, 0xda, 0xd2, 0x6e, 0xcd, 0x97, 0xf0, 0xbf, 0x44, 0x3b, 0x6e,
  0xec, 0xf0, 0x3d, 0x2b, 0xc5, 0x09, 0x7f, 0x7e, 0xc9, 0x5b, 0xe4, 0x29,
  0x5b, 0x1c, 0x84, 0xd0, 0x61, 0x6b, 0x57, 0x50, 0xc6, 0x95, 0x08, 0x22,
  0x2f, 0xad, 0x15, 0x94, 0x3a, 0xe9, 0x7b, 0x59, 0xcf, 0xf9, 0xf5, 0x67,
  0x6e, 0x01, 0x92, 0x76, 0x86, 0xdb, 0xc0, 0xd8, 0x0e, 0xdc, 0xfe, 0xd9,
  0x4d, 0xdc, 0xec, 0x6a, 0xfd, 0x11, 0xef, 0xff, 0xc9, 0xdc, 0x4b, 0x93,
  0x7d, 0x27, 0xfd, 0xc7, 0x7c, 0xfc, 0x2f, 0xa0, 0xc0, 0x1c, 0x00, 0x01,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04, 0xc6, 0x29, 0x00, 0x04,
  0xc0, 0x1c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x10,
  0x20, 0x01, 0x05, 0x03, 0xba, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x02, 0x00, 0x30, 0xc0, 0x3b, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07,
  0xe9, 0x00, 0x00, 0x04, 0xaa, 0xf7, 0xaa, 0x02, 0xc0, 0x3b, 0x00, 0x1c,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x10, 0x28, 0x01, 0x01, 0xb8,
  0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
  0xc0, 0x5a, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04,
  0xc0, 0x21, 0x04, 0x0c, 0xc0, 0x5a, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x07,
  0xe9, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x00, 0x02, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xc0, 0x79, 0x00, 0x01,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04, 0xc7, 0x07, 0x5b, 0x0d,
  0xc0, 0x79, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x10,
  0x20, 0x01, 0x05, 0x00, 0x00, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x0d, 0xc0, 0x98, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07,
  0xe9, 0x00, 0x00, 0x04, 0xc0, 0xcb, 0xe6, 0x0a, 0xc0, 0x98, 0x00, 0x1c,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00,
  0x00, 0xa8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
  0xc0, 0xb7, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04,
  0xc0, 0x05, 0x05, 0xf1, 0xc0, 0xb7, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x07,
  0xe9, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x00, 0x2f, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0xc0, 0xd6, 0x00, 0x01,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04, 0xc0, 0x70, 0x24, 0x04,
  0xc0, 0xd6, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x10,
  0x20, 0x01, 0x05, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x0d, 0x0d, 0xc0, 0xf5, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07,
  0xe9, 0x00, 0x00, 0x04, 0xc6, 0x61, 0xbe, 0x35, 0xc0, 0xf5, 0x00, 0x1c,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00,
  0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53,
  0xc1, 0x14, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04,
  0xc0, 0x24, 0x94, 0x11, 0xc1, 0x14, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x07,
  0xe9, 0x00, 0x00, 0x10, 0x20, 0x01, 0x07, 0xfe, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53, 0xc1, 0x33, 0x00, 0x01,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04, 0xc0, 0x3a, 0x80, 0x1e,
  0xc1, 0x33, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x10,
  0x20, 0x01, 0x05, 0x03, 0x0c, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x02, 0x00, 0x30, 0xc1, 0x52, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07,
  0xe9, 0x00, 0x00, 0x04, 0xc1, 0x00, 0x0e, 0x81, 0xc1, 0x52, 0x00, 0x1c,
  0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x10, 0x20, 0x01, 0x07, 0xfd,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
  0xc1, 0x71, 0x00, 0x01, 0x00, 0x01, 0x00, 0x07, 0xe9, 0x00, 0x00, 0x04,
  0xc7, 0x07, 0x53, 0x2a, 0x00, 0x00, 0x29, 0x04, 0xd0, 0x00, 0x00, 0x80,
  0x00, 0x00, 0x00, 0x00};

  const std::string packet(reinterpret_cast<const char*>(data.data()), data.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) it's the API
  MOADNSParser parser1(false, packet);
  BOOST_CHECK_EQUAL(parser1.d_answers.size(), 38U); // 38 auth/answer records, default budget is high
  BOOST_CHECK_NO_THROW(MOADNSParser(false, packet.data(), packet.size(), 23U)); // just enough
  BOOST_CHECK_THROW(MOADNSParser(false, packet.data(), packet.size(), 22U), MOADNSException);
}

BOOST_AUTO_TEST_SUITE_END()
