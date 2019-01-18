#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "ednscookies.hh"
#include "ednssubnet.hh"
#include "packetcache.hh"

BOOST_AUTO_TEST_SUITE(packetcache_hh)

BOOST_AUTO_TEST_CASE(test_PacketCacheAuthCollision) {

  /* auth version (ECS is not processed, we just hash the whole query except for the ID, while lowercasing the qname) */
  const DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  EDNSSubnetOpts opt;
  DNSPacketWriter::optvect_t ednsOptions;

  {
    /* same query, different IDs */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2);

    BOOST_CHECK_EQUAL(hash1, hash2);
    BOOST_CHECK(PacketCache::queryMatches(spacket1, spacket2, qname));
  }

  {
    /* same query, different IDs, different ECS, still hashes to the same value */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    opt.source = Netmask("10.0.18.199/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pw1.addOpt(512, 0, 0, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("10.0.131.66/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pw2.addOpt(512, 0, 0, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match */
    BOOST_CHECK(!PacketCache::queryMatches(spacket1, spacket2, qname));
  }

  {
    /* same query but one has DNSSECOK, not the other, different IDs, different ECS, still hashes to the same value */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    opt.source = Netmask("47.8.0.0/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pw1.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("18.43.1.0/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    /* no EDNSOpts::DNSSECOK !! */
    pw2.addOpt(512, 0, 0, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match */
    BOOST_CHECK(!PacketCache::queryMatches(spacket1, spacket2, qname));
  }

  {
    /* same query but different cookies, still hashes to the same value */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    opt.source = Netmask("192.0.2.1/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    EDNSCookiesOpt cookiesOpt;
    cookiesOpt.client = string("deadbeef");
    cookiesOpt.server = string("deadbeef");
    cookiesOpt.server[4] = -42;
    cookiesOpt.server[5] = -6;
    cookiesOpt.server[6] = 1;
    cookiesOpt.server[7] = 0;
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)));
    pw1.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("192.0.2.1/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    cookiesOpt.client = string("deadbeef");
    cookiesOpt.server = string("deadbeef");
    cookiesOpt.server[4] = 29;
    cookiesOpt.server[5] = -79;
    cookiesOpt.server[6] = 1;
    cookiesOpt.server[7] = 0;
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)));
    pw2.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match */
    BOOST_CHECK(!PacketCache::queryMatches(spacket1, spacket2, qname));
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheRecSimple) {

  const DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  EDNSSubnetOpts opt;
  DNSPacketWriter::optvect_t ednsOptions;
  uint16_t ecsBegin;
  uint16_t ecsEnd;

  {
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    pw1.addOpt(512, 0, 0);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    /* set the RD length to a large value */
    unsigned char* ptr = reinterpret_cast<unsigned char*>(&spacket1.at(sizeof(dnsheader) + qname.wirelength() + /* qtype and qclass */ 4 + /* OPT root label (1), type (2), class (2) and ttl (4) */ 9));
    *ptr = 255;
    *(ptr + 1) = 255;
    /* truncate the end of the OPT header to try to trigger an out of bounds read */
    spacket1.resize(spacket1.size() - 6);
    PacketCache::canHashPacket(spacket1, &ecsBegin, &ecsEnd);
    /* no ECS */
    BOOST_CHECK_EQUAL(ecsBegin, 0);
    BOOST_CHECK_EQUAL(ecsEnd, 0);
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheRecCollision) {

  /* rec version (ECS is processed, we hash the whole query except for the ID and the ECS value, while lowercasing the qname) */
  const DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  EDNSSubnetOpts opt;
  DNSPacketWriter::optvect_t ednsOptions;
  uint16_t ecsBegin;
  uint16_t ecsEnd;

  {
    /* same query, different IDs */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, &ecsBegin, &ecsEnd);
    /* no ECS */
    BOOST_CHECK_EQUAL(ecsBegin, 0);
    BOOST_CHECK_EQUAL(ecsEnd, 0);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, &ecsBegin, &ecsEnd);
    /* no ECS */
    BOOST_CHECK_EQUAL(ecsBegin, 0);
    BOOST_CHECK_EQUAL(ecsEnd, 0);

    BOOST_CHECK_EQUAL(hash1, hash2);
    BOOST_CHECK(PacketCache::queryMatches(spacket1, spacket2, qname, ecsBegin, ecsEnd));
  }

  {
    /* same query, different IDs, different ECS, still hashes to the same value */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    opt.source = Netmask("10.0.18.199/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pw1.addOpt(512, 0, 0, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, &ecsBegin, &ecsEnd);
    /* ECS value */
    BOOST_CHECK_EQUAL(ecsBegin, sizeof(dnsheader) + qname.wirelength() + ( 2 * sizeof(uint16_t)) /* qtype */ + (2 * sizeof(uint16_t)) /* qclass */ + /* OPT root label */ 1 + sizeof(uint32_t) /* TTL */ + DNS_RDLENGTH_SIZE);
    BOOST_CHECK_EQUAL(ecsEnd, ecsBegin + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + 2 /* family */ + 1 /* scope length */ + 1 /* source length */ + 4 /* IPv4 */);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("10.0.131.66/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pw2.addOpt(512, 0, 0, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, &ecsBegin, &ecsEnd);
    /* ECS value */
    BOOST_CHECK_EQUAL(ecsBegin, sizeof(dnsheader) + qname.wirelength() + ( 2 * sizeof(uint16_t)) /* qtype */ + (2 * sizeof(uint16_t)) /* qclass */ + /* OPT root label */ 1 + sizeof(uint32_t) /* TTL */ + DNS_RDLENGTH_SIZE);
    BOOST_CHECK_EQUAL(ecsEnd, ecsBegin + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + 2 /* family */ + 1 /* scope length */ + 1 /* source length */ + 4 /* IPv4 */);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same and we don't hash the ECS so we should match */
    BOOST_CHECK(PacketCache::queryMatches(spacket1, spacket2, qname, ecsBegin, ecsEnd));
  }

  {
    /* same query but different cookies, still hashes to the same value */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    opt.source = Netmask("192.0.2.1/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    EDNSCookiesOpt cookiesOpt;
    cookiesOpt.client = string("deadbeef");
    cookiesOpt.server = string("deadbeef");
    cookiesOpt.server[4] = -20;
    cookiesOpt.server[5] = -114;
    cookiesOpt.server[6] = 0;
    cookiesOpt.server[7] = 0;
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)));
    pw1.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, &ecsBegin, &ecsEnd);
    /* ECS value */
    BOOST_CHECK_EQUAL(ecsBegin, sizeof(dnsheader) + qname.wirelength() + ( 2 * sizeof(uint16_t)) /* qtype */ + (2 * sizeof(uint16_t)) /* qclass */ + /* OPT root label */ 1 + sizeof(uint32_t) /* TTL */ + DNS_RDLENGTH_SIZE);
    BOOST_CHECK_EQUAL(ecsEnd, ecsBegin + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + 2 /* family */ + 1 /* scope length */ + 1 /* source length */ + 4 /* IPv4 */);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("192.0.2.1/32");
    ednsOptions.clear();
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    cookiesOpt.client = string("deadbeef");
    cookiesOpt.server = string("deadbeef");
    cookiesOpt.server[4] = 103;
    cookiesOpt.server[5] = 68;
    cookiesOpt.server[6] = 0;
    cookiesOpt.server[7] = 0;
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::COOKIE, makeEDNSCookiesOptString(cookiesOpt)));
    pw2.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, &ecsBegin, &ecsEnd);
    /* ECS value */
    BOOST_CHECK_EQUAL(ecsBegin, sizeof(dnsheader) + qname.wirelength() + ( 2 * sizeof(uint16_t)) /* qtype */ + (2 * sizeof(uint16_t)) /* qclass */ + /* OPT root label */ 1 + sizeof(uint32_t) /* TTL */ + DNS_RDLENGTH_SIZE);
    BOOST_CHECK_EQUAL(ecsEnd, ecsBegin + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + 2 /* family */ + 1 /* scope length */ + 1 /* source length */ + 4 /* IPv4 */);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match, even though we skip the ECS part, because the cookies are different */
    BOOST_CHECK(!PacketCache::queryMatches(spacket1, spacket2, qname, ecsBegin, ecsEnd));
  }
}

BOOST_AUTO_TEST_SUITE_END()
