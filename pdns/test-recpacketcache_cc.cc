#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "recpacketcache.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "dns_random.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "iputils.hh"
#include <utility>

struct EDNSCookiesOpt
{
  string client;
  string server;
};

static string makeEDNSCookiesOptString(const EDNSCookiesOpt& eco)
{
  string ret;
  if (eco.client.length() != 8)
    return ret;
  if (eco.server.length() != 0 && (eco.server.length() < 8 || eco.server.length() > 32))
    return ret;
  ret.assign(eco.client);
  if (eco.server.length() != 0)
    ret.append(eco.server);
  return ret;
}

BOOST_AUTO_TEST_SUITE(recpacketcache_cc)

BOOST_AUTO_TEST_CASE(test_recPacketCacheSimple) {
  RecursorPacketCache rpc;
  BOOST_CHECK_EQUAL(rpc.size(), 0);

  DNSName qname("www.powerdns.com");
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qname, QType::A);
  pw.getHeader()->rd=true;
  pw.getHeader()->qr=false;
  pw.getHeader()->id=random();
  string qpacket((const char*)&packet[0], packet.size());
  pw.startRecord(qname, QType::A, 3600);

  ARecordContent ar("127.0.0.1");
  ar.toPacket(pw);
  pw.commit();
  string rpacket((const char*)&packet[0], packet.size());

  rpc.insertResponsePacket(0,qname, QType::A, QClass::IN, qpacket, rpacket, time(0), 3600, nullptr);
  BOOST_CHECK_EQUAL(rpc.size(), 1);
  rpc.doPruneTo(0);
  BOOST_CHECK_EQUAL(rpc.size(), 0);
  rpc.insertResponsePacket(0,qname, QType::A, QClass::IN, qpacket, rpacket, time(0), 3600, nullptr);
  BOOST_CHECK_EQUAL(rpc.size(), 1);
  rpc.doWipePacketCache(qname);
  BOOST_CHECK_EQUAL(rpc.size(), 0);

  rpc.insertResponsePacket(0,qname, QType::A, QClass::IN, qpacket, rpacket, time(0), 3600, nullptr);
  uint32_t age=0;
  string fpacket;
  bool found = rpc.getResponsePacket(0, qpacket, time(0), &fpacket, &age, nullptr);
  BOOST_CHECK_EQUAL(found, 1);
  BOOST_CHECK_EQUAL(fpacket, rpacket);

  packet.clear();
  qname+=DNSName("co.uk");
  DNSPacketWriter pw2(packet, qname, QType::A);

  pw2.getHeader()->rd=true;
  pw2.getHeader()->qr=false;
  pw2.getHeader()->id=random();
  qpacket.assign((const char*)&packet[0], packet.size());
  found = rpc.getResponsePacket(0, qpacket, time(0), &fpacket, &age, nullptr);
  BOOST_CHECK_EQUAL(found, 0);

  rpc.doWipePacketCache(DNSName("com"), 0xffff, true);
  BOOST_CHECK_EQUAL(rpc.size(), 0);



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
    auto hash1 = RecursorPacketCache::canHashPacket(spacket1, &ecsBegin, &ecsEnd);
    /* no ECS */
    BOOST_CHECK_EQUAL(ecsBegin, 0);
    BOOST_CHECK_EQUAL(ecsEnd, 0);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = RecursorPacketCache::canHashPacket(spacket2, &ecsBegin, &ecsEnd);
    /* no ECS */
    BOOST_CHECK_EQUAL(ecsBegin, 0);
    BOOST_CHECK_EQUAL(ecsEnd, 0);

    BOOST_CHECK_EQUAL(hash1, hash2);
    BOOST_CHECK(RecursorPacketCache::queryMatches(spacket1, spacket2, qname, ecsBegin, ecsEnd));
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
    auto hash1 = RecursorPacketCache::canHashPacket(spacket1, &ecsBegin, &ecsEnd);
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
    auto hash2 = RecursorPacketCache::canHashPacket(spacket2, &ecsBegin, &ecsEnd);
    /* ECS value */
    BOOST_CHECK_EQUAL(ecsBegin, sizeof(dnsheader) + qname.wirelength() + ( 2 * sizeof(uint16_t)) /* qtype */ + (2 * sizeof(uint16_t)) /* qclass */ + /* OPT root label */ 1 + sizeof(uint32_t) /* TTL */ + DNS_RDLENGTH_SIZE);
    BOOST_CHECK_EQUAL(ecsEnd, ecsBegin + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + 2 /* family */ + 1 /* scope length */ + 1 /* source length */ + 4 /* IPv4 */);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same and we don't hash the ECS so we should match */
    BOOST_CHECK(RecursorPacketCache::queryMatches(spacket1, spacket2, qname, ecsBegin, ecsEnd));
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
    auto hash1 = RecursorPacketCache::canHashPacket(spacket1, &ecsBegin, &ecsEnd);
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
    auto hash2 = RecursorPacketCache::canHashPacket(spacket2, &ecsBegin, &ecsEnd);
    /* ECS value */
    BOOST_CHECK_EQUAL(ecsBegin, sizeof(dnsheader) + qname.wirelength() + ( 2 * sizeof(uint16_t)) /* qtype */ + (2 * sizeof(uint16_t)) /* qclass */ + /* OPT root label */ 1 + sizeof(uint32_t) /* TTL */ + DNS_RDLENGTH_SIZE);
    BOOST_CHECK_EQUAL(ecsEnd, ecsBegin + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + 2 /* family */ + 1 /* scope length */ + 1 /* source length */ + 4 /* IPv4 */);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match, even though we skip the ECS part, because the cookies are different */
    BOOST_CHECK(!RecursorPacketCache::queryMatches(spacket1, spacket2, qname, ecsBegin, ecsEnd));
  }
}

BOOST_AUTO_TEST_SUITE_END()
