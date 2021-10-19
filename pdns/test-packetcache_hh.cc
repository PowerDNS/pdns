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
  static const std::unordered_set<uint16_t> optionsToSkip{ EDNSOptionCode::COOKIE };
  static const std::unordered_set<uint16_t> noOptionsToSkip{ };

  {
    /* same query, different IDs */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, optionsToSkip);

    BOOST_CHECK_EQUAL(hash1, hash2);
    BOOST_CHECK(PacketCache::queryMatches(spacket1, spacket2, qname, optionsToSkip));
  }

  {
    /* same query, different IDs, different ECS, still hashes to the same value */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    opt.source = Netmask("10.0.152.74/32");
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    pw1.addOpt(512, 0, 0, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("10.2.70.250/32");
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    pw2.addOpt(512, 0, 0, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, optionsToSkip);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match */
    BOOST_CHECK(!PacketCache::queryMatches(spacket1, spacket2, qname, optionsToSkip));

#if 0
    /* to be able to compute a new collision if the hashing function is updated */
    {
    std::map<uint32_t, Netmask> colMap;
    size_t collisions = 0;
    size_t total = 0;

    for (size_t idxA = 0; idxA < 256; idxA++) {
      for (size_t idxB = 0; idxB < 256; idxB++) {
        for (size_t idxC = 0; idxC < 256; idxC++) {
          vector<uint8_t> secondQuery;
          DNSPacketWriter pwFQ(secondQuery, qname, QType::AAAA, QClass::IN, 0);
          pwFQ.getHeader()->rd = 1;
          pwFQ.getHeader()->qr = false;
          pwFQ.getHeader()->id = 0x42;
          opt.source = Netmask("10." + std::to_string(idxA) + "." + std::to_string(idxB) + "." + std::to_string(idxC) + "/32");
          ednsOptions.clear();
          ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
          pwFQ.addOpt(512, 0, 0, ednsOptions);
          pwFQ.commit();
          auto secondKey = PacketCache::canHashPacket(std::string(reinterpret_cast<const char *>(secondQuery.data()), secondQuery.size()), optionsToSkip);
          auto pair = colMap.emplace(secondKey, opt.source);
          total++;
          if (!pair.second) {
            collisions++;
            cerr<<"Collision between "<<colMap[secondKey].toString()<<" and "<<opt.source.toString()<<" for key "<<secondKey<<endl;
            goto done1;
          }
        }
      }
    }
  done1:
    cerr<<"collisions: "<<collisions<<endl;
    cerr<<"total: "<<total<<endl;
    }
#endif
  }

  {
    /* same query but one has DNSSECOK, not the other, different IDs, different ECS, still hashes to the same value */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    opt.source = Netmask("10.0.34.159/32");
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    pw1.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("10.0.179.58/32");
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    /* no EDNSOpts::DNSSECOK !! */
    pw2.addOpt(512, 0, 0, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, optionsToSkip);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match */
    BOOST_CHECK(!PacketCache::queryMatches(spacket1, spacket2, qname, optionsToSkip));
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
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    EDNSCookiesOpt cookiesOpt(string("deadbeefdeadbeef"));
    ednsOptions.emplace_back(EDNSOptionCode::COOKIE, cookiesOpt.makeOptString());
    pw1.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("192.0.2.1/32");
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    cookiesOpt.makeFromString(string("deadbeefbadc0fee"));
    ednsOptions.emplace_back(EDNSOptionCode::COOKIE, cookiesOpt.makeOptString());
    pw2.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, optionsToSkip);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match */
    BOOST_CHECK(!PacketCache::queryMatches(spacket1, spacket2, qname, noOptionsToSkip));
    /* but it does match if we skip cookies, though */
    BOOST_CHECK(PacketCache::queryMatches(spacket1, spacket2, qname, optionsToSkip));

#if 0
    {
      /* to be able to compute a new collision if the packet cache hashing code is updated */
    std::map<uint32_t, Netmask> colMap;
    size_t collisions = 0;
    size_t total = 0;

    for (size_t idxA = 0; idxA < 256; idxA++) {
      for (size_t idxB = 0; idxB < 256; idxB++) {
        for (size_t idxC = 0; idxC < 256; idxC++) {
          vector<uint8_t> secondQuery;
          DNSPacketWriter pwFQ(secondQuery, qname, QType::AAAA, QClass::IN, 0);
          pwFQ.getHeader()->rd = 1;
          pwFQ.getHeader()->qr = false;
          pwFQ.getHeader()->id = 0x42;
          opt.source = Netmask("10." + std::to_string(idxA) + "." + std::to_string(idxB) + "." + std::to_string(idxC) + "/32");
          ednsOptions.clear();
          ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
          pwFQ.addOpt(512, 0, 32768, ednsOptions);
          pwFQ.commit();
          auto secondKey = PacketCache::canHashPacket(std::string(reinterpret_cast<const char *>(secondQuery.data()), secondQuery.size()), optionsToSkip);
          colMap.emplace(secondKey, opt.source);

          secondQuery.clear();
          DNSPacketWriter pwSQ(secondQuery, qname, QType::AAAA, QClass::IN, 0);
          pwSQ.getHeader()->rd = 1;
          pwSQ.getHeader()->qr = false;
          pwSQ.getHeader()->id = 0x42;
          opt.source = Netmask("10." + std::to_string(idxA) + "." + std::to_string(idxB) + "." + std::to_string(idxC) + "/32");
          ednsOptions.clear();
          ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
          pwSQ.addOpt(512, 0, 0, ednsOptions);
          pwSQ.commit();
          secondKey = PacketCache::canHashPacket(std::string(reinterpret_cast<const char *>(secondQuery.data()), secondQuery.size()), optionsToSkip);

          total++;
          if (colMap.count(secondKey)) {
            collisions++;
            cerr<<"Collision between "<<colMap[secondKey].toString()<<" and "<<opt.source.toString()<<" for key "<<secondKey<<endl;
            goto done2;
          }
        }
      }
    }
  done2:
    cerr<<"collisions: "<<collisions<<endl;
    cerr<<"total: "<<total<<endl;
  }
#endif
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheRecSimple) {

  const DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  EDNSSubnetOpts opt;
  DNSPacketWriter::optvect_t ednsOptions;
  static const std::unordered_set<uint16_t> optionsToSkip{ EDNSOptionCode::COOKIE, EDNSOptionCode::ECS };

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
    BOOST_CHECK_NO_THROW(PacketCache::canHashPacket(spacket1, optionsToSkip));
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheRecCollision) {

  /* rec version (ECS is processed, we hash the whole query except for the ID and the ECS value, while lowercasing the qname) */
  const DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  EDNSSubnetOpts opt;
  DNSPacketWriter::optvect_t ednsOptions;
  static const std::unordered_set<uint16_t> optionsToSkip{ EDNSOptionCode::COOKIE, EDNSOptionCode::ECS };

  {
    /* same query, different IDs */
    vector<uint8_t> packet;
    DNSPacketWriter pw1(packet, qname, qtype);
    pw1.getHeader()->rd = true;
    pw1.getHeader()->qr = false;
    pw1.getHeader()->id = 0x42;
    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, optionsToSkip);

    BOOST_CHECK_EQUAL(hash1, hash2);
    BOOST_CHECK(PacketCache::queryMatches(spacket1, spacket2, qname, optionsToSkip));
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
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    pw1.addOpt(512, 0, 0, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("10.0.131.66/32");
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    pw2.addOpt(512, 0, 0, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, optionsToSkip);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same and we don't hash the ECS so we should match */
    BOOST_CHECK(PacketCache::queryMatches(spacket1, spacket2, qname, optionsToSkip));
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
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    EDNSCookiesOpt cookiesOpt(string("deadbeefdead\x11\xee\x00\x00").c_str(), 16);
    ednsOptions.emplace_back(EDNSOptionCode::COOKIE, cookiesOpt.makeOptString());
    pw1.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.source = Netmask("192.0.2.1/32");
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    cookiesOpt.makeFromString(string("deadbeefdead\x67\x44\x00\x00").c_str(), 16);
    ednsOptions.emplace_back(EDNSOptionCode::COOKIE, cookiesOpt.makeOptString());
    pw2.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw2.commit();

    string spacket2((const char*)&packet[0], packet.size());
    auto hash2 = PacketCache::canHashPacket(spacket2, optionsToSkip);

    BOOST_CHECK_EQUAL(hash1, hash2);
    /* the hash is the same but we should _not_ match, even though we skip the ECS part, because the cookies are different */
    static const std::unordered_set<uint16_t> skipECSOnly{ EDNSOptionCode::ECS };
    BOOST_CHECK(!PacketCache::queryMatches(spacket1, spacket2, qname, skipECSOnly));

    /* we do match if we skip the cookie as well */
    BOOST_CHECK(PacketCache::queryMatches(spacket1, spacket2, qname, optionsToSkip));
  }
}

BOOST_AUTO_TEST_SUITE_END()
