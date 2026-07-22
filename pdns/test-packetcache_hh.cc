#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

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
    opt.setSource(Netmask("10.0.59.220/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
    pw1.addOpt(512, 0, 0, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.setSource(Netmask("10.0.167.48/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
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
    opt.setSource(Netmask("10.0.41.6/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
    pw1.addOpt(512, 0, EDNSOpts::DNSSECOK, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.setSource(Netmask("10.0.119.79/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
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
    opt.setSource(Netmask("192.0.2.1/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
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
    opt.setSource(Netmask("192.0.2.1/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
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
    opt.setSource(Netmask("10.0.18.199/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
    pw1.addOpt(512, 0, 0, ednsOptions);
    pw1.commit();

    string spacket1((const char*)&packet[0], packet.size());
    auto hash1 = PacketCache::canHashPacket(spacket1, optionsToSkip);

    packet.clear();
    DNSPacketWriter pw2(packet, qname, qtype);
    pw2.getHeader()->rd = true;
    pw2.getHeader()->qr = false;
    pw2.getHeader()->id = 0x84;
    opt.setSource(Netmask("10.0.131.66/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
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
    opt.setSource(Netmask("192.0.2.1/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
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
    opt.setSource(Netmask("192.0.2.1/32"));
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
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

BOOST_AUTO_TEST_CASE(test_PacketCacheEDNSOptionLengthBound) {
  /* queryMatches() has to use the same EDNS option-length bound as
     hashAfterQname(): the room left for an option value is
     (rdLen - rdataRead - 4), since the option code (2) and length (2)
     precede the value. A query whose OPT option declares a length within
     four bytes of the remaining RDATA is malformed and must be treated the
     same way by both, otherwise the hash and the match disagree. */
  const DNSName qname("www.powerdns.com.");
  const uint16_t qtype = QType::AAAA;
  static const std::unordered_set<uint16_t> skipECS{ EDNSOptionCode::ECS };

  EDNSSubnetOpts opt;
  DNSPacketWriter::optvect_t ednsOptions;

  auto makeQuery = [&](const std::string& ecsSource) -> std::string {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, qname, qtype);
    pw.getHeader()->rd = true;
    pw.getHeader()->qr = false;
    pw.getHeader()->id = 0x42;
    opt.setSource(Netmask(ecsSource));
    const std::string ecs = opt.makeOptString();
    ednsOptions.clear();
    ednsOptions.emplace_back(EDNSOptionCode::ECS, ecs);
    pw.addOpt(512, 0, 0, ednsOptions);
    pw.commit();

    std::string spacket(reinterpret_cast<const char*>(packet.data()), packet.size());
    /* the ECS option is the last thing in the packet; its length field sits two
       bytes before its value. Bump it by 3 so the option claims to run past the
       actual RDATA end, landing in the (rdLen - 3 .. rdLen) window. */
    auto* optLen = reinterpret_cast<unsigned char*>(&spacket.at(spacket.size() - ecs.size() - 2));
    const uint16_t bumped = static_cast<uint16_t>((optLen[0] * 256 + optLen[1]) + 3);
    optLen[0] = static_cast<unsigned char>(bumped >> 8);
    optLen[1] = static_cast<unsigned char>(bumped & 0xff);
    return spacket;
  };

  /* two queries differing only in the (skipped) ECS option value */
  const std::string queryA = makeQuery("192.0.2.0/24");
  const std::string queryB = makeQuery("203.0.113.0/24");

  /* hashAfterQname() sees the malformed option and hashes the raw remainder, so
     the differing ECS bytes give different hashes */
  BOOST_CHECK(PacketCache::canHashPacket(queryA, skipECS) != PacketCache::canHashPacket(queryB, skipECS));

  /* queryMatches() confirms a hash hit, so it must refuse to match two queries
     that hash differently */
  BOOST_CHECK(!PacketCache::queryMatches(queryA, queryB, qname, skipECS));
}

BOOST_AUTO_TEST_SUITE_END()
