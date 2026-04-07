/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/test/tools/old/interface.hpp>
#include <boost/test/unit_test_suite.hpp>
#include <stdexcept>

#include "iputils.hh"
#include "dnsdist-edns.hh"
#include "dnsdist-ecs.hh"
#include "dnsname.hh"
#include "dnswriter.hh"
#include "ednscookies.hh"
#include "ednsextendederror.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "dns.hh"
#include "qtype.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdist_edns)

BOOST_AUTO_TEST_CASE(getExtendedDNSError)
{
  const DNSName name("www.powerdns.com.");

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.commit();

    auto [infoCode, extraText] = dnsdist::edns::getExtendedDNSError(query);
    BOOST_CHECK(!infoCode);
    BOOST_CHECK(!extraText);
  }

  {
    /* EDNS but no EDE */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.addOpt(512, 0, 0);
    pw.commit();

    auto [infoCode, extraText] = dnsdist::edns::getExtendedDNSError(query);
    BOOST_CHECK(!infoCode);
    BOOST_CHECK(!extraText);
  }

  {
    /* EDE with a numerical code but no text */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    const EDNSExtendedError ede{
      .infoCode = static_cast<uint16_t>(EDNSExtendedError::code::NetworkError),
      .extraText = ""};
    opts.emplace_back(EDNSOptionCode::EXTENDEDERROR, makeEDNSExtendedErrorOptString(ede));
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    auto [infoCode, extraText] = dnsdist::edns::getExtendedDNSError(query);
    BOOST_CHECK(infoCode);
    BOOST_CHECK_EQUAL(*infoCode, ede.infoCode);
    BOOST_CHECK(!extraText);
  }

  {
    /* EDE with both code and text */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    const EDNSExtendedError ede{
      .infoCode = static_cast<uint16_t>(EDNSExtendedError::code::Synthesized),
      .extraText = "Synthesized from aggressive NSEC cache"};
    opts.emplace_back(EDNSOptionCode::EXTENDEDERROR, makeEDNSExtendedErrorOptString(ede));
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    auto [infoCode, extraText] = dnsdist::edns::getExtendedDNSError(query);
    BOOST_CHECK(infoCode);
    BOOST_CHECK_EQUAL(*infoCode, ede.infoCode);
    BOOST_CHECK(extraText);
    BOOST_CHECK_EQUAL(*extraText, ede.extraText);
  }

  {
    /* EDE with truncated text */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    const EDNSExtendedError ede{
      .infoCode = static_cast<uint16_t>(EDNSExtendedError::code::Synthesized),
      .extraText = "Synthesized from aggressive NSEC cache"};
    opts.emplace_back(EDNSOptionCode::EXTENDEDERROR, makeEDNSExtendedErrorOptString(ede));
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    /* truncate the EDE text by one byte */
    query.resize(query.size() - 1U);

    BOOST_CHECK_THROW(dnsdist::edns::getExtendedDNSError(query), std::out_of_range);
  }

  {
    /* EDE before ECS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    const EDNSExtendedError ede{
      .infoCode = static_cast<uint16_t>(EDNSExtendedError::code::Synthesized),
      .extraText = "Synthesized from aggressive NSEC cache"};
    opts.emplace_back(EDNSOptionCode::EXTENDEDERROR, makeEDNSExtendedErrorOptString(ede));
    EDNSSubnetOpts ecsOpt;
    ecsOpt.setSource(Netmask(ComboAddress("192.0.2.1"), 24U));
    const auto ecsOptStr = ecsOpt.makeOptString();
    opts.emplace_back(EDNSOptionCode::ECS, ecsOptStr);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    auto [infoCode, extraText] = dnsdist::edns::getExtendedDNSError(query);
    BOOST_CHECK(infoCode);
    BOOST_CHECK_EQUAL(*infoCode, ede.infoCode);
    BOOST_CHECK(extraText);
    BOOST_CHECK_EQUAL(*extraText, ede.extraText);
  }

  {
    /* EDE after ECS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    EDNSSubnetOpts ecsOpt;
    ecsOpt.setSource(Netmask(ComboAddress("192.0.2.1"), 24U));
    const auto ecsOptStr = ecsOpt.makeOptString();
    opts.emplace_back(EDNSOptionCode::ECS, ecsOptStr);
    const EDNSExtendedError ede{
      .infoCode = static_cast<uint16_t>(EDNSExtendedError::code::Synthesized),
      .extraText = "Synthesized from aggressive NSEC cache"};
    opts.emplace_back(EDNSOptionCode::EXTENDEDERROR, makeEDNSExtendedErrorOptString(ede));
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    auto [infoCode, extraText] = dnsdist::edns::getExtendedDNSError(query);
    BOOST_CHECK(infoCode);
    BOOST_CHECK_EQUAL(*infoCode, ede.infoCode);
    BOOST_CHECK(extraText);
    BOOST_CHECK_EQUAL(*extraText, ede.extraText);
  }

  {
    /* Cookie, EDE, padding */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    const EDNSCookiesOpt cookieOpt("deadbeefdeadbeef");
    const auto cookieOptStr = cookieOpt.makeOptString();
    opts.emplace_back(EDNSOptionCode::COOKIE, cookieOptStr);
    const EDNSExtendedError ede{
      .infoCode = static_cast<uint16_t>(EDNSExtendedError::code::Synthesized),
      .extraText = "Synthesized from aggressive NSEC cache"};
    opts.emplace_back(EDNSOptionCode::EXTENDEDERROR, makeEDNSExtendedErrorOptString(ede));
    std::string paddingOptStr;
    paddingOptStr.resize(42U);
    opts.emplace_back(EDNSOptionCode::PADDING, paddingOptStr);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    auto [infoCode, extraText] = dnsdist::edns::getExtendedDNSError(query);
    BOOST_CHECK(infoCode);
    BOOST_CHECK_EQUAL(*infoCode, ede.infoCode);
    BOOST_CHECK(extraText);
    BOOST_CHECK_EQUAL(*extraText, ede.extraText);
  }
}

BOOST_AUTO_TEST_CASE(test_locateEDNSOptRR)
{
  PacketBuffer packet;
  DNSName qname{"example.com"};
  uint16_t optStart;
  size_t optLen;
  bool last;

  auto reset = [&packet, &optStart, &optLen, &last]() {
    packet.clear();
    optStart = 0;
    optLen = 0;
    last = false;
  };

  {
    reset();
    BOOST_CHECK_THROW(locateEDNSOptRR(packet, nullptr, &optLen, &last), std::runtime_error);
    BOOST_CHECK_THROW(locateEDNSOptRR(packet, &optStart, nullptr, &last), std::runtime_error);
    BOOST_CHECK_THROW(locateEDNSOptRR(packet, &optStart, &optLen, nullptr), std::runtime_error);
  }

  {
    reset();
    // A normal packet with OPT
    GenericDNSPacketWriter<PacketBuffer> pw(packet, qname, 1);
    pw.getHeader()->rd = 1;
    pw.addOpt(1232, 0, 0);
    pw.commit();
    BOOST_CHECK_EQUAL(locateEDNSOptRR(packet, &optStart, &optLen, &last), 0U);
    BOOST_CHECK_EQUAL(optStart, 29);
    BOOST_CHECK_EQUAL(optLen, 11);
    BOOST_CHECK(last);

    // Make only a header, should error, as there is no question section but QDCOUNT=1
    BOOST_CHECK_THROW(locateEDNSOptRR(PacketBuffer(packet.begin(), packet.begin() + 12), &optStart, &optLen, &last), std::out_of_range);

    // Only a Question section in the packet, but header has ARCOUNT=1, should error
    BOOST_CHECK_THROW(locateEDNSOptRR(PacketBuffer(packet.begin(), packet.begin() + 28), &optStart, &optLen, &last), std::out_of_range);
  }

  {
    reset();
    // No OPT in the packet
    GenericDNSPacketWriter<PacketBuffer> pw(packet, qname, 1);
    pw.getHeader()->rd = 1;
    BOOST_CHECK_EQUAL(locateEDNSOptRR(packet, &optStart, &optLen, &last), ENOENT);

    // Too small packet, should error
    packet.resize(11);
    BOOST_CHECK_THROW(locateEDNSOptRR(packet, &optStart, &optLen, &last), std::runtime_error);
  }

  {
    // An OPT record that has the wrong Owner name
    reset();
    GenericDNSPacketWriter<PacketBuffer> pw(packet, qname, 1);
    pw.getHeader()->rd = 1;
    pw.startRecord(DNSName("notroot"), QType::OPT, 3600, QClass::IN, DNSResourceRecord::Place::ADDITIONAL, false);
    pw.commit();
    BOOST_CHECK_EQUAL(locateEDNSOptRR(packet, &optStart, &optLen, &last), ENOENT);
  }

  {
    // Adds an OPT record that has the wrong Owner name *and* a good one, we should see the good one
    reset();
    GenericDNSPacketWriter<PacketBuffer> pw(packet, qname, 1);
    pw.getHeader()->rd = 1;
    pw.addOpt(1232, 0, 0);
    pw.commit();
    pw.startRecord(DNSName("notroot"), QType::OPT, 3600, QClass::IN, DNSResourceRecord::Place::ADDITIONAL, false);
    pw.commit();
    BOOST_CHECK_EQUAL(locateEDNSOptRR(packet, &optStart, &optLen, &last), 0U);
    BOOST_CHECK_EQUAL(optStart, 29);
    BOOST_CHECK_EQUAL(optLen, 11);
    BOOST_CHECK(!last);
  }
}

BOOST_AUTO_TEST_CASE(addEDNSPadding)
{
  const DNSName qname{"powerdns.com"};
  const uint16_t defaultEdnsBufSize{1232};
  const ComboAddress answer{"192.0.2.1"};

  auto getPacket = [qname, answer](bool edns = false, uint16_t ednsBufSize = 0, size_t padding = 0) {
    if (ednsBufSize == 0) {
      ednsBufSize = defaultEdnsBufSize;
    }
    PacketBuffer buf;
    GenericDNSPacketWriter<PacketBuffer> pwQ(buf, qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->qr = 1; // This is a response
    pwQ.getHeader()->rd = 1;
    pwQ.startRecord(qname, QType::A);
    pwQ.xfrCAWithoutPort(4, answer);
    pwQ.commit();
    if (edns) {
      vector<pair<uint16_t, std::string>> ednsopts;
      if (padding > 0) {
        std::string paddingOptStr;
        paddingOptStr.resize(padding);
        ednsopts.push_back({EDNSOptionCode::PADDING, paddingOptStr});
      }
      pwQ.addOpt(ednsBufSize, 0, 0, ednsopts);
    }
    pwQ.commit();

    return buf;
  };

  {
    // A packet where padding should not be added, as the option exists
    auto packet = getPacket(true, defaultEdnsBufSize, 64);
    auto initial_size = packet.size();

    BOOST_CHECK(!dnsdist::edns::addEDNSPadding(packet, defaultEdnsBufSize));
    BOOST_CHECK_EQUAL(packet.size(), initial_size);
  }

  {
    // A packet where padding should not be added, as there is no EDNS
    auto packet = getPacket(false);
    auto initial_size = packet.size();
    BOOST_CHECK(!dnsdist::edns::addEDNSPadding(packet, defaultEdnsBufSize));
    BOOST_CHECK_EQUAL(packet.size(), initial_size);
  }

  {
    // A packet where padding should not be added, as there is no more room
    auto packet = getPacket(true);
    auto initial_size = packet.size();

    BOOST_CHECK(!dnsdist::edns::addEDNSPadding(packet, packet.size()));
    BOOST_CHECK_EQUAL(packet.size(), initial_size);

    BOOST_CHECK(!dnsdist::edns::addEDNSPadding(packet, packet.size() + 2));
    BOOST_CHECK_EQUAL(packet.size(), initial_size);

    // 4 bytes should fit as that is the EDNS OptionCode + Length field
    BOOST_CHECK(dnsdist::edns::addEDNSPadding(packet, packet.size() + 4));
    BOOST_CHECK_EQUAL(packet.size(), initial_size + 4);
  }

  {
    // A packet where padding *should* be added
    auto packetWithEDNSNoPadding = getPacket(true, defaultEdnsBufSize, 0);
    BOOST_CHECK(dnsdist::edns::addEDNSPadding(packetWithEDNSNoPadding, defaultEdnsBufSize));
    BOOST_CHECK_EQUAL(packetWithEDNSNoPadding.size() % 468, 0);
  }
}

BOOST_AUTO_TEST_SUITE_END();
