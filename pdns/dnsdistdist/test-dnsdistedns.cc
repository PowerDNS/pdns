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

#include "dnsdist-edns.hh"
#include "dnsname.hh"
#include "dnswriter.hh"
#include "ednscookies.hh"
#include "ednsextendederror.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"

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

    BOOST_CHECK_THROW(dnsdist::edns::getExtendedDNSError(query), std::range_error);
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

BOOST_AUTO_TEST_SUITE_END();
