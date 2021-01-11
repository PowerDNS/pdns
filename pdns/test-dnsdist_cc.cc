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
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include <unistd.h>

#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-xpf.hh"

#include "dolog.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednscookies.hh"
#include "ednssubnet.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdist_cc)

static const uint16_t ECSSourcePrefixV4 = 24;
static const uint16_t ECSSourcePrefixV6 = 56;

static void validateQuery(const PacketBuffer& packet, bool hasEdns=true, bool hasXPF=false, uint16_t additionals=0, uint16_t answers=0, uint16_t authorities=0)
{
  MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, answers);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, authorities);
  uint16_t expectedARCount = additionals + (hasEdns ? 1U : 0U) + (hasXPF ? 1U : 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, expectedARCount);
}

static void validateECS(const PacketBuffer& packet, const ComboAddress& expected)
{
  ComboAddress rem("::1");
  unsigned int consumed = 0;
  uint16_t qtype;
  uint16_t qclass;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  DNSQuestion dq(&qname, qtype, qclass, nullptr, &rem, const_cast<PacketBuffer&>(packet), false, nullptr);
  BOOST_CHECK(parseEDNSOptions(dq));
  BOOST_REQUIRE(dq.ednsOptions != nullptr);
  BOOST_CHECK_EQUAL(dq.ednsOptions->size(), 1U);
  const auto& ecsOption = dq.ednsOptions->find(EDNSOptionCode::ECS);
  BOOST_REQUIRE(ecsOption != dq.ednsOptions->cend());

  string expectedOption;
  generateECSOption(expected, expectedOption, expected.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);
  /* we need to skip the option code and length, which are not included */
  BOOST_REQUIRE_EQUAL(ecsOption->second.values.size(), 1U);
  BOOST_CHECK_EQUAL(expectedOption.substr(EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), std::string(ecsOption->second.values.at(0).content, ecsOption->second.values.at(0).size));
}

static void validateResponse(const PacketBuffer& packet, bool hasEdns, uint8_t additionalCount=0)
{
  MOADNSParser mdp(false, reinterpret_cast<const char*>(packet.data()), packet.size());

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qr, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, (hasEdns ? 1U : 0U) + additionalCount);
}

BOOST_AUTO_TEST_CASE(test_addXPF)
{
  static const uint16_t xpfOptionCode = 65422;

  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests
  ComboAddress remote;
  DNSName name("www.powerdns.com.");

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  PacketBuffer queryWithXPF;

  {
    PacketBuffer packet = query;

    /* large enough packet */
    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    BOOST_CHECK_EQUAL(qname, name);
    BOOST_CHECK(qtype == QType::A);

    DNSQuestion dq(&qname, qtype, QClass::IN, &remote, &remote, packet, false, &queryTime);

    BOOST_CHECK(addXPF(dq, xpfOptionCode));
    BOOST_CHECK(packet.size() > query.size());
    validateQuery(packet, false, true);
    queryWithXPF = packet;
  }

  {
    PacketBuffer packet = query;

    /* packet is already too large for the 4096 limit over UDP */
    packet.resize(4096);
    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    BOOST_CHECK_EQUAL(qname, name);
    BOOST_CHECK(qtype == QType::A);

    DNSQuestion dq(&qname, qtype, QClass::IN, &remote, &remote, packet, false, &queryTime);

    BOOST_REQUIRE(!addXPF(dq, xpfOptionCode));
    BOOST_CHECK_EQUAL(packet.size(), 4096U);
    packet.resize(query.size());
    validateQuery(packet, false, false);
  }

  {
    PacketBuffer packet = query;

    /* packet with trailing data (overriding it) */
    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    BOOST_CHECK_EQUAL(qname, name);
    BOOST_CHECK(qtype == QType::A);

    DNSQuestion dq(&qname, qtype, QClass::IN, &remote, &remote, packet, false, &queryTime);

    /* add trailing data */
    const size_t trailingDataSize = 10;
    /* Making sure we have enough room to allow for fake trailing data */
    packet.resize(packet.size() + trailingDataSize);
    for (size_t idx = 0; idx < trailingDataSize; idx++) {
      packet.push_back('A');
    }

    BOOST_CHECK(addXPF(dq, xpfOptionCode));
    BOOST_CHECK_EQUAL(packet.size(), queryWithXPF.size());
    BOOST_CHECK_EQUAL(memcmp(queryWithXPF.data(), packet.data(), queryWithXPF.size()), 0);
    validateQuery(packet, false, true);
  }
}

BOOST_AUTO_TEST_CASE(addECSWithoutEDNS)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.0.2.1");
  DNSName name("www.powerdns.com.");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  uint16_t len = query.size();

  /* large enough packet */
  PacketBuffer packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, false, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, remote);
  PacketBuffer queryWithEDNS = packet;

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, false, newECSOption));
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  packet.resize(query.size());
  validateQuery(packet, false);

  /* packet with trailing data (overriding it) */
  packet = query;
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  /* add trailing data */
  const size_t trailingDataSize = 10;
  /* Making sure we have enough room to allow for fake trailing data */
  packet.resize(packet.size() + trailingDataSize);
  for (size_t idx = 0; idx < trailingDataSize; idx++) {
    packet[len + idx] = 'A';
  }

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, false, newECSOption));
  BOOST_REQUIRE_EQUAL(packet.size(), queryWithEDNS.size());
  BOOST_CHECK_EQUAL(memcmp(queryWithEDNS.data(), packet.data(), queryWithEDNS.size()), 0);
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
}

BOOST_AUTO_TEST_CASE(addECSWithoutEDNSAlreadyParsed)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.0.2.1");
  DNSName name("www.powerdns.com.");

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;

  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  uint16_t qclass;
  DNSName qname(reinterpret_cast<const char *>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);

  DNSQuestion dq(&qname, qtype, qclass, nullptr, &remote, packet, false, nullptr);
  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(!parseEDNSOptions(dq));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dq, ednsAdded, ecsAdded));
  BOOST_CHECK_GT(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, remote);

  /* trailing data */
  packet = query;
  packet.resize(2048);

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);
  DNSQuestion dq2(&qname, qtype, qclass, nullptr, &remote, packet, false, nullptr);

  BOOST_CHECK(handleEDNSClientSubnet(dq2, ednsAdded, ecsAdded));
  BOOST_CHECK_GT(packet.size(), query.size());
  BOOST_CHECK_LT(packet.size(), 2048U);
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, remote);
}

BOOST_AUTO_TEST_CASE(addECSWithEDNSNoECS) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote;
  DNSName name("www.powerdns.com.");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  pw.addOpt(512, 0, 0);
  pw.commit();

  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, false, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, remote);

  /* not large enough packet */
  consumed = 0;
  ednsAdded = false;
  ecsAdded = false;
  packet = query;

  qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, false, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
}

BOOST_AUTO_TEST_CASE(addECSWithEDNSNoECSAlreadyParsed) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("2001:DB8::1");
  DNSName name("www.powerdns.com.");

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  pw.addOpt(512, 0, 0);
  pw.commit();

  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  uint16_t qclass;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);

  DNSQuestion dq(&qname, qtype, qclass, nullptr, &remote, packet, false, nullptr);
  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(parseEDNSOptions(dq));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dq, ednsAdded, ecsAdded));
  BOOST_CHECK_GT(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, remote);

  /* trailing data */
  packet = query;
  packet.resize(2048);
  consumed = 0;
  ednsAdded = false;
  ecsAdded = false;
  qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);
  DNSQuestion dq2(&qname, qtype, qclass, nullptr, &remote, packet, false, nullptr);

  BOOST_CHECK(handleEDNSClientSubnet(dq2, ednsAdded, ecsAdded));
  BOOST_CHECK_GT(packet.size(), query.size());
  BOOST_CHECK_LT(packet.size(), 2048U);
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, remote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSameSize) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
  validateECS(packet, remote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSameSizeAlreadyParsed) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  uint16_t qclass;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);

  DNSQuestion dq(&qname, qtype, qclass, nullptr, &remote, packet, false, nullptr);
  dq.ecsOverride = true;

  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(parseEDNSOptions(dq));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dq, ednsAdded, ecsAdded));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
  validateECS(packet, remote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSmaller) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 32);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() < query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
  validateECS(packet, remote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithLarger) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  // smaller (less specific so less bits) option
  static_assert(8 < ECSSourcePrefixV4, "The ECS scope should be smaller");
  ecsOpts.source = Netmask(origRemote, 8);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
}

BOOST_AUTO_TEST_CASE(replaceECSFollowedByTSIG) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 8);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.startRecord(DNSName("tsigname."), QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  pw.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 1);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 1);
}

BOOST_AUTO_TEST_CASE(replaceECSAfterAN) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  pw.startRecord(DNSName("powerdns.com."), QType::A, 0, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.commit();
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 8);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 0, 1, 0);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 0, 1, 0);
}

BOOST_AUTO_TEST_CASE(replaceECSAfterAuth) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  pw.startRecord(DNSName("powerdns.com."), QType::A, 0, QClass::IN, DNSResourceRecord::AUTHORITY, true);
  pw.commit();
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 8);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 0, 0, 1);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 0, 0, 1);
}

BOOST_AUTO_TEST_CASE(replaceECSBetweenTwoRecords) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 8);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.startRecord(DNSName("additional"), QType::A, 0, QClass::IN, DNSResourceRecord::ADDITIONAL, false);
  pw.xfr32BitInt(0x01020304);
  pw.addOpt(512, 0, 0, opts);
  pw.startRecord(DNSName("tsigname."), QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  pw.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 2);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 2);
}

BOOST_AUTO_TEST_CASE(insertECSInEDNSBetweenTwoRecords) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  pw.startRecord(DNSName("additional"), QType::A, 0, QClass::IN, DNSResourceRecord::ADDITIONAL, false);
  pw.xfr32BitInt(0x01020304);
  pw.addOpt(512, 0, 0);
  pw.startRecord(DNSName("tsigname."), QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  pw.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet, true, false, 2);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(query, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false, 2);
}

BOOST_AUTO_TEST_CASE(insertECSAfterTSIG) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  pw.startRecord(DNSName("tsigname."), QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  pw.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  /* the MOADNSParser does not allow anything except XPF after a TSIG */
  BOOST_CHECK_THROW(validateQuery(packet, true, false, 1), MOADNSException);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, false);
}


BOOST_AUTO_TEST_CASE(removeEDNSWhenFirst) {
  DNSName name("www.powerdns.com.");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);
  pw.addOpt(512, 0, 0);
  pw.commit();
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNS(response, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse(newResponse, false, 1);
}

BOOST_AUTO_TEST_CASE(removeEDNSWhenIntermediary) {
  DNSName name("www.powerdns.com.");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);
  pw.startRecord(DNSName("other.powerdns.com."), QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();
  pw.addOpt(512, 0, 0);
  pw.commit();
  pw.startRecord(DNSName("yetanother.powerdns.com."), QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNS(response, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse(newResponse, false, 2);
}

BOOST_AUTO_TEST_CASE(removeEDNSWhenLast) {
  DNSName name("www.powerdns.com.");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();
  pw.startRecord(DNSName("other.powerdns.com."), QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();
  pw.addOpt(512, 0, 0);
  pw.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNS(response, newResponse);

  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse(newResponse, false, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenOnlyOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(response, &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  res = removeEDNSOptionFromOPT(reinterpret_cast<char *>(response.data()) + optStart, &optLen, EDNSOptionCode::ECS);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(optLen, existingOptLen - (origECSOptionStr.size() + 4));
  responseLen -= (existingOptLen - optLen);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) response.data(), responseLen, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(response, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenFirstOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV6);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  string cookiesOptionStr = makeEDNSCookiesOptString(cookiesOpt);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(response, &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  res = removeEDNSOptionFromOPT(reinterpret_cast<char *>(response.data()) + optStart, &optLen, EDNSOptionCode::ECS);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(optLen, existingOptLen - (origECSOptionStr.size() + 4));
  responseLen -= (existingOptLen - optLen);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) response.data(), responseLen, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(response, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenIntermediaryOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);

  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  string cookiesOptionStr1 = makeEDNSCookiesOptString(cookiesOpt);
  string cookiesOptionStr2 = makeEDNSCookiesOptString(cookiesOpt);

  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr1));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr2));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(response, &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  res = removeEDNSOptionFromOPT(reinterpret_cast<char *>(response.data()) + optStart, &optLen, EDNSOptionCode::ECS);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(optLen, existingOptLen - (origECSOptionStr.size() + 4));
  responseLen -= (existingOptLen - optLen);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) response.data(), responseLen, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(response, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenLastOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  string cookiesOptionStr = makeEDNSCookiesOptString(cookiesOpt);
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(response, &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  res = removeEDNSOptionFromOPT(reinterpret_cast<char *>(response.data()) + optStart, &optLen, EDNSOptionCode::ECS);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(optLen, existingOptLen - (origECSOptionStr.size() + 4));
  responseLen -= (existingOptLen - optLen);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) response.data(), responseLen, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(response, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenOnlyOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(newResponse, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenFirstOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  string cookiesOptionStr = makeEDNSCookiesOptString(cookiesOpt);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(newResponse, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenIntermediaryOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  string cookiesOptionStr1 = makeEDNSCookiesOptString(cookiesOpt);
  string cookiesOptionStr2 = makeEDNSCookiesOptString(cookiesOpt);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr1));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr2));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(newResponse, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenLastOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  string cookiesOptionStr = makeEDNSCookiesOptString(cookiesOpt);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(newResponse, true, 1);
}

static DNSQuestion getDNSQuestion(const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& lc, const ComboAddress& rem, const struct timespec& realTime, PacketBuffer& query)
{
  return DNSQuestion(&qname, qtype, qclass, &lc, &rem, query, false, &realTime);
}

static DNSQuestion turnIntoResponse(const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& lc, const ComboAddress& rem, const struct timespec& queryRealTime, PacketBuffer&  query, bool resizeBuffer=true)
{
  if (resizeBuffer) {
    query.resize(4096);
  }

  auto dq = getDNSQuestion(qname, qtype, qclass, lc, rem, queryRealTime, query);

  BOOST_CHECK(addEDNSToQueryTurnedResponse(dq));

  return dq;
}

static int getZ(const DNSName& qname, const uint16_t qtype, const uint16_t qclass, PacketBuffer& query)
{
  ComboAddress lc("127.0.0.1");
  ComboAddress rem("127.0.0.1");
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);
  DNSQuestion dq = getDNSQuestion(qname, qtype, qclass, lc, rem, queryRealTime, query);

  return getEDNSZ(dq);
}

BOOST_AUTO_TEST_CASE(test_getEDNSZ) {

  uint16_t z;
  uint16_t udpPayloadSize;
  DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(ComboAddress("127.0.0.1"), ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  string cookiesOptionStr = makeEDNSCookiesOptString(cookiesOpt);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), false);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* truncated EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pw.commit();

    query.resize(query.size() - (/* RDLEN */ sizeof(uint16_t) + /* last byte of TTL / Z */ 1));
    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), false);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* valid EDNS, no options, DO not set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

  {
    /* valid EDNS, no options, DO set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

    {
    /* valid EDNS, options, DO not set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

  {
    /* valid EDNS, options, DO set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO, opts);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

}

BOOST_AUTO_TEST_CASE(test_addEDNSToQueryTurnedResponse) {

  uint16_t z;
  uint16_t udpPayloadSize;
  DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(ComboAddress("127.0.0.1"), ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  string cookiesOptionStr = makeEDNSCookiesOptString(cookiesOpt);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  ComboAddress lc("127.0.0.1");
  ComboAddress rem("127.0.0.1");
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.getHeader()->qr = 1;
    pw.getHeader()->rcode = RCode::NXDomain;
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size(), &udpPayloadSize, &z), false);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* truncated EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pw.commit();

    query.resize(query.size() - (/* RDLEN */ sizeof(uint16_t) + /* last byte of TTL / Z */ 1));
    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query, false);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size(), &udpPayloadSize, &z), false);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* valid EDNS, no options, DO not set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0);
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, g_PayloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, no options, DO set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, g_PayloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, options, DO not set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, g_PayloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, options, DO set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO, opts);
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, g_PayloadSizeSelfGenAnswers);
  }
}

BOOST_AUTO_TEST_CASE(test_getEDNSOptionsStart) {
  const DNSName qname("www.powerdns.com.");
  const uint16_t qtype = QType::A;
  const uint16_t qclass = QClass::IN;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(ComboAddress("127.0.0.1"), ECSSourcePrefixV4);
  const string ecsOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, ecsOptionStr));
  const ComboAddress lc("127.0.0.1");
  const ComboAddress rem("127.0.0.1");
  uint16_t optRDPosition;
  size_t remaining;

  const size_t optRDExpectedOffset = sizeof(dnsheader) + qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + DNS_TTL_SIZE;

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.getHeader()->qr = 1;
    pw.getHeader()->rcode = RCode::NXDomain;
    pw.commit();

    int res = getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, ENOENT);

    /* truncated packet (should not matter) */
    query.resize(query.size() - 1);
    res = getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, ENOENT);
  }

  {
    /* valid EDNS, no options */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0);
    pw.commit();

    int res = getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);

    /* truncated packet */
    query.resize(query.size() - 1);

    res = getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);
    BOOST_CHECK_EQUAL(res, ENOENT);
  }

  {
    /* valid EDNS, options */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    int res = getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);

    /* truncated options (should not matter for this test) */
    query.resize(query.size() - 1);
    res = getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);
    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);
  }

}

BOOST_AUTO_TEST_CASE(test_isEDNSOptionInOpt) {

  auto locateEDNSOption = [](const PacketBuffer& query, uint16_t code, size_t* optContentStart, uint16_t* optContentLen) {
    uint16_t optStart;
    size_t optLen;
    bool last = false;
    int res = locateEDNSOptRR(query, &optStart, &optLen, &last);
    if (res != 0) {
      // no EDNS OPT RR
      return false;
    }

    if (optLen < optRecordMinimumSize) {
      return false;
    }

    if (optStart < query.size() && query.at(optStart) != 0) {
      // OPT RR Name != '.'
      return false;
    }

    return isEDNSOptionInOpt(query, optStart, optLen, code, optContentStart, optContentLen);
  };

  const DNSName qname("www.powerdns.com.");
  const uint16_t qtype = QType::A;
  const uint16_t qclass = QClass::IN;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(ComboAddress("127.0.0.1"), ECSSourcePrefixV4);
  const string ecsOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  const size_t sizeOfECSContent = ecsOptionStr.size();
  const size_t sizeOfECSOption = /* option code */ 2 + /* option length */ 2 + sizeOfECSContent;
  EDNSCookiesOpt cookiesOpt;
  cookiesOpt.client = string("deadbeef");
  cookiesOpt.server = string("deadbeef");
  const string cookiesOptionStr = makeEDNSCookiesOptString(cookiesOpt);
  const size_t sizeOfCookieOption = /* option code */ 2 + /* option length */ 2 + cookiesOpt.client.size() + cookiesOpt.server.size();
  /*
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
    opts.push_back(make_pair(EDNSOptionCode::ECS, ecsOptionStr));
    opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  */
  const ComboAddress lc("127.0.0.1");
  const ComboAddress rem("127.0.0.1");
  size_t optContentStart;
  uint16_t optContentLen;

  const size_t optRDExpectedOffset = sizeof(dnsheader) + qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + DNS_TTL_SIZE;

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.getHeader()->qr = 1;
    pw.getHeader()->rcode = RCode::NXDomain;
    pw.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, false);

    /* truncated packet (should not matter here) */
    query.resize(query.size() - 1);
    found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, false);
  }

  {
    /* valid EDNS, no options */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0);
    pw.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, false);

    /* truncated packet */
    query.resize(query.size() - 1);
    BOOST_CHECK_THROW(locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen), std::out_of_range);
  }

  {
    /* valid EDNS, two cookie options but no ECS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
    opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, false);

    /* truncated packet */
    query.resize(query.size() - 1);
    BOOST_CHECK_THROW(locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen), std::range_error);
  }

  {
    /* valid EDNS, two ECS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.push_back(make_pair(EDNSOptionCode::ECS, ecsOptionStr));
    opts.push_back(make_pair(EDNSOptionCode::ECS, ecsOptionStr));
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, true);
    if (found == true) {
      BOOST_CHECK_EQUAL(optContentStart, optRDExpectedOffset + sizeof(uint16_t) /* RD len */ + /* option code */ 2 + /* option length */ 2);
      BOOST_CHECK_EQUAL(optContentLen, sizeOfECSContent);
    }

    /* truncated packet */
    query.resize(query.size() - 1);
    BOOST_CHECK_THROW(locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen), std::range_error);
  }

  {
    /* valid EDNS, one ECS between two cookies */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
    opts.push_back(make_pair(EDNSOptionCode::ECS, ecsOptionStr));
    opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, true);
    if (found == true) {
      BOOST_CHECK_EQUAL(optContentStart, optRDExpectedOffset + sizeof(uint16_t) /* RD len */ + sizeOfCookieOption + /* option code */ 2 + /* option length */ 2);
      BOOST_CHECK_EQUAL(optContentLen, sizeOfECSContent);
    }

    /* truncated packet */
    query.resize(query.size() - 1);
    BOOST_CHECK_THROW(locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen), std::range_error);
  }

  {
    /* valid EDNS, one 65002 after an ECS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, qname, qtype, qclass, 0);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.push_back(make_pair(EDNSOptionCode::ECS, ecsOptionStr));
    opts.push_back(make_pair(65535, cookiesOptionStr));
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    bool found = locateEDNSOption(query, 65535, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, true);
    if (found == true) {
      BOOST_CHECK_EQUAL(optContentStart, optRDExpectedOffset + sizeof(uint16_t) /* RD len */ + sizeOfECSOption + /* option code */ 2 + /* option length */ 2);
      BOOST_CHECK_EQUAL(optContentLen, cookiesOptionStr.size());
    }

    /* truncated packet */
    query.resize(query.size() - 1);
    BOOST_CHECK_THROW(locateEDNSOption(query, 65002, &optContentStart, &optContentLen), std::range_error);
  }
}

BOOST_AUTO_TEST_CASE(test_setNegativeAndAdditionalSOA) {
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests
  ComboAddress remote;
  DNSName name("www.powerdns.com.");

  PacketBuffer query;
  PacketBuffer queryWithEDNS;
  GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  GenericDNSPacketWriter<PacketBuffer> pwEDNS(queryWithEDNS, name, QType::A, QClass::IN, 0);
  pwEDNS.getHeader()->rd = 1;
  pwEDNS.addOpt(1232, 0, 0);
  pwEDNS.commit();

  /* test NXD */
  {
    /* no incoming EDNS */
    auto packet = query;

    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    DNSQuestion dq(&qname, qtype, QClass::IN, &remote, &remote, packet, false, &queryTime);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dq, true, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4 , 5));
    BOOST_CHECK(packet.size() > query.size());
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NXDomain);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 1U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_name, DNSName("zone."));
  }
  {
    /* now with incoming EDNS */
    auto packet = queryWithEDNS;

    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    DNSQuestion dq(&qname, qtype, QClass::IN, &remote, &remote, packet, false, &queryTime);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dq, true, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4 , 5));
    BOOST_CHECK(packet.size() > queryWithEDNS.size());
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NXDomain);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 2U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 2U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_name, DNSName("zone."));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).first.d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).first.d_name, g_rootdnsname);
  }

  /* test No Data */
  {
    /* no incoming EDNS */
    auto packet = query;

    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    DNSQuestion dq(&qname, qtype, QClass::IN, &remote, &remote, packet, false, &queryTime);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dq, false, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4 , 5));
    BOOST_CHECK(packet.size() > query.size());
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NoError);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 1U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_name, DNSName("zone."));
  }
  {
    /* now with incoming EDNS */
    auto packet = queryWithEDNS;

    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    DNSQuestion dq(&qname, qtype, QClass::IN, &remote, &remote, packet, false, &queryTime);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dq, false, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4 , 5));
    BOOST_CHECK(packet.size() > queryWithEDNS.size());
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NoError);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 2U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 2U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_name, DNSName("zone."));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).first.d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).first.d_name, g_rootdnsname);
  }
}

BOOST_AUTO_TEST_CASE(getEDNSOptionsWithoutEDNS) {
  const ComboAddress remote("192.168.1.25");
  const DNSName name("www.powerdns.com.");
  const ComboAddress origRemote("127.0.0.1");
  const ComboAddress v4("192.0.2.1");

  {
    /* no EDNS and no other additional record */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.commit();

    /* large enough packet */
    auto packet = query;

    unsigned int consumed = 0;
    uint16_t qtype;
    uint16_t qclass;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dq(&qname, qtype, qclass, nullptr, &remote, packet, false, nullptr);

    BOOST_CHECK(!parseEDNSOptions(dq));
  }

  {
    /* nothing in additional (so no EDNS) but a record in ANSWER */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.startRecord(name, QType::A, 60, QClass::IN, DNSResourceRecord::ANSWER);
    pw.xfrIP(v4.sin4.sin_addr.s_addr);
    pw.commit();

    /* large enough packet */
    auto packet = query;

    unsigned int consumed = 0;
    uint16_t qtype;
    uint16_t qclass;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dq(&qname, qtype, qclass, nullptr, &remote, packet, false, nullptr);

    BOOST_CHECK(!parseEDNSOptions(dq));
  }

  {
    /* nothing in additional (so no EDNS) but a record in AUTHORITY */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, name, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.startRecord(name, QType::A, 60, QClass::IN, DNSResourceRecord::AUTHORITY);
    pw.xfrIP(v4.sin4.sin_addr.s_addr);
    pw.commit();

    /* large enough packet */
    auto packet = query;

    unsigned int consumed = 0;
    uint16_t qtype;
    uint16_t qclass;
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dq(&qname, qtype, qclass, nullptr, &remote, packet, false, nullptr);

    BOOST_CHECK(!parseEDNSOptions(dq));
  }
}

BOOST_AUTO_TEST_SUITE_END();
