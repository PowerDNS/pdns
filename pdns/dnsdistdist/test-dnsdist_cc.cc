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
#include <unistd.h>

#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-internal-queries.hh"
#include "dnsdist-snmp.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-xsk.hh"

#include "dolog.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednscookies.hh"
#include "ednssubnet.hh"

ProcessQueryResult processQueryAfterRules(DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend)
{
  (void)dnsQuestion;
  (void)selectedBackend;
  return ProcessQueryResult::Drop;
}

bool processResponseAfterRules(PacketBuffer& response, DNSResponse& dnsResponse, bool muted)
{
  (void)response;
  (void)dnsResponse;
  (void)muted;
  return false;
}

bool applyRulesToResponse(const std::vector<dnsdist::rules::ResponseRuleAction>& respRuleActions, DNSResponse& dnsResponse)
{
  (void)respRuleActions;
  (void)dnsResponse;
  return true;
}

bool handleTimeoutResponseRules(const std::vector<dnsdist::rules::ResponseRuleAction>& rules, InternalQueryState& ids, const std::shared_ptr<DownstreamState>& d_ds, const std::shared_ptr<TCPQuerySender>& sender)
{
  (void)rules;
  (void)ids;
  (void)d_ds;
  (void)sender;
  return false;
}

void handleServerStateChange(const string& nameWithAddr, bool newResult)
{
  (void)nameWithAddr;
  (void)newResult;
  return;
}

bool sendUDPResponse(int origFD, const PacketBuffer& response, const int delayMsec, const ComboAddress& origDest, const ComboAddress& origRemote)
{
  (void)origFD;
  (void)response;
  (void)delayMsec;
  (void)origDest;
  (void)origRemote;
  return false;
}

bool assignOutgoingUDPQueryToBackend(std::shared_ptr<DownstreamState>& downstream, uint16_t queryID, DNSQuestion& dnsQuestion, PacketBuffer& query, bool actuallySend)
{
  (void)downstream;
  (void)queryID;
  (void)dnsQuestion;
  (void)query;
  (void)actuallySend;
  return true;
}

namespace dnsdist
{
std::unique_ptr<CrossProtocolQuery> getInternalQueryFromDQ(DNSQuestion& dnsQuestion, bool isResponse)
{
  (void)dnsQuestion;
  (void)isResponse;
  return nullptr;
}
}

// NOLINTNEXTLINE(readability-convert-member-functions-to-static): only a stub
bool DNSDistSNMPAgent::sendBackendStatusChangeTrap([[maybe_unused]] DownstreamState const& backend)
{
  return false;
}

#ifdef HAVE_XSK
namespace dnsdist::xsk
{
bool XskProcessQuery(ClientState& clientState, XskPacket& packet)
{
  (void)clientState;
  (void)packet;
  return false;
}
}
#endif /* HAVE_XSK */

bool processResponderPacket(std::shared_ptr<DownstreamState>& dss, PacketBuffer& response, InternalQueryState&& ids)
{
  (void)dss;
  (void)response;
  (void)ids;
  return false;
}

BOOST_AUTO_TEST_SUITE(test_dnsdist_cc)

static const uint16_t ECSSourcePrefixV4 = 24;
static const uint16_t ECSSourcePrefixV6 = 56;

static void validateQuery(const PacketBuffer& packet, bool hasEdns = true, uint16_t additionals = 0, uint16_t answers = 0, uint16_t authorities = 0)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, answers);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, authorities);
  uint16_t expectedARCount = additionals + (hasEdns ? 1U : 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, expectedARCount);
}

static void validateECS(const PacketBuffer& packet, const ComboAddress& expected)
{
  InternalQueryState ids;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.origRemote = ComboAddress("::1");
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
  DNSQuestion dnsQuestion(ids, const_cast<PacketBuffer&>(packet));
  BOOST_CHECK(parseEDNSOptions(dnsQuestion));
  BOOST_REQUIRE(dnsQuestion.ednsOptions != nullptr);
  BOOST_CHECK_EQUAL(dnsQuestion.ednsOptions->size(), 1U);
  const auto& ecsOption = dnsQuestion.ednsOptions->find(EDNSOptionCode::ECS);
  BOOST_REQUIRE(ecsOption != dnsQuestion.ednsOptions->cend());

  string expectedOption;
  generateECSOption(expected, expectedOption, expected.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);
  /* we need to skip the option code and length, which are not included */
  BOOST_REQUIRE_EQUAL(ecsOption->second.values.size(), 1U);
  BOOST_CHECK_EQUAL(expectedOption.substr(EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE), std::string(ecsOption->second.values.at(0).content, ecsOption->second.values.at(0).size));
}

static void validateResponse(const PacketBuffer& packet, bool hasEdns, uint8_t additionalCount = 0)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  MOADNSParser mdp(false, reinterpret_cast<const char*>(packet.data()), packet.size());

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qr, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, (hasEdns ? 1U : 0U) + additionalCount);
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
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  uint16_t len = query.size();

  /* large enough packet */
  PacketBuffer packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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

BOOST_AUTO_TEST_CASE(addECSWithoutEDNSButWithAnswer)
{
  /* this might happen for NOTIFY queries where, according to rfc1996:
     "If ANCOUNT>0, then the answer section represents an
     unsecure hint at the new RRset for this <QNAME,QCLASS,QTYPE>".
  */
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.0.2.1");
  DNSName name("www.powerdns.com.");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  packetWriter.startRecord(name, QType::A, 60, QClass::IN, DNSResourceRecord::ANSWER, false);
  packetWriter.xfrIP(remote.sin4.sin_addr.s_addr);
  packetWriter.commit();
  uint16_t len = query.size();

  /* large enough packet */
  PacketBuffer packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, false, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet, true, 0, 1);
  validateECS(packet, remote);
  PacketBuffer queryWithEDNS = packet;

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, false, newECSOption));
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  packet.resize(query.size());
  validateQuery(packet, false, 0, 1);

  /* packet with trailing data (overriding it) */
  packet = query;
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
  validateQuery(packet, true, 0, 1);
}

BOOST_AUTO_TEST_CASE(addECSWithoutEDNSAlreadyParsed)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1");
  ids.protocol = dnsdist::Protocol::DoUDP;
  bool ednsAdded = false;
  bool ecsAdded = false;
  DNSName name("www.powerdns.com.");

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;

  auto packet = query;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
  BOOST_CHECK_EQUAL(ids.qname, name);
  BOOST_CHECK(ids.qtype == QType::A);
  BOOST_CHECK(ids.qclass == QClass::IN);

  DNSQuestion dnsQuestion(ids, packet);
  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(!parseEDNSOptions(dnsQuestion));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dnsQuestion, ednsAdded, ecsAdded));
  BOOST_CHECK_GT(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, ids.origRemote);

  /* trailing data */
  packet = query;
  packet.resize(2048);

  ednsAdded = false;
  ecsAdded = false;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  ids.qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
  BOOST_CHECK_EQUAL(ids.qname, name);
  BOOST_CHECK(ids.qtype == QType::A);
  BOOST_CHECK(ids.qclass == QClass::IN);
  DNSQuestion dnsQuestion2(ids, packet);

  BOOST_CHECK(handleEDNSClientSubnet(dnsQuestion2, ednsAdded, ecsAdded));
  BOOST_CHECK_GT(packet.size(), query.size());
  BOOST_CHECK_LT(packet.size(), 2048U);
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, ids.origRemote);
}

BOOST_AUTO_TEST_CASE(addECSWithEDNSNoECS)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote;
  DNSName name("www.powerdns.com.");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  packetWriter.addOpt(512, 0, 0);
  packetWriter.commit();

  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, false, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
}

BOOST_AUTO_TEST_CASE(addECSWithEDNSNoECSAlreadyParsed)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("2001:DB8::1");
  ids.protocol = dnsdist::Protocol::DoUDP;
  bool ednsAdded = false;
  bool ecsAdded = false;
  DNSName name("www.powerdns.com.");

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  packetWriter.addOpt(512, 0, 0);
  packetWriter.commit();

  auto packet = query;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
  BOOST_CHECK_EQUAL(ids.qname, name);
  BOOST_CHECK(ids.qtype == QType::A);
  BOOST_CHECK(ids.qclass == QClass::IN);

  DNSQuestion dnsQuestion(ids, packet);
  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(parseEDNSOptions(dnsQuestion));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dnsQuestion, ednsAdded, ecsAdded));
  BOOST_CHECK_GT(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, ids.origRemote);

  /* trailing data */
  packet = query;
  packet.resize(2048);
  ednsAdded = false;
  ecsAdded = false;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
  BOOST_CHECK_EQUAL(ids.qname, name);
  BOOST_CHECK(ids.qtype == QType::A);
  BOOST_CHECK(ids.qclass == QClass::IN);
  DNSQuestion dnsQuestion2(ids, packet);

  BOOST_CHECK(handleEDNSClientSubnet(dnsQuestion2, ednsAdded, ecsAdded));
  BOOST_CHECK_GT(packet.size(), query.size());
  BOOST_CHECK_LT(packet.size(), 2048U);
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet);
  validateECS(packet, ids.origRemote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSameSize)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOption = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOption);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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

BOOST_AUTO_TEST_CASE(replaceECSWithSameSizeAlreadyParsed)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  ComboAddress origRemote("127.0.0.1");
  InternalQueryState ids;
  ids.origRemote = remote;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("www.powerdns.com.");

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, ids.qname, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOption = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOption);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  uint16_t qclass = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, ids.qname);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);

  DNSQuestion dnsQuestion(ids, packet);
  dnsQuestion.ecsOverride = true;

  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(parseEDNSOptions(dnsQuestion));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dnsQuestion, ednsAdded, ecsAdded));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
  validateECS(packet, remote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSmaller)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, 32));
  string origECSOption = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOption);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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

BOOST_AUTO_TEST_CASE(replaceECSWithLarger)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  // smaller (less specific so less bits) option
  static_assert(8 < ECSSourcePrefixV4, "The ECS scope should be smaller");
  ecsOpts.setSource(Netmask(origRemote, 8));
  string origECSOption = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOption);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet);
}

BOOST_AUTO_TEST_CASE(replaceECSFollowedByTSIG)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, 8));
  string origECSOption = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOption);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.startRecord(DNSName("tsigname."), QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  packetWriter.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 1);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 1);
}

BOOST_AUTO_TEST_CASE(replaceECSAfterAN)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  packetWriter.startRecord(DNSName("powerdns.com."), QType::A, 0, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.commit();
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, 8));
  string origECSOption = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOption);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 0, 1, 0);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 0, 1, 0);
}

BOOST_AUTO_TEST_CASE(replaceECSAfterAuth)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  packetWriter.startRecord(DNSName("powerdns.com."), QType::A, 0, QClass::IN, DNSResourceRecord::AUTHORITY, true);
  packetWriter.commit();
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, 8));
  string origECSOption = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOption);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 0, 0, 1);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 0, 0, 1);
}

BOOST_AUTO_TEST_CASE(replaceECSBetweenTwoRecords)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, 8));
  string origECSOption = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOption);
  packetWriter.startRecord(DNSName("additional"), QType::A, 0, QClass::IN, DNSResourceRecord::ADDITIONAL, false);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.startRecord(DNSName("tsigname."), QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  packetWriter.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 2);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 2);
}

BOOST_AUTO_TEST_CASE(insertECSInEDNSBetweenTwoRecords)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  packetWriter.startRecord(DNSName("additional"), QType::A, 0, QClass::IN, DNSResourceRecord::ADDITIONAL, false);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.addOpt(512, 0, 0);
  packetWriter.startRecord(DNSName("tsigname."), QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  packetWriter.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet, true, 2);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(query, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true, 2);
}

BOOST_AUTO_TEST_CASE(insertECSAfterTSIG)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  packetWriter.startRecord(DNSName("tsigname."), QType::TSIG, 0, QClass::ANY, DNSResourceRecord::ADDITIONAL, false);
  packetWriter.commit();

  /* large enough packet */
  auto packet = query;

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, 4096, consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK(packet.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  /* the MOADNSParser does not allow anything after a TSIG */
  BOOST_CHECK_THROW(validateQuery(packet, true, 1), MOADNSException);
  validateECS(packet, remote);

  /* not large enough packet */
  packet = query;

  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(packet, packet.size(), consumed, ednsAdded, ecsAdded, true, newECSOption));
  BOOST_CHECK_EQUAL(packet.size(), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, true);
}

BOOST_AUTO_TEST_CASE(removeEDNSWhenFirst)
{
  DNSName name("www.powerdns.com.");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.addOpt(512, 0, 0);
  packetWriter.commit();
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNS(response, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(newResponse.data()), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse(newResponse, false, 1);
}

BOOST_AUTO_TEST_CASE(removeEDNSWhenIntermediary)
{
  DNSName name("www.powerdns.com.");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.startRecord(DNSName("other.powerdns.com."), QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();
  packetWriter.addOpt(512, 0, 0);
  packetWriter.commit();
  packetWriter.startRecord(DNSName("yetanother.powerdns.com."), QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNS(response, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(newResponse.data()), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse(newResponse, false, 2);
}

BOOST_AUTO_TEST_CASE(removeEDNSWhenLast)
{
  DNSName name("www.powerdns.com.");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();
  packetWriter.startRecord(DNSName("other.powerdns.com."), QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();
  packetWriter.addOpt(512, 0, 0);
  packetWriter.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNS(response, newResponse);

  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(newResponse.data()), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse(newResponse, false, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenOnlyOption)
{
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);

  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(response, &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  res = removeEDNSOptionFromOPT(reinterpret_cast<char*>(&response.at(optStart)), &optLen, EDNSOptionCode::ECS);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(optLen, existingOptLen - (origECSOptionStr.size() + 4));
  responseLen -= (existingOptLen - optLen);

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(response.data()), responseLen, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(response, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenFirstOption)
{
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);

  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV6));
  string origECSOptionStr = ecsOpts.makeOptString();
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(response, &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  res = removeEDNSOptionFromOPT(reinterpret_cast<char*>(&response.at(optStart)), &optLen, EDNSOptionCode::ECS);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(optLen, existingOptLen - (origECSOptionStr.size() + 4));
  responseLen -= (existingOptLen - optLen);

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(response.data()), responseLen, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(response, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenIntermediaryOption)
{
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);

  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr1 = cookiesOpt.makeOptString();
  string cookiesOptionStr2 = cookiesOpt.makeOptString();

  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr1);
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr2);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(response, &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  res = removeEDNSOptionFromOPT(reinterpret_cast<char*>(&response.at(optStart)), &optLen, EDNSOptionCode::ECS);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(optLen, existingOptLen - (origECSOptionStr.size() + 4));
  responseLen -= (existingOptLen - optLen);

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(response.data()), responseLen, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(response, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenLastOption)
{
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);

  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  uint16_t optStart = 0;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(response, &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  res = removeEDNSOptionFromOPT(reinterpret_cast<char*>(&response.at(optStart)), &optLen, EDNSOptionCode::ECS);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(optLen, existingOptLen - (origECSOptionStr.size() + 4));
  responseLen -= (existingOptLen - optLen);

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(response.data()), responseLen, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(response, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenOnlyOption)
{
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(newResponse.data()), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(newResponse, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenFirstOption)
{
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(newResponse.data()), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(newResponse, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenIntermediaryOption)
{
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr1 = cookiesOpt.makeOptString();
  string cookiesOptionStr2 = cookiesOpt.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr1);
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr2);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(newResponse.data()), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(newResponse, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenLastOption)
{
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(response, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->qr = 1;
  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  packetWriter.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(origRemote, ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);
  packetWriter.addOpt(512, 0, 0, opts);
  packetWriter.commit();

  packetWriter.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  packetWriter.xfr32BitInt(0x01020304);
  packetWriter.commit();

  PacketBuffer newResponse;
  int res = rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  DNSName qname(reinterpret_cast<const char*>(newResponse.data()), newResponse.size(), sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse(newResponse, true, 1);
}

static DNSQuestion turnIntoResponse(InternalQueryState& ids, PacketBuffer& query, bool resizeBuffer = true)
{
  if (resizeBuffer) {
    query.resize(4096);
  }

  auto dnsQuestion = DNSQuestion(ids, query);

  BOOST_CHECK(addEDNSToQueryTurnedResponse(dnsQuestion));

  return dnsQuestion;
}

static int getZ(const DNSName& qname, const uint16_t qtype, const uint16_t qclass, PacketBuffer& query)
{
  InternalQueryState ids;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = qname;
  ids.qtype = qtype;
  ids.qclass = qclass;
  ids.origDest = ComboAddress("127.0.0.1");
  ids.origRemote = ComboAddress("127.0.0.1");
  ids.queryRealTime.start();

  auto dnsQuestion = DNSQuestion(ids, query);

  return dnsdist::getEDNSZ(dnsQuestion);
}

BOOST_AUTO_TEST_CASE(test_getEDNSZ)
{
  uint16_t zValue = 0;
  uint16_t udpPayloadSize = 0;
  DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(ComboAddress("127.0.0.1"), ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &zValue), false);
    BOOST_CHECK_EQUAL(zValue, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* truncated EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    packetWriter.commit();

    query.resize(query.size() - (/* RDLEN */ sizeof(uint16_t) + /* last byte of TTL / Z */ 1));
    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &zValue), false);
    BOOST_CHECK_EQUAL(zValue, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* valid EDNS, no options, DO not set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, 0);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &zValue), true);
    BOOST_CHECK_EQUAL(zValue, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

  {
    /* valid EDNS, no options, DO set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), EDNS_HEADER_FLAG_DO);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &zValue), true);
    BOOST_CHECK_EQUAL(zValue, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

  {
    /* valid EDNS, options, DO not set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, 0, opts);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &zValue), true);
    BOOST_CHECK_EQUAL(zValue, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

  {
    /* valid EDNS, options, DO set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO, opts);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), EDNS_HEADER_FLAG_DO);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &zValue), true);
    BOOST_CHECK_EQUAL(zValue, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }
}

BOOST_AUTO_TEST_CASE(test_getEDNSVersion)
{
  const DNSName qname("www.powerdns.com.");
  const uint16_t qtype = QType::A;
  const uint16_t qclass = QClass::IN;
  const GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;

  auto getVersion = [&qname](PacketBuffer& query) {
    InternalQueryState ids;
    ids.protocol = dnsdist::Protocol::DoUDP;
    ids.qname = qname;
    ids.qtype = qtype;
    ids.qclass = qclass;
    ids.origDest = ComboAddress("127.0.0.1");
    ids.origRemote = ComboAddress("127.0.0.1");
    ids.queryRealTime.start();

    auto dnsQuestion = DNSQuestion(ids, query);

    return dnsdist::getEDNSVersion(dnsQuestion);
  };

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.commit();

    BOOST_CHECK(getVersion(query) == std::nullopt);
  }

  {
    /* truncated EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    packetWriter.commit();

    query.resize(query.size() - (/* RDLEN */ sizeof(uint16_t) + /* TTL */ 2));
    BOOST_CHECK(getVersion(query) == std::nullopt);
  }

  {
    /* valid EDNS, no options */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, 0);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(*getVersion(query), 0U);
  }

  {
    /* EDNS version 255 */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO, opts, 255U);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(*getVersion(query), 255U);
  }
}

BOOST_AUTO_TEST_CASE(test_getEDNSExtendedRCode)
{
  const DNSName qname("www.powerdns.com.");
  const uint16_t qtype = QType::A;
  const uint16_t qclass = QClass::IN;

  auto getExtendedRCode = [&qname](PacketBuffer& query) {
    InternalQueryState ids;
    ids.protocol = dnsdist::Protocol::DoUDP;
    ids.qname = qname;
    ids.qtype = qtype;
    ids.qclass = qclass;
    ids.origDest = ComboAddress("127.0.0.1");
    ids.origRemote = ComboAddress("127.0.0.1");
    ids.queryRealTime.start();

    auto dnsQuestion = DNSQuestion(ids, query);

    return dnsdist::getEDNSExtendedRCode(dnsQuestion);
  };

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.commit();

    BOOST_CHECK(getExtendedRCode(query) == std::nullopt);
  }

  {
    /* truncated EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    packetWriter.commit();

    query.resize(query.size() - (/* RDLEN */ sizeof(uint16_t) + /* TTL */ 2));
    BOOST_CHECK(getExtendedRCode(query) == std::nullopt);
  }

  {
    /* valid EDNS, no options */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, 0);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(*getExtendedRCode(query), 0U);
  }

  {
    /* EDNS extended RCode 4095 (15 for the normal RCode, 255 for the EDNS part) */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 4095U, EDNS_HEADER_FLAG_DO);
    packetWriter.commit();

    BOOST_CHECK_EQUAL(*getExtendedRCode(query), 255U);
  }
}

BOOST_AUTO_TEST_CASE(test_addEDNSToQueryTurnedResponse)
{
  InternalQueryState ids;
  ids.qname = DNSName("www.powerdns.com.");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.origDest = ComboAddress("127.0.0.1");
  ids.origRemote = ComboAddress("127.0.0.1");
  ids.queryRealTime.start();
  uint16_t zValue = 0;
  uint16_t udpPayloadSize = 0;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(ComboAddress("127.0.0.1"), ECSSourcePrefixV4));
  string origECSOptionStr = ecsOpts.makeOptString();
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  opts.emplace_back(EDNSOptionCode::ECS, origECSOptionStr);

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, ids.qname, ids.qtype, ids.qclass, 0);
    packetWriter.getHeader()->qr = 1;
    packetWriter.getHeader()->rcode = RCode::NXDomain;
    packetWriter.commit();

    auto dnsQuestion = turnIntoResponse(ids, query);
    BOOST_CHECK_EQUAL(dnsdist::getEDNSZ(dnsQuestion), 0);
    BOOST_CHECK(dnsdist::getEDNSVersion(dnsQuestion) == std::nullopt);
    BOOST_CHECK(dnsdist::getEDNSExtendedRCode(dnsQuestion) == std::nullopt);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size(), &udpPayloadSize, &zValue), false);
    BOOST_CHECK_EQUAL(zValue, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* truncated EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, ids.qname, ids.qtype, ids.qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    packetWriter.commit();

    query.resize(query.size() - (/* RDLEN */ sizeof(uint16_t) + /* last byte of TTL / Z */ 1));
    auto dnsQuestion = turnIntoResponse(ids, query, false);
    BOOST_CHECK_EQUAL(dnsdist::getEDNSZ(dnsQuestion), 0);
    BOOST_CHECK(dnsdist::getEDNSVersion(dnsQuestion) == std::nullopt);
    BOOST_CHECK(dnsdist::getEDNSExtendedRCode(dnsQuestion) == std::nullopt);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size(), &udpPayloadSize, &zValue), false);
    BOOST_CHECK_EQUAL(zValue, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* valid EDNS, no options, DO not set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, ids.qname, ids.qtype, ids.qclass, 0);
    packetWriter.addOpt(512, 0, 0);
    packetWriter.commit();

    auto dnsQuestion = turnIntoResponse(ids, query);
    BOOST_CHECK_EQUAL(dnsdist::getEDNSZ(dnsQuestion), 0);
    BOOST_CHECK_EQUAL(*dnsdist::getEDNSVersion(dnsQuestion), 0U);
    BOOST_CHECK_EQUAL(*dnsdist::getEDNSExtendedRCode(dnsQuestion), 0U);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size(), &udpPayloadSize, &zValue), true);
    BOOST_CHECK_EQUAL(zValue, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, dnsdist::configuration::getCurrentRuntimeConfiguration().d_payloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, no options, DO set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, ids.qname, ids.qtype, ids.qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    packetWriter.commit();

    auto dnsQuestion = turnIntoResponse(ids, query);
    BOOST_CHECK_EQUAL(dnsdist::getEDNSZ(dnsQuestion), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(*dnsdist::getEDNSVersion(dnsQuestion), 0U);
    BOOST_CHECK_EQUAL(*dnsdist::getEDNSExtendedRCode(dnsQuestion), 0U);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size(), &udpPayloadSize, &zValue), true);
    BOOST_CHECK_EQUAL(zValue, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, dnsdist::configuration::getCurrentRuntimeConfiguration().d_payloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, options, DO not set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, ids.qname, ids.qtype, ids.qclass, 0);
    packetWriter.addOpt(512, 0, 0, opts);
    packetWriter.commit();

    auto dnsQuestion = turnIntoResponse(ids, query);
    BOOST_CHECK_EQUAL(dnsdist::getEDNSZ(dnsQuestion), 0);
    BOOST_CHECK_EQUAL(*dnsdist::getEDNSVersion(dnsQuestion), 0U);
    BOOST_CHECK_EQUAL(*dnsdist::getEDNSExtendedRCode(dnsQuestion), 0U);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size(), &udpPayloadSize, &zValue), true);
    BOOST_CHECK_EQUAL(zValue, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, dnsdist::configuration::getCurrentRuntimeConfiguration().d_payloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, options, DO set */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, ids.qname, ids.qtype, ids.qclass, 0);
    packetWriter.addOpt(512, 0, EDNS_HEADER_FLAG_DO, opts);
    packetWriter.commit();

    auto dnsQuestion = turnIntoResponse(ids, query);
    BOOST_CHECK_EQUAL(dnsdist::getEDNSZ(dnsQuestion), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(*dnsdist::getEDNSVersion(dnsQuestion), 0U);
    BOOST_CHECK_EQUAL(*dnsdist::getEDNSExtendedRCode(dnsQuestion), 0U);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size(), &udpPayloadSize, &zValue), true);
    BOOST_CHECK_EQUAL(zValue, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, dnsdist::configuration::getCurrentRuntimeConfiguration().d_payloadSizeSelfGenAnswers);
  }
}

BOOST_AUTO_TEST_CASE(test_getEDNSOptionsStart)
{
  const DNSName qname("www.powerdns.com.");
  const uint16_t qtype = QType::A;
  const uint16_t qclass = QClass::IN;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.setSource(Netmask(ComboAddress("127.0.0.1"), ECSSourcePrefixV4));
  const string ecsOptionStr = ecsOpts.makeOptString();
  GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
  opts.emplace_back(EDNSOptionCode::ECS, ecsOptionStr);
  const ComboAddress rem("127.0.0.1");
  uint16_t optRDPosition = 0;
  size_t remaining = 0;

  const size_t optRDExpectedOffset = sizeof(dnsheader) + qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + DNS_TTL_SIZE;

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.getHeader()->qr = 1;
    packetWriter.getHeader()->rcode = RCode::NXDomain;
    packetWriter.commit();

    int res = dnsdist::getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, ENOENT);

    /* truncated packet (should not matter) */
    query.resize(query.size() - 1);
    res = dnsdist::getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, ENOENT);
  }

  {
    /* valid EDNS, no options */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, 0);
    packetWriter.commit();

    int res = dnsdist::getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);

    /* truncated packet */
    query.resize(query.size() - 1);

    res = dnsdist::getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);
    BOOST_CHECK_EQUAL(res, ENOENT);
  }

  {
    /* valid EDNS, options */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, 0, opts);
    packetWriter.commit();

    int res = dnsdist::getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);

    /* truncated options (should not matter for this test) */
    query.resize(query.size() - 1);
    res = dnsdist::getEDNSOptionsStart(query, qname.wirelength(), &optRDPosition, &remaining);
    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);
  }
}

BOOST_AUTO_TEST_CASE(test_isEDNSOptionInOpt)
{

  auto locateEDNSOption = [](const PacketBuffer& query, uint16_t code, size_t* optContentStart, uint16_t* optContentLen) {
    uint16_t optStart = 0;
    size_t optLen = 0;
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
  ecsOpts.setSource(Netmask(ComboAddress("127.0.0.1"), ECSSourcePrefixV4));
  const string ecsOptionStr = ecsOpts.makeOptString();
  const size_t sizeOfECSContent = ecsOptionStr.size();
  const size_t sizeOfECSOption = /* option code */ 2 + /* option length */ 2 + sizeOfECSContent;
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();
  const size_t sizeOfCookieOption = /* option code */ 2 + /* option length */ 2 + cookiesOpt.size();
  /*
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
    opts.emplace_back(EDNSOptionCode::ECS, ecsOptionStr);
    opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
  */
  const ComboAddress rem("127.0.0.1");
  size_t optContentStart{std::numeric_limits<size_t>::max()};
  uint16_t optContentLen{0};

  const size_t optRDExpectedOffset = sizeof(dnsheader) + qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + DNS_TTL_SIZE;

  {
    /* no EDNS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.getHeader()->qr = 1;
    packetWriter.getHeader()->rcode = RCode::NXDomain;
    packetWriter.commit();

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
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    packetWriter.addOpt(512, 0, 0);
    packetWriter.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, false);

    /* truncated packet */
    query.resize(query.size() - 1);
    BOOST_CHECK_THROW(locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen), std::out_of_range);
  }

  {
    /* valid EDNS, two cookie options but no ECS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
    opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
    packetWriter.addOpt(512, 0, 0, opts);
    packetWriter.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, false);

    /* truncated packet */
    query.resize(query.size() - 1);
    BOOST_CHECK_THROW(locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen), std::range_error);
  }

  {
    /* valid EDNS, two ECS */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.emplace_back(EDNSOptionCode::ECS, ecsOptionStr);
    opts.emplace_back(EDNSOptionCode::ECS, ecsOptionStr);
    packetWriter.addOpt(512, 0, 0, opts);
    packetWriter.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, true);
    if (found) {
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
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
    opts.emplace_back(EDNSOptionCode::ECS, ecsOptionStr);
    opts.emplace_back(EDNSOptionCode::COOKIE, cookiesOptionStr);
    packetWriter.addOpt(512, 0, 0, opts);
    packetWriter.commit();

    bool found = locateEDNSOption(query, EDNSOptionCode::ECS, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, true);
    if (found) {
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
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, qname, qtype, qclass, 0);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t opts;
    opts.emplace_back(EDNSOptionCode::ECS, ecsOptionStr);
    opts.emplace_back(65535, cookiesOptionStr);
    packetWriter.addOpt(512, 0, 0, opts);
    packetWriter.commit();

    bool found = locateEDNSOption(query, 65535, &optContentStart, &optContentLen);
    BOOST_CHECK_EQUAL(found, true);
    if (found) {
      BOOST_CHECK_EQUAL(optContentStart, optRDExpectedOffset + sizeof(uint16_t) /* RD len */ + sizeOfECSOption + /* option code */ 2 + /* option length */ 2);
      BOOST_CHECK_EQUAL(optContentLen, cookiesOptionStr.size());
    }

    /* truncated packet */
    query.resize(query.size() - 1);
    BOOST_CHECK_THROW(locateEDNSOption(query, 65002, &optContentStart, &optContentLen), std::range_error);
  }
}

BOOST_AUTO_TEST_CASE(test_setNegativeAndAdditionalSOA)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1");
  ids.protocol = dnsdist::Protocol::DoUDP;

  ComboAddress remote;
  DNSName name("www.powerdns.com.");

  PacketBuffer query;
  PacketBuffer queryWithEDNS;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
  packetWriter.getHeader()->rd = 1;
  GenericDNSPacketWriter<PacketBuffer> packetWriterEDNS(queryWithEDNS, name, QType::A, QClass::IN, 0);
  packetWriterEDNS.getHeader()->rd = 1;
  packetWriterEDNS.addOpt(1232, 0, 0);
  packetWriterEDNS.commit();

  /* test NXD */
  {
    /* no incoming EDNS */
    auto packet = query;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, nullptr);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dnsQuestion, true, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4, 5, false));
    BOOST_CHECK(packet.size() > query.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NXDomain);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 1U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, DNSName("zone."));
  }
  {
    /* now with incoming EDNS */
    auto packet = queryWithEDNS;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, nullptr);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dnsQuestion, true, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4, 5, false));
    BOOST_CHECK(packet.size() > queryWithEDNS.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NXDomain);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 2U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 2U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, DNSName("zone."));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_name, g_rootdnsname);
  }

  /* test No Data */
  {
    /* no incoming EDNS */
    auto packet = query;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, nullptr);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dnsQuestion, false, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4, 5, false));
    BOOST_CHECK(packet.size() > query.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NoError);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 1U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, DNSName("zone."));
  }
  {
    /* now with incoming EDNS */
    auto packet = queryWithEDNS;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, nullptr);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dnsQuestion, false, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4, 5, false));
    BOOST_CHECK(packet.size() > queryWithEDNS.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NoError);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 2U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 2U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, DNSName("zone."));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_name, g_rootdnsname);
  }

  /* SOA in the authority section*/

  /* test NXD */
  {
    /* no incoming EDNS */
    auto packet = query;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, nullptr);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dnsQuestion, true, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4,
                                            5, true));
    BOOST_CHECK(packet.size() > query.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NXDomain);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 1U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, DNSName("zone."));
  }
  {
    /* now with incoming EDNS */
    auto packet = queryWithEDNS;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, nullptr);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dnsQuestion, true, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4, 5, true));
    BOOST_CHECK(packet.size() > queryWithEDNS.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NXDomain);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 2U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, DNSName("zone."));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_name, g_rootdnsname);
  }

  /* test No Data */
  {
    /* no incoming EDNS */
    auto packet = query;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, nullptr);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dnsQuestion, false, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4, 5, true));
    BOOST_CHECK(packet.size() > query.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NoError);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 1U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, DNSName("zone."));
  }
  {
    /* now with incoming EDNS */
    auto packet = queryWithEDNS;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &ids.qtype, nullptr);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(setNegativeAndAdditionalSOA(dnsQuestion, false, DNSName("zone."), 42, DNSName("mname."), DNSName("rname."), 1, 2, 3, 4, 5, true));
    BOOST_CHECK(packet.size() > queryWithEDNS.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    MOADNSParser mdp(true, reinterpret_cast<const char*>(packet.data()), packet.size());

    BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");
    BOOST_CHECK_EQUAL(mdp.d_header.rcode, RCode::NoError);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);
    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 2U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::SOA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, DNSName("zone."));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_name, g_rootdnsname);
  }
}

BOOST_AUTO_TEST_CASE(getEDNSOptionsWithoutEDNS)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.168.1.25");
  ids.protocol = dnsdist::Protocol::DoUDP;

  const DNSName name("www.powerdns.com.");
  const ComboAddress v4Addr("192.0.2.1");

  {
    /* no EDNS and no other additional record */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
    packetWriter.getHeader()->rd = 1;
    packetWriter.commit();

    /* large enough packet */
    auto packet = query;

    unsigned int consumed = 0;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(!parseEDNSOptions(dnsQuestion));
  }

  {
    /* nothing in additional (so no EDNS) but a record in ANSWER */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
    packetWriter.getHeader()->rd = 1;
    packetWriter.startRecord(name, QType::A, 60, QClass::IN, DNSResourceRecord::ANSWER);
    packetWriter.xfrIP(v4Addr.sin4.sin_addr.s_addr);
    packetWriter.commit();

    /* large enough packet */
    auto packet = query;

    unsigned int consumed = 0;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(!parseEDNSOptions(dnsQuestion));
  }

  {
    /* nothing in additional (so no EDNS) but a record in AUTHORITY */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> packetWriter(query, name, QType::A, QClass::IN, 0);
    packetWriter.getHeader()->rd = 1;
    packetWriter.startRecord(name, QType::A, 60, QClass::IN, DNSResourceRecord::AUTHORITY);
    packetWriter.xfrIP(v4Addr.sin4.sin_addr.s_addr);
    packetWriter.commit();

    /* large enough packet */
    auto packet = query;

    unsigned int consumed = 0;
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DNSName qname(reinterpret_cast<const char*>(packet.data()), packet.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dnsQuestion(ids, packet);

    BOOST_CHECK(!parseEDNSOptions(dnsQuestion));
  }
}

BOOST_AUTO_TEST_CASE(test_setEDNSOption)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:42");
  ids.origDest = ComboAddress("127.0.0.1:53");
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("powerdns.com.");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.queryRealTime.start();

  timespec expiredTime{};
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  PacketBuffer packet;
  GenericDNSPacketWriter<PacketBuffer> packetWriter(packet, ids.qname, ids.qtype, ids.qclass, 0);
  packetWriter.addOpt(4096, 0, EDNS_HEADER_FLAG_DO);
  packetWriter.commit();

  DNSQuestion dnsQuestion(ids, packet);

  std::string result;
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();

  BOOST_REQUIRE(setEDNSOption(dnsQuestion, EDNSOptionCode::COOKIE, cookiesOptionStr));

  const auto& data = dnsQuestion.getData();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  MOADNSParser mdp(true, reinterpret_cast<const char*>(data.data()), data.size());

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), ids.qname.toString());
  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::OPT));
  BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, g_rootdnsname);

  EDNS0Record edns0{};
  BOOST_REQUIRE(getEDNS0Record(dnsQuestion.getData(), edns0));
  BOOST_CHECK_EQUAL(edns0.version, 0U);
  BOOST_CHECK_EQUAL(edns0.extRCode, 0U);
  BOOST_CHECK_EQUAL(ntohs(edns0.extFlags), EDNS_HEADER_FLAG_DO);

  BOOST_REQUIRE(parseEDNSOptions(dnsQuestion));
  BOOST_REQUIRE(dnsQuestion.ednsOptions != nullptr);
  BOOST_CHECK_EQUAL(dnsQuestion.ednsOptions->size(), 1U);
  const auto& ecsOption = dnsQuestion.ednsOptions->find(EDNSOptionCode::COOKIE);
  BOOST_REQUIRE(ecsOption != dnsQuestion.ednsOptions->cend());

  BOOST_REQUIRE_EQUAL(ecsOption->second.values.size(), 1U);
  BOOST_CHECK_EQUAL(cookiesOptionStr, std::string(ecsOption->second.values.at(0).content, ecsOption->second.values.at(0).size));
}

BOOST_AUTO_TEST_SUITE_END();
