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

static void validateQuery(const char * packet, size_t packetSize, bool hasEdns=true, bool hasXPF=false)
{
  MOADNSParser mdp(true, packet, packetSize);

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  uint16_t expectedARCount = 0 + (hasEdns ? 1 : 0) + (hasXPF ? 1 : 0);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, expectedARCount);
}

static void validateECS(const char* packet, size_t packetSize, const ComboAddress& expected)
{
  ComboAddress rem("::1");
  unsigned int consumed = 0;
  uint16_t qtype;
  uint16_t qclass;
  DNSName qname(packet, packetSize, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  DNSQuestion dq(&qname, qtype, qclass, consumed, nullptr, &rem, const_cast<dnsheader*>(reinterpret_cast<const dnsheader*>(packet)), packetSize, packetSize, false, nullptr);
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

static void validateResponse(const char * packet, size_t packetSize, bool hasEdns, uint8_t additionalCount=0)
{
  MOADNSParser mdp(false, packet, packetSize);

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

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  const uint16_t len = query.size();
  vector<uint8_t> queryWithXPF;

  {
    char packet[1500];
    memcpy(packet, query.data(), query.size());

    /* large enough packet */
    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    BOOST_CHECK_EQUAL(qname, name);
    BOOST_CHECK(qtype == QType::A);

    auto dh = reinterpret_cast<dnsheader*>(packet);
    DNSQuestion dq(&qname, qtype, QClass::IN, qname.wirelength(), &remote, &remote, dh, sizeof(packet), query.size(), false, &queryTime);

    BOOST_CHECK(addXPF(dq, xpfOptionCode, false));
    BOOST_CHECK(static_cast<size_t>(dq.len) > query.size());
    validateQuery(packet, dq.len, false, true);
    queryWithXPF.resize(dq.len);
    memcpy(queryWithXPF.data(), packet, dq.len);
  }

  {
    char packet[1500];
    memcpy(packet, query.data(), query.size());

    /* not large enough packet */
    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    BOOST_CHECK_EQUAL(qname, name);
    BOOST_CHECK(qtype == QType::A);

    auto dh = reinterpret_cast<dnsheader*>(packet);
    DNSQuestion dq(&qname, qtype, QClass::IN, qname.wirelength(), &remote, &remote, dh, sizeof(packet), query.size(), false, &queryTime);
    dq.size = dq.len;

    BOOST_CHECK(!addXPF(dq, xpfOptionCode, false));
    BOOST_CHECK_EQUAL(static_cast<size_t>(dq.len), query.size());
    validateQuery(packet, dq.len, false, false);
  }

  {
    char packet[1500];
    memcpy(packet, query.data(), query.size());

    /* packet with trailing data (overriding it) */
    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    BOOST_CHECK_EQUAL(qname, name);
    BOOST_CHECK(qtype == QType::A);

    auto dh = reinterpret_cast<dnsheader*>(packet);
    DNSQuestion dq(&qname, qtype, QClass::IN, qname.wirelength(), &remote, &remote, dh, sizeof(packet), query.size(), false, &queryTime);

    /* add trailing data */
    const size_t trailingDataSize = 10;
    /* Making sure we have enough room to allow for fake trailing data */
    BOOST_REQUIRE(sizeof(packet) > dq.len && (sizeof(packet) - dq.len) > trailingDataSize);
    for (size_t idx = 0; idx < trailingDataSize; idx++) {
      packet[dq.len + idx] = 'A';
    }
    dq.len += trailingDataSize;

    BOOST_CHECK(addXPF(dq, xpfOptionCode, false));
    BOOST_CHECK_EQUAL(static_cast<size_t>(dq.len), queryWithXPF.size());
    BOOST_CHECK_EQUAL(memcmp(queryWithXPF.data(), packet, queryWithXPF.size()), 0);
    validateQuery(packet, dq.len, false, true);
  }

  {
    char packet[1500];
    memcpy(packet, query.data(), query.size());

    /* packet with trailing data (preserving trailing data) */
    unsigned int consumed = 0;
    uint16_t qtype;
    DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
    BOOST_CHECK_EQUAL(qname, name);
    BOOST_CHECK(qtype == QType::A);

    auto dh = reinterpret_cast<dnsheader*>(packet);
    DNSQuestion dq(&qname, qtype, QClass::IN, qname.wirelength(), &remote, &remote, dh, sizeof(packet), query.size(), false, &queryTime);

    /* add trailing data */
    const size_t trailingDataSize = 10;
    /* Making sure we have enough room to allow for fake trailing data */
    BOOST_REQUIRE(sizeof(packet) > dq.len && (sizeof(packet) - dq.len) > trailingDataSize);
    for (size_t idx = 0; idx < trailingDataSize; idx++) {
      packet[dq.len + idx] = 'A';
    }
    dq.len += trailingDataSize;

    BOOST_CHECK(addXPF(dq, xpfOptionCode, true));
    BOOST_CHECK(static_cast<size_t>(dq.len) > queryWithXPF.size());
    BOOST_CHECK_EQUAL(memcmp(queryWithXPF.data(), packet, queryWithXPF.size()), 0);
    for (size_t idx = 0; idx < trailingDataSize; idx++) {
      BOOST_CHECK_EQUAL(packet[queryWithXPF.size() + idx], 'A');
    }
    validateQuery(packet, dq.len, false, true);
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

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  uint16_t len = query.size();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, false, newECSOption, false));
  BOOST_CHECK(static_cast<size_t>(len) > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);
  validateECS(packet, len, remote);
  vector<uint8_t> queryWithEDNS;
  queryWithEDNS.resize(len);
  memcpy(queryWithEDNS.data(), packet, len);

  /* not large enough packet */
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  len = query.size();
  qname = DNSName(reinterpret_cast<char*>(query.data()), len, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(reinterpret_cast<char*>(query.data()), query.size(), consumed, &len, &ednsAdded, &ecsAdded, false, newECSOption, false));
  BOOST_CHECK_EQUAL(static_cast<size_t>(len), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(reinterpret_cast<char*>(query.data()), len, false);

  /* packet with trailing data (overriding it) */
  memcpy(packet, query.data(), query.size());
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  len = query.size();
  qname = DNSName(packet, len, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  /* add trailing data */
  const size_t trailingDataSize = 10;
  /* Making sure we have enough room to allow for fake trailing data */
  BOOST_REQUIRE(sizeof(packet) > len && (sizeof(packet) - len) > trailingDataSize);
  for (size_t idx = 0; idx < trailingDataSize; idx++) {
    packet[len + idx] = 'A';
  }
  len += trailingDataSize;
  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, false, newECSOption, false));
  BOOST_REQUIRE_EQUAL(static_cast<size_t>(len), queryWithEDNS.size());
  BOOST_CHECK_EQUAL(memcmp(queryWithEDNS.data(), packet, queryWithEDNS.size()), 0);
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);

  /* packet with trailing data (preserving trailing data) */
  memcpy(packet, query.data(), query.size());
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  len = query.size();
  qname = DNSName(packet, len, sizeof(dnsheader), false, &qtype, nullptr, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  /* add trailing data */
  /* Making sure we have enough room to allow for fake trailing data */
  BOOST_REQUIRE(sizeof(packet) > len && (sizeof(packet) - len) > trailingDataSize);
  for (size_t idx = 0; idx < trailingDataSize; idx++) {
    packet[len + idx] = 'A';
  }
  len += trailingDataSize;
  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, false, newECSOption, true));
  BOOST_REQUIRE_EQUAL(static_cast<size_t>(len), queryWithEDNS.size() + trailingDataSize);
  BOOST_CHECK_EQUAL(memcmp(queryWithEDNS.data(), packet, queryWithEDNS.size()), 0);
  for (size_t idx = 0; idx < trailingDataSize; idx++) {
    BOOST_CHECK_EQUAL(packet[queryWithEDNS.size() + idx], 'A');
  }
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);
}

BOOST_AUTO_TEST_CASE(addECSWithoutEDNSAlreadyParsed)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.0.2.1");
  DNSName name("www.powerdns.com.");

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  uint16_t qclass;
  DNSName qname(packet, query.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);

  DNSQuestion dq(&qname, qtype, qclass, consumed, nullptr, &remote, reinterpret_cast<dnsheader*>(packet), sizeof(packet), query.size(), false, nullptr);
  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(!parseEDNSOptions(dq));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dq, &ednsAdded, &ecsAdded, false));
  BOOST_CHECK_GT(static_cast<size_t>(dq.len), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, dq.len);
  validateECS(packet, dq.len, remote);

  /* not large enough packet */
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  qname = DNSName(reinterpret_cast<char*>(query.data()), query.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);
  DNSQuestion dq2(&qname, qtype, qclass, consumed, nullptr, &remote, reinterpret_cast<dnsheader*>(query.data()), query.size(), query.size(), false, nullptr);

  BOOST_CHECK(!handleEDNSClientSubnet(dq2, &ednsAdded, &ecsAdded, false));
  BOOST_CHECK_EQUAL(static_cast<size_t>(dq2.len), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(reinterpret_cast<char*>(query.data()), dq2.len, false);
}

BOOST_AUTO_TEST_CASE(addECSWithEDNSNoECS) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote;
  DNSName name("www.powerdns.com.");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  pw.addOpt(512, 0, 0);
  pw.commit();
  uint16_t len = query.size();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, false, newECSOption, false));
  BOOST_CHECK((size_t) len > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet, len);
  validateECS(packet, len, remote);

  /* not large enough packet */
  consumed = 0;
  ednsAdded = false;
  ecsAdded = false;
  len = query.size();
  qname = DNSName(reinterpret_cast<char*>(query.data()), len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(reinterpret_cast<char*>(query.data()), query.size(), consumed, &len, &ednsAdded, &ecsAdded, false, newECSOption, false));
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(reinterpret_cast<char*>(query.data()), len);
}

BOOST_AUTO_TEST_CASE(addECSWithEDNSNoECSAlreadyParsed) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("2001:DB8::1");
  DNSName name("www.powerdns.com.");

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  pw.addOpt(512, 0, 0);
  pw.commit();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  uint16_t qclass;
  DNSName qname(packet, query.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);

  DNSQuestion dq(&qname, qtype, qclass, consumed, nullptr, &remote, reinterpret_cast<dnsheader*>(packet), sizeof(packet), query.size(), false, nullptr);
  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(parseEDNSOptions(dq));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dq, &ednsAdded, &ecsAdded, false));
  BOOST_CHECK_GT(static_cast<size_t>(dq.len), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet, dq.len);
  validateECS(packet, dq.len, remote);

  /* not large enough packet */
  consumed = 0;
  ednsAdded = false;
  ecsAdded = false;
  qname = DNSName(reinterpret_cast<char*>(query.data()), query.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);
  DNSQuestion dq2(&qname, qtype, qclass, consumed, nullptr, &remote, reinterpret_cast<dnsheader*>(query.data()), query.size(), query.size(), false, nullptr);

  BOOST_CHECK(!handleEDNSClientSubnet(dq2, &ednsAdded, &ecsAdded, false));
  BOOST_CHECK_EQUAL(static_cast<size_t>(dq2.len), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(reinterpret_cast<char*>(query.data()), dq2.len);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSameSize) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();
  uint16_t len = query.size();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, true, newECSOption, false));
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);
  validateECS(packet, len, remote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSameSizeAlreadyParsed) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  uint16_t qclass;
  DNSName qname(packet, query.size(), sizeof(dnsheader), false, &qtype, &qclass, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  BOOST_CHECK(qclass == QClass::IN);

  DNSQuestion dq(&qname, qtype, qclass, consumed, nullptr, &remote, reinterpret_cast<dnsheader*>(packet), sizeof(packet), query.size(), false, nullptr);
  dq.ecsOverride = true;

  /* Parse the options before handling ECS, simulating a Lua rule asking for EDNS Options */
  BOOST_CHECK(parseEDNSOptions(dq));

  /* And now we add our own ECS */
  BOOST_CHECK(handleEDNSClientSubnet(dq, &ednsAdded, &ecsAdded, false));
  BOOST_CHECK_EQUAL(static_cast<size_t>(dq.len), query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, dq.len);
  validateECS(packet, dq.len, remote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSmaller) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 32);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();
  uint16_t len = query.size();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, true, newECSOption, false));
  BOOST_CHECK((size_t) len < query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);
  validateECS(packet, len, remote);
}

BOOST_AUTO_TEST_CASE(replaceECSWithLarger) {
  bool ednsAdded = false;
  bool ecsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");
  string newECSOption;
  generateECSOption(remote, newECSOption, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6);

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 8);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOption));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();
  uint16_t len = query.size();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, true, newECSOption, false));
  BOOST_CHECK((size_t) len > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);
  validateECS(packet, len, remote);

  /* not large enough packet */
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  len = query.size();
  qname = DNSName(reinterpret_cast<char*>(query.data()), len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(reinterpret_cast<char*>(query.data()), query.size(), consumed, &len, &ednsAdded, &ecsAdded, true, newECSOption, false));
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(reinterpret_cast<char*>(query.data()), len);
}

BOOST_AUTO_TEST_CASE(removeEDNSWhenFirst) {
  DNSName name("www.powerdns.com.");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);
  pw.addOpt(512, 0, 0);
  pw.commit();
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  vector<uint8_t> newResponse;
  int res = rewriteResponseWithoutEDNS(std::string((const char *) response.data(), response.size()), newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse((const char *) newResponse.data(), newResponse.size(), false, 1);
}

BOOST_AUTO_TEST_CASE(removeEDNSWhenIntermediary) {
  DNSName name("www.powerdns.com.");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
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

  vector<uint8_t> newResponse;
  int res = rewriteResponseWithoutEDNS(std::string((const char *) response.data(), response.size()), newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse((const char *) newResponse.data(), newResponse.size(), false, 2);
}

BOOST_AUTO_TEST_CASE(removeEDNSWhenLast) {
  DNSName name("www.powerdns.com.");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();
  pw.startRecord(DNSName("other.powerdns.com."), QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();
  pw.addOpt(512, 0, 0);
  pw.commit();

  vector<uint8_t> newResponse;
  int res = rewriteResponseWithoutEDNS(std::string((const char *) response.data(), response.size()), newResponse);

  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse((const char *) newResponse.data(), newResponse.size(), false, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenOnlyOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(std::string((char *) response.data(), response.size()), &optStart, &optLen, &last);
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
  DNSName qname((const char*) response.data(), responseLen, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) response.data(), responseLen, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenFirstOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
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
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(std::string((char *) response.data(), response.size()), &optStart, &optLen, &last);
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
  DNSName qname((const char*) response.data(), responseLen, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) response.data(), responseLen, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenIntermediaryOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
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

  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr1));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr2));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(std::string((char *) response.data(), response.size()), &optStart, &optLen, &last);
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
  DNSName qname((const char*) response.data(), responseLen, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) response.data(), responseLen, true, 1);
}

BOOST_AUTO_TEST_CASE(removeECSWhenLastOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
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
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  uint16_t optStart;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR(std::string((char *) response.data(), response.size()), &optStart, &optLen, &last);
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
  DNSName qname((const char*) response.data(), responseLen, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) response.data(), responseLen, true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenOnlyOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);

  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, ECSSourcePrefixV4);
  string origECSOptionStr = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  vector<uint8_t> newResponse;
  int res = rewriteResponseWithoutEDNSOption(std::string((const char *) response.data(), response.size()), EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) newResponse.data(), newResponse.size(), true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenFirstOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
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
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  vector<uint8_t> newResponse;
  int res = rewriteResponseWithoutEDNSOption(std::string((const char *) response.data(), response.size()), EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) newResponse.data(), newResponse.size(), true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenIntermediaryOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
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
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr1));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr2));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  vector<uint8_t> newResponse;
  int res = rewriteResponseWithoutEDNSOption(std::string((const char *) response.data(), response.size()), EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) newResponse.data(), newResponse.size(), true, 1);
}

BOOST_AUTO_TEST_CASE(rewritingWithoutECSWhenLastOption) {
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
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
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  pw.addOpt(512, 0, 0, opts);
  pw.commit();

  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ADDITIONAL, true);
  pw.xfr32BitInt(0x01020304);
  pw.commit();

  vector<uint8_t> newResponse;
  int res = rewriteResponseWithoutEDNSOption(std::string((const char *) response.data(), response.size()), EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) newResponse.data(), newResponse.size(), true, 1);
}

static DNSQuestion getDNSQuestion(const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& lc, const ComboAddress& rem, const struct timespec& realTime, vector<uint8_t>& query, size_t len)
{
  dnsheader* dh = reinterpret_cast<dnsheader*>(query.data());

  return DNSQuestion(&qname, qtype, qclass, qname.wirelength(), &lc, &rem, dh, query.size(), len, false, &realTime);
}

static DNSQuestion turnIntoResponse(const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& lc, const ComboAddress& rem, const struct timespec& queryRealTime, vector<uint8_t>&  query, bool resizeBuffer=true)
{
  size_t length = query.size();
  if (resizeBuffer) {
    query.resize(4096);
  }

  auto dq = getDNSQuestion(qname, qtype, qclass, lc, rem, queryRealTime, query, length);

  BOOST_CHECK(addEDNSToQueryTurnedResponse(dq));

  return dq;
}

static int getZ(const DNSName& qname, const uint16_t qtype, const uint16_t qclass, vector<uint8_t>& query)
{
  ComboAddress lc("127.0.0.1");
  ComboAddress rem("127.0.0.1");
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);
  size_t length = query.size();
  DNSQuestion dq = getDNSQuestion(qname, qtype, qclass, lc, rem, queryRealTime, query, length);

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
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));

  {
    /* no EDNS */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), false);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* truncated EDNS */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
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
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

  {
    /* valid EDNS, no options, DO set */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

    {
    /* valid EDNS, options, DO not set */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    BOOST_CHECK_EQUAL(getZ(qname, qtype, qclass, query), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 512);
  }

  {
    /* valid EDNS, options, DO set */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
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
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::COOKIE, cookiesOptionStr));
  opts.push_back(make_pair(EDNSOptionCode::ECS, origECSOptionStr));
  ComboAddress lc("127.0.0.1");
  ComboAddress rem("127.0.0.1");
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);

  {
    /* no EDNS */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.getHeader()->qr = 1;
    pw.getHeader()->rcode = RCode::NXDomain;
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.dh), dq.len, &udpPayloadSize, &z), false);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* truncated EDNS */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pw.commit();

    query.resize(query.size() - (/* RDLEN */ sizeof(uint16_t) + /* last byte of TTL / Z */ 1));
    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.dh), dq.len, &udpPayloadSize, &z), false);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, 0);
  }

  {
    /* valid EDNS, no options, DO not set */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0);
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.dh), dq.len, &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, g_PayloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, no options, DO set */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.dh), dq.len, &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(udpPayloadSize, g_PayloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, options, DO not set */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), 0);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.dh), dq.len, &udpPayloadSize, &z), true);
    BOOST_CHECK_EQUAL(z, 0);
    BOOST_CHECK_EQUAL(udpPayloadSize, g_PayloadSizeSelfGenAnswers);
  }

  {
    /* valid EDNS, options, DO set */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, EDNS_HEADER_FLAG_DO, opts);
    pw.commit();

    auto dq = turnIntoResponse(qname, qtype, qclass, lc, rem, queryRealTime, query);
    BOOST_CHECK_EQUAL(getEDNSZ(dq), EDNS_HEADER_FLAG_DO);
    BOOST_CHECK_EQUAL(getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(dq.dh), dq.len, &udpPayloadSize, &z), true);
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
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNSOptionCode::ECS, ecsOptionStr));
  const ComboAddress lc("127.0.0.1");
  const ComboAddress rem("127.0.0.1");
  uint16_t optRDPosition;
  size_t remaining;

  const size_t optRDExpectedOffset = sizeof(dnsheader) + qname.wirelength() + DNS_TYPE_SIZE + DNS_CLASS_SIZE + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + DNS_TTL_SIZE;

  {
    /* no EDNS */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.getHeader()->qr = 1;
    pw.getHeader()->rcode = RCode::NXDomain;
    pw.commit();

    int res = getEDNSOptionsStart(reinterpret_cast<const char*>(query.data()), qname.wirelength(), query.size(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, ENOENT);

    /* truncated packet (should not matter) */
    query.resize(query.size() - 1);
    res = getEDNSOptionsStart(reinterpret_cast<const char*>(query.data()), qname.wirelength(), query.size(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, ENOENT);
  }

  {
    /* valid EDNS, no options */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0);
    pw.commit();

    int res = getEDNSOptionsStart(reinterpret_cast<const char*>(query.data()), qname.wirelength(), query.size(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);

    /* truncated packet */
    query.resize(query.size() - 1);

    res = getEDNSOptionsStart(reinterpret_cast<const char*>(query.data()), qname.wirelength(), query.size(), &optRDPosition, &remaining);
    BOOST_CHECK_EQUAL(res, ENOENT);
  }

  {
    /* valid EDNS, options */
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    pw.addOpt(512, 0, 0, opts);
    pw.commit();

    int res = getEDNSOptionsStart(reinterpret_cast<const char*>(query.data()), qname.wirelength(), query.size(), &optRDPosition, &remaining);

    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);

    /* truncated options (should not matter for this test) */
    query.resize(query.size() - 1);
    res = getEDNSOptionsStart(reinterpret_cast<const char*>(query.data()), qname.wirelength(), query.size(), &optRDPosition, &remaining);
    BOOST_CHECK_EQUAL(res, 0);
    BOOST_CHECK_EQUAL(optRDPosition, optRDExpectedOffset);
    BOOST_CHECK_EQUAL(remaining, query.size() - optRDExpectedOffset);
  }

}

BOOST_AUTO_TEST_CASE(test_isEDNSOptionInOpt) {

  auto locateEDNSOption = [](const vector<uint8_t>& query, uint16_t code, size_t* optContentStart, uint16_t* optContentLen) {
    uint16_t optStart;
    size_t optLen;
    bool last = false;
    std::string packetStr(reinterpret_cast<const char*>(query.data()), query.size());
    int res = locateEDNSOptRR(packetStr, &optStart, &optLen, &last);
    if (res != 0) {
      // no EDNS OPT RR
      return false;
    }

    if (optLen < optRecordMinimumSize) {
      return false;
    }

    if (optStart < query.size() && packetStr.at(optStart) != 0) {
      // OPT RR Name != '.'
      return false;
    }

    return isEDNSOptionInOpt(packetStr, optStart, optLen, code, optContentStart, optContentLen);
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
    DNSPacketWriter::optvect_t opts;
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
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
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
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
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
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    DNSPacketWriter::optvect_t opts;
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
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    DNSPacketWriter::optvect_t opts;
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
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    DNSPacketWriter::optvect_t opts;
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
    vector<uint8_t> query;
    DNSPacketWriter pw(query, qname, qtype, qclass, 0);
    DNSPacketWriter::optvect_t opts;
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

BOOST_AUTO_TEST_SUITE_END();
