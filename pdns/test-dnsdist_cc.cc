
/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2013 - 2015  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dolog.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednssubnet.hh"
#include <unistd.h>

BOOST_AUTO_TEST_SUITE(dnsdist_cc)

bool g_console{true};
bool g_verbose{true};

static void validateQuery(const char * packet, size_t packetSize)
{
  MOADNSParser mdp(packet, packetSize);

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1);
}

static void validateResponse(const char * packet, size_t packetSize, bool hasEdns)
{
  MOADNSParser mdp(packet, packetSize);

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qr, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, hasEdns ? 1 : 0);
}

BOOST_AUTO_TEST_CASE(addECSWithoutEDNS)
{
  string largerPacket;
  bool ednsAdded = false;
  ComboAddress remote;
  DNSName name("www.powerdns.com.");

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  uint16_t len = query.size();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, largerPacket, &ednsAdded, remote);
  BOOST_CHECK((size_t) len > query.size());
  BOOST_CHECK_EQUAL(largerPacket.size(), 0);
  BOOST_CHECK_EQUAL(ednsAdded, true);
  validateQuery(packet, len);

  /* not large enought packet */
  consumed = 0;
  len = query.size();
  qname = DNSName((char*) query.data(), len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  handleEDNSClientSubnet((char*) query.data(), query.size(), consumed, &len, largerPacket, &ednsAdded, remote);
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK(largerPacket.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  validateQuery(largerPacket.c_str(), largerPacket.size());
}

BOOST_AUTO_TEST_CASE(addECSWithEDNSNoECS) {
  string largerPacket;
  bool ednsAdded = false;
  ComboAddress remote;
  DNSName name("www.powerdns.com.");

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

  handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, largerPacket, &ednsAdded, remote);
  BOOST_CHECK((size_t) len > query.size());
  BOOST_CHECK_EQUAL(largerPacket.size(), 0);
  BOOST_CHECK_EQUAL(ednsAdded, false);
  validateQuery(packet, len);

  /* not large enought packet */
  consumed = 0;
  len = query.size();
  qname = DNSName((char*) query.data(), len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  handleEDNSClientSubnet((char*) query.data(), query.size(), consumed, &len, largerPacket, &ednsAdded, remote);
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK(largerPacket.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  validateQuery(largerPacket.c_str(), largerPacket.size());
}

BOOST_AUTO_TEST_CASE(replaceECSWithSameSize) {
  string largerPacket;
  bool ednsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, g_ECSSourcePrefixV4);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNS0_OPTION_CODE_ECS, origECSOption));
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

  g_ECSOverride = true;
  handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, largerPacket, &ednsAdded, remote);
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK_EQUAL(largerPacket.size(), 0);
  BOOST_CHECK_EQUAL(ednsAdded, false);
  validateQuery(packet, len);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSmaller) {
  string largerPacket;
  bool ednsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 32);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNS0_OPTION_CODE_ECS, origECSOption));
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

  g_ECSOverride = true;
  handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, largerPacket, &ednsAdded, remote);
  BOOST_CHECK((size_t) len < query.size());
  BOOST_CHECK_EQUAL(largerPacket.size(), 0);
  BOOST_CHECK_EQUAL(ednsAdded, false);
  validateQuery(packet, len);
}

BOOST_AUTO_TEST_CASE(replaceECSWithLarger) {
  string largerPacket;
  bool ednsAdded = false;
  ComboAddress remote("192.168.1.25");
  DNSName name("www.powerdns.com.");
  ComboAddress origRemote("127.0.0.1");

  vector<uint8_t> query;
  DNSPacketWriter pw(query, name, QType::A, QClass::IN, 0);
  pw.getHeader()->rd = 1;
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = Netmask(origRemote, 8);
  string origECSOption = makeEDNSSubnetOptsString(ecsOpts);
  DNSPacketWriter::optvect_t opts;
  opts.push_back(make_pair(EDNS0_OPTION_CODE_ECS, origECSOption));
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

  g_ECSOverride = true;
  handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, largerPacket, &ednsAdded, remote);
  BOOST_CHECK((size_t) len > query.size());
  BOOST_CHECK_EQUAL(largerPacket.size(), 0);
  BOOST_CHECK_EQUAL(ednsAdded, false);
  validateQuery(packet, len);

  /* not large enought packet */
  consumed = 0;
  len = query.size();
  qname = DNSName((char*) query.data(), len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  g_ECSOverride = true;
  handleEDNSClientSubnet((char*) query.data(), query.size(), consumed, &len, largerPacket, &ednsAdded, remote);
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK(largerPacket.size() > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  validateQuery(largerPacket.c_str(), largerPacket.size());
}

BOOST_AUTO_TEST_CASE(removeEDNS) {
  DNSName name("www.powerdns.com.");

  vector<uint8_t> response;
  DNSPacketWriter pw(response, name, QType::A, QClass::IN, 0);
  pw.getHeader()->qr = 1;
  pw.startRecord(name, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER, true);
  pw.xfr32BitInt(0x01020304);
  pw.addOpt(512, 0, 0);
  pw.commit();

  vector<uint8_t> newResponse;
  int res = rewriteResponseWithoutEDNS((const char *) response.data(), response.size(), newResponse);

  BOOST_CHECK_EQUAL(res, 0);

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);
  size_t const ednsOptRRSize = sizeof(struct dnsrecordheader) + 1 /* root in OPT RR */;
  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - ednsOptRRSize);

  validateResponse((const char *) newResponse.data(), newResponse.size(), false);
}

BOOST_AUTO_TEST_SUITE_END();
