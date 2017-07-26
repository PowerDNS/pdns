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

#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dolog.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednscookies.hh"
#include "ednssubnet.hh"
#include <unistd.h>

BOOST_AUTO_TEST_SUITE(dnsdist_cc)

bool g_console{true};
bool g_syslog{true};
bool g_verbose{true};

static const uint16_t ECSSourcePrefixV4 = 24;
static const uint16_t ECSSourcePrefixV6 = 56;

static void validateQuery(const char * packet, size_t packetSize, bool hasEdns=true)
{
  MOADNSParser mdp(true, packet, packetSize);

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, (hasEdns ? 1 : 0));
}

static void validateResponse(const char * packet, size_t packetSize, bool hasEdns, uint8_t additionalCount=0)
{
  MOADNSParser mdp(false, packet, packetSize);

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), "www.powerdns.com.");

  BOOST_CHECK_EQUAL(mdp.d_header.qr, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, (hasEdns ? 1 : 0) + additionalCount);
}

BOOST_AUTO_TEST_CASE(addECSWithoutEDNS)
{
  bool ednsAdded = false;
  bool ecsAdded = false;
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

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, remote, false, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6));
  BOOST_CHECK((size_t) len > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, true);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);

  /* not large enough packet */
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  len = query.size();
  qname = DNSName(reinterpret_cast<char*>(query.data()), len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(reinterpret_cast<char*>(query.data()), query.size(), consumed, &len, &ednsAdded, &ecsAdded, remote, false, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6));
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(reinterpret_cast<char*>(query.data()), len, false);
}

BOOST_AUTO_TEST_CASE(addECSWithEDNSNoECS) {
  bool ednsAdded = false;
  bool ecsAdded = false;
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

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, remote, false, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6));
  BOOST_CHECK((size_t) len > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, true);
  validateQuery(packet, len);

  /* not large enough packet */
  consumed = 0;
  ednsAdded = false;
  ecsAdded = false;
  len = query.size();
  qname = DNSName(reinterpret_cast<char*>(query.data()), len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(reinterpret_cast<char*>(query.data()), query.size(), consumed, &len, &ednsAdded, &ecsAdded, remote, false, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6));
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(reinterpret_cast<char*>(query.data()), len);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSameSize) {
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
  uint16_t len = query.size();

  /* large enough packet */
  char packet[1500];
  memcpy(packet, query.data(), query.size());

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname(packet, len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, remote, true, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6));
  BOOST_CHECK_EQUAL((size_t) len, query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);
}

BOOST_AUTO_TEST_CASE(replaceECSWithSmaller) {
  bool ednsAdded = false;
  bool ecsAdded = false;
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

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, remote, true, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6));
  BOOST_CHECK((size_t) len < query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);
}

BOOST_AUTO_TEST_CASE(replaceECSWithLarger) {
  bool ednsAdded = false;
  bool ecsAdded = false;
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

  BOOST_CHECK(handleEDNSClientSubnet(packet, sizeof packet, consumed, &len, &ednsAdded, &ecsAdded, remote, true, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6));
  BOOST_CHECK((size_t) len > query.size());
  BOOST_CHECK_EQUAL(ednsAdded, false);
  BOOST_CHECK_EQUAL(ecsAdded, false);
  validateQuery(packet, len);

  /* not large enough packet */
  ednsAdded = false;
  ecsAdded = false;
  consumed = 0;
  len = query.size();
  qname = DNSName(reinterpret_cast<char*>(query.data()), len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  BOOST_CHECK(!handleEDNSClientSubnet(reinterpret_cast<char*>(query.data()), query.size(), consumed, &len, &ednsAdded, &ecsAdded, remote, true, remote.sin4.sin_family == AF_INET ? ECSSourcePrefixV4 : ECSSourcePrefixV6));
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
  int res = rewriteResponseWithoutEDNS((const char *) response.data(), response.size(), newResponse);
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
  int res = rewriteResponseWithoutEDNS((const char *) response.data(), response.size(), newResponse);
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
  int res = rewriteResponseWithoutEDNS((const char *) response.data(), response.size(), newResponse);

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

  char * optStart = NULL;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR((char *) response.data(), response.size(), &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  res = removeEDNSOptionFromOPT(optStart, &optLen, EDNSOptionCode::ECS);
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

  char * optStart = NULL;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR((char *) response.data(), response.size(), &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  res = removeEDNSOptionFromOPT(optStart, &optLen, EDNSOptionCode::ECS);
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

  char * optStart = NULL;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR((char *) response.data(), response.size(), &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  res = removeEDNSOptionFromOPT(optStart, &optLen, EDNSOptionCode::ECS);
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

  char * optStart = NULL;
  size_t optLen = 0;
  bool last = false;

  int res = locateEDNSOptRR((char *) response.data(), response.size(), &optStart, &optLen, &last);
  BOOST_CHECK_EQUAL(res, 0);
  BOOST_CHECK_EQUAL(last, true);

  size_t responseLen = response.size();
  size_t existingOptLen = optLen;
  BOOST_CHECK(existingOptLen < responseLen);
  res = removeEDNSOptionFromOPT(optStart, &optLen, EDNSOptionCode::ECS);
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
  int res = rewriteResponseWithoutEDNSOption((const char *) response.data(), response.size(), EDNSOptionCode::ECS, newResponse);
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
  int res = rewriteResponseWithoutEDNSOption((const char *) response.data(), response.size(), EDNSOptionCode::ECS, newResponse);
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
  int res = rewriteResponseWithoutEDNSOption((const char *) response.data(), response.size(), EDNSOptionCode::ECS, newResponse);
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
  int res = rewriteResponseWithoutEDNSOption((const char *) response.data(), response.size(), EDNSOptionCode::ECS, newResponse);
  BOOST_CHECK_EQUAL(res, 0);

  BOOST_CHECK_EQUAL(newResponse.size(), response.size() - (origECSOptionStr.size() + 4));

  unsigned int consumed = 0;
  uint16_t qtype;
  DNSName qname((const char*) newResponse.data(), newResponse.size(), sizeof(dnsheader), false, &qtype, NULL, &consumed);
  BOOST_CHECK_EQUAL(qname, name);
  BOOST_CHECK(qtype == QType::A);

  validateResponse((const char *) newResponse.data(), newResponse.size(), true, 1);
}

BOOST_AUTO_TEST_SUITE_END();
