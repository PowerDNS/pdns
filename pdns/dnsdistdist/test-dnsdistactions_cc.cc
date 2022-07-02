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

#include <thread>
#include <boost/test/unit_test.hpp>

#include "dnsdist-ecs.hh"
#include "dnsdist-lua.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednscookies.hh"

BOOST_AUTO_TEST_SUITE(dnsdistluaaction_cc)

BOOST_AUTO_TEST_CASE(test_SetEDNSOptionAction) {
  DNSName qname("powerdns.com.");
  uint16_t qtype = QType::A;
  uint16_t qclass = QClass::IN;
  ComboAddress lc("127.0.0.1:53");
  ComboAddress rem("192.0.2.1:42");
  auto proto = dnsdist::Protocol::DoUDP;
  struct timespec queryRealTime;
  gettime(&queryRealTime, true);
  struct timespec expiredTime;
  /* the internal QPS limiter does not use the real time */
  gettime(&expiredTime);

  PacketBuffer packet;
  GenericDNSPacketWriter<PacketBuffer> pw(packet, qname, qtype, qclass, 0);
  pw.addOpt(4096, 0, EDNS_HEADER_FLAG_DO);
  pw.commit();

  DNSQuestion dq(&qname, qtype, qclass, &lc, &rem, packet, proto, &queryRealTime);

  std::string result;
  EDNSCookiesOpt cookiesOpt("deadbeefdeadbeef");
  string cookiesOptionStr = cookiesOpt.makeOptString();

  SetEDNSOptionAction seoa(EDNSOptionCode::COOKIE, cookiesOptionStr);
  seoa(&dq, &result);

  const auto& data = dq.getData();
  MOADNSParser mdp(true, reinterpret_cast<const char*>(data.data()), data.size());

  BOOST_CHECK_EQUAL(mdp.d_qname.toString(), qname.toString());
  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_header.ancount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
  BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);
  BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_type, static_cast<uint16_t>(QType::OPT));
  BOOST_CHECK_EQUAL(mdp.d_answers.at(0).first.d_name, g_rootdnsname);

  EDNS0Record edns0;  
  BOOST_REQUIRE(getEDNS0Record(dq, edns0));
  BOOST_CHECK_EQUAL(edns0.version, 0U);
  BOOST_CHECK_EQUAL(edns0.extRCode, 0U);
  BOOST_CHECK_EQUAL(edns0.extFlags, EDNS_HEADER_FLAG_DO);

  BOOST_REQUIRE(parseEDNSOptions(dq));
  BOOST_REQUIRE(dq.ednsOptions != nullptr);
  BOOST_CHECK_EQUAL(dq.ednsOptions->size(), 1U);
  const auto& ecsOption = dq.ednsOptions->find(EDNSOptionCode::COOKIE);
  BOOST_REQUIRE(ecsOption != dq.ednsOptions->cend());

  BOOST_REQUIRE_EQUAL(ecsOption->second.values.size(), 1U);
  BOOST_CHECK_EQUAL(cookiesOptionStr, std::string(ecsOption->second.values.at(0).content, ecsOption->second.values.at(0).size));
}

BOOST_AUTO_TEST_SUITE_END()
