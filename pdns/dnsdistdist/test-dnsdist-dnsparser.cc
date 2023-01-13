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

#include "dnsdist-dnsparser.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdist_dnsparser)

BOOST_AUTO_TEST_CASE(test_Overlay)
{
  const DNSName target("powerdns.com.");

  {
    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, target, QType::ANY, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(42);
    pwR.startRecord(target, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v4("192.0.2.1");
    pwR.xfrCAWithoutPort(4, v4);
    pwR.commit();
    pwR.startRecord(target, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("2001:db8::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.startRecord(target, QType::NS, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrName(DNSName("pdns-public-ns1.powerdns.com."));
    pwR.commit();
    pwR.startRecord(target, QType::SOA, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrName(DNSName("pdns-public-ns1.powerdns.com."));
    pwR.xfrName(DNSName("admin.powerdns.com."));
    pwR.xfr32BitInt(1);
    pwR.xfr32BitInt(2);
    pwR.xfr32BitInt(3);
    pwR.xfr32BitInt(4);
    pwR.xfr32BitInt(5);
    pwR.commit();
    pwR.startRecord(target, QType::MX, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr16BitInt(75);
    pwR.xfrName(DNSName("download1.powerdns.com."));
    pwR.commit();
    pwR.startRecord(target, QType::TXT, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrText("\"random text\"");
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    {
      // check packet smaller than dnsheader
      BOOST_CHECK_THROW(dnsdist::DNSPacketOverlay(std::string_view(reinterpret_cast<const char*>(response.data()), 11U)), std::runtime_error);
      // check corrupted packet
      BOOST_CHECK_THROW(dnsdist::DNSPacketOverlay(std::string_view(reinterpret_cast<const char*>(response.data()), response.size() - 1)), std::runtime_error);
    }

    dnsdist::DNSPacketOverlay overlay(std::string_view(reinterpret_cast<const char*>(response.data()), response.size()));
    BOOST_CHECK_EQUAL(overlay.d_qname, target);
    BOOST_CHECK_EQUAL(overlay.d_qtype, QType::ANY);
    BOOST_CHECK_EQUAL(overlay.d_qclass, QClass::IN);
    BOOST_CHECK_EQUAL(overlay.d_header.qr, 1U);
    BOOST_CHECK_EQUAL(overlay.d_header.rd, 1U);
    BOOST_CHECK_EQUAL(overlay.d_header.ra, 1U);
    BOOST_CHECK_EQUAL(overlay.d_header.id, htons(42));
    BOOST_CHECK_EQUAL(ntohs(overlay.d_header.qdcount), 1U);
    BOOST_CHECK_EQUAL(ntohs(overlay.d_header.ancount), 6U);
    BOOST_CHECK_EQUAL(ntohs(overlay.d_header.nscount), 0U);
    BOOST_CHECK_EQUAL(ntohs(overlay.d_header.arcount), 1U);
    BOOST_CHECK_EQUAL(overlay.d_records.size(), 7U);

    /* this is off, of course, but we are only doing a sanity check here */
    uint16_t lastOffset = sizeof(dnsheader) + target.wirelength() + sizeof(uint16_t) + sizeof(uint16_t);
    for (const auto& record : overlay.d_records) {
      if (record.d_type == QType::OPT) {
        continue;
      }

      BOOST_CHECK_EQUAL(record.d_name, target);
      BOOST_CHECK_EQUAL(record.d_class, QClass::IN);
      BOOST_CHECK_EQUAL(record.d_ttl, 7200);
      BOOST_CHECK_EQUAL(record.d_place, 1U);
      BOOST_CHECK_GE(record.d_contentOffset, lastOffset);
      lastOffset = record.d_contentOffset + record.d_contentLength;
    }
  }
}

BOOST_AUTO_TEST_SUITE_END();
