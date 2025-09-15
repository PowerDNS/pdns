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

#include "dnsdist-dnsparser.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdist_dnsparser)

BOOST_AUTO_TEST_CASE(test_Query)
{
  const DNSName target("powerdns.com.");
  const DNSName newTarget("dnsdist.org.");
  const DNSName notTheTarget("not-powerdns.com.");

  {
    /* query for the target */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, target, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.getHeader()->id = htons(42);
    pw.commit();

    BOOST_CHECK(dnsdist::changeNameInDNSPacket(query, target, newTarget));

    MOADNSParser mdp(false, reinterpret_cast<const char*>(query.data()), query.size());
    BOOST_CHECK_EQUAL(mdp.d_qname, newTarget);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  }

  {
    /* query smaller than a DNS header */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, target, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.getHeader()->id = htons(42);
    pw.commit();

    query.resize(sizeof(dnsheader) - 1);
    BOOST_CHECK(!dnsdist::changeNameInDNSPacket(query, target, newTarget));
  }

  {
    /* query for a different name than the target */
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pw(query, notTheTarget, QType::A, QClass::IN, 0);
    pw.getHeader()->rd = 1;
    pw.getHeader()->id = htons(42);
    pw.commit();

    BOOST_CHECK(dnsdist::changeNameInDNSPacket(query, target, newTarget));

    MOADNSParser mdp(false, reinterpret_cast<const char*>(query.data()), query.size());
    BOOST_CHECK_EQUAL(mdp.d_qname, notTheTarget);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
  }
}

BOOST_AUTO_TEST_CASE(test_Response)
{
  const DNSName target("powerdns.com.");
  const DNSName newTarget("dnsdist.org.");
  const DNSName notTheTarget("not-powerdns.com.");

  {
    /* response for the target, A and AAAA */
    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, target, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(42);
    pwR.startRecord(target, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v4("192.0.2.1");
    pwR.xfrCAWithoutPort(4, v4);
    pwR.commit();
    pwR.startRecord(target, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
    ComboAddress v6("2001:db8::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    BOOST_CHECK(dnsdist::changeNameInDNSPacket(response, target, newTarget));

    MOADNSParser mdp(false, reinterpret_cast<const char*>(response.data()), response.size());
    BOOST_CHECK_EQUAL(mdp.d_qname, newTarget);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 2U);

    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 3U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::A));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, newTarget);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_type, static_cast<uint16_t>(QType::AAAA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_name, newTarget);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(2).d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(2).d_name, g_rootdnsname);
  }

  {
    /* response with A for the target, AAAA for another name */
    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, target, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(42);
    pwR.startRecord(target, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v4("192.0.2.1");
    pwR.xfrCAWithoutPort(4, v4);
    pwR.commit();
    pwR.startRecord(notTheTarget, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
    ComboAddress v6("2001:db8::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    BOOST_CHECK(dnsdist::changeNameInDNSPacket(response, target, newTarget));

    MOADNSParser mdp(false, reinterpret_cast<const char*>(response.data()), response.size());
    BOOST_CHECK_EQUAL(mdp.d_qname, newTarget);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 2U);

    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 3U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::A));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, newTarget);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_type, static_cast<uint16_t>(QType::AAAA));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_name, notTheTarget);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(2).d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(2).d_name, g_rootdnsname);
  }

  {
    /* response with CNAME for the target, A for another name */
    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, target, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(42);
    pwR.startRecord(target, QType::CNAME, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrName(notTheTarget);
    pwR.commit();
    pwR.startRecord(notTheTarget, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v4("192.0.2.1");
    pwR.xfrCAWithoutPort(4, v4);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    BOOST_CHECK(dnsdist::changeNameInDNSPacket(response, target, newTarget));

    MOADNSParser mdp(false, reinterpret_cast<const char*>(response.data()), response.size());
    BOOST_CHECK_EQUAL(mdp.d_qname, newTarget);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 2U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);

    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 3U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::CNAME));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, newTarget);
    auto content = getRR<UnknownRecordContent>(mdp.d_answers.at(0));
    BOOST_REQUIRE(content != nullptr);
    BOOST_CHECK_EQUAL(content->getRawContent().size(), notTheTarget.getStorage().size());

    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_type, static_cast<uint16_t>(QType::A));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(1).d_name, notTheTarget);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(2).d_type, static_cast<uint16_t>(QType::OPT));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(2).d_name, g_rootdnsname);
  }

  {
    /* response with a lot of records for the target, all supported */
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
    pwR.startRecord(target, QType::MX, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr16BitInt(75);
    pwR.xfrName(DNSName("download1.powerdns.com."));
    pwR.commit();
    pwR.startRecord(target, QType::TXT, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrText("\"random text\"");
    pwR.commit();
    pwR.startRecord(target, QType::RRSIG, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrType(QType::TXT);
    pwR.xfr8BitInt(13);
    pwR.xfr8BitInt(2);
    pwR.xfr32BitInt(42);
    pwR.xfrTime(42);
    pwR.xfrTime(42);
    pwR.xfr16BitInt(42);
    pwR.xfrName(DNSName("powerdns.com."));
    pwR.xfrBlob(std::string());
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    BOOST_CHECK(dnsdist::changeNameInDNSPacket(response, target, newTarget));

    MOADNSParser mdp(false, reinterpret_cast<const char*>(response.data()), response.size());
    BOOST_CHECK_EQUAL(mdp.d_qname, newTarget);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 6U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);

    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 7U);
    for (const auto& answer : mdp.d_answers) {
      if (answer.d_type == QType::OPT) {
        continue;
      }
      BOOST_CHECK_EQUAL(answer.d_class, QClass::IN);
      BOOST_CHECK_EQUAL(answer.d_name, newTarget);
    }
  }

  {
    /* response with a lot of records for the target, all supported */
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
    pwR.startRecord(target, QType::SRV, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr16BitInt(1);
    pwR.xfr16BitInt(2);
    pwR.xfr16BitInt(65535);
    pwR.xfrName(DNSName("target.powerdns.com."));
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    {
      // before
      MOADNSParser mdp(false, reinterpret_cast<const char*>(response.data()), response.size());
      BOOST_CHECK_EQUAL(mdp.d_qname, target);
      BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
      BOOST_CHECK_EQUAL(mdp.d_header.ancount, 7U);
      BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
      BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);

      BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 8U);
      for (const auto& answer : mdp.d_answers) {
        if (answer.d_type == QType::OPT) {
          continue;
        }
        BOOST_CHECK_EQUAL(answer.d_class, QClass::IN);
        BOOST_CHECK_EQUAL(answer.d_name, target);
      }
    }

    // rebasing
    BOOST_CHECK(dnsdist::changeNameInDNSPacket(response, target, newTarget));

    {
      // after
      MOADNSParser mdp(false, reinterpret_cast<const char*>(response.data()), response.size());
      BOOST_CHECK_EQUAL(mdp.d_qname, newTarget);
      BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
      BOOST_CHECK_EQUAL(mdp.d_header.ancount, 7U);
      BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
      BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);

      BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 8U);
      for (const auto& answer : mdp.d_answers) {
        if (answer.d_type == QType::OPT) {
          continue;
        }
        BOOST_CHECK_EQUAL(answer.d_class, QClass::IN);
        BOOST_CHECK_EQUAL(answer.d_name, newTarget);
      }
    }
  }

  {
    /* response with an ALIAS record, which is not supported */
    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, target, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(42);
    pwR.startRecord(target, QType::ALIAS, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrName(notTheTarget);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    BOOST_CHECK(!dnsdist::changeNameInDNSPacket(response, target, newTarget));

    MOADNSParser mdp(false, reinterpret_cast<const char*>(response.data()), response.size());
    BOOST_CHECK_EQUAL(mdp.d_qname, target);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 1U);

    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 2U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::ALIAS));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, target);
  }
}

BOOST_AUTO_TEST_CASE(test_Overlay)
{
  const DNSName target("powerdns.com.");
  const DNSName notTheTarget("not-powerdns.com.");

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
      BOOST_CHECK_EQUAL(record.d_ttl, 7200U);
      BOOST_CHECK_EQUAL(record.d_place, 1U);
      BOOST_CHECK_GE(record.d_contentOffset, lastOffset);
      lastOffset = record.d_contentOffset + record.d_contentLength;
    }
  }

  {
    /* response with A and AAAA records, using parsers */
    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, target, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(42);
    pwR.startRecord(target, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress addrV4("192.0.2.1");
    pwR.xfrCAWithoutPort(4, addrV4);
    pwR.commit();
    pwR.startRecord(target, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
    ComboAddress addrV6("2001:db8::1");
    pwR.xfrCAWithoutPort(6, addrV6);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    auto packet = std::string_view(reinterpret_cast<const char*>(response.data()), response.size());
    dnsdist::DNSPacketOverlay overlay(packet);
    BOOST_CHECK_EQUAL(overlay.d_records[0].d_type, QType::A);
    BOOST_CHECK(*dnsdist::RecordParsers::parseARecord(packet, overlay.d_records[0]) == addrV4);
    BOOST_CHECK(*dnsdist::RecordParsers::parseAddressRecord(packet, overlay.d_records[0]) == addrV4);

    BOOST_CHECK_EQUAL(overlay.d_records[1].d_type, QType::AAAA);
    BOOST_CHECK(*dnsdist::RecordParsers::parseAAAARecord(packet, overlay.d_records[1]) == addrV6);
    BOOST_CHECK(*dnsdist::RecordParsers::parseAddressRecord(packet, overlay.d_records[1]) == addrV6);
  }

  {
    /* response with CNAME record, using parser */
    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, target, QType::A, QClass::IN, 0);
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->id = htons(42);
    pwR.startRecord(target, QType::CNAME, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfrName(notTheTarget);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): this is the API we have
    auto packet = std::string_view(reinterpret_cast<const char*>(response.data()), response.size());
    dnsdist::DNSPacketOverlay overlay(packet);
    BOOST_CHECK_EQUAL(overlay.d_records[0].d_type, QType::CNAME);
    BOOST_CHECK_EQUAL(*dnsdist::RecordParsers::parseCNAMERecord(packet, overlay.d_records[0]), notTheTarget);
  }
}

BOOST_AUTO_TEST_SUITE_END();
