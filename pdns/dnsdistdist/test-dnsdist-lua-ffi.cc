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

#include "dnsdist-lua-ffi.hh"
#include "base64.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-configuration.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-web.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"

bool dnsdist::webserver::addMetricDefinition(const dnsdist::prometheus::PrometheusMetricDefinition& def)
{
  (void)def;
  return true;
}

BOOST_AUTO_TEST_SUITE(test_dnsdist_lua_ffi)

BOOST_AUTO_TEST_CASE(test_Query)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:4242");
  ids.origDest = ComboAddress("192.0.2.255:53");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("www.powerdns.com.");
  ids.queryRealTime.start();
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  pwQ.getHeader()->id = htons(42);

  DNSQuestion dq(ids, query);
  dnsdist_ffi_dnsquestion_t lightDQ(&dq);
  const auto initialData = dq.getData();

  {
    // dnsdist_ffi_dnsquestion_get_qtype
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_qtype(&lightDQ), ids.qtype);
  }

  {
    // dnsdist_ffi_dnsquestion_get_qclass
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_qclass(&lightDQ), ids.qclass);
  }

  {
    // dnsdist_ffi_dnsquestion_get_id
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_id(&lightDQ), ntohs(pwQ.getHeader()->id));
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_id(nullptr), 0U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_localaddr, dnsdist_ffi_dnsquestion_get_local_port
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_localaddr(&lightDQ, reinterpret_cast<const void**>(&buffer), &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, sizeof(ids.origDest.sin4.sin_addr.s_addr));
    BOOST_CHECK(memcmp(buffer, &ids.origDest.sin4.sin_addr.s_addr, sizeof(ids.origDest.sin4.sin_addr.s_addr)) == 0);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_local_port(&lightDQ), 53U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_remoteaddr, dnsdist_ffi_dnsquestion_get_remote_port
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_remoteaddr(&lightDQ, reinterpret_cast<const void**>(&buffer), &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, sizeof(ids.origRemote.sin4.sin_addr.s_addr));
    BOOST_CHECK(memcmp(buffer, &ids.origRemote.sin4.sin_addr.s_addr, sizeof(ids.origRemote.sin4.sin_addr.s_addr)) == 0);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_remote_port(&lightDQ), 4242U);
    BOOST_CHECK(!dnsdist_ffi_dnsquestion_is_remote_v6(nullptr));
    BOOST_CHECK(!dnsdist_ffi_dnsquestion_is_remote_v6(&lightDQ));
  }

  {
    // dnsdist_ffi_dnsquestion_get_masked_remoteaddr
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_masked_remoteaddr(&lightDQ, reinterpret_cast<const void**>(&buffer), &bufferSize, 16);
    BOOST_REQUIRE(buffer != nullptr);
    auto masked = Netmask(ids.origRemote, 16).getMaskedNetwork();
    BOOST_REQUIRE_EQUAL(bufferSize, sizeof(masked.sin4.sin_addr.s_addr));
    BOOST_CHECK(memcmp(buffer, &masked.sin4.sin_addr.s_addr, sizeof(masked.sin4.sin_addr.s_addr)) == 0);
  }

  {
    const char* buffer[6];
    size_t bufferSize = 6;

    // invalid
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_mac_addr(nullptr, buffer, 0), 0U);
    // too small
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_mac_addr(&lightDQ, buffer, 0), 0U);

    // we will not find the correspondig MAC address in /proc/net/arp, unfortunately, especially not on !linux
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_mac_addr(&lightDQ, buffer, bufferSize), 0U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_qname_raw
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_qname_raw(&lightDQ, &buffer, &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, ids.qname.getStorage().size());
    BOOST_CHECK(memcmp(buffer, ids.qname.getStorage().data(), ids.qname.getStorage().size()) == 0);
  }

  {
    // test V6 as well
    ids.origRemote = ComboAddress("[2001:db8::1]:65535");
    ids.origDest = ComboAddress("[2001:db8::2]:53");

    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_remoteaddr(&lightDQ, reinterpret_cast<const void**>(&buffer), &bufferSize);
    BOOST_REQUIRE(buffer != nullptr);
    BOOST_REQUIRE_EQUAL(bufferSize, sizeof(ids.origRemote.sin6.sin6_addr.s6_addr));
    BOOST_CHECK(memcmp(buffer, &ids.origRemote.sin6.sin6_addr.s6_addr, sizeof(ids.origRemote.sin6.sin6_addr.s6_addr)) == 0);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_remote_port(&lightDQ), 65535U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_qname_hash
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_qname_hash(&lightDQ, 42), ids.qname.hash(42));
  }

  {
    // dnsdist_ffi_dnsquestion_get_rcode
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_rcode(&lightDQ), RCode::NoError);
  }

  {
    // dnsdist_ffi_dnsquestion_get_header
    BOOST_CHECK(memcmp(dnsdist_ffi_dnsquestion_get_header(&lightDQ), pwQ.getHeader(), sizeof(dnsheader)) == 0);
  }

  {
    // dnsdist_ffi_dnsquestion_get_len, dnsdist_ffi_dnsquestion_get_size
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_len(&lightDQ), query.size());
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_size(&lightDQ), query.size());

    auto oldSize = query.size();
    BOOST_CHECK(dnsdist_ffi_dnsquestion_set_size(&lightDQ, oldSize + 1));
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_size(&lightDQ), oldSize + 1);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_len(&lightDQ), oldSize + 1);
    dnsdist_ffi_dnsquestion_set_len(&lightDQ, oldSize);

    auto max = std::numeric_limits<size_t>::max();
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_set_size(&lightDQ, max), 0U);
  }

  {
    // dnsdist_ffi_dnsquestion_get_opcode
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_opcode(&lightDQ), Opcode::Query);
  }

  {
    // dnsdist_ffi_dnsquestion_get_tcp
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tcp(&lightDQ), false);
  }

  {
    // dnsdist_ffi_dnsquestion_get_protocol
    BOOST_CHECK(static_cast<uint8_t>(dnsdist_ffi_dnsquestion_get_protocol(nullptr)) == dnsdist::Protocol(dnsdist::Protocol::DoUDP).toNumber());

    BOOST_CHECK(static_cast<uint8_t>(dnsdist_ffi_dnsquestion_get_protocol(&lightDQ)) == dnsdist::Protocol(dnsdist::Protocol::DoUDP).toNumber());
    for (const auto protocol : {dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoTCP, dnsdist::Protocol::DNSCryptUDP, dnsdist::Protocol::DNSCryptTCP, dnsdist::Protocol::DoT, dnsdist::Protocol::DoH}) {
      dq.ids.protocol = protocol;
      BOOST_CHECK(static_cast<uint8_t>(dnsdist_ffi_dnsquestion_get_protocol(&lightDQ)) == protocol);
    }
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_elapsed_us(nullptr), 0U);
    BOOST_CHECK_GT(dnsdist_ffi_dnsquestion_get_elapsed_us(&lightDQ), 0U);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_skip_cache(&lightDQ), false);
    dnsdist_ffi_dnsquestion_set_skip_cache(&lightDQ, true);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_skip_cache(&lightDQ), true);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_use_ecs(&lightDQ), true);
    dnsdist_ffi_dnsquestion_set_use_ecs(&lightDQ, false);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_use_ecs(&lightDQ), false);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_ecs_override(&lightDQ), false);
    dnsdist_ffi_dnsquestion_set_ecs_override(&lightDQ, true);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_ecs_override(&lightDQ), true);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(&lightDQ), false);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_temp_failure_ttl(&lightDQ), 0U);

    dnsdist_ffi_dnsquestion_set_temp_failure_ttl(&lightDQ, 42);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(&lightDQ), true);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_temp_failure_ttl(&lightDQ), 42U);
    dnsdist_ffi_dnsquestion_unset_temp_failure_ttl(&lightDQ);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(&lightDQ), false);
  }

  {
    BOOST_CHECK(!dnsdist_ffi_dnsquestion_get_do(&lightDQ));
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_ecs_prefix_length(&lightDQ), dnsdist::configuration::getCurrentRuntimeConfiguration().d_ECSSourcePrefixV4);
    dnsdist_ffi_dnsquestion_set_ecs_prefix_length(&lightDQ, 65535);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_ecs_prefix_length(&lightDQ), 65535U);
  }

  {
    const char* buffer = nullptr;
    size_t bufferSize = 0;
    dnsdist_ffi_dnsquestion_get_sni(&lightDQ, &buffer, &bufferSize);
    BOOST_CHECK_EQUAL(bufferSize, 0U);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_trailing_data(&lightDQ, nullptr), 0U);
    std::string garbage("thisissomegarbagetrailingdata");
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_set_trailing_data(&lightDQ, garbage.data(), garbage.size()), true);
    const char* buffer = nullptr;
    BOOST_REQUIRE_EQUAL(dnsdist_ffi_dnsquestion_get_trailing_data(&lightDQ, &buffer), garbage.size());
    BOOST_CHECK_EQUAL(garbage, std::string(buffer));
  }

  {
    dq.getMutableData() = initialData;
    const auto oldData = dq.getData();
    std::vector<dnsdist_ffi_raw_value> values;
    ComboAddress v4("192.0.2.1");
    ComboAddress v6("[2001:db8::42]");
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    values.push_back({reinterpret_cast<const char*>(&v4.sin4.sin_addr.s_addr), sizeof(v4.sin4.sin_addr.s_addr)});
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    values.push_back({reinterpret_cast<const char*>(&v6.sin6.sin6_addr.s6_addr), sizeof(v6.sin6.sin6_addr.s6_addr)});

    dnsdist_ffi_dnsquestion_spoof_addrs(&lightDQ, values.data(), values.size());
    BOOST_CHECK(dq.getData().size() > oldData.size());

    MOADNSParser mdp(false, reinterpret_cast<const char*>(dq.getData().data()), dq.getData().size());
    BOOST_CHECK_EQUAL(mdp.d_qname, ids.qname);
    BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
    /* only the A has been added since the query was not ANY */
    BOOST_CHECK_EQUAL(mdp.d_header.ancount, 1U);
    BOOST_CHECK_EQUAL(mdp.d_header.nscount, 0U);
    BOOST_CHECK_EQUAL(mdp.d_header.arcount, 0U);

    BOOST_REQUIRE_EQUAL(mdp.d_answers.size(), 1U);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_type, static_cast<uint16_t>(QType::A));
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_class, QClass::IN);
    BOOST_CHECK_EQUAL(mdp.d_answers.at(0).d_name, ids.qname);

    dq.getMutableData() = oldData;
  }

  {
    BOOST_CHECK(!dnsdist_ffi_dnsquestion_set_restartable(nullptr));
    BOOST_CHECK(dnsdist_ffi_dnsquestion_set_restartable(&lightDQ));
  }

  {
    BOOST_CHECK_EQUAL(ids.ttlCap, 0U);
    dnsdist_ffi_dnsquestion_set_max_returned_ttl(&lightDQ, 42U);
    BOOST_CHECK_EQUAL(ids.ttlCap, 42U);
  }

  {
    const std::string tagName("my-tag");
    const std::string tagValue("my-value");
    const std::string tagRawValue("my-\0-binary-value");
    std::string buffer;
    buffer.resize(512);
    BOOST_CHECK(dnsdist_ffi_dnsquestion_get_tag(nullptr, nullptr) == nullptr);
    BOOST_CHECK(dnsdist_ffi_dnsquestion_get_tag(&lightDQ, nullptr) == nullptr);
    BOOST_CHECK(dnsdist_ffi_dnsquestion_get_tag(&lightDQ, tagName.c_str()) == nullptr);

    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(nullptr, nullptr, nullptr, 0), 0U);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(&lightDQ, tagName.c_str(), buffer.data(), buffer.size()), 0U);

    dnsdist_ffi_dnsquestion_set_tag(&lightDQ, tagName.c_str(), tagValue.c_str());

    auto got = dnsdist_ffi_dnsquestion_get_tag(&lightDQ, tagName.c_str());
    BOOST_CHECK(got != nullptr);
    BOOST_CHECK_EQUAL(got, tagValue.c_str());

    const dnsdist_ffi_tag_t* tags = nullptr;
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_array(nullptr, nullptr), 0U);
    BOOST_REQUIRE_EQUAL(dnsdist_ffi_dnsquestion_get_tag_array(&lightDQ, &tags), 1U);
    BOOST_CHECK_EQUAL(std::string(tags[0].name), tagName.c_str());
    BOOST_CHECK_EQUAL(std::string(tags[0].value), tagValue.c_str());

    dnsdist_ffi_dnsquestion_set_tag_raw(&lightDQ, tagName.c_str(), tagRawValue.c_str(), tagRawValue.size());

    // too small
    buffer.resize(1);
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(&lightDQ, tagName.c_str(), buffer.data(), buffer.size()), 0U);

    buffer.resize(tagRawValue.size());
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(&lightDQ, tagName.c_str(), buffer.data(), buffer.size()), tagRawValue.size());
    BOOST_CHECK_EQUAL(buffer, tagRawValue);

    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_tag_raw(&lightDQ, "wrong tag name", buffer.data(), buffer.size()), 0U);

    // dnsdist_ffi_dnsquestion_get_tag_array

    {
      // no DOHUnit attached
      BOOST_CHECK(dnsdist_ffi_dnsquestion_get_http_path(&lightDQ) == nullptr);
      BOOST_CHECK(dnsdist_ffi_dnsquestion_get_http_query_string(&lightDQ) == nullptr);
      BOOST_CHECK(dnsdist_ffi_dnsquestion_get_http_host(&lightDQ) == nullptr);
      BOOST_CHECK(dnsdist_ffi_dnsquestion_get_http_scheme(&lightDQ) == nullptr);
      BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_http_headers(&lightDQ, nullptr), 0U);
      dnsdist_ffi_dnsquestion_set_http_response(&lightDQ, 0U, nullptr, 0U, nullptr);
    }
  }

  const std::string deviceID{"my-device-id"};
  const std::string deviceName{"my-device-name"};
  const std::string requestorID{"my-requestor-ID"};
  dnsdist_ffi_dnsquestion_set_device_id(nullptr, nullptr, 0);
  dnsdist_ffi_dnsquestion_set_device_id(&lightDQ, nullptr, 0);
  dnsdist_ffi_dnsquestion_set_device_id(&lightDQ, deviceID.c_str(), deviceID.size());
  dnsdist_ffi_dnsquestion_set_device_name(nullptr, nullptr, 0);
  dnsdist_ffi_dnsquestion_set_device_name(&lightDQ, nullptr, 0);
  dnsdist_ffi_dnsquestion_set_device_name(&lightDQ, deviceName.c_str(), deviceName.size());
  dnsdist_ffi_dnsquestion_set_requestor_id(nullptr, nullptr, 0);
  dnsdist_ffi_dnsquestion_set_requestor_id(&lightDQ, nullptr, 0);
  dnsdist_ffi_dnsquestion_set_requestor_id(&lightDQ, requestorID.c_str(), requestorID.size());
  BOOST_REQUIRE(ids.d_protoBufData != nullptr);
  BOOST_CHECK_EQUAL(ids.d_protoBufData->d_deviceID, deviceID);
  BOOST_CHECK_EQUAL(ids.d_protoBufData->d_deviceName, deviceName);
  BOOST_CHECK_EQUAL(ids.d_protoBufData->d_requestorID, requestorID);

  /* no frontend yet */
  BOOST_CHECK(dnsdist_ffi_dnsquestion_get_incoming_interface(nullptr) == nullptr);
  BOOST_CHECK(dnsdist_ffi_dnsquestion_get_incoming_interface(&lightDQ) == nullptr);
  {
    /* frontend without and interface set */
    const std::string interface{};
    ClientState frontend(ids.origDest, false, false, 0, interface, {}, false);
    ids.cs = &frontend;
    const auto* itfPtr = dnsdist_ffi_dnsquestion_get_incoming_interface(&lightDQ);
    BOOST_REQUIRE(itfPtr != nullptr);
    BOOST_CHECK_EQUAL(std::string(itfPtr), interface);
    ids.cs = nullptr;
  }
  {
    /* frontend with interface set */
    const std::string interface{"interface-name-0"};
    ClientState frontend(ids.origDest, false, false, 0, interface, {}, false);
    ids.cs = &frontend;
    const auto* itfPtr = dnsdist_ffi_dnsquestion_get_incoming_interface(&lightDQ);
    BOOST_REQUIRE(itfPtr != nullptr);
    BOOST_CHECK_EQUAL(std::string(itfPtr), interface);
    ids.cs = nullptr;
  }
}

BOOST_AUTO_TEST_CASE(test_Response)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:4242");
  ids.origDest = ComboAddress("192.0.2.255:53");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("www.powerdns.com.");
  ids.queryRealTime.start();

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::A, QClass::IN, 0);
  pwR.getHeader()->qr = 1;
  pwR.getHeader()->rd = 1;
  pwR.getHeader()->id = htons(42);

  ComboAddress dsAddr("192.0.2.1:53");
  auto ds = std::make_shared<DownstreamState>(dsAddr);

  DNSResponse dr(ids, response, ds);
  dnsdist_ffi_dnsresponse_t lightDR(&dr);

  {
    dnsdist_ffi_dnsresponse_set_min_ttl(&lightDR, 42);
    dnsdist_ffi_dnsresponse_set_max_ttl(&lightDR, 84);
    dnsdist_ffi_dnsresponse_limit_ttl(&lightDR, 42, 84);
  }

  {
    BOOST_CHECK_EQUAL(ids.ttlCap, 0U);
    dnsdist_ffi_dnsresponse_set_max_returned_ttl(&lightDR, 42);
    BOOST_CHECK_EQUAL(ids.ttlCap, 42U);
  }

  {
    /* invalid parameters */
    BOOST_CHECK(!dnsdist_ffi_dnsresponse_rebase(&lightDR, nullptr, 0));

    /* invalid name */
    BOOST_CHECK(!dnsdist_ffi_dnsresponse_rebase(&lightDR, "\5AAAA", 5));

    DNSName newName("not-powerdns.com.");
    BOOST_CHECK(dnsdist_ffi_dnsresponse_rebase(&lightDR, newName.getStorage().data(), newName.getStorage().size()));
    BOOST_CHECK_EQUAL(ids.qname.toString(), newName.toString());
  }

  {
    dnsdist_ffi_dnsresponse_clear_records_type(nullptr, QType::A);
    dnsdist_ffi_dnsresponse_clear_records_type(&lightDR, QType::A);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsresponse_get_stale_cache_hit(&lightDR), false);
  }

  {
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsresponse_get_restart_count(&lightDR), 0);
  }
}

BOOST_AUTO_TEST_CASE(test_Server)
{
  ComboAddress dsAddr("192.0.2.1:53");
  auto ds = std::make_shared<DownstreamState>(dsAddr);
  dnsdist_ffi_server_t server(ds);

  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_outstanding(&server), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_is_up(&server), false);
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_name(&server), "");
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_name_with_addr(&server), dsAddr.toStringWithPort());
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_weight(&server), 1);
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_order(&server), 1);
  BOOST_CHECK_EQUAL(dnsdist_ffi_server_get_latency(&server), 0.0);
}

BOOST_AUTO_TEST_CASE(test_PacketCache)
{
  DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 10,
  };
  auto packetCache = std::make_shared<DNSDistPacketCache>(settings);

  ComboAddress ipv4("192.0.2.1");
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("powerdns.com.");
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;

  PacketBuffer response;
  GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::A, QClass::IN, 0);
  pwR.getHeader()->id = pwQ.getHeader()->id;
  pwR.startRecord(ids.qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
  pwR.xfrCAWithoutPort(4, ipv4);
  pwR.commit();

  bool dnssecOK = true;
  bool receivedOverUDP = true;
  uint32_t key = 0;
  boost::optional<Netmask> subnet;
  ids.queryRealTime.start();
  DNSQuestion dq(ids, query);
  packetCache->get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
  packetCache->insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader().get())), dnssecOK, ids.qname, QType::A, QClass::IN, response, receivedOverUDP, 0, boost::none);

  std::string poolName("test-pool");
  auto testPool = std::make_shared<ServerPool>();
  testPool->packetCache = packetCache;
  std::string poolWithNoCacheName("test-pool-without-cache");
  auto testPoolWithNoCache = std::make_shared<ServerPool>();
  dnsdist::configuration::updateRuntimeConfiguration([&poolName, &testPool, &poolWithNoCacheName, &testPoolWithNoCache](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_pools.emplace(poolName, testPool);
    config.d_pools.emplace(poolWithNoCacheName, testPoolWithNoCache);
  });

  {
    dnsdist_ffi_domain_list_t* list = nullptr;
    {
      // invalid parameters
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_domain_list_by_addr(nullptr, nullptr, nullptr), 0U);
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_domain_list_by_addr("not-existing-pool", ipv4.toString().c_str(), &list), 0U);
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_domain_list_by_addr(poolName.c_str(), "invalid-address", &list), 0U);
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_domain_list_by_addr(poolWithNoCacheName.c_str(), ipv4.toString().c_str(), &list), 0U);
    }

    {
      // no match
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_domain_list_by_addr(poolName.c_str(), ComboAddress("192.0.2.254").toString().c_str(), &list), 0U);
    }

    auto got = dnsdist_ffi_packetcache_get_domain_list_by_addr(poolName.c_str(), ipv4.toString().c_str(), &list);
    BOOST_REQUIRE_EQUAL(got, 1U);
    BOOST_REQUIRE(list != nullptr);

    {
      // invalid parameters
      BOOST_CHECK(dnsdist_ffi_domain_list_get(nullptr, 0) == nullptr);
      BOOST_CHECK(dnsdist_ffi_domain_list_get(list, 1) == nullptr);
    }

    {
      const char* domain = dnsdist_ffi_domain_list_get(list, 0);
      BOOST_CHECK(domain == ids.qname.toString());
    }

    dnsdist_ffi_domain_list_free(list);
  }

  {
    dnsdist_ffi_address_list_t* addresses = nullptr;
    {
      // invalid parameters
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_address_list_by_domain(nullptr, nullptr, nullptr), 0U);
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_address_list_by_domain("not-existing-pool", ids.qname.toString().c_str(), &addresses), 0U);
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_address_list_by_domain(poolName.c_str(), "invalid-dns...name", &addresses), 0U);
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_address_list_by_domain(poolWithNoCacheName.c_str(), ipv4.toString().c_str(), &addresses), 0U);
    }

    {
      // no match
      BOOST_CHECK_EQUAL(dnsdist_ffi_packetcache_get_address_list_by_domain(poolName.c_str(), "wrong.name.", &addresses), 0U);
    }

    auto got = dnsdist_ffi_packetcache_get_address_list_by_domain(poolName.c_str(), ids.qname.toString().c_str(), &addresses);
    BOOST_REQUIRE_EQUAL(got, 1U);
    BOOST_REQUIRE(addresses != nullptr);

    {
      // invalid parameters
      BOOST_CHECK(dnsdist_ffi_address_list_get(nullptr, 0) == nullptr);
      BOOST_CHECK(dnsdist_ffi_address_list_get(addresses, 1) == nullptr);
    }

    {
      const char* addr = dnsdist_ffi_address_list_get(addresses, 0);
      BOOST_CHECK(addr == ipv4.toString());
    }

    dnsdist_ffi_address_list_free(addresses);
  }
}

BOOST_AUTO_TEST_CASE(test_ProxyProtocol)
{
  ComboAddress v4("192.0.2.1");
  ComboAddress v6("[2001:db8::42]");

  std::vector<dnsdist_ffi_proxy_protocol_value> values;
  values.push_back({"test-value", 10U, 1U});

  std::vector<uint8_t> output;
  output.resize(4096);

  {
    // too small buffer
    auto got = dnsdist_ffi_generate_proxy_protocol_payload(sizeof(v4.sin4.sin_addr.s_addr), &v4.sin4.sin_addr.s_addr, &v4.sin4.sin_addr.s_addr, 4242U, 53U, true, values.size(), values.data(), output.data(), 0);
    BOOST_CHECK_EQUAL(got, 0U);
  }

  {
    // invalid address size
    auto got = dnsdist_ffi_generate_proxy_protocol_payload(0U, &v4.sin4.sin_addr.s_addr, &v4.sin4.sin_addr.s_addr, 4242U, 53U, true, values.size(), values.data(), output.data(), 0);
    BOOST_CHECK_EQUAL(got, 0U);
  }

  {
    auto got = dnsdist_ffi_generate_proxy_protocol_payload(sizeof(v4.sin4.sin_addr.s_addr), &v4.sin4.sin_addr.s_addr, &v4.sin4.sin_addr.s_addr, 4242U, 53U, true, values.size(), values.data(), output.data(), output.size());
    BOOST_CHECK_EQUAL(got, 41U);
  }
}

BOOST_AUTO_TEST_CASE(test_ProxyProtocolQuery)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:4242");
  ids.origDest = ComboAddress("192.0.2.255:53");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("www.powerdns.com.");
  ids.queryRealTime.start();
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  pwQ.getHeader()->id = htons(42);

  DNSQuestion dnsQuestion(ids, query);
  dnsdist_ffi_dnsquestion_t lightDQ(&dnsQuestion);

  std::vector<dnsdist_ffi_proxy_protocol_value> values;
  values.push_back({"test-value", 10U, 1U});

  {
    auto added = dnsdist_ffi_dnsquestion_add_proxy_protocol_values(nullptr, values.size(), values.data());
    BOOST_CHECK_EQUAL(added, false);
  }

  {
    auto added = dnsdist_ffi_dnsquestion_add_proxy_protocol_values(&lightDQ, 0, values.data());
    BOOST_CHECK_EQUAL(added, false);
  }

  {
    auto added = dnsdist_ffi_dnsquestion_add_proxy_protocol_values(&lightDQ, values.size(), nullptr);
    BOOST_CHECK_EQUAL(added, false);
  }

  {
    auto added = dnsdist_ffi_dnsquestion_add_proxy_protocol_values(&lightDQ, values.size(), values.data());
    BOOST_CHECK_EQUAL(added, true);
    BOOST_REQUIRE(dnsQuestion.proxyProtocolValues != nullptr);
    BOOST_REQUIRE_EQUAL(dnsQuestion.proxyProtocolValues->size(), values.size());
    BOOST_CHECK_EQUAL(dnsQuestion.proxyProtocolValues->at(0).type, values.at(0).type);
    BOOST_REQUIRE_EQUAL(dnsQuestion.proxyProtocolValues->at(0).content.size(), values.at(0).size);
    BOOST_CHECK_EQUAL(memcmp(dnsQuestion.proxyProtocolValues->at(0).content.data(), values.at(0).value, values.at(0).size), 0);
  }
}

BOOST_AUTO_TEST_CASE(test_ProxyProtocolIncoming)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:4242");
  ids.origDest = ComboAddress("192.0.2.255:53");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("www.powerdns.com.");
  ids.queryRealTime.start();
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  pwQ.getHeader()->id = htons(42);

  DNSQuestion dnsQuestion(ids, query);
  dnsdist_ffi_dnsquestion_t lightDQ(&dnsQuestion);

  {
    /* invalid dq */
    const dnsdist_ffi_proxy_protocol_value_t* out = nullptr;
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_proxy_protocol_values(nullptr, &out), 0U);
  }
  {
    /* invalid pointer */
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_proxy_protocol_values(&lightDQ, nullptr), 0U);
  }
  {
    /* no proxy protocol values */
    const dnsdist_ffi_proxy_protocol_value_t* out = nullptr;
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_get_proxy_protocol_values(&lightDQ, &out), 0U);
  }

  {
    /* add some proxy protocol TLV values */
    dnsQuestion.proxyProtocolValues = std::make_unique<std::vector<ProxyProtocolValue>>();
    dnsQuestion.proxyProtocolValues->emplace_back(ProxyProtocolValue{"foo", 42});
    dnsQuestion.proxyProtocolValues->emplace_back(ProxyProtocolValue{"bar", 255});
    dnsQuestion.proxyProtocolValues->emplace_back(ProxyProtocolValue{"", 0});
    const dnsdist_ffi_proxy_protocol_value_t* out = nullptr;
    auto count = dnsdist_ffi_dnsquestion_get_proxy_protocol_values(&lightDQ, &out);
    BOOST_REQUIRE_EQUAL(count, 3U);
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic): sorry, this is a C API
    BOOST_CHECK_EQUAL(out[0].type, 42U);
    BOOST_CHECK_EQUAL(out[0].value, "foo");
    BOOST_CHECK_EQUAL(out[1].type, 255U);
    BOOST_CHECK_EQUAL(out[1].value, "bar");
    BOOST_CHECK_EQUAL(out[2].type, 0U);
    BOOST_CHECK_EQUAL(out[2].value, "");
    // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic): sorry, this is a C API
  }
}

BOOST_AUTO_TEST_CASE(test_PacketOverlay)
{
  const DNSName target("powerdns.com.");
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

  /* invalid parameters */
  BOOST_CHECK(!dnsdist_ffi_dnspacket_parse(nullptr, 0, nullptr));

  dnsdist_ffi_dnspacket_t* packet = nullptr;
  // invalid packet
  BOOST_CHECK(!dnsdist_ffi_dnspacket_parse(reinterpret_cast<const char*>(response.data()), response.size() - 1, &packet));
  BOOST_REQUIRE(dnsdist_ffi_dnspacket_parse(reinterpret_cast<const char*>(response.data()), response.size(), &packet));
  BOOST_REQUIRE(packet != nullptr);

  const char* qname = nullptr;
  size_t qnameSize = 0;

  // invalid parameters
  dnsdist_ffi_dnspacket_get_qname_raw(nullptr, nullptr, 0);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_qtype(nullptr), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_qclass(nullptr), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_qtype(packet), QType::A);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_qclass(packet), QClass::IN);

  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 1), 1U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 2), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 3), 2U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_records_count_in_section(packet, 4), 0U);

  dnsdist_ffi_dnspacket_get_qname_raw(packet, &qname, &qnameSize);
  BOOST_REQUIRE(qname != nullptr);
  BOOST_REQUIRE_EQUAL(qnameSize, target.wirelength());
  BOOST_CHECK_EQUAL(memcmp(qname, target.getStorage().data(), target.getStorage().size()), 0);

  {
    std::string parsedName;
    parsedName.resize(1024);

    // too small
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_name_at_offset_raw(reinterpret_cast<const char*>(response.data()), response.size(), sizeof(dnsheader), parsedName.data(), 1U), 0U);
    // invalid parameters
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_name_at_offset_raw(nullptr, 0, sizeof(dnsheader), parsedName.data(), parsedName.size()), 0U);
    // invalid packet
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_name_at_offset_raw(reinterpret_cast<const char*>(response.data()), sizeof(dnsheader) + 2, sizeof(dnsheader), parsedName.data(), parsedName.size()), 0U);

    auto parsedNameSize = dnsdist_ffi_dnspacket_get_name_at_offset_raw(reinterpret_cast<const char*>(response.data()), response.size(), sizeof(dnsheader), parsedName.data(), parsedName.size());
    BOOST_REQUIRE_GT(parsedNameSize, 0U);
    BOOST_REQUIRE_EQUAL(parsedNameSize, target.wirelength());
    BOOST_CHECK_EQUAL(memcmp(parsedName.c_str(), target.getStorage().data(), target.getStorage().size()), 0);
  }

  const char* name = nullptr;
  size_t nameSize = 0;
  dnsdist_ffi_dnspacket_get_record_name_raw(nullptr, 0, nullptr, 0);
  BOOST_REQUIRE(name == nullptr);

  // invalid parameters
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_type(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_class(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_ttl(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_length(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_offset(nullptr, 0), 0U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_name_at_offset_raw(nullptr, 0, 0, nullptr, 0), 0U);

  // first record */
  dnsdist_ffi_dnspacket_get_record_name_raw(packet, 0, &name, &nameSize);
  BOOST_REQUIRE(name != nullptr);
  BOOST_REQUIRE_EQUAL(nameSize, target.wirelength());
  BOOST_CHECK_EQUAL(memcmp(name, target.getStorage().data(), target.getStorage().size()), 0);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_type(packet, 0), QType::A);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_class(packet, 0), QClass::IN);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_ttl(packet, 0), 7200U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_length(packet, 0), sizeof(v4.sin4.sin_addr.s_addr));
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_offset(packet, 0), 42U);

  // second record
  dnsdist_ffi_dnspacket_get_record_name_raw(packet, 1, &name, &nameSize);
  BOOST_REQUIRE(name != nullptr);
  BOOST_REQUIRE_EQUAL(nameSize, target.wirelength());
  BOOST_CHECK_EQUAL(memcmp(name, target.getStorage().data(), target.getStorage().size()), 0);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_type(packet, 1), QType::AAAA);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_class(packet, 1), QClass::IN);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_ttl(packet, 1), 7200U);
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_length(packet, 1), sizeof(v6.sin6.sin6_addr.s6_addr));
  BOOST_CHECK_EQUAL(dnsdist_ffi_dnspacket_get_record_content_offset(packet, 1), 58U);

  dnsdist_ffi_dnspacket_free(packet);
}

BOOST_AUTO_TEST_CASE(test_RingBuffers)
{
  dnsheader dh;
  memset(&dh, 0, sizeof(dh));
  dh.id = htons(42);
  dh.rd = 1;
  dh.ancount = htons(1);
  dh.nscount = htons(1);
  dh.arcount = htons(1);
  dh.rcode = RCode::NXDomain;
  DNSName qname("rings.luaffi.powerdns.com.");
  ComboAddress requestor1("192.0.2.1");
  ComboAddress backend("192.0.2.42");
  uint16_t qtype = QType::AAAA;
  uint16_t size = 42;
  dnsdist::Protocol protocol = dnsdist::Protocol::DoUDP;
  dnsdist::Protocol outgoingProtocol = dnsdist::Protocol::DoUDP;
  unsigned int responseTime = 0;
  struct timespec now;
  gettime(&now);

  g_rings.reset();
  g_rings.init(10000, 10);
  BOOST_CHECK_EQUAL(g_rings.getNumberOfQueryEntries(), 0U);

  g_rings.insertQuery(now, requestor1, qname, qtype, size, dh, protocol);
  g_rings.insertResponse(now, requestor1, qname, qtype, responseTime, size, dh, backend, outgoingProtocol);

  dnsdist_ffi_ring_entry_list_t* list = nullptr;

  {
    // invalid
    BOOST_CHECK_EQUAL(dnsdist_ffi_ring_get_entries(nullptr), 0U);
    BOOST_CHECK(list == nullptr);
    BOOST_CHECK_EQUAL(dnsdist_ffi_ring_get_entries_by_addr(requestor1.toString().c_str(), nullptr), 0U);
    BOOST_CHECK_EQUAL(dnsdist_ffi_ring_get_entries_by_addr(nullptr, &list), 0U);
    BOOST_CHECK(list == nullptr);
    BOOST_CHECK_EQUAL(dnsdist_ffi_ring_get_entries_by_addr("invalid-address", &list), 0U);
    BOOST_CHECK(list == nullptr);
    BOOST_CHECK_EQUAL(dnsdist_ffi_ring_get_entries_by_mac(nullptr, nullptr), 0U);
    BOOST_CHECK(list == nullptr);
    BOOST_CHECK(!dnsdist_ffi_ring_entry_is_response(nullptr, 0));
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_age(nullptr, 0) == 0.0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_name(nullptr, 0) == nullptr);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_type(nullptr, 0) == 0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_requestor(nullptr, 0) == nullptr);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_backend(nullptr, 0) == nullptr);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_protocol(nullptr, 0) == 0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_size(nullptr, 0) == 0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_latency(nullptr, 0) == 0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_id(nullptr, 0) == 0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_rcode(nullptr, 0) == 0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_aa(nullptr, 0) == false);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_rd(nullptr, 0) == false);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_tc(nullptr, 0) == false);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_ancount(nullptr, 0) == 0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_nscount(nullptr, 0) == 0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_arcount(nullptr, 0) == 0);
    BOOST_CHECK(!dnsdist_ffi_ring_entry_has_mac_address(nullptr, 0));
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_mac_address(nullptr, 0) == nullptr);
  }

  BOOST_REQUIRE_EQUAL(dnsdist_ffi_ring_get_entries(&list), 2U);
  BOOST_CHECK(list != nullptr);

  BOOST_CHECK(!dnsdist_ffi_ring_entry_is_response(list, 0));
  BOOST_CHECK(dnsdist_ffi_ring_entry_is_response(list, 1));

  for (size_t idx = 0; idx < 2; idx++) {
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_age(list, idx) >= 0.0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_age(list, idx) < 2.0);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_name(list, idx) == qname.toString());
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_type(list, idx) == qtype);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_requestor(list, idx) == requestor1.toStringWithPort());
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_protocol(list, idx) == protocol.toNumber());
    BOOST_CHECK_EQUAL(dnsdist_ffi_ring_entry_get_size(list, idx), size);
    BOOST_CHECK_EQUAL(dnsdist_ffi_ring_entry_get_id(list, idx), 42U);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_aa(list, idx) == false);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_rd(list, idx) == true);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_tc(list, idx) == false);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_ancount(list, idx) == 1);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_nscount(list, idx) == 1);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_arcount(list, idx) == 1);
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_rcode(list, idx) == RCode::NXDomain);
    if (dnsdist_ffi_ring_entry_is_response(list, idx)) {
      BOOST_CHECK(dnsdist_ffi_ring_entry_get_backend(list, idx) == backend.toStringWithPort());
      BOOST_CHECK_EQUAL(dnsdist_ffi_ring_entry_get_latency(list, idx), responseTime);
    }
    BOOST_CHECK(!dnsdist_ffi_ring_entry_has_mac_address(list, idx));
    BOOST_CHECK(dnsdist_ffi_ring_entry_get_mac_address(list, idx) == std::string());
  }

  dnsdist_ffi_ring_entry_list_free(list);
  list = nullptr;

  // not the right requestor
  BOOST_REQUIRE_EQUAL(dnsdist_ffi_ring_get_entries_by_addr("192.0.2.2", &list), 0U);
  BOOST_CHECK(list == nullptr);

  BOOST_REQUIRE_EQUAL(dnsdist_ffi_ring_get_entries_by_addr(requestor1.toString().c_str(), &list), 2U);
  BOOST_CHECK(list != nullptr);
  dnsdist_ffi_ring_entry_list_free(list);
  list = nullptr;
}

BOOST_AUTO_TEST_CASE(test_NetworkEndpoint)
{
  {
    dnsdist_ffi_network_endpoint_t* endpoint = nullptr;
    BOOST_CHECK(!dnsdist_ffi_network_endpoint_new("a", 1, nullptr));
    BOOST_CHECK(!dnsdist_ffi_network_endpoint_new(nullptr, 1, &endpoint));
    BOOST_CHECK(!dnsdist_ffi_network_endpoint_new("a", 0, &endpoint));
    // the path does not exist
    BOOST_CHECK(!dnsdist_ffi_network_endpoint_new("a", 1, &endpoint));
  }

  {
    BOOST_CHECK(!dnsdist_ffi_network_endpoint_is_valid(nullptr));
  }

  {
    dnsdist_ffi_network_endpoint_t* endpoint = nullptr;
    BOOST_CHECK(!dnsdist_ffi_network_endpoint_send(nullptr, "a", 1));
    BOOST_CHECK(!dnsdist_ffi_network_endpoint_send(endpoint, nullptr, 1));
  }

  {
    dnsdist_ffi_network_endpoint_free(nullptr);
  }
}

BOOST_AUTO_TEST_CASE(test_hash)
{
  const uint32_t seed = 0x42;
  const std::array<unsigned char, 10> data{{'0', 'x', 'd', 'e', 'a', 'd', 'b', 'E', 'e', 'F'}};
  const std::array<unsigned char, 10> capitalizedData{{'0', 'X', 'D', 'E', 'A', 'D', 'B', 'E', 'E', 'F'}};

  {
    /* invalid */
    BOOST_CHECK_EQUAL(dnsdist_ffi_hash(0, nullptr, 0, false), 0U);
    BOOST_CHECK_EQUAL(dnsdist_ffi_hash(seed, nullptr, 0, false), seed);
  }
  {
    /* case sensitive */
    auto hash = dnsdist_ffi_hash(seed, data.data(), data.size(), false);
    BOOST_CHECK_EQUAL(hash, burtle(data.data(), data.size(), seed));
    BOOST_CHECK_NE(hash, burtle(capitalizedData.data(), capitalizedData.size(), seed));
    BOOST_CHECK_NE(hash, burtleCI(capitalizedData.data(), capitalizedData.size(), seed));
  }
  {
    /* case insensitive */
    auto hash = dnsdist_ffi_hash(seed, data.data(), data.size(), true);
    BOOST_CHECK_EQUAL(hash, burtleCI(data.data(), data.size(), seed));
    BOOST_CHECK_NE(hash, burtle(capitalizedData.data(), capitalizedData.size(), seed));
    BOOST_CHECK_EQUAL(hash, burtleCI(capitalizedData.data(), capitalizedData.size(), seed));
  }
}

BOOST_AUTO_TEST_CASE(test_SVC_Generation)
{
  dnsdist_ffi_svc_record_parameters* parameters{nullptr};

  {
    /* invalid parameters */
    BOOST_CHECK_EQUAL(dnsdist_ffi_svc_record_parameters_new(nullptr, 0, false, &parameters), false);
    BOOST_CHECK_EQUAL(dnsdist_ffi_svc_record_parameters_new("powerdns.com.", 0, false, nullptr), false);
  }

  BOOST_REQUIRE_EQUAL(dnsdist_ffi_svc_record_parameters_new("powerdns.com.", 1, true, &parameters), true);
  BOOST_REQUIRE(parameters != nullptr);

  {
    /* invalid parameters */
    dnsdist_ffi_svc_record_parameters_set_port(nullptr, 0);
    dnsdist_ffi_svc_record_parameters_set_ech(nullptr, "alpn", 4);
    dnsdist_ffi_svc_record_parameters_set_additional_param(nullptr, 7, "/dns-query{?dns}", 16);
    dnsdist_ffi_svc_record_parameters_set_additional_param(parameters, 7, nullptr, 0);
    dnsdist_ffi_svc_record_parameters_add_mandatory_param(nullptr, 0);
    dnsdist_ffi_svc_record_parameters_add_alpn(nullptr, "h2", 2);
    dnsdist_ffi_svc_record_parameters_add_alpn(parameters, nullptr, 0);
    dnsdist_ffi_svc_record_parameters_add_ipv4_hint(parameters, nullptr, 0);
    dnsdist_ffi_svc_record_parameters_add_ipv4_hint(nullptr, nullptr, 0);
    dnsdist_ffi_svc_record_parameters_add_ipv6_hint(parameters, nullptr, 0);
    dnsdist_ffi_svc_record_parameters_add_ipv6_hint(nullptr, nullptr, 0);
    dnsdist_ffi_dnsquestion_generate_svc_response(nullptr, nullptr, 0, 0);
  }

  dnsdist_ffi_svc_record_parameters_set_port(parameters, 443);
  dnsdist_ffi_svc_record_parameters_set_ech(parameters, "binary", 6);
  dnsdist_ffi_svc_record_parameters_set_additional_param(parameters, 7, "/dns-query{?dns}", 16);
  dnsdist_ffi_svc_record_parameters_add_mandatory_param(parameters, 7);
  dnsdist_ffi_svc_record_parameters_add_alpn(parameters, "h2", 2);
  dnsdist_ffi_svc_record_parameters_add_ipv4_hint(parameters, "9.9.9.9", 8);
  dnsdist_ffi_svc_record_parameters_add_ipv6_hint(parameters, "2620:fe::fe", 11);

  {
    InternalQueryState ids;
    ids.origRemote = ComboAddress("192.0.2.1:4242");
    ids.origDest = ComboAddress("192.0.2.255:53");
    ids.qtype = QType::A;
    ids.qclass = QClass::IN;
    ids.protocol = dnsdist::Protocol::DoUDP;
    ids.qname = DNSName("www.powerdns.com.");
    ids.queryRealTime.start();
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = htons(42);

    DNSQuestion dnsQuestion(ids, query);
    dnsdist_ffi_dnsquestion_t lightDQ(&dnsQuestion);
    std::array<const dnsdist_ffi_svc_record_parameters*, 1> list = {parameters};
    BOOST_CHECK_EQUAL(dnsdist_ffi_dnsquestion_generate_svc_response(&lightDQ, list.data(), list.size(), 42), true);
  }

  dnsdist_ffi_svc_record_parameters_free(parameters);
}

#if !defined(DISABLE_PROTOBUF)
BOOST_AUTO_TEST_CASE(test_meta_values)
{
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:4242");
  ids.origDest = ComboAddress("192.0.2.255:53");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = DNSName("www.powerdns.com.");
  ids.queryRealTime.start();
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  pwQ.getHeader()->id = htons(42);

  DNSQuestion dnsQuestion(ids, query);
  dnsdist_ffi_dnsquestion_t lightDQ(&dnsQuestion);

  {
    /* check invalid parameters */
    dnsdist_ffi_dnsquestion_meta_begin_key(nullptr, nullptr, 0);
    dnsdist_ffi_dnsquestion_meta_begin_key(&lightDQ, nullptr, 0);
    dnsdist_ffi_dnsquestion_meta_begin_key(&lightDQ, "some-key", 0);
    dnsdist_ffi_dnsquestion_meta_add_str_value_to_key(nullptr, nullptr, 0);
    dnsdist_ffi_dnsquestion_meta_add_str_value_to_key(&lightDQ, nullptr, 0);
    dnsdist_ffi_dnsquestion_meta_add_str_value_to_key(&lightDQ, "some-str-value", 0);
    dnsdist_ffi_dnsquestion_meta_add_int64_value_to_key(nullptr, 0);
    dnsdist_ffi_dnsquestion_meta_end_key(nullptr);
  }

  {
    /* trying to end a key that has not been started */
    dnsdist_ffi_dnsquestion_meta_end_key(&lightDQ);
  }

  {
    const std::string key{"some-key"};
    const std::string value1{"first value"};
    const std::string value2{"second value"};
    BOOST_CHECK_EQUAL(dnsQuestion.d_rawProtobufContent.size(), 0U);
    dnsdist_ffi_dnsquestion_meta_begin_key(&lightDQ, key.data(), key.size());
    /* we should not be able to begin a new key without ending it first */
    dnsdist_ffi_dnsquestion_meta_begin_key(&lightDQ, key.data(), key.size());
    dnsdist_ffi_dnsquestion_meta_add_str_value_to_key(&lightDQ, value1.data(), value1.size());
    dnsdist_ffi_dnsquestion_meta_add_int64_value_to_key(&lightDQ, 42);
    dnsdist_ffi_dnsquestion_meta_add_str_value_to_key(&lightDQ, value2.data(), value2.size());
    dnsdist_ffi_dnsquestion_meta_add_int64_value_to_key(&lightDQ, -42);
    dnsdist_ffi_dnsquestion_meta_end_key(&lightDQ);
    BOOST_CHECK_EQUAL(dnsQuestion.d_rawProtobufContent.size(), 55U);
    BOOST_CHECK_EQUAL(Base64Encode(dnsQuestion.d_rawProtobufContent), "sgE0Cghzb21lLWtleRIoCgtmaXJzdCB2YWx1ZRAqCgxzZWNvbmQgdmFsdWUQ1v//////////AQ==");
  }
}
#endif /* DISABLE_PROTOBUF */

BOOST_AUTO_TEST_CASE(test_set_altername_name)
{
  const DNSName initialQName("www.powerdns.com.");
  InternalQueryState ids;
  ids.origRemote = ComboAddress("192.0.2.1:4242");
  ids.origDest = ComboAddress("192.0.2.255:53");
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.qname = initialQName;
  ids.queryRealTime.start();
  PacketBuffer query;
  GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  pwQ.getHeader()->id = htons(42);

  DNSQuestion dnsQuestion(ids, query);
  dnsdist_ffi_dnsquestion_t lightDQ(&dnsQuestion);

  {
    /* check invalid parameters */
    dnsdist_ffi_dnsquestion_set_alternate_name(nullptr, nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0);
    dnsdist_ffi_dnsquestion_set_alternate_name(&lightDQ, nullptr, 0, nullptr, 0, nullptr, 0, nullptr, 0);
    dnsdist_ffi_dnsquestion_set_alternate_name(&lightDQ, "alternate", 0, nullptr, 0, nullptr, 0, nullptr, 0);
  }

  const std::string tag("alternate-name-tag");
  const std::string tagValue("alternate-name-tag-value");
  const std::string formerTagName("alternate-name-former-value");
  const DNSName target("new.target.net.");
  BOOST_REQUIRE(dnsdist_ffi_dnsquestion_set_alternate_name(&lightDQ, target.getStorage().data(), target.getStorage().size(), tag.data(), tag.size(), tagValue.data(), tagValue.size(), formerTagName.data(), formerTagName.size()));

  BOOST_CHECK_EQUAL(ids.qname.toString(), target.toString());
  BOOST_CHECK_EQUAL(ids.skipCache, true);
  BOOST_REQUIRE(ids.qTag != nullptr);
  BOOST_CHECK_EQUAL(ids.qTag->at(tag), tagValue);
  BOOST_CHECK_EQUAL(ids.qTag->at(formerTagName), initialQName.getStorage());

  MOADNSParser mdp(false, reinterpret_cast<const char*>(dnsQuestion.getData().data()), dnsQuestion.getData().size());
  BOOST_CHECK_EQUAL(mdp.d_qname, target);
  BOOST_CHECK_EQUAL(mdp.d_header.qdcount, 1U);
}

BOOST_AUTO_TEST_SUITE_END();
