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
#include "dnsdist-ecs.hh"
#include "ednsoptions.hh"
#include "noinitvector.hh"
#include "protozero-trace.hh"
#include "dnswriter.hh"
#include "dnsparser.hh"
#include "views.hh"

#include <array>
#include <boost/test/unit_test_suite.hpp>
#include <initializer_list>
#include <limits>
#include <memory>
#include <ostream>
#include <vector>
#ifndef DISABLE_PROTOBUF
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>
#include <boost/test/tools/old/interface.hpp>
#include <string>

#include "dnsdist-opentelemetry.hh"

#define BOOST_TEST_NO_MAIN

BOOST_AUTO_TEST_SUITE(dnsdistopentelemetry_cc)
BOOST_AUTO_TEST_CASE(TraceID)
{
  // Ensure we always have a TraceID
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  BOOST_CHECK_NE(tracer->getTraceID(), pdns::trace::s_emptyTraceID);

  // Ensure we have a trace ID, even if we don't call getTraceID
  tracer = pdns::trace::dnsdist::Tracer::getTracer();
  tracer->openSpan("bla");
  auto data = tracer->getTracesData();
  BOOST_CHECK_NE(data.resource_spans.at(0).scope_spans.at(0).spans.at(0).trace_id, pdns::trace::s_emptyTraceID);
}

BOOST_AUTO_TEST_CASE(getLastSpanID)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();

  // Empty SpanID returned when there are no spans
  auto lastSpanID = tracer->getLastSpanID();
  BOOST_CHECK_EQUAL(lastSpanID, SpanID{});

  // Add event before activation
  auto closer = tracer->openSpan("myevent");
  auto spanid = closer.getSpanID();
  lastSpanID = tracer->getLastSpanID();
  BOOST_CHECK_EQUAL(spanid, lastSpanID);

  for (auto i = 0; i < 4; i++) {
    auto closer2 = tracer->openSpan("myevent" + std::to_string(i));
    spanid = closer2.getSpanID();
    lastSpanID = tracer->getLastSpanID();
  }
  BOOST_CHECK_EQUAL(spanid, lastSpanID);
}

BOOST_AUTO_TEST_CASE(getLastSpanIDForName)
{
  // We only create spans with the same name
  std::string eventName{"myEvent"};
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();

  // Empty SpanID returned when there are no spans
  auto lastSpanID = tracer->getLastSpanIDForName(eventName);
  BOOST_CHECK_EQUAL(lastSpanID, SpanID{});

  // Add event before activation
  auto spanid = tracer->openSpan(eventName).getSpanID();
  lastSpanID = tracer->getLastSpanIDForName(eventName);
  BOOST_CHECK_EQUAL(spanid, lastSpanID);

  for (auto i = 0; i < 4; i++) {
    spanid = tracer->openSpan(eventName).getSpanID();
  }
  lastSpanID = tracer->getLastSpanIDForName(eventName);
  BOOST_CHECK_EQUAL(spanid, lastSpanID);
}

BOOST_AUTO_TEST_CASE(Closer)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();

  auto spanid = tracer->openSpan("foo").getSpanID();

  SpanID openeventSpanID;
  SpanID openevent2SpanID;

  {
    auto openEventCloser = tracer->openSpan("openEvent");
    openeventSpanID = openEventCloser.getSpanID();
    auto openEventCloser2 = tracer->openSpan("openEvent2", openeventSpanID);
    openevent2SpanID = openEventCloser2.getSpanID();

    // Make sure the destructor does not segfault when it is empty
    pdns::trace::dnsdist::Tracer::Closer emptyCloser;
  }

  // Closer is out of scope, so each event should have a closing time
  auto trace = tracer->getTracesData();
  BOOST_ASSERT(trace.resource_spans.at(0).scope_spans.at(0).spans.size() == 3);

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).span_id, spanid);
  BOOST_CHECK_NE(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).end_time_unix_nano, 0U);

  BOOST_CHECK_NE(trace.resource_spans.at(0).scope_spans.at(0).spans.at(1).end_time_unix_nano, 0U);
  BOOST_CHECK_NE(trace.resource_spans.at(0).scope_spans.at(0).spans.at(1).end_time_unix_nano, 0U);

  // Check the parent span_id for the second closer
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(2).span_id, openevent2SpanID);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(2).parent_span_id, openeventSpanID);

  pdns::trace::dnsdist::Tracer::Closer emptyCloser;
  BOOST_CHECK_EQUAL(emptyCloser.getSpanID(), SpanID{});
}

BOOST_AUTO_TEST_CASE(traceAttributes)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  tracer->setTraceAttribute("foo", AnyValue{"bar"});

  auto trace = tracer->getTracesData();
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).resource.attributes.size(), 1U);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).resource.attributes.at(0).key, "service.name");

  // Check if we have a hostname
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.size(), 2U);

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.at(0).key, "foo");
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.at(0).value, AnyValue{"bar"});

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.at(1).key, "hostname");
}

BOOST_AUTO_TEST_CASE(spanAttributes)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("myspan");
  auto spanid = closer.getSpanID();
  tracer->setSpanAttribute(spanid, "foo", AnyValue{42});
  closer.setAttribute("bar", AnyValue{"hello"});
  auto trace = tracer->getTracesData();

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.size(), 1U);

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.size(), 2U);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.at(0).key, "foo");
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.at(0).value, AnyValue{42});

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.at(1).key, "bar");
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.at(1).value, AnyValue{"hello"});
}

BOOST_AUTO_TEST_CASE(rootSpanAttributes)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("myspan");
  auto spanid = closer.getSpanID();
  tracer->openSpan("not root", spanid);

  tracer->setRootSpanAttribute("foobar", AnyValue{"baz"});

  auto trace = tracer->getTracesData();

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.size(), 2U);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.size(), 1U);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.at(0).key, "foobar");
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.at(0).value, AnyValue{"baz"});
}

BOOST_AUTO_TEST_CASE(getOTProtobuf)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto data = tracer->getOTProtobuf();
  BOOST_TEST(data.size() >= 100U);

  tracer->setTraceAttribute("foo", AnyValue{"bar"});
  data = tracer->getOTProtobuf();
  BOOST_TEST(data.size() >= 110U);
}

BOOST_AUTO_TEST_CASE(setTraceID)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto oldTraceID = tracer->getTraceID();
  auto newTraceID = pdns::trace::TraceID::getRandomTraceID();
  while (oldTraceID == newTraceID) {
    newTraceID.makeRandom();
  }
  tracer->setTraceID(newTraceID);
  BOOST_CHECK_EQUAL(tracer->getTraceID(), newTraceID);
}

BOOST_AUTO_TEST_CASE(setRootSpanID)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  // Setting the root span id without any spans should not error
  auto newRootSpanID = pdns::trace::SpanID::getRandomSpanID();
  tracer->setRootSpanID(newRootSpanID);
  BOOST_CHECK_EQUAL(pdns::trace::s_emptySpanID, tracer->getRootSpanID());

  // Add a Span, this'll be the root span
  auto originalRootSpanID = tracer->openSpan("rootspan").getSpanID();
  BOOST_CHECK_EQUAL(originalRootSpanID, tracer->getRootSpanID());

  // Add 4 spans, all children of the root span
  for (auto i = 0; i < 4; i++) {
    tracer->openSpan("span " + std::to_string(i), originalRootSpanID);
  }

  // Now set the new root span ID
  while (newRootSpanID == originalRootSpanID) {
    newRootSpanID.makeRandom();
  }
  tracer->setRootSpanID(newRootSpanID);
  BOOST_CHECK_EQUAL(tracer->getRootSpanID(), newRootSpanID);

  // Verify the parent_span_id is updated
  auto data = tracer->getTracesData();
  for (auto i = 0; i < 4; i++) {
    BOOST_CHECK_EQUAL(data.resource_spans.at(0).scope_spans.at(0).spans.at(i + 1).parent_span_id, newRootSpanID);
  }

  // New tracer, so we can easily test if non-root parent span IDs are not updated
  tracer = pdns::trace::dnsdist::Tracer::getTracer();
  // Add a Span, this'll be the root span
  originalRootSpanID = tracer->openSpan("rootspan").getSpanID();
  BOOST_CHECK_EQUAL(originalRootSpanID, tracer->getRootSpanID());

  tracer->openSpan("span one", pdns::trace::SpanID::getRandomSpanID());
  tracer->openSpan("span two", pdns::trace::SpanID::getRandomSpanID());
  while (newRootSpanID == originalRootSpanID) {
    newRootSpanID.makeRandom();
  }
  tracer->setRootSpanID(newRootSpanID);
  data = tracer->getTracesData();
  for (auto i = 0; i < 2; i++) {
    BOOST_CHECK_NE(data.resource_spans.at(0).scope_spans.at(0).spans.at(i + 1).parent_span_id, newRootSpanID);
  }
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_empty)
{
  // Ensure we return false when Tracer is nullptr
  PacketBuffer buf;
  auto ret = pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, nullptr, 0, 0, EDNSOptionCode::TRACEPARENT, false);
  BOOST_CHECK(!ret);
};

static void checkTraceparent(const PacketBuffer& packet, const std::shared_ptr<pdns::trace::dnsdist::Tracer> tracer, const size_t optRDPosition)
{
  pdns::trace::EDNSOTTraceRecordView data{reinterpret_cast<const uint8_t*>(&packet[optRDPosition + DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE]), pdns::trace::EDNSOTTraceRecord::fullSize}; // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)

  uint8_t version;
  BOOST_ASSERT(data.getVersion(version));
  BOOST_CHECK_EQUAL(version, 0U);

  uint8_t reserved;
  BOOST_ASSERT(data.getReserved(reserved));
  BOOST_CHECK_EQUAL(reserved, 0U);

  pdns::trace::TraceID traceid;
  BOOST_ASSERT(data.getTraceID(traceid));
  BOOST_CHECK_EQUAL(traceid, tracer->getTraceID());

  pdns::trace::SpanID spanid;
  BOOST_ASSERT(data.getSpanID(spanid));
  BOOST_CHECK_EQUAL(spanid, tracer->getLastSpanID());

  uint8_t flags;
  BOOST_ASSERT(data.getFlags(flags));
  BOOST_CHECK_EQUAL(flags, 0U);
}

static const uint16_t ednsBufSize{1700};
static const DNSName qname{"powerdns.com"};
static PacketBuffer getPacket(bool edns = false, bool traceparentOpt = false)
{
  PacketBuffer buf;
  GenericDNSPacketWriter<PacketBuffer> pwQ(buf, qname, QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;
  if (edns) {
    vector<pair<uint16_t, std::string>> ednsopts;
    if (traceparentOpt) {
      ednsopts.push_back({EDNSOptionCode::TRACEPARENT, {
                                                         0, // VERSION
                                                         0, // RESERVED
                                                         1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, // TRACEID
                                                         1, 2, 3, 4, 5, 6, 7, 8, // SPANID
                                                         0 // FLAGS
                                                       }});
    }
    pwQ.addOpt(ednsBufSize, 0, 0, ednsopts);
  }
  pwQ.commit();

  return buf;
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_udp)
{
  auto buf = getPacket();

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), 0, EDNSOptionCode::TRACEPARENT, false);

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(buf, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);
  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we set the EDNS buffer size to 512 for non-EDNS queries
  uint16_t ednsBufSizeFromPacket = (buf.at(optRDPosition - 6) << 8) + buf.at(optRDPosition - 5);
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, 512);

  checkTraceparent(buf, tracer, optRDPosition);
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_udp_proxy)
{
  auto buf = getPacket();

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  // Let's just add 7 bytes to the beginning of the packet
  const size_t proxyPayloadSize = 7;
  std::array<uint8_t, proxyPayloadSize> proxyPayload{1, 2, 3, 4, 5, 6, 7};
  buf.insert(buf.begin(), proxyPayload.begin(), proxyPayload.end());

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), proxyPayloadSize, EDNSOptionCode::TRACEPARENT, false);

  // Ensure we still have the full proxy payload
  std::array<uint8_t, proxyPayloadSize> payloadAfter;
  std::copy_n(buf.begin(), proxyPayloadSize, payloadAfter.begin());
  BOOST_CHECK(proxyPayload == payloadAfter);

  // Make a DNS packet without Proxy headers and test
  PacketBuffer packet{buf.begin() + proxyPayloadSize, buf.end()};

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(packet, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);
  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we set the EDNS buffer size to 512 for non-EDNS queries
  uint16_t ednsBufSizeFromPacket = (packet.at(optRDPosition - 6) << 8) + packet.at(optRDPosition - 5);
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, 512);

  checkTraceparent(packet, tracer, optRDPosition);
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_udp_edns)
{
  auto buf = getPacket(true);

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), 0, EDNSOptionCode::TRACEPARENT, false);

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(buf, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);
  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we keep the EDNS buffer size
  uint16_t ednsBufSizeFromPacket = (buf.at(optRDPosition - 6) << 8) + buf.at(optRDPosition - 5);
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, ednsBufSize);

  checkTraceparent(buf, tracer, optRDPosition);
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_udp_edns_traceparent)
{
  auto buf = getPacket(true, true);

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), 0, EDNSOptionCode::TRACEPARENT, false);

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(buf, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);

  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we keep the EDNS buffer size
  uint16_t ednsBufSizeFromPacket = (buf.at(optRDPosition - 6) << 8) + buf.at(optRDPosition - 5);
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, ednsBufSize);

  // Check that we overwrote the whole TRACEPARENT
  checkTraceparent(buf, tracer, optRDPosition);
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_udp_edns_proxy)
{
  auto buf = getPacket(true);

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  // Let's just add 7 bytes to the beginning of the packet
  const size_t proxyPayloadSize = 7;
  std::array<uint8_t, proxyPayloadSize> proxyPayload{1, 2, 3, 4, 5, 6, 7};
  buf.insert(buf.begin(), proxyPayload.begin(), proxyPayload.end());

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), proxyPayloadSize, EDNSOptionCode::TRACEPARENT, false);

  // Ensure we still have the full proxy payload
  std::array<uint8_t, proxyPayloadSize> payloadAfter;
  std::copy_n(buf.begin(), proxyPayloadSize, payloadAfter.begin());
  BOOST_CHECK(proxyPayload == payloadAfter);

  // Make a DNS packet without Proxy headers and test
  PacketBuffer packet{buf.begin() + proxyPayloadSize, buf.end()};

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(packet, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);
  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we keep the EDNS buffer size
  uint16_t ednsBufSizeFromPacket = (packet.at(optRDPosition - 6) << 8) + packet.at(optRDPosition - 5);
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, ednsBufSize);

  checkTraceparent(packet, tracer, optRDPosition);
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_tcp)
{
  auto buf = getPacket();

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  std::array<uint8_t, 2> tcpSize{(uint8_t)(buf.size() >> 8), (uint8_t)buf.size()};
  buf.insert(buf.begin(), tcpSize.begin(), tcpSize.end());

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), 0, EDNSOptionCode::TRACEPARENT, true);

  // Verify we set the new TCP size correctly
  uint16_t tcpSizeAfter = (buf.at(0) << 8) + buf.at(1);
  BOOST_CHECK_EQUAL(tcpSizeAfter, buf.size() - 2);

  PacketBuffer packet{buf.begin() + 2, buf.end()};

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(packet, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);
  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we set the EDNS buffer size to max(uint16_t) for non-EDNS TCP queries
  uint16_t ednsBufSizeFromPacket = (packet.at(optRDPosition - 6) << 8) + packet.at(optRDPosition - 5);
  // Ignored over TCP, but we still set is to 512
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, 512);

  checkTraceparent(packet, tracer, optRDPosition);
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_tcp_proxy)
{
  auto buf = getPacket();

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  std::array<uint8_t, 2> tcpSize{(uint8_t)(buf.size() >> 8), (uint8_t)buf.size()};
  buf.insert(buf.begin(), tcpSize.begin(), tcpSize.end());

  // Let's just add 7 bytes to the beginning of the packet
  const size_t proxyPayloadSize = 7;
  std::array<uint8_t, proxyPayloadSize> proxyPayload{1, 2, 3, 4, 5, 6, 7};
  buf.insert(buf.begin(), proxyPayload.begin(), proxyPayload.end());

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), proxyPayloadSize, EDNSOptionCode::TRACEPARENT, true);

  // Ensure we still have the full proxy payload
  std::array<uint8_t, proxyPayloadSize> payloadAfter;
  std::copy_n(buf.begin(), proxyPayloadSize, payloadAfter.begin());
  BOOST_CHECK(proxyPayload == payloadAfter);

  // Make a DNS packet without Proxy headers and test
  PacketBuffer packet{buf.begin() + proxyPayloadSize, buf.end()};

  // Verify we set the new TCP size correctly
  uint16_t tcpSizeAfter = (packet.at(0) << 8) + packet.at(1);
  BOOST_CHECK_EQUAL(tcpSizeAfter, packet.size() - 2);

  // Strip the TCP header
  packet = {packet.begin() + 2, packet.end()};

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(packet, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);
  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we set the EDNS buffer size to max(uint16_t) for non-EDNS TCP queries
  uint16_t ednsBufSizeFromPacket = (packet.at(optRDPosition - 6) << 8) + packet.at(optRDPosition - 5);
  // Ignored over TCP, but we still set is to 512
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, 512);

  checkTraceparent(packet, tracer, optRDPosition);
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_tcp_edns)
{
  auto buf = getPacket(true);

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  std::array<uint8_t, 2> tcpSize{(uint8_t)(buf.size() >> 8), (uint8_t)buf.size()};
  buf.insert(buf.begin(), tcpSize.begin(), tcpSize.end());

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), 0, EDNSOptionCode::TRACEPARENT, true);

  // Verify we set the new TCP size correctly
  uint16_t tcpSizeAfter = (buf.at(0) << 8) + buf.at(1);
  BOOST_CHECK_EQUAL(tcpSizeAfter, buf.size() - 2);

  PacketBuffer packet{buf.begin() + 2, buf.end()};

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(packet, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);
  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we keep the EDNS buffer size
  uint16_t ednsBufSizeFromPacket = (packet.at(optRDPosition - 6) << 8) + packet.at(optRDPosition - 5);
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, ednsBufSize);

  checkTraceparent(packet, tracer, optRDPosition);
}

BOOST_AUTO_TEST_CASE(addTraceparentToPacketBuffer_tcp_edns_proxy)
{
  auto buf = getPacket(true);

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto closer = tracer->openSpan("foo");

  std::array<uint8_t, 2> tcpSize{(uint8_t)(buf.size() >> 8), (uint8_t)buf.size()};
  buf.insert(buf.begin(), tcpSize.begin(), tcpSize.end());

  // Let's just add 7 bytes to the beginning of the packet
  const size_t proxyPayloadSize = 7;
  std::array<uint8_t, proxyPayloadSize> proxyPayload{1, 2, 3, 4, 5, 6, 7};
  buf.insert(buf.begin(), proxyPayload.begin(), proxyPayload.end());

  pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(buf, tracer, qname.wirelength(), proxyPayloadSize, EDNSOptionCode::TRACEPARENT, true);

  // Ensure we still have the full proxy payload
  std::array<uint8_t, proxyPayloadSize> payloadAfter;
  std::copy_n(buf.begin(), proxyPayloadSize, payloadAfter.begin());
  BOOST_CHECK(proxyPayload == payloadAfter);

  // Make a DNS packet without Proxy headers and test
  PacketBuffer packet{buf.begin() + proxyPayloadSize, buf.end()};

  // Verify we set the new TCP size correctly
  uint16_t tcpSizeAfter = (packet.at(0) << 8) + packet.at(1);
  BOOST_CHECK_EQUAL(tcpSizeAfter, packet.size() - 2);

  packet = {packet.begin() + 2, packet.end()};

  uint16_t optRDPosition{0};
  size_t remaining{0};
  auto ednsOptstartRet = dnsdist::getEDNSOptionsStart(packet, qname.wirelength(), &optRDPosition, &remaining);

  BOOST_CHECK_EQUAL(ednsOptstartRet, 0);
  BOOST_CHECK_NE(optRDPosition, 0);
  BOOST_CHECK_EQUAL(remaining, DNS_RDLENGTH_SIZE + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE + pdns::trace::EDNSOTTraceRecord::fullSize);

  // Ensure we keep the EDNS buffer size
  uint16_t ednsBufSizeFromPacket = (packet.at(optRDPosition - 6) << 8) + packet.at(optRDPosition - 5);
  BOOST_CHECK_EQUAL(ednsBufSizeFromPacket, ednsBufSize);

  checkTraceparent(packet, tracer, optRDPosition);
}

BOOST_AUTO_TEST_SUITE_END()
#endif // DISABLE_PROTOBUF
