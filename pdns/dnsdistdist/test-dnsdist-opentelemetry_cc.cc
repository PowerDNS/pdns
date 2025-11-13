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
#include "protozero-trace.hh"
#include <boost/test/unit_test_suite.hpp>
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
  auto spanid = tracer->openSpan("myevent").getSpanID();
  lastSpanID = tracer->getLastSpanID();
  BOOST_CHECK_EQUAL(spanid, lastSpanID);

  for (auto i = 0; i < 4; i++) {
    spanid = tracer->openSpan("myevent" + std::to_string(i)).getSpanID();
  }
  lastSpanID = tracer->getLastSpanID();
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
    auto closer = tracer->getCloser(spanid);

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

BOOST_AUTO_TEST_SUITE_END()
#endif // DISABLE_PROTOBUF
