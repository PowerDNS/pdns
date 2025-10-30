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
#ifndef DISABLE_PROTOBUF
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#include <boost/optional/optional.hpp>
#endif

#include <boost/test/unit_test.hpp>
#include <boost/test/tools/old/interface.hpp>
#include <string>

#include "dnsdist-opentelemetry.hh"

#define BOOST_TEST_NO_MAIN

BOOST_AUTO_TEST_SUITE(dnsdistopentelemetry_cc)
BOOST_AUTO_TEST_CASE(getTraceID)
{
  // Ensure we always have a TraceID after activation
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  BOOST_CHECK_EQUAL(tracer->getTraceID(), TraceID{});

  // Ensure we have one *after* activation
  tracer->activate();
  auto traceid = tracer->getTraceID();
  BOOST_CHECK_NE(traceid, TraceID{});

  // Ensure we have the same one *after* deactivation
  tracer->deactivate();
  BOOST_CHECK_EQUAL(tracer->getTraceID(), traceid);

  // Ensure we have the same one *after* reactivation
  tracer->deactivate();
  BOOST_CHECK_EQUAL(tracer->getTraceID(), traceid);
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

  tracer->activate();
  spanid = tracer->openSpan("post-activation-myevent").getSpanID();
  lastSpanID = tracer->getLastSpanID();
  BOOST_CHECK_EQUAL(spanid, lastSpanID);

  for (auto i = 0; i < 4; i++) {
    spanid = tracer->openSpan("post-activation-myevent" + std::to_string(i)).getSpanID();
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
  auto preactivationSpanID = spanid;

  tracer->activate();
  spanid = tracer->openSpan(eventName).getSpanID();
  lastSpanID = tracer->getLastSpanIDForName(eventName);
  BOOST_CHECK_EQUAL(spanid, lastSpanID);

  for (auto i = 0; i < 4; i++) {
    spanid = tracer->openSpan(eventName).getSpanID();
  }
  lastSpanID = tracer->getLastSpanIDForName(eventName);
  BOOST_CHECK_EQUAL(spanid, lastSpanID);

  tracer->deactivate();
  lastSpanID = tracer->getLastSpanIDForName(eventName);
  BOOST_CHECK_EQUAL(preactivationSpanID, lastSpanID);
}

BOOST_AUTO_TEST_CASE(activate)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();

  // We don't actually check the internal state, but we infer it from the order
  // of the output.
  auto preActivationSpanID = tracer->openSpan("pre-activation-event").getSpanID();
  tracer->activate();
  auto postActivationSpanID = tracer->openSpan("post-activation-event").getSpanID();

  // Ensure order is pre1, post1
  auto trace = tracer->getTracesData();
  BOOST_ASSERT(trace.resource_spans.at(0).scope_spans.at(0).spans.size() == 2);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).span_id, preActivationSpanID);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(1).span_id, postActivationSpanID);

  // Now deactivate and check if the order will be pre1, pre2, post1
  tracer->deactivate();
  auto preActivationSpanID2 = tracer->openSpan("pre-activation-event2").getSpanID();

  trace = tracer->getTracesData();
  BOOST_ASSERT(trace.resource_spans.at(0).scope_spans.at(0).spans.size() == 3);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).span_id, preActivationSpanID);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(1).span_id, preActivationSpanID2);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(2).span_id, postActivationSpanID);
}

BOOST_AUTO_TEST_CASE(Closer)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();

  auto prespanid = tracer->openSpan("foo").getSpanID();
  tracer->activate();
  auto postspanid = tracer->openSpan("bar").getSpanID();

  SpanID openeventSpanID;
  SpanID openevent2SpanID;

  {
    auto precloser = tracer->getCloser(prespanid);
    auto postcloser = tracer->getCloser(postspanid);

    auto openEventCloser = tracer->openSpan("openEvent");
    openeventSpanID = openEventCloser.getSpanID();
    auto openEventCloser2 = tracer->openSpan("openEvent2", openeventSpanID);
    openevent2SpanID = openEventCloser2.getSpanID();

    // Make sure the destructor does not segfault when it is empty
    pdns::trace::dnsdist::Tracer::Closer emptyCloser;
  }

  // Closer is out of scope, so each event should have a closing time
  auto trace = tracer->getTracesData();
  BOOST_ASSERT(trace.resource_spans.at(0).scope_spans.at(0).spans.size() == 4);

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).span_id, prespanid);
  BOOST_CHECK_NE(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).end_time_unix_nano, 0U);

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(1).span_id, postspanid);
  BOOST_CHECK_NE(trace.resource_spans.at(0).scope_spans.at(0).spans.at(1).end_time_unix_nano, 0U);

  BOOST_CHECK_NE(trace.resource_spans.at(0).scope_spans.at(0).spans.at(2).end_time_unix_nano, 0U);
  BOOST_CHECK_NE(trace.resource_spans.at(0).scope_spans.at(0).spans.at(3).end_time_unix_nano, 0U);

  // Check the parent span_id for the second closer
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(3).span_id, openevent2SpanID);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(3).parent_span_id, openeventSpanID);

  pdns::trace::dnsdist::Tracer::Closer emptyCloser;
  BOOST_CHECK_EQUAL(emptyCloser.getSpanID(), SpanID{});
}

BOOST_AUTO_TEST_CASE(attributes)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  tracer->setTraceAttribute("foo", AnyValue{"bar"});

  // Test that no attributes are added when the tracer is not activated
  auto trace = tracer->getTracesData();
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).resource.attributes.size(), 1U);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).resource.attributes.at(0).key, "service.name");

  // Check if we have a hostname
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.size(), 1U);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.at(0).key, "hostname");

  // Now activate and add 2 attributes
  tracer->activate();
  tracer->setTraceAttribute("foo", AnyValue{"bar"});
  tracer->setTraceAttribute("baz", AnyValue{256});

  trace = tracer->getTracesData();

  BOOST_ASSERT(trace.resource_spans.at(0).resource.attributes.size() == 1);
  // hostname plus the two we set
  BOOST_ASSERT(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.size() == 3);

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.at(0).key, "foo");
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.at(0).value, AnyValue{"bar"});

  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.at(1).key, "baz");
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).scope.attributes.at(1).value, AnyValue{256});

  // Add a span and some attributes
  auto spanid = tracer->openSpan("anEvent").getSpanID();
  tracer->setSpanAttribute(spanid, "spanattr", AnyValue{"exciting"});

  trace = tracer->getTracesData();

  BOOST_ASSERT(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.size() == 1);
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.front().key, "spanattr");
  BOOST_CHECK_EQUAL(trace.resource_spans.at(0).scope_spans.at(0).spans.at(0).attributes.front().value, AnyValue{"exciting"});
}

BOOST_AUTO_TEST_CASE(getOTProtobuf)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto data = tracer->getOTProtobuf();
  BOOST_TEST(data.size() >= 100U);

  tracer->activate();
  tracer->setTraceAttribute("foo", AnyValue{"bar"});
  data = tracer->getOTProtobuf();
  BOOST_TEST(data.size() >= 110U);
}

BOOST_AUTO_TEST_CASE(setTraceID)
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  tracer->activate();
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
  // Make sure that we can set the root spanid when we have no spans
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

  auto data = tracer->getTracesData();
  for (auto i = 0; i < 4; i++) {
    BOOST_CHECK_EQUAL(data.resource_spans.at(0).scope_spans.at(0).spans.at(i + 1).parent_span_id, newRootSpanID);
  }

  // Now activate, add some new post activation spans, set a new rootspanID and check the post-spans are also set well.
  tracer->activate();
  originalRootSpanID = newRootSpanID;
  for (auto i = 0; i < 4; i++) {
    tracer->openSpan("post activation span " + std::to_string(i), originalRootSpanID);
  }

  // Now set the new root span ID
  while (newRootSpanID == originalRootSpanID) {
    newRootSpanID.makeRandom();
  }
  tracer->setRootSpanID(newRootSpanID);
  BOOST_CHECK_EQUAL(tracer->getRootSpanID(), newRootSpanID);

  data = tracer->getTracesData();
  for (auto i = 0; i < 8; i++) {
    BOOST_CHECK_EQUAL(data.resource_spans.at(0).scope_spans.at(0).spans.at(i + 1).parent_span_id, newRootSpanID);
  }

  // New tracer, so we can easily test if non-root parent span IDs are not updated
  tracer = pdns::trace::dnsdist::Tracer::getTracer();
  // Add a Span, this'll be the root span
  originalRootSpanID = tracer->openSpan("rootspan").getSpanID();
  BOOST_CHECK_EQUAL(originalRootSpanID, tracer->getRootSpanID());

  tracer->openSpan("preact span", pdns::trace::SpanID::getRandomSpanID());
  tracer->activate();
  tracer->openSpan("postact span", pdns::trace::SpanID::getRandomSpanID());
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
