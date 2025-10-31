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
#define CATCH_CONFIG_NO_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>
#include <string>

#include "dnsdist-opentelemetry.hh"
#include "protozero-trace.hh"

TEST_CASE("OpenTelemetry-base")
{
  BENCHMARK("pdns::trace::dnsdist::Tracer::getTracer")
  {
    return pdns::trace::dnsdist::Tracer::getTracer();
  };

  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto spanID = pdns::trace::SpanID::getRandomSpanID();

  BENCHMARK("pdns::trace::dnsdist::Tracer::getCloser")
  {
    return tracer->getCloser(spanID);
  };

  BENCHMARK("pdns::trace::dnsdist::Tracer::openSpan")
  {
    return tracer->openSpan("foo");
  };
}

TEST_CASE("OpenTelemetry-addSpanThroughCloser")
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  auto spanID = pdns::trace::SpanID::getRandomSpanID();

  BENCHMARK("openspan")
  {
    return tracer->openSpan("activated", spanID);
  };
}

TEST_CASE("OpenTelemetry-spaninfo")
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  // Ensures span attributes are actually stored
  auto rootSpanID = tracer->openSpan("mySpan").getSpanID();
  auto stringvalue = pdns::trace::AnyValue{"hello"};
  auto intvalue = pdns::trace::AnyValue{43854};

  BENCHMARK("dnsdist::trace::Tracer::setSpanAttribute-string one span")
  {
    tracer->setSpanAttribute(rootSpanID, "key", stringvalue);
  };

  BENCHMARK("dnsdist::trace::Tracer::setSpanAttribute-int one span")
  {
    tracer->setSpanAttribute(rootSpanID, "key", intvalue);
  };

  auto spanID = rootSpanID;
  for (auto i = 0; i < 40; i++) {
    spanID = tracer->openSpan("fooSpan" + std::to_string(i), spanID).getSpanID();
  }

  BENCHMARK("dnsdist::trace::Tracer::setSpanAttribute-string 42 spans, first")
  {
    tracer->setSpanAttribute(rootSpanID, "key", stringvalue);
  };

  BENCHMARK("dnsdist::trace::Tracer::setSpanAttribute-int 42 spans, first")
  {
    tracer->setSpanAttribute(rootSpanID, "key", intvalue);
  };

  BENCHMARK("dnsdist::trace::Tracer::setSpanAttribute-string 42 spans, last")
  {
    tracer->setSpanAttribute(spanID, "key", stringvalue);
  };

  BENCHMARK("dnsdist::trace::Tracer::setSpanAttribute-int 42 spans, last")
  {
    tracer->setSpanAttribute(spanID, "key", intvalue);
  };
}

TEST_CASE("OpenTelemetry-getLastSpanID")
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();
  pdns::trace::dnsdist::Tracer::Closer closer;
  for (auto i = 0; i < 40; i++) {
    closer = tracer->openSpan("foo" + std::to_string(i));
  }

  BENCHMARK("getLastSpanID")
  {
    return tracer->getLastSpanID();
  };

  BENCHMARK("getRootSpanID")
  {
    return tracer->getRootSpanID();
  };

  BENCHMARK("getLastSpanIDForName-first")
  {
    return tracer->getLastSpanIDForName("foo0");
  };

  BENCHMARK("getLastSpanIDForName-middle")
  {
    return tracer->getLastSpanIDForName("foo20");
  };

  BENCHMARK("getLastSpanIDForName-does-not-exist")
  {
    return tracer->getLastSpanIDForName("doesnotexist");
  };
}

TEST_CASE("OpenTelemetry-getTracesData")
{
  auto tracer = pdns::trace::dnsdist::Tracer::getTracer();

  BENCHMARK("empty Tracer")
  {
    return tracer->getTracesData();
  };

  for (auto i = 0; i < 40; i++) {
    tracer->openSpan("foo" + std::to_string(i));
  }

  BENCHMARK("Tracer with 41 spans")
  {
    return tracer->getTracesData();
  };
}
#endif
