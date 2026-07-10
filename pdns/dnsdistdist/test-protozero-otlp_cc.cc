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

#include "misc.hh"
#include "protozero-trace.hh"
#include <boost/test/tools/old/interface.hpp>
#include <boost/test/unit_test.hpp>
#include <vector>

#ifndef DISABLE_PROTOBUF

#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include "protozero-otlp.hh"
#define BOOST_TEST_NO_MAIN

BOOST_AUTO_TEST_SUITE(protozeroOtlp)
BOOST_AUTO_TEST_CASE(ExportTraceServiceRequest)
{
  std::string buf;
  protozero::pbf_writer writer{buf};

  pdns::trace::ExportTraceServiceRequest etsr{
    .resource_spans = {
      {.resource = {
         .attributes = {{pdns::trace::KeyValue{.key = "foo", .value = {"bar"}}}}},
       .scope_spans = {{.scope = {.name = "test"}}}}}};

  etsr.encode(writer);
  BOOST_CHECK_EQUAL(buf, "\x0a\x1a\x0a\x0e\x0a\x0c\x0a\x03\x66\x6f\x6f\x12\x05\x0a\x03\x62\x61\x72\x12\x08\x0a\x06\x0a\x04\x74\x65\x73\x74");

  protozero::pbf_reader reader{buf};
  pdns::trace::ExportTraceServiceRequest outEtsr = pdns::trace::ExportTraceServiceRequest::decode(reader);
  BOOST_CHECK(outEtsr == etsr);
}

BOOST_AUTO_TEST_CASE(ExportTraceServiceResponse)
{
  std::string buf;
  protozero::pbf_writer writer{buf};

  pdns::trace::ExportTraceServiceResponse etsr;
  etsr.partial_success = {
    2,
    "I'm an error message!",
  };
  etsr.encode(writer);

  BOOST_CHECK_EQUAL(buf, "\x0a\x19\x08\x02\x12\x15\x49\x27\x6d\x20\x61\x6e\x20\x65\x72\x72\x6f\x72\x20\x6d\x65\x73\x73\x61\x67\x65\x21");

  protozero::pbf_reader reader{buf};
  pdns::trace::ExportTraceServiceResponse outEtsr = pdns::trace::ExportTraceServiceResponse::decode(reader);
  BOOST_CHECK(outEtsr == etsr);
}
BOOST_AUTO_TEST_SUITE_END()
#endif // DISABLE_PROTOBUF
