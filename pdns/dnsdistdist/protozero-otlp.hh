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

#pragma once

#include <protozero/pbf_reader.hpp>
#include <protozero/pbf_writer.hpp>
#include <vector>

#include "protozero-trace.hh"

namespace pdns::trace
{
// https://github.com/open-telemetry/opentelemetry-proto/blob/v1.10.0/opentelemetry/proto/collector/trace/v1/trace_service.proto

struct ExportTraceServiceRequest
{
  // This message is the same as TracesData
  std::vector<ResourceSpans> resource_spans; // = 1

  void encode(protozero::pbf_writer& writer) const
  {
    pdns::trace::encode(writer, 1, resource_spans);
  }

  static ExportTraceServiceRequest decode(protozero::pbf_reader& reader);
};

struct ExportTracePartialSuccess
{
  int64_t rejected_spans; // = 1
  std::string error_message; // = 2

  void encode(protozero::pbf_writer& writer) const;
  static ExportTracePartialSuccess decode(protozero::pbf_reader& reader)
  {
    ExportTracePartialSuccess ret{
      .rejected_spans = 0,
      .error_message = "",
    };
    while (reader.next()) {
      switch (reader.tag()) {
      case 1:
        ret.rejected_spans = reader.get_int64();
      case 2:
        ret.error_message = reader.get_string();
      }
    }
    return ret;
  };
};

struct ExportTraceServiceResponse
{
  ExportTracePartialSuccess partial_success; // = 1

  void encode(protozero::pbf_writer& writer) const;
  static ExportTraceServiceResponse decode(protozero::pbf_reader& reader)
  {
    ExportTraceServiceResponse ret;
    while (reader.next()) {
      switch (reader.tag()) {
      case 1:
        auto sub = reader.get_message();
        ret.partial_success = ExportTracePartialSuccess::decode(sub);
      }
    }
    return ret;
  }
};

} // namespace pdns::trace
