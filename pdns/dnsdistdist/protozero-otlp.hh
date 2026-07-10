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

  void encode(protozero::pbf_writer& writer) const;
  static ExportTraceServiceRequest decode(protozero::pbf_reader& reader);
  bool operator==(const ExportTraceServiceRequest& rhs) const;
};

struct ExportTracePartialSuccess
{
  int64_t rejected_spans{0}; // = 1
  std::string error_message{""}; // = 2

  void encode(protozero::pbf_writer& writer) const;
  static ExportTracePartialSuccess decode(protozero::pbf_reader& reader);
  bool operator==(const ExportTracePartialSuccess& rhs) const;
};

struct ExportTraceServiceResponse
{
  ExportTracePartialSuccess partial_success; // = 1

  void encode(protozero::pbf_writer& writer) const;
  static ExportTraceServiceResponse decode(protozero::pbf_reader& reader);
  bool operator==(const ExportTraceServiceResponse& rhs) const;
};

} // namespace pdns::trace
