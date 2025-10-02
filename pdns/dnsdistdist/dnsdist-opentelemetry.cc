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

#include "dnsdist-opentelemetry.hh"

#include <vector>

#ifndef DISABLE_PROTOBUF
#include "protozero-trace.hh"
#endif

namespace pdns::trace::dnsdist
{

TracesData Tracer::getTracesData() const
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  auto otTrace = pdns::trace::TracesData{
    .resource_spans = {
      pdns::trace::ResourceSpans{
        .resource = {
          .attributes = std::vector<pdns::trace::KeyValue>{
            pdns::trace::KeyValue{
              "service.name", pdns::trace::AnyValue{"dnsdist"}},
          }},
        .scope_spans = std::vector<pdns::trace::ScopeSpans>{{}}}}};

  otTrace.resource_spans.at(0).resource.attributes.insert(
    otTrace.resource_spans.at(0).resource.attributes.end(),
    d_attributes.begin(),
    d_attributes.end());

  for (auto const& preActivationTrace : d_preActivationSpans) {
    otTrace.resource_spans.at(0).scope_spans.at(0).spans.push_back(
      {
        .trace_id = d_traceid,
        .span_id = preActivationTrace.span_id,
        .parent_span_id = preActivationTrace.parent_span_id,
        .name = preActivationTrace.name,
        .start_time_unix_nano = preActivationTrace.start_time_unix_nano,
        .end_time_unix_nano = preActivationTrace.end_time_unix_nano,
      });
  }

  otTrace.resource_spans.at(0).scope_spans.at(0).spans.insert(
    otTrace.resource_spans.at(0).scope_spans.at(0).spans.end(),
    d_postActivationSpans.begin(),
    d_postActivationSpans.end());
  return otTrace;
#endif
}

std::string Tracer::getOTProtobuf() const
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  // TODO: Should we close all spans?
  return getTracesData().encode();
#endif
}

SpanID Tracer::addSpan([[maybe_unused]] const std::string& name)
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  return addSpan(name, SpanID{});
#endif
}

SpanID Tracer::addSpan([[maybe_unused]] const std::string& name, [[maybe_unused]] const SpanID& parentSpanID)
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  auto spanID = pdns::trace::randomSpanID();
  if (d_activated) {
    d_postActivationSpans.push_back({
      .trace_id = d_traceid,
      .span_id = spanID,
      .parent_span_id = parentSpanID,
      .name = name,
      .start_time_unix_nano = pdns::trace::timestamp(),
    });
    return spanID;
  }

  // We're not activated, so we are in pre-activation.
  d_preActivationSpans.push_back({
    .name = name,
    .span_id = spanID,
    .parent_span_id = parentSpanID,
    .start_time_unix_nano = pdns::trace::timestamp(),
    .end_time_unix_nano = 0,
  });

  d_lastSpanID = spanID;

  return spanID;
#endif
}

// TODO: Figure out what to do with duplicate keys
bool Tracer::setTraceAttribute([[maybe_unused]] const std::string& key, [[maybe_unused]] const AnyValue& value)
{
#ifdef DISABLE_PROTOBUF
  // always succesfull
  return true;
#else
  if (!d_activated) {
    return false;
  }
  d_attributes.push_back({key, value});
  return true;
#endif
}

void Tracer::closeSpan([[maybe_unused]] const SpanID& spanID)
{
#ifndef DISABLE_PROTOBUF
  if (d_activated) {
    auto spanIt = std::find_if(
      d_postActivationSpans.rbegin(),
      d_postActivationSpans.rend(),
      [spanID](const pdns::trace::Span& span) { return span.span_id == spanID; });
    if (spanIt != d_postActivationSpans.rend()) {
      if (spanIt->end_time_unix_nano == 0) {
        spanIt->end_time_unix_nano = pdns::trace::timestamp();
      }
      return;
    }
  }

  auto spanIt = std::find_if(
    d_preActivationSpans.rbegin(),
    d_preActivationSpans.rend(),
    [spanID](const preActivationSpanInfo& span) { return span.span_id == spanID; });
  if (spanIt != d_preActivationSpans.rend() && spanIt->end_time_unix_nano == 0) {
    spanIt->end_time_unix_nano = pdns::trace::timestamp();
    return;
  }
#endif
}

// TODO: Figure out what to do with duplicate keys
void Tracer::setSpanAttribute([[maybe_unused]] const SpanID& spanid, [[maybe_unused]] const std::string& key, [[maybe_unused]] const AnyValue& value)
{
#ifndef DISABLE_PROTOBUF
  if (d_activated) {
    if (auto iter = std::find_if(d_postActivationSpans.rbegin(),
                                 d_postActivationSpans.rend(),
                                 [spanid](const pdns::trace::Span& span) { return span.span_id == spanid; });
        iter != d_postActivationSpans.rend()) {
      iter->attributes.push_back({key, value});
      return;
    }
  }
  // XXX: It is not possible to add attributes to d_preActivationTraces. Perhaps these should be converted on calling activate
#endif
}

SpanID Tracer::getLastSpanID() const
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  if (d_activated && d_postActivationSpans.size() != 0) {
    return d_postActivationSpans.back().span_id;
  }
  if (d_preActivationSpans.size() != 0) {
    return d_preActivationSpans.back().span_id;
  }
  return SpanID{};
#endif
}

SpanID Tracer::getLastSpanIDForName([[maybe_unused]] const std::string& name) const
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  if (d_activated && d_postActivationSpans.size() != 0) {
    if (auto iter = std::find_if(d_postActivationSpans.rbegin(),
                                 d_postActivationSpans.rend(),
                                 [name](const pdns::trace::Span& span) { return span.name == name; });
        iter != d_postActivationSpans.rend()) {
      return iter->span_id;
    }
  }

  if (d_preActivationSpans.size() != 0) {
    if (auto iter = std::find_if(d_preActivationSpans.rbegin(),
                                 d_preActivationSpans.rend(),
                                 [name](const preActivationSpanInfo& span) { return span.name == name; });
        iter != d_preActivationSpans.rend()) {
      return iter->span_id;
    }
  }
  return SpanID{};
#endif
}

TraceID Tracer::getTraceID() const
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  return d_traceid;
#endif
}

Tracer::Closer Tracer::getCloser([[maybe_unused]] const SpanID& spanid)
{
#ifdef DISABLE_PROTOBUF
  return Tracer::Closer();
#else
  return {shared_from_this(), spanid};
#endif
}

Tracer::Closer Tracer::openSpan([[maybe_unused]] const std::string& name)
{
#ifdef DISABLE_PROTOBUF
  return Tracer::Closer();
#else
  auto spanid = addSpan(name);
  return getCloser(spanid);
#endif
}

Tracer::Closer Tracer::openSpan([[maybe_unused]] const std::string& name, [[maybe_unused]] const SpanID& parentSpanID)
{
#ifdef DISABLE_PROTOBUF
  return Tracer::Closer();
#else
  auto spanid = addSpan(name, parentSpanID);
  return getCloser(spanid);
#endif
}

SpanID Tracer::Closer::getSpanID() const
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  return d_spanID;
#endif
}

} // namespace pdns::trace::dnsdist
