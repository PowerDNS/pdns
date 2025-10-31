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
#include "misc.hh"

#include <vector>

#ifndef DISABLE_PROTOBUF
#include "protozero-trace.hh"
#endif

namespace pdns::trace::dnsdist
{

#ifndef DISABLE_PROTOBUF
static const KeyValue hostnameAttr{.key = "hostname", .value = {getHostname().value_or("")}};
#endif

TracesData Tracer::getTracesData()
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  auto otTrace = pdns::trace::TracesData{
    .resource_spans = {
      {.resource = {
         .attributes = {
           {"service.name", {"dnsdist"}},
         }},
       .scope_spans = {{.scope = {
                          .name = "dnsdist/queryFromFrontend",
                          .version = PACKAGE_VERSION,
                          .attributes = {d_attributes.begin(), d_attributes.end()},
                        },
                        .spans = {}}}}}};

  otTrace.resource_spans.at(0).scope_spans.at(0).scope.attributes.push_back(hostnameAttr);

  auto lockedSpans = d_spans.read_only_lock();
  for (auto const& lockedSpan : *lockedSpans) {
    otTrace.resource_spans.at(0).scope_spans.at(0).spans.push_back(
      {
        .trace_id = getTraceID(),
        .span_id = lockedSpan.span_id,
        .parent_span_id = lockedSpan.parent_span_id,
        .name = lockedSpan.name,
        .kind = pdns::trace::Span::SpanKind::SPAN_KIND_SERVER,
        .start_time_unix_nano = lockedSpan.start_time_unix_nano,
        .end_time_unix_nano = lockedSpan.end_time_unix_nano,
        .attributes = lockedSpan.attributes,
      });
  }

  return otTrace;
#endif
}

std::string Tracer::getOTProtobuf()
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
  auto spanID = pdns::trace::SpanID::getRandomSpanID();
  d_spans.lock()->push_back({
    .name = name,
    .span_id = spanID,
    .parent_span_id = parentSpanID,
    .start_time_unix_nano = pdns::trace::timestamp(),
    .end_time_unix_nano = 0,
    .attributes = {},
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
  d_attributes.push_back({key, value});
  return true;
#endif
}

void Tracer::closeSpan([[maybe_unused]] const SpanID& spanID)
{
#ifndef DISABLE_PROTOBUF
  auto lockedSpans = d_spans.lock();
  auto spanIt = std::find_if(
    lockedSpans->rbegin(),
    lockedSpans->rend(),
    [spanID](const miniSpan& span) { return span.span_id == spanID; });
  if (spanIt != lockedSpans->rend() && spanIt->end_time_unix_nano == 0) {
    spanIt->end_time_unix_nano = pdns::trace::timestamp();
    return;
  }
#endif
}

void Tracer::setRootSpanAttribute([[maybe_unused]] const std::string& key, [[maybe_unused]] const AnyValue& value)
{
#ifndef DISABLE_PROTOBUF
  setSpanAttribute(getRootSpanID(), key, value);
#endif
}

// TODO: Figure out what to do with duplicate keys
void Tracer::setSpanAttribute([[maybe_unused]] const SpanID& spanid, [[maybe_unused]] const std::string& key, [[maybe_unused]] const AnyValue& value)
{
#ifndef DISABLE_PROTOBUF
  auto lockedSpans = d_spans.lock();
  if (auto iter = std::find_if(lockedSpans->rbegin(),
                               lockedSpans->rend(),
                               [spanid](const auto& span) { return span.span_id == spanid; });
      iter != lockedSpans->rend()) {
    iter->attributes.push_back({key, value});
  }
#endif
}

SpanID Tracer::getRootSpanID()
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  if (auto spans = d_spans.read_only_lock(); !spans->empty()) {
    auto iter = std::find_if(spans->cbegin(), spans->cend(), [](const auto& span) { return span.parent_span_id == pdns::trace::s_emptySpanID; });
    if (iter != spans->cend()) {
      return iter->span_id;
    }
  }
  return SpanID{};
#endif
}

SpanID Tracer::getLastSpanID()
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  if (auto lockedSpans = d_spans.read_only_lock(); !lockedSpans->empty()) {
    return lockedSpans->back().span_id;
  }
  return pdns::trace::s_emptySpanID;
#endif
}

SpanID Tracer::getLastSpanIDForName([[maybe_unused]] const std::string& name)
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  if (auto lockedSpans = d_spans.read_only_lock(); !lockedSpans->empty()) {
    if (auto iter = std::find_if(lockedSpans->rbegin(),
                                 lockedSpans->rend(),
                                 [name](const miniSpan& span) { return span.name == name; });
        iter != lockedSpans->rend()) {
      return iter->span_id;
    }
  }
  return pdns::trace::s_emptySpanID;
#endif
}

TraceID Tracer::getTraceID() const
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  if (d_traceid == pdns::trace::s_emptyTraceID) {
    d_traceid.makeRandom();
  }
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
