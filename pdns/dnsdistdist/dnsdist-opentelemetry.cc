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

  {
    auto lockedPre = d_preActivationSpans.read_only_lock();

    for (auto const& preActivationTrace : *lockedPre) {
      otTrace.resource_spans.at(0).scope_spans.at(0).spans.push_back(
        {
          .trace_id = d_traceid,
          .span_id = preActivationTrace.span_id,
          .parent_span_id = preActivationTrace.parent_span_id,
          .name = preActivationTrace.name,
          .kind = pdns::trace::Span::SpanKind::SPAN_KIND_SERVER,
          .start_time_unix_nano = preActivationTrace.start_time_unix_nano,
          .end_time_unix_nano = preActivationTrace.end_time_unix_nano,
        });

      if (preActivationTrace.parent_span_id == pdns::trace::s_emptySpanID) {
        // This is the root span
        otTrace.resource_spans.at(0).scope_spans.at(0).spans.back().attributes.insert(
          otTrace.resource_spans.at(0).scope_spans.at(0).spans.back().attributes.cend(),
          d_rootSpanAttributes.begin(),
          d_rootSpanAttributes.end());
      }
    }
  }

  {
    auto lockedPost = d_postActivationSpans.read_only_lock();
    otTrace.resource_spans.at(0).scope_spans.at(0).spans.insert(
      otTrace.resource_spans.at(0).scope_spans.at(0).spans.end(),
      lockedPost->begin(),
      lockedPost->end());
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
  if (d_activated) {
    d_postActivationSpans.lock()->push_back({
      .trace_id = d_traceid,
      .span_id = spanID,
      .parent_span_id = parentSpanID,
      .name = name,
      .kind = pdns::trace::Span::SpanKind::SPAN_KIND_SERVER,
      .start_time_unix_nano = pdns::trace::timestamp(),
    });
    return spanID;
  }

  // We're not activated, so we are in pre-activation.
  d_preActivationSpans.lock()->push_back({
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
    auto lockedPost = d_postActivationSpans.lock();
    auto spanIt = std::find_if(
      lockedPost->rbegin(),
      lockedPost->rend(),
      [spanID](const pdns::trace::Span& span) { return span.span_id == spanID; });
    if (spanIt != lockedPost->rend()) {
      if (spanIt->end_time_unix_nano == 0) {
        spanIt->end_time_unix_nano = pdns::trace::timestamp();
      }
      return;
    }
  }

  auto lockedPre = d_preActivationSpans.lock();
  auto spanIt = std::find_if(
    lockedPre->rbegin(),
    lockedPre->rend(),
    [spanID](const preActivationSpanInfo& span) { return span.span_id == spanID; });
  if (spanIt != lockedPre->rend() && spanIt->end_time_unix_nano == 0) {
    spanIt->end_time_unix_nano = pdns::trace::timestamp();
    return;
  }
#endif
}

void Tracer::setRootSpanAttribute([[maybe_unused]] const std::string& key, [[maybe_unused]] const AnyValue& value)
{
#ifndef DISABLE_PROTOBUF
  d_rootSpanAttributes.push_back({
    .key = key,
    .value = value,
  });
#endif
}

// TODO: Figure out what to do with duplicate keys
void Tracer::setSpanAttribute([[maybe_unused]] const SpanID& spanid, [[maybe_unused]] const std::string& key, [[maybe_unused]] const AnyValue& value)
{
#ifndef DISABLE_PROTOBUF
  if (d_activated) {
    auto lockedPost = d_postActivationSpans.lock();
    if (auto iter = std::find_if(lockedPost->rbegin(),
                                 lockedPost->rend(),
                                 [spanid](const pdns::trace::Span& span) { return span.span_id == spanid; });
        iter != lockedPost->rend()) {
      iter->attributes.push_back({key, value});
      return;
    }
  }
  // XXX: It is not possible to add attributes to d_preActivationTraces. Perhaps these should be converted on calling activate
#endif
}

SpanID Tracer::getRootSpanID()
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  if (auto spans = d_preActivationSpans.read_only_lock(); spans->size() != 0) {
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
  if (d_activated && d_postActivationSpans.read_only_lock()->size() != 0) {
    return d_postActivationSpans.read_only_lock()->back().span_id;
  }
  if (d_preActivationSpans.read_only_lock()->size() != 0) {
    return d_preActivationSpans.read_only_lock()->back().span_id;
  }
  return SpanID{};
#endif
}

SpanID Tracer::getLastSpanIDForName([[maybe_unused]] const std::string& name)
{
#ifdef DISABLE_PROTOBUF
  return 0;
#else
  if (d_activated && d_postActivationSpans.read_only_lock()->size() != 0) {
    auto lockedPost = d_postActivationSpans.read_only_lock();
    if (auto iter = std::find_if(lockedPost->rbegin(),
                                 lockedPost->rend(),
                                 [name](const pdns::trace::Span& span) { return span.name == name; });
        iter != lockedPost->rend()) {
      return iter->span_id;
    }
  }

  if (d_preActivationSpans.read_only_lock()->size() != 0) {
    auto lockedPre = d_preActivationSpans.read_only_lock();
    if (auto iter = std::find_if(lockedPre->rbegin(),
                                 lockedPre->rend(),
                                 [name](const preActivationSpanInfo& span) { return span.name == name; });
        iter != lockedPre->rend()) {
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
