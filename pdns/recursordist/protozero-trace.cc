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

namespace pdns::trace
{

void AnyValue::encode(protozero::pbf_writer& writer) const
{
  if (std::holds_alternative<std::string>(*this)) {
    pdns::trace::encode(writer, 1, std::get<std::string>(*this), true);
  }
  else if (std::holds_alternative<bool>(*this)) {
    pdns::trace::encode(writer, 2, std::get<bool>(*this), true);
  }
  else if (std::holds_alternative<int64_t>(*this)) {
    pdns::trace::encode(writer, 3, std::get<int64_t>(*this), true);
  }
  else if (std::holds_alternative<double>(*this)) {
    pdns::trace::encode(writer, 4, std::get<double>(*this), true);
  }
  else if (std::holds_alternative<ArrayValue>(*this)) {
    protozero::pbf_writer sub{writer, 5};
    std::get<ArrayValue>(*this).encode(sub);
  }
  else if (std::holds_alternative<KeyValueList>(*this)) {
    protozero::pbf_writer sub{writer, 6};
    std::get<KeyValueList>(*this).encode(sub);
  }
  else if (std::holds_alternative<std::vector<uint8_t>>(*this)) {
    pdns::trace::encode(writer, 7, std::get<std::vector<uint8_t>>(*this), true);
  }
}

AnyValue AnyValue::decode(protozero::pbf_reader& reader)
{
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      return AnyValue{reader.get_string()};
      break;
    case 2:
      return AnyValue{reader.get_bool()};
      break;
    case 3:
      return AnyValue{reader.get_int64()};
      break;
    case 4:
      return AnyValue{reader.get_double()};
      break;
    case 5: {
      protozero::pbf_reader arrayvalue = reader.get_message();
      return AnyValue{ArrayValue::decode(arrayvalue)};
      break;
    }
    case 6: {
      protozero::pbf_reader kvlist = reader.get_message();
      return AnyValue{KeyValueList::decode(kvlist)};
      break;
    }
    case 7: {
      auto value = reader.get_view();
      std::vector<uint8_t> data{};
      data.reserve(value.size());
      for (size_t i = 0; i < value.size(); ++i) {
        data.push_back(static_cast<uint8_t>(value.data()[i]));
      }
      return AnyValue{std::move(data)};
      break;
    }
    default:
      break;
    }
  }

  return {};
}

void EntityRef::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, schema_url);
  pdns::trace::encode(writer, 2, type);
  for (auto const& element : id_keys) {
    pdns::trace::encode(writer, 3, element);
  }
  for (auto const& element : description_keys) {
    pdns::trace::encode(writer, 4, element);
  }
}

EntityRef EntityRef::decode(protozero::pbf_reader& reader)
{
  EntityRef ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      ret.schema_url = reader.get_string();
      break;
    case 2:
      ret.type = reader.get_string();
      break;
    case 3:
      ret.id_keys.emplace_back(reader.get_string());
      break;
    case 4:
      ret.description_keys.emplace_back(reader.get_string());
      break;
    default:
      break;
    }
  }
  return ret;
}

void KeyValue::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, key);
  {
    protozero::pbf_writer val_sub{writer, 2};
    value.encode(val_sub);
  }
}

void Resource::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, attributes);
  pdns::trace::encode(writer, 2, dropped_attributes_count);
  pdns::trace::encode(writer, 3, entity_refs);
}

Resource Resource::decode(protozero::pbf_reader& reader)
{
  Resource ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1: {
      auto sub = reader.get_message();
      ret.attributes.emplace_back(KeyValue::decode(sub));
      break;
    }
    case 2:
      ret.dropped_attributes_count = reader.get_uint32();
      break;
    case 3: {
      auto sub = reader.get_message();
      ret.entity_refs.emplace_back(EntityRef::decode(sub));
      break;
    }
    default:
      break;
    }
  }
  return ret;
}

void InstrumentationScope::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, name);
  pdns::trace::encode(writer, 2, version);
  pdns::trace::encode(writer, 3, attributes);
  pdns::trace::encode(writer, 4, dropped_attributes_count);
}

InstrumentationScope InstrumentationScope::decode(protozero::pbf_reader& reader)
{
  InstrumentationScope ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      ret.name = reader.get_string();
      break;
    case 2:
      ret.version = reader.get_string();
      break;
    case 3: {
      auto sub = reader.get_message();
      ret.attributes.emplace_back(KeyValue::decode(sub));
      break;
    }
    case 4:
      ret.dropped_attributes_count = reader.get_uint32();
      break;
    default:
      break;
    }
  }
  return ret;
}

void Status::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 2, message);
  pdns::trace::encode(writer, 3, uint32_t(code));
}

Status Status::decode(protozero::pbf_reader& reader)
{
  Status ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 2:
      ret.message = reader.get_string();
      break;
    case 3:
      ret.code = static_cast<StatusCode>(reader.get_uint32());
      break;
    default:
      break;
    }
  }
  return ret;
}

void Span::Event::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encodeFixed(writer, 1, time_unix_nano);
  pdns::trace::encode(writer, 2, name);
  pdns::trace::encode(writer, 3, attributes);
  pdns::trace::encode(writer, 4, dropped_attributes_count);
}

Span::Event Span::Event::decode(protozero::pbf_reader& reader)
{
  Span::Event ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      ret.time_unix_nano = reader.get_fixed64();
      break;
    case 2:
      ret.name = reader.get_string();
      break;
    case 3: {
      auto sub = reader.get_message();
      ret.attributes.emplace_back(KeyValue::decode(sub));
      break;
    }
    case 4:
      ret.dropped_attributes_count = reader.get_uint32();
    default:
      break;
    }
  }
  return ret;
}

void Span::Link::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, trace_id);
  pdns::trace::encode(writer, 2, span_id);
  pdns::trace::encode(writer, 3, trace_state);
  pdns::trace::encode(writer, 4, attributes);
  pdns::trace::encode(writer, 5, dropped_attributes_count);
  pdns::trace::encodeFixed(writer, 6, flags);
}

Span::Link Span::Link::decode(protozero::pbf_reader& reader)
{
  Link ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      ret.trace_id = decodeTraceID(reader);
      break;
    case 2:
      ret.span_id = decodeSpanID(reader);
      break;
    case 3:
      ret.trace_state = reader.get_string();
      break;
    case 4: {
      auto sub = reader.get_message();
      ret.attributes.emplace_back(KeyValue::decode(sub));
      break;
    }
    case 5:
      ret.dropped_attributes_count = reader.get_uint32();
      break;
    case 6:
      ret.flags = reader.get_fixed32();
    default:
      break;
    }
  }
  return ret;
}

void Span::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, trace_id);
  pdns::trace::encode(writer, 2, span_id);
  pdns::trace::encode(writer, 3, trace_state);
  pdns::trace::encode(writer, 4, parent_span_id);
  pdns::trace::encode(writer, 5, name);
  pdns::trace::encode(writer, 6, uint32_t(kind));
  pdns::trace::encodeFixed(writer, 7, start_time_unix_nano);
  pdns::trace::encodeFixed(writer, 8, end_time_unix_nano);
  pdns::trace::encode(writer, 9, attributes);
  pdns::trace::encode(writer, 10, dropped_attributes_count);
  pdns::trace::encode(writer, 11, events);
  pdns::trace::encode(writer, 12, dropped_events_count);
  pdns::trace::encode(writer, 13, links);
  pdns::trace::encode(writer, 14, dropped_links_count);
  if (status.code != Status::StatusCode::STATUS_CODE_UNSET || !status.message.empty()) {
    protozero::pbf_writer sub{writer, 15};
    status.encode(sub);
  }
}

Span Span::decode(protozero::pbf_reader& reader)
{
  Span ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      ret.trace_id = decodeTraceID(reader);
      break;
    case 2:
      ret.span_id = decodeSpanID(reader);
      break;
    case 3:
      ret.trace_state = reader.get_string();
      break;
    case 4:
      ret.parent_span_id = decodeSpanID(reader);
      break;
    case 5:
      ret.name = reader.get_string();
      break;
    case 6:
      ret.kind = static_cast<Span::SpanKind>(reader.get_uint32());
      break;
    case 7:
      ret.start_time_unix_nano = reader.get_fixed64();
      break;
    case 8:
      ret.end_time_unix_nano = reader.get_fixed64();
      break;
    case 9: {
      auto sub = reader.get_message();
      ret.attributes.emplace_back(KeyValue::decode(sub));
      break;
    }
    case 10:
      ret.dropped_attributes_count = reader.get_uint32();
      break;
    case 11: {
      auto sub = reader.get_message();
      ret.events.emplace_back(Span::Event::decode(sub));
      break;
    }
    case 12:
      ret.dropped_events_count = reader.get_uint32();
      break;
    case 13: {
      auto sub = reader.get_message();
      ret.links.emplace_back(Span::Link::decode(sub));
      break;
    }
    case 14:
      ret.dropped_links_count = reader.get_uint32();
      break;
    case 15: {
      auto sub = reader.get_message();
      ret.status = Status::decode(sub);
      break;
    }
    default:
      break;
    }
  }
  return ret;
}

void ScopeSpans::encode(protozero::pbf_writer& writer) const
{
  {
    protozero::pbf_writer sub{writer, 1};
    scope.encode(sub);
  }
  pdns::trace::encode(writer, 2, spans);
  pdns::trace::encode(writer, 3, schema_url);
}

ScopeSpans ScopeSpans::decode(protozero::pbf_reader& reader)
{
  ScopeSpans ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1: {
      auto sub = reader.get_message();
      ret.scope = InstrumentationScope::decode(sub);
      break;
    }
    case 2: {
      auto sub = reader.get_message();
      ret.spans.emplace_back(Span::decode(sub));
      break;
    }
    case 3:
      ret.schema_url = reader.get_string();
    default:
      break;
    }
  }
  return ret;
}

void ResourceSpans::encode(protozero::pbf_writer& writer) const
{
  {
    protozero::pbf_writer sub{writer, 1};
    resource.encode(sub);
  }
  pdns::trace::encode(writer, 2, scope_spans);
  pdns::trace::encode(writer, 3, schema_url);
}

ResourceSpans ResourceSpans::decode(protozero::pbf_reader& reader)
{
  ResourceSpans ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1: {
      protozero::pbf_reader sub = reader.get_message();
      ret.resource = Resource::decode(sub);
      break;
    }
    case 2: {
      protozero::pbf_reader sub = reader.get_message();
      ret.scope_spans.emplace_back(ScopeSpans::decode(sub));
      break;
    }
    case 3:
      ret.schema_url = reader.get_string();
    default:
      break;
    }
  }
  return ret;
}

void TracesData::encode(protozero::pbf_writer& writer) const
{
  pdns::trace::encode(writer, 1, resource_spans);
}

TracesData TracesData::decode(protozero::pbf_reader& reader)
{
  TracesData ret;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1: {
      auto sub = reader.get_message();
      ret.resource_spans.emplace_back(ResourceSpans::decode(sub));
      break;
    }
    default:
      break;
    }
  }
  return ret;
}

KeyValue KeyValue::decode(protozero::pbf_reader& reader)
{
  KeyValue value;
  while (reader.next()) {
    switch (reader.tag()) {
    case 1:
      value.key = reader.get_string();
      break;
    case 2: {
      protozero::pbf_reader sub = reader.get_message();
      value.value = AnyValue::decode(sub);
      break;
    }
    default:
      break;
    }
  }
  return value;
}

}
