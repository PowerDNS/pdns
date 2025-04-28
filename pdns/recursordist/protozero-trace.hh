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

#include <array>
#include <variant>
#include <vector>

#include <protozero/pbf_reader.hpp>
#include <protozero/pbf_writer.hpp>

// See https://github.com/open-telemetry/opentelemetry-proto/tree/main/opentelemetry/proto

namespace pdns::trace
{

struct AnyValue;
struct ArrayValue;
struct KeyValue;
struct KeyValueList;

inline void encode(protozero::pbf_writer& writer, uint8_t field, bool value, bool always = false)
{
  if (always || value) {
    writer.add_bool(field, value);
  }
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, uint32_t value, bool always = false)
{
  if (always || value != 0) {
    writer.add_uint32(field, value);
  }
}

inline void encodeFixed(protozero::pbf_writer& writer, uint8_t field, uint32_t value)
{
  writer.add_fixed32(field, value);
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, int64_t value, bool always = false)
{
  if (always || value != 0) {
    writer.add_int64(field, value);
  }
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, uint64_t value, bool always = false)
{
  if (always || value != 0) {
    writer.add_uint64(field, value);
  }
}

inline void encodeFixed(protozero::pbf_writer& writer, uint8_t field, uint64_t value)
{
  writer.add_fixed64(field, value);
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, double value, bool always = false)
{
  if (always || value != 0.0) {
    writer.add_double(field, value);
  }
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, const std::string& value, bool always = false)
{
  if (always || !value.empty()) {
    writer.add_string(field, value);
  }
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, const std::vector<uint8_t>& value, bool always = false)
{
  if (always || !value.empty()) {
    writer.add_bytes(field, reinterpret_cast<const char*>(value.data()), value.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) it's the API
  }
}

template <typename T>
void encode(protozero::pbf_writer& writer, const std::vector<T>& vec)
{
  for (auto const& element : vec) {
    element.encode(writer);
  }
}

template <typename T>
void encode(protozero::pbf_writer& writer, uint8_t field, const std::vector<T>& vec)
{
  for (auto const& element : vec) {
    protozero::pbf_writer sub{writer, field};
    element.encode(sub);
  }
}

template <typename T, typename E>
T decode(protozero::pbf_reader& reader)
{
  std::vector<E> vec;
  while (reader.next()) {
    if (reader.tag() == 1) {
      protozero::pbf_reader sub = reader.get_message();
      vec.emplace_back(E::decode(sub));
    }
  }
  return {vec};
}

struct ArrayValue
{
  std::vector<AnyValue> values; // = 1

  void encode(protozero::pbf_writer& writer) const
  {
    pdns::trace::encode(writer, 1, values);
  }

  static ArrayValue decode(protozero::pbf_reader& reader);

  bool operator==(const ArrayValue& rhs) const
  {
    return values == rhs.values;
  }
};

struct KeyValueList
{
  std::vector<KeyValue> values; // = 1

  void encode(protozero::pbf_writer& writer) const
  {
    pdns::trace::encode(writer, 1, values);
  }

  static KeyValueList decode(protozero::pbf_reader& reader);

  bool operator==(const KeyValueList& rhs) const
  {
    return values == rhs.values;
  }
};

struct AnyValue : public std::variant<char, std::string, bool, int64_t, double, ArrayValue, KeyValueList, std::vector<uint8_t>>
{
  void encode(protozero::pbf_writer& writer) const;
  static AnyValue decode(protozero::pbf_reader& reader);
};

struct EntityRef
{
  std::string schema_url; // == 1
  std::string type; // == 2
  std::vector<std::string> id_keys; // == 3
  std::vector<std::string> description_keys; // == 4

  void encode(protozero::pbf_writer& writer) const;
  static EntityRef decode(protozero::pbf_reader& reader);
};

struct KeyValue
{
  std::string key; // = 1
  AnyValue value; // = 2
  void encode(protozero::pbf_writer& writer) const;
  static KeyValue decode(protozero::pbf_reader& reader);

  bool operator==(const KeyValue& rhs) const
  {
    return key == rhs.key && value == rhs.value;
  }
};

struct Resource
{
  std::vector<KeyValue> attributes; // = 1
  uint32_t dropped_attributes_count{0}; // = 2;
  std::vector<EntityRef> entity_refs; // = 3

  void encode(protozero::pbf_writer& writer) const;
  static Resource decode(protozero::pbf_reader& reader);
};

struct InstrumentationScope
{
  std::string name; // = 1
  std::string version; // = 2
  std::vector<KeyValue> attributes; // = 3
  uint32_t dropped_attributes_count{0}; // = 4

  void encode(protozero::pbf_writer& writer) const;
  static InstrumentationScope decode(protozero::pbf_reader& reader);
};

using TraceID = std::array<uint8_t, 16>;
using SpanID = std::array<uint8_t, 8>;

inline void encode(protozero::pbf_writer& writer, uint8_t field, const TraceID& value)
{
  writer.add_bytes(field, reinterpret_cast<const char*>(value.data()), value.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) it's the API
}

inline TraceID decodeTraceID(protozero::pbf_reader& reader)
{
  TraceID bytes;
  auto [data, len] = reader.get_data();
  memcpy(bytes.data(), data, std::min(bytes.size(), static_cast<size_t>(len)));
  return bytes;
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, const SpanID& value)
{
  writer.add_bytes(field, reinterpret_cast<const char*>(value.data()), value.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) it's the API
}

inline SpanID decodeSpanID(protozero::pbf_reader& reader)
{
  SpanID bytes;
  auto [data, len] = reader.get_data();
  memcpy(bytes.data(), data, std::min(bytes.size(), static_cast<size_t>(len)));
  return bytes;
}

struct Status
{
  std::string message; // = 2;

  // For the semantics of status codes see
  // https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/api.md#set-status
  enum class StatusCode : uint8_t
  {
    STATUS_CODE_UNSET = 0,
    STATUS_CODE_OK = 1,
    STATUS_CODE_ERROR = 2,
  };

  // The status code.
  StatusCode code{StatusCode::STATUS_CODE_UNSET}; //  = 3;

  void encode(protozero::pbf_writer& writer) const;
  static Status decode(protozero::pbf_reader& reader);
};

struct Span
{
  TraceID trace_id; // = 1
  SpanID span_id; // = 2
  std::string trace_state; // = 3
  SpanID parent_span_id; // = 4
  std::string name; // = 5
  enum class SpanKind : uint8_t
  {
    SPAN_KINUNSPECIFIED = 0,
    SPAN_KININTERNAL = 1,
    SPAN_KINSERVER = 2,
    SPAN_KINCLIENT = 3,
    SPAN_KINPRODUCER = 4,
    SPAN_KINCONSUMER = 5,
  };
  SpanKind kind{Span::SpanKind::SPAN_KINUNSPECIFIED}; // = 6
  uint64_t start_time_unix_nano{0}; // = 7
  uint64_t end_time_unix_nano{0}; // = 8
  std::vector<KeyValue> attributes; // = 9
  uint32_t dropped_attribute_count{0}; // = 10
  struct Event
  {
    uint64_t time_unix_nano; // = 1
    std::string name; // = 2
    std::vector<KeyValue> attributes; // = 3
    uint32_t dropped_attribute_count{0}; // = 4

    void encode(protozero::pbf_writer& writer) const;
    static Event decode(protozero::pbf_reader& reader);
  };
  std::vector<Event> events; // = 11
  uint32_t dropped_events_count; // = 12
  struct Link
  {
    TraceID trace_id; // = 1
    SpanID span_id; // = 2
    std::string trace_state; // = 3
    std::vector<KeyValue> attributes; // = 4
    uint32_t dropped_attribute_count{0}; // = 5
    uint32_t flags{0}; // = 6

    void encode(protozero::pbf_writer& writer) const;
    static Link decode(protozero::pbf_reader& reader);
  };
  std::vector<Link> links; // = 13
  uint32_t dropped_links_count{0}; // = 14
  Status status; // = 15

  void encode(protozero::pbf_writer& writer) const;
  static Span decode(protozero::pbf_reader& reader);
};

struct ScopeSpans
{
  InstrumentationScope scope; // = 1
  std::vector<Span> spans; // = 2
  std::string schema_url; // = 3

  void encode(protozero::pbf_writer& writer) const;
  static ScopeSpans decode(protozero::pbf_reader& reader);
};

struct ResourceSpans
{
  Resource resource; // = 1
  std::vector<ScopeSpans> scope_spans; // = 2
  std::string schema_url; // = 3

  void encode(protozero::pbf_writer& writer) const;
  static ResourceSpans decode(protozero::pbf_reader& reader);
};

struct TracesData
{
  std::vector<ResourceSpans> resource_spans; // = 1

  void encode(protozero::pbf_writer& writer) const;
  static TracesData decode(protozero::pbf_reader& reader);
};

inline ArrayValue ArrayValue::decode(protozero::pbf_reader& reader)
{
  return pdns::trace::decode<ArrayValue, AnyValue>(reader);
}

inline KeyValueList KeyValueList::decode(protozero::pbf_reader& reader)
{
  return pdns::trace::decode<KeyValueList, KeyValue>(reader);
}

}
