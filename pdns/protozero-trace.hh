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

#include "dns_random.hh"
#include "ednsoptions.hh"
#include "misc.hh"

// See https://github.com/open-telemetry/opentelemetry-proto/tree/main/opentelemetry/proto

namespace pdns::trace
{

// https://github.com/open-telemetry/opentelemetry-proto/blob/main/opentelemetry/proto/common/v1/common.proto

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
  if (value != 0) {
    writer.add_fixed32(field, value);
  }
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
  if (value != 0) {
    writer.add_fixed64(field, value);
  }
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
  return {std::move(vec)};
}

struct ArrayValue
{
  std::vector<AnyValue> values{}; // = 1

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
  std::vector<KeyValue> values{}; // = 1

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

using NoValue = char;
struct AnyValue : public std::variant<NoValue, std::string, bool, int64_t, double, ArrayValue, KeyValueList, std::vector<uint8_t>>
{
  void encode(protozero::pbf_writer& writer) const;
  static AnyValue decode(protozero::pbf_reader& reader);
  [[nodiscard]] std::string toLogString() const;
  friend std::ostream& operator<<(std::ostream& ostrm, const AnyValue& val)
  {
    return ostrm << val.toLogString();
  }
};

struct EntityRef
{
  std::string schema_url{}; // == 1
  std::string type{}; // == 2
  std::vector<std::string> id_keys{}; // == 3
  std::vector<std::string> description_keys{}; // == 4

  void encode(protozero::pbf_writer& writer) const;
  static EntityRef decode(protozero::pbf_reader& reader);
};

struct KeyValue
{
  std::string key{}; // = 1
  AnyValue value{}; // = 2
  void encode(protozero::pbf_writer& writer) const;
  static KeyValue decode(protozero::pbf_reader& reader);

  bool operator==(const KeyValue& rhs) const
  {
    return key == rhs.key && value == rhs.value;
  }
};

struct Resource
{
  std::vector<KeyValue> attributes{}; // = 1
  uint32_t dropped_attributes_count{0}; // = 2;
  std::vector<EntityRef> entity_refs{}; // = 3

  void encode(protozero::pbf_writer& writer) const;
  static Resource decode(protozero::pbf_reader& reader);
};

struct InstrumentationScope
{
  std::string name{}; // = 1
  std::string version{}; // = 2
  std::vector<KeyValue> attributes{}; // = 3
  uint32_t dropped_attributes_count{0}; // = 4

  void encode(protozero::pbf_writer& writer) const;
  static InstrumentationScope decode(protozero::pbf_reader& reader);
};

struct TraceID : public std::array<uint8_t, 16>
{
  constexpr TraceID() :
    array{} {};
  TraceID(const std::initializer_list<uint8_t>& arg) :
    array{}
  {
    std::copy(arg.begin(), arg.end(), begin());
  }

  [[nodiscard]] std::string toLogString() const;
  friend std::ostream& operator<<(std::ostream& ostrm, const TraceID& val)
  {
    return ostrm << val.toLogString();
  }

  static TraceID getRandomTraceID()
  {
    TraceID ret;
    ret.makeRandom();
    return ret;
  }

  void makeRandom()
  {
    dns_random(this->data(), this->size());
  }

  void clear()
  {
    this->fill(0);
  }
};
constexpr TraceID s_emptyTraceID = {};

struct SpanID : public std::array<uint8_t, 8>
{
  constexpr SpanID() :
    array{} {};
  SpanID(const std::initializer_list<uint8_t>& arg) :
    array{}
  {
    std::copy(arg.begin(), arg.end(), begin());
  }

  [[nodiscard]] std::string toLogString() const;
  friend std::ostream& operator<<(std::ostream& ostrm, const SpanID& val)
  {
    return ostrm << val.toLogString();
  }

  static SpanID getRandomSpanID()
  {
    SpanID ret;
    ret.makeRandom();
    return ret;
  }

  void makeRandom()
  {
    dns_random(this->data(), this->size());
  }

  void clear()
  {
    this->fill(0);
  }
};
constexpr SpanID s_emptySpanID = {};

inline void fill(TraceID& trace, const std::string& data)
{
  if (data.size() != trace.size()) {
    throw std::runtime_error("TraceID size mismatch");
  }
  std::copy(data.begin(), data.end(), trace.begin());
}

inline void fill(SpanID& span, const std::string& data)
{
  if (data.size() != span.size()) {
    throw std::runtime_error("SpanID size mismatch");
  }
  std::copy(data.begin(), data.end(), span.begin());
}

inline void fill(TraceID& trace, const char* data, size_t size)
{
  fill(trace, std::string(data, size));
}

inline void fill(SpanID& span, const char* data, size_t size)
{
  fill(span, std::string(data, size));
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, const TraceID& value)
{
  writer.add_bytes(field, reinterpret_cast<const char*>(value.data()), value.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) it's the API
}

inline TraceID decodeTraceID(protozero::pbf_reader& reader)
{
  TraceID bytes;
  const auto data = reader.get_view();
  const auto len = std::min(bytes.size(), data.size());
  std::copy(data.data(), data.data() + len, bytes.begin()); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return bytes;
}

inline void encode(protozero::pbf_writer& writer, uint8_t field, const SpanID& value)
{
  writer.add_bytes(field, reinterpret_cast<const char*>(value.data()), value.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast) it's the API
}

inline SpanID decodeSpanID(protozero::pbf_reader& reader)
{
  SpanID bytes;
  const auto data = reader.get_view();
  const auto len = std::min(bytes.size(), data.size());
  std::copy(data.data(), data.data() + len, bytes.begin()); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return bytes;
}

// The Status type defines a logical error model that is suitable for different
// programming environments, including REST APIs and RPC APIs.
struct Status
{
  // A developer-facing human readable error message.
  std::string message{}; // = 2;

  // For the semantics of status codes see
  // https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/api.md#set-status
  enum class StatusCode : uint8_t
  {
    // The default status.
    STATUS_CODE_UNSET = 0,
    // The Span has been validated by an Application developer or Operator to
    // have completed successfully.
    STATUS_CODE_OK = 1,
    // The Span contains an error.
    STATUS_CODE_ERROR = 2,
  };

  // The status code.
  StatusCode code{StatusCode::STATUS_CODE_UNSET}; //  = 3;

  void clear()
  {
    message.clear();
    code = StatusCode::STATUS_CODE_UNSET;
  }
  void encode(protozero::pbf_writer& writer) const;
  static Status decode(protozero::pbf_reader& reader);
};

inline uint64_t timestamp()
{
  timespec now{};
  clock_gettime(CLOCK_REALTIME, &now);
  return (1000000000ULL * now.tv_sec) + now.tv_nsec;
}

// This struct is used to store the info of the initial span. As it is passed around resolving
// queries, it needs to be as small as possible, hence no full Span.
struct InitialSpanInfo
{
  TraceID trace_id{};
  SpanID span_id{};
  SpanID parent_span_id{};
  uint64_t start_time_unix_nano{0};

  void clear()
  {
    trace_id.clear();
    span_id.clear();
    parent_span_id.clear();
    start_time_unix_nano = 0;
  }
};

struct Span
{
  // A unique identifier for a trace. All spans from the same trace share
  // the same `trace_id`. The ID is a 16-byte array. An ID with all zeroes OR
  // of length other than 16 bytes is considered invalid (empty string in OTLP/JSON
  // is zero-length and thus is also invalid).
  //
  // This field is required.
  TraceID trace_id{}; // = 1
  // A unique identifier for a span within a trace, assigned when the span
  // is created. The ID is an 8-byte array. An ID with all zeroes OR of length
  // other than 8 bytes is considered invalid (empty string in OTLP/JSON
  // is zero-length and thus is also invalid).
  //
  // This field is required.
  SpanID span_id{}; // = 2
  // trace_state conveys information about request position in multiple distributed tracing graphs.
  // It is a trace_state in w3c-trace-context format: https://www.w3.org/TR/trace-context/#tracestate-header
  // See also https://github.com/w3c/distributed-tracing for more details about this field.
  std::string trace_state{}; // = 3
  // The `span_id` of this span's parent span. If this is a root span, then this
  // field must be empty. The ID is an 8-byte array.
  SpanID parent_span_id{}; // = 4
  // A description of the span's operation.
  //
  // For example, the name can be a qualified method name or a file name
  // and a line number where the operation is called. A best practice is to use
  // the same display name at the same call point in an application.
  // This makes it easier to correlate spans in different traces.
  //
  // This field is semantically required to be set to non-empty string.
  // Empty value is equivalent to an unknown span name.
  //
  // This field is required.
  std::string name{}; // = 5

  // SpanKind is the type of span. Can be used to specify additional relationships between spans
  // in addition to a parent/child relationship.
  enum class SpanKind : uint8_t
  {
    // Unspecified. Do NOT use as default.
    // Implementations MAY assume SpanKind to be INTERNAL when receiving UNSPECIFIED.
    SPAN_KIND_UNSPECIFIED = 0,
    // Indicates that the span represents an internal operation within an application,
    // as opposed to an operation happening at the boundaries. Default value.
    SPAN_KIND_INTERNAL = 1,
    // Indicates that the span covers server-side handling of an RPC or other
    // remote network request.
    SPAN_KIND_SERVER = 2,
    // Indicates that the span describes a request to some remote service.
    SPAN_KIND_CLIENT = 3,
    // Indicates that the span describes a producer sending a message to a broker.
    // Unlike CLIENT and SERVER, there is often no direct critical path latency relationship
    // between producer and consumer spans. A PRODUCER span ends when the message was accepted
    // by the broker while the logical processing of the message might span a much longer time.
    SPAN_KIND_PRODUCER = 4,
    // Indicates that the span describes consumer receiving a message from a broker.
    // Like the PRODUCER kind, there is often no direct critical path latency relationship
    // between producer and consumer spans.
    SPAN_KINCONSUMER = 5,
  };
  // Distinguishes between spans generated in a particular context. For example,
  // two spans with the same name may be distinguished using `CLIENT` (caller)
  // and `SERVER` (callee) to identify queueing latency associated with the span.
  SpanKind kind{Span::SpanKind::SPAN_KIND_UNSPECIFIED}; // = 6
  // start_time_unix_nano is the start time of the span. On the client side, this is the time
  // kept by the local machine where the span execution starts. On the server side, this
  // is the time when the server's application handler starts running.
  // Value is UNIX Epoch time in nanoseconds since 00:00:00 UTC on 1 January 1970.
  //
  // This field is semantically required and it is expected that end_time >= start_time.
  uint64_t start_time_unix_nano{0}; // = 7
  // end_time_unix_nano is the end time of the span. On the client side, this is the time
  // kept by the local machine where the span execution ends. On the server side, this
  // is the time when the server application handler stops running.
  // Value is UNIX Epoch time in nanoseconds since 00:00:00 UTC on 1 January 1970.
  //
  // This field is semantically required and it is expected that end_time >= start_time.
  uint64_t end_time_unix_nano{0}; // = 8
  // attributes is a collection of key/value pairs. Note, global attributes
  // like server name can be set using the resource API. Examples of attributes:
  //
  //     "/http/user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
  //     "/http/server_latency": 300
  //     "example.com/myattribute": true
  //     "example.com/score": 10.239
  //
  // The OpenTelemetry API specification further restricts the allowed value types:
  // https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/common/README.md#attribute
  // Attribute keys MUST be unique (it is not allowed to have more than one
  // attribute with the same key).
  std::vector<KeyValue> attributes{}; // = 9
  // dropped_attributes_count is the number of attributes that were discarded. Attributes
  // can be discarded because their keys are too long or because there are too many
  // attributes. If this value is 0, then no attributes were dropped.
  uint32_t dropped_attributes_count{0}; // = 10

  // Event is a time-stamped annotation of the span, consisting of user-supplied
  // text description and key-value pairs.x
  struct Event
  {
    // time_unix_nano is the time the event occurred.
    uint64_t time_unix_nano; // = 1
    // name of the event.
    // This field is semantically required to be set to non-empty string.
    std::string name; // = 2
    // attributes is a collection of attribute key/value pairs on the event.
    // Attribute keys MUST be unique (it is not allowed to have more than one
    // attribute with the same key).
    std::vector<KeyValue> attributes; // = 3
    // dropped_attributes_count is the number of dropped attributes. If the value is 0,
    // then no attributes were dropped.
    uint32_t dropped_attributes_count{0}; // = 4

    void encode(protozero::pbf_writer& writer) const;
    static Event decode(protozero::pbf_reader& reader);
  };
  // events is a collection of Event items.
  std::vector<Event> events{}; // = 11
  // dropped_events_count is the number of dropped events. If the value is 0, then no
  // events were dropped.
  uint32_t dropped_events_count{0}; // = 12

  // A pointer from the current span to another span in the same trace or in a
  // different trace. For example, this can be used in batching operations,
  // where a single batch handler processes multiple requests from different
  // traces or when the handler receives a request from a different project.
  struct Link
  {
    // A unique identifier of a trace that this linked span is part of. The ID is a
    // 16-byte array.
    TraceID trace_id; // = 1
    // A unique identifier for the linked span. The ID is an 8-byte array.
    SpanID span_id; // = 2
    // The trace_state associated with the link.
    std::string trace_state; // = 3
    // attributes is a collection of attribute key/value pairs on the link.
    // Attribute keys MUST be unique (it is not allowed to have more than one
    // attribute with the same key).
    std::vector<KeyValue> attributes; // = 4
    // dropped_attributes_count is the number of dropped attributes. If the value is 0,
    // then no attributes were dropped.
    uint32_t dropped_attributes_count{0}; // = 5
    // Flags, a bit field.
    //
    // Bits 0-7 (8 least significant bits) are the trace flags as defined in W3C Trace
    // Context specification. To read the 8-bit W3C trace flag, use
    // `flags & SPAN_FLAGS_TRACE_FLAGS_MASK`.
    //
    // See https://www.w3.org/TR/trace-context-2/#trace-flags for the flag definitions.
    //
    // Bits 8 and 9 represent the 3 states of whether the link is remote.
    // The states are (unknown, is not remote, is remote).
    // To read whether the value is known, use `(flags & SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK) != 0`.
    // To read whether the link is remote, use `(flags & SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK) != 0`.
    //
    // Readers MUST NOT assume that bits 10-31 (22 most significant bits) will be zero.
    // When creating new spans, bits 10-31 (most-significant 22-bits) MUST be zero.
    //
    // [Optional].
    uint32_t flags{0}; // = 6

    void encode(protozero::pbf_writer& writer) const;
    static Link decode(protozero::pbf_reader& reader);
  };
  std::vector<Link> links{}; // = 13
  uint32_t dropped_links_count{0}; // = 14
  Status status{}; // = 15

  // Flags, a bit field.
  //
  // Bits 0-7 (8 least significant bits) are the trace flags as defined in W3C Trace
  // Context specification. To read the 8-bit W3C trace flag, use
  // `flags & SPAN_FLAGS_TRACE_FLAGS_MASK`.
  //
  // See https://www.w3.org/TR/trace-context-2/#trace-flags for the flag definitions.
  //
  // Bits 8 and 9 represent the 3 states of whether a span's parent
  // is remote. The states are (unknown, is not remote, is remote).
  // To read whether the value is known, use `(flags & SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK) != 0`.
  // To read whether the span is remote, use `(flags & SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK) != 0`.
  //
  // When creating span messages, if the message is logically forwarded from another source
  // with an equivalent flags fields (i.e., usually another OTLP span message), the field SHOULD
  // be copied as-is. If creating from a source that does not have an equivalent flags field
  // (such as a runtime representation of an OpenTelemetry span), the high 22 bits MUST
  // be set to zero.
  // Readers MUST NOT assume that bits 10-31 (22 most significant bits) will be zero.
  //
  // [Optional].
  uint32_t flags{0}; // = 16;

  void close()
  {
    end_time_unix_nano = timestamp();
  }

  void clear()
  {
    trace_id.clear(); // 1
    span_id.clear(); // 2
    trace_state.clear(); // 3
    parent_span_id.clear(); // 4
    name.clear(); // 5
    kind = SpanKind::SPAN_KIND_UNSPECIFIED; // 6
    start_time_unix_nano = 0; // 7
    end_time_unix_nano = 0; // 8
    attributes.clear(); // 9
    dropped_attributes_count = 0; // 10
    events.clear(); // 11
    dropped_events_count = 0; // 12
    links.clear(); // 13
    dropped_links_count = 0; //14
    status.clear(); // 15
    flags = 0; // 16
  }
  void encode(protozero::pbf_writer& writer) const;
  static Span decode(protozero::pbf_reader& reader);
};

// SpanFlags represents constants used to interpret the
// Span.flags field, which is protobuf 'fixed32' type and is to
// be used as bit-fields. Each non-zero value defined in this enum is
// a bit-mask.  To extract the bit-field, for example, use an
// expression like:
//
//   (span.flags & SPAN_FLAGS_TRACE_FLAGS_MASK)
//
// See https://www.w3.org/TR/trace-context-2/#trace-flags for the flag definitions.
//
// Note that Span flags were introduced in version 1.1 of the
// OpenTelemetry protocol.  Older Span producers do not set this
// field, consequently consumers should not rely on the absence of a
// particular flag bit to indicate the presence of a particular feature.
enum class SpanFlags : uint16_t
{
  // The zero value for the enum. Should not be used for comparisons.
  // Instead use bitwise "and" with the appropriate mask as shown above.
  SPAN_FLAGS_DO_NOT_USE = 0,
  // Bits 0-7 are used for trace flags.
  SPAN_FLAGS_TRACE_FLAGS_MASK = 0x000000FF,
  // Bits 8 and 9 are used to indicate that the parent span or link span is remote.
  // Bit 8 (`HAS_IS_REMOTE`) indicates whether the value is known.
  // Bit 9 (`IS_REMOTE`) indicates whether the span or link is remote.
  SPAN_FLAGS_CONTEXT_HAS_IS_REMOTE_MASK = 0x00000100,
  SPAN_FLAGS_CONTEXT_IS_REMOTE_MASK = 0x00000200,
  // Bits 10-31 are reserved for future use.
};

// A collection of Spans produced by an InstrumentationScope.
struct ScopeSpans
{
  // The instrumentation scope information for the spans in this message.
  // Semantically when InstrumentationScope isn't set, it is equivalent with
  // an empty instrumentation scope name (unknown).
  InstrumentationScope scope{}; // = 1
  // A list of Spans that originate from an instrumentation scope.
  std::vector<Span> spans{}; // = 2
  // The Schema URL, if known. This is the identifier of the Schema that the span data
  // is recorded in. Notably, the last part of the URL path is the version number of the
  // schema: http[s]://server[:port]/path/<version>. To learn more about Schema URL see
  // https://opentelemetry.io/docs/specs/otel/schemas/#schema-url
  // This schema_url applies to all spans and span events in the "spans" field.
  std::string schema_url{}; // = 3

  void close()
  {
    for (auto& element : spans) {
      element.close();
    }
  }
  void encode(protozero::pbf_writer& writer) const;
  static ScopeSpans decode(protozero::pbf_reader& reader);
};

// A collection of ScopeSpans from a Resource.
struct ResourceSpans
{
  // The resource for the spans in this message.
  // If this field is not set then no resource info is known.
  Resource resource; // = 1
  // A list of ScopeSpans that originate from a resource.
  std::vector<ScopeSpans> scope_spans; // = 2
  // The Schema URL, if known. This is the identifier of the Schema that the resource data
  // is recorded in. Notably, the last part of the URL path is the version number of the
  // schema: http[s]://server[:port]/path/<version>. To learn more about Schema URL see
  // https://opentelemetry.io/docs/specs/otel/schemas/#schema-url
  // This schema_url applies to the data in the "resource" field. It does not apply
  // to the data in the "scope_spans" field which have their own schema_url field.
  std::string schema_url{}; // = 3

  void close()
  {
    for (auto& element : scope_spans) {
      element.close();
    }
  }
  void encode(protozero::pbf_writer& writer) const;
  static ResourceSpans decode(protozero::pbf_reader& reader);
};

// TracesData represents the traces data that can be stored in a persistent storage,
// OR can be embedded by other protocols that transfer OTLP traces data but do
// not implement the OTLP protocol.
//
// The main difference between this message and collector protocol is that
// in this message there will not be any "control" or "metadata" specific to
// OTLP protocol.
//
// When new fields are added into this message, the OTLP request MUST be updated
// as well.
struct TracesData
{
  // An array of ResourceSpans.
  // For data coming from a single resource this array will typically contain
  // one element. Intermediary nodes that receive data from multiple origins
  // typically batch the data before forwarding further and in that case this
  // array will contain multiple elements.
  std::vector<ResourceSpans> resource_spans; // = 1

  void close()
  {
    for (auto& element : resource_spans) {
      element.close();
    }
  }
  void encode(protozero::pbf_writer& writer) const;
  static TracesData decode(protozero::pbf_reader& reader);

  [[nodiscard]] std::string encode() const
  {
    std::string data;
    protozero::pbf_writer writer{data};
    encode(writer);
    return data;
  }

  static TracesData boilerPlate(std::string&& service, std::vector<Span>&& spans, const std::vector<KeyValue>& attributes, std::string& serverID)
  {
    auto& spanAttrs = spans.at(0).attributes;
    spanAttrs.insert(spanAttrs.end(), attributes.begin(), attributes.end());
    auto host = getHostname();
    std::string hostname = host.value_or("unset");
    InstrumentationScope scope{
      .name = "rec", .version = VERSION, .attributes = {{"hostname", {hostname}}, {"server.id", {serverID}}}};
    return TracesData{
      .resource_spans = {pdns::trace::ResourceSpans{.resource = {.attributes = {{"service.name", {{std::move(service)}}}}}, .scope_spans = {{.scope = std::move(scope), .spans = std::move(spans)}}}}};
  }
};

inline ArrayValue ArrayValue::decode(protozero::pbf_reader& reader)
{
  return pdns::trace::decode<ArrayValue, AnyValue>(reader);
}

inline KeyValueList KeyValueList::decode(protozero::pbf_reader& reader)
{
  return pdns::trace::decode<KeyValueList, KeyValue>(reader);
}

struct EDNSOTTraceRecord
{
  // 1 byte version, 1 byte reserved/alignment, 16 bytes traceid, optional 8 bytes spanid
  static constexpr size_t fullSize = 1 + 1 + 16 + 8;
  static constexpr size_t sizeNoSpanID = 1 + 1 + 16;
  static constexpr size_t traceIDOffset = 1 + 1;
  static constexpr size_t spanIDOffset = 1 + 1 + 16;

  EDNSOTTraceRecord(uint8_t* arg) :
    data(arg) {}
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  void setVersion(uint8_t version)
  {
    data[0] = version;
  }
  void setTraceID(const TraceID& traceid)
  {
    std::copy(traceid.begin(), traceid.end(), &data[traceIDOffset]);
  }
  void setSpanID(const SpanID& spanid)
  {
    std::copy(spanid.begin(), spanid.end(), &data[spanIDOffset]);
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
private:
  uint8_t* data;
};

struct EDNSOTTraceRecordView
{
  EDNSOTTraceRecordView(const uint8_t* arg, size_t argsize) :
    data(arg), size(argsize) {}

  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  [[nodiscard]] bool getVersion(uint8_t& version) const
  {
    if (size > 0) {
      version = data[0];
      return true;
    }
    return false;
  }
  [[nodiscard]] bool getTraceID(TraceID& traceid) const
  {
    if (size >= pdns::trace::EDNSOTTraceRecord::sizeNoSpanID) {
      std::copy(&data[EDNSOTTraceRecord::traceIDOffset], &data[EDNSOTTraceRecord::traceIDOffset + traceid.size()], traceid.begin());
      return true;
    }
    return false;
  }
  [[nodiscard]] bool getSpanID(SpanID& spanid) const
  {
    if (size == pdns::trace::EDNSOTTraceRecord::fullSize) {
      std::copy(&data[EDNSOTTraceRecord::spanIDOffset], &data[EDNSOTTraceRecord::spanIDOffset + spanid.size()], spanid.begin());
      return true;
    }
    return false;
  }
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
private:
  const uint8_t* const data;
  const size_t size;
};

void extractOTraceIDs(const EDNSOptionViewMap& map, pdns::trace::InitialSpanInfo& span);
bool extractOTraceIDs(const EDNSOptionViewMap& map, const EDNSOptionCode::EDNSOptionCodeEnum& eoc, pdns::trace::TraceID& traceID, pdns::trace::SpanID& spanID);

} // namespace pdns::trace
