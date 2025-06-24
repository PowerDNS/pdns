#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include "config.h"
#include <fstream>
#include <boost/test/unit_test.hpp>

#include "protozero-trace.hh"
#include "misc.hh"

BOOST_AUTO_TEST_SUITE(test_protobuf_trace)

BOOST_AUTO_TEST_CASE(resource0)
{
  pdns::trace::Resource resource{};
  std::string data;
  protozero::pbf_writer writer{data};
  resource.encode(writer);
#if 0
  std::ofstream x("x");
  x << data;
#endif
  BOOST_CHECK_EQUAL(makeHexDump(data, " "), "");
}

BOOST_AUTO_TEST_CASE(resource1)
{
  pdns::trace::Resource resource{
    {
      {"foo0", {"bar"}},
      {"foo1", {99.99}},
    },
    99,
    {{{"schema0", "type0", {"id00", "id01"}, {"desc00", "desc01"}},
      {"schema1", "type1", {"id10", "id11"}, {"desc10", "desc11"}}}}};
  std::string data;
  protozero::pbf_writer writer{data};
  resource.encode(writer);
#if 0
  std::ofstream x("x");
  x << data;
#endif
  BOOST_CHECK_EQUAL(makeHexDump(data, " "), "0a 0d 0a 04 66 6f 6f 30 12 05 0a 03 62 61 72 0a 11 0a 04 66 6f 6f 31 12 09 21 8f c2 f5 28 5c ff 58 40 10 63 1a 2c 0a 07 73 63 68 65 6d 61 30 12 05 74 79 70 65 30 1a 04 69 64 30 30 1a 04 69 64 30 31 22 06 64 65 73 63 30 30 22 06 64 65 73 63 30 31 1a 2c 0a 07 73 63 68 65 6d 61 31 12 05 74 79 70 65 31 1a 04 69 64 31 30 1a 04 69 64 31 31 22 06 64 65 73 63 31 30 22 06 64 65 73 63 31 31 ");
}

template <typename T>
static void testAny(const T& testcase)
{
  std::string data;
  protozero::pbf_writer writer{data};
  pdns::trace::AnyValue wrapper{testcase};
  wrapper.encode(writer);
#if 0
  std::ofstream x("x");
  x << data;
#endif

  protozero::pbf_reader reader{data};
  pdns::trace::AnyValue value = pdns::trace::AnyValue::decode(reader);
  if (!std::holds_alternative<pdns::trace::NoValue>(value)) {
    BOOST_CHECK(testcase == std::get<T>(value));
  }
  else {
    if (std::holds_alternative<pdns::trace::ArrayValue>(wrapper)) {
      BOOST_CHECK(std::get<pdns::trace::ArrayValue>(wrapper).values.empty());
    }
    else if (std::holds_alternative<pdns::trace::KeyValueList>(wrapper)) {
      BOOST_CHECK(std::get<pdns::trace::KeyValueList>(wrapper).values.empty());
    }
  }
}

BOOST_AUTO_TEST_CASE(any)
{
  testAny(std::string{"foo"});
  testAny(false);
  testAny(true);
  testAny(static_cast<int64_t>(0));
  testAny(static_cast<int64_t>(1));
  testAny(static_cast<int64_t>(-1));
  testAny(std::numeric_limits<int64_t>::min());
  testAny(std::numeric_limits<int64_t>::max());
  testAny(0.0);
  testAny(1.0);
  testAny(-1.0);
  testAny(std::numeric_limits<double>::min());
  testAny(std::numeric_limits<double>::max());

  pdns::trace::ArrayValue avalue;
  testAny(avalue);
  avalue.values.emplace_back(pdns::trace::AnyValue{"foo"});
  avalue.values.emplace_back(pdns::trace::AnyValue{1.99});
  testAny(avalue);

  pdns::trace::KeyValueList kvlist;
  testAny(kvlist);
  kvlist.values.emplace_back(pdns::trace::KeyValue{"foo", {"bar"}});
  kvlist.values.emplace_back(pdns::trace::KeyValue{"baz", {1.99}});
  testAny(kvlist);

  std::vector<uint8_t> bytes;
  testAny(bytes);
  bytes.push_back(0);
  bytes.push_back(1);
  bytes.push_back(2);
  testAny(bytes);
}

BOOST_AUTO_TEST_CASE(traces1)
{
  pdns::trace::Span span = {
    .trace_id = {0x5B, 0x8E, 0xFF, 0xF7, 0x98, 0x03, 0x81, 0x03, 0xD2, 0x69, 0xB6, 0x33, 0x81, 0x3F, 0xC6, 0x0C},
    .span_id = {0xEE, 0xE1, 0x9B, 0x7E, 0xC3, 0xC1, 0xB1, 0x74},
    .parent_span_id = {0xEE, 0xE1, 0x9B, 0x7E, 0xC3, 0xC1, 0xB1, 0x73},
    .name = "I'm a server span",
    .kind = pdns::trace::Span::SpanKind::SPAN_KINSERVER,
    .start_time_unix_nano = 1544712660000000000UL,
    .end_time_unix_nano = 1544712661000000000UL,
    .attributes = {{"my.span.attr", {"some value"}}}};
  pdns::trace::InstrumentationScope scope = {"my.library", "1.0.0", {{"my.scope.attribute", {"some scope attribute"}}}};
  pdns::trace::ScopeSpans scopespans = {.scope = scope, .spans = {span}};
  pdns::trace::Resource res = {.attributes = {{"service.name", {"my.service"}}}};
  pdns::trace::ResourceSpans resspans = {.resource = res, .scope_spans = {scopespans}};
  pdns::trace::TracesData traces = {.resource_spans = {resspans}};

  std::string data;
  protozero::pbf_writer writer{data};
  traces.encode(writer);
#if 0
  std::ofstream z("z");
  z << data;
#endif
  const string expected = ""
                          "0a d3 01 0a 1e 0a 1c 0a 0c 73 65 72 76 69 63 65 "
                          "2e 6e 61 6d 65 12 0c 0a 0a 6d 79 2e 73 65 72 76 "
                          "69 63 65 12 b0 01 0a 41 0a 0a 6d 79 2e 6c 69 62 "
                          "72 61 72 79 12 05 31 2e 30 2e 30 1a 2c 0a 12 6d "
                          "79 2e 73 63 6f 70 65 2e 61 74 74 72 69 62 75 74 "
                          "65 12 16 0a 14 73 6f 6d 65 20 73 63 6f 70 65 20 "
                          "61 74 74 72 69 62 75 74 65 12 6b 0a 10 5b 8e ff "
                          "f7 98 03 81 03 d2 69 b6 33 81 3f c6 0c 12 08 ee "
                          "e1 9b 7e c3 c1 b1 74 22 08 ee e1 9b 7e c3 c1 b1 "
                          "73 2a 11 49 27 6d 20 61 20 73 65 72 76 65 72 20 "
                          "73 70 61 6e 30 02 39 00 48 59 e3 fa eb 6f 15 41 "
                          "00 12 f4 1e fb eb 6f 15 4a 1c 0a 0c 6d 79 2e 73 "
                          "70 61 6e 2e 61 74 74 72 12 0c 0a 0a 73 6f 6d 65 "
                          "20 76 61 6c 75 65 ";
  BOOST_CHECK_EQUAL(makeHexDump(data, " "), expected);

  protozero::pbf_reader reader{data};
  auto copy = pdns::trace::TracesData::decode(reader);
  data.clear();
  protozero::pbf_writer copyWriter{data};
  copy.encode(copyWriter);
  BOOST_CHECK_EQUAL(makeHexDump(data, " "), expected);
}

BOOST_AUTO_TEST_CASE(traces2)
{
  pdns::trace::Span span1{
    .trace_id = {0x5B, 0x8E, 0xFF, 0xF7, 0x98, 0x03, 0x81, 0x03, 0xD2, 0x69, 0xB6, 0x33, 0x81, 0x3F, 0xC6, 0x0C},
    .span_id = {0xEE, 0xE1, 0x9B, 0x7E, 0xC3, 0xC1, 0xB1, 0x74},
    .parent_span_id = {0xEE, 0xE1, 0x9B, 0x7E, 0xC3, 0xC1, 0xB1, 0x73},
    .name = "I'm a server span",
    .kind = pdns::trace::Span::SpanKind::SPAN_KINSERVER,
    .start_time_unix_nano = 1544712660000000000UL,
    .end_time_unix_nano = 1544712661000000000UL,
    .attributes = {{"my.span.attr", {"some value"}}, {"attr2", {1.0}}},
    .dropped_attributes_count = 1,
    .events = {
      {.time_unix_nano = 100,
       .name = "event1",
       .attributes = {{"a", {"b"}}, {"c", {"d"}}},
       .dropped_attributes_count = 101},
      {.time_unix_nano = 200,
       .name = "event2",
       .attributes = {{"c", {"d"}}, {"e", {""}}},
       .dropped_attributes_count = 201},
    },
    .dropped_events_count = 2,
    .links = {
      {.trace_id = {0x1}, .span_id = {0x4}, .trace_state = "state1", .attributes = {{"foo", {"bar"}}, {"bar", {true}}}, .dropped_attributes_count = 1000, .flags = static_cast<uint32_t>(pdns::trace::SpanFlags::SPAN_FLAGS_TRACE_FLAGS_MASK)},
      {.trace_id = {0x2}, .span_id = {0x3}, .trace_state = "state2", .attributes = {{"foo", {"bar"}}, {"bar", {true}}}, .dropped_attributes_count = 1001, .flags = static_cast<uint32_t>(pdns::trace::SpanFlags::SPAN_FLAGS_TRACE_FLAGS_MASK)},
    },
    .dropped_links_count = 3,
    .status = {"hi", pdns::trace::Status::StatusCode::STATUS_CODE_OK},
    .flags = 33,
  };
  pdns::trace::Span span2{span1};
  pdns::trace::Span span3{span1};
  pdns::trace::Span span4{span1};
  pdns::trace::InstrumentationScope scope{"name", "version", {{"key1", {0.1}}, {"key2", {false}}}, 100};
  pdns::trace::ScopeSpans scopespans1{scope, {span1, span2}, "url"};
  pdns::trace::ScopeSpans scopespans2{scope, {span3, span4}, "url"};
  pdns::trace::Resource res{.attributes = {{"key1", {"foo"}}, {"key2", {"bar"}}},
                            .dropped_attributes_count = 99,
                            .entity_refs = {{"url1", "type1", {"id_key1", "id_key2"}, {"desc_key1", "desc_key2"}},
                                            {"url2", "type2", {"id_key3", "id_key4"}, {"desc_key3", "desc_key4"}}}};
  pdns::trace::ResourceSpans resspans1{res, {scopespans1, scopespans2}, "url"};
  pdns::trace::ResourceSpans resspans2{res, {scopespans1, scopespans2}, "url"};
  pdns::trace::TracesData traces{{resspans1, resspans2}};

  std::string data;
  protozero::pbf_writer writer{data};
  traces.encode(writer);
#if 0
  std::ofstream x("x");
  x << data;
#endif
  protozero::pbf_reader reader{data};
  auto copy = pdns::trace::TracesData::decode(reader);
  string copyData;
  protozero::pbf_writer copyWriter{copyData};
  copy.encode(copyWriter);
  BOOST_CHECK_EQUAL(data, copyData);
}

BOOST_AUTO_TEST_SUITE_END()
