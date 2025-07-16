#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include <memory>
#include <boost/algorithm/string/trim.hpp>
#include <boost/format.hpp>
#include <fstream>

#include "rec-rust-lib/cxxsettings.hh"

BOOST_AUTO_TEST_SUITE(test_settings)

BOOST_AUTO_TEST_CASE(test_rust_empty)
{
  const std::string yaml = "{}\n";
  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);

  // Check an attribute to see if it has the right default value
  BOOST_CHECK_EQUAL(settings.dnssec.aggressive_nsec_cache_size, 100000U);

  // Generate yaml, should be empty as all values are default
  auto back = settings.to_yaml_string();
  // rust::String does not play nice with BOOST_CHECK_EQUAL, it lacks a <<
  BOOST_CHECK_EQUAL(yaml, std::string(back));
}

BOOST_AUTO_TEST_CASE(test_rust_syntaxerror)
{
  const std::string yaml = "{incoming: port: \n";
  BOOST_CHECK_THROW(pdns::rust::settings::rec::parse_yaml_string(yaml), rust::Error);
}

BOOST_AUTO_TEST_CASE(test_rust_unknown_section)
{
  const std::string yaml = "{adskldsaj: port: \n";
  BOOST_CHECK_THROW(pdns::rust::settings::rec::parse_yaml_string(yaml), rust::Error);
}

BOOST_AUTO_TEST_CASE(test_rust_unknown_field)
{
  const std::string yaml = "{incoming: akajkj0: \n";
  BOOST_CHECK_THROW(pdns::rust::settings::rec::parse_yaml_string(yaml), rust::Error);
}

BOOST_AUTO_TEST_CASE(test_rust_parse)
{
  const std::string yaml = R"EOT(dnssec:
  aggressive_nsec_cache_size: 10
incoming:
  allow_from:
  - '!123.123.123.123'
  - ::1
recursor:
  auth_zones:
  - zone: example.com
    file: a/file/name
  - zone: example.net
    file: another/file/name
  forward_zones:
  - zone: .
    forwarders:
    - 9.9.9.9
  forward_zones_recurse:
  - zone: .
    forwarders:
    - 9.9.9.9
    - 1.2.3.4
    - ::99
    recurse: true
webservice:
  api_key: otto
packetcache:
  disable: true
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  BOOST_CHECK_EQUAL(settings.dnssec.aggressive_nsec_cache_size, 10U);
  BOOST_CHECK_EQUAL(settings.incoming.allow_from.size(), 2U);
  BOOST_REQUIRE_EQUAL(settings.recursor.auth_zones.size(), 2U);
  BOOST_REQUIRE_EQUAL(settings.recursor.forward_zones.size(), 1U);
  BOOST_REQUIRE_EQUAL(settings.recursor.forward_zones[0].forwarders.size(), 1U);
  BOOST_REQUIRE_EQUAL(settings.recursor.forward_zones_recurse.size(), 1U);
  BOOST_REQUIRE_EQUAL(settings.recursor.forward_zones_recurse[0].forwarders.size(), 3U);
  BOOST_CHECK(settings.recursor.forward_zones_recurse[0].recurse);
  auto back = settings.to_yaml_string();
  // rust::String does not play nice with BOOST_CHECK_EQUAL, it lacks a <<
  BOOST_CHECK_EQUAL(yaml, std::string(back));
}

BOOST_AUTO_TEST_CASE(test_rust_validation_with_error1)
{
  const std::string yaml = R"EOT(
incoming:
  allow_from: ["1.2.3.8999"]
)EOT";

  BOOST_CHECK_THROW({
    auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
    auto back = settings.to_yaml_string();
    settings.validate(); }, rust::Error);
}

BOOST_AUTO_TEST_CASE(test_rust_validation_with_error2)
{
  const std::string yaml = R"EOT(
recursor:
  forward_zones:
    - zone: "example.com"
      forwarders:
        - 1.2.3.4
        - '-a.b'
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  auto back = settings.to_yaml_string();
  BOOST_CHECK_THROW({ settings.validate(); }, rust::Error);
}

BOOST_AUTO_TEST_CASE(test_rust_validation_with_error3)
{
  const std::string yaml = R"EOT(
recursor:
  forward_zones:
    - zone:
      forwarders:
        - 1.2.3.4
)EOT";

  BOOST_CHECK_THROW({
    auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
    auto back = settings.to_yaml_string();
    settings.validate(); }, rust::Error);
}

BOOST_AUTO_TEST_CASE(test_rust_validation_with_error4)
{
  const std::string yaml = R"EOT(
recursor:
  forward_zones:
    - zone: ok
)EOT";

  BOOST_CHECK_THROW({
    auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
    auto back = settings.to_yaml_string();
    settings.validate(); }, rust::Error);
}

BOOST_AUTO_TEST_CASE(test_rust_validation_with_error5)
{
  const std::string yaml = R"EOT(
recursor:
  auth_zones:
    - zone: %1%
      file: filename
)EOT";

  const vector<string> oktests = {
    ".",
    "one",
    "one.",
    "two.label"
    "two.label.",
  };
  for (const auto& ok : oktests) {
    auto yamltest = boost::format(yaml) % ok;
    BOOST_CHECK_NO_THROW({
      auto settings = pdns::rust::settings::rec::parse_yaml_string(yamltest.str());
      settings.validate();
    });
  }
  const vector<string> noktests = {
    "",
    "..",
    "two..label",
    ".two.label",
    "three€.a.label",
    "three.a.label..",
  };
  for (const auto& nok : noktests) {
    auto yamltest = boost::format(yaml) % nok;
    BOOST_CHECK_THROW({
      auto settings = pdns::rust::settings::rec::parse_yaml_string(yamltest.str());
      auto back = settings.to_yaml_string();
      settings.validate(); }, rust::Error);
  }
}

BOOST_AUTO_TEST_CASE(test_rust_validation_no_error)
{
  // All defaults
  const std::string yaml = "{}\n";

  BOOST_CHECK_NO_THROW({
    auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
    settings.validate();
  });
}

BOOST_AUTO_TEST_CASE(test_rust_forwardzones_to_yaml)
{
  using pdns::rust::settings::rec::ForwardZone;
  rust::Vec<ForwardZone> vec;
  vec.emplace_back(ForwardZone{"zone1", {"1.2.3.4"}, false, false});
  vec.emplace_back(ForwardZone{"zone2", {"1.2.3.4", "::1"}, true, true});

  auto yaml = pdns::rust::settings::rec::forward_zones_to_yaml_string(vec);

  const std::string expected = R"EOT(- zone: zone1
  forwarders:
  - 1.2.3.4
- zone: zone2
  forwarders:
  - 1.2.3.4
  - ::1
  recurse: true
  notify_allowed: true
)EOT";

  BOOST_CHECK_EQUAL(std::string(yaml), expected);
}

BOOST_AUTO_TEST_CASE(test_rust_parse_forwardzones_to_yaml)
{
  std::string fileContent = R"EOT(
# aap
example1.com= 1.2.3.4, 5.6.7.8; 8.9.0.1
^+example2.com = ::1
)EOT";

  const std::string expected = R"EOT(- zone: example1.com
  forwarders:
  - 1.2.3.4
  - 5.6.7.8
  - 8.9.0.1
- zone: example2.com
  forwarders:
  - ::1
  recurse: true
  notify_allowed: true
)EOT";

  std::string temp("/tmp/test-settingsXXXXXXXXXX");
  int fileDesc = mkstemp(temp.data());
  BOOST_REQUIRE(fileDesc > 0);
  auto filePtr = pdns::UniqueFilePtr(fdopen(fileDesc, "w"));
  BOOST_REQUIRE(filePtr != nullptr);
  size_t written = fwrite(fileContent.data(), 1, fileContent.length(), filePtr.get());
  BOOST_REQUIRE(written == fileContent.length());
  filePtr = nullptr;

  rust::Vec<pdns::rust::settings::rec::ForwardZone> forwards;
  pdns::settings::rec::oldStyleForwardsFileToBridgeStruct(temp, forwards);
  unlink(temp.data());

  auto yaml = pdns::rust::settings::rec::forward_zones_to_yaml_string(forwards);
  BOOST_CHECK_EQUAL(std::string(yaml), expected);
}

BOOST_AUTO_TEST_CASE(test_rust_merge_defaults)
{
  const std::string yaml = "{}\n";
  auto lhs = pdns::rust::settings::rec::parse_yaml_string(yaml);

  pdns::rust::settings::rec::merge(lhs, yaml);
  auto back = lhs.to_yaml_string();
  BOOST_CHECK_EQUAL(yaml, std::string(back));
}

BOOST_AUTO_TEST_CASE(test_rust_merge_lhs_default)
{
  const std::string yaml = "{}\n";
  auto lhs = pdns::rust::settings::rec::parse_yaml_string(yaml);
  auto rhs = pdns::rust::settings::rec::parse_yaml_string(yaml);

  const std::string yaml2 = R"EOT(
recursor:
  forward_zones:
  - zone: zone
    forwarders:
    - 1.2.3.4
dnssec:
  validation: validate
)EOT";

  pdns::rust::settings::rec::merge(lhs, yaml2);

  BOOST_CHECK_EQUAL(std::string(lhs.dnssec.validation), "validate");
  BOOST_CHECK_EQUAL(lhs.recursor.forward_zones.size(), 1U);
}

BOOST_AUTO_TEST_CASE(test_rust_merge_lhs_nondefault)
{
  const std::string yaml = "{}\n";
  auto lhs = pdns::rust::settings::rec::parse_yaml_string(yaml);
  auto rhs = pdns::rust::settings::rec::parse_yaml_string(yaml);

  lhs.dnssec.validation = "no";
  lhs.recursor.forward_zones.emplace_back(pdns::rust::settings::rec::ForwardZone{"zone1", {"1.2.3.4"}, false, false});

  rhs.dnssec.validation = "validate";
  rhs.recursor.forward_zones.emplace_back(pdns::rust::settings::rec::ForwardZone{"zone2", {"1.2.3.4"}, false, false});

  const auto yaml2 = rhs.to_yaml_string();
  pdns::rust::settings::rec::merge(lhs, yaml2);

  BOOST_CHECK_EQUAL(std::string(lhs.dnssec.validation), "validate");
  BOOST_CHECK_EQUAL(lhs.recursor.forward_zones.size(), 2U);
}

BOOST_AUTO_TEST_CASE(test_rust_merge_rhs_mixed)
{
  const std::string yaml = "{}\n";
  auto lhs = pdns::rust::settings::rec::parse_yaml_string(yaml);
  auto rhs = pdns::rust::settings::rec::parse_yaml_string(yaml);

  lhs.dnssec.validation = "no";
  lhs.recursor.forward_zones.emplace_back(pdns::rust::settings::rec::ForwardZone{"zone1", {"1.2.3.4"}, false, false});
  rhs.recursor.forward_zones.emplace_back(pdns::rust::settings::rec::ForwardZone{"zone2", {"1.2.3.4"}, false, false});

  const auto yaml2 = rhs.to_yaml_string();
  pdns::rust::settings::rec::merge(lhs, yaml);

  pdns::rust::settings::rec::merge(lhs, yaml2);

  BOOST_CHECK_EQUAL(std::string(lhs.dnssec.validation), "no");
  BOOST_CHECK_EQUAL(lhs.recursor.forward_zones.size(), 2U);
}

BOOST_AUTO_TEST_CASE(test_rust_merge_list_nonempty_default1)
{
  const std::string yaml = "{}\n";
  auto lhs = pdns::rust::settings::rec::parse_yaml_string(yaml);
  auto rhs = pdns::rust::settings::rec::parse_yaml_string(yaml);

  // Note that dont_query is a non-empty list by default
  // lhs default, rhs is not (empty ), rhs overwrites lhs
  rhs.outgoing.dont_query = {};
  const auto yaml2 = rhs.to_yaml_string();
  pdns::rust::settings::rec::merge(lhs, yaml2);

  BOOST_CHECK_EQUAL(lhs.outgoing.dont_query.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_rust_merge_list_nonempty_default2)
{
  const std::string yaml = "{}\n";
  auto lhs = pdns::rust::settings::rec::parse_yaml_string(yaml);
  auto rhs = pdns::rust::settings::rec::parse_yaml_string(yaml);

  rhs.outgoing.dont_query = {"1.2.3.4"};
  // lhs default, rhs overwrites lhs
  const auto yaml2 = rhs.to_yaml_string();
  pdns::rust::settings::rec::merge(lhs, yaml2);

  BOOST_CHECK_EQUAL(lhs.outgoing.dont_query.size(), 1U);

  rhs = pdns::rust::settings::rec::parse_yaml_string(yaml);
  rhs.outgoing.dont_query = {"4.5.6.7"};
  // lhs not default, rhs gets merged
  const auto yaml3 = rhs.to_yaml_string();
  pdns::rust::settings::rec::merge(lhs, yaml2);

  BOOST_CHECK_EQUAL(lhs.outgoing.dont_query.size(), 2U);
}

BOOST_AUTO_TEST_CASE(test_rust_merge_nondefault_and_default)
{
  const std::string yaml1 = "{}\n";
  auto lhs = pdns::rust::settings::rec::parse_yaml_string(yaml1);
  lhs.recordcache.max_entries = 99;
  lhs.dnssec.validation = "no";
  const std::string yaml2 = R"EOT(
  dnssec:
    validation: process
  incoming:
    allow_from:
    - 4.5.6.7/1
)EOT";
  pdns::rust::settings::rec::merge(lhs, yaml2);

  BOOST_CHECK_EQUAL(lhs.dnssec.validation, "process");
  BOOST_CHECK_EQUAL(lhs.incoming.allow_from.size(), 1U);
  BOOST_CHECK_EQUAL(lhs.recordcache.max_entries, 99U);
}

BOOST_AUTO_TEST_CASE(test_rust_merge_override)
{
  const std::string yaml1 = R"EOT(
  incoming:
    allow_from:
    - 4.5.6.7/1
)EOT";
  auto lhs = pdns::rust::settings::rec::parse_yaml_string(yaml1);
  lhs.recordcache.max_entries = 99;
  lhs.dnssec.validation = "no";
  const std::string yaml2 = R"EOT(
  dnssec:
    validation: process
  incoming:
    allow_from: !override
    - 1.2.3.4/1
)EOT";
  pdns::rust::settings::rec::merge(lhs, yaml2);

  BOOST_CHECK_EQUAL(lhs.dnssec.validation, "process");
  BOOST_REQUIRE_EQUAL(lhs.incoming.allow_from.size(), 1U);
  BOOST_CHECK_EQUAL(lhs.incoming.allow_from.at(0), "1.2.3.4/1");
  BOOST_CHECK_EQUAL(lhs.recordcache.max_entries, 99U);
}

BOOST_AUTO_TEST_CASE(test_yaml_defaults_ta)
{
  // Two entries: one all default, one all overrides
  const std::string yaml1 = R"EOT(dnssec:

)EOT";
  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml1);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.dnssec.trustanchors.size(), 1U);
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.trustanchors[0].name), ".");
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.trustanchors[0].dsrecords[0]), "20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d");
  BOOST_CHECK_EQUAL(settings.dnssec.negative_trustanchors.size(), 0U);
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.trustanchorfile), "");
  BOOST_CHECK_EQUAL(settings.dnssec.trustanchorfile_interval, 24U);

  const std::string yaml2 = R"EOT(dnssec:
  trustanchors:
    - name: a
      dsrecords: [b]
    - name: a
      dsrecords: [c]
  negative_trustanchors:
    - name: c
      reason: d
  trustanchorfile: e
  trustanchorfile_interval: 99
)EOT";
  settings = pdns::rust::settings::rec::parse_yaml_string(yaml2);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.dnssec.trustanchors.size(), 2U);
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.trustanchors[0].name), "a");
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.trustanchors[0].dsrecords[0]), "b");
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.trustanchors[1].dsrecords[0]), "c");
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.negative_trustanchors[0].name), "c");
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.negative_trustanchors[0].reason), "d");
  BOOST_CHECK_EQUAL(std::string(settings.dnssec.trustanchorfile), "e");
  BOOST_CHECK_EQUAL(settings.dnssec.trustanchorfile_interval, 99U);
}

BOOST_AUTO_TEST_CASE(test_yaml_ta_merge)
{
  // If the YAML sets a root zone DS, the default one(s) are thrown away
  const std::string yaml1 = R"EOT(dnssec:
  trustanchors:
    - name: .
      dsrecords: ['19718 13 2 8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D7 71D7805A']
    - name: a
      dsrecords: ['37331 13 2 2F0BEC2D6F79DFBD1D08FD21A3AF92D0E39A4B9EF1E3F4111FFF2824 90DA453B']
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml1);
  settings.validate();
  LuaConfigItems lua1;
  ProxyMapping proxyMapping;
  pdns::settings::rec::fromBridgeStructToLuaConfig(settings, lua1, proxyMapping);
  BOOST_CHECK_EQUAL(lua1.dsAnchors.size(), 2U);
  BOOST_CHECK_EQUAL(lua1.dsAnchors[DNSName(".")].size(), 1U);
  BOOST_CHECK_EQUAL(lua1.dsAnchors[DNSName(".")].begin()->getZoneRepresentation(), "19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a");
  BOOST_CHECK_EQUAL(lua1.dsAnchors[DNSName("a")].size(), 1U);

  // Not adding a root DS should leave the default intact
  const std::string yaml2 = R"EOT(dnssec:
  trustanchors:
    - name: a
      dsrecords: ['19718 13 2 8ACBB0CD28F41250A80A491389424D341522D946B0DA0C0291F2D3D7 71D7805A']
    - name: a
      dsrecords: ['37331 13 2 2F0BEC2D6F79DFBD1D08FD21A3AF92D0E39A4B9EF1E3F4111FFF2824 90DA453B']
)EOT";

  settings = pdns::rust::settings::rec::parse_yaml_string(yaml2);
  settings.validate();
  LuaConfigItems lua2;
  pdns::settings::rec::fromBridgeStructToLuaConfig(settings, lua2, proxyMapping);
  BOOST_CHECK_EQUAL(lua2.dsAnchors.size(), 2U);
  BOOST_CHECK_EQUAL(lua2.dsAnchors[DNSName(".")].size(), 2U);
  BOOST_CHECK_EQUAL(lua2.dsAnchors[DNSName("a")].size(), 2U);
}

BOOST_AUTO_TEST_CASE(test_yaml_defaults_protobuf)
{
  // Two entries: one all default, one all overrides
  const std::string yaml1 = R"EOT(logging:
  protobuf_servers:
  - servers: [1.2.3.4]
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml1);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].timeout, 2U);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].maxQueuedEntries, 100U);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].reconnectWaitTime, 1U);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].taggedOnly, false);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].asyncConnect, false);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].logQueries, true);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].logResponses, true);
  // Code below crashes clang
  // std::vector<string> testv = {"A", "AAAA", "CNAME"})
  // BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].exportTypes, testv);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].logMappedFrom, false);

  const std::string yaml2 = R"EOT(logging:
  protobuf_servers:
  - servers: [6.7.8.9]
    timeout: 100
    maxQueuedEntries: 101
    reconnectWaitTime: 102
    taggedOnly: true
    asyncConnect: true
    logQueries: false
    logResponses: false
    logMappedFrom: true
)EOT";
  settings = pdns::rust::settings::rec::parse_yaml_string(yaml2);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].timeout, 100U);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].maxQueuedEntries, 101U);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].reconnectWaitTime, 102U);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].taggedOnly, true);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].asyncConnect, true);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].logQueries, false);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].logResponses, false);
  BOOST_CHECK_EQUAL(settings.logging.protobuf_servers[0].logMappedFrom, true);
}

BOOST_AUTO_TEST_CASE(test_yaml_defaults_outgoing_protobuf)
{
  // Two entries: one all default, one all overrides
  const std::string yaml1 = R"EOT(logging:
  outgoing_protobuf_servers:
  - servers: ['::1']
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml1);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].timeout, 2U);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].maxQueuedEntries, 100U);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].reconnectWaitTime, 1U);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].taggedOnly, false);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].asyncConnect, false);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].logQueries, true);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].logResponses, true);
  // Code below crashes clang
  // std::vector<string> testv = {"A", "AAAA", "CNAME"})
  // BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].exportTypes, testv);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].logMappedFrom, false);

  const std::string yaml2 = R"EOT(logging:
  outgoing_protobuf_servers:
  - servers: [123.123.123.123]
    timeout: 100
    maxQueuedEntries: 101
    reconnectWaitTime: 102
    taggedOnly: true
    asyncConnect: true
    logQueries: false
    logResponses: false
    logMappedFrom: true
)EOT";
  settings = pdns::rust::settings::rec::parse_yaml_string(yaml2);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].timeout, 100U);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].maxQueuedEntries, 101U);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].reconnectWaitTime, 102U);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].taggedOnly, true);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].asyncConnect, true);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].logQueries, false);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].logResponses, false);
  BOOST_CHECK_EQUAL(settings.logging.outgoing_protobuf_servers[0].logMappedFrom, true);
}

BOOST_AUTO_TEST_CASE(test_yaml_defaults_dnstap)
{
  // Two entries: one all default, one all overrides
  const std::string yaml1 = R"EOT(logging:
  dnstap_framestream_servers:
  - servers: [3.4.5.6]
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml1);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].logQueries, true);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].logResponses, true);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].bufferHint, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].flushTimeout, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].inputQueueSize, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].outputQueueSize, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].queueNotifyThreshold, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].reopenInterval, 0U);

  const std::string yaml2 = R"EOT(logging:
  dnstap_framestream_servers:
  - servers: ['[::2]:99']
    logQueries: false
    logResponses: false
    bufferHint: 1
    flushTimeout: 2
    inputQueueSize: 3
    outputQueueSize: 4
    queueNotifyThreshold: 5
    reopenInterval: 6
)EOT";
  settings = pdns::rust::settings::rec::parse_yaml_string(yaml2);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].logQueries, false);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].logResponses, false);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].bufferHint, 1U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].flushTimeout, 2U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].inputQueueSize, 3U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].outputQueueSize, 4U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].queueNotifyThreshold, 5U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_framestream_servers[0].reopenInterval, 6U);
}

BOOST_AUTO_TEST_CASE(test_yaml_defaults_dnstapnod)
{
  // Two entries: one all default, one all overrides
  const std::string yaml1 = R"EOT(logging:
  dnstap_nod_framestream_servers:
  - servers: [1.2.3.4:100]
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml1);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].logNODs, true);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].logUDRs, false);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].bufferHint, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].flushTimeout, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].inputQueueSize, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].outputQueueSize, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].queueNotifyThreshold, 0U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].reopenInterval, 0U);

  const std::string yaml2 = R"EOT(logging:
  dnstap_nod_framestream_servers:
  - servers: [1::1]
    logNODs: false
    logUDRs: true
    bufferHint: 1
    flushTimeout: 2
    inputQueueSize: 3
    outputQueueSize: 4
    queueNotifyThreshold: 5
    reopenInterval: 6
)EOT";
  settings = pdns::rust::settings::rec::parse_yaml_string(yaml2);
  settings.validate();
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].logNODs, false);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].logUDRs, true);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].bufferHint, 1U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].flushTimeout, 2U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].inputQueueSize, 3U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].outputQueueSize, 4U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].queueNotifyThreshold, 5U);
  BOOST_CHECK_EQUAL(settings.logging.dnstap_nod_framestream_servers[0].reopenInterval, 6U);
}

BOOST_AUTO_TEST_CASE(test_yaml_defaults_rpz)
{
  // Two entries: one all default, one all overrides
  const std::string yaml = R"EOT(recursor:
  rpzs:
  - name: file
  - name: zone
    addresses: [1.2.3.4]
  - name: nondef
    addresses: [1.2.3.4]
    defcontent: a
    defpol: b
    defpolOverrideLocalData: false
    defttl: 99
    extendedErrorCode: 100
    extendedErrorExtra: c
    includeSOA: true
    ignoreDuplicates: true
    maxTTL: 101
    policyName: c
    tags: [d,e]
    overridesGettag: false
    zoneSizeHint: 102
    tsig:
      name: f
      algo: g
      secret: ego=
    refresh: 103
    maxReceivedMBytes: 104
    localAddress: '1.2.3.4'
    axfrTimeout: 105
    dumpFile: j
    seedFile: k
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  settings.validate();

  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[0].name), "file");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[0].defcontent), "");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[0].defpol), "");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].defpolOverrideLocalData, true);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].defttl, -1U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].extendedErrorCode, -1U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].extendedErrorExtra, "");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].includeSOA, false);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].ignoreDuplicates, false);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].maxTTL, -1U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].tags.size(), 0U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].overridesGettag, true);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[0].zoneSizeHint, 0U);

  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].name), "zone");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].addresses[0]), "1.2.3.4");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].tsig.name), "");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].tsig.algo), "");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].tsig.secret), "");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[1].refresh, 0U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[1].maxReceivedMBytes, 0U);
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].localAddress), "");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[1].axfrTimeout, 20U);
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].dumpFile), "");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].seedFile), "");

  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].name), "nondef");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[1].addresses[0]), "1.2.3.4");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].defcontent), "a");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].defpol), "b");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].defpolOverrideLocalData, false);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].defttl, 99U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].extendedErrorCode, 100U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].extendedErrorExtra, "c");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].includeSOA, true);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].ignoreDuplicates, true);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].maxTTL, 101U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].tags.size(), 2U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].tags[0], "d");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].tags[1], "e");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].overridesGettag, false);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].zoneSizeHint, 102U);

  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].tsig.name), "f");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].tsig.algo), "g");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].tsig.secret), "ego=");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].refresh, 103U);
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].maxReceivedMBytes, 104U);
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].localAddress), "1.2.3.4");
  BOOST_CHECK_EQUAL(settings.recursor.rpzs[2].axfrTimeout, 105U);
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].dumpFile), "j");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.rpzs[2].seedFile), "k");
}

BOOST_AUTO_TEST_CASE(test_yaml_sortlist)
{
  const std::string yaml = R"EOT(recursor:
  sortlists:
    - key: 1.2.3.4/8
      subnets:
      - subnet: 5.6.7.8
        order: 99
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  settings.validate();
  BOOST_CHECK_EQUAL(std::string(settings.recursor.sortlists[0].key), "1.2.3.4/8");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.sortlists[0].subnets[0].subnet), "5.6.7.8");
  BOOST_CHECK_EQUAL(settings.recursor.sortlists[0].subnets[0].order, 99U);
}

BOOST_AUTO_TEST_CASE(test_yaml_ztc)
{
  const std::string yaml = R"EOT(recordcache:
    zonetocaches:
    - zone: zone
      method: axfr
      sources: [1.2.3.4]
    - zone: zone2
      method: axfr
      sources: ['[ffee::1]:99']
      timeout: 1
      tsig:
        name: a
        algo: b
        secret: a2FkanNrYWRqc2sK
      refreshPeriod: 2
      retryOnErrorPeriod: 3
      maxReceivedMBytes: 4
      localAddress: ::1
      zonemd: ignore
      dnssec: require
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  settings.validate();
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[0].zone), "zone");
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[0].method), "axfr");
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[0].sources[0]), "1.2.3.4");
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[0].timeout, 20U);
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[0].tsig.name), "");
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[0].tsig.algo), "");
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[0].tsig.secret), "");
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[0].refreshPeriod, 86400U);
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[0].retryOnErrorPeriod, 60U);
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[0].maxReceivedMBytes, 0U);
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[0].localAddress, "");
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[0].zonemd, "validate");
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[0].dnssec, "validate");

  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[1].zone), "zone2");
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[1].method), "axfr");
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[1].sources[0]), "[ffee::1]:99");
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[1].timeout, 1U);
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[1].tsig.name), "a");
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[1].tsig.algo), "b");
  BOOST_CHECK_EQUAL(std::string(settings.recordcache.zonetocaches[1].tsig.secret), "a2FkanNrYWRqc2sK");
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[1].refreshPeriod, 2U);
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[1].retryOnErrorPeriod, 3U);
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[1].maxReceivedMBytes, 4U);
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[1].localAddress, "::1");
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[1].zonemd, "ignore");
  BOOST_CHECK_EQUAL(settings.recordcache.zonetocaches[1].dnssec, "require");
}

BOOST_AUTO_TEST_CASE(test_yaml_additionals)
{
  const std::string yaml = R"EOT(recursor:
    allowed_additional_qtypes:
    - qtype: A
      targets: [A, MX, AAAA]
    - qtype: MX
      targets: [A]
      mode: CacheOnly
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  settings.validate();
  BOOST_CHECK_EQUAL(std::string(settings.recursor.allowed_additional_qtypes[0].qtype), "A");
  BOOST_CHECK_EQUAL(settings.recursor.allowed_additional_qtypes[0].targets.size(), 3U);
  BOOST_CHECK_EQUAL(std::string(settings.recursor.allowed_additional_qtypes[0].mode), "CacheOnlyRequireAuth");

  BOOST_CHECK_EQUAL(std::string(settings.recursor.allowed_additional_qtypes[1].qtype), "MX");
  BOOST_CHECK_EQUAL(settings.recursor.allowed_additional_qtypes[1].targets.size(), 1U);
  BOOST_CHECK_EQUAL(std::string(settings.recursor.allowed_additional_qtypes[1].mode), "CacheOnly");
}

BOOST_AUTO_TEST_CASE(test_yaml_proxymapping)
{
  const std::string yaml = R"EOT(incoming:
    proxymappings:
    - subnet: 1.2.3.4
      address: 4.5.6.7
    - subnet: 3.4.5.6
      address: 6.7.8.9
      domains: [a, b, c]
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  settings.validate();
  BOOST_CHECK_EQUAL(std::string(settings.incoming.proxymappings[0].subnet), "1.2.3.4");
  BOOST_CHECK_EQUAL(std::string(settings.incoming.proxymappings[0].address), "4.5.6.7");
  BOOST_CHECK_EQUAL(settings.incoming.proxymappings[0].domains.size(), 0U);

  BOOST_CHECK_EQUAL(std::string(settings.incoming.proxymappings[1].subnet), "3.4.5.6");
  BOOST_CHECK_EQUAL(std::string(settings.incoming.proxymappings[1].address), "6.7.8.9");
  BOOST_CHECK_EQUAL(settings.incoming.proxymappings[1].domains.size(), 3U);
}

BOOST_AUTO_TEST_CASE(test_yaml_forwardingcatalogzones)
{
  const std::string yaml = R"EOT(recursor:
  forwarding_catalog_zones:
  - zone: 'forward.invalid'
    xfr:
      addresses: [192.168.178.3:53]
    groups:
      - forwarders: [1.2.3.4]
      - name: mygroup
        forwarders: [4.5.6.7]
        recurse: true
        notify_allowed: true
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  settings.validate();
  BOOST_CHECK_EQUAL(std::string(settings.recursor.forwarding_catalog_zones[0].zone), "forward.invalid");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.forwarding_catalog_zones[0].xfr.addresses[0]), "192.168.178.3:53");
  BOOST_CHECK_EQUAL(settings.recursor.forwarding_catalog_zones[0].groups[0].forwarders.size(), 1U);
  BOOST_CHECK_EQUAL(std::string(settings.recursor.forwarding_catalog_zones[0].groups[0].forwarders[0]), "1.2.3.4");
  BOOST_CHECK_EQUAL(std::string(settings.recursor.forwarding_catalog_zones[0].groups[0].name), "");

  BOOST_CHECK_EQUAL(settings.recursor.forwarding_catalog_zones[0].groups[1].forwarders.size(), 1U);
  BOOST_CHECK_EQUAL(std::string(settings.recursor.forwarding_catalog_zones[0].groups[1].forwarders[0]), "4.5.6.7");
  BOOST_CHECK_EQUAL(settings.recursor.forwarding_catalog_zones[0].groups[1].recurse, true);
  BOOST_CHECK_EQUAL(settings.recursor.forwarding_catalog_zones[0].groups[1].notify_allowed, true);
}

BOOST_AUTO_TEST_CASE(test_yaml_to_luaconfigand_back)
{
  const std::string yaml = R"EOT(dnssec:
  trustanchors:
  - name: .
    dsrecords:
    - 10000 8 2 a06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d
  - name: aa.
    dsrecords:
    - 1234 8 2 a06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d
    - 4567 8 2 b06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d
  negative_trustanchors:
  - name: aa.
    reason: aaa
  - name: kwh.
    reason: why
  trustanchorfile: tmp/tas
  trustanchorfile_interval: 99
incoming:
  proxymappings:
  - subnet: 1.0.0.0/8
    address: 4.5.6.7
  - subnet: 3.4.5.6/32
    address: 6.7.8.9
    domains:
    - a.
    - b.
    - c.
recursor:
  sortlists:
  - key: 1.0.0.0/8
    subnets:
    - subnet: 5.6.7.8/32
      order: 99
  rpzs:
  - name: rpz.local
    addresses:
    - 192.168.178.3:53
    refresh: 10
    dumpFile: tmp/rpz.dump
    seedFile: tmp/rpz.dump
  - name: zzzz
    addresses:
    - '[::1]:99'
    defcontent: a
    defpol: Custom
    defpolOverrideLocalData: false
    defttl: 10
    extendedErrorCode: 11
    extendedErrorExtra: b
    includeSOA: true
    ignoreDuplicates: true
    maxTTL: 12
    policyName: c
    tags:
    - d
    - e
    overridesGettag: false
    zoneSizeHint: 13
  - name: tmp/file2.rpz
    ignoreDuplicates: true
  allowed_additional_qtypes:
  - qtype: A
    targets:
    - A
    - MX
    - AAAA
  - qtype: MX
    targets:
    - SRV
    - HTTPS
    mode: CacheOnly
logging:
  protobuf_servers:
  - servers:
    - 1.2.3.4:99
    timeout: 100
    maxQueuedEntries: 101
    reconnectWaitTime: 102
    taggedOnly: true
    asyncConnect: true
    logQueries: false
    logResponses: false
    exportTypes:
    - A
    - MX
    logMappedFrom: true
  outgoing_protobuf_servers:
  - servers:
    - 1.2.3.6:101
    timeout: 100
    maxQueuedEntries: 101
    reconnectWaitTime: 102
    taggedOnly: true
    asyncConnect: true
    logQueries: false
    exportTypes:
    - A
    - MX
    logMappedFrom: true
  dnstap_framestream_servers:
  - servers:
    - b
    logQueries: false
    logResponses: false
    bufferHint: 1
    flushTimeout: 2
    inputQueueSize: 3
    outputQueueSize: 4
    queueNotifyThreshold: 5
    reopenInterval: 6
  dnstap_nod_framestream_servers:
  - servers:
    - c
    logNODs: false
    logUDRs: true
    bufferHint: 1
    flushTimeout: 2
    inputQueueSize: 3
    outputQueueSize: 4
    queueNotifyThreshold: 5
    reopenInterval: 6
recordcache:
  zonetocaches:
  - zone: zone
    method: url
    sources:
    - https://www.example.com
  - zone: anotherzone
    method: axfr
    sources:
    - '[::1]:999'
    timeout: 1
    tsig:
      name: a.
      algo: b.
      secret: aGVsbG8hCg==
    refreshPeriod: 2
    retryOnErrorPeriod: 3
    maxReceivedMBytes: 4
    localAddress: 'ffff::'
    zonemd: ignore
    dnssec: require
)EOT";
  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  settings.validate();

  // create a Lua config based on YAML
  LuaConfigItems luaConfig;
  ProxyMapping proxyMapping;
  pdns::settings::rec::fromBridgeStructToLuaConfig(settings, luaConfig, proxyMapping);

  // Create YAML, given a Lua config
  auto newsettings = pdns::rust::settings::rec::parse_yaml_string("");
  try {
    pdns::settings::rec::fromLuaConfigToBridgeStruct(luaConfig, proxyMapping, newsettings);
  }
  catch (std::exception& e) {
    cerr << e.what() << endl;
    BOOST_CHECK(false);
  }
  // They should be the same
  auto newyaml = newsettings.to_yaml_string();

#if 0
  std::ofstream aaa("a");
  std::ofstream bbb("b");
  aaa << "===" << endl
      << yaml << endl
      << "===" << endl;
  bbb << "===" << endl
      << newyaml << endl
      << "===" << endl;
#endif

  BOOST_CHECK_EQUAL(yaml, std::string(newyaml));
}

BOOST_AUTO_TEST_SUITE_END()
