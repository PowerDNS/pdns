#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#include <boost/test/unit_test.hpp>

#include <memory>
#include <boost/algorithm/string/trim.hpp>
#include <boost/format.hpp>

#include "settings/cxxsettings.hh"

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
    settings.validate();
  },
                    rust::Error);
}

BOOST_AUTO_TEST_CASE(test_rust_validation_with_error2)
{
  const std::string yaml = R"EOT(
recursor:
  forward_zones:
    - zone: "example.com"
      forwarders:
        - 1.2.3.4
        - a.b
)EOT";

  auto settings = pdns::rust::settings::rec::parse_yaml_string(yaml);
  auto back = settings.to_yaml_string();
  BOOST_CHECK_THROW({
    settings.validate();
  },
                    rust::Error);
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
    settings.validate();
  },
                    rust::Error);
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
    settings.validate();
  },
                    rust::Error);
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
      settings.validate();
    },
                      rust::Error);
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
  auto filePtr = std::unique_ptr<FILE, decltype(&fclose)>(fdopen(fileDesc, "w"), fclose);
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

BOOST_AUTO_TEST_SUITE_END()
