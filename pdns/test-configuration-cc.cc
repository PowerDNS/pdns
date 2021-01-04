#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "configuration.hh"
#include "iputils.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_configuration_cc)

BOOST_AUTO_TEST_CASE(test_simple)
{
  std::string optName("my-option");
  std::string optVal("foobar");
  std::string help(R"(I am a very
useful help)");
  std::string setOptVal;
  pdns::config::configInfoFuncs cb;

  pdns::config::resetRegisteredItems();

  BOOST_CHECK_THROW(pdns::config::registerOption(optName, cb), std::runtime_error);

  cb.check =
    [optVal](const YAML::Node& n, const bool initial) {
      if (initial) {
        BOOST_CHECK_EQUAL(n.as<std::string>(), optVal);
      }
      else {
        BOOST_CHECK(n.as<std::string>() != optVal);
        throw std::runtime_error("Not accepted");
      }
    };
  BOOST_CHECK_THROW(pdns::config::registerOption(optName, cb), std::runtime_error);

  cb.apply =
    [&setOptVal](const YAML::Node& n, const bool initial) {
      setOptVal = n.as<std::string>();
    };
  BOOST_CHECK_THROW(pdns::config::registerOption(optName, cb), std::runtime_error);

  cb.defaults =
    [optVal]() {
      return YAML::Node(optVal);
    };
  BOOST_CHECK_THROW(pdns::config::registerOption(optName, cb), std::runtime_error);

  cb.current =
    [&setOptVal]() {
      return YAML::Load(setOptVal);
    };

  cb.help = help;

  // Registration should succeed now
  BOOST_CHECK_NO_THROW(pdns::config::registerOption(optName, cb));
  BOOST_CHECK(pdns::config::isRegistered(optName));

  // Check if we throw if the name is already registred
  BOOST_CHECK_THROW(pdns::config::registerOption(optName, cb), std::runtime_error);

  YAML::Node config;

  // Initial apply
  config[optName] = optVal;
  pdns::config::setConfig(config);
  auto retNode = pdns::config::getConfig(optName);
  BOOST_ASSERT(retNode.IsScalar());
  BOOST_CHECK_EQUAL(retNode.as<std::string>(), optVal);

  // not an initial apply
  config[optName] = optVal + "bla";
  BOOST_CHECK_THROW(pdns::config::setConfig(config), std::runtime_error);

  // Should return the initial value
  auto retNode2 = pdns::config::getConfig(optName);
  BOOST_ASSERT(retNode2.IsScalar());
  BOOST_CHECK_EQUAL(retNode2.as<std::string>(), optVal);

  auto defaults = pdns::config::dumpDefault(optName);
  BOOST_CHECK_EQUAL(defaults, R"(# I am a very
# useful help
my-option: foobar)");
}

BOOST_AUTO_TEST_CASE(typed_config_option_bool) {
  std::string optName("my-option");
  std::string help(R"(I am a very
useful help)");

  // Let's do a bool first
  pdns::config::resetRegisteredItems();
  auto boolOpt = std::make_shared<bool>(true);
  BOOST_CHECK_NO_THROW(pdns::config::registerOption<bool>(optName, true, help, boolOpt));
  BOOST_CHECK_THROW(pdns::config::registerOption<bool>(optName, true, help, boolOpt), std::runtime_error);

  BOOST_CHECK_EQUAL(pdns::config::getDefault<bool>(optName), true);

  YAML::Node config;
  config[optName] = false;

  BOOST_CHECK_NO_THROW(pdns::config::setConfig(config));
  BOOST_CHECK_EQUAL(pdns::config::getDefault<bool>(optName), true);
  BOOST_CHECK_EQUAL(pdns::config::getConfig<bool>(optName), false);
  BOOST_CHECK_EQUAL(*boolOpt, false);

  // We are runtime update-able
  config[optName] = true;
  BOOST_CHECK_NO_THROW(pdns::config::setConfig(config));
  BOOST_CHECK_EQUAL(pdns::config::getDefault<bool>(optName), true);
  BOOST_CHECK_EQUAL(pdns::config::getConfig<bool>(optName), true);
  BOOST_CHECK_EQUAL(*boolOpt, true);
}

BOOST_AUTO_TEST_CASE(typed_config_option_bool_no_runtime) {
  std::string optName("my-option");
  std::string help(R"(I am a very
useful help)");

  pdns::config::resetRegisteredItems();
  auto boolOpt = std::make_shared<bool>(true);
  BOOST_CHECK_NO_THROW(pdns::config::registerOption<bool>(optName, false, help, boolOpt));
  BOOST_CHECK_THROW(pdns::config::registerOption<bool>(optName, true, help, boolOpt), std::runtime_error);

  BOOST_CHECK_EQUAL(pdns::config::getDefault<bool>(optName), true);

  YAML::Node config;
  config[optName] = false;

  BOOST_CHECK_NO_THROW(pdns::config::setConfig(config));
  BOOST_CHECK_EQUAL(pdns::config::getDefault<bool>(optName), true);
  BOOST_CHECK_EQUAL(pdns::config::getConfig<bool>(optName), false);
  BOOST_CHECK_EQUAL(*boolOpt, false);

  // We are not runtime update-able, but the value is unchanged
  config[optName] = false;
  BOOST_CHECK_NO_THROW(pdns::config::setConfig(config));
  BOOST_CHECK_EQUAL(pdns::config::getDefault<bool>(optName), true);
  BOOST_CHECK_EQUAL(pdns::config::getConfig<bool>(optName), false);
  BOOST_CHECK_EQUAL(*boolOpt, false);

  // We are not runtime update-able, but the value is changed
  config[optName] = true;
  BOOST_CHECK_THROW(pdns::config::setConfig(config), std::runtime_error);
  BOOST_CHECK_EQUAL(pdns::config::getDefault<bool>(optName), true);
  BOOST_CHECK_EQUAL(pdns::config::getConfig<bool>(optName), false);
  BOOST_CHECK_EQUAL(*boolOpt, false);
}

BOOST_AUTO_TEST_CASE(typed_config_CA) {
  std::string optName("my-option");
  std::string help(R"(I am a very
useful help)");

  pdns::config::resetRegisteredItems();
  auto address = std::make_shared<ComboAddress>("127.0.0.1");

  BOOST_CHECK_NO_THROW(pdns::config::registerOption<ComboAddress>(optName, true, help, address));
  BOOST_CHECK_THROW(pdns::config::registerOption<ComboAddress>(optName, true, help, address), std::runtime_error);

  BOOST_CHECK(pdns::config::getDefault<ComboAddress>(optName) == ComboAddress("127.0.0.1:53"));

  YAML::Node config;
  config[optName] = ComboAddress("127.0.0.53");
  ComboAddress expected("127.0.0.53:53");

  BOOST_CHECK_NO_THROW(pdns::config::setConfig(config));
  BOOST_CHECK(pdns::config::getDefault<ComboAddress>(optName) == ComboAddress("127.0.0.1:53"));
  BOOST_CHECK(pdns::config::getConfig<ComboAddress>(optName) == expected);
  BOOST_CHECK(*address == expected);

  // We are runtime update-able
  config[optName] = ComboAddress("127.0.0.54");
  expected = ComboAddress("127.0.0.54:53");
  BOOST_CHECK_NO_THROW(pdns::config::setConfig(config));
  BOOST_CHECK(pdns::config::getDefault<ComboAddress>(optName) == ComboAddress("127.0.0.1:53"));
  BOOST_CHECK(pdns::config::getConfig<ComboAddress>(optName) == expected);
  BOOST_CHECK(*address == expected);
}

BOOST_AUTO_TEST_CASE(typed_config_list_of_CAs) {
  std::string optName("my-option");
  std::string help(R"(I am a very
useful help)");

  pdns::config::resetRegisteredItems();
  auto addresses = std::make_shared<vector<ComboAddress>>();
  addresses->push_back(ComboAddress("127.0.0.1"));
  addresses->push_back(ComboAddress("::1"));

  vector<ComboAddress> expectedDefaults;
  expectedDefaults.push_back(ComboAddress("127.0.0.1:53"));
  expectedDefaults.push_back(ComboAddress("[::1]:53"));

  BOOST_CHECK_NO_THROW(pdns::config::registerOption<vector<ComboAddress>>(optName, true, help, addresses));
  BOOST_CHECK_THROW(pdns::config::registerOption<vector<ComboAddress>>(optName, true, help, addresses), std::runtime_error);

  BOOST_CHECK(pdns::config::getDefault<vector<ComboAddress>>(optName) == expectedDefaults);
  
  YAML::Node config;
  config[optName].push_back("127.0.0.53");
  auto expected = vector<ComboAddress>({ComboAddress("127.0.0.53:53")});

  BOOST_CHECK_NO_THROW(pdns::config::setConfig(config));
  BOOST_CHECK(pdns::config::getDefault<vector<ComboAddress>>(optName) == expectedDefaults);
  BOOST_CHECK(pdns::config::getConfig<vector<ComboAddress>>(optName) == expected);
  BOOST_CHECK(*addresses == expected);

  // We are runtime update-able
  config[optName] = vector<std::string>();
  config[optName].push_back("127.0.0.54");
  expected = vector<ComboAddress>({ComboAddress("127.0.0.54:53")});
  BOOST_CHECK_NO_THROW(pdns::config::setConfig(config));
  BOOST_CHECK(pdns::config::getDefault<vector<ComboAddress>>(optName) == expectedDefaults);
  BOOST_CHECK(pdns::config::getConfig<vector<ComboAddress>>(optName) == expected);
  BOOST_CHECK(*addresses == expected);
}
BOOST_AUTO_TEST_SUITE_END()