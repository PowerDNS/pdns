#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include "configuration.hh"

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

BOOST_AUTO_TEST_SUITE_END()