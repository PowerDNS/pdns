#include <iostream>

#include "dnsdist-plugins.hh"

static std::optional<dnsdist::plugins::Error> configurationDone()
{
  std::cerr << __PRETTY_FUNCTION__ << std::endl;
  return std::nullopt;
}

static void regularMaintenance()
{
  std::cerr << __PRETTY_FUNCTION__ << std::endl;
}

static void unloading()
{
  std::cerr << __PRETTY_FUNCTION__ << std::endl;
}

struct DemoPlugin
{
  DemoPlugin() noexcept
  {
    const dnsdist::plugins::PluginDescription demoPluginDescription{
      .d_configurationDone = configurationDone,
      .d_maintenance = regularMaintenance,
      .d_destroy = unloading,
    };
    auto error = dnsdist::plugins::registerNewPlugin("demo", demoPluginDescription);
    if (error.has_value()) {
      std::cerr<<"Error registering the demo plugin: "<<error.value()<<std::endl;
    }
  }
};

static const DemoPlugin s_plugin;
