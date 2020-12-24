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
#include "configuration.hh"

namespace pdns
{
namespace config
{
  /// @brief This holds the configuration of the progam instance.
  static Config g_config;

  void parseConfigFile(const std::string& fname) {
      auto parsed = YAML::LoadFile(fname);
      g_config.setConfig(parsed);
  }

  void setConfig(const YAML::Node &n) {
      g_config.setConfig(n);
  }

  void registerOption(const std::string& name, const configInfoFuncs &cb) {
    g_config.registerConfig(name, cb);
  };

  YAML::Node getConfig(const std::string &name) {
      return g_config.getConfig(name);
  }

  YAML::Node getDefault(const std::string &name) {
    return g_config.getDefault(name);
  }

  std::string dumpDefault(const std::string &name) {
    YAML::Emitter e;
    e<<YAML::Comment(g_config.getHelp(name))
      << YAML::BeginMap
      << YAML::Key << name
      << YAML::Value << g_config.getDefault(name);
    return e.c_str();
  }

  std::string dumpDefaults() {
    auto regd = g_config.getRegisteredItems();
    std::string ret;
    for (auto const reg : regd) {
      ret += dumpDefault(reg);
      ret += '\n';
      ret += '\n';
    }
    return ret;
  }

  std::string dumpConfig(const std::string &name) {
    YAML::Emitter e;
    e<<YAML::Comment(g_config.getHelp(name))
      << YAML::BeginMap
      << YAML::Key << name
      << YAML::Value << g_config.getConfig(name);
    return e.c_str();
  }

  void Config::registerConfig(const std::string& name, const configInfoFuncs &cb)
  {
      if (d_initialConfigLoaded) {
          throw std::runtime_error("Registration for configuration elements is closed. '" + name + "' can not be registered.");
      }
      if (d_roConfig->d_registered.find(name) != d_roConfig->d_registered.end()) {
          throw std::runtime_error(name + " is already registered");
      }
      if (cb.check == nullptr) {
        throw std::runtime_error("'check' function not defined in callback for '" + name + "'");
      }
      if (cb.apply == nullptr) {
        throw std::runtime_error("'apply' function not defined in callback for '" + name + "'");
      }
      if (cb.defaults == nullptr) {
        throw std::runtime_error("'defaults' function not defined in callback for '" + name + "'");
      }
      if (cb.current == nullptr) {
        throw std::runtime_error("'current' function not defined in callback for '" + name + "'");
      }
      auto cfg = d_config.getCopy();
      cfg.d_registered[name] = cb;
      d_config.setState(cfg);
  }

  void Config::setConfig(const YAML::Node& newConfig)
  {
    if (!newConfig.IsMap()) {
      throw std::runtime_error("newConfig is not a map!");
    }
    auto nit = newConfig.begin();
    while (nit != newConfig.end()) {
      auto opt = nit->first.as<std::string>();
      auto registeredOpt = d_roConfig->d_registered.find(opt);
      if (registeredOpt == d_roConfig->d_registered.end()) {
        // TODO add option to ignore unknown options?
        throw std::runtime_error("Configuration option '" + opt + "' is not known");
      }
      registeredOpt->second.check(nit->second, !d_initialConfigLoaded);
      nit++;
    }

    // We made it! So the config must be good
    // Now apply it all
    nit = newConfig.begin();
    while (nit != newConfig.end()) {
      auto opt = nit->first.as<std::string>();
      auto registeredOpt = d_roConfig->d_registered.find(opt);
      if (registeredOpt == d_roConfig->d_registered.end()) {
        // This should never happen, we bail in the previous loop
        throw std::runtime_error("Configuration option '" + opt + "' is not known");
      }
      registeredOpt->second.apply(nit->second, !d_initialConfigLoaded);
      nit++;
    }
    d_initialConfigLoaded = true;
  }

  bool isRegistered(const std::string &name) {
    try {
      g_config.getHelp(name);
      return true;
    } catch (...) {}
    return false;
  }

  YAML::Node Config::getConfig(const std::string& name)
  {
    if (!d_initialConfigLoaded) {
      // TODO should we return the defaults in this case?
      throw std::runtime_error("No configuration loaded");
    }
    return getRegistered(name)->second.current();
  }

  Config::registered_const_iterator Config::getRegistered(const std::string &name) {
    const auto it = d_roConfig->d_registered.find(name);
    if (it == d_roConfig->d_registered.cend()) {
      throw std::runtime_error("'" + name + "', it is not registered");
    }
    return it;
  }

  std::vector<std::string> Config::getRegisteredItems() {
    std::vector<std::string> ret;
    for (auto const &reg : d_roConfig->d_registered) {
      ret.push_back(reg.first);
    }
    return ret;
  }

  YAML::Node Config::getDefault(const std::string& name) {
    return getRegistered(name)->second.defaults();
  }

  std::string Config::getHelp(const std::string& name) {
    return getRegistered(name)->second.help;
  }

} // namespace config
} // namespace pdns
