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
#include <yaml-cpp/yaml.h>
#include <string>
#include <functional>
#include <map>
#include "sholder.hh"

namespace pdns
{
namespace config
{
  /**
   * @brief This function is called to check a new configuration for a registered item
   * 
   * The called function MUST throw an std::runtime_error when the provided new
   * configuration is not apply-able. This function MUST NOT have any side effects
   * when calles.
   * 
   * The boolean argument indicates whether a config has been applied already:
   *   true: This is an initial configuration
   *   false: This is an updated configuration
   */
  typedef std::function<void(const YAML::Node&, const bool)> f_check;

  /**
   * @brief This function is called to apply a new configuration for a registered item
   * 
   * The boolean argument indicates whether a config has been applied already:
   *   true: This is an initial configuration
   *   false: This is an updated configuration
   */
  typedef std::function<void(const YAML::Node&, const bool) noexcept> f_apply;

  /**
   * @brief This function is called to retrieve the defaults
   * 
   * This function should return the *value* of its configuration deafult
   */
  typedef std::function<YAML::Node() noexcept> f_defaults;

  /**
   * @brief This function is called to retrieve the current config
   * 
   * This function should return the *value* of its configuration item
   */
  typedef std::function<YAML::Node() noexcept> f_current;

  typedef struct {
    f_check check;
    f_defaults defaults;
    f_apply apply;
    f_current current;
    std::string help;
  } configInfoFuncs;

  /**
  * @brief Register a new configuration item
  * 
  * Configuration items MUST be registered before configuration is loaded.
  * After loading configuration (via e.g. parseConfigFile or setConfig), registration
  * for new configuration is closed.
  * 
  * @param name 
  * @param cb 
  * @throws std::runtime_error when |name| is already registered, a mandatory
  *         function is missing in |cb| or configuration is loaded.
  */
  void registerOption(const std::string& name, const configInfoFuncs &cb);

  /**
   * @brief Parse the YAML file at |fname|
   * 
   * @param fname 
   * @throws YAML::ParserException if the file at |fname| is malformed
   * @throws YAML::BadFile when the file cannot be loaded
   * @throws std::runtime_error when check() fails for a config item
   */
  void parseConfigFile(const std::string& fname);

  /**
   * @brief Set the configuration to |n|
   * 
   * This calls the check function for all registered config items.
   * When the checks are successful, apply is called
   * 
   * @param n 
   * @throws std::runtime_error when check() fails for a config item
   */
  void setConfig(const YAML::Node &n);

  /**
   * @brief Get the node for a registered part of the config
   * 
   * @param name 
   * @return YAML::Node 
   * @throws std::runtime_error when |name| is not registered
   */
  YAML::Node getConfig(const std::string &name);
  /**
   * @brief Returns the current configuration as a YAML string, including the help
   * 
   * @param name 
   * @return std::string 
   * @throws std::runtime_error when |name| is not registered
   */
  std::string dumpConfig(const std::string &name);

  /**
   * @brief Returns the YAML node describing the default config for |name|
   * 
   * @param name 
   * @return YAML::Node 
   * @throws std::runtime_error when |name| is not registered
   */
  YAML::Node getDefault(const std::string &name);

  /**
   * @brief Returns the default configuration for |name| as a YAML string
   * 
   * @param name 
   * @return std::string 
   * @throws std::runtime_error when |name| is not registered
   */
  std::string dumpDefault(const std::string &name);

  /**
   * @brief Returns the full default configuration for as a YAML string
   * 
   * @param name 
   * @return std::string 
   */
  std::string dumpDefaults();

  /**
   * @brief Returns whether or not |name| is registered
   * 
   * @param name 
   * @return true 
   * @return false 
   */
  bool isRegistered(const std::string &name);

  /**
   * @brief This class holds a configuration instance
   * 
   * This class shouldn't be used directly, the pdns::config namespace
   * has functions to manipulate and query the global configuration instance.
   * 
   */
  class Config
  {
  public:
    /**
     * @brief Register a configuration node
     * 
     * @param name  Name of the node in the top-level of the config
     * @param cb    The callbacks to register
     */
    void registerConfig(const std::string& name, const configInfoFuncs &cb);

    /**
     * @brief Set new configuration state
     * 
     * Calls all check functions for registered items
     * 
     * @param newConfig 
     */
    void setConfig(const YAML::Node& newConfig);

    /**
     * @brief Retrieve the configuration node for |name|
     * 
     * @param name 
     * @return YAML::Node 
     */
    YAML::Node getConfig(const std::string& name);

    /**
     * @brief Retrieve the default configuration node for |name|
     * 
     * @param name 
     * @return YAML::Node 
     */
    YAML::Node getDefault(const std::string& name);

    /**
     * @brief Retrieve the stored help for |name|
     * 
     * @param name 
     * @return std::string 
     */
    std::string getHelp(const std::string& name);

    /**
     * @brief Get the names of all registered config
     * 
     * @return std::vector<std::string> 
     */
    std::vector<std::string> getRegisteredItems();

  private:
    class configHolder {
      public:
      /**
       * @brief The current config applied
       */
      std::map<std::string, configInfoFuncs> d_registered;
    };
    GlobalStateHolder<configHolder> d_config;
    LocalStateHolder<configHolder> d_roConfig{d_config.getLocal()};
    /// @brief wheter we still accept new registrations, true also indicates we have set an initial config
    bool d_initialConfigLoaded{false};

    typedef std::map<std::string, pdns::config::configInfoFuncs>::const_iterator registered_const_iterator;
    registered_const_iterator getRegistered(const std::string &name);
  }; // class Config

} // namespace config
} // namespace pdns
