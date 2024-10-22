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

#include "dnsdist-configuration-yaml.hh"
#include "iputils.hh"
#include "remote_logger.hh"

#if defined(HAVE_YAML_CONFIGURATION)

#include "dolog.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-kvs.hh"
#include "rust/cxx.h"
#include "rust/lib.rs.h"
#endif /* HAVE_YAML_CONFIGURATION */

namespace dnsdist::configuration::yaml
{

bool loadConfigurationFromFile(const std::string fileName)
{
#if defined(HAVE_YAML_CONFIGURATION)
  auto file = std::ifstream(fileName);
  if (!file.is_open()) {
    errlog("Unable to open YAML file %s: %s", fileName, stringerror(errno));
    return false;
  }

  try {
    auto data = std::string(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

    auto globalConfig = dnsdist::rust::settings::from_yaml_string(data);
    cerr<<globalConfig.metrics.carbon[0].address<<endl;
    for (const auto& selector : globalConfig.selectors) {
      cerr << "Selector: " << selector.selector->d_rule->toString() << endl;
    }
    return true;
  }
  catch (const ::rust::Error& exp) {
    errlog("Rust error while opening YAML file %s: %s", fileName, exp.what());
  }
  catch (const std::exception& exp) {
    errlog("C++ error while opening YAML file %s: %s", fileName, exp.what());
  }
  return false;
#else
  (void)fileName;
  cerr << "Unsupported YAML configuration" << endl;
  return false;
#endif /* HAVE_YAML_CONFIGURATION */
}
}

#if defined(HAVE_YAML_CONFIGURATION)
namespace dnsdist::rust::settings
{

using RegisteredTypes = std::variant<std::shared_ptr<DNSSelector>, std::shared_ptr<NetmaskGroup>, std::shared_ptr<KeyValueStore>, std::shared_ptr<KeyValueLookupKey>, std::shared_ptr<RemoteLoggerInterface>>;
static LockGuarded<std::unordered_map<std::string, RegisteredTypes>> s_registeredTypesMap;

template <class T>
static void registerType(const std::shared_ptr<T>& entry, std::string& name)
{
  if (name.empty()) {
    auto uuid = getUniqueID();
    name = boost::uuids::to_string(uuid);
  }

  auto [it, inserted] = s_registeredTypesMap.lock()->try_emplace(name, entry);
  if (!inserted) {
    throw std::runtime_error("Trying to register a type named '" + name + "' while one already exists");
  }
}

template <class T>
static std::shared_ptr<T> getRegisteredTypeByName(const std::string& name)
{
  auto map = s_registeredTypesMap.lock();
  auto item = map->find(name);
  if (item == map->end()) {
    return nullptr;
  }
  if (auto* ptr = std::get_if<std::shared_ptr<T>>(&item->second)) {
    return *ptr;
  }
  return nullptr;
}

template <class T>
static std::shared_ptr<T> getRegisteredTypeByName(const ::rust::String& name)
{
    auto nameStr = std::string(name);
    return getRegisteredTypeByName<T>(nameStr);
}

std::shared_ptr<DNSSelector> getSelectorByName(const ::rust::String& name)
{
    return getRegisteredTypeByName<DNSSelector>(name);
}

const std::string& getNameFromSelector(const DNSSelector& selector)
{
  return selector.d_name;
}

static std::shared_ptr<DNSSelector> newDNSSelector(std::shared_ptr<DNSRule>&& rule, const ::rust::String& name)
{
  auto selector = std::make_shared<DNSSelector>();
  selector->d_name = std::string(name);
  selector->d_rule = std::move(rule);
  registerType(selector, selector->d_name);
  return selector;
}

std::shared_ptr<DNSSelector> getMaxIPQPSSelector(const MaxQPSIPRuleConfiguration& config)
{
  auto rule = std::shared_ptr<DNSRule>(new MaxQPSIPRule(config.qps, config.burst, config.ipv4_mask, config.ipv6_mask, config.expiration, config.cleanup_delay, config.scan_fraction, config.shards));
  return newDNSSelector(std::move(rule), config.name);
}

std::shared_ptr<DNSSelector> getAllSelector()
{
  auto rule = std::shared_ptr<DNSRule>(new AllRule());
  return newDNSSelector(std::move(rule), "");
}

std::shared_ptr<DNSSelector> getAndSelector(const AndSelectorConfig& config)
{
  LuaArray<std::shared_ptr<DNSRule>> selectors;
  int counter = 1;
  for (const auto& selector : config.selectors) {
    auto dnsSelector = getRegisteredTypeByName<DNSSelector>(std::string(selector));
    if (dnsSelector) {
      selectors.push_back({counter++, dnsSelector->d_rule});
    }
  }
  auto rule = std::shared_ptr<DNSRule>(new AndRule(selectors));
  return newDNSSelector(std::move(rule), config.name);
}

std::shared_ptr<DNSSelector> getTCPSelector(const TCPSelectorConfig& config)
{
  auto rule = std::shared_ptr<DNSRule>(new TCPRule(config.tcp));
  return newDNSSelector(std::move(rule), config.name);
}

std::shared_ptr<DNSSelector> getNetmaskGroupSelector(const NetmaskGroupSelectorConfig& config)
{
  std::shared_ptr<NetmaskGroup> nmg;
  if (!config.netmask_group.empty()) {
    nmg = getRegisteredTypeByName<NetmaskGroup>(std::string(config.netmask_group));
  }
  if (!nmg) {
    nmg = std::make_shared<NetmaskGroup>();
  }
  for (const auto& netmask : config.netmasks) {
    nmg->addMask(std::string(netmask));
  }
  auto rule = std::shared_ptr<DNSRule>(new NetmaskGroupRule(*nmg, config.source, config.quiet));
  return newDNSSelector(std::move(rule), config.name);
}

}
#endif /* defined(HAVE_YAML_CONFIGURATION) */
