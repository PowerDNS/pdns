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

#if defined(HAVE_YAML_CONFIGURATION)

#include <fstream>

#include "dolog.hh"
#include "dnsdist-rules.hh"
#include "rust/cxx.h"
#include "rust/lib.rs.h"
#endif /* HAVE_YAML_CONFIGURATION */

namespace dnsdist::configuration::yaml
{
#if defined(HAVE_YAML_CONFIGURATION)
// static std::shared_ptr<DNSRule> getSelector(const dnsdist::rust::settings::TestSelector selector)
// {
//   if (selector.selector_type == "All") {
//     return std::make_shared<AllRule>();
//   }
//   if (selector.selector_type == "TCP") {
//     return std::make_shared<TCPRule>(selector.tcp.tcp);
//   }
//   throw std::runtime_error("Unsupported selector type: " + std::string(selector.selector_type));
// }
#endif /* HAVE_YAML_CONFIGURATION */

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
    // for (const auto& rule : globalConfig.response_rules) {
    //   cerr<<"Name: "<<rule.name<<", type "<<rule.selector.selector_type<<endl;
    //   for (const auto& selector : rule.selector.selectors) {
    //     cerr<<selector.name<<" -> "<<selector.selector_type<<endl;
    //     for (const auto& extra : selector.extra) {
    //       cerr<<" - "<<extra.key<<" => "<<extra.value<<endl;
    //     }
    //   }
    //   for (const auto& extra : rule.extra) {
    //     cerr<<extra.key<<" => "<<extra.value<<endl;
    //   }
    // }
    // for (const auto& selector : globalConfig.testselectors) {
    //   cerr<<"Selector: "<<selector.selector_type<<endl;
    //   auto got = getSelector(selector);
    //   cerr<<"Got: "<<got->toString()<<endl;
    //   for (const auto& sub : selector.andSel.selectors) {
    //     cerr<<"  "<<sub<<endl;
    //   }
    // }
    for (const auto& selector : globalConfig.realselectors) {
      cerr<<"REAL Selector: "<<selector.selector->d_rule->toString()<<endl;
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
  cerr<<"Unsupported YAML configuration"<<endl;
  return false;
#endif /* HAVE_YAML_CONFIGURATION */
}
}

#if defined(HAVE_YAML_CONFIGURATION)
namespace dnsdist::rust::settings
{

static LockGuarded<std::unordered_map<std::string, std::shared_ptr<DNSSelector>>> s_selectorsMap;

static void registerSelector(const std::shared_ptr<DNSSelector>& selector, std::string& name)
{
  if (name.empty()) {
    auto uuid = getUniqueID();
    name = boost::uuids::to_string(uuid);
  }

  auto [it, inserted] = s_selectorsMap.lock()->try_emplace(name, selector);
  if (!inserted) {
    throw std::runtime_error("Trying to register a selector named '" + name + "' while one already exists");
  }
}

static std::shared_ptr<DNSSelector> getSelectorByName(const std::string& name)
{
  auto map = s_selectorsMap.lock();
  auto item = map->find(name);
  if (item == map->end()) {
      return nullptr;
  }
  return item->second;
}

std::shared_ptr<DNSSelector> getSelectorByName(const ::rust::string& name)
{
  auto nameStr = std::string(name);
  return getSelectorByName(nameStr);
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
  registerSelector(selector, selector->d_name);
  return selector;
}

std::shared_ptr<DNSSelector> getMaxIPQPSSelector(const MaxQPSIPRuleConfig& config)
{
  auto rule = std::shared_ptr<DNSRule>(new MaxQPSIPRule(config.qps, config.burst, config.ipv4trunc, 64, 300, 60, 10, 10));
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
    auto dnsSelector = getSelectorByName(std::string(selector));
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

std::shared_ptr<DNSSelector> getNetmaskGroupSelector(const NetmaskGroupByNetmasksSelectorConfig& config)
{
    NetmaskGroup nmg;
    for (const auto& netmask : config.netmasks) {
        nmg.addMask(std::string(netmask));
    }
    auto rule = std::shared_ptr<DNSRule>(new NetmaskGroupRule(nmg, config.source, config.quiet));
    return newDNSSelector(std::move(rule), config.name);
}

}
#endif /* defined(HAVE_YAML_CONFIGURATION) */
