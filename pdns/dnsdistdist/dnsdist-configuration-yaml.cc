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
    for (const auto& rule : globalConfig.response_rules) {
      cerr<<"Name: "<<rule.name<<", type "<<rule.selector.selector_type<<endl;
      for (const auto& selector : rule.selector.selectors) {
        cerr<<selector.name<<" -> "<<selector.selector_type<<endl;
        for (const auto& extra : selector.extra) {
          cerr<<" - "<<extra.key<<" => "<<extra.value<<endl;
        }
      }
      for (const auto& extra : rule.extra) {
        cerr<<extra.key<<" => "<<extra.value<<endl;
      }
    }
    for (const auto& selector : globalConfig.testselectors) {
      cerr<<"Selector: "<<selector.selector_type<<endl;
      for (const auto& sub : selector.andSel.selectors) {
        cerr<<"  "<<sub<<endl;
      }
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
