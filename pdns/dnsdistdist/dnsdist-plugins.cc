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
#include "dnsdist-plugins.hh"
#include "dnsdist-configuration.hh"

namespace dnsdist::plugins
{
std::optional<Error> registerNewPlugin(const std::string& name, const PluginDescription& description)
{
  try {
    dnsdist::configuration::updateImmutableConfiguration([name, description](dnsdist::configuration::ImmutableConfiguration& immutable) {
      auto& entry = immutable.d_plugins[name];
      if (entry.d_handle != nullptr) {
        throw std::runtime_error("Trying to register a plugin named " + name + " that has already been registered");
      }
      entry.d_description = description;
    });
  }
  catch (const std::exception& exp) {
    return exp.what();
  }
  return std::nullopt;
}

std::optional<Error> loadPlugin(const std::string& path, const std::string& pluginName)
{
  if (dnsdist::configuration::isImmutableConfigurationDone()) {
    return "Attempting to load a plugin after the configuration phase";
  }

  auto libraryPath = path + pluginName + ".so";
  PluginLibraryHandle handle(dlopen(libraryPath.c_str(), RTLD_NOW | RTLD_LOCAL), dlclose);
  if (!handle) {
    // NOLINTNEXTLINE(concurrency-mt-unsafe): only called from the main thread
    return dlerror();
  }

  try {
    dnsdist::configuration::updateImmutableConfiguration([&pluginName, &handle](dnsdist::configuration::ImmutableConfiguration& immutable) {
      immutable.d_plugins[pluginName].d_handle = std::move(handle);
    });
  }
  catch (const std::exception& exp) {
    return exp.what();
  }
  return std::nullopt;
}

}
