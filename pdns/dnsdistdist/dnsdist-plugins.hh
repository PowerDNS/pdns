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

#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <dlfcn.h>

namespace dnsdist::plugins
{
using Error = std::string;
using PluginLibraryHandle = std::unique_ptr<void, decltype(&dlclose)>;

struct PluginDescription
{
  /* called in the main thread when the configuration has been fully parsed,
     but before making parts of it immutable */
  std::function<std::optional<Error>()> d_configurationDone;
  /* called once per second, if set */
  std::function<void()> d_maintenance;
  /* called when we are about to exit nicely (so it might not be called at all
     in some cases */
  std::function<void()> d_destroy;
};

struct PluginContext
{
  PluginLibraryHandle d_handle{nullptr, dlclose};
  PluginDescription d_description;
};

/* plugins should call this function when they are loaded */
std::optional<Error> registerNewPlugin(const std::string& name, const PluginDescription& description) __attribute__ ((visibility ("default")));;

/* called by DNSdist, as early as possible during configuration parsing, to load
   configured plugins */
std::optional<Error> loadPlugin(const std::string& path, const std::string& pluginName);

/* called when we are about to exit nicely, calling the plugin's destroy function */
void destroyPlugin(PluginContext& context) noexcept;
}
