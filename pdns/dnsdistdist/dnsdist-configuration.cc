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

#include "dnsdist-configuration.hh"
#include "sholder.hh"

namespace dnsdist::configuration
{
static GlobalStateHolder<RuntimeConfiguration> s_currentRuntimeConfiguration;
static ImmutableConfiguration s_immutableConfiguration;
static std::atomic<bool> s_immutableConfigurationDone{false};

static const RuntimeConfiguration& getCurrentRuntimeConfigurationInternal(bool refresh)
{
  static thread_local auto t_threadLocalConfiguration = s_currentRuntimeConfiguration.getLocal();
  return t_threadLocalConfiguration.get(!refresh);
}

const RuntimeConfiguration& getCurrentRuntimeConfiguration()
{
  return getCurrentRuntimeConfigurationInternal(false);
}

const RuntimeConfiguration& refreshLocalRuntimeConfiguration()
{
  return getCurrentRuntimeConfigurationInternal(true);
}

void updateRuntimeConfiguration(const std::function<void(RuntimeConfiguration&)>& mutator)
{
  s_currentRuntimeConfiguration.modify(mutator);
  /* refresh the local "cache" right away */
  refreshLocalRuntimeConfiguration();
}

void updateImmutableConfiguration(const std::function<void(ImmutableConfiguration&)>& mutator)
{
  if (isImmutableConfigurationDone()) {
    throw std::runtime_error("Trying to update an immutable setting at runtime!");
  }

  mutator(s_immutableConfiguration);
}

const ImmutableConfiguration& getImmutableConfiguration()
{
  return s_immutableConfiguration;
}

bool isImmutableConfigurationDone()
{
  return s_immutableConfigurationDone.load();
}

void setImmutableConfigurationDone()
{
  if (s_immutableConfigurationDone.exchange(true)) {
    throw std::runtime_error("Trying to seal the runtime-immutable configuration a second time");
  }
}
}
