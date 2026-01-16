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
#include <vector>
#include <thread>

#include "dnsname.hh"
#include "dnsdist-protocols.hh"
#include "iputils.hh"
#include "lock.hh"

struct DownstreamState;
namespace Logr
{
class Logger;
}

namespace dnsdist
{

class ServiceDiscovery
{
public:
  static bool addUpgradeableServer(std::shared_ptr<DownstreamState>& server, uint32_t interval, std::string poolAfterUpgrade, uint16_t dohSVCKey, bool keepAfterUpgrade);

  /* starts a background thread if needed */
  static bool run();

  struct DiscoveredResolverConfig
  {
    ComboAddress d_addr;
    std::string d_subjectName;
    std::string d_dohPath;
    uint16_t d_port{0};
    dnsdist::Protocol d_protocol;
  };

  static const uint16_t s_defaultDoHSVCKey;

private:
  static const DNSName s_discoveryDomain;
  static const QType s_discoveryType;

  struct UpgradeableBackend
  {
    std::shared_ptr<DownstreamState> d_ds;
    std::string d_poolAfterUpgrade;
    time_t d_nextCheck;
    uint32_t d_interval;
    uint16_t d_dohKey;
    bool keepAfterUpgrade;
  };

  static bool getDiscoveredConfig(const Logr::Logger& logger, const UpgradeableBackend& backend, DiscoveredResolverConfig& config);
  static bool tryToUpgradeBackend(const Logr::Logger& logger, const UpgradeableBackend& backend);

  static void worker();

  static LockGuarded<std::vector<std::shared_ptr<UpgradeableBackend>>> s_upgradeableBackends;
  static std::thread s_thread;
};

}
