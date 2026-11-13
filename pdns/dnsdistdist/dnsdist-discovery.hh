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

#include "dnsdist-tcp.hh"
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

class RedirectionQuerySender : public TCPQuerySender
{
public:
  [[nodiscard]] bool active() const override
  {
    return true;
  }

  void handleResponse([[maybe_unused]] const struct timeval& now, TCPResponse&& response) override
  {
    d_response = response.d_buffer;
  }

  void handleXFRResponse([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
    handleResponse(now, std::move(response));
  }

  void notifyIOError([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
    d_error = true;
  }

  PacketBuffer d_response;
  bool d_error{false};
};

class ServiceDiscovery
{
public:
  static bool addUpgradeableServer(std::shared_ptr<DownstreamState>& server, uint32_t interval, std::string poolAfterUpgrade, uint16_t dohSVCKey, bool keepAfterUpgrade, bool enableRedirection, uint32_t redirectInterval, std::string poolAfterRedirect, uint16_t redirectDohSVCKey, bool keepAfterRedirect, uint32_t redirectMaxFollowCount);
  static bool addRedirectableServer(std::shared_ptr<DownstreamState>& server, uint32_t interval, std::string poolAfterUpgrade, uint16_t dohSVCKey, bool keepAfterRedirect, uint32_t maxFollowCount);

  /* starts a background thread if needed */
  static bool run();

  struct DiscoveredResolverConfig
  {
    ComboAddress d_addr;
    std::string d_subjectName;
    std::string d_dohPath;
    uint16_t d_port{0};
    dnsdist::Protocol d_protocol;
    uint32_t d_ttl;

    bool operator==(const DiscoveredResolverConfig& rhs) const
    {
      return d_addr == rhs.d_addr && d_subjectName == rhs.d_subjectName && d_dohPath == rhs.d_dohPath && d_port == rhs.d_port && d_protocol == rhs.d_protocol && d_ttl == rhs.d_ttl;
    }
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
    bool d_enableRedirect;
    std::string d_poolAfterRedirect;
    uint32_t d_redirectInterval;
    uint16_t d_redirectDohKey;
    bool d_keepAfterRedirect;
    uint32_t d_redirectMaxFollowCount;
  };

  struct RedirectableBackend
  {
    std::shared_ptr<DownstreamState> d_origDs;
    std::shared_ptr<DownstreamState> d_currentDs;
    std::string d_poolAfterRedirect;
    time_t d_nextCheck;
    uint32_t d_interval;
    uint16_t d_dohKey;
    bool d_keepAfterRedirect;
    uint32_t d_maxFollowCount;
  };

  static bool getDiscoveredConfig(const Logr::Logger& logger, const std::shared_ptr<DownstreamState>& backend, uint16_t dohKey, DiscoveredResolverConfig& config);
  static bool tryToUpgradeBackend(const Logr::Logger& logger, const UpgradeableBackend& backend, std::shared_ptr<DownstreamState>& upgradedBackend);
  static bool tryToRedirectBackend(const Logr::Logger& logger, RedirectableBackend& backend, uint32_t& ttl);

  static void worker();

  static LockGuarded<std::vector<std::shared_ptr<UpgradeableBackend>>> s_upgradeableBackends;
  static LockGuarded<std::vector<std::shared_ptr<ServiceDiscovery::RedirectableBackend>>> s_redirectableBackends;
  static std::thread s_thread;
};

}

namespace std
{
template <>
struct hash<dnsdist::ServiceDiscovery::DiscoveredResolverConfig>
{
  auto operator()(const dnsdist::ServiceDiscovery::DiscoveredResolverConfig& config) const
  {
    size_t currentHash = ComboAddress::addressOnlyHash{}(config.d_addr);
    boost::hash_combine(currentHash, std::hash<std::string>{}(config.d_subjectName));
    boost::hash_combine(currentHash, std::hash<std::string>{}(config.d_dohPath));
    boost::hash_combine(currentHash, std::hash<uint16_t>{}(config.d_port));
    boost::hash_combine(currentHash, std::hash<uint8_t>{}(config.d_protocol.toNumber()));
    boost::hash_combine(currentHash, std::hash<uint32_t>{}(config.d_ttl));
    return currentHash;
  }
};
}
