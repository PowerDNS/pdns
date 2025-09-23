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
#include <memory>

#include "dnsdist-lbpolicies.hh"

class DNSDistPacketCache;

struct ServerPool
{
  const std::shared_ptr<DNSDistPacketCache> getCache() const
  {
    return packetCache;
  }

  bool getECS() const
  {
    return d_useECS;
  }

  /* Note that the pool will do a consistency check,
     and might decide to override the supplied value
     if all backends in the pool have the same ECS
     value and the value differs from the supplied one */
  void setECS(bool useECS);

  bool getZeroScope() const
  {
    return d_zeroScope;
  }

  /* Note that the pool will do a consistency check,
     and might decide to override the supplied value
     if all backends in the pool have the same disable zero scope setting
     value and the value differs from the supplied one */
  void setZeroScope(bool enabled);

  bool isConsistent() const
  {
    return d_isConsistent;
  }

  /* sum of outstanding queries for all servers in this pool */
  size_t poolLoad() const;
  size_t countServers(bool upOnly) const;
  bool hasAtLeastOneServerAvailable() const;
  const ServerPolicy::NumberedServerVector& getServers() const;
  void addServer(std::shared_ptr<DownstreamState>& server);
  void removeServer(std::shared_ptr<DownstreamState>& server);
  bool isTCPOnly() const
  {
    // coverity[missing_lock]
    return d_tcpOnly;
  }

  std::shared_ptr<DNSDistPacketCache> packetCache{nullptr};
  std::shared_ptr<ServerPolicy> policy{nullptr};

private:
  void updateConsistency();

  ServerPolicy::NumberedServerVector d_servers;
  bool d_useECS{false};
  bool d_zeroScope{true};
  bool d_tcpOnly{false};
  bool d_isConsistent{true};
};
