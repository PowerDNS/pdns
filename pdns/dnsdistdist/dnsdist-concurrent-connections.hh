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

#include <map>
#include "iputils.hh"
#include "lock.hh"

namespace dnsdist
{
class IncomingConcurrentTCPConnectionsManager
{
public:
  static bool accountNewTCPConnection(const ComboAddress& from)
  {
    if (s_maxTCPConnectionsPerClient == 0) {
      return true;
    }
    auto db = s_tcpClientsConcurrentConnectionsCount.lock();
    auto& count = (*db)[from];
    if (count >= s_maxTCPConnectionsPerClient) {
      return false;
    }
    ++count;
    return true;
  }

  static void accountClosedTCPConnection(const ComboAddress& from)
  {
    if (s_maxTCPConnectionsPerClient == 0) {
      return;
    }
    auto db = s_tcpClientsConcurrentConnectionsCount.lock();
    auto& count = db->at(from);
    count--;
    if (count == 0) {
      db->erase(from);
    }
  }

  static void setMaxTCPConnectionsPerClient(size_t max)
  {
    s_maxTCPConnectionsPerClient = max;
  }

private:
  static LockGuarded<std::map<ComboAddress, size_t, ComboAddress::addressOnlyLessThan>> s_tcpClientsConcurrentConnectionsCount;
  static size_t s_maxTCPConnectionsPerClient;
};

}
