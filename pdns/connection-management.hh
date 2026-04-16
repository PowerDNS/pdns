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

#include "lock.hh"

class ConcurrentConnectionManager
{
public:
  ConcurrentConnectionManager(size_t max)
  {
    setMaxConcurrentConnections(max);
  }

  void setMaxConcurrentConnections(size_t max)
  {
    d_data.lock()->d_maxConcurrentConnections = max;
  }

  size_t getMaxConcurrentConnections()
  {
    return d_data.lock()->d_maxConcurrentConnections;
  }

  bool registerConnection()
  {
    auto data = d_data.lock();
    if (data->d_maxConcurrentConnections == 0 || data->d_currentConnectionsCount < data->d_maxConcurrentConnections) {
      ++data->d_currentConnectionsCount;
      return true;
    }
    return false;
  }

  void releaseConnection()
  {
    --(d_data.lock()->d_currentConnectionsCount);
  }

private:
  struct Data
  {
    size_t d_maxConcurrentConnections{0};
    size_t d_currentConnectionsCount{0};
  };

  LockGuarded<Data> d_data;
};
