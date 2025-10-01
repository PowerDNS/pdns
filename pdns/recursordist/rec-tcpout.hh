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

#include "iputils.hh"
#include "tcpiohandler.hh"

class TCPOutConnectionManager
{
public:
  // Max idle time for a connection, 0 is no timeout
  static struct timeval s_maxIdleTime;
  // Per thread maximum of idle connections for a specific destination, 0 means no idle connections will be kept open
  static size_t s_maxIdlePerAuth;
  // Max total number of queries to handle per connection, 0 is no max
  static size_t s_maxQueries;
  // Per thread max # of idle connections, 0 means no idle connections will be kept open
  static size_t s_maxIdlePerThread;

  struct Connection
  {
    [[nodiscard]] std::string toString() const
    {
      if (d_handler) {
        return std::to_string(d_handler->getDescriptor()) + ' ' + std::to_string(d_handler.use_count());
      }
      return "";
    }

    std::shared_ptr<TCPIOHandler> d_handler;
    std::optional<ComboAddress> d_local;
    timeval d_last_used{0, 0};
    size_t d_numqueries{0};
  };

  using endpoints_t = std::pair<ComboAddress, std::optional<ComboAddress>>;

  void store(const struct timeval& now, const endpoints_t& endpoints, Connection&& connection);
  Connection get(const endpoints_t& pair);
  void cleanup(const struct timeval& now);

  [[nodiscard]] size_t size() const
  {
    return d_idle_connections.size();
  }
  [[nodiscard]] uint64_t* getSize() const
  {
    return new uint64_t(size()); // NOLINT(cppcoreguidelines-owning-memory): it's the API
  }

  static std::shared_ptr<TLSCtx> getTLSContext(const std::string& name, const ComboAddress& address);

private:
  // This does not take into account that we can have multiple connections with different hosts (via SNI) to the same IP.
  // That is OK, since we are connecting by IP only at the moment.
  std::multimap<endpoints_t, Connection> d_idle_connections;
};

extern thread_local TCPOutConnectionManager t_tcp_manager;
uint64_t getCurrentIdleTCPConnections();
