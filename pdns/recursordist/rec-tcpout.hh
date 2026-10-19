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
#include "query-local-address.hh"

namespace pdns::rust::settings::rec
{
struct Recursorsettings;
}

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

  struct Endpoint
  {
    ComboAddress d_remote;
    std::optional<pdns::AddressAndInterface> d_local;
    std::string d_subject;
    std::string d_tlsConfig;
    size_t d_iteration{0};
    bool operator<(const Endpoint& rhs) const
    {
      return std::make_tuple(d_remote, d_local, d_subject, d_tlsConfig, d_iteration) < std::make_tuple(rhs.d_remote, rhs.d_local, rhs.d_subject, rhs.d_tlsConfig, rhs.d_iteration);
    }
  };

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
    Endpoint d_endpoint;
    timeval d_last_used{0, 0};
    size_t d_numqueries{0};
    bool d_verboseLogging{false};
  };

  void store(const struct timeval& now, Connection&& connection);
  Connection get(const Endpoint& endpoint);
  void cleanup(const struct timeval& now);

  [[nodiscard]] size_t size() const
  {
    return d_idle_connections.size();
  }
  [[nodiscard]] uint64_t* getSize() const
  {
    return new uint64_t(size()); // NOLINT(cppcoreguidelines-owning-memory): it's the API
  }

  static void setupOutgoingTLSConfigTables(pdns::rust::settings::rec::Recursorsettings& settings);
  static std::shared_ptr<TLSCtx> getTLSContext(const std::string& name, const ComboAddress& address, bool& verboseLogging, std::string& subjectName, std::string& subjectAddress, std::string& configName, size_t& iteration);

private:
  // This does not take into account that we can have multiple connections with different hosts (via SNI) to the same IP.
  // That is OK, since we are connecting by IP only at the moment.
  std::multimap<Endpoint, Connection> d_idle_connections;
};

extern thread_local TCPOutConnectionManager t_tcp_manager;
uint64_t getCurrentIdleTCPConnections();
