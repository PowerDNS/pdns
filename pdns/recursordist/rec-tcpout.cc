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

#include "rec-tcpout.hh"

// This line from /usr/include/openssl/ssl2.h: # define CERT char
// throws dnsrecords.hh off the rails.
#undef CERT

#include "syncres.hh"

timeval TCPOutConnectionManager::s_maxIdleTime;
size_t TCPOutConnectionManager::s_maxQueries;
size_t TCPOutConnectionManager::s_maxIdlePerAuth;
size_t TCPOutConnectionManager::s_maxIdlePerThread;

void TCPOutConnectionManager::cleanup(const struct timeval& now)
{
  if (s_maxIdleTime.tv_sec == 0 && s_maxIdleTime.tv_usec == 0) {
    // no maximum idle time
    return;
  }

  for (auto it = d_idle_connections.begin(); it != d_idle_connections.end();) {
    timeval idle = now - it->second.d_last_used;
    if (s_maxIdleTime < idle) {
      it = d_idle_connections.erase(it);
    }
    else {
      ++it;
    }
  }
}

void TCPOutConnectionManager::store(const struct timeval& now, const pair_t& pair, Connection&& connection)
{
  ++connection.d_numqueries;
  if (s_maxQueries > 0 && connection.d_numqueries >= s_maxQueries) {
    return;
  }

  if (d_idle_connections.size() >= s_maxIdlePerThread || d_idle_connections.count(pair) >= s_maxIdlePerAuth) {
    cleanup(now);
  }

  if (d_idle_connections.size() >= s_maxIdlePerThread) {
    return;
  }
  if (d_idle_connections.count(pair) >= s_maxIdlePerAuth) {
    return;
  }

  gettimeofday(&connection.d_last_used, nullptr);
  d_idle_connections.emplace(pair, std::move(connection));
}

TCPOutConnectionManager::Connection TCPOutConnectionManager::get(const pair_t& pair)
{
  if (d_idle_connections.count(pair) > 0) {
    auto connection = d_idle_connections.extract(pair);
    return connection.mapped();
  }
  return Connection{};
}

uint64_t getCurrentIdleTCPConnections()
{
  return broadcastAccFunction<uint64_t>([] { return t_tcp_manager.getSize(); });
}
