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

timeval TCPOutConnectionManager::maxIdleTime;
size_t TCPOutConnectionManager::maxQueries;
size_t TCPOutConnectionManager::maxIdlePerAuth;
size_t TCPOutConnectionManager::maxIdlePerThread;

void TCPOutConnectionManager::cleanup()
{
  if (maxIdleTime.tv_sec == 0 && maxIdleTime.tv_usec == 0) {
    // no maximum idle time
    return;
  }
  struct timeval now;
  gettimeofday(&now, nullptr);

  for (auto it = d_idle_connections.begin(); it != d_idle_connections.end();) {
    timeval idle = now - it->second.d_last_used;
    if (maxIdleTime < idle) {
      it = d_idle_connections.erase(it);
    }
    else {
      ++it;
    }
  }
}

void TCPOutConnectionManager::store(const ComboAddress& ip, Connection& connection)
{
  cleanup();
  if (d_idle_connections.size() >= maxIdlePerThread) {
    return;
  }
  if (d_idle_connections.count(ip) >= maxIdlePerAuth) {
    return;
  }

  ++connection.d_numqueries;
  if (maxQueries > 0 && connection.d_numqueries > maxQueries) {
    return;
  }
  gettimeofday(&connection.d_last_used, nullptr);
  d_idle_connections.emplace(ip, connection);
}

TCPOutConnectionManager::Connection TCPOutConnectionManager::get(const ComboAddress& ip)
{
  if (d_idle_connections.count(ip) > 0) {
    auto h = d_idle_connections.extract(ip);
    return h.mapped();
  }
  return Connection{};
}

uint64_t getCurrentIdleTCPConnections()
{
  return broadcastAccFunction<uint64_t>([] { return t_tcp_manager.getSize(); });
}
