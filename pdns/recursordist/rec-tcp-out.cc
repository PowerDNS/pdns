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

#include <random>
#include "rec-tcp-out.hh"
#include "dns_random.hh"
#include "query-local-address.hh"
#include "syncres.hh"

thread_local pdns::TCPOutConnectionManager t_tcpConnections;

namespace pdns
{

timeval TCPOutConnectionManager::maxIdle;
size_t TCPOutConnectionManager::maxQueries;
size_t TCPOutConnectionManager::maxPerAuth;
size_t TCPOutConnectionManager::maxPerThread;

unique_ptr<TCPOutConnectionManager::TCPOutConnection> TCPOutConnectionManager::getConnection(const ComboAddress& address, const timeval& now, bool& isNew)
{
  if (d_idle_connections.count(address) > 0) {
    // idle connection available
    isNew = false;
    auto nh = d_idle_connections.extract(address);
    return std::move(nh.mapped());
  }
  // No idle connection available, make a new one. Caller will either discard it (fine) or call setIdle on it so it will be
  // put in the pool of available connections
  isNew = true;
  auto s = make_unique<Socket>(address.sin4.sin_family, SOCK_STREAM);
  s->setNonBlocking();
  ComboAddress local = getQueryLocalAddress(address.sin4.sin_family, 0);
  s->bind(local);
  s->connect(address);
  incCreated();
  return make_unique<TCPOutConnection>(std::move(s), now);
}

void TCPOutConnectionManager::setIdle(const ComboAddress& address, unique_ptr<TCPOutConnection>&& tcp, const struct timeval& now)
{
  this->incQueries();
  if (maxPerAuth == 0) {
    // We're done, connectionds wil be destroyed since we do not hold on the idle connections
    return;
  }

  auto count = d_idle_connections.count(address);
  // Hold on to the connection if we have not reached maxQueries
  if (maxQueries == 0 || tcp->getQueries() < maxQueries) {
    tcp->setLastUsed(now);
    tcp->incQueries();
    d_idle_connections.emplace(address, std::move(tcp));
    count++;
  }
  if (count > maxPerAuth) {
    // erase the oldest by using a range, since multimap::find will return an random element
    // see https://en.cppreference.com/w/cpp/container/multimap/equal_range
    const auto& i = d_idle_connections.equal_range(address);
    if (i.first != d_idle_connections.end()) {
      d_idle_connections.erase(i.first);
    }
  }
}

void TCPOutConnectionManager::cleanup(const timeval& now)
{
  // Enforce maxIdle if it is set
  if (timeval{0, 0} < maxIdle) {
    auto i = d_idle_connections.begin();
    while (i != d_idle_connections.end()) {
      auto& conn = *i->second;
      if (maxIdle < now - conn.getLastUsed()) {
        i = d_idle_connections.erase(i);
      }
      else {
        ++i;
      }
    }
  }

  // Still too many? Enforce maxPerThread by killing random connections
  // One day we might want to start using a multi-index and use a LRU method
  if (d_idle_connections.size() > maxPerThread) {
    std::uniform_real_distribution<> dis(0.0, 1.0);
    std::mt19937 gen(dns_random(0xffffffff));

    // suppose we have 10 and max is 6
    double fraction = double(maxPerThread) / d_idle_connections.size();
    // fraction = 0.6
    auto i = d_idle_connections.begin();
    while (i != d_idle_connections.end()) {
      // this will throw away 4/10 on average
      if (dis(gen) > fraction) {
        i = d_idle_connections.erase(i);
      }
      else {
        ++i;
      }
    }
  }
}

uint64_t TCPOutConnectionManager::getAllQueriesDone()
{
  return broadcastAccFunction<uint64_t>([] { return t_tcpConnections.getQueries(); });
}

uint64_t TCPOutConnectionManager::getAllConnectionsCreated()
{
  return broadcastAccFunction<uint64_t>([] { return t_tcpConnections.getCreated(); });
}

uint64_t TCPOutConnectionManager::getCurrentIdleConnections()
{
  return broadcastAccFunction<uint64_t>([] { return t_tcpConnections.getSize(); });
}

} // namespace pdns
