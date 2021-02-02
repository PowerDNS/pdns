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

#include "namespaces.hh"
#include "iputils.hh"
#include "sstuff.hh"

namespace pdns
{

/*
 * This class maintains TCP connections belonging to specific tread.
 * The main data strructure is a multimap, it tracks idle connections to a specific address.
 *
 * ATM we do a send-query receive-answer make-idle mechanism. No OOO processing is done.
 * So multiple connections to the same auth can be active. Hence the multimap.
 * If a connection is in the multimap, it is idle and available to connect to the address. 
 */
class TCPOutConnectionManager
{
public:
  class TCPOutConnection
  {
  public:
    TCPOutConnection(unique_ptr<Socket>&& s, const timeval& now) :
      d_socket(std::move(s)),
      d_last_used(now)
    {
    }
    Socket& getSocket()
    {
      return *d_socket;
    }
    void setLastUsed(const timeval& now)
    {
      d_last_used = now;
    }
    struct timeval getLastUsed() const
    {
      return d_last_used;
    }
    size_t getQueries() const
    {
      return d_queries;
    }
    void incQueries()
    {
      ++d_queries;
    }

  private:
    unique_ptr<Socket> d_socket;
    struct timeval d_last_used;
    size_t d_queries{0};
  };

  unique_ptr<TCPOutConnection> getConnection(const ComboAddress& address, const timeval& now, bool& isNew);
  void setIdle(const ComboAddress& address, unique_ptr<TCPOutConnection>&& connection, const timeval& now);
  size_t size() const
  {
    return d_idle_connections.size();
  }
  uint64_t* getSize() const
  {
    return new uint64_t(size());
  }
  void incCreated()
  {
    d_created++;
  }
  uint64_t* getCreated() const
  {
    return new uint64_t(d_created);
  }
  void incQueries()
  {
    d_queries++;
  }
  uint64_t* getQueries() const
  {
    return new uint64_t(d_queries);
  }

  void cleanup(const timeval& now);

  // Max idle time for a connection, 0 is no timeout
  static struct timeval maxIdle;
  // Per thread maximum of idle connections for a specific destination, 0 means no idle connections will be kept open
  static size_t maxPerAuth;
  // Max number of queries to process per connection, 0 is no max
  static size_t maxQueries;
  // Per thread max # of connections, here 0 means a real limit
  static size_t maxPerThread;

  static uint64_t getAllQueriesDone(); // actually redundant, there's already "tcp-outqueries" maintained by Syncres
  static uint64_t getAllConnectionsCreated();
  static uint64_t getCurrentIdleConnections();

private:
  std::multimap<ComboAddress, unique_ptr<TCPOutConnection>> d_idle_connections;
  uint64_t d_created{0};
  uint64_t d_queries{0};
};

} // namespace pdns

extern thread_local pdns::TCPOutConnectionManager t_tcpConnections;
