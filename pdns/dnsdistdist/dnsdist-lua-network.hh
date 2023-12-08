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

#include <thread>
#include <unordered_map>

#include "lock.hh"
#include "mplexer.hh"
#include "sstuff.hh"

namespace dnsdist
{
class NetworkListener
{
public:
  NetworkListener();
  NetworkListener(const NetworkListener&) = delete;
  NetworkListener(NetworkListener&&) = delete;
  NetworkListener& operator=(const NetworkListener&) = delete;
  NetworkListener& operator=(NetworkListener&&) = delete;
  ~NetworkListener();

  using EndpointID = uint16_t;
  using NetworkDatagramCB = std::function<void(EndpointID endpoint, std::string&& dgram, const std::string& from)>;
  bool addUnixListeningEndpoint(const std::string& path, EndpointID endpointID, NetworkDatagramCB callback);
  void start();
  void runOnce(timeval& now, uint32_t timeout);

private:
  struct ListenerData
  {
    ListenerData();

    std::unique_ptr<FDMultiplexer> d_mplexer;
    std::unordered_map<std::string, Socket> d_sockets;
    std::atomic<bool> d_running{false};
    std::atomic<bool> d_exiting{false};
  };

  static void readCB(int desc, FDMultiplexer::funcparam_t& param);
  static void mainThread(std::shared_ptr<ListenerData>& data);
  static void runOnce(ListenerData& data, timeval& now, uint32_t timeout);

  struct CBData
  {
    NetworkDatagramCB d_cb;
    EndpointID d_endpoint;
  };

  std::shared_ptr<ListenerData> d_data;
};

class NetworkEndpoint
{
public:
  NetworkEndpoint(const std::string& path);
  bool send(const std::string_view& payload) const;

private:
  Socket d_socket;
};
}
