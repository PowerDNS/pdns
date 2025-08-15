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
#include <vector>

#include "dnsdist-resolver.hh"
#include "iputils.hh"
#include "threadname.hh"

namespace dnsdist::resolver
{
void asynchronousResolver(const std::string& hostname, const std::function<void(const std::string& hostname, std::vector<ComboAddress>& ips)>& callback)
{
  setThreadName("dnsdist/resolve");
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_ADDRCONFIG;
  hints.ai_socktype = SOCK_DGRAM;
  addrinfo* infosRaw{nullptr};
  std::vector<ComboAddress> addresses;
  auto ret = getaddrinfo(hostname.c_str(), nullptr, &hints, &infosRaw);
  if (ret != 0) {
    callback(hostname, addresses);
    return;
  }
  auto infos = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>(infosRaw, &freeaddrinfo);
  for (const auto* addr = infos.get(); addr != nullptr; addr = addr->ai_next) {
    try {
      addresses.emplace_back(addr->ai_addr, addr->ai_addrlen);
    }
    catch (...) {
    }
  }
  callback(hostname, addresses);
}
}
