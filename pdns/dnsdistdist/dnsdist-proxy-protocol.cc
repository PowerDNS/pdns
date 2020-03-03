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

#include "dnsdist-proxy-protocol.hh"

bool addProxyProtocol(DNSQuestion& dq)
{
  auto payload = makeProxyHeader(dq.tcp, *dq.remote, *dq.local, dq.proxyProtocolValues ? *dq.proxyProtocolValues : std::vector<ProxyProtocolValue>());
  if ((dq.size - dq.len) < payload.size()) {
    return false;
  }

  memmove(reinterpret_cast<char*>(dq.dh) + payload.size(), dq.dh, dq.len);
  memcpy(dq.dh, payload.c_str(), payload.size());
  dq.len += payload.size();

  return true;
}

bool addProxyProtocol(std::vector<uint8_t>& buffer, bool tcp, const ComboAddress& source, const ComboAddress& destination, const std::vector<ProxyProtocolValue>& values)
{
  auto payload = makeProxyHeader(tcp, source, destination, values);

  auto previousSize = buffer.size();
  buffer.resize(previousSize + payload.size());
  std::copy_backward(buffer.begin(), buffer.begin() + previousSize, buffer.end());
  std::copy(payload.begin(), payload.end(), buffer.begin());

  return true;
}
