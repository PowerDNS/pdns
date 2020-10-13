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

std::string getProxyProtocolPayload(const DNSQuestion& dq)
{
  return makeProxyHeader(dq.tcp, *dq.remote, *dq.local, dq.proxyProtocolValues ? *dq.proxyProtocolValues : std::vector<ProxyProtocolValue>());
}

bool addProxyProtocol(DNSQuestion& dq, const std::string& payload)
{
  if (!dq.hasRoomFor(payload.size())) {
    return false;
  }

  return addProxyProtocol(dq.getMutableData(), payload);
}

bool addProxyProtocol(DNSQuestion& dq)
{
  auto payload = getProxyProtocolPayload(dq);
  return addProxyProtocol(dq, payload);
}

bool addProxyProtocol(PacketBuffer& buffer, const std::string& payload)
{
  auto previousSize = buffer.size();
  if (payload.size() > (std::numeric_limits<size_t>::max() - previousSize)) {
    return false;
  }

  buffer.insert(buffer.begin(), payload.begin(), payload.end());

  return true;
}

bool addProxyProtocol(PacketBuffer& buffer, bool tcp, const ComboAddress& source, const ComboAddress& destination, const std::vector<ProxyProtocolValue>& values)
{
  auto payload = makeProxyHeader(tcp, source, destination, values);
  return addProxyProtocol(buffer, payload);
}
