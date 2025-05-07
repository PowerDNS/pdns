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
#include "dnsdist-metrics.hh"
#include "dolog.hh"

NetmaskGroup g_proxyProtocolACL;
size_t g_proxyProtocolMaximumSize = 512;
bool g_applyACLToProxiedClients = false;

std::string getProxyProtocolPayload(const DNSQuestion& dq)
{
  return makeProxyHeader(dq.overTCP(), dq.ids.origRemote, dq.ids.origDest, dq.proxyProtocolValues ? *dq.proxyProtocolValues : std::vector<ProxyProtocolValue>());
}

bool addProxyProtocol(DNSQuestion& dq, const std::string& payload)
{
  if (!dq.hasRoomFor(payload.size())) {
    return false;
  }

  return addProxyProtocol(dq.getMutableData(), payload);
}

bool addProxyProtocol(DNSQuestion& dnsQuestion, size_t* proxyProtocolPayloadSize)
{
  auto payload = getProxyProtocolPayload(dnsQuestion);
  size_t payloadSize = payload.size();

  if (!addProxyProtocol(dnsQuestion, payload)) {
    return false;
  }

  if (proxyProtocolPayloadSize != nullptr) {
    *proxyProtocolPayloadSize = payloadSize;
  }
  return true;
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

bool expectProxyProtocolFrom(const ComboAddress& remote)
{
  return g_proxyProtocolACL.match(remote);
}

bool handleProxyProtocol(const ComboAddress& remote, bool isTCP, const NetmaskGroup& acl, PacketBuffer& query, ComboAddress& realRemote, ComboAddress& realDestination, std::vector<ProxyProtocolValue>& values)
{
  bool tcp;
  bool proxyProto;

  ssize_t used = parseProxyHeader(query, proxyProto, realRemote, realDestination, tcp, values);
  if (used <= 0) {
    ++dnsdist::metrics::g_stats.proxyProtocolInvalid;
    vinfolog("Ignoring invalid proxy protocol (%d, %d) query over %s from %s", query.size(), used, (isTCP ? "TCP" : "UDP"), remote.toStringWithPort());
    return false;
  }
  else if (static_cast<size_t>(used) > g_proxyProtocolMaximumSize) {
    vinfolog("Proxy protocol header in %s packet from %s is larger than proxy-protocol-maximum-size (%d), dropping", (isTCP ? "TCP" : "UDP"), remote.toStringWithPort(), used);
    ++dnsdist::metrics::g_stats.proxyProtocolInvalid;
    return false;
  }

  query.erase(query.begin(), query.begin() + used);

  /* on TCP we have not read the actual query yet */
  if (!isTCP && query.size() < sizeof(struct dnsheader)) {
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    return false;
  }

  if (proxyProto && g_applyACLToProxiedClients) {
    if (!acl.match(realRemote)) {
      vinfolog("Query from %s dropped because of ACL", realRemote.toStringWithPort());
      ++dnsdist::metrics::g_stats.aclDrops;
      return false;
    }
  }

  return true;
}
