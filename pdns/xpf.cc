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

#include "xpf.hh"

std::string generateXPFPayload(bool tcp, const ComboAddress& remote, const ComboAddress& local)
{
  if (remote.sin4.sin_family != local.sin4.sin_family) {
    throw std::runtime_error("The XPF local and remote addresses must be of the same family");
  }

  std::string ret;
  const uint8_t version = remote.isIPv4() ? 4 : 6;
  const uint8_t protocol = tcp ? 6 : 17;
  const size_t addrSize = remote.isIPv4() ? sizeof(remote.sin4.sin_addr.s_addr) : sizeof(remote.sin6.sin6_addr.s6_addr);
  const uint16_t remotePort = remote.sin4.sin_port;
  const uint16_t localPort = local.sin4.sin_port;

  ret.reserve(sizeof(version) + sizeof(protocol) + (addrSize * 2) + sizeof(remotePort) + sizeof(localPort));

  ret.append(reinterpret_cast<const char*>(&version), sizeof(version));
  ret.append(reinterpret_cast<const char*>(&protocol), sizeof(protocol));

  if (remote.isIPv4()) {
    assert(addrSize == sizeof(remote.sin4.sin_addr.s_addr));
    ret.append(reinterpret_cast<const char*>(&remote.sin4.sin_addr.s_addr), addrSize);
  }
  else {
    assert(addrSize == sizeof(remote.sin6.sin6_addr.s6_addr));
    ret.append(reinterpret_cast<const char*>(&remote.sin6.sin6_addr.s6_addr), addrSize);
  }

  if (remote.isIPv4()) {
    assert(addrSize == sizeof(local.sin4.sin_addr.s_addr));
    ret.append(reinterpret_cast<const char*>(&local.sin4.sin_addr.s_addr), addrSize);
  }
  else {
    assert(addrSize == sizeof(local.sin6.sin6_addr.s6_addr));
    ret.append(reinterpret_cast<const char*>(&local.sin6.sin6_addr.s6_addr), addrSize);
  }

  ret.append(reinterpret_cast<const char*>(&remotePort), sizeof(remotePort));
  ret.append(reinterpret_cast<const char*>(&localPort), sizeof(localPort));

  return ret;
}

bool parseXPFPayload(const char* payload, size_t len, ComboAddress& source, ComboAddress* destination)
{
  static const size_t addr4Size = sizeof(source.sin4.sin_addr.s_addr);
  static const size_t addr6Size = sizeof(source.sin6.sin6_addr.s6_addr);
  uint8_t version;
  uint8_t protocol;
  uint16_t sourcePort;
  uint16_t destinationPort;

  if (len != (sizeof(version) + sizeof(protocol) + (addr4Size * 2) + sizeof(sourcePort) + sizeof(destinationPort)) &&
      len != (sizeof(version) + sizeof(protocol) + (addr6Size * 2) + sizeof(sourcePort) + sizeof(destinationPort))) {
    return false;
  }

  size_t pos = 0;

  memcpy(&version, payload + pos, sizeof(version));
  pos += sizeof(version);

  if (version != 4 && version != 6) {
    return false;
  }

  memcpy(&protocol, payload + pos, sizeof(protocol));
  pos += sizeof(protocol);

  if (protocol != 6 && protocol != 17) {
    return false;
  }

  const size_t addrSize = version == 4 ? sizeof(source.sin4.sin_addr.s_addr) : sizeof(source.sin6.sin6_addr.s6_addr);
  if (len - pos != ((addrSize * 2) + sizeof(sourcePort) + sizeof(destinationPort))) {
    return false;
  }

  source = makeComboAddressFromRaw(version, payload + pos, addrSize);
  pos += addrSize;
  if (destination != nullptr) {
    *destination = makeComboAddressFromRaw(version, payload + pos, addrSize);
  }
  pos += addrSize;

  memcpy(&sourcePort, payload + pos, sizeof(sourcePort));
  pos += sizeof(sourcePort);
  source.sin4.sin_port = sourcePort;

  memcpy(&destinationPort, payload + pos, sizeof(destinationPort));
  pos += sizeof(destinationPort);
  if (destination != nullptr) {
    destination->sin4.sin_port = destinationPort;
  }

  return true;
}
