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

std::string generateXPFPayload(bool tcp, const ComboAddress& source, const ComboAddress& destination)
{
  if (source.sin4.sin_family != destination.sin4.sin_family) {
    throw std::runtime_error("The XPF destination and source addresses must be of the same family");
  }

  std::string ret;
  const uint8_t version = source.isIPv4() ? 4 : 6;
  const uint8_t protocol = tcp ? 6 : 17;
  const size_t addrSize = source.isIPv4() ? sizeof(source.sin4.sin_addr.s_addr) : sizeof(source.sin6.sin6_addr.s6_addr);
  const uint16_t sourcePort = source.sin4.sin_port;
  const uint16_t destinationPort = destination.sin4.sin_port;

  ret.reserve(sizeof(version) + sizeof(protocol) + (addrSize * 2) + sizeof(sourcePort) + sizeof(destinationPort));

  ret.append(reinterpret_cast<const char*>(&version), sizeof(version));
  ret.append(reinterpret_cast<const char*>(&protocol), sizeof(protocol));

  // We already established source and destination sin_family equivalence
  if (source.isIPv4()) {
    assert(addrSize == sizeof(source.sin4.sin_addr.s_addr));
    ret.append(reinterpret_cast<const char*>(&source.sin4.sin_addr.s_addr), addrSize);
    assert(addrSize == sizeof(destination.sin4.sin_addr.s_addr));
    ret.append(reinterpret_cast<const char*>(&destination.sin4.sin_addr.s_addr), addrSize);
  }
  else {
    assert(addrSize == sizeof(source.sin6.sin6_addr.s6_addr));
    ret.append(reinterpret_cast<const char*>(&source.sin6.sin6_addr.s6_addr), addrSize);
    assert(addrSize == sizeof(destination.sin6.sin6_addr.s6_addr));
    ret.append(reinterpret_cast<const char*>(&destination.sin6.sin6_addr.s6_addr), addrSize);
  }

  ret.append(reinterpret_cast<const char*>(&sourcePort), sizeof(sourcePort));
  ret.append(reinterpret_cast<const char*>(&destinationPort), sizeof(destinationPort));

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

  if (len != (sizeof(version) + sizeof(protocol) + (addr4Size * 2) + sizeof(sourcePort) + sizeof(destinationPort)) && len != (sizeof(version) + sizeof(protocol) + (addr6Size * 2) + sizeof(sourcePort) + sizeof(destinationPort))) {
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
