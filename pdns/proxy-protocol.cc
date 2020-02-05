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

#include "proxy-protocol.hh"

// TODO: handle TLV after address struct
// TODO: maybe use structs instead of explicitly working byte by byte, like https://github.com/dovecot/core/blob/master/src/lib-master/master-service-haproxy.c

#define PROXYMAGIC "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define PROXYMAGICLEN sizeof(PROXYMAGIC)-1

static string proxymagic(PROXYMAGIC, PROXYMAGICLEN);

std::string makeProxyHeader(bool tcp, const ComboAddress& source, const ComboAddress& destination)
{
  if (source.sin4.sin_family != destination.sin4.sin_family) {
    throw std::runtime_error("The PROXY destination and source addresses must be of the same family");
  }

  std::string ret;
  const uint8_t versioncommand = (0x20 | 0x01); 
  const uint8_t protocol = (source.isIPv4() ? 0x10 : 0x20) | (tcp ? 0x01 : 0x02);
  const size_t addrSize = source.isIPv4() ? sizeof(source.sin4.sin_addr.s_addr) : sizeof(source.sin6.sin6_addr.s6_addr);
  const uint16_t sourcePort = source.sin4.sin_port;
  const uint16_t destinationPort = destination.sin4.sin_port;
  const uint16_t contentlen = htons((addrSize * 2) + sizeof(sourcePort) + sizeof(destinationPort));

  ret.reserve(proxymagic.size() + sizeof(versioncommand) + sizeof(protocol) + sizeof(contentlen) + contentlen);

  ret.append(proxymagic);

  ret.append(reinterpret_cast<const char*>(&versioncommand), sizeof(versioncommand));
  ret.append(reinterpret_cast<const char*>(&protocol), sizeof(protocol));

  ret.append(reinterpret_cast<const char*>(&contentlen), sizeof(contentlen));

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

/* returns: number of bytes consumed (positive) after successful parse
         or number of bytes missing (negative)
         or unfixable parse error (0)*/
ssize_t parseProxyHeader(const char* payload, size_t len, ComboAddress& source, ComboAddress& destination, bool& tcp)
{
  string header(payload, len);
  static const size_t addr4Size = sizeof(source.sin4.sin_addr.s_addr);
  static const size_t addr6Size = sizeof(source.sin6.sin6_addr.s6_addr);
  uint8_t versioncommand;
  uint8_t protocol;

  if (len < 16) {
    // this is too short to be a complete proxy header
    return -(16 - len); 
  }

  if (header.substr(0, proxymagic.size()) != proxymagic) {
    // wrong magic, can not be a proxy header
    return 0;
  }

  versioncommand = header.at(12);
  if (versioncommand != 0x21) {
    // FIXME: handle 0x20 here to mean 'proxy header present but use socket peer&local'
    return 0;
  }

  protocol = header.at(13);
  size_t addrSize;
  if ((protocol & 0xf) == 1) {
    tcp = true;
  } else if ((protocol & 0xf) == 2) {
    tcp = false;
  } else {
    return 0;
  }

  protocol = protocol >> 4;

  if (protocol == 1) {
    protocol = 4;
    addrSize = addr4Size; // IPv4
  } else if (protocol == 2) {
    protocol = 6;
    addrSize = addr6Size; // IPv6
  } else {
    // invalid protocol
    return 0;
  }

  uint16_t contentlen = (header.at(14) << 8) + header.at(15);
  uint16_t expectedlen = (addrSize * 2) + sizeof(source.sin4.sin_port) + sizeof(source.sin4.sin_port);

  if (contentlen != expectedlen) {
    return 0;
  }

  if (len < 16 + contentlen) {
    return (-(16 + contentlen) - len);
  }

  size_t pos = 16;

  source = makeComboAddressFromRaw(protocol, &header.at(pos), addrSize);
  pos = pos + addrSize;
  destination = makeComboAddressFromRaw(protocol, &header.at(pos), addrSize);
  pos = pos + addrSize;
  source.sin4.sin_port = htons((header.at(pos) << 8) + header.at(pos+1));
  pos = pos + sizeof(uint16_t);
  destination.sin4.sin_port = htons((header.at(pos) << 8) + header.at(pos+1));
  pos = pos + sizeof(uint16_t);

  return pos;
}
