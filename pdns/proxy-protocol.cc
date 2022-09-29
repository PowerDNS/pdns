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

// TODO: maybe use structs instead of explicitly working byte by byte, like https://github.com/dovecot/core/blob/master/src/lib-master/master-service-haproxy.c

#define PROXYMAGIC "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"
#define PROXYMAGICLEN sizeof(PROXYMAGIC)-1

static const string proxymagic(PROXYMAGIC, PROXYMAGICLEN);

static void makeSimpleHeader(uint8_t command, uint8_t protocol, uint16_t contentLen, size_t additionalSize, std::string& out)
{
  const uint8_t versioncommand = (0x20 | command);
  const size_t totalSize = proxymagic.size() + sizeof(versioncommand) + sizeof(protocol) + sizeof(contentLen) + additionalSize;
  if (out.capacity() < totalSize) {
    out.reserve(totalSize);
  }

  out.append(proxymagic);

  out.append(reinterpret_cast<const char*>(&versioncommand), sizeof(versioncommand));
  out.append(reinterpret_cast<const char*>(&protocol), sizeof(protocol));

  out.append(reinterpret_cast<const char*>(&contentLen), sizeof(contentLen));
}

std::string makeLocalProxyHeader()
{
  std::string out;
  makeSimpleHeader(0x00, 0, 0, 0, out);
  return out;
}

std::string makeProxyHeader(bool tcp, const ComboAddress& source, const ComboAddress& destination, const std::vector<ProxyProtocolValue>& values)
{
  if (source.sin4.sin_family != destination.sin4.sin_family) {
    throw std::runtime_error("The PROXY destination and source addresses must be of the same family");
  }

  const uint8_t command = 0x01;
  const uint8_t protocol = (source.isIPv4() ? 0x10 : 0x20) | (tcp ? 0x01 : 0x02);
  const size_t addrSize = source.isIPv4() ? sizeof(source.sin4.sin_addr.s_addr) : sizeof(source.sin6.sin6_addr.s6_addr);
  const uint16_t sourcePort = source.sin4.sin_port;
  const uint16_t destinationPort = destination.sin4.sin_port;

  size_t valuesSize = 0;
  for (const auto& value : values) {
    if (value.content.size() > std::numeric_limits<uint16_t>::max()) {
      throw std::runtime_error("The size of proxy protocol values is limited to " + std::to_string(std::numeric_limits<uint16_t>::max()) + ", trying to add a value of size " + std::to_string(value.content.size()));
    }
    valuesSize += sizeof(uint8_t) + sizeof(uint8_t) * 2 + value.content.size();
    if (valuesSize > std::numeric_limits<uint16_t>::max()) {
      throw std::runtime_error("The total size of proxy protocol values is limited to " + std::to_string(std::numeric_limits<uint16_t>::max()));
    }
  }

  /* size of the data that will come _after_ the minimal proxy protocol header */
  size_t additionalDataSize = (addrSize * 2) + sizeof(sourcePort) + sizeof(destinationPort) + valuesSize;
  if (additionalDataSize > std::numeric_limits<uint16_t>::max()) {
    throw std::runtime_error("The size of a proxy protocol header is limited to " + std::to_string(std::numeric_limits<uint16_t>::max()) + ", trying to send one of size " + std::to_string(additionalDataSize));
  }

  const uint16_t contentlen = htons(static_cast<uint16_t>(additionalDataSize));
  std::string ret;
  makeSimpleHeader(command, protocol, contentlen, additionalDataSize, ret);

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

  for (const auto& value : values) {
    uint16_t contentSize = htons(static_cast<uint16_t>(value.content.size()));
    ret.append(reinterpret_cast<const char*>(&value.type), sizeof(value.type));
    ret.append(reinterpret_cast<const char*>(&contentSize), sizeof(contentSize));
    ret.append(reinterpret_cast<const char*>(value.content.data()), value.content.size());
  }

  return ret;
}

/* returns: number of bytes consumed (positive) after successful parse
         or number of bytes missing (negative)
         or unfixable parse error (0)*/
template<typename Container> ssize_t isProxyHeaderComplete(const Container& header, bool* proxy, bool* tcp, size_t* addrSizeOut, uint8_t* protocolOut)
{
  static const size_t addr4Size = sizeof(ComboAddress::sin4.sin_addr.s_addr);
  static const size_t addr6Size = sizeof(ComboAddress::sin6.sin6_addr.s6_addr);
  size_t addrSize = 0;
  uint8_t versioncommand;
  uint8_t protocol;

  if (header.size() < s_proxyProtocolMinimumHeaderSize) {
    // this is too short to be a complete proxy header
    return -(s_proxyProtocolMinimumHeaderSize - header.size());
  }

  if (std::memcmp(&header.at(0), &proxymagic.at(0), proxymagic.size()) != 0) {
    // wrong magic, can not be a proxy header
    return 0;
  }

  versioncommand = header.at(12);
  /* check version */
  if (!(versioncommand & 0x20)) {
    return 0;
  }

  /* remove the version to get the command */
  uint8_t command = versioncommand & ~0x20;

  if (command == 0x01) {
    protocol = header.at(13);
    if ((protocol & 0xf) == 1) {
      if (tcp) {
        *tcp = true;
      }
    } else if ((protocol & 0xf) == 2) {
      if (tcp) {
        *tcp = false;
      }
    } else {
      return 0;
    }

    protocol = protocol >> 4;

    if (protocol == 1) {
      if (protocolOut) {
        *protocolOut = 4;
      }
      addrSize = addr4Size; // IPv4
    } else if (protocol == 2) {
      if (protocolOut) {
        *protocolOut = 6;
      }
      addrSize = addr6Size; // IPv6
    } else {
      // invalid protocol
      return 0;
    }

    if (addrSizeOut) {
      *addrSizeOut = addrSize;
    }

    if (proxy) {
      *proxy = true;
    }
  }
  else if (command == 0x00) {
    if (proxy) {
      *proxy = false;
    }
  }
  else {
    /* unsupported command */
    return 0;
  }

  uint16_t contentlen = (static_cast<uint8_t>(header.at(14)) << 8) + static_cast<uint8_t>(header.at(15));
  uint16_t expectedlen = 0;
  if (command != 0x00) {
    expectedlen = (addrSize * 2) + sizeof(ComboAddress::sin4.sin_port) + sizeof(ComboAddress::sin4.sin_port);
  }

  if (contentlen < expectedlen) {
    return 0;
  }

  if (header.size() < s_proxyProtocolMinimumHeaderSize + contentlen) {
    return -((s_proxyProtocolMinimumHeaderSize + contentlen) - header.size());
  }

  return s_proxyProtocolMinimumHeaderSize + contentlen;
}

/* returns: number of bytes consumed (positive) after successful parse
         or number of bytes missing (negative)
         or unfixable parse error (0)*/
template<typename Container> ssize_t parseProxyHeader(const Container& header, bool& proxy, ComboAddress& source, ComboAddress& destination, bool& tcp, std::vector<ProxyProtocolValue>& values)
{
  size_t addrSize = 0;
  uint8_t protocol = 0;
  ssize_t got = isProxyHeaderComplete(header, &proxy, &tcp, &addrSize, &protocol);
  if (got <= 0) {
    return got;
  }

  size_t pos = s_proxyProtocolMinimumHeaderSize;

  if (proxy) {
    source = makeComboAddressFromRaw(protocol, reinterpret_cast<const char*>(&header.at(pos)), addrSize);
    pos = pos + addrSize;
    destination = makeComboAddressFromRaw(protocol, reinterpret_cast<const char*>(&header.at(pos)), addrSize);
    pos = pos + addrSize;
    source.setPort((static_cast<uint8_t>(header.at(pos)) << 8) + static_cast<uint8_t>(header.at(pos+1)));
    pos = pos + sizeof(uint16_t);
    destination.setPort((static_cast<uint8_t>(header.at(pos)) << 8) + static_cast<uint8_t>(header.at(pos+1)));
    pos = pos + sizeof(uint16_t);
  }

  size_t remaining = got - pos;
  while (remaining >= (sizeof(uint8_t) + sizeof(uint16_t))) {
    /* we still have TLV values to parse */
    uint8_t type = static_cast<uint8_t>(header.at(pos));
    pos += sizeof(uint8_t);
    uint16_t len = (static_cast<uint8_t>(header.at(pos)) << 8) + static_cast<uint8_t>(header.at(pos + 1));
    pos += sizeof(uint16_t);

    if (len > 0) {
      if (len > (got - pos)) {
        return 0;
      }

      values.push_back({std::string(reinterpret_cast<const char*>(&header.at(pos)), len), type});
      pos += len;
    }
    else {
      values.push_back({"", type});
    }

    remaining = got - pos;
  }

  return pos;
}

#include "noinitvector.hh"
template ssize_t isProxyHeaderComplete<std::string>(const std::string& header, bool* proxy, bool* tcp, size_t* addrSizeOut, uint8_t* protocolOut);
template ssize_t isProxyHeaderComplete<PacketBuffer>(const PacketBuffer& header, bool* proxy, bool* tcp, size_t* addrSizeOut, uint8_t* protocolOut);
template ssize_t parseProxyHeader<std::string>(const std::string& header, bool& proxy, ComboAddress& source, ComboAddress& destination, bool& tcp, std::vector<ProxyProtocolValue>& values);
template ssize_t parseProxyHeader<PacketBuffer>(const PacketBuffer& header, bool& proxy, ComboAddress& source, ComboAddress& destination, bool& tcp, std::vector<ProxyProtocolValue>& values);
