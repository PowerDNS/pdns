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

#include "config.h"

#include "ednssubnet.hh"

namespace
{
struct EDNSSubnetOptsWire
{
  uint16_t family;
  uint8_t sourceMask;
  uint8_t scopeMask;
} GCCPACKATTRIBUTE; // BRRRRR

}

bool getEDNSSubnetOptsFromString(const std::string& options, EDNSSubnetOpts* eso)
{
  return getEDNSSubnetOptsFromString(options.c_str(), options.length(), eso);
}

bool getEDNSSubnetOptsFromString(const char* options, unsigned int len, EDNSSubnetOpts* eso)
{
  EDNSSubnetOptsWire esow{};
  static_assert(sizeof(esow) == 4, "sizeof(EDNSSubnetOptsWire) must be 4 bytes");
  if (len < sizeof(esow)) {
    return false;
  }
  memcpy(&esow, options, sizeof(esow));
  esow.family = ntohs(esow.family);

  ComboAddress address;
  unsigned int octetsin = esow.sourceMask > 0 ? (((esow.sourceMask - 1) >> 3) + 1) : 0;

  if (esow.family == 1) {
    if (len != sizeof(esow) + octetsin) {
      return false;
    }
    if (octetsin > sizeof(address.sin4.sin_addr.s_addr)) {
      return false;
    }
    address.reset();
    address.sin4.sin_family = AF_INET;
    if (octetsin > 0) {
      memcpy(&address.sin4.sin_addr.s_addr, options + sizeof(esow), octetsin); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
  }
  else if (esow.family == 2) {
    if (len != sizeof(esow) + octetsin) {
      return false;
    }
    if (octetsin > sizeof(address.sin6.sin6_addr.s6_addr)) {
      return false;
    }

    address.reset();
    address.sin4.sin_family = AF_INET6;
    if (octetsin > 0) {
      memcpy(&address.sin6.sin6_addr.s6_addr, options + sizeof(esow), octetsin); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    }
  }
  else {
    return false;
  }
  eso->source = Netmask(address, esow.sourceMask);
  /* 'address' has more bits set (potentially) than scopeMask. This leads to odd looking netmasks that promise
     more precision than they have. For this reason we truncate the address to scopeMask bits */

  address.truncate(esow.scopeMask); // truncate will not throw for odd scopeMasks
  eso->scope = Netmask(address, esow.scopeMask);

  return true;
}

std::string makeEDNSSubnetOptsString(const EDNSSubnetOpts& eso)
{
  std::string ret;
  EDNSSubnetOptsWire esow{};
  uint16_t family = htons(eso.source.getNetwork().sin4.sin_family == AF_INET ? 1 : 2);
  esow.family = family;
  esow.sourceMask = eso.source.getBits();
  esow.scopeMask = eso.scope.getBits();
  // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
  ret.assign(reinterpret_cast<const char*>(&esow), sizeof(esow));
  int octetsout = ((esow.sourceMask - 1) >> 3) + 1;

  ComboAddress src = eso.source.getNetwork();
  src.truncate(esow.sourceMask);

  if (family == htons(1)) {
    ret.append(reinterpret_cast<const char*>(&src.sin4.sin_addr.s_addr), octetsout);
  }
  else {
    ret.append(reinterpret_cast<const char*>(&src.sin6.sin6_addr.s6_addr), octetsout);
  }
  // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  return ret;
}
