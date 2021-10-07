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

#include "packetcache.hh"
#include "statbag.hh"

StatBag S;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {

  if (size > std::numeric_limits<uint16_t>::max() || size < sizeof(dnsheader)) {
    return 0;
  }

  std::string input(reinterpret_cast<const char*>(data), size);

  /* auth's version */
  try {
    static const std::unordered_set<uint16_t> optionsToIgnore{ EDNSOptionCode::COOKIE };

    PacketCache::canHashPacket(input, optionsToIgnore);
    DNSName qname(input.data(), input.size(), sizeof(dnsheader), false);
    PacketCache::queryMatches(input, input, qname, optionsToIgnore);
  }
  catch(const std::exception& e) {
  }
  catch(const PDNSException& e) {
  }

  /* recursor's version */
  try {
    static const std::unordered_set<uint16_t> optionsToIgnore{ EDNSOptionCode::COOKIE, EDNSOptionCode::ECS };

    PacketCache::canHashPacket(input, optionsToIgnore);
    DNSName qname(input.data(), input.size(), sizeof(dnsheader), false);
    PacketCache::queryMatches(input, input, qname, optionsToIgnore);
  }
  catch(const std::exception& e) {
  }
  catch(const PDNSException& e) {
  }

  return 0;
}
