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

#include "dnsdist-cache.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{

  if (size > std::numeric_limits<uint16_t>::max()) {
    return 0;
  }

  /* dnsdist's version */
  DNSDistPacketCache pcSkipCookies(10000);
  // By default, cookies are not hashed
  pcSkipCookies.setECSParsingEnabled(true);

  DNSDistPacketCache pcHashCookies(10000);
  pcHashCookies.setECSParsingEnabled(true);
  // Do not skip cookies
  pcHashCookies.setSkippedOptions({});

  try {
    uint16_t qtype;
    uint16_t qclass;
    unsigned int consumed;
    PacketBuffer vect(data, data + size);
    const DNSName qname(reinterpret_cast<const char*>(data), size, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    pcSkipCookies.getKey(qname.getStorage(), consumed, vect, false);
    pcHashCookies.getKey(qname.getStorage(), consumed, vect, false);
    boost::optional<Netmask> subnet;
    DNSDistPacketCache::getClientSubnet(vect, consumed, subnet);
  }
  catch (const std::exception& e) {
  }
  catch (const PDNSException& e) {
  }

  return 0;
}
