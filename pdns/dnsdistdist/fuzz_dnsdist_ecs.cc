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

#include <limits>

#include "dnsdist-ecs.hh"
#include "dnsname.hh"
#include "dns.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size > std::numeric_limits<uint16_t>::max()) {
    return 0;
  }

  const PacketBuffer packet(data, data + size);

  // Wire-format EDNS/OPT parsing on the raw packet.
  try {
    EDNS0Record edns0{};
    getEDNS0Record(packet, edns0);
  }
  catch (...) {
  }

  try {
    uint16_t optStart = 0;
    size_t optLen = 0;
    bool last = false;
    if (locateEDNSOptRR(packet, &optStart, &optLen, &last) == 0) {
      size_t optContentStart = 0;
      uint16_t optContentLen = 0;
      isEDNSOptionInOpt(packet, optStart, optLen, EDNSOptionCode::ECS,
                        &optContentStart, &optContentLen);
    }
  }
  catch (...) {
  }

  try {
    PacketBuffer newContent;
    rewriteResponseWithoutEDNS(packet, newContent);
  }
  catch (...) {
  }

  try {
    PacketBuffer newContent;
    rewriteResponseWithoutEDNSOption(packet, EDNSOptionCode::ECS, newContent);
  }
  catch (...) {
  }

  // ECS add/replace; needs the question name's wire length.
  try {
    uint16_t qtype = 0;
    uint16_t qclass = 0;
    unsigned int consumed = 0;
    const DNSName qname(reinterpret_cast<const char*>(data), size,
                        sizeof(dnsheader), false, &qtype, &qclass, &consumed);

    uint16_t optRDPosition = 0;
    size_t remaining = 0;
    dnsdist::getEDNSOptionsStart(packet, consumed, &optRDPosition, &remaining);

    PacketBuffer mutablePacket(packet);
    bool ednsAdded = false;
    bool ecsAdded = false;
    std::string newECSOption;
    const ComboAddress source("192.0.2.1");
    generateECSOption(source, newECSOption, 24);
    handleEDNSClientSubnet(mutablePacket, mutablePacket.size() + 512, consumed,
                           ednsAdded, ecsAdded, true, newECSOption);
  }
  catch (...) {
  }

  return 0;
}
