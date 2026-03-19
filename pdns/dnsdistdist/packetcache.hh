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
#pragma once

#include "dnsdist-cache.hh"
#include "ednsoptions.hh"
#include "misc.hh"
#include "iputils.hh"

class PacketCache : public boost::noncopyable
{
public:

  /* hash the packet from the provided position, which should point right after tje qname. This skips:
     - the query ID ;
     - EDNS Cookie options, if any ;
     - Any given option code present in optionsToSkip
  */
  static void hashAfterQname(const std::string_view& packet, CacheKey& key, size_t pos, const std::unordered_set<uint16_t>& optionsToSkip = {EDNSOptionCode::COOKIE}, const std::vector<uint16_t>& payloadRanks = {})
  {
    const size_t packetSize = packet.size();
    assert(packetSize >= sizeof(dnsheader));

    /* we need at least 2 (QTYPE) + 2 (QCLASS)

       + OPT root label (1), type (2), class (2) and ttl (4)
       + the OPT RR rdlen (2)
       = 15
    */
    const dnsheader_aligned dnsheaderdata(packet.data());
    const struct dnsheader *dh = dnsheaderdata.get();
    if (ntohs(dh->qdcount) != 1 || ntohs(dh->ancount) != 0 || ntohs(dh->nscount) != 0 || ntohs(dh->arcount) != 1 || (pos + 15) > packetSize) {
      if (packetSize > pos) {
        key.update(&packet.at(pos), packetSize - pos);
      }
      return;
    }

    if (payloadRanks.empty()) {
      key.update(&packet.at(pos), 15);
    }
    else {
      std::vector<unsigned char> optrr(packet.begin() + pos, packet.begin() + pos + 15);
      uint16_t bufSize = optrr.at(7) * 256 + optrr.at(8);
      auto it = std::upper_bound(payloadRanks.begin(), payloadRanks.end(), bufSize);
      if (it != payloadRanks.begin()) {
        it--;
        optrr[7] = (*it) >> 8;
        optrr[8] = (*it) & 0xff;
      }
      key.update(reinterpret_cast<const char*>(&optrr.at(0)), 15);
    }
    if ( (pos + 15) == packetSize ) {
      return;
    }

    /* skip the qtype (2), qclass (2) */
    /* root label (1), type (2), class (2) and ttl (4) */
    /* already hashed above */
    pos += 13;

    const uint16_t rdLen = ((static_cast<uint16_t>(packet.at(pos)) * 256) + static_cast<uint16_t>(packet.at(pos + 1)));
    /* skip the rd length */
    /* already hashed above */
    pos += 2;

    if (rdLen > (packetSize - pos)) {
      if (pos < packetSize) {
        key.update(&packet.at(pos), packetSize - pos);
      }
      return;
    }

    uint16_t rdataRead = 0;
    uint16_t optionCode;
    uint16_t optionLen;

    while (pos < packetSize && rdataRead < rdLen && getNextEDNSOption(&packet.at(pos), rdLen - rdataRead, optionCode, optionLen)) {
      if (optionLen > (rdLen - rdataRead - 4)) {
        if (packetSize > pos) {
          key.update(&packet.at(pos), packetSize - pos);
        }
        return;
      }

      if (optionsToSkip.count(optionCode) == 0) {
        /* hash the option code, length and content */
        key.update(&packet.at(pos), static_cast<size_t>(4 + optionLen));
      }
      else {
        /* skip option: hash only its code and length */
        key.update(&packet.at(pos), 4);
      }

      pos += 4 + optionLen;
      rdataRead += 4 + optionLen;
    }

    if (pos < packetSize) {
      key.update(&packet.at(pos), packetSize - pos);
    }
  }

};
