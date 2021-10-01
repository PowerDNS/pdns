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
  static uint32_t hashAfterQname(const pdns_string_view& packet, uint32_t currentHash, size_t pos, const std::unordered_set<uint16_t>& optionsToSkip = {EDNSOptionCode::COOKIE})
  {
    const size_t packetSize = packet.size();
    assert(packetSize >= sizeof(dnsheader));

    /* we need at least 2 (QTYPE) + 2 (QCLASS)

       + OPT root label (1), type (2), class (2) and ttl (4)
       + the OPT RR rdlen (2)
       = 15
    */
    const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(packet.data());
    if (ntohs(dh->qdcount) != 1 || ntohs(dh->ancount) != 0 || ntohs(dh->nscount) != 0 || ntohs(dh->arcount) != 1 || (pos + 15) >= packetSize) {
      if (packetSize > pos) {
        currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), packetSize - pos, currentHash);
      }
      return currentHash;
    }

    currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), 15, currentHash);
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
        currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), packetSize - pos, currentHash);
      }
      return currentHash;
    }

    uint16_t rdataRead = 0;
    uint16_t optionCode;
    uint16_t optionLen;

    while (pos < packetSize && rdataRead < rdLen && getNextEDNSOption(&packet.at(pos), rdLen - rdataRead, optionCode, optionLen)) {
      if (optionLen > (rdLen - rdataRead - 4)) {
        if (packetSize > pos) {
          currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), packetSize - pos, currentHash);
        }
        return currentHash;
      }

      if (optionsToSkip.count(optionCode) == 0) {
        /* hash the option code, length and content */
        currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), 4 + optionLen, currentHash);
      }
      else {
        /* skip option: hash only its code and length */
        currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), 4, currentHash);
      }

      pos += 4 + optionLen;
      rdataRead += 4 + optionLen;
    }

    if (pos < packetSize) {
      currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(pos)), packetSize - pos, currentHash);
    }

    return currentHash;
  }

  static uint32_t hashHeaderAndQName(const std::string& packet, size_t& pos)
  {
    uint32_t currentHash = 0;
    const size_t packetSize = packet.size();
    assert(packetSize >= sizeof(dnsheader));
    currentHash = burtle(reinterpret_cast<const unsigned char*>(&packet.at(2)), sizeof(dnsheader) - 2, currentHash); // rest of dnsheader, skip id
    pos = sizeof(dnsheader);

    for (; pos < packetSize; ) {
      const unsigned char labelLen = static_cast<unsigned char>(packet.at(pos));
      currentHash = burtle(&labelLen, 1, currentHash);
      ++pos;
      if (labelLen == 0) {
        break;
      }

      for (size_t idx = 0; idx < labelLen && pos < packetSize; ++idx, ++pos) {
        const unsigned char l = dns_tolower(packet.at(pos));
        currentHash = burtle(&l, 1, currentHash);
      }
    }

    return currentHash;
  }

  /* hash the packet from the beginning, including the qname. This skips:
     - the query ID ;
     - EDNS Cookie options, if any ;
     - Any given option code present in optionsToSkip
  */
  static uint32_t canHashPacket(const std::string& packet, const std::unordered_set<uint16_t>& optionsToSkip = {EDNSOptionCode::COOKIE})
  {
    size_t pos = 0;
    uint32_t currentHash = hashHeaderAndQName(packet, pos);
    size_t packetSize = packet.size();

    if (pos >= packetSize) {
      return currentHash;
    }

    return hashAfterQname(packet, currentHash, pos, optionsToSkip);
  }

  static bool queryHeaderMatches(const std::string& cachedQuery, const std::string& query)
  {
    if (cachedQuery.size() != query.size()) {
      return false;
    }

    return (cachedQuery.compare(/* skip the ID */ 2, sizeof(dnsheader) - 2, query, 2, sizeof(dnsheader) - 2) == 0);
  }

  static bool queryMatches(const std::string& cachedQuery, const std::string& query, const DNSName& qname, const std::unordered_set<uint16_t>& optionsToIgnore)
  {
    const size_t querySize = query.size();
    const size_t cachedQuerySize = cachedQuery.size();
    if (querySize != cachedQuerySize) {
      return false;
    }

    if (!queryHeaderMatches(cachedQuery, query)) {
      return false;
    }

    size_t pos = sizeof(dnsheader) + qname.wirelength();

    /* we need at least 2 (QTYPE) + 2 (QCLASS)
       + OPT root label (1), type (2), class (2) and ttl (4)
       + the OPT RR rdlen (2)
       = 15
    */
    const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(query.data());
    if (ntohs(dh->qdcount) != 1 || ntohs(dh->ancount) != 0 || ntohs(dh->nscount) != 0 || ntohs(dh->arcount) != 1 || (pos + 15) >= querySize || optionsToIgnore.empty()) {
      return cachedQuery.compare(pos, cachedQuerySize - pos, query, pos, querySize - pos) == 0;
    }

    /* compare up to the first option, if any */
    if (cachedQuery.compare(pos, 15, query, pos, 15) != 0) {
      return false;
    }

    /* skip the qtype (2), qclass (2) */
    /* root label (1), type (2), class (2) and ttl (4) */
    /* already compared above */
    pos += 13;

    const uint16_t rdLen = ((static_cast<unsigned char>(query.at(pos)) * 256) + static_cast<unsigned char>(query.at(pos + 1)));
    /* skip the rd length */
    /* already compared above */
    pos += sizeof(uint16_t);

    if (rdLen > (querySize - pos)) {
      /* something is wrong, let's just compare everything */
      return cachedQuery.compare(pos, cachedQuerySize - pos, query, pos, querySize - pos) == 0;
    }

    uint16_t rdataRead = 0;
    uint16_t optionCode;
    uint16_t optionLen;

    while (pos < querySize && rdataRead < rdLen && getNextEDNSOption(&query.at(pos), rdLen - rdataRead, optionCode, optionLen)) {
      if (optionLen > (rdLen - rdataRead)) {
        return cachedQuery.compare(pos, cachedQuerySize - pos, query, pos, querySize - pos) == 0;
      }

      /* compare the option code and length */
      if (cachedQuery.compare(pos, 4, query, pos, 4) != 0) {
        return false;
      }
      pos += 4;
      rdataRead += 4;

      if (optionLen > 0 && optionsToIgnore.count(optionCode) == 0) {
        if (cachedQuery.compare(pos, optionLen, query, pos, optionLen) != 0) {
          return false;
        }
      }
      pos += optionLen;
      rdataRead += optionLen;
    }

    if (pos >= querySize) {
        return true;
    }

    return cachedQuery.compare(pos, cachedQuerySize - pos, query, pos, querySize - pos) == 0;
  }

};
