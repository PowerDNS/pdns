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
#ifndef PACKETCACHE_HH
#define PACKETCACHE_HH

#include "ednsoptions.hh"
#include "misc.hh"
#include "iputils.hh"

class PacketCache : public boost::noncopyable
{
protected:
  static uint32_t canHashPacket(const std::string& packet, bool skipECS=true)
  {
    uint32_t ret = 0;
    ret=burtle((const unsigned char*)packet.c_str() + 2, 10, ret); // rest of dnsheader, skip id
    size_t packetSize = packet.size();
    size_t pos = 12;
    const char* end = packet.c_str() + packetSize;
    const char* p = packet.c_str() + pos;

    for(; p < end && *p; ++p) { // XXX if you embed a 0 in your qname we'll stop lowercasing there
      const unsigned char l = dns_tolower(*p); // label lengths can safely be lower cased
      ret=burtle(&l, 1, ret);
    }                           // XXX the embedded 0 in the qname will break the subnet stripping

    struct dnsheader* dh = (struct dnsheader*)packet.c_str();
    const char* skipBegin = p;
    const char* skipEnd = p;
    /* we need at least 1 (final empty label) + 2 (QTYPE) + 2 (QCLASS)
       + OPT root label (1), type (2), class (2) and ttl (4)
       + the OPT RR rdlen (2)
       = 16
    */
    if(skipECS && ntohs(dh->arcount)==1 && (pos+16) < packetSize) {
      char* optionBegin = nullptr;
      size_t optionLen = 0;
      /* skip the final empty label (1), the qtype (2), qclass (2) */
      /* root label (1), type (2), class (2) and ttl (4) */
      int res = getEDNSOption((char*) p + 14, end - (p + 14), EDNSOptionCode::ECS, &optionBegin, &optionLen);
      if (res == 0) {
        skipBegin = optionBegin;
        skipEnd = optionBegin + optionLen;
      }
    }
    if (skipBegin > p) {
      // cerr << "Hashing from " << (p-packet.c_str()) << " for " << skipBegin-p << "bytes, end is at "<< end-packet.c_str() << endl;
      ret = burtle((const unsigned char*)p, skipBegin-p, ret);
    }
    if (skipEnd < end) {
      // cerr << "Hashing from " << (skipEnd-packet.c_str()) << " for " << end-skipEnd << "bytes, end is at " << end-packet.c_str() << endl;
      ret = burtle((const unsigned char*) skipEnd, end-skipEnd, ret);
    }

    return ret;
  }
};

#endif /* PACKETCACHE_HH */
