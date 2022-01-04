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
#include "dnsdist-dnsparser.hh"
#include "dnsparser.hh"

namespace dnsdist
{
DNSPacketOverlay::DNSPacketOverlay(const std::string_view& packet)
{
  if (packet.size() < sizeof(dnsheader)) {
    throw std::runtime_error("Packet is too small for a DNS packet");
  }

  memcpy(&d_header, packet.data(), sizeof(dnsheader));
  uint64_t numRecords = ntohs(d_header.ancount) + ntohs(d_header.nscount) + ntohs(d_header.arcount);
  d_records.reserve(numRecords);

  try
  {
    PacketReader reader(pdns_string_view(reinterpret_cast<const char*>(packet.data()), packet.size()));

    for (uint16_t n = 0; n < ntohs(d_header.qdcount) ; ++n) {
      reader.xfrName(d_qname);
      reader.xfrType(d_qtype);
      reader.xfrType(d_qclass);
    }

    for (uint64_t n = 0; n < numRecords; ++n) {
      Record rec;
      reader.xfrName(rec.d_name);
      rec.d_place = n < ntohs(d_header.ancount) ? DNSResourceRecord::ANSWER : (n < (ntohs(d_header.ancount) + ntohs(d_header.nscount)) ? DNSResourceRecord::AUTHORITY : DNSResourceRecord::ADDITIONAL);
      reader.xfrType(rec.d_type);
      reader.xfrType(rec.d_class);
      reader.xfr32BitInt(rec.d_ttl);
      reader.xfr16BitInt(rec.d_contentLength);
      rec.d_contentOffset = reader.getPosition();
      reader.skip(rec.d_contentLength);
      d_records.push_back(std::move(rec));
    }
  }
  catch (const std::exception& e) {
    throw std::runtime_error("Unable to parse DNS packet: " + std::string(e.what()));
  }
  catch (const PDNSException& e) {
    throw std::runtime_error("Unable to parse DNS packet: " + e.reason);
  }
  catch (...) {
    throw std::runtime_error("Unable to parse DNS packet");
  }
}
}

