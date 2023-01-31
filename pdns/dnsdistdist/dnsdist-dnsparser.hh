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

#include "dnsparser.hh"

namespace dnsdist
{
class DNSPacketOverlay
{
public:
  DNSPacketOverlay(const std::string_view& packet);

  struct Record
  {
    DNSName d_name;
    uint32_t d_ttl;
    uint16_t d_type;
    uint16_t d_class;
    uint16_t d_contentLength;
    uint16_t d_contentOffset;
    DNSResourceRecord::Place d_place;
  };

  DNSName d_qname;
  std::vector<Record> d_records;
  uint16_t d_qtype;
  uint16_t d_qclass;
  dnsheader d_header;
};

/* Rewrite, if they are exactly equal to 'from', the qname and owner name of any record
 * to 'to'. Since that might break DNS name pointers, the whole payload is rewritten,
 * and the operation may fail if there is at least one unsupported record in the payload,
 * because it could contain pointers that would not be rewritten.
 */
bool changeNameInDNSPacket(PacketBuffer& initialPacket, const DNSName& from, const DNSName& to);
}
