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

#include "dnsdist-xpf.hh"

#include "dnsparser.hh"
#include "xpf.hh"

bool addXPF(DNSQuestion& dq, uint16_t optionCode)
{
  std::string payload = generateXPFPayload(dq.tcp, *dq.remote, *dq.local);
  uint8_t root = '\0';
  dnsrecordheader drh;
  drh.d_type = htons(optionCode);
  drh.d_class = htons(QClass::IN);
  drh.d_ttl = 0;
  drh.d_clen = htons(payload.size());
  size_t recordHeaderLen = sizeof(root) + sizeof(drh);

  if (!dq.hasRoomFor(payload.size() + recordHeaderLen)) {
    return false;
  }

  size_t xpfSize = sizeof(root) + sizeof(drh) + payload.size();
  auto& data = dq.getMutableData();
  uint32_t realPacketLen = getDNSPacketLength(reinterpret_cast<const char*>(data.data()), data.size());
  data.resize(realPacketLen + xpfSize);

  size_t pos = realPacketLen;
  memcpy(reinterpret_cast<char*>(&data.at(pos)), &root, sizeof(root));
  pos += sizeof(root);
  memcpy(reinterpret_cast<char*>(&data.at(pos)), &drh, sizeof(drh));
  pos += sizeof(drh);
  memcpy(reinterpret_cast<char*>(&data.at(pos)), payload.data(), payload.size());
  pos += payload.size();

  dq.getHeader()->arcount = htons(ntohs(dq.getHeader()->arcount) + 1);

  return true;
}
