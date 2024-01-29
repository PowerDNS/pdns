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

#include "xsk.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
#ifdef HAVE_XSK
  if (size > XskSocket::getFrameSize()) {
    return 0;
  }

  try {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast): packet data is usually mutable
    XskPacket packet(const_cast<uint8_t*>(data), size, size);
    if (packet.parse(false)) {
      const auto& dest = packet.getToAddr();
      const auto& orig = packet.getFromAddr();
      const auto* payload = packet.getPayloadData();
      auto capacity = packet.getCapacity();
      auto length = packet.getDataLen();
      auto frameLen = packet.getFrameLen();
      auto header = packet.cloneHeaderToPacketBuffer();
      auto buffer = packet.clonePacketBuffer();
      (void)dest;
      (void)orig;
      (void)payload;
      (void)capacity;
      (void)length;
      (void)frameLen;
    }
  }
  catch (const std::exception& e) {
  }
#endif /* HAVE_XSK */
  return 0;
}
