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

#include "dnsdist-udp.hh"
#include "dolog.hh"

namespace dnsdist::udp
{
void sendfromto(int sock, const PacketBuffer& buffer, const ComboAddress& from, const ComboAddress& dest)
{
  const int flags = 0;
  if (from.sin4.sin_family == 0) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto ret = sendto(sock, buffer.data(), buffer.size(), flags, reinterpret_cast<const struct sockaddr*>(&dest), dest.getSocklen());
    if (ret == -1) {
      int error = errno;
      vinfolog("Error sending UDP response to %s: %s", dest.toStringWithPort(), stringerror(error));
    }
    return;
  }

  try {
    sendMsgWithOptions(sock, buffer.data(), buffer.size(), &dest, &from, 0, 0);
  }
  catch (const std::exception& exp) {
    vinfolog("Error sending UDP response from %s to %s: %s", from.toStringWithPort(), dest.toStringWithPort(), exp.what());
  }
}
} // namespace dnsdist::udp
