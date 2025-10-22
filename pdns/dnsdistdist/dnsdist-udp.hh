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

#include <cstddef>
#include <cstdint>
#include <limits>

#include "noinitvector.hh"
#include "iputils.hh"
#include "dnscrypt.hh"

namespace dnsdist::udp
{
// we are not willing to receive a bigger UDP response than that, no matter what
static constexpr size_t s_maxUDPResponsePacketSize{4096U};
static size_t const s_initialUDPPacketBufferSize = s_maxUDPResponsePacketSize + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
static_assert(s_initialUDPPacketBufferSize <= std::numeric_limits<uint16_t>::max(), "Packet size should fit in a uint16_t");

void sendfromto(int sock, const PacketBuffer& buffer, const ComboAddress& from, const ComboAddress& dest);
void truncateTC(PacketBuffer& packet, size_t maximumSize, unsigned int qnameWireLength, bool addEDNSToSelfGeneratedResponses);
} // namespace dnsdist::udp
