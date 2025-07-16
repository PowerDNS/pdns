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

#include <map>
#include <memory>
#include <string>

#include "config.h"

#if defined(HAVE_DNS_OVER_QUIC) || defined(HAVE_DNS_OVER_HTTP3)

#include <quiche.h>

#include "dolog.hh"
#include "noinitvector.hh"
#include "sstuff.hh"
#include "libssl.hh"
#include "dnsdist-crypto.hh"

namespace dnsdist::doq
{

static const std::map<const std::string, int> s_available_cc_algorithms = {
  {"reno", QUICHE_CC_RENO},
  {"cubic", QUICHE_CC_CUBIC},
  {"bbr", QUICHE_CC_BBR},
};

using QuicheConnection = std::unique_ptr<quiche_conn, decltype(&quiche_conn_free)>;
using QuicheHTTP3Connection = std::unique_ptr<quiche_h3_conn, decltype(&quiche_h3_conn_free)>;
using QuicheConfig = std::shared_ptr<quiche_config>;
using QuicheHTTP3Config = std::unique_ptr<quiche_h3_config, decltype(&quiche_h3_config_free)>;

struct QuicheParams
{
  TLSConfig d_tlsConfig;
  std::string d_keyLogFile;
  uint64_t d_idleTimeout{5};
  uint64_t d_maxInFlight{65535};
  std::string d_ccAlgo{"reno"};
  std::string d_alpn;
};

/* from rfc9250 section-4.3 */
enum class DOQ_Error_Codes : uint64_t
{
  DOQ_NO_ERROR = 0,
  DOQ_INTERNAL_ERROR = 1,
  DOQ_PROTOCOL_ERROR = 2,
  DOQ_REQUEST_CANCELLED = 3,
  DOQ_EXCESSIVE_LOAD = 4,
  DOQ_UNSPECIFIED_ERROR = 5
};

/* Quiche type values do not match rfc9000 */
enum class DOQ_Packet_Types : uint8_t
{
  QUIC_PACKET_TYPE_INITIAL = 1,
  QUIC_PACKET_TYPE_RETRY = 2,
  QUIC_PACKET_TYPE_HANDSHAKE = 3,
  QUIC_PACKET_TYPE_ZERO_RTT = 4,
  QUIC_PACKET_TYPE_SHORT = 5,
  QUIC_PACKET_TYPE_VERSION_NEGOTIATION = 6
};

static constexpr size_t MAX_TOKEN_LEN = dnsdist::crypto::authenticated::getEncryptedSize(std::tuple_size<decltype(dnsdist::crypto::authenticated::Nonce::value)>{} /* nonce */ + sizeof(uint64_t) /* TTD */ + 16 /* IPv6 */ + QUICHE_MAX_CONN_ID_LEN);
static constexpr size_t MAX_DATAGRAM_SIZE = 1200;
static constexpr size_t LOCAL_CONN_ID_LEN = 16;
static constexpr std::array<uint8_t, 4> DOQ_ALPN{'\x03', 'd', 'o', 'q'};
static constexpr std::array<uint8_t, 3> DOH3_ALPN{'\x02', 'h', '3'};

void fillRandom(PacketBuffer& buffer, size_t size);
std::optional<PacketBuffer> getCID();
PacketBuffer mintToken(const PacketBuffer& dcid, const ComboAddress& peer);
std::optional<PacketBuffer> validateToken(const PacketBuffer& token, const ComboAddress& peer);
void handleStatelessRetry(Socket& sock, const PacketBuffer& clientConnID, const PacketBuffer& serverConnID, const ComboAddress& peer, const ComboAddress& localAddr, uint32_t version, PacketBuffer& buffer, bool socketBoundToAny);
void handleVersionNegotiation(Socket& sock, const PacketBuffer& clientConnID, const PacketBuffer& serverConnID, const ComboAddress& peer, const ComboAddress& localAddr, PacketBuffer& buffer, bool socketBoundToAny);
void flushEgress(Socket& sock, QuicheConnection& conn, const ComboAddress& peer, const ComboAddress& localAddr, PacketBuffer& buffer, bool socketBoundToAny);
void configureQuiche(QuicheConfig& config, const QuicheParams& params, bool isHTTP);
bool recvAsync(Socket& socket, PacketBuffer& buffer, ComboAddress& clientAddr, ComboAddress& localAddr);
std::string getSNIFromQuicheConnection(const QuicheConnection& conn);
};

#endif
