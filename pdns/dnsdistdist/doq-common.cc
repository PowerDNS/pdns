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

#include "doq-common.hh"
#include "dnsdist-random.hh"
#include "libssl.hh"

#ifdef HAVE_DNS_OVER_QUIC

#if 0
#define DEBUGLOG_ENABLED
#define DEBUGLOG(x) std::cerr << x << std::endl;
#else
#define DEBUGLOG(x)
#endif

namespace dnsdist::doq
{

static const std::string s_quicRetryTokenKey = newKey(false);

PacketBuffer mintToken(const PacketBuffer& dcid, const ComboAddress& peer)
{
  try {
    SodiumNonce nonce;
    nonce.init();

    const auto addrBytes = peer.toByteString();
    // this token will be valid for 60s
    const uint64_t ttd = time(nullptr) + 60U;
    PacketBuffer plainTextToken;
    plainTextToken.reserve(sizeof(ttd) + addrBytes.size() + dcid.size());
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    plainTextToken.insert(plainTextToken.end(), reinterpret_cast<const uint8_t*>(&ttd), reinterpret_cast<const uint8_t*>(&ttd) + sizeof(ttd));
    plainTextToken.insert(plainTextToken.end(), addrBytes.begin(), addrBytes.end());
    plainTextToken.insert(plainTextToken.end(), dcid.begin(), dcid.end());
    //	NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto encryptedToken = sodEncryptSym(std::string_view(reinterpret_cast<const char*>(plainTextToken.data()), plainTextToken.size()), s_quicRetryTokenKey, nonce, false);
    // a bit sad, let's see if we can do better later
    auto encryptedTokenPacket = PacketBuffer(encryptedToken.begin(), encryptedToken.end());
    encryptedTokenPacket.insert(encryptedTokenPacket.begin(), nonce.value.begin(), nonce.value.end());
    return encryptedTokenPacket;
  }
  catch (const std::exception& exp) {
    vinfolog("Error while minting DoH3 token: %s", exp.what());
    throw;
  }
}

void fillRandom(PacketBuffer& buffer, size_t size)
{
  buffer.reserve(size);
  while (size > 0) {
    buffer.insert(buffer.end(), dnsdist::getRandomValue(std::numeric_limits<uint8_t>::max()));
    --size;
  }
}

std::optional<PacketBuffer> getCID()
{
  PacketBuffer buffer;

  fillRandom(buffer, LOCAL_CONN_ID_LEN);

  return buffer;
}

// returns the original destination ID if the token is valid, nothing otherwise
std::optional<PacketBuffer> validateToken(const PacketBuffer& token, const ComboAddress& peer)
{
  try {
    SodiumNonce nonce;
    auto addrBytes = peer.toByteString();
    const uint64_t now = time(nullptr);
    const auto minimumSize = nonce.value.size() + sizeof(now) + addrBytes.size();
    if (token.size() <= minimumSize) {
      return std::nullopt;
    }

    memcpy(nonce.value.data(), token.data(), nonce.value.size());

    //	NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto cipher = std::string_view(reinterpret_cast<const char*>(&token.at(nonce.value.size())), token.size() - nonce.value.size());
    auto plainText = sodDecryptSym(cipher, s_quicRetryTokenKey, nonce, false);

    if (plainText.size() <= sizeof(now) + addrBytes.size()) {
      return std::nullopt;
    }

    uint64_t ttd{0};
    memcpy(&ttd, plainText.data(), sizeof(ttd));
    if (ttd < now) {
      return std::nullopt;
    }

    if (std::memcmp(&plainText.at(sizeof(ttd)), &*addrBytes.begin(), addrBytes.size()) != 0) {
      return std::nullopt;
    }
    // NOLINTNEXTLINE(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions)
    return PacketBuffer(plainText.begin() + (sizeof(ttd) + addrBytes.size()), plainText.end());
  }
  catch (const std::exception& exp) {
    vinfolog("Error while validating DoH3 token: %s", exp.what());
    return std::nullopt;
  }
}

void handleStatelessRetry(Socket& sock, const PacketBuffer& clientConnID, const PacketBuffer& serverConnID, const ComboAddress& peer, uint32_t version)
{
  auto newServerConnID = getCID();
  if (!newServerConnID) {
    return;
  }

  auto token = mintToken(serverConnID, peer);

  PacketBuffer out(MAX_DATAGRAM_SIZE);
  auto written = quiche_retry(clientConnID.data(), clientConnID.size(),
                              serverConnID.data(), serverConnID.size(),
                              newServerConnID->data(), newServerConnID->size(),
                              token.data(), token.size(),
                              version,
                              out.data(), out.size());

  if (written < 0) {
    DEBUGLOG("failed to create retry packet " << written);
    return;
  }

  out.resize(written);
  sock.sendTo(std::string(out.begin(), out.end()), peer);
}

void handleVersionNegociation(Socket& sock, const PacketBuffer& clientConnID, const PacketBuffer& serverConnID, const ComboAddress& peer)
{
  PacketBuffer out(MAX_DATAGRAM_SIZE);

  auto written = quiche_negotiate_version(clientConnID.data(), clientConnID.size(),
                                          serverConnID.data(), serverConnID.size(),
                                          out.data(), out.size());

  if (written < 0) {
    DEBUGLOG("failed to create vneg packet " << written);
    return;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  sock.sendTo(reinterpret_cast<const char*>(out.data()), written, peer);
}

void flushEgress(Socket& sock, QuicheConnection& conn, const ComboAddress& peer)
{
  std::array<uint8_t, MAX_DATAGRAM_SIZE> out{};
  quiche_send_info send_info;

  while (true) {
    auto written = quiche_conn_send(conn.get(), out.data(), out.size(), &send_info);
    if (written == QUICHE_ERR_DONE) {
      return;
    }

    if (written < 0) {
      return;
    }
    // FIXME pacing (as send_info.at should tell us when to send the packet) ?
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    sock.sendTo(reinterpret_cast<const char*>(out.data()), written, peer);
  }
}

void configureQuiche(QuicheConfig& config, const QuicheParams& params)
{
  for (const auto& pair : params.d_tlsConfig.d_certKeyPairs) {
    auto res = quiche_config_load_cert_chain_from_pem_file(config.get(), pair.d_cert.c_str());
    if (res != 0) {
      throw std::runtime_error("Error loading the server certificate: " + std::to_string(res));
    }
    if (pair.d_key) {
      res = quiche_config_load_priv_key_from_pem_file(config.get(), pair.d_key->c_str());
      if (res != 0) {
        throw std::runtime_error("Error loading the server key: " + std::to_string(res));
      }
    }
  }

  {
    auto res = quiche_config_set_application_protos(config.get(),
                                                    reinterpret_cast<const uint8_t*>(params.d_alpn.data()),
                                                    params.d_alpn.size());
    if (res != 0) {
      throw std::runtime_error("Error setting ALPN: " + std::to_string(res));
    }
  }

  quiche_config_set_max_idle_timeout(config.get(), params.d_idleTimeout * 1000);
  /* maximum size of an outgoing packet, which means the buffer we pass to quiche_conn_send() should be at least that big */
  quiche_config_set_max_send_udp_payload_size(config.get(), MAX_DATAGRAM_SIZE);
  quiche_config_set_max_recv_udp_payload_size(config.get(), MAX_DATAGRAM_SIZE);

  // The number of concurrent remotely-initiated bidirectional streams to be open at any given time
  // https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_streams_bidi
  // 0 means none will get accepted, that's why we have a default value of 65535
  quiche_config_set_initial_max_streams_bidi(config.get(), params.d_maxInFlight);

  // The number of bytes of incoming stream data to be buffered for each localy or remotely-initiated bidirectional stream
  quiche_config_set_initial_max_stream_data_bidi_local(config.get(), 8192);
  quiche_config_set_initial_max_stream_data_bidi_remote(config.get(), 8192);

  // The number of total bytes of incoming stream data to be buffered for the whole connection
  // https://docs.rs/quiche/latest/quiche/struct.Config.html#method.set_initial_max_data
  quiche_config_set_initial_max_data(config.get(), 8192 * params.d_maxInFlight);
  if (!params.d_keyLogFile.empty()) {
    quiche_config_log_keys(config.get());
  }

  auto algo = dnsdist::doq::s_available_cc_algorithms.find(params.d_ccAlgo);
  if (algo != dnsdist::doq::s_available_cc_algorithms.end()) {
    quiche_config_set_cc_algorithm(config.get(), static_cast<enum quiche_cc_algorithm>(algo->second));
  }

  {
    PacketBuffer resetToken;
    fillRandom(resetToken, 16);
    quiche_config_set_stateless_reset_token(config.get(), resetToken.data());
  }
}

};

#endif
