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

static const std::string s_quicRetryTokenKey = dnsdist::crypto::authenticated::newKey(false);

PacketBuffer mintToken(const PacketBuffer& dcid, const ComboAddress& peer)
{
  try {
    dnsdist::crypto::authenticated::Nonce nonce;
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
    const auto encryptedToken = dnsdist::crypto::authenticated::encryptSym(std::string_view(reinterpret_cast<const char*>(plainTextToken.data()), plainTextToken.size()), s_quicRetryTokenKey, nonce, false);
    // a bit sad, let's see if we can do better later
    PacketBuffer encryptedTokenPacket;
    encryptedTokenPacket.reserve(encryptedToken.size() + nonce.value.size());
    encryptedTokenPacket.insert(encryptedTokenPacket.begin(), encryptedToken.begin(), encryptedToken.end());
    encryptedTokenPacket.insert(encryptedTokenPacket.begin(), nonce.value.begin(), nonce.value.end());
    return encryptedTokenPacket;
  }
  catch (const std::exception& exp) {
    VERBOSESLOG(infolog("Error while minting DoH3 token: %s", exp.what()),
                dnsdist::logging::getTopLogger()->error(Logr::Info, exp.what(), "Error while minting DoH3 token"));
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
    dnsdist::crypto::authenticated::Nonce nonce;
    auto addrBytes = peer.toByteString();
    const uint64_t now = time(nullptr);
    const auto minimumSize = nonce.value.size() + sizeof(now) + addrBytes.size();
    if (token.size() <= minimumSize) {
      return std::nullopt;
    }

    memcpy(nonce.value.data(), token.data(), nonce.value.size());

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto cipher = std::string_view(reinterpret_cast<const char*>(&token.at(nonce.value.size())), token.size() - nonce.value.size());
    auto plainText = dnsdist::crypto::authenticated::decryptSym(cipher, s_quicRetryTokenKey, nonce, false);

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
    VERBOSESLOG(infolog("Error while validating DoH3 token: %s", exp.what()),
                dnsdist::logging::getTopLogger()->error(Logr::Info, exp.what(), "Error while validating DoH3 token"));
    return std::nullopt;
  }
}

static void sendFromTo(Socket& sock, const ComboAddress& peer, const ComboAddress& local, PacketBuffer& buffer, [[maybe_unused]] bool socketBoundToAny)
{
  /* we only want to specify the source address to use if we were able to
     either harvest it from the incoming packet, or if our socket is already
     bound to a specific address */
  bool setSourceAddress = local.sin4.sin_family != 0;
#if defined(__FreeBSD__) || defined(__DragonFly__)
  /* FreeBSD and DragonFlyBSD refuse the use of IP_SENDSRCADDR on a socket that is bound to a
     specific address, returning EINVAL in that case. */
  if (!socketBoundToAny) {
    setSourceAddress = false;
  }
#endif /* __FreeBSD__ || __DragonFly__ */

  if (!setSourceAddress) {
    const int flags = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto ret = sendto(sock.getHandle(), buffer.data(), buffer.size(), flags, reinterpret_cast<const struct sockaddr*>(&peer), peer.getSocklen());
    if (ret < 0) {
      auto error = errno;
      VERBOSESLOG(infolog("Error while sending QUIC datagram of size %d to %s: %s", buffer.size(), peer.toStringWithPort(), stringerror(error)),
                  dnsdist::logging::getTopLogger()->error(Logr::Info, error, "Error while sending QUIC datagram", "size", Logging::Loggable(buffer.size()), "destination", Logging::Loggable(peer)));
    }
    return;
  }

  try {
    sendMsgWithOptions(sock.getHandle(), buffer.data(), buffer.size(), &peer, &local, 0, 0);
  }
  catch (const std::exception& exp) {
    VERBOSESLOG(infolog("Error while sending QUIC datagram of size %d from %s to %s: %s", buffer.size(), local.toStringWithPort(), peer.toStringWithPort(), exp.what()),
                dnsdist::logging::getTopLogger()->error(Logr::Info, exp.what(), "Error while sending QUIC datagram", "size", Logging::Loggable(buffer.size()), "source", Logging::Loggable(local), "destination", Logging::Loggable(peer)));
  }
}

void handleStatelessRetry(Socket& sock, const PacketBuffer& clientConnID, const PacketBuffer& serverConnID, const ComboAddress& peer, const ComboAddress& localAddr, uint32_t version, PacketBuffer& buffer, bool socketBoundToAny)
{
  auto newServerConnID = getCID();
  if (!newServerConnID) {
    return;
  }

  auto token = mintToken(serverConnID, peer);

  buffer.resize(MAX_DATAGRAM_SIZE);
  auto written = quiche_retry(clientConnID.data(), clientConnID.size(),
                              serverConnID.data(), serverConnID.size(),
                              newServerConnID->data(), newServerConnID->size(),
                              token.data(), token.size(),
                              version,
                              buffer.data(), buffer.size());

  if (written < 0) {
    DEBUGLOG("failed to create retry packet " << written);
    return;
  }

  buffer.resize(static_cast<size_t>(written));
  sendFromTo(sock, peer, localAddr, buffer, socketBoundToAny);
}

void handleVersionNegotiation(Socket& sock, const PacketBuffer& clientConnID, const PacketBuffer& serverConnID, const ComboAddress& peer, const ComboAddress& localAddr, PacketBuffer& buffer, bool socketBoundToAny)
{
  buffer.resize(MAX_DATAGRAM_SIZE);

  auto written = quiche_negotiate_version(clientConnID.data(), clientConnID.size(),
                                          serverConnID.data(), serverConnID.size(),
                                          buffer.data(), buffer.size());

  if (written < 0) {
    DEBUGLOG("failed to create vneg packet " << written);
    return;
  }

  buffer.resize(static_cast<size_t>(written));
  sendFromTo(sock, peer, localAddr, buffer, socketBoundToAny);
}

void flushEgress(Socket& sock, QuicheConnection& conn, const ComboAddress& peer, const ComboAddress& localAddr, PacketBuffer& buffer, bool socketBoundToAny)
{
  buffer.resize(MAX_DATAGRAM_SIZE);
  quiche_send_info send_info;

  while (true) {
    auto written = quiche_conn_send(conn.get(), buffer.data(), buffer.size(), &send_info);
    if (written == QUICHE_ERR_DONE) {
      return;
    }

    if (written < 0) {
      return;
    }
    // FIXME pacing (as send_info.at should tell us when to send the packet) ?
    buffer.resize(static_cast<size_t>(written));
    sendFromTo(sock, peer, localAddr, buffer, socketBoundToAny);
  }
}

void configureQuiche(QuicheConfig& config, const QuicheParams& params, bool isHTTP)
{
  for (const auto& pair : params.d_tlsConfig.d_certKeyPairs) {
    auto res = quiche_config_load_cert_chain_from_pem_file(config.get(), pair.d_cert.c_str());
    if (res != 0) {
      throw std::runtime_error("Error loading the server certificate from '" + pair.d_cert + "': " + std::to_string(res));
    }
    if (pair.d_key) {
      res = quiche_config_load_priv_key_from_pem_file(config.get(), pair.d_key->c_str());
      if (res != 0) {
        throw std::runtime_error("Error loading the server key from '" + *(pair.d_key) + "': " + std::to_string(res));
      }
    }
  }

  {
    auto res = quiche_config_set_application_protos(config.get(),
                                                    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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

  // The number of bytes of incoming stream data to be buffered for each locally or remotely-initiated bidirectional stream
  quiche_config_set_initial_max_stream_data_bidi_local(config.get(), 8192);
  quiche_config_set_initial_max_stream_data_bidi_remote(config.get(), 8192);

  if (isHTTP) {
    /* see rfc9114 section 6.2. Unidirectional Streams:
       Each endpoint needs to create at least one unidirectional stream for the HTTP control stream.
       QPACK requires two additional unidirectional streams, and other extensions might require further streams.
       Therefore, the transport parameters sent by both clients and servers MUST allow the peer to create at least three
       unidirectional streams.
       These transport parameters SHOULD also provide at least 1,024 bytes of flow-control credit to each unidirectional stream.
    */
    quiche_config_set_initial_max_streams_uni(config.get(), 3U);
    quiche_config_set_initial_max_stream_data_uni(config.get(), 1024U);
  }

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

bool recvAsync(Socket& socket, PacketBuffer& buffer, ComboAddress& clientAddr, ComboAddress& localAddr)
{
  msghdr msgh{};
  iovec iov{};
  /* used by HarvestDestinationAddress */
  cmsgbuf_aligned cbuf;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), reinterpret_cast<char*>(&buffer.at(0)), buffer.size(), &clientAddr);

  ssize_t got = recvmsg(socket.getHandle(), &msgh, 0);
  if (got < 0) {
    int error = errno;
    if (error != EAGAIN) {
      throw NetworkError("Error in recvmsg: " + stringerror(error));
    }
    return false;
  }

  if ((msgh.msg_flags & MSG_TRUNC) != 0) {
    return false;
  }

  buffer.resize(static_cast<size_t>(got));

  if (HarvestDestinationAddress(&msgh, &localAddr)) {
    /* so it turns out that sometimes the kernel lies to us:
       the address is set to 0.0.0.0:0 which makes our sendfromto() use
       the wrong address. In that case it's better to let the kernel
       do the work by itself and use sendto() instead.
       This is indicated by setting the family to 0 which is acted upon
       in sendUDPResponse() and DelayedPacket::().
    */
    if (localAddr.isUnspecified()) {
      localAddr.sin4.sin_family = 0;
    }
  }
  else {
    localAddr.sin4.sin_family = 0;
  }

  return !buffer.empty();
}

std::string getSNIFromQuicheConnection([[maybe_unused]] const QuicheConnection& conn)
{
#if defined(HAVE_QUICHE_CONN_SERVER_NAME)
  const uint8_t* sniPtr = nullptr;
  size_t sniPtrSize = 0;
  quiche_conn_server_name(conn.get(), &sniPtr, &sniPtrSize);
  if (sniPtrSize > 0) {
    return std::string(reinterpret_cast<const char*>(sniPtr), sniPtrSize);
  }
#endif /* HAVE_QUICHE_CONN_SERVER_NAME */
  return {};
}
}

#endif
