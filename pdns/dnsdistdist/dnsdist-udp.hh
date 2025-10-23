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
#include "dnsdist.hh"
#include "dnsdist-tcp.hh"
#include "dnsparser.hh"

namespace dnsdist::udp
{
// we are not willing to receive a bigger UDP response than that, no matter what
static constexpr size_t s_maxUDPResponsePacketSize{4096U};
static size_t const s_initialUDPPacketBufferSize = s_maxUDPResponsePacketSize + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
static_assert(s_initialUDPPacketBufferSize <= std::numeric_limits<uint16_t>::max(), "Packet size should fit in a uint16_t");

void sendfromto(int sock, const PacketBuffer& buffer, const ComboAddress& from, const ComboAddress& dest);
void truncateTC(PacketBuffer& packet, size_t maximumSize, unsigned int qnameWireLength, bool addEDNSToSelfGeneratedResponses);
void handleResponseTC4UDPClient(DNSQuestion& dnsQuestion, uint16_t udpPayloadSize, PacketBuffer& response);
void handleResponseForUDPClient(InternalQueryState& ids, PacketBuffer& response, const std::shared_ptr<DownstreamState>& backend, bool isAsync, bool selfGenerated);

#if !defined(DISABLE_RECVMMSG) && defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
void queueResponse(const PacketBuffer& response, const ComboAddress& dest, const ComboAddress& remote, struct mmsghdr& outMsg, struct iovec* iov, cmsgbuf_aligned* cbuf);
#elif !defined(HAVE_RECVMMSG)
struct mmsghdr
{
  msghdr msg_hdr;
  unsigned int msg_len{0};
};
#endif

bool isUDPQueryAcceptable(ClientState& clientState, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, bool& expectProxyProtocol);
void processUDPQuery(ClientState& clientState, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, PacketBuffer& query, std::vector<mmsghdr>* responsesVect, unsigned int* queuedResponses, struct iovec* respIOV, cmsgbuf_aligned* respCBuf);

size_t getMaximumIncomingPacketSize(const ClientState& clientState);
size_t getInitialUDPPacketBufferSize(bool expectProxyProtocol);

#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
void MultipleMessagesUDPClientThread(ClientState* clientState);
#endif
#endif

void udpClientThread(std::vector<ClientState*> states);

class UDPTCPCrossQuerySender : public TCPQuerySender
{
public:
  UDPTCPCrossQuerySender() = default;
  UDPTCPCrossQuerySender(const UDPTCPCrossQuerySender&) = delete;
  UDPTCPCrossQuerySender& operator=(const UDPTCPCrossQuerySender&) = delete;
  UDPTCPCrossQuerySender(UDPTCPCrossQuerySender&&) = default;
  UDPTCPCrossQuerySender& operator=(UDPTCPCrossQuerySender&&) = default;
  ~UDPTCPCrossQuerySender() override = default;

  [[nodiscard]] bool active() const override
  {
    return true;
  }

  void handleResponse(const struct timeval& now, TCPResponse&& response) override
  {
    (void)now;
    if (!response.d_ds && !response.d_idstate.selfGenerated) {
      throw std::runtime_error("Passing a cross-protocol answer originated from UDP without a valid downstream");
    }

    auto& ids = response.d_idstate;

    dnsdist::udp::handleResponseForUDPClient(ids, response.d_buffer, response.d_ds, response.isAsync(), response.d_idstate.selfGenerated);
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    return handleResponse(now, std::move(response));
  }

  void notifyIOError([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
    // nothing to do
  }
};

class UDPCrossProtocolQuery : public CrossProtocolQuery
{
public:
  UDPCrossProtocolQuery(PacketBuffer&& buffer_, InternalQueryState&& ids_, std::shared_ptr<DownstreamState> backend) :
    CrossProtocolQuery(InternalQuery(std::move(buffer_), std::move(ids_)), backend)
  {
    auto& ids = query.d_idstate;
    const auto& buffer = query.d_buffer;

    if (ids.udpPayloadSize == 0) {
      uint16_t zValue = 0;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(buffer.data()), buffer.size(), &ids.udpPayloadSize, &zValue);
      if (!ids.dnssecOK) {
        ids.dnssecOK = (zValue & EDNS_HEADER_FLAG_DO) != 0;
      }
      if (ids.udpPayloadSize < 512) {
        ids.udpPayloadSize = 512;
      }
    }
  }
  UDPCrossProtocolQuery(const UDPCrossProtocolQuery&) = delete;
  UDPCrossProtocolQuery& operator=(const UDPCrossProtocolQuery&) = delete;
  UDPCrossProtocolQuery(UDPCrossProtocolQuery&&) = delete;
  UDPCrossProtocolQuery& operator=(UDPCrossProtocolQuery&&) = delete;
  ~UDPCrossProtocolQuery() override = default;

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    return s_sender;
  }

private:
  static std::shared_ptr<UDPTCPCrossQuerySender> s_sender;
};

std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion);

} // namespace dnsdist::udp
