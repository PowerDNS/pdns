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

#include "dnsdist.hh"
#include "dnsdist-udp.hh"
#include "dnsdist-metrics.hh"
#include "dnsparser.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dolog.hh"
#include "dnsdist-configuration.hh"

namespace dnsdist::udp
{
static std::string contextToStr(Context context)
{
  if (context == Context::Frontend) {
    return "frontend";
  }
  if (context == Context::Backend) {
    return "backend";
  }

  return "";
}

void setUDPSocketBufferSizes(int socketDesc, const Logr::Logger& logger, Context context, const ComboAddress& addr)
{
  const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
  if (immutableConfig.d_socketUDPSendBuffer > 0) {
    try {
      setSocketSendBuffer(socketDesc, immutableConfig.d_socketUDPSendBuffer);
    }
    catch (const std::exception& e) {
      if (context == Context::Frontend) {
        SLOG(warnlog(e.what()),
             logger.error(Logr::Warning, e.what(), "Failed to raise send buffer size on UDP socket", "frontend.address", Logging::Loggable(addr)));
      }
    }
  }
  else {
    try {
      auto result = raiseSocketSendBufferToMax(socketDesc);
      if (result > 0 && context == Context::Frontend) {
        SLOG(infolog("Raised send buffer to %u for %s address '%s'", result, contextToStr(context), addr.toStringWithPort()),
             logger.info(Logr::Info, "Raised send buffer size", "frontend.address", Logging::Loggable(addr), "network.send_buffer_size", Logging::Loggable(result)));
      }
    }
    catch (const std::exception& e) {
      if (context == Context::Frontend) {
        SLOG(warnlog(e.what()),
             logger.error(Logr::Warning, e.what(), "Failed to raise send buffer size on UDP socket", "frontend.address", Logging::Loggable(addr)));
      }
    }
  }

  if (immutableConfig.d_socketUDPRecvBuffer > 0) {
    try {
      setSocketReceiveBuffer(socketDesc, immutableConfig.d_socketUDPRecvBuffer);
    }
    catch (const std::exception& e) {
      if (context == Context::Frontend) {
        SLOG(warnlog(e.what()),
             logger.error(Logr::Warning, e.what(), "Failed to raise receive buffer size on UDP socket", "frontend.address", Logging::Loggable(addr)));
      }
    }
  }
  else {
    try {
      auto result = raiseSocketReceiveBufferToMax(socketDesc);
      if (result > 0 && context == Context::Frontend) {
        SLOG(infolog("Raised receive buffer to %u for address '%s'", result, addr.toStringWithPort()),
             logger.info(Logr::Info, "Raised receive buffer size", "frontend.address", Logging::Loggable(addr), "buffer_size", Logging::Loggable(result)));
      }
    }
    catch (const std::exception& e) {
      if (context == Context::Frontend) {
        SLOG(warnlog(e.what()),
             logger.error(Logr::Warning, e.what(), "Failed to raise receive buffer size on UDP socket", "frontend.address", Logging::Loggable(addr)));
      }
    }
  }
}

void sendfromto(int sock, const PacketBuffer& buffer, const ComboAddress& from, const ComboAddress& dest)
{
  const int flags = 0;
  if (from.sin4.sin_family == 0) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto ret = sendto(sock, buffer.data(), buffer.size(), flags, reinterpret_cast<const struct sockaddr*>(&dest), dest.getSocklen());
    if (ret == -1) {
      int error = errno;
      VERBOSESLOG(infolog("Error sending UDP response to %s: %s", dest.toStringWithPort(), stringerror(error)),
                  dnsdist::logging::getTopLogger("sendfromto")->error(Logr::Info, error, "Error sending UDP response", "client.address", Logging::Loggable(dest)));
    }
    return;
  }

  try {
    sendMsgWithOptions(sock, buffer.data(), buffer.size(), &dest, &from, 0, 0);
  }
  catch (const std::exception& exp) {
    VERBOSESLOG(infolog("Error sending UDP response from %s to %s: %s", from.toStringWithPort(), dest.toStringWithPort(), exp.what()),
                dnsdist::logging::getTopLogger("sendfromto")->error(Logr::Info, exp.what(), "Error sending UDP response", "source.address", Logging::Loggable(from), "client.address", Logging::Loggable(dest)));
  }
}

void truncateTC(PacketBuffer& packet, size_t maximumSize, unsigned int qnameWireLength, bool addEDNSToSelfGeneratedResponses)
{
  try {
    bool hadEDNS = false;
    uint16_t payloadSize = 0;
    uint16_t zValue = 0;

    if (addEDNSToSelfGeneratedResponses) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      hadEDNS = getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(packet.data()), packet.size(), &payloadSize, &zValue);
    }

    packet.resize(static_cast<uint16_t>(sizeof(dnsheader) + qnameWireLength + DNS_TYPE_SIZE + DNS_CLASS_SIZE));
    dnsdist::PacketMangling::editDNSHeaderFromPacket(packet, [](dnsheader& header) {
      header.ancount = 0;
      header.arcount = 0;
      header.nscount = 0;
      return true;
    });

    if (hadEDNS) {
      addEDNS(packet, maximumSize, (zValue & EDNS_HEADER_FLAG_DO) != 0, payloadSize, 0);
    }
  }
  catch (...) {
    ++dnsdist::metrics::g_stats.truncFail;
  }
}

void handleResponseTC4UDPClient(DNSQuestion& dnsQuestion, uint16_t udpPayloadSize, PacketBuffer& response)
{
  if (udpPayloadSize != 0 && response.size() > udpPayloadSize) {
    VERBOSESLOG(infolog("Got a response of size %d while the initial UDP payload size was %d, truncating", response.size(), udpPayloadSize),
                dnsQuestion.getLogger()->withName("udp-response")->info(Logr::Info, "Got a UDP response larger than the initial UDP payload size, truncating", "dns.response.size", Logging::Loggable(response.size()), "dns.query.udp_payload_size", Logging::Loggable(udpPayloadSize)));

    truncateTC(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnsQuestion.ids.qname.wirelength(), dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses);
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
      header.tc = true;
      return true;
    });
  }
  else if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_truncateTC && dnsQuestion.getHeader()->tc) {
    truncateTC(response, dnsQuestion.getMaximumSize(), dnsQuestion.ids.qname.wirelength(), dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses);
  }
}

void handleResponseForUDPClient(InternalQueryState& ids, PacketBuffer& response, const std::shared_ptr<DownstreamState>& backend, bool isAsync, bool selfGenerated)
{
  DNSResponse dnsResponse(ids, response, backend);

  handleResponseTC4UDPClient(dnsResponse, ids.udpPayloadSize, response);

  /* when the answer is encrypted in place, we need to get a copy
     of the original header before encryption to fill the ring buffer */
  dnsheader cleartextDH{};
  memcpy(&cleartextDH, dnsResponse.getHeader().get(), sizeof(cleartextDH));

  if (!isAsync) {
    if (!processResponse(response, dnsResponse, ids.cs != nullptr && ids.cs->muted)) {
      return;
    }

    if (dnsResponse.isAsynchronous()) {
      return;
    }
  }

  ++dnsdist::metrics::g_stats.responses;
  if (ids.cs != nullptr) {
    ++ids.cs->responses;
  }

  bool muted = true;
  if (ids.cs != nullptr && !ids.cs->muted && !ids.isXSK()) {
    sendUDPResponse(ids.cs->udpFD, response, dnsResponse.ids.delayMsec, ids.hopLocal, ids.hopRemote);
    muted = false;
  }

  if (!selfGenerated) {
    auto latencyUs = ids.queryRealTime.udiff();
    if (!muted) {
      if (!ids.isXSK()) {
        VERBOSESLOG(infolog("Got answer from %s, relayed to %s (UDP), took %d us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), latencyUs),
                    dnsResponse.getLogger()->withName("udp-response")->info(Logr::Info, "Got answer from backend, relayed to client"));
      }
      else {
        VERBOSESLOG(infolog("Got answer from %s, relayed to %s (UDP via XSK), took %d us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), latencyUs),
                    dnsResponse.getLogger()->withName("udp-xsk-response")->info(Logr::Info, "Got answer from backend, relayed to client"));
      }
    }
    else {
      if (!ids.isXSK()) {
        VERBOSESLOG(infolog("Got answer from %s, NOT relayed to %s (UDP) since that frontend is muted, took %d us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), latencyUs),
                    dnsResponse.getLogger()->withName("udp-response")->info(Logr::Info, "Got answer from backend, NOT relayed to client since that frontend is muted"));
      }
      else {
        VERBOSESLOG(infolog("Got answer from %s, relayed to %s (UDP via XSK), took %d us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), latencyUs),
                    dnsResponse.getLogger()->withName("udp-xsk-response")->info(Logr::Info, "Got answer from backend, NOT relayed to client since that frontend is muted"));
      }
    }

    handleResponseSent(ids, latencyUs, dnsResponse.ids.origRemote, backend->d_config.remote, response.size(), cleartextDH, backend->getProtocol(), true);
  }
  else {
    handleResponseSent(ids, 0., dnsResponse.ids.origRemote, ComboAddress(), response.size(), cleartextDH, dnsdist::Protocol::DoUDP, false);
  }
}

std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion)
{
  dnsQuestion.ids.origID = dnsQuestion.getHeader()->id;
  return std::make_unique<dnsdist::udp::UDPCrossProtocolQuery>(std::move(dnsQuestion.getMutableData()), std::move(dnsQuestion.ids), nullptr);
}
} // namespace dnsdist::udp
