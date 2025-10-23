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
#include "dnsdist-dnscrypt.hh"
#include "dnsdist-metrics.hh"
#include "dnsparser.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-proxy-protocol.hh"
#include "threadname.hh"
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
  {
    if (udpPayloadSize != 0 && response.size() > udpPayloadSize) {
      vinfolog("Got a response of size %d while the initial UDP payload size was %d, truncating", response.size(), udpPayloadSize);
      dnsdist::udp::truncateTC(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnsQuestion.ids.qname.wirelength(), dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses);
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
        header.tc = true;
        return true;
      });
    }
    else if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_truncateTC && dnsQuestion.getHeader()->tc) {
      dnsdist::udp::truncateTC(response, dnsQuestion.getMaximumSize(), dnsQuestion.ids.qname.wirelength(), dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses);
    }
  }
}

void handleResponseForUDPClient(InternalQueryState& ids, PacketBuffer& response, const std::shared_ptr<DownstreamState>& backend, bool isAsync, bool selfGenerated)
{
  DNSResponse dnsResponse(ids, response, backend);

  dnsdist::udp::handleResponseTC4UDPClient(dnsResponse, ids.udpPayloadSize, response);

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
    double udiff = ids.queryRealTime.udiff();
    if (!muted) {
      vinfolog("Got answer from %s, relayed to %s (UDP), took %f us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), udiff);
    }
    else {
      if (!ids.isXSK()) {
        vinfolog("Got answer from %s, NOT relayed to %s (UDP) since that frontend is muted, took %f us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), udiff);
      }
      else {
        vinfolog("Got answer from %s, relayed to %s (UDP via XSK), took %f us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), udiff);
      }
    }

    handleResponseSent(ids, udiff, dnsResponse.ids.origRemote, backend->d_config.remote, response.size(), cleartextDH, backend->getProtocol(), true);
  }
  else {
    handleResponseSent(ids, 0., dnsResponse.ids.origRemote, ComboAddress(), response.size(), cleartextDH, dnsdist::Protocol::DoUDP, false);
  }
}

#if !defined(DISABLE_RECVMMSG) && defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
void queueResponse(const PacketBuffer& response, const ComboAddress& dest, const ComboAddress& remote, struct mmsghdr& outMsg, struct iovec* iov, cmsgbuf_aligned* cbuf)
{
  outMsg.msg_len = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-pro-type-reinterpret-cast): API
  fillMSGHdr(&outMsg.msg_hdr, iov, nullptr, 0, const_cast<char*>(reinterpret_cast<const char*>(&response.at(0))), response.size(), const_cast<ComboAddress*>(&remote));

  if (dest.sin4.sin_family == 0) {
    outMsg.msg_hdr.msg_control = nullptr;
  }
  else {
    addCMsgSrcAddr(&outMsg.msg_hdr, cbuf, &dest, 0);
  }
}
#endif

bool isUDPQueryAcceptable(ClientState& clientState, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, bool& expectProxyProtocol)
{
  if ((msgh->msg_flags & MSG_TRUNC) != 0) {
    /* message was too large for our buffer */
    vinfolog("Dropping message too large for our buffer");
    ++clientState.nonCompliantQueries;
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    return false;
  }

  expectProxyProtocol = clientState.d_enableProxyProtocol && expectProxyProtocolFrom(remote);
  if (!dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.match(remote) && !expectProxyProtocol) {
    vinfolog("Query from %s dropped because of ACL", remote.toStringWithPort());
    ++dnsdist::metrics::g_stats.aclDrops;
    return false;
  }

  if (HarvestDestinationAddress(msgh, &dest)) {
    /* so it turns out that sometimes the kernel lies to us:
       the address is set to 0.0.0.0:0 which makes our sendfromto() use
       the wrong address. In that case it's better to let the kernel
       do the work by itself and use sendto() instead.
       This is indicated by setting the family to 0 which is acted upon
       in sendUDPResponse() and DelayedPacket::().
    */
    const ComboAddress bogusV4("0.0.0.0:0");
    const ComboAddress bogusV6("[::]:0");
    if ((dest.sin4.sin_family == AF_INET && dest == bogusV4) || (dest.sin4.sin_family == AF_INET6 && dest == bogusV6)) {
      dest.sin4.sin_family = 0;
    }
    else {
      /* we don't get the port, only the address */
      dest.sin4.sin_port = clientState.local.sin4.sin_port;
    }
  }
  else {
    dest.sin4.sin_family = 0;
  }

  ++clientState.queries;
  ++dnsdist::metrics::g_stats.queries;

  return true;
}

void processUDPQuery(ClientState& clientState, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, PacketBuffer& query, std::vector<mmsghdr>* responsesVect, unsigned int* queuedResponses, struct iovec* respIOV, cmsgbuf_aligned* respCBuf)
{
  assert(responsesVect == nullptr || (queuedResponses != nullptr && respIOV != nullptr && respCBuf != nullptr));
  uint16_t queryId = 0;
  InternalQueryState ids;

  pdns::trace::dnsdist::Tracer::Closer closer;
  if (auto tracer = ids.getTracer(); tracer != nullptr) {
    closer = tracer->openSpan("processUDPQuery");
  }

  ids.cs = &clientState;
  ids.origRemote = remote;
  ids.hopRemote = remote;
  ids.protocol = dnsdist::Protocol::DoUDP;

  try {
    bool expectProxyProtocol = false;
    if (!isUDPQueryAcceptable(clientState, msgh, remote, dest, expectProxyProtocol)) {
      return;
    }
    /* dest might have been updated, if we managed to harvest the destination address */
    if (dest.sin4.sin_family != 0) {
      ids.origDest = dest;
      ids.hopLocal = dest;
    }
    else {
      /* if we have not been able to harvest the destination address,
         we do NOT want to update dest or hopLocal, to let the kernel
         pick the less terrible option, but we want to update origDest
         which is used by rules and actions to at least the correct
         address family */
      ids.origDest = clientState.local;
      ids.hopLocal.sin4.sin_family = 0;
    }

    std::vector<ProxyProtocolValue> proxyProtocolValues;
    if (expectProxyProtocol && !handleProxyProtocol(remote, false, dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL, query, ids.origRemote, ids.origDest, proxyProtocolValues)) {
      return;
    }

    ids.queryRealTime.start();

    auto dnsCryptResponse = dnsdist::dnscrypt::checkDNSCryptQuery(clientState, query, ids.dnsCryptQuery, ids.queryRealTime.d_start.tv_sec, false);
    if (dnsCryptResponse) {
      sendUDPResponse(clientState.udpFD, query, 0, dest, remote);
      return;
    }

    {
      /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
      const dnsheader_aligned dnsHeader(query.data());
      queryId = ntohs(dnsHeader->id);

      if (!checkQueryHeaders(*dnsHeader, clientState)) {
        return;
      }

      if (dnsHeader->qdcount == 0) {
        dnsdist::PacketMangling::editDNSHeaderFromPacket(query, [](dnsheader& header) {
          header.rcode = RCode::NotImp;
          header.qr = true;
          return true;
        });

        sendUDPResponse(clientState.udpFD, query, 0, dest, remote);
        return;
      }
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
    if (ids.dnsCryptQuery) {
      ids.protocol = dnsdist::Protocol::DNSCryptUDP;
    }
    DNSQuestion dnsQuestion(ids, query);
    const uint16_t* flags = getFlagsFromDNSHeader(dnsQuestion.getHeader().get());
    ids.origFlags = *flags;

    if (!proxyProtocolValues.empty()) {
      dnsQuestion.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
    }

    // save UDP payload size from origin query
    uint16_t udpPayloadSize = 0;
    uint16_t zValue = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &zValue);
    if (!ids.dnssecOK) {
      ids.dnssecOK = (zValue & EDNS_HEADER_FLAG_DO) != 0;
    }
    if (udpPayloadSize < 512) {
      udpPayloadSize = 512;
    }

    std::shared_ptr<DownstreamState> backend{nullptr};
    auto result = processQuery(dnsQuestion, backend);

    if (result == ProcessQueryResult::Drop || result == ProcessQueryResult::Asynchronous) {
      return;
    }

    // the buffer might have been invalidated by now (resized)
    const auto dnsHeader = dnsQuestion.getHeader();
    if (result == ProcessQueryResult::SendAnswer) {
      /* ensure payload size is not exceeded */
      dnsdist::udp::handleResponseTC4UDPClient(dnsQuestion, udpPayloadSize, query);
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
      if (dnsQuestion.ids.delayMsec == 0 && responsesVect != nullptr) {
        queueResponse(query, dest, remote, (*responsesVect)[*queuedResponses], respIOV, respCBuf);
        (*queuedResponses)++;
        handleResponseSent(dnsQuestion.ids.qname, dnsQuestion.ids.qtype, 0., remote, ComboAddress(), query.size(), *dnsHeader, dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoUDP, false);
        return;
      }
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
#endif /* DISABLE_RECVMMSG */
      /* we use dest, always, because we don't want to use the listening address to send a response since it could be 0.0.0.0 */
      sendUDPResponse(clientState.udpFD, query, dnsQuestion.ids.delayMsec, dest, remote);

      handleResponseSent(dnsQuestion.ids.qname, dnsQuestion.ids.qtype, 0., remote, ComboAddress(), query.size(), *dnsHeader, dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoUDP, false);
      return;
    }

    if (result != ProcessQueryResult::PassToBackend || backend == nullptr) {
      return;
    }

    if (backend->isTCPOnly()) {
      std::string proxyProtocolPayload;
      /* we need to do this _before_ creating the cross protocol query because
         after that the buffer will have been moved */
      if (backend->d_config.useProxyProtocol) {
        proxyProtocolPayload = getProxyProtocolPayload(dnsQuestion);
      }

      ids.origID = dnsHeader->id;
      auto cpq = std::make_unique<dnsdist::udp::UDPCrossProtocolQuery>(std::move(query), std::move(ids), backend);
      cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

      backend->passCrossProtocolQuery(std::move(cpq));
      return;
    }

    assignOutgoingUDPQueryToBackend(backend, dnsHeader->id, dnsQuestion, query);
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in UDP question thread while parsing a query from %s, id %d: %s", ids.origRemote.toStringWithPort(), queryId, e.what());
  }
}

size_t getInitialUDPPacketBufferSize(bool expectProxyProtocol)
{
  static_assert(dnsdist::configuration::s_udpIncomingBufferSize <= dnsdist::udp::s_initialUDPPacketBufferSize, "The incoming buffer size should not be larger than s_initialUDPPacketBufferSize");

  const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (!expectProxyProtocol || runtimeConfig.d_proxyProtocolACL.empty()) {
    return s_initialUDPPacketBufferSize;
  }

  return s_initialUDPPacketBufferSize + runtimeConfig.d_proxyProtocolMaximumSize;
}

size_t getMaximumIncomingPacketSize(const ClientState& clientState)
{
  if (clientState.dnscryptCtx) {
    return getInitialUDPPacketBufferSize(clientState.d_enableProxyProtocol);
  }

  const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (!clientState.d_enableProxyProtocol || runtimeConfig.d_proxyProtocolACL.empty()) {
    return dnsdist::configuration::s_udpIncomingBufferSize;
  }

  return dnsdist::configuration::s_udpIncomingBufferSize + runtimeConfig.d_proxyProtocolMaximumSize;
}

#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
void MultipleMessagesUDPClientThread(ClientState* clientState)
{
  struct MMReceiver
  {
    PacketBuffer packet;
    ComboAddress remote;
    ComboAddress dest;
    iovec iov{};
    /* used by HarvestDestinationAddress */
    cmsgbuf_aligned cbuf{};
  };
  const size_t vectSize = dnsdist::configuration::getImmutableConfiguration().d_udpVectorSize;

  if (vectSize > std::numeric_limits<uint16_t>::max()) {
    throw std::runtime_error("The value of setUDPMultipleMessagesVectorSize is too high, the maximum value is " + std::to_string(std::numeric_limits<uint16_t>::max()));
  }

  auto recvData = std::vector<MMReceiver>(vectSize);
  auto msgVec = std::vector<mmsghdr>(vectSize);
  auto outMsgVec = std::vector<mmsghdr>(vectSize);

  /* the actual buffer is larger because:
     - we may have to add EDNS and/or ECS
     - we use it for self-generated responses (from rule or cache)
     but we only accept incoming payloads up to that size
  */
  const size_t initialBufferSize = getInitialUDPPacketBufferSize(clientState->d_enableProxyProtocol);
  const size_t maxIncomingPacketSize = getMaximumIncomingPacketSize(*clientState);

  /* initialize the structures needed to receive our messages */
  for (size_t idx = 0; idx < vectSize; idx++) {
    recvData[idx].remote.sin4.sin_family = clientState->local.sin4.sin_family;
    recvData[idx].packet.resize(initialBufferSize);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    fillMSGHdr(&msgVec[idx].msg_hdr, &recvData[idx].iov, &recvData[idx].cbuf, sizeof(recvData[idx].cbuf), reinterpret_cast<char*>(recvData[idx].packet.data()), maxIncomingPacketSize, &recvData[idx].remote);
  }

  /* go now */
  for (;;) {

    /* reset the IO vector, since it's also used to send the vector of responses
       to avoid having to copy the data around */
    for (size_t idx = 0; idx < vectSize; idx++) {
      recvData[idx].packet.resize(initialBufferSize);
      recvData[idx].iov.iov_base = &recvData[idx].packet.at(0);
      recvData[idx].iov.iov_len = recvData[idx].packet.size();
    }

    /* block until we have at least one message ready, but return
       as many as possible to save the syscall costs */
    int msgsGot = recvmmsg(clientState->udpFD, msgVec.data(), vectSize, MSG_WAITFORONE | MSG_TRUNC, nullptr);

    if (msgsGot <= 0) {
      vinfolog("Getting UDP messages via recvmmsg() failed with: %s", stringerror());
      continue;
    }

    unsigned int msgsToSend = 0;

    /* process the received messages */
    for (int msgIdx = 0; msgIdx < msgsGot; msgIdx++) {
      const struct msghdr* msgh = &msgVec[msgIdx].msg_hdr;
      unsigned int got = msgVec[msgIdx].msg_len;
      const ComboAddress& remote = recvData[msgIdx].remote;

      if (static_cast<size_t>(got) < sizeof(struct dnsheader)) {
        ++dnsdist::metrics::g_stats.nonCompliantQueries;
        ++clientState->nonCompliantQueries;
        continue;
      }

      recvData[msgIdx].packet.resize(got);
      dnsdist::configuration::refreshLocalRuntimeConfiguration();
      processUDPQuery(*clientState, msgh, remote, recvData[msgIdx].dest, recvData[msgIdx].packet, &outMsgVec, &msgsToSend, &recvData[msgIdx].iov, &recvData[msgIdx].cbuf);
    }

    /* immediate (not delayed or sent to a backend) responses (mostly from a rule, dynamic block
       or the cache) can be sent in batch too */

    if (msgsToSend > 0 && msgsToSend <= static_cast<unsigned int>(msgsGot)) {
      int sent = sendmmsg(clientState->udpFD, outMsgVec.data(), msgsToSend, 0);

      if (sent < 0 || static_cast<unsigned int>(sent) != msgsToSend) {
        vinfolog("Error sending responses with sendmmsg() (%d on %u): %s", sent, msgsToSend, stringerror());
      }
    }
  }
}
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
#endif /* DISABLE_RECVMMSG */
// listens to incoming queries, sends out to downstream servers, noting the intended return path
void udpClientThread(std::vector<ClientState*> states)
{
  try {
    setThreadName("dnsdist/udpClie");
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
    if (dnsdist::configuration::getImmutableConfiguration().d_udpVectorSize > 1) {
      MultipleMessagesUDPClientThread(states.at(0));
    }
    else
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
#endif /* DISABLE_RECVMMSG */
    {
      /* the actual buffer is larger because:
         - we may have to add EDNS and/or ECS
         - we use it for self-generated responses (from rule or cache)
         but we only accept incoming payloads up to that size
      */
      struct UDPStateParam
      {
        ClientState* cs{nullptr};
        size_t maxIncomingPacketSize{0};
        int socket{-1};
      };
      const size_t initialBufferSize = getInitialUDPPacketBufferSize(true);
      PacketBuffer packet(initialBufferSize);

      msghdr msgh{};
      iovec iov{};
      ComboAddress remote;
      ComboAddress dest;

      auto handleOnePacket = [&packet, &iov, &msgh, &remote, &dest, initialBufferSize](const UDPStateParam& param) {
        packet.resize(initialBufferSize);
        iov.iov_base = &packet.at(0);
        iov.iov_len = packet.size();

        ssize_t got = recvmsg(param.socket, &msgh, 0);

        if (got < 0 || static_cast<size_t>(got) < sizeof(struct dnsheader)) {
          ++dnsdist::metrics::g_stats.nonCompliantQueries;
          ++param.cs->nonCompliantQueries;
          return;
        }

        packet.resize(static_cast<size_t>(got));

        dnsdist::configuration::refreshLocalRuntimeConfiguration();
        processUDPQuery(*param.cs, &msgh, remote, dest, packet, nullptr, nullptr, nullptr, nullptr);
      };

      std::vector<UDPStateParam> params;
      for (auto& state : states) {
        const size_t maxIncomingPacketSize = getMaximumIncomingPacketSize(*state);
        params.emplace_back(UDPStateParam{state, maxIncomingPacketSize, state->udpFD});
      }

      if (params.size() == 1) {
        const auto& param = params.at(0);
        remote.sin4.sin_family = param.cs->local.sin4.sin_family;
        /* used by HarvestDestinationAddress */
        cmsgbuf_aligned cbuf;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), reinterpret_cast<char*>(&packet.at(0)), param.maxIncomingPacketSize, &remote);
        while (true) {
          try {
            handleOnePacket(param);
          }
          catch (const std::bad_alloc& e) {
            /* most exceptions are handled by handleOnePacket(), but we might be out of memory (std::bad_alloc)
               in which case we DO NOT want to log (as it would trigger another memory allocation attempt
               that might throw as well) but wait a bit (one millisecond) and then try to recover */
            usleep(1000);
          }
        }
      }
      else {
        auto callback = [&remote, &msgh, &iov, &packet, &handleOnePacket, initialBufferSize](int socket, FDMultiplexer::funcparam_t& funcparam) {
          (void)socket;
          const auto* param = boost::any_cast<const UDPStateParam*>(funcparam);
          try {
            remote.sin4.sin_family = param->cs->local.sin4.sin_family;
            packet.resize(initialBufferSize);
            /* used by HarvestDestinationAddress */
            cmsgbuf_aligned cbuf;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), reinterpret_cast<char*>(&packet.at(0)), param->maxIncomingPacketSize, &remote);
            handleOnePacket(*param);
          }
          catch (const std::bad_alloc& e) {
            /* most exceptions are handled by handleOnePacket(), but we might be out of memory (std::bad_alloc)
               in which case we DO NOT want to log (as it would trigger another memory allocation attempt
               that might throw as well) but wait a bit (one millisecond) and then try to recover */
            usleep(1000);
          }
        };
        auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(params.size()));
        for (const auto& param : params) {
          mplexer->addReadFD(param.socket, callback, &param);
        }

        timeval now{};
        while (true) {
          mplexer->run(&now, -1);
        }
      }
    }
  }
  catch (const std::exception& e) {
    errlog("UDP client thread died because of exception: %s", e.what());
  }
  catch (const PDNSException& e) {
    errlog("UDP client thread died because of PowerDNS exception: %s", e.reason);
  }
  catch (...) {
    errlog("UDP client thread died because of an exception: %s", "unknown");
  }
}

std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion)
{
  dnsQuestion.ids.origID = dnsQuestion.getHeader()->id;
  return std::make_unique<dnsdist::udp::UDPCrossProtocolQuery>(std::move(dnsQuestion.getMutableData()), std::move(dnsQuestion.ids), nullptr);
}
} // namespace dnsdist::udp
