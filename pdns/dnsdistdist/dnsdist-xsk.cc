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
#include "dnsdist-xsk.hh"

#ifdef HAVE_XSK
#include <sys/poll.h>

#include "dolog.hh"
#include "dnsdist-metrics.hh"
#include "dnsdist-udp.hh"
#include "dnsdist-dnscrypt.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-proxy-protocol.hh"
#include "threadname.hh"
#include "xsk.hh"

namespace dnsdist::xsk
{
std::vector<std::shared_ptr<XskSocket>> g_xsk;

void XskResponderThread(std::shared_ptr<DownstreamState> dss, std::shared_ptr<XskWorker> xskInfo)
{
  try {
    setThreadName("dnsdist/XskResp");
    auto pollfds = getPollFdsForWorker(*xskInfo);
    while (!dss->isStopped()) {
      poll(pollfds.data(), pollfds.size(), -1);
      dnsdist::configuration::refreshLocalRuntimeConfiguration();
      bool needNotify = false;
      if ((pollfds[0].revents & POLLIN) != 0) {
        needNotify = true;
        xskInfo->cleanSocketNotification();
        xskInfo->processIncomingFrames([&](XskPacket packet) {
          if (packet.getDataLen() < sizeof(dnsheader)) {
            xskInfo->markAsFree(packet);
            return;
          }
          const dnsheader_aligned dnsHeader(packet.getPayloadData());
          const auto queryId = dnsHeader->id;
          auto ids = dss->getState(queryId);
          if (ids) {
            if (!ids->isXSK()) {
              dss->restoreState(queryId, std::move(*ids));
              ids = std::nullopt;
            }
          }
          if (!ids) {
            xskInfo->markAsFree(packet);
            return;
          }
          auto response = packet.clonePacketBuffer();
          if (response.size() > packet.getCapacity()) {
            /* fallback to sending the packet via normal socket */
            ids->xskPacketHeader.clear();
          }
          if (!processResponderPacket(dss, response, std::move(*ids))) {
            xskInfo->markAsFree(packet);
            vinfolog("XSK packet dropped because processResponderPacket failed");
            return;
          }
          if (response.size() > packet.getCapacity()) {
            /* fallback to sending the packet via normal socket */
            sendUDPResponse(ids->cs->udpFD, response, ids->delayMsec, ids->hopLocal, ids->hopRemote);
            infolog("XSK packet falling back because packet is too large");
            xskInfo->markAsFree(packet);
            return;
          }
          packet.setHeader(ids->xskPacketHeader);
          if (!packet.setPayload(response)) {
            infolog("Unable to set XSK payload !");
          }
          if (ids->delayMsec > 0) {
            packet.addDelay(ids->delayMsec);
          }
          packet.updatePacket();
          xskInfo->pushToSendQueue(packet);
        });
      }
      if (needNotify) {
        xskInfo->notifyXskSocket();
      }
    }
  }
  catch (const std::exception& e) {
    errlog("XSK responder thread died because of exception: %s", e.what());
  }
  catch (const PDNSException& e) {
    errlog("XSK responder thread died because of PowerDNS exception: %s", e.reason);
  }
  catch (...) {
    errlog("XSK responder thread died because of an exception: %s", "unknown");
  }
}

bool XskIsQueryAcceptable(const XskPacket& packet, ClientState& clientState, bool& expectProxyProtocol)
{
  const auto& from = packet.getFromAddr();
  expectProxyProtocol = expectProxyProtocolFrom(from);
  if (!dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.match(from) && !expectProxyProtocol) {
    vinfolog("Query from %s dropped because of ACL", from.toStringWithPort());
    ++dnsdist::metrics::g_stats.aclDrops;
    return false;
  }
  clientState.queries++;
  ++dnsdist::metrics::g_stats.queries;

  return true;
}

void XskRouter(std::shared_ptr<XskSocket> xsk)
{
  setThreadName("dnsdist/XskRouter");
  uint32_t failed = 0;
  // packets to be submitted for sending
  vector<XskPacket> fillInTx;
  const auto& fds = xsk->getDescriptors();
  // list of workers that need to be notified
  std::set<int> needNotify;
  while (true) {
    try {
      auto ready = xsk->wait(-1);
      dnsdist::configuration::refreshLocalRuntimeConfiguration();
      // descriptor 0 gets incoming AF_XDP packets
      if ((fds.at(0).revents & POLLIN) != 0) {
        auto packets = xsk->recv(64, &failed);
        dnsdist::metrics::g_stats.nonCompliantQueries += failed;
        for (auto& packet : packets) {
          const auto dest = packet.getToAddr();
          auto worker = xsk->getWorkerByDestination(dest);
          if (!worker) {
            xsk->markAsFree(packet);
            continue;
          }
          worker->pushToProcessingQueue(packet);
          needNotify.insert(worker->workerWaker.getHandle());
        }
        for (auto socket : needNotify) {
          uint64_t value = 1;
          auto written = write(socket, &value, sizeof(value));
          if (written != sizeof(value)) {
            // oh, well, the worker is clearly overloaded
            // but there is nothing we can do about it,
            // and hopefully the queue will be processed eventually
          }
        }
        needNotify.clear();
        ready--;
      }
      for (size_t fdIndex = 1; fdIndex < fds.size() && ready > 0; fdIndex++) {
        if ((fds.at(fdIndex).revents & POLLIN) != 0) {
          ready--;
          const auto& info = xsk->getWorkerByDescriptor(fds.at(fdIndex).fd);
          info->processOutgoingFrames([&](XskPacket packet) {
            if ((packet.getFlags() & XskPacket::UPDATE) == 0) {
              xsk->markAsFree(packet);
              return;
            }
            if ((packet.getFlags() & XskPacket::DELAY) != 0) {
              xsk->pushDelayed(packet);
              return;
            }
            fillInTx.push_back(packet);
          });
          info->cleanWorkerNotification();
        }
      }
      xsk->pickUpReadyPacket(fillInTx);
      xsk->recycle(4096);
      xsk->fillFq();
      xsk->send(fillInTx);
    }
    catch (...) {
      vinfolog("Exception in XSK router loop");
    }
  }
}

void XskClientThread(ClientState* clientState)
{
  setThreadName("dnsdist/xskClient");
  auto xskInfo = clientState->xskInfo;

  for (;;) {
    while (!xskInfo->hasIncomingFrames()) {
      xskInfo->waitForXskSocket();
    }
    dnsdist::configuration::refreshLocalRuntimeConfiguration();
    xskInfo->processIncomingFrames([&](XskPacket packet) {
      if (XskProcessQuery(*clientState, packet)) {
        packet.updatePacket();
        xskInfo->pushToSendQueue(packet);
      }
      else {
        xskInfo->markAsFree(packet);
      }
    });
    xskInfo->notifyXskSocket();
  }
}

static std::string getDestinationMap(bool isV6)
{
  return !isV6 ? "/sys/fs/bpf/dnsdist/xsk-destinations-v4" : "/sys/fs/bpf/dnsdist/xsk-destinations-v6";
}

void addDestinationAddress(const ComboAddress& addr)
{
  auto map = getDestinationMap(addr.isIPv6());
  XskSocket::addDestinationAddress(map, addr);
}

void removeDestinationAddress(const ComboAddress& addr)
{
  auto map = getDestinationMap(addr.isIPv6());
  XskSocket::removeDestinationAddress(map, addr);
}

void clearDestinationAddresses()
{
  auto map = getDestinationMap(false);
  XskSocket::clearDestinationMap(map, false);
  map = getDestinationMap(true);
  XskSocket::clearDestinationMap(map, true);
}

bool XskProcessQuery(ClientState& clientState, XskPacket& packet)
{
  uint16_t queryId = 0;
  const auto& remote = packet.getFromAddr();
  const auto& dest = packet.getToAddr();
  InternalQueryState ids;
  ids.cs = &clientState;
  ids.origRemote = remote;
  ids.hopRemote = remote;
  ids.origDest = dest;
  ids.hopLocal = dest;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.xskPacketHeader = packet.cloneHeaderToPacketBuffer();

  try {
    bool expectProxyProtocol = false;
    if (!XskIsQueryAcceptable(packet, clientState, expectProxyProtocol)) {
      return false;
    }

    auto query = packet.clonePacketBuffer();
    std::vector<ProxyProtocolValue> proxyProtocolValues;
    if (expectProxyProtocol && !handleProxyProtocol(remote, false, dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL, query, ids.origRemote, ids.origDest, proxyProtocolValues)) {
      return false;
    }

    ids.queryRealTime.start();

    auto dnsCryptResponse = dnsdist::dnscrypt::checkDNSCryptQuery(clientState, query, ids.dnsCryptQuery, ids.queryRealTime.d_start.tv_sec, false);
    if (dnsCryptResponse) {
      packet.setPayload(query);
      return true;
    }

    {
      /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
      dnsheader_aligned dnsHeader(query.data());
      queryId = ntohs(dnsHeader->id);

      if (!checkQueryHeaders(*dnsHeader, clientState)) {
        return false;
      }

      if (dnsHeader->qdcount == 0) {
        dnsdist::PacketMangling::editDNSHeaderFromPacket(query, [](dnsheader& header) {
          header.rcode = RCode::NotImp;
          header.qr = true;
          return true;
        });
        packet.setPayload(query);
        return true;
      }
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
    if (ids.origDest.sin4.sin_family == 0) {
      ids.origDest = clientState.local;
    }
    if (ids.dnsCryptQuery) {
      ids.protocol = dnsdist::Protocol::DNSCryptUDP;
    }
    DNSQuestion dnsQuestion(ids, query);
    if (!proxyProtocolValues.empty()) {
      dnsQuestion.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
    }
    std::shared_ptr<DownstreamState> backend{nullptr};
    auto result = processQuery(dnsQuestion, backend);

    if (result == ProcessQueryResult::Drop) {
      return false;
    }

    if (result == ProcessQueryResult::SendAnswer) {
      packet.setPayload(query);
      if (dnsQuestion.ids.delayMsec > 0) {
        packet.addDelay(dnsQuestion.ids.delayMsec);
      }
      const auto dnsHeader = dnsQuestion.getHeader();
      handleResponseSent(ids.qname, ids.qtype, 0., remote, ComboAddress(), query.size(), *dnsHeader, dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoUDP, false);
      return true;
    }

    if (result != ProcessQueryResult::PassToBackend || backend == nullptr) {
      return false;
    }

    // the buffer might have been invalidated by now (resized)
    const auto dnsHeader = dnsQuestion.getHeader();
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
      return false;
    }

    if (backend->d_xskInfos.empty()) {
      assignOutgoingUDPQueryToBackend(backend, dnsHeader->id, dnsQuestion, query, true);
      return false;
    }

    assignOutgoingUDPQueryToBackend(backend, dnsHeader->id, dnsQuestion, query, false);
    auto sourceAddr = backend->pickSourceAddressForSending();
    packet.setAddr(sourceAddr, backend->d_config.sourceMACAddr, backend->d_config.remote, backend->d_config.destMACAddr);
    packet.setPayload(query);
    packet.rewrite();
    return true;
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in UDP question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
  }
  return false;
}

}
#endif /* HAVE_XSK */
