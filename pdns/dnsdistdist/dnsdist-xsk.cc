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
    auto localRespRuleActions = dnsdist::rules::getResponseRuleChainHolder(dnsdist::rules::ResponseRuleChain::ResponseRules).getLocal();
    auto localCacheInsertedRespRuleActions = dnsdist::rules::getResponseRuleChainHolder(dnsdist::rules::ResponseRuleChain::CacheInsertedResponseRules).getLocal();
    auto pollfds = getPollFdsForWorker(*xskInfo);
    while (!dss->isStopped()) {
      poll(pollfds.data(), pollfds.size(), -1);
      bool needNotify = false;
      if ((pollfds[0].revents & POLLIN) != 0) {
        needNotify = true;
        xskInfo->cleanSocketNotification();
#if defined(__SANITIZE_THREAD__)
        xskInfo->incomingPacketsQueue.lock()->consume_all([&](XskPacket& packet) {
#else
        xskInfo->incomingPacketsQueue.consume_all([&](XskPacket& packet) {
#endif
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
          if (!processResponderPacket(dss, response, *localRespRuleActions, *localCacheInsertedRespRuleActions, std::move(*ids))) {
            xskInfo->markAsFree(packet);
            infolog("XSK packet pushed to queue because processResponderPacket failed");
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

bool XskIsQueryAcceptable(const XskPacket& packet, ClientState& clientState, LocalHolders& holders, bool& expectProxyProtocol)
{
  const auto& from = packet.getFromAddr();
  expectProxyProtocol = expectProxyProtocolFrom(from);
  if (!holders.acl->match(from) && !expectProxyProtocol) {
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
#if defined(__SANITIZE_THREAD__)
          info->outgoingPacketsQueue.lock()->consume_all([&](XskPacket& packet) {
#else
          info->outgoingPacketsQueue.consume_all([&](XskPacket& packet) {
#endif
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
  LocalHolders holders;

  for (;;) {
#if defined(__SANITIZE_THREAD__)
    while (xskInfo->incomingPacketsQueue.lock()->read_available() == 0U) {
#else
    while (xskInfo->incomingPacketsQueue.read_available() == 0U) {
#endif
      xskInfo->waitForXskSocket();
    }
#if defined(__SANITIZE_THREAD__)
    xskInfo->incomingPacketsQueue.lock()->consume_all([&](XskPacket& packet) {
#else
    xskInfo->incomingPacketsQueue.consume_all([&](XskPacket& packet) {
#endif
      if (XskProcessQuery(*clientState, holders, packet)) {
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

}
#endif /* HAVE_XSK */
