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
    auto logger = dnsdist::logging::getTopLogger()->withName("xsk-response-worker")->withValues("backend-name", Logging::Loggable(dss->getName()), "backend-address", Logging::Loggable(dss->d_config.remote));

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
            VERBOSESLOG(infolog("XSK packet dropped because processResponderPacket failed"),
                        logger->info(Logr::Info, "XSK packet dropped because processResponderPacket failed"));
            return;
          }
          if (response.size() > packet.getCapacity()) {
            /* fallback to sending the packet via normal socket */
            sendUDPResponse(ids->cs->udpFD, response, ids->delayMsec, ids->hopLocal, ids->hopRemote);
            VERBOSESLOG(infolog("XSK packet falling back because packet is too large"),
                        logger->info(Logr::Info, "XSK packet falling back because packet is too large"));
            xskInfo->markAsFree(packet);
            return;
          }
          packet.setHeader(ids->xskPacketHeader);
          if (!packet.setPayload(response)) {
            VERBOSESLOG(infolog("Unable to set XSK payload!"),
                        logger->info(Logr::Info, "Unable to set XSK payload!"));
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
    SLOG(errlog("XSK responder thread died because of exception: %s", e.what()),
         dnsdist::logging::getTopLogger()->error(Logr::Error, e.what(), "XSK responder thread died because of exception"));
  }
  catch (const PDNSException& e) {
    SLOG(errlog("XSK responder thread died because of PowerDNS exception: %s", e.reason),
         dnsdist::logging::getTopLogger()->error(Logr::Error, e.reason, "XSK responder thread died because of exception"));
  }
  catch (...) {
    SLOG(errlog("XSK responder thread died because of an unknown exception"),
         dnsdist::logging::getTopLogger()->info(Logr::Error, "XSK responder thread died because of an unknown exception"));
  }
}

bool XskIsQueryAcceptable(const XskPacket& packet, ClientState& clientState, bool& expectProxyProtocol)
{
  const auto& from = packet.getFromAddr();
  expectProxyProtocol = expectProxyProtocolFrom(from);
  if (!dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.match(from) && !expectProxyProtocol) {
    VERBOSESLOG(infolog("Query from %s dropped because of ACL", from.toStringWithPort()),
                dnsdist::logging::getTopLogger()->info(Logr::Info, "Query dropped because of ACL", "address", Logging::Loggable(from)));
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
  auto logger = dnsdist::logging::getTopLogger()->withName("xsk-router");

  uint32_t failed = 0;
  // packets to be submitted for sending
  vector<XskPacket> fillInTx;
  const auto& fds = xsk->getDescriptors();
  // list of workers that need to be notified
  std::set<int> needNotify;
  std::vector<XskPacket> packets;
  while (true) {
    try {
      auto ready = xsk->wait(-1);
      dnsdist::configuration::refreshLocalRuntimeConfiguration();
      // descriptor 0 gets incoming AF_XDP packets
      if ((fds.at(0).revents & POLLIN) != 0) {
        xsk->recv(packets, 64, &failed);
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
            if ((packet.getFlags() & XskPacket::UPDATED) == 0) {
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
      VERBOSESLOG(infolog("Exception in XSK router loop"),
                  logger->info(Logr::Info, "Exception in XSK router loop"));
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

}
#endif /* HAVE_XSK */
