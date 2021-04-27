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

#include "dnsdist-healthchecks.hh"
#include "tcpiohandler-mplexer.hh"
#include "dnswriter.hh"
#include "dolog.hh"

bool g_verboseHealthChecks{false};

struct HealthCheckData
{
  enum class TCPState : uint8_t { WritingQuery, ReadingResponseSize, ReadingResponse };

  HealthCheckData(std::shared_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& ds, DNSName&& checkName, uint16_t checkType, uint16_t checkClass, uint16_t queryID): d_ds(ds), d_mplexer(mplexer), d_udpSocket(-1), d_checkName(std::move(checkName)), d_checkType(checkType), d_checkClass(checkClass), d_queryID(queryID)
  {
  }

  const std::shared_ptr<DownstreamState> d_ds;
  std::shared_ptr<FDMultiplexer> d_mplexer;
  std::unique_ptr<TCPIOHandler> d_tcpHandler{nullptr};
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  PacketBuffer d_buffer;
  Socket d_udpSocket;
  DNSName d_checkName;
  struct timeval d_ttd{0, 0};
  size_t d_bufferPos{0};
  uint16_t d_checkType;
  uint16_t d_checkClass;
  uint16_t d_queryID;
  TCPState d_tcpState{TCPState::WritingQuery};
  bool d_initial{false};
};

void updateHealthCheckResult(const std::shared_ptr<DownstreamState>& dss, bool initial, bool newState)
{
  if (initial) {
    warnlog("Marking downstream %s as '%s'", dss->getNameWithAddr(), newState ? "up" : "down");
    dss->setUpStatus(newState);
    return;
  }

  if (newState) {
    /* check succeeded */
    dss->currentCheckFailures = 0;

    if (!dss->upStatus) {
      /* we were marked as down */
      dss->consecutiveSuccessfulChecks++;
      if (dss->consecutiveSuccessfulChecks < dss->minRiseSuccesses) {
        /* if we need more than one successful check to rise
           and we didn't reach the threshold yet,
           let's stay down */
        newState = false;
      }
    }
  }
  else {
    /* check failed */
    dss->consecutiveSuccessfulChecks = 0;

    if (dss->upStatus) {
      /* we are currently up */
      dss->currentCheckFailures++;
      if (dss->currentCheckFailures < dss->maxCheckFailures) {
        /* we need more than one failure to be marked as down,
           and we did not reach the threshold yet, let's stay down */
        newState = true;
      }
    }
  }

  if (newState != dss->upStatus) {
    warnlog("Marking downstream %s as '%s'", dss->getNameWithAddr(), newState ? "up" : "down");

    if (newState && (!dss->connected || dss->reconnectOnUp)) {
      newState = dss->reconnect();

      if (dss->connected && !dss->threadStarted.test_and_set()) {
        dss->tid = std::thread(responderThread, dss);
      }
    }

    dss->setUpStatus(newState);
    dss->currentCheckFailures = 0;
    dss->consecutiveSuccessfulChecks = 0;
    if (g_snmpAgent && g_snmpTrapsEnabled) {
      g_snmpAgent->sendBackendStatusChangeTrap(dss);
    }
  }
}

static bool handleResponse(std::shared_ptr<HealthCheckData>& data)
{
  auto& ds = data->d_ds;
  try {
    if (data->d_buffer.size() < sizeof(dnsheader)) {
      if (g_verboseHealthChecks) {
        infolog("Invalid health check response of size %d from backend %s, expecting at least %d", data->d_buffer.size(), ds->getNameWithAddr(), sizeof(dnsheader));
      }
      return false;
    }

    const dnsheader * responseHeader = reinterpret_cast<const dnsheader*>(data->d_buffer.data());
    if (responseHeader->id != data->d_queryID) {
      if (g_verboseHealthChecks) {
        infolog("Invalid health check response id %d from backend %s, expecting %d", data->d_queryID, ds->getNameWithAddr(), data->d_queryID);
      }
      return false;
    }

    if (!responseHeader->qr) {
      if (g_verboseHealthChecks) {
        infolog("Invalid health check response from backend %s, expecting QR to be set", ds->getNameWithAddr());
      }
      return false;
    }

    if (responseHeader->rcode == RCode::ServFail) {
      if (g_verboseHealthChecks) {
        infolog("Backend %s responded to health check with ServFail", ds->getNameWithAddr());
      }
      return false;
    }

    if (ds->mustResolve && (responseHeader->rcode == RCode::NXDomain || responseHeader->rcode == RCode::Refused)) {
      if (g_verboseHealthChecks) {
        infolog("Backend %s responded to health check with %s while mustResolve is set", ds->getNameWithAddr(), responseHeader->rcode == RCode::NXDomain ? "NXDomain" : "Refused");
      }
      return false;
    }

    uint16_t receivedType;
    uint16_t receivedClass;
    DNSName receivedName(reinterpret_cast<const char*>(data->d_buffer.data()), data->d_buffer.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != data->d_checkName || receivedType != data->d_checkType || receivedClass != data->d_checkClass) {
      if (g_verboseHealthChecks) {
        infolog("Backend %s responded to health check with an invalid qname (%s vs %s), qtype (%s vs %s) or qclass (%d vs %d)", ds->getNameWithAddr(), receivedName.toLogString(), data->d_checkName.toLogString(), QType(receivedType).toString(), QType(data->d_checkType).toString(), receivedClass, data->d_checkClass);
      }
      return false;
    }
  }
  catch(const std::exception& e)
  {
    if (g_verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", ds->getNameWithAddr(), e.what());
    }
    return false;
  }
  catch(...)
  {
    if (g_verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", ds->getNameWithAddr());
    }
    return false;
  }

  return true;
}

static void healthCheckUDPCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(param);
  data->d_mplexer->removeReadFD(fd);

  ComboAddress from;
  from.sin4.sin_family = data->d_ds->remote.sin4.sin_family;
  auto fromlen = from.getSocklen();
  data->d_buffer.resize(512);
  auto got = recvfrom(data->d_udpSocket.getHandle(), &data->d_buffer.at(0), data->d_buffer.size(), 0, reinterpret_cast<sockaddr *>(&from), &fromlen);
  if (got < 0) {
    if (g_verboseHealthChecks) {
      infolog("Error receiving health check response from %s: %s", data->d_ds->remote.toStringWithPort(), stringerror());
    }
    updateHealthCheckResult(data->d_ds, data->d_initial, false);
  }

  /* we are using a connected socket but hey.. */
  if (from != data->d_ds->remote) {
    if (g_verboseHealthChecks) {
      infolog("Invalid health check response received from %s, expecting one from %s", from.toStringWithPort(), data->d_ds->remote.toStringWithPort());
    }
    updateHealthCheckResult(data->d_ds, data->d_initial, false);
  }

  updateHealthCheckResult(data->d_ds, data->d_initial, handleResponse(data));
}

static void healthCheckTCPCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(param);

  IOStateGuard ioGuard(data->d_ioState);
  try {
    auto ioState = IOState::Done;

    if (data->d_tcpState == HealthCheckData::TCPState::WritingQuery) {
      ioState = data->d_tcpHandler->tryWrite(data->d_buffer, data->d_bufferPos, data->d_buffer.size());
      if (ioState == IOState::Done) {
        data->d_bufferPos = 0;
        data->d_buffer.resize(sizeof(uint16_t));
        data->d_tcpState = HealthCheckData::TCPState::ReadingResponseSize;
      }
    }

    if (data->d_tcpState == HealthCheckData::TCPState::ReadingResponseSize) {
      ioState = data->d_tcpHandler->tryRead(data->d_buffer, data->d_bufferPos, data->d_buffer.size());
      if (ioState == IOState::Done) {
        data->d_bufferPos = 0;
        uint16_t responseSize;
        memcpy(&responseSize, &data->d_buffer.at(0), sizeof(responseSize));
        data->d_buffer.resize(ntohs(responseSize));
        data->d_tcpState = HealthCheckData::TCPState::ReadingResponse;
      }
    }

    if (data->d_tcpState == HealthCheckData::TCPState::ReadingResponse) {
      ioState = data->d_tcpHandler->tryRead(data->d_buffer, data->d_bufferPos, data->d_buffer.size());
      if (ioState == IOState::Done) {
        updateHealthCheckResult(data->d_ds, data->d_initial, handleResponse(data));
      }
    }

    if (ioState == IOState::Done) {
      /* remove us from the mplexer, we are done */
      data->d_ioState->update(ioState, healthCheckTCPCallback, data);
    }
    else {
      data->d_ioState->update(ioState, healthCheckTCPCallback, data, data->d_ttd);
    }

    /* the state has been updated, we can release the guard */
    ioGuard.release();
  }
  catch (const std::exception& e) {
    if (g_verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", data->d_ds->getNameWithAddr(), e.what());
    }
  }
  catch (...) {
    if (g_verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", data->d_ds->getNameWithAddr());
    }
  }
}

bool queueHealthCheck(std::shared_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& ds, bool initialCheck)
{
  try
  {
    uint16_t queryID = getRandomDNSID();
    DNSName checkName = ds->checkName;
    uint16_t checkType = ds->checkType.getCode();
    uint16_t checkClass = ds->checkClass;
    dnsheader checkHeader;
    memset(&checkHeader, 0, sizeof(checkHeader));

    checkHeader.qdcount = htons(1);
    checkHeader.id = queryID;

    checkHeader.rd = true;
    if (ds->setCD) {
      checkHeader.cd = true;
    }

    if (ds->checkFunction) {
      auto lock = g_lua.lock();
      auto ret = ds->checkFunction(checkName, checkType, checkClass, &checkHeader);
      checkName = std::get<0>(ret);
      checkType = std::get<1>(ret);
      checkClass = std::get<2>(ret);
    }

    PacketBuffer packet;
    GenericDNSPacketWriter<PacketBuffer> dpw(packet, checkName, checkType, checkClass);
    dnsheader* requestHeader = dpw.getHeader();
    *requestHeader = checkHeader;

    /* we need to compute that _before_ adding the proxy protocol payload */
    uint16_t packetSize = packet.size();
    size_t proxyProtocolPayloadSize = 0;
    if (ds->useProxyProtocol) {
      auto payload = makeLocalProxyHeader();
      proxyProtocolPayloadSize = payload.size();
      packet.insert(packet.begin(), payload.begin(), payload.end());
    }

    Socket sock(ds->remote.sin4.sin_family, ds->doHealthcheckOverTCP() ? SOCK_STREAM : SOCK_DGRAM);

    sock.setNonBlocking();
    if (!IsAnyAddress(ds->sourceAddr)) {
      sock.setReuseAddr();
#ifdef IP_BIND_ADDRESS_NO_PORT
      if (ds->ipBindAddrNoPort) {
        SSetsockopt(sock.getHandle(), SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
      }
#endif

      if (!ds->sourceItfName.empty()) {
#ifdef SO_BINDTODEVICE
        int res = setsockopt(sock.getHandle(), SOL_SOCKET, SO_BINDTODEVICE, ds->sourceItfName.c_str(), ds->sourceItfName.length());
        if (res != 0 && g_verboseHealthChecks) {
          infolog("Error setting SO_BINDTODEVICE on the health check socket for backend '%s': %s", ds->getNameWithAddr(), stringerror());
        }
#endif
      }
      sock.bind(ds->sourceAddr);
    }

    auto data = std::make_shared<HealthCheckData>(mplexer, ds, std::move(checkName), checkType, checkClass, queryID);
    data->d_initial = initialCheck;

    gettimeofday(&data->d_ttd, nullptr);
    data->d_ttd.tv_sec += ds->checkTimeout / 1000; /* ms to seconds */
    data->d_ttd.tv_usec += (ds->checkTimeout % 1000) * 1000; /* remaining ms to us */
    if (data->d_ttd.tv_usec > 1000000) {
      ++data->d_ttd.tv_sec;
      data->d_ttd.tv_usec -= 1000000;
    }

    if (!ds->doHealthcheckOverTCP()) {
      sock.connect(ds->remote);
      data->d_udpSocket = std::move(sock);
      ssize_t sent = udpClientSendRequestToBackend(ds, data->d_udpSocket.getHandle(), packet, true);
      if (sent < 0) {
        int ret = errno;
        if (g_verboseHealthChecks) {
          infolog("Error while sending a health check query to backend %s: %d", ds->getNameWithAddr(), ret);
        }
        return false;
      }

      mplexer->addReadFD(data->d_udpSocket.getHandle(), &healthCheckUDPCallback, data, &data->d_ttd);
    }
    else {
      data->d_tcpHandler = std::make_unique<TCPIOHandler>(ds->d_tlsSubjectName, sock.releaseHandle(), timeval{ds->checkTimeout,0}, ds->d_tlsCtx, time(nullptr));
      data->d_ioState = std::make_unique<IOStateHandler>(*mplexer, data->d_tcpHandler->getDescriptor());

      data->d_tcpHandler->tryConnect(ds->tcpFastOpen, ds->remote);

      const uint8_t sizeBytes[] = { static_cast<uint8_t>(packetSize / 256), static_cast<uint8_t>(packetSize % 256) };
      packet.insert(packet.begin() + proxyProtocolPayloadSize, sizeBytes, sizeBytes + 2);
      data->d_buffer = std::move(packet);

      auto ioState = data->d_tcpHandler->tryWrite(data->d_buffer, data->d_bufferPos, data->d_buffer.size());
      if (ioState == IOState::Done) {
        data->d_bufferPos = 0;
        data->d_buffer.resize(sizeof(uint16_t));
        data->d_tcpState = HealthCheckData::TCPState::ReadingResponseSize;
        ioState = IOState::NeedRead;
      }

      data->d_ioState->update(ioState, healthCheckTCPCallback, data, data->d_ttd);
    }

    return true;
  }
  catch (const std::exception& e)
  {
    if (g_verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", ds->getNameWithAddr(), e.what());
    }
    return false;
  }
  catch(...)
  {
    if (g_verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", ds->getNameWithAddr());
    }
    return false;
  }
}

void handleQueuedHealthChecks(std::shared_ptr<FDMultiplexer>& mplexer, bool initial)
{
  while (mplexer->getWatchedFDCount(false) > 0 || mplexer->getWatchedFDCount(true) > 0) {
    struct timeval now;
    int ret = mplexer->run(&now, 100);
    if (ret == -1) {
      if (g_verboseHealthChecks) {
        infolog("Error while waiting for the health check response from backends: %d", ret);
      }
      break;
    }
    auto timeouts = mplexer->getTimeouts(now);
    for (const auto& timeout : timeouts) {
      auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(timeout.second);
      try {
        if (data->d_ioState) {
          data->d_ioState.reset();
        }
        else {
          mplexer->removeReadFD(timeout.first);
        }
        if (g_verboseHealthChecks) {
          infolog("Timeout while waiting for the health check response from backend %s", data->d_ds->getNameWithAddr());
        }

        updateHealthCheckResult(data->d_ds, initial, false);
      }
      catch (const std::exception& e) {
        if (g_verboseHealthChecks) {
          infolog("Error while delaing with a timeout for the health check response from backend %s: %s", data->d_ds->getNameWithAddr(), e.what());
        }
      }
      catch (...) {
        if (g_verboseHealthChecks) {
          infolog("Error while delaing with a timeout for the health check response from backend %s", data->d_ds->getNameWithAddr());
        }
      }
    }

    timeouts = mplexer->getTimeouts(now, true);
    for (const auto& timeout : timeouts) {
      auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(timeout.second);
      try {
        data->d_ioState.reset();
        if (g_verboseHealthChecks) {
          infolog("Timeout while waiting for the health check response from backend %s", data->d_ds->getNameWithAddr());
        }

        updateHealthCheckResult(data->d_ds, initial, false);
      }
      catch (const std::exception& e) {
        if (g_verboseHealthChecks) {
          infolog("Error while delaing with a timeout for the health check response from backend %s: %s", data->d_ds->getNameWithAddr(), e.what());
        }
      }
      catch (...) {
        if (g_verboseHealthChecks) {
          infolog("Error while delaing with a timeout for the health check response from backend %s", data->d_ds->getNameWithAddr());
        }
      }
    }
  }
}
