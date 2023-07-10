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
#include "dnsdist-random.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-session-cache.hh"

bool g_verboseHealthChecks{false};

struct HealthCheckData
{
  enum class TCPState : uint8_t { WritingQuery, ReadingResponseSize, ReadingResponse };

  HealthCheckData(FDMultiplexer& mplexer, const std::shared_ptr<DownstreamState>& ds, DNSName&& checkName, uint16_t checkType, uint16_t checkClass, uint16_t queryID): d_ds(ds), d_mplexer(mplexer), d_udpSocket(-1), d_checkName(std::move(checkName)), d_checkType(checkType), d_checkClass(checkClass), d_queryID(queryID)
  {
  }

  const std::shared_ptr<DownstreamState> d_ds;
  FDMultiplexer& d_mplexer;
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

static bool handleResponse(std::shared_ptr<HealthCheckData>& data)
{
  auto& ds = data->d_ds;
  try {
    if (data->d_buffer.size() < sizeof(dnsheader)) {
      ++data->d_ds->d_healthCheckMetrics.d_parseErrors;
      if (g_verboseHealthChecks) {
        infolog("Invalid health check response of size %d from backend %s, expecting at least %d", data->d_buffer.size(), ds->getNameWithAddr(), sizeof(dnsheader));
      }
      return false;
    }

    const dnsheader * responseHeader = reinterpret_cast<const dnsheader*>(data->d_buffer.data());
    if (responseHeader->id != data->d_queryID) {
      ++data->d_ds->d_healthCheckMetrics.d_mismatchErrors;
      if (g_verboseHealthChecks) {
        infolog("Invalid health check response id %d from backend %s, expecting %d", responseHeader->id, ds->getNameWithAddr(), data->d_queryID);
      }
      return false;
    }

    if (!responseHeader->qr) {
      ++data->d_ds->d_healthCheckMetrics.d_invalidResponseErrors;
      if (g_verboseHealthChecks) {
        infolog("Invalid health check response from backend %s, expecting QR to be set", ds->getNameWithAddr());
      }
      return false;
    }

    if (responseHeader->rcode == RCode::ServFail) {
      ++data->d_ds->d_healthCheckMetrics.d_invalidResponseErrors;
      if (g_verboseHealthChecks) {
        infolog("Backend %s responded to health check with ServFail", ds->getNameWithAddr());
      }
      return false;
    }

    if (ds->d_config.mustResolve && (responseHeader->rcode == RCode::NXDomain || responseHeader->rcode == RCode::Refused)) {
      ++data->d_ds->d_healthCheckMetrics.d_invalidResponseErrors;
      if (g_verboseHealthChecks) {
        infolog("Backend %s responded to health check with %s while mustResolve is set", ds->getNameWithAddr(), responseHeader->rcode == RCode::NXDomain ? "NXDomain" : "Refused");
      }
      return false;
    }

    uint16_t receivedType;
    uint16_t receivedClass;
    DNSName receivedName(reinterpret_cast<const char*>(data->d_buffer.data()), data->d_buffer.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != data->d_checkName || receivedType != data->d_checkType || receivedClass != data->d_checkClass) {
      ++data->d_ds->d_healthCheckMetrics.d_mismatchErrors;
      if (g_verboseHealthChecks) {
        infolog("Backend %s responded to health check with an invalid qname (%s vs %s), qtype (%s vs %s) or qclass (%d vs %d)", ds->getNameWithAddr(), receivedName.toLogString(), data->d_checkName.toLogString(), QType(receivedType).toString(), QType(data->d_checkType).toString(), receivedClass, data->d_checkClass);
      }
      return false;
    }
  }
  catch (const std::exception& e) {
    ++data->d_ds->d_healthCheckMetrics.d_parseErrors;
    if (g_verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", ds->getNameWithAddr(), e.what());
    }
    return false;
  }
  catch (...) {
    if (g_verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", ds->getNameWithAddr());
    }
    return false;
  }

  return true;
}

class HealthCheckQuerySender : public TCPQuerySender
{
public:
  HealthCheckQuerySender(std::shared_ptr<HealthCheckData>& data): d_data(data)
  {
  }

  ~HealthCheckQuerySender()
  {
  }

  bool active() const override
  {
    return true;
  }

  void handleResponse(const struct timeval& now, TCPResponse&& response) override
  {
    d_data->d_buffer = std::move(response.d_buffer);
    d_data->d_ds->submitHealthCheckResult(d_data->d_initial, ::handleResponse(d_data));
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    throw std::runtime_error("Unexpected XFR reponse to a health check query");
  }

  void notifyIOError(InternalQueryState&& query, const struct timeval& now) override
  {
    ++d_data->d_ds->d_healthCheckMetrics.d_networkErrors;
    d_data->d_ds->submitHealthCheckResult(d_data->d_initial, false);
  }

private:
  std::shared_ptr<HealthCheckData> d_data;
};

static void healthCheckUDPCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(param);
  data->d_mplexer.removeReadFD(fd);

  ComboAddress from;
  from.sin4.sin_family = data->d_ds->d_config.remote.sin4.sin_family;
  auto fromlen = from.getSocklen();
  data->d_buffer.resize(512);
  auto got = recvfrom(data->d_udpSocket.getHandle(), &data->d_buffer.at(0), data->d_buffer.size(), 0, reinterpret_cast<sockaddr *>(&from), &fromlen);
  if (got < 0) {
    int savederrno = errno;
    if (g_verboseHealthChecks) {
      infolog("Error receiving health check response from %s: %s", data->d_ds->d_config.remote.toStringWithPort(), stringerror(savederrno));
    }
    ++data->d_ds->d_healthCheckMetrics.d_networkErrors;
    data->d_ds->submitHealthCheckResult(data->d_initial, false);
    return;
  }
  data->d_buffer.resize(static_cast<size_t>(got));

  /* we are using a connected socket but hey.. */
  if (from != data->d_ds->d_config.remote) {
    if (g_verboseHealthChecks) {
      infolog("Invalid health check response received from %s, expecting one from %s", from.toStringWithPort(), data->d_ds->d_config.remote.toStringWithPort());
    }
    ++data->d_ds->d_healthCheckMetrics.d_networkErrors;
    data->d_ds->submitHealthCheckResult(data->d_initial, false);
    return;
  }

  data->d_ds->submitHealthCheckResult(data->d_initial, handleResponse(data));
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
        data->d_ds->submitHealthCheckResult(data->d_initial, handleResponse(data));
      }
    }

    if (ioState == IOState::Done) {
      /* remove us from the mplexer, we are done */
      data->d_ioState->update(ioState, healthCheckTCPCallback, data);
      if (data->d_tcpHandler->isTLS()) {
        try {
          auto sessions = data->d_tcpHandler->getTLSSessions();
          if (!sessions.empty()) {
            g_sessionCache.putSessions(data->d_ds->getID(), time(nullptr), std::move(sessions));
          }
        }
        catch (const std::exception& e) {
          vinfolog("Unable to get a TLS session from the DoT healthcheck: %s", e.what());
        }
      }
    }
    else {
      data->d_ioState->update(ioState, healthCheckTCPCallback, data, data->d_ttd);
    }

    /* the state has been updated, we can release the guard */
    ioGuard.release();
  }
  catch (const std::exception& e) {
    ++data->d_ds->d_healthCheckMetrics.d_networkErrors;
    data->d_ds->submitHealthCheckResult(data->d_initial, false);
    if (g_verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", data->d_ds->getNameWithAddr(), e.what());
    }
  }
  catch (...) {
    data->d_ds->submitHealthCheckResult(data->d_initial, false);
    if (g_verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", data->d_ds->getNameWithAddr());
    }
  }
}

bool queueHealthCheck(std::unique_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& ds, bool initialCheck)
{
  try {
    uint16_t queryID = dnsdist::getRandomDNSID();
    DNSName checkName = ds->d_config.checkName;
    uint16_t checkType = ds->d_config.checkType.getCode();
    uint16_t checkClass = ds->d_config.checkClass;
    dnsheader checkHeader;
    memset(&checkHeader, 0, sizeof(checkHeader));

    checkHeader.qdcount = htons(1);
    checkHeader.id = queryID;

    checkHeader.rd = true;
    if (ds->d_config.setCD) {
      checkHeader.cd = true;
    }

    if (ds->d_config.checkFunction) {
      auto lock = g_lua.lock();
      auto ret = ds->d_config.checkFunction(checkName, checkType, checkClass, &checkHeader);
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
    std::string proxyProtocolPayload;
    size_t proxyProtocolPayloadSize = 0;
    if (ds->d_config.useProxyProtocol) {
      proxyProtocolPayload = makeLocalProxyHeader();
      proxyProtocolPayloadSize = proxyProtocolPayload.size();
      if (!ds->isDoH()) {
        packet.insert(packet.begin(), proxyProtocolPayload.begin(), proxyProtocolPayload.end());
      }
    }

    Socket sock(ds->d_config.remote.sin4.sin_family, ds->doHealthcheckOverTCP() ? SOCK_STREAM : SOCK_DGRAM);

    sock.setNonBlocking();

#ifdef SO_BINDTODEVICE
    if (!ds->d_config.sourceItfName.empty()) {
      int res = setsockopt(sock.getHandle(), SOL_SOCKET, SO_BINDTODEVICE, ds->d_config.sourceItfName.c_str(), ds->d_config.sourceItfName.length());
      if (res != 0 && g_verboseHealthChecks) {
        infolog("Error setting SO_BINDTODEVICE on the health check socket for backend '%s': %s", ds->getNameWithAddr(), stringerror());
      }
    }
#endif

    if (!IsAnyAddress(ds->d_config.sourceAddr)) {
      if (ds->doHealthcheckOverTCP()) {
        sock.setReuseAddr();
      }
#ifdef IP_BIND_ADDRESS_NO_PORT
      if (ds->d_config.ipBindAddrNoPort) {
        SSetsockopt(sock.getHandle(), SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
      }
#endif
      sock.bind(ds->d_config.sourceAddr, false);
    }

    auto data = std::make_shared<HealthCheckData>(*mplexer, ds, std::move(checkName), checkType, checkClass, queryID);
    data->d_initial = initialCheck;

    gettimeofday(&data->d_ttd, nullptr);
    data->d_ttd.tv_sec += ds->d_config.checkTimeout / 1000; /* ms to seconds */
    data->d_ttd.tv_usec += (ds->d_config.checkTimeout % 1000) * 1000; /* remaining ms to us */
    normalizeTV(data->d_ttd);

    if (!ds->doHealthcheckOverTCP()) {
      sock.connect(ds->d_config.remote);
      data->d_udpSocket = std::move(sock);
      ssize_t sent = udpClientSendRequestToBackend(ds, data->d_udpSocket.getHandle(), packet, true);
      if (sent < 0) {
        int ret = errno;
        if (g_verboseHealthChecks) {
          infolog("Error while sending a health check query (ID %d) to backend %s: %d", queryID, ds->getNameWithAddr(), ret);
        }
        return false;
      }

      mplexer->addReadFD(data->d_udpSocket.getHandle(), &healthCheckUDPCallback, data, &data->d_ttd);
    }
    else if (ds->isDoH()) {
      InternalQuery query(std::move(packet), InternalQueryState());
      query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);
      auto sender = std::shared_ptr<TCPQuerySender>(new HealthCheckQuerySender(data));
      if (!sendH2Query(ds, mplexer, sender, std::move(query), true)) {
        data->d_ds->submitHealthCheckResult(data->d_initial, false);
      }
    }
    else {
      data->d_tcpHandler = std::make_unique<TCPIOHandler>(ds->d_config.d_tlsSubjectName, ds->d_config.d_tlsSubjectIsAddr, sock.releaseHandle(), timeval{ds->d_config.checkTimeout,0}, ds->d_tlsCtx);
      data->d_ioState = std::make_unique<IOStateHandler>(*mplexer, data->d_tcpHandler->getDescriptor());
      if (ds->d_tlsCtx) {
        try {
          time_t now = time(nullptr);
          auto tlsSession = g_sessionCache.getSession(ds->getID(), now);
          if (tlsSession) {
            data->d_tcpHandler->setTLSSession(tlsSession);
          }
        }
        catch (const std::exception& e) {
          vinfolog("Unable to restore a TLS session for the DoT healthcheck for backend %s: %s", ds->getNameWithAddr(), e.what());
        }
      }
      data->d_tcpHandler->tryConnect(ds->d_config.tcpFastOpen, ds->d_config.remote);

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
  catch (const std::exception& e) {
    if (g_verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", ds->getNameWithAddr(), e.what());
    }
    return false;
  }
  catch (...) {
    if (g_verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", ds->getNameWithAddr());
    }
    return false;
  }
}

void handleQueuedHealthChecks(FDMultiplexer& mplexer, bool initial)
{
  while (mplexer.getWatchedFDCount(false) > 0 || mplexer.getWatchedFDCount(true) > 0) {
    struct timeval now;
    int ret = mplexer.run(&now, 100);
    if (ret == -1) {
      if (g_verboseHealthChecks) {
        infolog("Error while waiting for the health check response from backends: %d", ret);
      }
      break;
    }
    if (ret > 0) {
      /* we got at least one event other than a timeout */
      continue;
    }

    handleH2Timeouts(mplexer, now);

    auto timeouts = mplexer.getTimeouts(now);
    for (const auto& timeout : timeouts) {
      if (timeout.second.type() != typeid(std::shared_ptr<HealthCheckData>)) {
        continue;
      }

      auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(timeout.second);
      try {
        /* UDP does not have an IO state, H2 is handled separately */
        if (data->d_ioState) {
          data->d_ioState.reset();
        }
        else {
          mplexer.removeReadFD(timeout.first);
        }
        if (g_verboseHealthChecks) {
          infolog("Timeout while waiting for the health check response (ID %d) from backend %s", data->d_queryID, data->d_ds->getNameWithAddr());
        }

        ++data->d_ds->d_healthCheckMetrics.d_timeOuts;
        data->d_ds->submitHealthCheckResult(initial, false);
      }
      catch (const std::exception& e) {
        if (g_verboseHealthChecks) {
          infolog("Error while dealing with a timeout for the health check response (ID %d) from backend %s: %s", data->d_queryID, data->d_ds->getNameWithAddr(), e.what());
        }
      }
      catch (...) {
        if (g_verboseHealthChecks) {
          infolog("Error while dealing with a timeout for the health check response (ID %d) from backend %s", data->d_queryID, data->d_ds->getNameWithAddr());
        }
      }
    }

    timeouts = mplexer.getTimeouts(now, true);
    for (const auto& timeout : timeouts) {
      if (timeout.second.type() != typeid(std::shared_ptr<HealthCheckData>)) {
        continue;
      }
      auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(timeout.second);
      try {
        /* UDP does not block while writing, H2 is handled separately */
        data->d_ioState.reset();
        if (g_verboseHealthChecks) {
          infolog("Timeout while waiting for the health check response (ID %d) from backend %s", data->d_queryID, data->d_ds->getNameWithAddr());
        }

        ++data->d_ds->d_healthCheckMetrics.d_timeOuts;
        data->d_ds->submitHealthCheckResult(initial, false);
      }
      catch (const std::exception& e) {
        if (g_verboseHealthChecks) {
          infolog("Error while dealing with a timeout for the health check response (ID %d) from backend %s: %s", data->d_queryID, data->d_ds->getNameWithAddr(), e.what());
        }
      }
      catch (...) {
        if (g_verboseHealthChecks) {
          infolog("Error while dealing with a timeout for the health check response (ID %d) from backend %s", data->d_queryID, data->d_ds->getNameWithAddr());
        }
      }
    }
  }
}
