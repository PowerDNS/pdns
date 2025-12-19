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
#include "dnsdist-lua.hh"
#include "dnsdist-random.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-session-cache.hh"

struct HealthCheckData
{
  enum class TCPState : uint8_t
  {
    WritingQuery,
    ReadingResponseSize,
    ReadingResponse
  };

  HealthCheckData(FDMultiplexer& mplexer, std::shared_ptr<DownstreamState> downstream, DNSName&& checkName, uint16_t checkType, uint16_t checkClass, uint16_t queryID) :
    d_ds(std::move(downstream)), d_mplexer(mplexer), d_udpSocket(-1), d_checkName(std::move(checkName)), d_checkType(checkType), d_checkClass(checkClass), d_queryID(queryID)
  {
  }

  const std::shared_ptr<DownstreamState> d_ds;
  FDMultiplexer& d_mplexer;
  std::unique_ptr<TCPIOHandler> d_tcpHandler{nullptr};
  std::unique_ptr<IOStateHandler> d_ioState{nullptr};
  PacketBuffer d_buffer;
  Socket d_udpSocket;
  DNSName d_checkName;
  StopWatch d_elapsed{false};
  timeval d_ttd{0, 0};
  size_t d_bufferPos{0};
  uint16_t d_checkType;
  uint16_t d_checkClass;
  uint16_t d_queryID;
  TCPState d_tcpState{TCPState::WritingQuery};
  bool d_initial{false};
};

static void updateLatencyMetrics(DownstreamState& downstream, int elapsed /* microseconds */)
{
  auto& histo = downstream.d_healthCheckLatencyHisto;
  downstream.d_healthCheckLatency.store(elapsed);

  if (elapsed < 1000) {
    ++histo.latency0_1;
  }
  else if (elapsed < 10000) {
    ++histo.latency1_10;
  }
  else if (elapsed < 50000) {
    ++histo.latency10_50;
  }
  else if (elapsed < 100000) {
    ++histo.latency50_100;
  }
  else if (elapsed < 1000000) {
    ++histo.latency100_1000;
  }
  else {
    ++histo.latencySlow;
  }

  histo.latencySum += static_cast<unsigned long>(elapsed) / 1000;
  ++histo.latencyCount;
}

static bool handleResponse(std::shared_ptr<HealthCheckData>& data)
{
  const auto verboseHealthChecks = dnsdist::configuration::getCurrentRuntimeConfiguration().d_verboseHealthChecks;
  const auto& downstream = data->d_ds;
  try {
    if (data->d_buffer.size() < sizeof(dnsheader)) {
      ++data->d_ds->d_healthCheckMetrics.d_parseErrors;
      if (verboseHealthChecks) {
        infolog("Invalid health check response of size %d from backend %s, expecting at least %d", data->d_buffer.size(), downstream->getNameWithAddr(), sizeof(dnsheader));
      }
      return false;
    }

    dnsheader_aligned responseHeader(data->d_buffer.data());
    if (responseHeader.get()->id != data->d_queryID) {
      ++data->d_ds->d_healthCheckMetrics.d_mismatchErrors;
      if (verboseHealthChecks) {
        infolog("Invalid health check response id %d from backend %s, expecting %d", responseHeader.get()->id, downstream->getNameWithAddr(), data->d_queryID);
      }
      return false;
    }

    if (!responseHeader.get()->qr) {
      ++data->d_ds->d_healthCheckMetrics.d_invalidResponseErrors;
      if (verboseHealthChecks) {
        infolog("Invalid health check response from backend %s, expecting QR to be set", downstream->getNameWithAddr());
      }
      return false;
    }

    if (responseHeader.get()->rcode == RCode::ServFail) {
      ++data->d_ds->d_healthCheckMetrics.d_invalidResponseErrors;
      if (verboseHealthChecks) {
        infolog("Backend %s responded to health check with ServFail", downstream->getNameWithAddr());
      }
      return false;
    }

    if (downstream->d_config.mustResolve && (responseHeader.get()->rcode == RCode::NXDomain || responseHeader.get()->rcode == RCode::Refused)) {
      ++data->d_ds->d_healthCheckMetrics.d_invalidResponseErrors;
      if (verboseHealthChecks) {
        infolog("Backend %s responded to health check with %s while mustResolve is set", downstream->getNameWithAddr(), responseHeader.get()->rcode == RCode::NXDomain ? "NXDomain" : "Refused");
      }
      return false;
    }

    uint16_t receivedType{0};
    uint16_t receivedClass{0};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    DNSName receivedName(reinterpret_cast<const char*>(data->d_buffer.data()), static_cast<int>(data->d_buffer.size()), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != data->d_checkName || receivedType != data->d_checkType || receivedClass != data->d_checkClass) {
      ++data->d_ds->d_healthCheckMetrics.d_mismatchErrors;
      if (verboseHealthChecks) {
        infolog("Backend %s responded to health check with an invalid qname (%s vs %s), qtype (%s vs %s) or qclass (%d vs %d)", downstream->getNameWithAddr(), receivedName.toLogString(), data->d_checkName.toLogString(), QType(receivedType).toString(), QType(data->d_checkType).toString(), receivedClass, data->d_checkClass);
      }
      return false;
    }
  }
  catch (const std::exception& e) {
    ++data->d_ds->d_healthCheckMetrics.d_parseErrors;
    if (verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", downstream->getNameWithAddr(), e.what());
    }
    return false;
  }
  catch (...) {
    if (verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", downstream->getNameWithAddr());
    }
    return false;
  }

  const auto elapsed = data->d_elapsed.udiff();
  updateLatencyMetrics(*data->d_ds, elapsed);

  return true;
}

class HealthCheckQuerySender : public TCPQuerySender
{
public:
  HealthCheckQuerySender(std::shared_ptr<HealthCheckData>& data) :
    d_data(data)
  {
  }
  HealthCheckQuerySender(const HealthCheckQuerySender&) = default;
  HealthCheckQuerySender(HealthCheckQuerySender&&) = default;
  HealthCheckQuerySender& operator=(const HealthCheckQuerySender&) = default;
  HealthCheckQuerySender& operator=(HealthCheckQuerySender&&) = default;
  ~HealthCheckQuerySender() override = default;

  [[nodiscard]] bool active() const override
  {
    return true;
  }

  void handleResponse(const struct timeval& now, TCPResponse&& response) override
  {
    (void)now;
    d_data->d_buffer = std::move(response.d_buffer);
    d_data->d_ds->submitHealthCheckResult(d_data->d_initial, ::handleResponse(d_data));
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    (void)now;
    (void)response;
    throw std::runtime_error("Unexpected XFR response to a health check query");
  }

  void notifyIOError(const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
    (void)now;
    (void)response;
    ++d_data->d_ds->d_healthCheckMetrics.d_networkErrors;
    d_data->d_ds->submitHealthCheckResult(d_data->d_initial, false);
  }

private:
  std::shared_ptr<HealthCheckData> d_data;
};

static void healthCheckUDPCallback(int descriptor, FDMultiplexer::funcparam_t& param)
{
  auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(param);
  const auto verboseHealthChecks = dnsdist::configuration::getCurrentRuntimeConfiguration().d_verboseHealthChecks;

  ssize_t got = 0;
  ComboAddress from;
  do {
    from.sin4.sin_family = data->d_ds->d_config.remote.sin4.sin_family;
    auto fromlen = from.getSocklen();
    data->d_buffer.resize(512);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    got = recvfrom(data->d_udpSocket.getHandle(), data->d_buffer.data(), data->d_buffer.size(), 0, reinterpret_cast<sockaddr*>(&from), &fromlen);
    if (got < 0) {
      int savederrno = errno;
      if (savederrno == EINTR) {
        /* interrupted before any data was available, let's try again */
        continue;
      }
      if (savederrno == EWOULDBLOCK || savederrno == EAGAIN) {
        /* spurious wake-up, let's return to sleep */
        return;
      }

      if (verboseHealthChecks) {
        infolog("Error receiving health check response from %s: %s", data->d_ds->d_config.remote.toStringWithPort(), stringerror(savederrno));
      }
      ++data->d_ds->d_healthCheckMetrics.d_networkErrors;
      data->d_ds->submitHealthCheckResult(data->d_initial, false);
      data->d_mplexer.removeReadFD(descriptor);
      return;
    }
  } while (got < 0);

  data->d_buffer.resize(static_cast<size_t>(got));

  /* we are using a connected socket but hey.. */
  if (from != data->d_ds->d_config.remote) {
    if (verboseHealthChecks) {
      infolog("Invalid health check response received from %s, expecting one from %s", from.toStringWithPort(), data->d_ds->d_config.remote.toStringWithPort());
    }
    ++data->d_ds->d_healthCheckMetrics.d_networkErrors;
    data->d_ds->submitHealthCheckResult(data->d_initial, false);
    return;
  }

  data->d_mplexer.removeReadFD(descriptor);
  data->d_ds->submitHealthCheckResult(data->d_initial, handleResponse(data));
}

static void healthCheckTCPCallback(int descriptor, FDMultiplexer::funcparam_t& param)
{
  (void)descriptor;
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
        uint16_t responseSize{0};
        memcpy(&responseSize, data->d_buffer.data(), sizeof(responseSize));
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
    const auto verboseHealthChecks = dnsdist::configuration::getCurrentRuntimeConfiguration().d_verboseHealthChecks;
    if (verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", data->d_ds->getNameWithAddr(), e.what());
    }
  }
  catch (...) {
    data->d_ds->submitHealthCheckResult(data->d_initial, false);
    const auto verboseHealthChecks = dnsdist::configuration::getCurrentRuntimeConfiguration().d_verboseHealthChecks;
    if (verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", data->d_ds->getNameWithAddr());
    }
  }
}

bool queueHealthCheck(std::unique_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& downstream, bool initialCheck)
{
  const auto verboseHealthChecks = dnsdist::configuration::getCurrentRuntimeConfiguration().d_verboseHealthChecks;
  try {
    uint16_t queryID = dnsdist::getRandomDNSID();
    DNSName checkName = downstream->d_config.checkName;
    uint16_t checkType = downstream->d_config.checkType.getCode();
    uint16_t checkClass = downstream->d_config.checkClass;
    dnsheader checkHeader{};
    memset(&checkHeader, 0, sizeof(checkHeader));

    checkHeader.qdcount = htons(1);
    checkHeader.id = queryID;

    checkHeader.rd = true;
    if (downstream->d_config.setCD) {
      checkHeader.cd = true;
    }

    if (downstream->d_config.checkFunction) {
      auto lock = g_lua.lock();
      auto ret = downstream->d_config.checkFunction(checkName, checkType, checkClass, &checkHeader);
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
    if (downstream->d_config.useProxyProtocol) {
      proxyProtocolPayload = makeLocalProxyHeader();
      proxyProtocolPayloadSize = proxyProtocolPayload.size();
      if (!downstream->isDoH()) {
        packet.insert(packet.begin(), proxyProtocolPayload.begin(), proxyProtocolPayload.end());
      }
    }

    Socket sock(downstream->d_config.remote.sin4.sin_family, downstream->doHealthcheckOverTCP() ? SOCK_STREAM : SOCK_DGRAM);

    sock.setNonBlocking();

#ifdef SO_BINDTODEVICE
    if (!downstream->d_config.sourceItfName.empty()) {
      int res = setsockopt(sock.getHandle(), SOL_SOCKET, SO_BINDTODEVICE, downstream->d_config.sourceItfName.c_str(), downstream->d_config.sourceItfName.length());
      if (res != 0 && verboseHealthChecks) {
        infolog("Error setting SO_BINDTODEVICE on the health check socket for backend '%s': %s", downstream->getNameWithAddr(), stringerror());
      }
    }
#endif

    if (!IsAnyAddress(downstream->d_config.sourceAddr)) {
      if (downstream->doHealthcheckOverTCP()) {
        sock.setReuseAddr();
      }
#ifdef IP_BIND_ADDRESS_NO_PORT
      if (downstream->d_config.ipBindAddrNoPort) {
        SSetsockopt(sock.getHandle(), SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
      }
#endif
      sock.bind(downstream->d_config.sourceAddr, false);
    }

    auto data = std::make_shared<HealthCheckData>(*mplexer, downstream, std::move(checkName), checkType, checkClass, queryID);
    data->d_initial = initialCheck;

    gettimeofday(&data->d_ttd, nullptr);
    data->d_ttd.tv_sec += static_cast<decltype(data->d_ttd.tv_sec)>(downstream->d_config.checkTimeout / 1000); /* ms to seconds */
    data->d_ttd.tv_usec += static_cast<decltype(data->d_ttd.tv_usec)>((downstream->d_config.checkTimeout % 1000) * 1000); /* remaining ms to us */
    normalizeTV(data->d_ttd);
    data->d_elapsed.start();

    if (!downstream->doHealthcheckOverTCP()) {
      sock.connect(downstream->d_config.remote);
      data->d_udpSocket = std::move(sock);
      ssize_t sent = udpClientSendRequestToBackend(downstream, data->d_udpSocket.getHandle(), packet, true);
      if (sent < 0) {
        int ret = errno;
        if (verboseHealthChecks) {
          infolog("Error while sending a health check query (ID %d) to backend %s: %d", queryID, downstream->getNameWithAddr(), ret);
        }
        return false;
      }

      mplexer->addReadFD(data->d_udpSocket.getHandle(), &healthCheckUDPCallback, data, &data->d_ttd);
    }
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    else if (downstream->isDoH()) {
      InternalQuery query(std::move(packet), InternalQueryState());
      query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);
      auto sender = std::shared_ptr<TCPQuerySender>(new HealthCheckQuerySender(data));
      if (!sendH2Query(downstream, mplexer, sender, std::move(query), true)) {
        data->d_ds->submitHealthCheckResult(data->d_initial, false);
      }
    }
#endif
    else {
      data->d_tcpHandler = std::make_unique<TCPIOHandler>(downstream->d_config.d_tlsSubjectName, downstream->d_config.d_tlsSubjectIsAddr, sock.releaseHandle(), timeval{downstream->d_config.checkTimeout, 0}, downstream->d_tlsCtx);
      data->d_ioState = std::make_unique<IOStateHandler>(*mplexer, data->d_tcpHandler->getDescriptor());
      if (downstream->d_tlsCtx) {
        try {
          time_t now = time(nullptr);
          auto tlsSession = g_sessionCache.getSession(downstream->getID(), now);
          if (tlsSession) {
            data->d_tcpHandler->setTLSSession(tlsSession);
          }
        }
        catch (const std::exception& e) {
          vinfolog("Unable to restore a TLS session for the DoT healthcheck for backend %s: %s", downstream->getNameWithAddr(), e.what());
        }
      }
      data->d_tcpHandler->tryConnect(downstream->d_config.tcpFastOpen, downstream->d_config.remote);

      const std::array<uint8_t, 2> sizeBytes = {static_cast<uint8_t>(packetSize / 256), static_cast<uint8_t>(packetSize % 256)};
      packet.insert(packet.begin() + static_cast<ssize_t>(proxyProtocolPayloadSize), sizeBytes.begin(), sizeBytes.end());
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
    if (verboseHealthChecks) {
      infolog("Error checking the health of backend %s: %s", downstream->getNameWithAddr(), e.what());
    }
    return false;
  }
  catch (...) {
    if (verboseHealthChecks) {
      infolog("Unknown exception while checking the health of backend %s", downstream->getNameWithAddr());
    }
    return false;
  }
}

void handleQueuedHealthChecks(FDMultiplexer& mplexer, bool initial)
{
  const auto verboseHealthChecks = dnsdist::configuration::getCurrentRuntimeConfiguration().d_verboseHealthChecks;
  while (mplexer.getWatchedFDCount(false) > 0 || mplexer.getWatchedFDCount(true) > 0) {
    struct timeval now{};
    int ret = mplexer.run(&now, 100);
    if (ret == -1) {
      if (verboseHealthChecks) {
        infolog("Error while waiting for the health check response from backends: %d", ret);
      }
      break;
    }
    if (ret > 0) {
      /* we got at least one event other than a timeout */
      continue;
    }

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    handleH2Timeouts(mplexer, now);
#endif

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
        if (verboseHealthChecks) {
          infolog("Timeout while waiting for the health check response (ID %d) from backend %s", data->d_queryID, data->d_ds->getNameWithAddr());
        }

        ++data->d_ds->d_healthCheckMetrics.d_timeOuts;
        data->d_ds->submitHealthCheckResult(initial, false);
      }
      catch (const std::exception& e) {
        /* this is not supposed to happen as the file descriptor has to be
           there for us to reach that code, and the submission code should not throw,
           but let's provide a nice error message if it ever does. */
        if (verboseHealthChecks) {
          infolog("Error while dealing with a timeout for the health check response (ID %d) from backend %s: %s", data->d_queryID, data->d_ds->getNameWithAddr(), e.what());
        }
      }
      catch (...) {
        /* this is even less likely to happen */
        if (verboseHealthChecks) {
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
        if (verboseHealthChecks) {
          infolog("Timeout while waiting for the health check response (ID %d) from backend %s", data->d_queryID, data->d_ds->getNameWithAddr());
        }

        ++data->d_ds->d_healthCheckMetrics.d_timeOuts;
        data->d_ds->submitHealthCheckResult(initial, false);
      }
      catch (const std::exception& e) {
        /* this is not supposed to happen as the submission code should not throw,
           but let's provide a nice error message if it ever does. */
        if (verboseHealthChecks) {
          infolog("Error while dealing with a timeout for the health check response (ID %d) from backend %s: %s", data->d_queryID, data->d_ds->getNameWithAddr(), e.what());
        }
      }
      catch (...) {
        /* this is even less likely to happen */
        if (verboseHealthChecks) {
          infolog("Error while dealing with a timeout for the health check response (ID %d) from backend %s", data->d_queryID, data->d_ds->getNameWithAddr());
        }
      }
    }
  }
}
