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
#include "dnswriter.hh"
#include "dolog.hh"

bool g_verboseHealthChecks{false};

void updateHealthCheckResult(const std::shared_ptr<DownstreamState>& dss, bool newState)
{
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
  if(newState != dss->upStatus) {
    warnlog("Marking downstream %s as '%s'", dss->getNameWithAddr(), newState ? "up" : "down");

    if (newState && !dss->connected) {
      newState = dss->reconnect();

      if (dss->connected && !dss->threadStarted.test_and_set()) {
        dss->tid = std::thread(responderThread, dss);
      }
    }

    dss->upStatus = newState;
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
    string reply;
    ComboAddress from;
    data->d_sock.recvFrom(reply, from);

    /* we are using a connected socket but hey.. */
    if (from != ds->remote) {
      if (g_verboseHealthChecks) {
        infolog("Invalid health check response received from %s, expecting one from %s", from.toStringWithPort(), ds->remote.toStringWithPort());
      }
      return false;
    }

    const dnsheader * responseHeader = reinterpret_cast<const dnsheader *>(reply.c_str());

    if (reply.size() < sizeof(*responseHeader)) {
      if (g_verboseHealthChecks) {
        infolog("Invalid health check response of size %d from backend %s, expecting at least %d", reply.size(), ds->getNameWithAddr(), sizeof(*responseHeader));
      }
      return false;
    }

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
    DNSName receivedName(reply.c_str(), reply.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

    if (receivedName != data->d_checkName || receivedType != data->d_checkType || receivedClass != data->d_checkClass) {
      if (g_verboseHealthChecks) {
        infolog("Backend %s responded to health check with an invalid qname (%s vs %s), qtype (%s vs %s) or qclass (%d vs %d)", ds->getNameWithAddr(), receivedName.toLogString(), data->d_checkName.toLogString(), QType(receivedType).getName(), QType(data->d_checkType).getName(), receivedClass, data->d_checkClass);
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

static void healthCheckCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(param);
  data->d_mplexer->removeReadFD(fd);
  updateHealthCheckResult(data->d_ds, handleResponse(data));
}

static void initialHealthCheckCallback(int fd, FDMultiplexer::funcparam_t& param)
{
  auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(param);
  data->d_mplexer->removeReadFD(fd);
  bool up = handleResponse(data);
  warnlog("Marking downstream %s as '%s'", data->d_ds->getNameWithAddr(), up ? "up" : "down");
  data->d_ds->upStatus = up;
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
      std::lock_guard<std::mutex> lock(g_luamutex);
      auto ret = ds->checkFunction(checkName, checkType, checkClass, &checkHeader);
      checkName = std::get<0>(ret);
      checkType = std::get<1>(ret);
      checkClass = std::get<2>(ret);
    }

    vector<uint8_t> packet;
    DNSPacketWriter dpw(packet, checkName, checkType, checkClass);
    dnsheader * requestHeader = dpw.getHeader();
    *requestHeader = checkHeader;

    Socket sock(ds->remote.sin4.sin_family, SOCK_DGRAM);
    sock.setNonBlocking();
    if (!IsAnyAddress(ds->sourceAddr)) {
      sock.setReuseAddr();
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
    sock.connect(ds->remote);
    ssize_t sent = udpClientSendRequestToBackend(ds, sock.getHandle(), reinterpret_cast<char*>(&packet[0]), packet.size(), true);
    if (sent < 0) {
      int ret = errno;
      if (g_verboseHealthChecks)
        infolog("Error while sending a health check query to backend %s: %d", ds->getNameWithAddr(), ret);
      return false;
    }

    auto data = std::make_shared<HealthCheckData>(mplexer, ds, std::move(sock), std::move(checkName), checkType, checkClass, queryID);
    struct timeval ttd;
    gettimeofday(&ttd, nullptr);
    ttd.tv_sec += ds->checkTimeout / 1000; /* ms to seconds */
    ttd.tv_usec += (ds->checkTimeout % 1000) * 1000; /* remaining ms to us */
    if (ttd.tv_usec > 1000000) {
      ++ttd.tv_sec;
      ttd.tv_usec -= 1000000;
    }
    mplexer->addReadFD(data->d_sock.getHandle(), initialCheck ? &initialHealthCheckCallback : &healthCheckCallback, data, &ttd);

    return true;
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
}

void handleQueuedHealthChecks(std::shared_ptr<FDMultiplexer>& mplexer, bool initial)
{
  while (mplexer->getWatchedFDCount(false) > 0) {
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
      mplexer->removeReadFD(timeout.first);
      auto data = boost::any_cast<std::shared_ptr<HealthCheckData>>(timeout.second);
      if (g_verboseHealthChecks) {
        infolog("Timeout while waiting for the health check response from backend %s", data->d_ds->getNameWithAddr());
      }
      if (initial) {
        warnlog("Marking downstream %s as 'down'", data->d_ds->getNameWithAddr());
        data->d_ds->upStatus = false;
      }
      else {
        updateHealthCheckResult(data->d_ds, false);
      }
    }
  }
}
