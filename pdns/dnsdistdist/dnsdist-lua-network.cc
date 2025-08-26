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
#include <sys/socket.h>
#include <sys/un.h>

#include "dnsdist-lua-network.hh"
#include "dolog.hh"
#include "threadname.hh"

namespace dnsdist
{
NetworkListener::ListenerData::ListenerData() :
  d_mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(10)))
{
}

NetworkListener::NetworkListener() :
  d_data(std::make_shared<ListenerData>())
{
}

NetworkListener::~NetworkListener()
{
  d_data->d_exiting = true;

  /* wake up the listening thread */
  for (const auto& socket : d_data->d_sockets) {
    shutdown(socket.second.getHandle(), SHUT_RD);
  }
}

void NetworkListener::readCB(int desc, FDMultiplexer::funcparam_t& param)
{
  auto cbData = boost::any_cast<std::shared_ptr<NetworkListener::CBData>>(param);
  std::string packet;

#ifdef MSG_TRUNC
  /* first we peek to avoid allocating a very large buffer. "MSG_TRUNC [...] return the real length of the datagram, even when it was longer than the passed buffer" */
  auto peeked = recvfrom(desc, nullptr, 0, MSG_PEEK | MSG_TRUNC, nullptr, nullptr);
  if (peeked > 0) {
    packet.resize(static_cast<size_t>(peeked));
  }
#endif
  if (packet.empty()) {
    packet.resize(65535);
  }

  sockaddr_un from{};
  memset(&from, 0, sizeof(from));

  socklen_t fromLen = sizeof(from);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  auto got = recvfrom(desc, &packet.at(0), packet.size(), 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
  if (got > 0) {
    packet.resize(static_cast<size_t>(got));
    std::string fromAddr;
    if (fromLen <= sizeof(from)) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
      fromAddr = std::string(from.sun_path, strlen(from.sun_path));
    }
    try {
      cbData->d_cb(cbData->d_endpoint, std::move(packet), fromAddr);
    }
    catch (const std::exception& e) {
      vinfolog("Exception in the read callback of a NetworkListener: %s", e.what());
    }
    catch (...) {
      vinfolog("Exception in the read callback of a NetworkListener");
    }
  }
}

bool NetworkListener::addUnixListeningEndpoint(const std::string& path, NetworkListener::EndpointID endpointID, NetworkListener::NetworkDatagramCB callback)
{
  if (d_data->d_running) {
    throw std::runtime_error("NetworkListener should not be altered at runtime");
  }

  sockaddr_un sun{};
  if (makeUNsockaddr(path, &sun) != 0) {
    throw std::runtime_error("Invalid Unix socket path '" + path + "'");
  }

  bool abstractPath = path.at(0) == '\0';
  if (!abstractPath) {
    int err = unlink(path.c_str());
    if (err != 0) {
      err = errno;
      if (err != ENOENT) {
        vinfolog("Error removing Unix socket to path '%s': %s", path, stringerror(err));
      }
    }
  }

  Socket sock(sun.sun_family, SOCK_DGRAM, 0);
  socklen_t sunLength = sizeof(sun);
  if (abstractPath) {
    /* abstract paths can contain null bytes so we need to set the actual size */
    sunLength = sizeof(sa_family_t) + path.size();
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (bind(sock.getHandle(), reinterpret_cast<const struct sockaddr*>(&sun), sunLength) != 0) {
    std::string sanitizedPath(path);
    if (abstractPath) {
      sanitizedPath[0] = '@';
    }
    throw std::runtime_error("Error binding Unix socket to path '" + sanitizedPath + "': " + stringerror());
  }

  sock.setNonBlocking();

  auto cbData = std::make_shared<CBData>();
  cbData->d_endpoint = endpointID;
  cbData->d_cb = std::move(callback);
  d_data->d_mplexer->addReadFD(sock.getHandle(), readCB, cbData);

  d_data->d_sockets.insert({path, std::move(sock)});
  return true;
}

void NetworkListener::runOnce(ListenerData& data, timeval& now, uint32_t timeout)
{
  if (data.d_exiting) {
    return;
  }

  dnsdist::configuration::refreshLocalRuntimeConfiguration();
  data.d_running = true;
  if (data.d_sockets.empty()) {
    throw runtime_error("NetworkListener started with no sockets");
  }

  data.d_mplexer->run(&now, static_cast<int>(timeout));
}

void NetworkListener::runOnce(timeval& now, uint32_t timeout)
{
  runOnce(*d_data, now, timeout);
}

void NetworkListener::mainThread(std::shared_ptr<ListenerData>& dataArg)
{
  /* take our own copy of the shared_ptr so it's still alive if the NetworkListener object
     gets destroyed while we are still running */
  // NOLINTNEXTLINE(performance-unnecessary-copy-initialization): we really need a copy here, or we end up with use-after-free as explained above
  auto data = dataArg;
  setThreadName("dnsdist/lua-net");
  timeval now{};

  while (!data->d_exiting) {
    runOnce(*data, now, -1);
  }
}

void NetworkListener::start()
{
  std::thread main = std::thread([this] {
    mainThread(d_data);
  });
  main.detach();
}

NetworkEndpoint::NetworkEndpoint(const std::string& path) :
  d_socket(AF_UNIX, SOCK_DGRAM, 0)
{
  sockaddr_un sun{};
  if (makeUNsockaddr(path, &sun) != 0) {
    throw std::runtime_error("Invalid Unix socket path '" + path + "'");
  }

  socklen_t sunLength = sizeof(sun);
  bool abstractPath = path.at(0) == '\0';

  if (abstractPath) {
    /* abstract paths can contain null bytes so we need to set the actual size */
    sunLength = sizeof(sa_family_t) + path.size();
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (connect(d_socket.getHandle(), reinterpret_cast<const struct sockaddr*>(&sun), sunLength) != 0) {
    std::string sanitizedPath(path);
    if (abstractPath) {
      sanitizedPath[0] = '@';
    }
    throw std::runtime_error("Error connecting Unix socket to path '" + sanitizedPath + "': " + stringerror());
  }

  d_socket.setNonBlocking();
}

bool NetworkEndpoint::send(const std::string_view& payload) const
{
  auto sent = ::send(d_socket.getHandle(), payload.data(), payload.size(), 0);
  if (sent <= 0) {
    return false;
  }

  return static_cast<size_t>(sent) == payload.size();
}
}
