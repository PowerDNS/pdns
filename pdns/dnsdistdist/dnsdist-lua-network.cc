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
NetworkListener::NetworkListener() :
  d_mplexer(std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(10)))
{
}

void NetworkListener::readCB(int desc, FDMultiplexer::funcparam_t& param)
{
  auto cbData = boost::any_cast<std::shared_ptr<NetworkListener::CBData>>(param);
  std::string packet;

#ifdef MSG_TRUNC
  /* first we peek to avoid allocating a very large buffer. "MSG_TRUNC [...] return the real length of the datagram, even when it was longer than the passed buffer" */
  auto peeked = recvfrom(desc, nullptr, 0, MSG_PEEK | MSG_TRUNC, nullptr, 0);
  if (peeked > 0) {
    packet.resize(static_cast<size_t>(peeked));
  }
#endif
  if (packet.size() == 0) {
    packet.resize(65535);
  }

  struct sockaddr_un from;
  memset(&from, 0, sizeof(from));

  socklen_t fromLen = sizeof(from);
  auto got = recvfrom(desc, &packet.at(0), packet.size(), 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
  if (got > 0) {
    packet.resize(static_cast<size_t>(got));
    std::string fromAddr;
    if (fromLen <= sizeof(from)) {
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

bool NetworkListener::addUnixListeningEndpoint(const std::string& path, NetworkListener::EndpointID id, NetworkListener::NetworkDatagramCB cb)
{
  if (d_running == true) {
    throw std::runtime_error("NetworkListener should not be altered at runtime");
  }

  struct sockaddr_un sun;
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

  if (bind(sock.getHandle(), reinterpret_cast<const struct sockaddr*>(&sun), sunLength) != 0) {
    std::string sanitizedPath(path);
    if (abstractPath) {
      sanitizedPath[0] = '@';
    }
    throw std::runtime_error("Error binding Unix socket to path '" + sanitizedPath + "': " + stringerror());
  }

  sock.setNonBlocking();

  auto cbData = std::make_shared<CBData>();
  cbData->d_endpoint = id;
  cbData->d_cb = std::move(cb);
  d_mplexer->addReadFD(sock.getHandle(), readCB, cbData);

  d_sockets.insert({path, std::move(sock)});
  return true;
}

void NetworkListener::runOnce(struct timeval& now, uint32_t timeout)
{
  d_running = true;
  if (d_sockets.empty()) {
    throw runtime_error("NetworkListener started with no sockets");
  }

  d_mplexer->run(&now, timeout);
}

void NetworkListener::mainThread()
{
  setThreadName("dnsdist/lua-net");
  struct timeval now;

  while (true) {
    runOnce(now, -1);
  }
}

void NetworkListener::start()
{
  std::thread main = std::thread([this] {
    mainThread();
  });
  main.detach();
}

NetworkEndpoint::NetworkEndpoint(const std::string& path) :
  d_socket(AF_UNIX, SOCK_DGRAM, 0)
{
  struct sockaddr_un sun;
  if (makeUNsockaddr(path, &sun) != 0) {
    throw std::runtime_error("Invalid Unix socket path '" + path + "'");
  }

  socklen_t sunLength = sizeof(sun);
  bool abstractPath = path.at(0) == '\0';

  if (abstractPath) {
    /* abstract paths can contain null bytes so we need to set the actual size */
    sunLength = sizeof(sa_family_t) + path.size();
  }
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
