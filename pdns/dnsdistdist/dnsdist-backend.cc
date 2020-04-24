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
#include "dolog.hh"

bool DownstreamState::reconnect()
{
  std::unique_lock<std::mutex> tl(connectLock, std::try_to_lock);
  if (!tl.owns_lock()) {
    /* we are already reconnecting */
    return false;
  }

  connected = false;
  for (auto& fd : sockets) {
    if (fd != -1) {
      if (sockets.size() > 1) {
        std::lock_guard<std::mutex> lock(socketsLock);
        mplexer->removeReadFD(fd);
      }
      /* shutdown() is needed to wake up recv() in the responderThread */
      shutdown(fd, SHUT_RDWR);
      close(fd);
      fd = -1;
    }
    if (!IsAnyAddress(remote)) {
      fd = SSocket(remote.sin4.sin_family, SOCK_DGRAM, 0);
      if (!IsAnyAddress(sourceAddr)) {
        SSetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 1);
        if (!sourceItfName.empty()) {
#ifdef SO_BINDTODEVICE
          int res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, sourceItfName.c_str(), sourceItfName.length());
          if (res != 0) {
            infolog("Error setting up the interface on backend socket '%s': %s", remote.toStringWithPort(), stringerror());
          }
#endif
        }

        SBind(fd, sourceAddr);
      }
      try {
        SConnect(fd, remote);
        if (sockets.size() > 1) {
          std::lock_guard<std::mutex> lock(socketsLock);
          mplexer->addReadFD(fd, [](int, boost::any) {});
        }
        connected = true;
      }
      catch(const std::runtime_error& error) {
        infolog("Error connecting to new server with address %s: %s", remote.toStringWithPort(), error.what());
        connected = false;
        break;
      }
    }
  }

  /* if at least one (re-)connection failed, close all sockets */
  if (!connected) {
    for (auto& fd : sockets) {
      if (fd != -1) {
        if (sockets.size() > 1) {
          try {
            std::lock_guard<std::mutex> lock(socketsLock);
            mplexer->removeReadFD(fd);
          }
          catch (const FDMultiplexerException& e) {
            /* some sockets might not have been added to the multiplexer
               yet, that's fine */
          }
        }
        /* shutdown() is needed to wake up recv() in the responderThread */
        shutdown(fd, SHUT_RDWR);
        close(fd);
        fd = -1;
      }
    }
  }

  return connected;
}
void DownstreamState::hash()
{
  vinfolog("Computing hashes for id=%s and weight=%d", id, weight);
  auto w = weight;
  WriteLock wl(&d_lock);
  hashes.clear();
  hashes.reserve(w);
  while (w > 0) {
    std::string uuid = boost::str(boost::format("%s-%d") % id % w);
    unsigned int wshash = burtleCI(reinterpret_cast<const unsigned char*>(uuid.c_str()), uuid.size(), g_hashperturb);
    hashes.push_back(wshash);
    --w;
  }
  std::sort(hashes.begin(), hashes.end());
}

void DownstreamState::setId(const boost::uuids::uuid& newId)
{
  id = newId;
  // compute hashes only if already done
  if (!hashes.empty()) {
    hash();
  }
}

void DownstreamState::setWeight(int newWeight)
{
  if (newWeight < 1) {
    errlog("Error setting server's weight: downstream weight value must be greater than 0.");
    return ;
  }
  weight = newWeight;
  if (!hashes.empty()) {
    hash();
  }
}

DownstreamState::DownstreamState(const ComboAddress& remote_, const ComboAddress& sourceAddr_, unsigned int sourceItf_, const std::string& sourceItfName_, size_t numberOfSockets, bool connect=true): sourceItfName(sourceItfName_), remote(remote_), sourceAddr(sourceAddr_), sourceItf(sourceItf_), name(remote_.toStringWithPort()), nameWithAddr(remote_.toStringWithPort())
{
  pthread_rwlock_init(&d_lock, nullptr);
  id = getUniqueID();
  threadStarted.clear();

  mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());

  sockets.resize(numberOfSockets);
  for (auto& fd : sockets) {
    fd = -1;
  }

  if (connect && !IsAnyAddress(remote)) {
    reconnect();
    idStates.resize(g_maxOutstanding);
    sw.start();
  }

}
