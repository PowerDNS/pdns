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
#include "dnsdist-nghttp2.hh"
#include "dnsdist-tcp.hh"
#include "dolog.hh"


bool DownstreamState::passCrossProtocolQuery(std::unique_ptr<CrossProtocolQuery>&& cpq)
{
  if (d_dohPath.empty()) {
    return g_tcpclientthreads && g_tcpclientthreads->passCrossProtocolQueryToThread(std::move(cpq));
  }
  else {
    return g_dohClientThreads && g_dohClientThreads->passCrossProtocolQueryToThread(std::move(cpq));
  }
}

bool DownstreamState::reconnect()
{
  std::unique_lock<std::mutex> tl(connectLock, std::try_to_lock);
  if (!tl.owns_lock() || isStopped()) {
    /* we are already reconnecting or stopped anyway */
    return false;
  }

  connected = false;
  for (auto& fd : sockets) {
    if (fd != -1) {
      if (sockets.size() > 1) {
        (*mplexer.lock())->removeReadFD(fd);
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
          (*mplexer.lock())->addReadFD(fd, [](int, boost::any) {});
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
            (*mplexer.lock())->removeReadFD(fd);
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

void DownstreamState::stop()
{
  d_stopped = true;

  {
    std::lock_guard<std::mutex> tl(connectLock);
    auto slock = mplexer.lock();

    for (auto& fd : sockets) {
      if (fd != -1) {
        /* shutdown() is needed to wake up recv() in the responderThread */
        shutdown(fd, SHUT_RDWR);
      }
    }
  }
}

void DownstreamState::hash()
{
  vinfolog("Computing hashes for id=%s and weight=%d", id, weight);
  auto w = weight;
  auto lockedHashes = hashes.write_lock();
  lockedHashes->clear();
  lockedHashes->reserve(w);
  while (w > 0) {
    std::string uuid = boost::str(boost::format("%s-%d") % id % w);
    unsigned int wshash = burtleCI(reinterpret_cast<const unsigned char*>(uuid.c_str()), uuid.size(), g_hashperturb);
    lockedHashes->push_back(wshash);
    --w;
  }
  std::sort(lockedHashes->begin(), lockedHashes->end());
  hashesComputed = true;
}

void DownstreamState::setId(const boost::uuids::uuid& newId)
{
  id = newId;
  // compute hashes only if already done
  if (hashesComputed) {
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
  if (hashesComputed) {
    hash();
  }
}

DownstreamState::DownstreamState(const ComboAddress& remote_, const ComboAddress& sourceAddr_, unsigned int sourceItf_, const std::string& sourceItfName_, size_t numberOfSockets, bool connect): remote(remote_), sourceAddr(sourceAddr_), sourceItfName(sourceItfName_), name(remote_.toStringWithPort()), nameWithAddr(remote_.toStringWithPort()), idStates(connect ? g_maxOutstanding : 0), sourceItf(sourceItf_)
{
  id = getUniqueID();
  threadStarted.clear();

  *(mplexer.lock()) = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());

  sockets.resize(numberOfSockets);
  for (auto& fd : sockets) {
    fd = -1;
  }

  if (connect && !IsAnyAddress(remote)) {
    reconnect();
    sw.start();
  }
}

DownstreamState::~DownstreamState()
{
  for (auto& fd : sockets) {
    if (fd >= 0) {
      close(fd);
      fd = -1;
    }
  }

  // we need to either detach or join the thread before it
  // is destroyed
  if (threadStarted.test_and_set()) {
    tid.detach();
  }
}

void DownstreamState::incCurrentConnectionsCount()
{
  auto currentConnectionsCount = ++tcpCurrentConnections;
  if (currentConnectionsCount > tcpMaxConcurrentConnections) {
    tcpMaxConcurrentConnections.store(currentConnectionsCount);
  }
}

size_t ServerPool::countServers(bool upOnly)
{
  size_t count = 0;
  auto servers = d_servers.read_lock();
  for (const auto& server : **servers) {
    if (!upOnly || std::get<1>(server)->isUp() ) {
      count++;
    }
  }
  return count;
}

size_t ServerPool::poolLoad()
{
  size_t load = 0;
  auto servers = d_servers.read_lock();
  for (const auto& server : **servers) {
    size_t serverOutstanding = std::get<1>(server)->outstanding.load();
    load += serverOutstanding;
  }
  return load;
}

const std::shared_ptr<ServerPolicy::NumberedServerVector> ServerPool::getServers()
{
  std::shared_ptr<ServerPolicy::NumberedServerVector> result;
  {
    result = *(d_servers.read_lock());
  }
  return result;
}

void ServerPool::addServer(shared_ptr<DownstreamState>& server)
{
  auto servers = d_servers.write_lock();
  /* we can't update the content of the shared pointer directly even when holding the lock,
     as other threads might hold a copy. We can however update the pointer as long as we hold the lock. */
  unsigned int count = static_cast<unsigned int>((*servers)->size());
  auto newServers = std::make_shared<ServerPolicy::NumberedServerVector>(*(*servers));
  newServers->emplace_back(++count, server);
  /* we need to reorder based on the server 'order' */
  std::stable_sort(newServers->begin(), newServers->end(), [](const std::pair<unsigned int,std::shared_ptr<DownstreamState> >& a, const std::pair<unsigned int,std::shared_ptr<DownstreamState> >& b) {
      return a.second->order < b.second->order;
    });
  /* and now we need to renumber for Lua (custom policies) */
  size_t idx = 1;
  for (auto& serv : *newServers) {
    serv.first = idx++;
  }
  *servers = std::move(newServers);
}

void ServerPool::removeServer(shared_ptr<DownstreamState>& server)
{
  auto servers = d_servers.write_lock();
  /* we can't update the content of the shared pointer directly even when holding the lock,
     as other threads might hold a copy. We can however update the pointer as long as we hold the lock. */
  auto newServers = std::make_shared<ServerPolicy::NumberedServerVector>(*(*servers));
  size_t idx = 1;
  bool found = false;
  for (auto it = newServers->begin(); it != newServers->end();) {
    if (found) {
      /* we need to renumber the servers placed
         after the removed one, for Lua (custom policies) */
      it->first = idx++;
      it++;
    }
    else if (it->second == server) {
      it = newServers->erase(it);
      found = true;
    } else {
      idx++;
      it++;
    }
  }
  *servers = std::move(newServers);
}
