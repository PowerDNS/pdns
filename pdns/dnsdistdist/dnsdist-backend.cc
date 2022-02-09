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
#include "dnsdist-random.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-tcp.hh"
#include "dolog.hh"

bool DownstreamState::passCrossProtocolQuery(std::unique_ptr<CrossProtocolQuery>&& cpq)
{
  if (d_config.d_dohPath.empty()) {
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
    if (!IsAnyAddress(d_config.remote)) {
      fd = SSocket(d_config.remote.sin4.sin_family, SOCK_DGRAM, 0);
      if (!IsAnyAddress(d_config.sourceAddr)) {
        SSetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 1);
        if (!d_config.sourceItfName.empty()) {
#ifdef SO_BINDTODEVICE
          int res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, d_config.sourceItfName.c_str(), d_config.sourceItfName.length());
          if (res != 0) {
            infolog("Error setting up the interface on backend socket '%s': %s", d_config.remote.toStringWithPort(), stringerror());
          }
#endif
        }

        SBind(fd, d_config.sourceAddr);
      }
      try {
        SConnect(fd, d_config.remote);
        if (sockets.size() > 1) {
          (*mplexer.lock())->addReadFD(fd, [](int, boost::any) {});
        }
        connected = true;
      }
      catch(const std::runtime_error& error) {
        infolog("Error connecting to new server with address %s: %s", d_config.remote.toStringWithPort(), error.what());
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
  if (d_stopped) {
    return;
  }
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
  vinfolog("Computing hashes for id=%s and weight=%d", *d_config.id, d_config.d_weight);
  auto w = d_config.d_weight;
  auto idStr = boost::str(boost::format("%s") % *d_config.id);
  auto lockedHashes = hashes.write_lock();
  lockedHashes->clear();
  lockedHashes->reserve(w);
  while (w > 0) {
    std::string uuid = boost::str(boost::format("%s-%d") % idStr % w);
    unsigned int wshash = burtleCI(reinterpret_cast<const unsigned char*>(uuid.c_str()), uuid.size(), g_hashperturb);
    lockedHashes->push_back(wshash);
    --w;
  }
  std::sort(lockedHashes->begin(), lockedHashes->end());
  hashesComputed = true;
}

void DownstreamState::setId(const boost::uuids::uuid& newId)
{
  d_config.id = newId;
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

  d_config.d_weight = newWeight;

  if (hashesComputed) {
    hash();
  }
}

DownstreamState::DownstreamState(DownstreamState::Config&& config, std::shared_ptr<TLSCtx> tlsCtx, bool connect): d_config(std::move(config)), d_tlsCtx(std::move(tlsCtx))
{
  threadStarted.clear();

  if (d_config.d_qpsLimit > 0) {
    qps = QPSLimiter(d_config.d_qpsLimit, d_config.d_qpsLimit);
  }

  if (d_config.id) {
    setId(*d_config.id);
  }
  else {
    d_config.id = getUniqueID();
  }

  if (d_config.d_weight > 0) {
    setWeight(d_config.d_weight);
  }

  setName(d_config.name);

  if (d_tlsCtx) {
    if (!d_config.d_dohPath.empty()) {
#ifdef HAVE_NGHTTP2
      setupDoHClientProtocolNegotiation(d_tlsCtx);

      if (g_configurationDone && g_outgoingDoHWorkerThreads && *g_outgoingDoHWorkerThreads == 0) {
        throw std::runtime_error("Error: setOutgoingDoHWorkerThreads() is set to 0 so no outgoing DoH worker thread is available to serve queries");
      }

      if (!g_outgoingDoHWorkerThreads || *g_outgoingDoHWorkerThreads == 0) {
        g_outgoingDoHWorkerThreads = 1;
      }
#endif /* HAVE_NGHTTP2 */
    }
    else {
      setupDoTProtocolNegotiation(d_tlsCtx);
    }
  }

  if (connect && !isTCPOnly()) {
    if (!IsAnyAddress(d_config.remote)) {
      connectUDPSockets();
    }
  }

  sw.start();
}


void DownstreamState::start()
{
  if (connected && !threadStarted.test_and_set()) {
    tid = std::thread(responderThread, shared_from_this());

    if (!d_config.d_cpus.empty()) {
      mapThreadToCPUList(tid.native_handle(), d_config.d_cpus);
    }

    tid.detach();
  }
}

void DownstreamState::connectUDPSockets()
{
  if (s_randomizeIDs) {
    idStates.clear();
  }
  else {
    idStates.resize(g_maxOutstanding);
  }
  sockets.resize(d_config.d_numberOfSockets);

  if (sockets.size() > 1) {
    *(mplexer.lock()) = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());
  }

  for (auto& fd : sockets) {
    fd = -1;
  }

  reconnect();
}

DownstreamState::~DownstreamState()
{
  for (auto& fd : sockets) {
    if (fd >= 0) {
      close(fd);
      fd = -1;
    }
  }
}

void DownstreamState::incCurrentConnectionsCount()
{
  auto currentConnectionsCount = ++tcpCurrentConnections;
  if (currentConnectionsCount > tcpMaxConcurrentConnections) {
    tcpMaxConcurrentConnections.store(currentConnectionsCount);
  }
}

int DownstreamState::pickSocketForSending()
{
  size_t numberOfSockets = sockets.size();
  if (numberOfSockets == 1) {
    return sockets[0];
  }

  size_t idx;
  if (s_randomizeSockets) {
    idx = dnsdist::getRandomValue(numberOfSockets);
  }
  else {
    idx = socketsOffset++;
  }

  return sockets[idx % numberOfSockets];
}

void DownstreamState::pickSocketsReadyForReceiving(std::vector<int>& ready)
{
  ready.clear();

  if (sockets.size() == 1) {
    ready.push_back(sockets[0]);
    return ;
  }

  (*mplexer.lock())->getAvailableFDs(ready, 1000);
}

bool DownstreamState::s_randomizeSockets{false};
bool DownstreamState::s_randomizeIDs{false};
int DownstreamState::s_udpTimeout{2};

static bool isIDSExpired(IDState& ids)
{
  auto age = ids.age++;
  return age > DownstreamState::s_udpTimeout;
}

void DownstreamState::handleTimeout(IDState& ids)
{
  /* We mark the state as unused as soon as possible
     to limit the risk of racing with the
     responder thread.
  */
  auto oldDU = ids.du;

  ids.du = nullptr;
  handleDOHTimeout(DOHUnitUniquePtr(oldDU, DOHUnit::release));
  oldDU = nullptr;
  ids.age = 0;
  reuseds++;
  --outstanding;
  ++g_stats.downstreamTimeouts; // this is an 'actively' discovered timeout
  vinfolog("Had a downstream timeout from %s (%s) for query for %s|%s from %s",
           d_config.remote.toStringWithPort(), getName(),
           ids.qname.toLogString(), QType(ids.qtype).toString(), ids.origRemote.toStringWithPort());

  struct timespec ts;
  gettime(&ts);

  struct dnsheader fake;
  memset(&fake, 0, sizeof(fake));
  fake.id = ids.origID;

  g_rings.insertResponse(ts, ids.origRemote, ids.qname, ids.qtype, std::numeric_limits<unsigned int>::max(), 0, fake, d_config.remote, getProtocol());
}

void DownstreamState::handleTimeouts()
{
  if (s_randomizeIDs) {
    auto map = d_idStatesMap.lock();
    for (auto it = map->begin(); it != map->end(); ) {
      auto& ids = it->second;
      if (isIDSExpired(ids)) {
        handleTimeout(ids);
        it = map->erase(it);
        continue;
      }
      ++it;
    }
  }
  else {
    for (IDState& ids : idStates) {
      int64_t usageIndicator = ids.usageIndicator;
      if (IDState::isInUse(usageIndicator) && isIDSExpired(ids)) {
        if (!ids.tryMarkUnused(usageIndicator)) {
          /* this state has been altered in the meantime,
             don't go anywhere near it */
          continue;
        }

        handleTimeout(ids);
      }
    }
  }
}

IDState* DownstreamState::getExistingState(unsigned int stateId)
{
  if (s_randomizeIDs) {
    auto map = d_idStatesMap.lock();
    auto it = map->find(stateId);
    if (it == map->end()) {
      return nullptr;
    }
    return &it->second;
  }
  else {
    if (stateId >= idStates.size()) {
      return nullptr;
    }
    return &idStates[stateId];
  }
}

void DownstreamState::releaseState(unsigned int stateId)
{
  if (s_randomizeIDs) {
    auto map = d_idStatesMap.lock();
    auto it = map->find(stateId);
    if (it == map->end()) {
      return;
    }
    if (it->second.isInUse()) {
      return;
    }
    map->erase(it);
  }
}

IDState* DownstreamState::getIDState(unsigned int& selectedID, int64_t& generation)
{
  DOHUnitUniquePtr du(nullptr, DOHUnit::release);
  IDState* ids = nullptr;
  if (s_randomizeIDs) {
    /* if the state is already in use we will retry,
       up to 5 five times. The last selected one is used
       even if it was already in use */
    size_t remainingAttempts = 5;
    auto map = d_idStatesMap.lock();

    bool done = false;
    do {
      selectedID = dnsdist::getRandomValue(std::numeric_limits<uint16_t>::max());
      auto [it, inserted] = map->insert({selectedID, IDState()});
      ids = &it->second;
      if (inserted) {
        done = true;
      }
      else {
        remainingAttempts--;
      }
    }
    while (!done && remainingAttempts > 0);
  }
  else {
    selectedID = (idOffset++) % idStates.size();
    ids = &idStates[selectedID];
  }

  ids->age = 0;

  /* that means that the state was in use, possibly with an allocated
     DOHUnit that we will need to handle, but we can't touch it before
     confirming that we now own this state */
  if (ids->isInUse()) {
    du = DOHUnitUniquePtr(ids->du, DOHUnit::release);
  }

  /* we atomically replace the value, we now own this state */
  generation = ids->generation++;
  if (!ids->markAsUsed(generation)) {
    /* the state was not in use.
       we reset 'du' because it might have still been in use when we read it. */
    du.release();
    ++outstanding;
  }
  else {
    /* we are reusing a state, no change in outstanding but if there was an existing DOHUnit we need
       to handle it because it's about to be overwritten. */
    ids->du = nullptr;
    ++reuseds;
    ++g_stats.downstreamTimeouts;
    handleDOHTimeout(std::move(du));
  }

  return ids;
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
      return a.second->d_config.order < b.second->d_config.order;
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
