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
#include "dnsdist-ecs.hh"
#include "dnsparser.hh"
#include "ednsoptions.hh"
#include "dolog.hh"
#include "lock.hh"
#include "gettime.hh"
#include <thread>
#include <atomic>

using std::thread;
using std::atomic;

/* TCP: the grand design. 
   We forward 'messages' between clients and downstream servers. Messages are 65k bytes large, tops. 
   An answer might theoretically consist of multiple messages (for example, in the case of AXFR), initially 
   we will not go there.

   In a sense there is a strong symmetry between UDP and TCP, once a connection to a downstream has been setup.
   This symmetry is broken because of head-of-line blocking within TCP though, necessitating additional connections
   to guarantee performance.

   So the idea is to have a 'pool' of available downstream connections, and forward messages to/from them and never queue.
   So whenever an answer comes in, we know where it needs to go.

   Let's start naively.
*/

static int setupTCPDownstream(shared_ptr<DownstreamState> ds, uint16_t& downstreamFailures)
{
  do {
    vinfolog("TCP connecting to downstream %s (%d)", ds->remote.toStringWithPort(), downstreamFailures);
    int sock = SSocket(ds->remote.sin4.sin_family, SOCK_STREAM, 0);
    try {
      if (!IsAnyAddress(ds->sourceAddr)) {
        SSetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef IP_BIND_ADDRESS_NO_PORT
        if (ds->ipBindAddrNoPort) {
          SSetsockopt(sock, SOL_IP, IP_BIND_ADDRESS_NO_PORT, 1);
        }
#endif
        SBind(sock, ds->sourceAddr);
      }
      setNonBlocking(sock);
#ifdef MSG_FASTOPEN
      if (!ds->tcpFastOpen) {
        SConnectWithTimeout(sock, ds->remote, ds->tcpConnectTimeout);
      }
#else
      SConnectWithTimeout(sock, ds->remote, ds->tcpConnectTimeout);
#endif /* MSG_FASTOPEN */
      return sock;
    }
    catch(const std::runtime_error& e) {
      /* don't leak our file descriptor if SConnect() (for example) throws */
      downstreamFailures++;
      close(sock);
      if (downstreamFailures > ds->retries) {
        throw;
      }
    }
  } while(downstreamFailures <= ds->retries);

  return -1;
}

struct ConnectionInfo
{
  int fd;
  ComboAddress remote;
  ClientState* cs;
};

uint64_t g_maxTCPQueuedConnections{1000};
size_t g_maxTCPQueriesPerConn{0};
size_t g_maxTCPConnectionDuration{0};
size_t g_maxTCPConnectionsPerClient{0};
static std::mutex tcpClientsCountMutex;
static std::map<ComboAddress,size_t,ComboAddress::addressOnlyLessThan> tcpClientsCount;
bool g_useTCPSinglePipe{false};
std::atomic<uint16_t> g_downstreamTCPCleanupInterval{60};

void* tcpClientThread(int pipefd);

static void decrementTCPClientCount(const ComboAddress& client)
{
  if (g_maxTCPConnectionsPerClient) {
    std::lock_guard<std::mutex> lock(tcpClientsCountMutex);
    tcpClientsCount[client]--;
    if (tcpClientsCount[client] == 0) {
      tcpClientsCount.erase(client);
    }
  }
}

void TCPClientCollection::addTCPClientThread()
{
  int pipefds[2] = { -1, -1};

  vinfolog("Adding TCP Client thread");

  if (d_useSinglePipe) {
    pipefds[0] = d_singlePipe[0];
    pipefds[1] = d_singlePipe[1];
  }
  else {
    if (pipe(pipefds) < 0) {
      errlog("Error creating the TCP thread communication pipe: %s", strerror(errno));
      return;
    }

    if (!setNonBlocking(pipefds[1])) {
      close(pipefds[0]);
      close(pipefds[1]);
      errlog("Error setting the TCP thread communication pipe non-blocking: %s", strerror(errno));
      return;
    }
  }

  {
    std::lock_guard<std::mutex> lock(d_mutex);

    if (d_numthreads >= d_tcpclientthreads.capacity()) {
      warnlog("Adding a new TCP client thread would exceed the vector capacity (%d/%d), skipping", d_numthreads.load(), d_tcpclientthreads.capacity());
      if (!d_useSinglePipe) {
        close(pipefds[0]);
        close(pipefds[1]);
      }
      return;
    }

    try {
      thread t1(tcpClientThread, pipefds[0]);
      t1.detach();
    }
    catch(const std::runtime_error& e) {
      /* the thread creation failed, don't leak */
      errlog("Error creating a TCP thread: %s", e.what());
      if (!d_useSinglePipe) {
        close(pipefds[0]);
        close(pipefds[1]);
      }
      return;
    }

    d_tcpclientthreads.push_back(pipefds[1]);
  }

  ++d_numthreads;
}

static bool getNonBlockingMsgLen(int fd, uint16_t* len, int timeout)
try
{
  uint16_t raw;
  size_t ret = readn2WithTimeout(fd, &raw, sizeof raw, timeout);
  if(ret != sizeof raw)
    return false;
  *len = ntohs(raw);
  return true;
}
catch(...) {
  return false;
}

static bool sendResponseToClient(int fd, const char* response, uint16_t responseLen)
{
  return sendSizeAndMsgWithTimeout(fd, responseLen, response, g_tcpSendTimeout, nullptr, nullptr, 0, 0, 0);
}

static bool maxConnectionDurationReached(unsigned int maxConnectionDuration, time_t start, unsigned int& remainingTime)
{
  if (maxConnectionDuration) {
    time_t curtime = time(nullptr);
    unsigned int elapsed = 0;
    if (curtime > start) { // To prevent issues when time goes backward
      elapsed = curtime - start;
    }
    if (elapsed >= maxConnectionDuration) {
      return true;
    }
    remainingTime = maxConnectionDuration - elapsed;
  }
  return false;
}

void cleanupClosedTCPConnections(std::map<ComboAddress,int>& sockets)
{
  for(auto it = sockets.begin(); it != sockets.end(); ) {
    if (isTCPSocketUsable(it->second)) {
      ++it;
    }
    else {
      close(it->second);
      it = sockets.erase(it);
    }
  }
}

std::shared_ptr<TCPClientCollection> g_tcpclientthreads;

void* tcpClientThread(int pipefd)
{
  /* we get launched with a pipe on which we receive file descriptors from clients that we own
     from that point on */
     
  bool outstanding = false;
  time_t lastTCPCleanup = time(nullptr);
  
  LocalHolders holders;
  auto localRespRulactions = g_resprulactions.getLocal();
#ifdef HAVE_DNSCRYPT
  /* when the answer is encrypted in place, we need to get a copy
     of the original header before encryption to fill the ring buffer */
  dnsheader dhCopy;
#endif

  map<ComboAddress,int> sockets;
  for(;;) {
    ConnectionInfo* citmp, ci;

    try {
      readn2(pipefd, &citmp, sizeof(citmp));
    }
    catch(const std::runtime_error& e) {
      throw std::runtime_error("Error reading from TCP acceptor pipe (" + std::to_string(pipefd) + ") in " + std::string(isNonBlocking(pipefd) ? "non-blocking" : "blocking") + " mode: " + e.what());
    }

    g_tcpclientthreads->decrementQueuedCount();
    ci=*citmp;
    delete citmp;    

    uint16_t qlen, rlen;
    vector<uint8_t> rewrittenResponse;
    shared_ptr<DownstreamState> ds;
    ComboAddress dest;
    dest.reset();
    dest.sin4.sin_family = ci.remote.sin4.sin_family;
    socklen_t len = dest.getSocklen();
    size_t queriesCount = 0;
    time_t connectionStartTime = time(NULL);
    std::vector<char> queryBuffer;

    if (getsockname(ci.fd, (sockaddr*)&dest, &len)) {
      dest = ci.cs->local;
    }

    try {
      for(;;) {
        unsigned int remainingTime = 0;
        ds = nullptr;
        outstanding = false;

        if(!getNonBlockingMsgLen(ci.fd, &qlen, g_tcpRecvTimeout))
          break;

        queriesCount++;

        if (qlen < sizeof(dnsheader)) {
          g_stats.nonCompliantQueries++;
          break;
        }

        ci.cs->queries++;
        g_stats.queries++;

        if (g_maxTCPQueriesPerConn && queriesCount > g_maxTCPQueriesPerConn) {
          vinfolog("Terminating TCP connection from %s because it reached the maximum number of queries per conn (%d / %d)", ci.remote.toStringWithPort(), queriesCount, g_maxTCPQueriesPerConn);
          break;
        }

        if (maxConnectionDurationReached(g_maxTCPConnectionDuration, connectionStartTime, remainingTime)) {
          vinfolog("Terminating TCP connection from %s because it reached the maximum TCP connection duration", ci.remote.toStringWithPort());
          break;
        }

        bool ednsAdded = false;
        bool ecsAdded = false;
        /* allocate a bit more memory to be able to spoof the content,
           or to add ECS without allocating a new buffer */
        queryBuffer.reserve(qlen + 512);

        char* query = &queryBuffer[0];
        readn2WithTimeout(ci.fd, query, qlen, g_tcpRecvTimeout, remainingTime);

#ifdef HAVE_DNSCRYPT
        std::shared_ptr<DnsCryptQuery> dnsCryptQuery = nullptr;

        if (ci.cs->dnscryptCtx) {
          dnsCryptQuery = std::make_shared<DnsCryptQuery>();
          uint16_t decryptedQueryLen = 0;
          vector<uint8_t> response;
          bool decrypted = handleDnsCryptQuery(ci.cs->dnscryptCtx, query, qlen, dnsCryptQuery, &decryptedQueryLen, true, response);

          if (!decrypted) {
            if (response.size() > 0) {
              sendResponseToClient(ci.fd, reinterpret_cast<char*>(response.data()), (uint16_t) response.size());
            }
            break;
          }
          qlen = decryptedQueryLen;
        }
#endif
        struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query);

        if (!checkQueryHeaders(dh)) {
          goto drop;
        }

	const uint16_t* flags = getFlagsFromDNSHeader(dh);
	uint16_t origFlags = *flags;
	uint16_t qtype, qclass;
	unsigned int consumed = 0;
	DNSName qname(query, qlen, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
	DNSQuestion dq(&qname, qtype, qclass, &dest, &ci.remote, dh, queryBuffer.capacity(), qlen, true);

	string poolname;
	int delayMsec=0;
	/* we need this one to be accurate ("real") for the protobuf message */
	struct timespec queryRealTime;
	struct timespec now;
	gettime(&now);
	gettime(&queryRealTime, true);

	if (!processQuery(holders, dq, poolname, &delayMsec, now)) {
	  goto drop;
	}

	if(dq.dh->qr) { // something turned it into a response
          restoreFlags(dh, origFlags);
#ifdef HAVE_DNSCRYPT
          if (!encryptResponse(query, &dq.len, dq.size, true, dnsCryptQuery, nullptr, nullptr)) {
            goto drop;
          }
#endif
          sendResponseToClient(ci.fd, query, dq.len);
	  g_stats.selfAnswered++;
	  goto drop;
	}

        std::shared_ptr<ServerPool> serverPool = getPool(*holders.pools, poolname);
        std::shared_ptr<DNSDistPacketCache> packetCache = nullptr;
        auto policy = holders.policy->policy;
        if (serverPool->policy != nullptr) {
          policy = serverPool->policy->policy;
        }
        {
          std::lock_guard<std::mutex> lock(g_luamutex);
          ds = policy(serverPool->servers, &dq);
          packetCache = serverPool->packetCache;
        }

        if (dq.useECS && ds && ds->useECS) {
          uint16_t newLen = dq.len;
          if (!handleEDNSClientSubnet(query, dq.size, consumed, &newLen, &ednsAdded, &ecsAdded, ci.remote, dq.ecsOverride, dq.ecsPrefixLength)) {
            vinfolog("Dropping query from %s because we couldn't insert the ECS value", ci.remote.toStringWithPort());
            goto drop;
          }
          dq.len = newLen;
        }

        uint32_t cacheKey = 0;
        if (packetCache && !dq.skipCache) {
          char cachedResponse[4096];
          uint16_t cachedResponseSize = sizeof cachedResponse;
          uint32_t allowExpired = ds ? 0 : g_staleCacheEntriesTTL;
          if (packetCache->get(dq, (uint16_t) consumed, dq.dh->id, cachedResponse, &cachedResponseSize, &cacheKey, allowExpired)) {
            DNSResponse dr(dq.qname, dq.qtype, dq.qclass, dq.local, dq.remote, (dnsheader*) cachedResponse, sizeof cachedResponse, cachedResponseSize, true, &queryRealTime);
#ifdef HAVE_PROTOBUF
            dr.uniqueId = dq.uniqueId;
#endif
            if (!processResponse(holders.cacheHitRespRulactions, dr, &delayMsec)) {
              goto drop;
            }

#ifdef HAVE_DNSCRYPT
            if (!encryptResponse(cachedResponse, &cachedResponseSize, sizeof cachedResponse, true, dnsCryptQuery, nullptr, nullptr)) {
              goto drop;
            }
#endif
            sendResponseToClient(ci.fd, cachedResponse, cachedResponseSize);
            g_stats.cacheHits++;
            goto drop;
          }
          g_stats.cacheMisses++;
        }

        if(!ds) {
          g_stats.noPolicy++;

          if (g_servFailOnNoPolicy) {
            restoreFlags(dh, origFlags);
            dq.dh->rcode = RCode::ServFail;
            dq.dh->qr = true;

#ifdef HAVE_DNSCRYPT
            if (!encryptResponse(query, &dq.len, dq.size, true, dnsCryptQuery, nullptr, nullptr)) {
              goto drop;
            }
#endif
            sendResponseToClient(ci.fd, query, dq.len);
          }

          break;
        }

	int dsock = -1;
	uint16_t downstreamFailures=0;
#ifdef MSG_FASTOPEN
	bool freshConn = true;
#endif /* MSG_FASTOPEN */
	if(sockets.count(ds->remote) == 0) {
	  dsock=setupTCPDownstream(ds, downstreamFailures);
	  sockets[ds->remote]=dsock;
	}
	else {
	  dsock=sockets[ds->remote];
#ifdef MSG_FASTOPEN
	  freshConn = false;
#endif /* MSG_FASTOPEN */
        }

        ds->queries++;
        ds->outstanding++;
        outstanding = true;

      retry:; 
        if (dsock < 0) {
          sockets.erase(ds->remote);
          break;
        }

        if (ds->retries > 0 && downstreamFailures > ds->retries) {
          vinfolog("Downstream connection to %s failed %d times in a row, giving up.", ds->getName(), downstreamFailures);
          close(dsock);
          dsock=-1;
          sockets.erase(ds->remote);
          break;
        }

        try {
          int socketFlags = 0;
#ifdef MSG_FASTOPEN
          if (ds->tcpFastOpen && freshConn) {
            socketFlags |= MSG_FASTOPEN;
          }
#endif /* MSG_FASTOPEN */
          sendSizeAndMsgWithTimeout(dsock, dq.len, query, ds->tcpSendTimeout, &ds->remote, &ds->sourceAddr, ds->sourceItf, 0, socketFlags);
        }
        catch(const runtime_error& e) {
          vinfolog("Downstream connection to %s died on us, getting a new one!", ds->getName());
          close(dsock);
          dsock=-1;
          sockets.erase(ds->remote);
          downstreamFailures++;
          dsock=setupTCPDownstream(ds, downstreamFailures);
          sockets[ds->remote]=dsock;
#ifdef MSG_FASTOPEN
          freshConn=true;
#endif /* MSG_FASTOPEN */
          goto retry;
        }

        bool xfrStarted = false;
        bool isXFR = (dq.qtype == QType::AXFR || dq.qtype == QType::IXFR);
        if (isXFR) {
          dq.skipCache = true;
        }

      getpacket:;

        if(!getNonBlockingMsgLen(dsock, &rlen, ds->tcpRecvTimeout)) {
	  vinfolog("Downstream connection to %s died on us phase 2, getting a new one!", ds->getName());
          close(dsock);
          dsock=-1;
          sockets.erase(ds->remote);
          downstreamFailures++;
          dsock=setupTCPDownstream(ds, downstreamFailures);
          sockets[ds->remote]=dsock;
#ifdef MSG_FASTOPEN
          freshConn=true;
#endif /* MSG_FASTOPEN */
          if(xfrStarted) {
            goto drop;
          }
          goto retry;
        }

        size_t responseSize = rlen;
        uint16_t addRoom = 0;
#ifdef HAVE_DNSCRYPT
        if (dnsCryptQuery && (UINT16_MAX - rlen) > (uint16_t) DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE) {
          addRoom = DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
        }
#endif
        responseSize += addRoom;
        char answerbuffer[responseSize];
        readn2WithTimeout(dsock, answerbuffer, rlen, ds->tcpRecvTimeout);
        char* response = answerbuffer;
        uint16_t responseLen = rlen;
        if (outstanding) {
          /* might be false for {A,I}XFR */
          --ds->outstanding;
          outstanding = false;
        }

        if (rlen < sizeof(dnsheader)) {
          break;
        }

        if (!responseContentMatches(response, responseLen, qname, qtype, qclass, ds->remote)) {
          break;
        }

        if (!fixUpResponse(&response, &responseLen, &responseSize, qname, origFlags, ednsAdded, ecsAdded, rewrittenResponse, addRoom)) {
          break;
        }

        dh = (struct dnsheader*) response;
        DNSResponse dr(&qname, qtype, qclass, &dest, &ci.remote, dh, responseSize, responseLen, true, &queryRealTime);
#ifdef HAVE_PROTOBUF
        dr.uniqueId = dq.uniqueId;
#endif
        if (!processResponse(localRespRulactions, dr, &delayMsec)) {
          break;
        }

	if (packetCache && !dq.skipCache) {
	  packetCache->insert(cacheKey, qname, qtype, qclass, response, responseLen, true, dh->rcode);
	}

#ifdef HAVE_DNSCRYPT
        if (!encryptResponse(response, &responseLen, responseSize, true, dnsCryptQuery, &dh, &dhCopy)) {
          goto drop;
        }
#endif
        if (!sendResponseToClient(ci.fd, response, responseLen)) {
          break;
        }

        if (isXFR) {
          if (dh->rcode == 0 && dh->ancount != 0) {
            if (xfrStarted == false) {
              xfrStarted = true;
              if (getRecordsOfTypeCount(response, responseLen, 1, QType::SOA) == 1) {
                goto getpacket;
              }
            }
            else if (getRecordsOfTypeCount(response, responseLen, 1, QType::SOA) == 0) {
              goto getpacket;
            }
          }
          /* Don't reuse the TCP connection after an {A,I}XFR */
          close(dsock);
          dsock=-1;
          sockets.erase(ds->remote);
        }

        g_stats.responses++;
        struct timespec answertime;
        gettime(&answertime);
        unsigned int udiff = 1000000.0*DiffTime(now,answertime);
        {
          std::lock_guard<std::mutex> lock(g_rings.respMutex);
          g_rings.respRing.push_back({answertime, ci.remote, qname, dq.qtype, (unsigned int)udiff, (unsigned int)responseLen, *dh, ds->remote});
        }

        rewrittenResponse.clear();
      }
    }
    catch(...){}

  drop:;
    
    vinfolog("Closing TCP client connection with %s", ci.remote.toStringWithPort());
    if (ci.fd >= 0) {
      close(ci.fd);
    }
    ci.fd = -1;
    if (ds && outstanding) {
      outstanding = false;
      --ds->outstanding;
    }
    decrementTCPClientCount(ci.remote);

    if (g_downstreamTCPCleanupInterval > 0 && (connectionStartTime > (lastTCPCleanup + g_downstreamTCPCleanupInterval))) {
      cleanupClosedTCPConnections(sockets);
      lastTCPCleanup = time(nullptr);
    }
  }
  return 0;
}

/* spawn as many of these as required, they call Accept on a socket on which they will accept queries, and 
   they will hand off to worker threads & spawn more of them if required
*/
void* tcpAcceptorThread(void* p)
{
  ClientState* cs = (ClientState*) p;
  bool tcpClientCountIncremented = false;
  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;
  
  g_tcpclientthreads->addTCPClientThread();

  auto acl = g_ACL.getLocal();
  for(;;) {
    bool queuedCounterIncremented = false;
    ConnectionInfo* ci = nullptr;
    tcpClientCountIncremented = false;
    try {
      socklen_t remlen = remote.getSocklen();
      ci = new ConnectionInfo;
      ci->cs = cs;
      ci->fd = -1;
#ifdef HAVE_ACCEPT4
      ci->fd = accept4(cs->tcpFD, (struct sockaddr*)&remote, &remlen, SOCK_NONBLOCK);
#else
      ci->fd = accept(cs->tcpFD, (struct sockaddr*)&remote, &remlen);
#endif
      if(ci->fd < 0) {
        throw std::runtime_error((boost::format("accepting new connection on socket: %s") % strerror(errno)).str());
      }

      if(!acl->match(remote)) {
	g_stats.aclDrops++;
	close(ci->fd);
	delete ci;
	ci=nullptr;
	vinfolog("Dropped TCP connection from %s because of ACL", remote.toStringWithPort());
	continue;
      }

#ifndef HAVE_ACCEPT4
      if (!setNonBlocking(ci->fd)) {
        close(ci->fd);
        delete ci;
        ci=nullptr;
        continue;
      }
#endif

      if(g_maxTCPQueuedConnections > 0 && g_tcpclientthreads->getQueuedCount() >= g_maxTCPQueuedConnections) {
        close(ci->fd);
        delete ci;
        ci=nullptr;
        vinfolog("Dropping TCP connection from %s because we have too many queued already", remote.toStringWithPort());
        continue;
      }

      if (g_maxTCPConnectionsPerClient) {
        std::lock_guard<std::mutex> lock(tcpClientsCountMutex);

        if (tcpClientsCount[remote] >= g_maxTCPConnectionsPerClient) {
          close(ci->fd);
          delete ci;
          ci=nullptr;
          vinfolog("Dropping TCP connection from %s because we have too many from this client already", remote.toStringWithPort());
          continue;
        }
        tcpClientsCount[remote]++;
        tcpClientCountIncremented = true;
      }

      vinfolog("Got TCP connection from %s", remote.toStringWithPort());

      ci->remote = remote;
      int pipe = g_tcpclientthreads->getThread();
      if (pipe >= 0) {
        queuedCounterIncremented = true;
        writen2WithTimeout(pipe, &ci, sizeof(ci), 0);
      }
      else {
        g_tcpclientthreads->decrementQueuedCount();
        queuedCounterIncremented = false;
        close(ci->fd);
        delete ci;
        ci=nullptr;
        if(tcpClientCountIncremented) {
          decrementTCPClientCount(remote);
        }
      }
    }
    catch(std::exception& e) {
      errlog("While reading a TCP question: %s", e.what());
      if(ci && ci->fd >= 0) 
	close(ci->fd);
      if(tcpClientCountIncremented) {
        decrementTCPClientCount(remote);
      }
      delete ci;
      ci = nullptr;
      if (queuedCounterIncremented) {
        g_tcpclientthreads->decrementQueuedCount();
      }
    }
    catch(...){}
  }

  return 0;
}


bool getMsgLen32(int fd, uint32_t* len)
try
{
  uint32_t raw;
  size_t ret = readn2(fd, &raw, sizeof raw);
  if(ret != sizeof raw)
    return false;
  *len = ntohl(raw);
  if(*len > 10000000) // arbitrary 10MB limit
    return false;
  return true;
}
catch(...) {
   return false;
}

bool putMsgLen32(int fd, uint32_t len)
try
{
  uint32_t raw = htonl(len);
  size_t ret = writen2(fd, &raw, sizeof raw);
  return ret==sizeof raw;
}
catch(...) {
  return false;
}
