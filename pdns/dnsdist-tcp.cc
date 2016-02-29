/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2013 - 2015  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dolog.hh"
#include "lock.hh"
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

static int setupTCPDownstream(shared_ptr<DownstreamState> ds)
{  
  vinfolog("TCP connecting to downstream %s", ds->remote.toStringWithPort());
  int sock = SSocket(ds->remote.sin4.sin_family, SOCK_STREAM, 0);
  if (!IsAnyAddress(ds->sourceAddr)) {
    SSetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
    SBind(sock, ds->sourceAddr);
  }
  SConnect(sock, ds->remote);
  setNonBlocking(sock);
  return sock;
}

struct ConnectionInfo
{
  int fd;
  ComboAddress remote;
  ClientState* cs;
};

void* tcpClientThread(int pipefd);

// Should not be called simultaneously!
void TCPClientCollection::addTCPClientThread()
{
  if (d_numthreads >= d_tcpclientthreads.capacity()) {
    warnlog("Adding a new TCP client thread would exceed the vector capacity, skipping");
    return;
  }

  vinfolog("Adding TCP Client thread");

  int pipefds[2] = { -1, -1};
  if(pipe(pipefds) < 0)
    unixDie("Creating pipe");

  if (!setNonBlocking(pipefds[1]))
    unixDie("Setting pipe non-blocking");

  d_tcpclientthreads.push_back(pipefds[1]);
  thread t1(tcpClientThread, pipefds[0]);
  t1.detach();
  ++d_numthreads;
}

static bool getNonBlockingMsgLen(int fd, uint16_t* len, int timeout)
try
{
  uint16_t raw;
  int ret = readn2WithTimeout(fd, &raw, sizeof raw, timeout);
  if(ret != sizeof raw)
    return false;
  *len = ntohs(raw);
  return true;
}
catch(...) {
  return false;
}

static bool putNonBlockingMsgLen(int fd, uint16_t len, int timeout)
try
{
  uint16_t raw = htons(len);
  int ret = writen2WithTimeout(fd, &raw, sizeof raw, timeout);
  return ret == sizeof raw;
}
catch(...) {
  return false;
}

static bool sendNonBlockingMsgLen(int fd, uint16_t len, int timeout, ComboAddress& dest, ComboAddress& local, unsigned int localItf)
try
{
  if (localItf == 0)
    return putNonBlockingMsgLen(fd, len, timeout);

  uint16_t raw = htons(len);
  ssize_t ret = sendMsgWithTimeout(fd, (char*) &raw, sizeof raw, timeout, dest, local, localItf);
  return ret == sizeof raw;
}
catch(...) {
  return false;
}

std::shared_ptr<TCPClientCollection> g_tcpclientthreads;

void* tcpClientThread(int pipefd)
{
  /* we get launched with a pipe on which we receive file descriptors from clients that we own
     from that point on */
     
  typedef std::function<bool(const DNSQuestion*)> blockfilter_t;
  bool outstanding = false;
  blockfilter_t blockFilter = 0;
  
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    auto candidate = g_lua.readVariable<boost::optional<blockfilter_t> >("blockFilter");
    if(candidate)
      blockFilter = *candidate;
  }     
     
  auto localPolicy = g_policy.getLocal();
  auto localRulactions = g_rulactions.getLocal();
  auto localDynBlockNMG = g_dynblockNMG.getLocal();
  auto localPools = g_pools.getLocal();

  map<ComboAddress,int> sockets;
  for(;;) {
    ConnectionInfo* citmp, ci;

    readn2(pipefd, &citmp, sizeof(citmp));
    --g_tcpclientthreads->d_queued;
    ci=*citmp;
    delete citmp;    

    uint16_t qlen, rlen;
    string poolname;
    const uint16_t rdMask = 1 << FLAGS_RD_OFFSET;
    const uint16_t cdMask = 1 << FLAGS_CD_OFFSET;
    const uint16_t restoreFlagsMask = UINT16_MAX & ~(rdMask | cdMask);
    string largerQuery;
    vector<uint8_t> rewrittenResponse;
    bool ednsAdded = false;
    shared_ptr<DownstreamState> ds;
    if (!setNonBlocking(ci.fd))
      goto drop;

    try {
      for(;;) {
        ds = nullptr;
        outstanding = false;

        if(!getNonBlockingMsgLen(ci.fd, &qlen, g_tcpRecvTimeout))
          break;

        if (qlen < sizeof(dnsheader)) {
          g_stats.nonCompliantQueries++;
          break;
        }

        /* if the query is small, allocate a bit more
           memory to be able to spoof the content,
           or to add ECS without allocating a new buffer */
        size_t querySize = qlen <= 4096 ? qlen + 512 : qlen;
        char queryBuffer[querySize];
        const char* query = queryBuffer;
        readn2WithTimeout(ci.fd, queryBuffer, qlen, g_tcpRecvTimeout);
#ifdef HAVE_DNSCRYPT
        std::shared_ptr<DnsCryptQuery> dnsCryptQuery = 0;

        if (ci.cs->dnscryptCtx) {
          dnsCryptQuery = std::make_shared<DnsCryptQuery>();
          uint16_t decryptedQueryLen = 0;
          vector<uint8_t> response;
          bool decrypted = handleDnsCryptQuery(ci.cs->dnscryptCtx, queryBuffer, qlen, dnsCryptQuery, &decryptedQueryLen, true, response);

          if (!decrypted) {
            if (response.size() > 0) {
              if (putNonBlockingMsgLen(ci.fd, response.size(), g_tcpSendTimeout))
                writen2WithTimeout(ci.fd, (const char *) response.data(), response.size(), g_tcpSendTimeout);
            }
            break;
          }
          qlen = decryptedQueryLen;
        }
#endif
        struct dnsheader* dh = (struct dnsheader*) query;

        if(dh->qr) {   // don't respond to responses
          g_stats.nonCompliantQueries++;
          goto drop;
        }

        if(dh->qdcount == 0) {
          g_stats.emptyQueries++;
          goto drop;
        }

	uint16_t qtype, qclass;
	unsigned int consumed = 0;
	DNSName qname(query, qlen, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
	DNSQuestion dq(&qname, qtype, qclass, &ci.cs->local, &ci.remote, (dnsheader*)query, querySize, qlen, true);
	string ruleresult;
	const uint16_t * flags = getFlagsFromDNSHeader(dq.dh);
	uint16_t origFlags = *flags;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	{
	  WriteLock wl(&g_rings.queryLock);
	  g_rings.queryRing.push_back({now,ci.remote,qname,dq.len,dq.qtype,*dq.dh});
	}

	g_stats.queries++;
	if (ci.cs) {
	  ci.cs->queries++;
	}

	if(auto got=localDynBlockNMG->lookup(ci.remote)) {
	  if(now < got->second.until) {
	    vinfolog("Query from %s dropped because of dynamic block", ci.remote.toStringWithPort());
	    g_stats.dynBlocked++;
	    got->second.blocks++;
	    goto drop;
	  }
	}

        if (dq.dh->rd) {
          g_stats.rdQueries++;
        }

        if(blockFilter) {
	  std::lock_guard<std::mutex> lock(g_luamutex);
	
	  if(blockFilter(&dq)) {
	    g_stats.blockFilter++;
	    goto drop;
          }
          if(dq.dh->tc && dq.dh->qr) { // don't truncate on TCP/IP!
            dq.dh->tc=false;        // maybe we should just pass blockFilter the TCP status
            dq.dh->qr=false;
          }
        }

        bool done=false;
	DNSAction::Action action=DNSAction::Action::None;
	for(const auto& lr : *localRulactions) {
	  if(lr.first->matches(&dq)) {
            lr.first->d_matches++;
            action=(*lr.second)(&dq, &ruleresult);
            switch(action) {
            case DNSAction::Action::Allow:
              done = true;
              break;
            case DNSAction::Action::Drop:
              g_stats.ruleDrop++;
              goto drop;
              break;
            case DNSAction::Action::Nxdomain:
              dq.dh->rcode = RCode::NXDomain;
              dq.dh->qr=true;
              g_stats.ruleNXDomain++;
              done = true;
              break;
            case DNSAction::Action::Spoof:
              spoofResponseFromString(dq, ruleresult);
              done = true;
              break;
            case DNSAction::Action::HeaderModify:
              done = true;
              break;
            case DNSAction::Action::Pool:
              poolname=ruleresult;
              done = true;
              break;
            /* non-terminal actions follow */
            case DNSAction::Action::Delay:
            case DNSAction::Action::None:
              break;
            }
	    if(done) {
	      break;
	    }
	  }
	}

	if(dq.dh->qr) { // something turned it into a response
	  if (putNonBlockingMsgLen(ci.fd, dq.len, g_tcpSendTimeout))
	    writen2WithTimeout(ci.fd, query, dq.len, g_tcpSendTimeout);

	  g_stats.selfAnswered++;
	  goto drop;
	}

	if(dq.qtype == QType::AXFR || dq.qtype == QType::IXFR)  // XXX fixme we really need to do better
	  break;

        std::shared_ptr<ServerPool> serverPool = getPool(*localPools, poolname);
        std::shared_ptr<DNSDistPacketCache> packetCache = nullptr;
	{
	  std::lock_guard<std::mutex> lock(g_luamutex);
	  ds = localPolicy->policy(serverPool->servers, &dq);
	  packetCache = serverPool->packetCache;
	}
	if(!ds) {
	  g_stats.noPolicy++;
	  break;
	}

        if (ds->useECS) {
          uint16_t newLen = dq.len;
          handleEDNSClientSubnet(queryBuffer, dq.size, consumed, &newLen, largerQuery, &ednsAdded, ci.remote);
          if (largerQuery.empty() == false) {
            query = largerQuery.c_str();
            dq.len = largerQuery.size();
            dq.size = largerQuery.size();
          } else {
            dq.len = newLen;
          }
        }

        uint32_t cacheKey = 0;
        if (packetCache && !dq.skipCache) {
          char cachedResponse[4096];
          uint16_t cachedResponseSize = sizeof cachedResponse;
          if (packetCache->get((unsigned char*) query, dq.len, *dq.qname, dq.qtype, dq.qclass, consumed, dq.dh->id, cachedResponse, &cachedResponseSize, true, &cacheKey)) {
            if (putNonBlockingMsgLen(ci.fd, cachedResponseSize, g_tcpSendTimeout))
              writen2WithTimeout(ci.fd, cachedResponse, cachedResponseSize, g_tcpSendTimeout);
            g_stats.cacheHits++;
            goto drop;
          }
          g_stats.cacheMisses++;
        }

	int dsock;
	if(sockets.count(ds->remote) == 0) {
	  dsock=sockets[ds->remote]=setupTCPDownstream(ds);
	}
	else
	  dsock=sockets[ds->remote];

        ds->queries++;
        ds->outstanding++;
        outstanding = true;

        uint16_t downstream_failures=0;
      retry:; 
        if (dsock < 0) {
          sockets.erase(ds->remote);
          break;
        }

        if (ds->retries > 0 && downstream_failures > ds->retries) {
          vinfolog("Downstream connection to %s failed %d times in a row, giving up.", ds->getName(), downstream_failures);
          close(dsock);
          sockets.erase(ds->remote);
          break;
        }

        if(!sendNonBlockingMsgLen(dsock, dq.len, ds->tcpSendTimeout, ds->remote, ds->sourceAddr, ds->sourceItf)) {
	  vinfolog("Downstream connection to %s died on us, getting a new one!", ds->getName());
          close(dsock);
          sockets[ds->remote]=dsock=setupTCPDownstream(ds);
          downstream_failures++;
          goto retry;
        }

        try {
          if (ds->sourceItf == 0) {
            writen2WithTimeout(dsock, query, dq.len, ds->tcpSendTimeout);
          }
          else {
            sendMsgWithTimeout(dsock, query, dq.len, ds->tcpSendTimeout, ds->remote, ds->sourceAddr, ds->sourceItf);
          }
        }
        catch(const runtime_error& e) {
          vinfolog("Downstream connection to %s died on us, getting a new one!", ds->getName());
          close(dsock);
          sockets[ds->remote]=dsock=setupTCPDownstream(ds);
          downstream_failures++;
          goto retry;
        }

        if(!getNonBlockingMsgLen(dsock, &rlen, ds->tcpRecvTimeout)) {
	  vinfolog("Downstream connection to %s died on us phase 2, getting a new one!", ds->getName());
          close(dsock);
          sockets[ds->remote]=dsock=setupTCPDownstream(ds);
          downstream_failures++;
          goto retry;
        }

        uint16_t responseSize = rlen;
#ifdef HAVE_DNSCRYPT
        if (ci.cs->dnscryptCtx && (UINT16_MAX - DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE) > rlen) {
          responseSize += DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
        }
#endif
        char answerbuffer[responseSize];
        readn2WithTimeout(dsock, answerbuffer, rlen, ds->tcpRecvTimeout);
        struct dnsheader* responseHeaders = (struct dnsheader*)answerbuffer;
        uint16_t * responseFlags = getFlagsFromDNSHeader(responseHeaders);
        /* clear the flags we are about to restore */
        *responseFlags &= restoreFlagsMask;
        /* only keep the flags we want to restore */
        origFlags &= ~restoreFlagsMask;
        /* set the saved flags as they were */
        *responseFlags |= origFlags;
        char* response = answerbuffer;
        uint16_t responseLen = rlen;
        --ds->outstanding;
        outstanding = false;

        if (ednsAdded) {
          const char * optStart = NULL;
          size_t optLen = 0;
          bool last = false;

          int res = locateEDNSOptRR(response, responseLen, &optStart, &optLen, &last);

          if (res == 0) {
            if (last) {
              /* simply remove the last AR */
              responseLen -= optLen;
              uint16_t arcount = ntohs(responseHeaders->arcount);
              arcount--;
              responseHeaders->arcount = htons(arcount);
            }
            else {
              /* Removing an intermediary RR could lead to compression error */
              if (rewriteResponseWithoutEDNS(response, responseLen, rewrittenResponse) == 0) {
#ifdef HAVE_DNSCRYPT
                if (ci.cs->dnscryptCtx && rewrittenResponse.capacity() < responseSize && ci.cs->dnscryptCtx) {
                  /* we preserve room for dnscrypt */
                  rewrittenResponse.reserve(responseSize);
                }
#endif
                responseSize = responseLen;
                responseLen = rewrittenResponse.size();
                response = reinterpret_cast<char*>(rewrittenResponse.data());
              }
              else {
                warnlog("Error rewriting content");
              }
            }
          }
        }

	if(g_fixupCase) {
	  string realname = qname.toDNSString();
	  memcpy(response + sizeof(dnsheader), realname.c_str(), realname.length());
	}

	if (packetCache && !dq.skipCache) {
	  packetCache->insert(cacheKey, qname, qtype, qclass, response, responseLen, true, dh->rcode == RCode::ServFail);
	}

#ifdef HAVE_DNSCRYPT
        if (ci.cs->dnscryptCtx) {
          uint16_t encryptedResponseLen = 0;
          int res = ci.cs->dnscryptCtx->encryptResponse(response, responseLen, responseSize, dnsCryptQuery, true, &encryptedResponseLen);

          if (res == 0) {
            responseLen = encryptedResponseLen;
          } else {
            /* dropping response */
            vinfolog("Error encrypting the response, dropping.");
            break;
          }
        }
#endif

        if (putNonBlockingMsgLen(ci.fd, responseLen, ds->tcpSendTimeout))
          writen2WithTimeout(ci.fd, response, responseLen, ds->tcpSendTimeout);

        g_stats.responses++;
        struct timespec answertime;
        clock_gettime(CLOCK_MONOTONIC, &answertime);
        unsigned int udiff = 1000000.0*DiffTime(now,answertime);
        {
          std::lock_guard<std::mutex> lock(g_rings.respMutex);
          g_rings.respRing.push_back({answertime,  ci.remote, qname, dq.qtype, (unsigned int)udiff, (unsigned int)responseLen, *dq.dh, ds->remote});
        }

        largerQuery.clear();
        rewrittenResponse.clear();
      }
    }
    catch(...){}

  drop:;
    
    vinfolog("Closing TCP client connection with %s", ci.remote.toStringWithPort());
    close(ci.fd); 
    ci.fd=-1;
    if (ds && outstanding) {
      outstanding = false;
      --ds->outstanding;
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

  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;
  
  g_tcpclientthreads->addTCPClientThread();

  auto acl = g_ACL.getLocal();
  for(;;) {
    ConnectionInfo* ci;
    try {
      ci=0;
      ci = new ConnectionInfo;
      ci->cs = cs;
      ci->fd = -1;
      ci->fd = SAccept(cs->tcpFD, remote);

      if(!acl->match(remote)) {
	g_stats.aclDrops++;
	close(ci->fd);
	delete ci;
	ci=0;
	vinfolog("Dropped TCP connection from %s because of ACL", remote.toStringWithPort());
	continue;
      }

      vinfolog("Got TCP connection from %s", remote.toStringWithPort());
      
      ci->remote = remote;
      int pipe = g_tcpclientthreads->getThread();
      if (pipe >= 0) {
        writen2WithTimeout(pipe, &ci, sizeof(ci), 0);
      }
      else {
        close(ci->fd);
        delete ci;
      }
    }
    catch(std::exception& e) {
      errlog("While reading a TCP question: %s", e.what());
      if(ci && ci->fd >= 0) 
	close(ci->fd);
      delete ci;
    }
    catch(...){}
  }

  return 0;
}


bool getMsgLen32(int fd, uint32_t* len)
try
{
  uint32_t raw;
  int ret = readn2(fd, &raw, sizeof raw);
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
  int ret = writen2(fd, &raw, sizeof raw);
  return ret==sizeof raw;
}
catch(...) {
  return false;
}
