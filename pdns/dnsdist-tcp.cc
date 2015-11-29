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
#include "dolog.hh"
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

static int setupTCPDownstream(const ComboAddress& remote)
{  
  vinfolog("TCP connecting to downstream %s", remote.toStringWithPort());
  int sock = SSocket(remote.sin4.sin_family, SOCK_STREAM, 0);
  SConnect(sock, remote);
  setNonBlocking(sock);
  return sock;
}

struct ConnectionInfo
{
  int fd;
  ComboAddress remote;
};

void* tcpClientThread(int pipefd);

// Should not be called simultaneously!
void TCPClientCollection::addTCPClientThread()
{  
  vinfolog("Adding TCP Client thread");

  int pipefds[2];
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

TCPClientCollection g_tcpclientthreads;

void* tcpClientThread(int pipefd)
{
  /* we get launched with a pipe on which we receive file descriptors from clients that we own
     from that point on */
     
  typedef std::function<bool(ComboAddress, DNSName, uint16_t, dnsheader*)> blockfilter_t;
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

  map<ComboAddress,int> sockets;
  for(;;) {
    ConnectionInfo* citmp, ci;

    readn2(pipefd, &citmp, sizeof(citmp));
    --g_tcpclientthreads.d_queued;
    ci=*citmp;
    delete citmp;    

    uint16_t qlen, rlen;
    string pool; 
    const uint16_t rdMask = 1 << FLAGS_RD_OFFSET;
    const uint16_t cdMask = 1 << FLAGS_CD_OFFSET;
    const uint16_t restoreFlagsMask = UINT16_MAX & ~(rdMask | cdMask);

    shared_ptr<DownstreamState> ds;
    if (!setNonBlocking(ci.fd))
      goto drop;

    try {
      for(;;) {      
        if(!getNonBlockingMsgLen(ci.fd, &qlen, g_tcpRecvTimeout))
          break;

        if (qlen < sizeof(dnsheader)) {
          g_stats.nonCompliantQueries++;
          break;
        }

        char query[qlen];
        readn2WithTimeout(ci.fd, query, qlen, g_tcpRecvTimeout);
	uint16_t qtype;
	DNSName qname(query, qlen, 12, false, &qtype);
	string ruleresult;
	struct dnsheader* dh =(dnsheader*)query;
	const uint16_t * flags = getFlagsFromDNSHeader(dh);
	uint16_t origFlags = *flags;
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);

	g_rings.queryRing.push_back({now,ci.remote,qname,qtype}); // XXX LOCK?!

	if(localDynBlockNMG->match(ci.remote)) {
	  vinfolog("Query from %s dropped because of dynamic block", ci.remote.toStringWithPort());
	  g_stats.dynBlocked++;
	  goto drop;
	}

        if(blockFilter) {
	  std::lock_guard<std::mutex> lock(g_luamutex);
	
	  if(blockFilter(ci.remote, qname, qtype, dh)) {
	    g_stats.blockFilter++;
	    goto drop;
          }
          if(dh->tc && dh->qr) { // don't truncate on TCP/IP!
            dh->tc=false;        // maybe we should just pass blockFilter the TCP status
            dh->qr=false;
          }
        }
	
	DNSAction::Action action=DNSAction::Action::None;
	for(const auto& lr : *localRulactions) {
	  if(lr.first->matches(ci.remote, qname, qtype, dh, qlen)) {
	    action=(*lr.second)(ci.remote, qname, qtype, dh, qlen, &ruleresult);
	    if(action != DNSAction::Action::None) {
	      lr.first->d_matches++;
	      break;
	    }
	  }
	}
	switch(action) {
	case DNSAction::Action::Drop:
	  g_stats.ruleDrop++;
	  goto drop;

	case DNSAction::Action::Nxdomain:
	  dh->rcode = RCode::NXDomain;
	  dh->qr=true;
	  g_stats.ruleNXDomain++;
	  break;
	case DNSAction::Action::Pool: 
	  pool=ruleresult;
	  break;
	  
	case DNSAction::Action::Spoof:
	  ;
	case DNSAction::Action::HeaderModify:
	  dh->qr=true;
	  break;
	case DNSAction::Action::Allow:
	case DNSAction::Action::None:
	case DNSAction::Action::Delay:
	  break;
	}
	
	if(dh->qr) { // something turned it into a response
	  if (putNonBlockingMsgLen(ci.fd, qlen, g_tcpSendTimeout))
	    writen2WithTimeout(ci.fd, query, rlen, g_tcpSendTimeout);
	  goto drop;
	}

	{
	  std::lock_guard<std::mutex> lock(g_luamutex);
	  ds = localPolicy->policy(getDownstreamCandidates(g_dstates.getCopy(), pool), ci.remote, qname, qtype, dh);
	}
	int dsock;
	if(!ds) {
	  g_stats.noPolicy++;
	  break;
	}
	if(sockets.count(ds->remote) == 0) {
	  dsock=sockets[ds->remote]=setupTCPDownstream(ds->remote);
	}
	else
	  dsock=sockets[ds->remote];

        ds->queries++;
        ds->outstanding++;

	if(qtype == QType::AXFR || qtype == QType::IXFR)  // XXX fixme we really need to do better
	  break;

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

        if(!putNonBlockingMsgLen(dsock, qlen, ds->tcpSendTimeout)) {
	  vinfolog("Downstream connection to %s died on us, getting a new one!", ds->getName());
          close(dsock);
          sockets[ds->remote]=dsock=setupTCPDownstream(ds->remote);
          downstream_failures++;
          goto retry;
        }
      
        writen2WithTimeout(dsock, query, qlen, ds->tcpSendTimeout);
      
        if(!getNonBlockingMsgLen(dsock, &rlen, ds->tcpRecvTimeout)) {
	  vinfolog("Downstream connection to %s died on us phase 2, getting a new one!", ds->getName());
          close(dsock);
          sockets[ds->remote]=dsock=setupTCPDownstream(ds->remote);
          downstream_failures++;
          goto retry;
        }

        char answerbuffer[rlen];
        readn2WithTimeout(dsock, answerbuffer, rlen, ds->tcpRecvTimeout);
        struct dnsheader* responseHeaders = (struct dnsheader*)answerbuffer;
        uint16_t * responseFlags = getFlagsFromDNSHeader(responseHeaders);
        /* clear the flags we are about to restore */
        *responseFlags &= restoreFlagsMask;
        /* only keep the flags we want to restore */
        origFlags &= ~restoreFlagsMask;
        /* set the saved flags as they were */
        *responseFlags |= origFlags;

        if (putNonBlockingMsgLen(ci.fd, rlen, ds->tcpSendTimeout))
          writen2WithTimeout(ci.fd, answerbuffer, rlen, ds->tcpSendTimeout);
      }
    }
    catch(...){}

  drop:;
    
    vinfolog("Closing TCP client connection with %s", ci.remote.toStringWithPort());
    close(ci.fd); 
    ci.fd=-1;
    if(ds)
      --ds->outstanding;
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
  
  g_tcpclientthreads.addTCPClientThread();

  auto acl = g_ACL.getLocal();
  for(;;) {
    ConnectionInfo* ci;
    try {
      ci=0;
      ci = new ConnectionInfo;
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
      int pipe = g_tcpclientthreads.getThread();
      writen2WithTimeout(pipe, &ci, sizeof(ci), 0);
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


bool getMsgLen(int fd, uint16_t* len)
try
{
  uint16_t raw;
  int ret = readn2(fd, &raw, 2);
  if(ret != 2)
    return false;
  *len = ntohs(raw);
  return true;
}
catch(...) {
   return false;
}

bool putMsgLen(int fd, uint16_t len)
try
{
  uint16_t raw = htons(len);
  int ret = writen2(fd, &raw, 2);
  return ret==2;
}
catch(...) {
  return false;
}
