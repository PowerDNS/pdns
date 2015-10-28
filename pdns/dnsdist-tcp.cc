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

  d_tcpclientthreads.push_back(pipefds[1]);    
  thread t1(tcpClientThread, pipefds[0]);
  t1.detach();
  ++d_numthreads;
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

  map<ComboAddress,int> sockets;
  for(;;) {
    ConnectionInfo* citmp, ci;

    readn2(pipefd, &citmp, sizeof(citmp));
    --g_tcpclientthreads.d_queued;
    ci=*citmp;
    delete citmp;    

    uint16_t qlen, rlen;
    string pool; 



    shared_ptr<DownstreamState> ds;
    try {
      for(;;) {      
        if(!getMsgLen(ci.fd, &qlen))
          break;
        
        char query[qlen];
        readn2(ci.fd, query, qlen);
	uint16_t qtype;
	DNSName qname(query, qlen, 12, false, &qtype);
	string ruleresult;
	struct dnsheader* dh =(dnsheader*)query;
	
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
	  putMsgLen(ci.fd, qlen);
	  writen2(ci.fd, query, rlen);
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

	if(qtype == QType::AXFR)  // XXX fixme we really need to do better
	  break;

      retry:; 
        if(!putMsgLen(dsock, qlen)) {
	  vinfolog("Downstream connection to %s died on us, getting a new one!", ds->remote.toStringWithPort());
          close(dsock);
          sockets[ds->remote]=dsock=setupTCPDownstream(ds->remote);
          goto retry;
        }
      
        writen2(dsock, query, qlen);
      
        if(!getMsgLen(dsock, &rlen)) {
	  vinfolog("Downstream connection to %s died on us phase 2, getting a new one!", ds->remote.toStringWithPort());
          close(dsock);
          sockets[ds->remote]=dsock=setupTCPDownstream(ds->remote);
          goto retry;
        }

        char answerbuffer[rlen];
        readn2(dsock, answerbuffer, rlen);
      
        putMsgLen(ci.fd, rlen);
        writen2(ci.fd, answerbuffer, rlen);
      }
    }
    catch(...){}

  drop:;
    
    vinfolog("Closing client connection with %s", ci.remote.toStringWithPort());
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

  for(;;) {
    try {
      ConnectionInfo* ci = new ConnectionInfo;      
      ci->fd = SAccept(cs->tcpFD, remote);

      vinfolog("Got connection from %s", remote.toStringWithPort());
      
      ci->remote = remote;
      writen2(g_tcpclientthreads.getThread(), &ci, sizeof(ci));
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
