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

int getTCPDownstream(policy_t policy, string pool, DownstreamState** ds, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{  
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    *ds = policy(getDownstreamCandidates(g_dstates.getCopy(), pool), remote, qname, qtype, dh).get(); 
  }
  
  vinfolog("TCP connecting to downstream %s", (*ds)->remote.toStringWithPort());
  int sock = SSocket((*ds)->remote.sin4.sin_family, SOCK_STREAM, 0);
  SConnect(sock, (*ds)->remote);
  return sock;
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
  int dsock = -1;
  DownstreamState *ds=0;
  
  for(;;) {
    ConnectionInfo* citmp, ci;

    readn2(pipefd, &citmp, sizeof(citmp));
    --g_tcpclientthreads.d_queued;
    ci=*citmp;
    delete citmp;
    
    uint16_t qlen, rlen;
    string pool; // empty for now
    try {
      auto localPolicy = g_policy.getLocal();
      for(;;) {      
        if(!getMsgLen(ci.fd, &qlen))
          break;
        
        char query[qlen];
        readn2(ci.fd, query, qlen);
	uint16_t qtype;
	DNSName qname(query, qlen, 12, false, &qtype);
	struct dnsheader* dh =(dnsheader*)query;
	if(dsock == -1) {
	  dsock = getTCPDownstream(localPolicy->policy, pool, &ds, ci.remote, qname, qtype, dh);
	}
	else {
	  vinfolog("Reusing existing TCP connection to %s", ds->remote.toStringWithPort());
	}
        ds->queries++;
        ds->outstanding++;

	if(qtype == QType::AXFR)  // XXX fixme we really need to do better
	  break;

      retry:; 
        if(!putMsgLen(dsock, qlen)) {
	  vinfolog("Downstream connection to %s died on us, getting a new one!", ds->remote.toStringWithPort());
          close(dsock);
          dsock=getTCPDownstream(localPolicy->policy, pool, &ds, ci.remote, qname, qtype, dh);
          goto retry;
        }
      
        writen2(dsock, query, qlen);
      
        if(!getMsgLen(dsock, &rlen)) {
	  vinfolog("Downstream connection to %s died on us phase 2, getting a new one!", ds->remote.toStringWithPort());
          close(dsock);
          dsock=getTCPDownstream(localPolicy->policy, pool, &ds, ci.remote, qname, qtype, dh);
          goto retry;
        }

        char answerbuffer[rlen];
        readn2(dsock, answerbuffer, rlen);
      
        putMsgLen(ci.fd, rlen);
        writen2(ci.fd, answerbuffer, rlen);
      }
    }
    catch(...){}
    
    vinfolog("Closing client connection with %s", ci.remote.toStringWithPort());
    close(ci.fd); 
    ci.fd=-1;
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
