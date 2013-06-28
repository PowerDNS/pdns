/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2013  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "sstuff.hh"
#include "misc.hh"
#include "statbag.hh"
#include <netinet/tcp.h>
#include <boost/program_options.hpp>
#include <boost/foreach.hpp>
#include <limits>

/* syntax: dnsdist 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220
   Added downstream server 8.8.8.8:53
   Added downstream server 8.8.4.4:53
   Added downstream server 208.67.222.222:53
   Added downstream server 208.67.220.220:53
   Listening on [::]:53

   And you are in business!
 */

StatBag S;
namespace po = boost::program_options;
po::variables_map g_vm;

bool g_verbose;
AtomicCounter g_pos;
uint16_t g_maxOutstanding;
bool g_console;

#define infolog(X,Y) if(g_verbose) { syslog(LOG_INFO, "%s", (boost::format((X)) % Y).str().c_str()); \
    if(g_console) cout << boost::format((X)) %Y << endl; } do{}while(0)
#define warnlog(X,Y) { syslog(LOG_WARNING, "%s", (boost::format((X)) % Y).str().c_str()); \
    if(g_console) cout << boost::format((X)) %Y << endl; } do{}while(0)
#define errlog(X,Y) {syslog(LOG_ERR, "%s", (boost::format((X)) % Y).str().c_str()); \
    if(g_console) cout << boost::format((X)) %Y << endl; }do{}while(0)

/* UDP: the grand design. Per socket we listen on for incoming queries there is one thread.
   Then we have a bunch of connected sockets for talking to downstream servers. 
   We send directly to those sockets.

   For the return path, per downstream server we have a thread that listens to responses.

   Per socket there is an array of 2^16 states, when we send out a packet downstream, we note
   there the original requestor and the original id. The new ID is the offset in the array.

   When an answer comes in on a socket, we look up the offset by the id, and lob it to the 
   original requestor.

   IDs are assigned by atomic increments of the socket offset.
 */

struct IDState
{
  IDState() : origFD(-1) {}

  int origFD;  // set to <0 to indicate this state is empty
  uint16_t origID;
  ComboAddress origRemote;
  AtomicCounter age;
};

struct DownstreamState
{
  int fd;            
  pthread_t tid;
  ComboAddress remote;

  vector<IDState> idStates;
  AtomicCounter idOffset;
  AtomicCounter sendErrors;
  AtomicCounter outstanding;
  AtomicCounter reuseds;
  AtomicCounter queries;
};

DownstreamState* g_dstates;
unsigned int g_numdownstreams;

// listens on a dedicated socket, lobs answers from downstream servers to original requestors
void* responderThread(void *p)
{
  DownstreamState* state = (DownstreamState*)p;
  char packet[65536];

  struct dnsheader* dh = (struct dnsheader*)packet;
  int len;
  for(;;) {
    len = recv(state->fd, packet, sizeof(packet), 0);
    if(len < 0)
      continue;

    if(dh->id >= g_maxOutstanding)
      continue;

    IDState* ids = &state->idStates[dh->id];
    if(ids->origFD < 0)
      continue;
    else
      --state->outstanding;  // you'd think you could game this, but we're using connected socket

    dh->id = ids->origID;
    sendto(ids->origFD, packet, len, 0, (struct sockaddr*)&ids->origRemote, ids->origRemote.getSocklen());
    infolog("Got answer from %s, relayed to %s", state->remote.toStringWithPort() % ids->origRemote.toStringWithPort());

    ids->origFD = -1;
  }
  return 0;
}

struct ClientState
{
  ComboAddress local;
  int udpFD;
  int tcpFD;
};

DownstreamState& getBestDownstream()
{
  unsigned int lowest = std::numeric_limits<unsigned int>::max();
  unsigned int chosen = 0;
  for(unsigned int n = 0; n < g_numdownstreams; ++n) {
    if(g_dstates[n].outstanding < lowest) {
      chosen = n;
      lowest=g_dstates[n].outstanding;
    }
  }      
  return g_dstates[chosen];
}

static void daemonize(void)
{
  if(fork())
    _exit(0); // bye bye
  
  setsid(); 

  int i=open("/dev/null",O_RDWR); /* open stdin */
  if(i < 0) 
    ; // L<<Logger::Critical<<"Unable to open /dev/null: "<<stringerror()<<endl;
  else {
    dup2(i,0); /* stdin */
    dup2(i,1); /* stderr */
    dup2(i,2); /* stderr */
    close(i);
  }
}


// listens to incoming queries, sends out to downstream servers, noting the intended return path 
void* udpClientThread(void* p)
{
  ClientState* cs = (ClientState*) p;

  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;
  socklen_t socklen = cs->local.getSocklen();
  
  char packet[1500];
  struct dnsheader* dh = (struct dnsheader*) packet;
  int len;

  for(;;) {
    len = recvfrom(cs->udpFD, packet, sizeof(packet), 0, (struct sockaddr*) &remote, &socklen);
    if(len < 0) 
      continue;

    /* right now, this is our simple round robin downstream selector */
    DownstreamState& ss = getBestDownstream();
    ss.queries++;

    unsigned int idOffset = (ss.idOffset++) % g_maxOutstanding;
    IDState* ids = &ss.idStates[idOffset];

    if(ids->origFD < 0) // if we are reusing, no change in outstanding
      ss.outstanding++;
    else
      ss.reuseds++;

    ids->origFD = cs->udpFD;
    ids->age = AtomicCounter();
    ids->origID = dh->id;
    ids->origRemote = remote;

    dh->id = idOffset;
    
    len = send(ss.fd, packet, len, 0);
    if(len < 0) 
      ss.sendErrors++;

    infolog("Got query from %s, relayed to %s", remote.toStringWithPort() % ss.remote.toStringWithPort());
  }
  return 0;
}

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

int getTCPDownstream(DownstreamState** ds)
{
  *ds = &getBestDownstream();
  infolog("TCP connecting to downstream %s", (*ds)->remote.toStringWithPort());
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

void* tcpClientThread(void* p);
class TCPClientCollection {
  vector<int> d_tcpclientthreads;
  AtomicCounter d_pos;
public:
  AtomicCounter d_queued, d_numthreads;

  TCPClientCollection()
  {
    d_tcpclientthreads.reserve(1024);
  }

  int getThread() 
  {
    int pos = d_pos++;
    ++d_queued;
    return d_tcpclientthreads[pos % d_numthreads];
  }

  // Should not be called simultaneously!
  void addTCPClientThread()
  {  
    infolog("Adding TCP Client threa%c", 'd');
    int pipefds[2];
    if(pipe(pipefds) < 0)
      unixDie("Creating pipe");
    int *fd = new int(pipefds[0]);
    d_tcpclientthreads.push_back(pipefds[1]);
    
    pthread_t tid;
    pthread_create(&tid, 0, tcpClientThread, (void*)fd);
    ++d_numthreads;
  }
} g_tcpclientthreads;


void* tcpClientThread(void* p)
{
  /* we get launched with a pipe on which we receive file descriptors from clients that we own
     from that point on */
  int pipefd = *(int*)p;
  delete (int*)p;

  int dsock = -1;
  DownstreamState *ds=0;
  
  for(;;) {
    ConnectionInfo* citmp, ci;
    readn2(pipefd, &citmp, sizeof(citmp));
    --g_tcpclientthreads.d_queued;
    ci=*citmp;
    delete citmp;
     
    if(dsock == -1)
      dsock = getTCPDownstream(&ds);
    else {
      infolog("Reusing existing TCP connection to %s", ds->remote.toStringWithPort());
    }

    uint16_t qlen, rlen;
    try {
      for(;;) {      
	if(!getMsgLen(ci.fd, &qlen))
	  break;
	
	ds->queries++;
	ds->outstanding++;
	char query[qlen];
	readn2(ci.fd, query, qlen);
	// FIXME: drop AXFR queries here, they confuse us
      retry:; 
	if(!putMsgLen(dsock, qlen)) {
	  infolog("Downstream connection to %s died on us, getting a new one!", ds->remote.toStringWithPort());
	  close(dsock);
	  dsock=getTCPDownstream(&ds);
	  goto retry;
	}
      
	writen2(dsock, query, qlen);
      
	if(!getMsgLen(dsock, &rlen)) {
	  infolog("Downstream connection to %s died on us phase 2, getting a new one!", ds->remote.toStringWithPort());
	  close(dsock);
	  dsock=getTCPDownstream(&ds);
	  goto retry;
	}

	char answerbuffer[rlen];
	readn2(dsock, answerbuffer, rlen);
      
	putMsgLen(ci.fd, rlen);
	writen2(ci.fd, answerbuffer, rlen);
      }
    }
    catch(...){}
    infolog("Closing client connection with %s", ci.remote.toStringWithPort());
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
      infolog("Got connection from %s", remote.toStringWithPort());
      
      ci->remote = remote;
      writen2(g_tcpclientthreads.getThread(), &ci, sizeof(ci));
    }
    catch(...){}
  }

  return 0;
}


void* statThread(void*)
{
  int interval = 1;
  if(!interval)
    return 0;
  uint32_t lastQueries=0;
  vector<DownstreamState> prev;
  prev.resize(g_numdownstreams);

  for(;;) {
    sleep(interval);
    
    if(g_tcpclientthreads.d_queued > 1 && g_tcpclientthreads.d_numthreads < 10)
      g_tcpclientthreads.addTCPClientThread();

    unsigned int outstanding=0;
    uint64_t numQueries=0;
    for(unsigned int n=0; n < g_numdownstreams; ++n) {
      DownstreamState& dss = g_dstates[n];
      infolog(" %s: %d outstanding, %f qps", dss.remote.toStringWithPort() % dss.outstanding % ((dss.queries - prev[n].queries)/interval));

      outstanding += dss.outstanding;
      prev[n].queries = dss.queries;
      numQueries += dss.queries;
      for(unsigned int i=0 ; i < g_maxOutstanding; ++i) {
	IDState& ids = dss.idStates[i];
	if(ids.origFD >=0 && ids.age++ > 2) {
	  ids.age = AtomicCounter();
	  ids.origFD = -1;
	  dss.reuseds++;
	  --dss.outstanding;
	}	  
      }
    }

    infolog("%d outstanding queries, %d qps", outstanding  % ((numQueries - lastQueries)/interval));
    lastQueries=numQueries;
  }
  return 0;
}



int main(int argc, char** argv)
try
{
  signal(SIGPIPE, SIG_IGN);
  openlog("dnsdist", LOG_PID, LOG_DAEMON);
  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("daemon", po::value<bool>()->default_value(true), "run in background")
    ("local", po::value<vector<string> >(), "Listen on which address")
    ("max-outstanding", po::value<uint16_t>()->default_value(65535), "maximum outstanding queries per downstream")
    ("verbose,v", "be verbose");
    
  hidden.add_options()
    ("remotes", po::value<vector<string> >(), "remote-host");

  alloptions.add(desc).add(hidden); 

  po::positional_options_description p;
  p.add("remotes", -1);

  po::store(po::command_line_parser(argc, argv).options(alloptions).positional(p).run(), g_vm);
  po::notify(g_vm);
  
  if(g_vm.count("help")) {
    cout << desc<<endl;
    exit(EXIT_SUCCESS);
  }

  g_verbose=g_vm.count("verbose");
  g_maxOutstanding = g_vm["max-outstanding"].as<uint16_t>();
  
  if(!g_vm.count("remotes")) {
    cerr<<"Need to specify at least one remote address"<<endl;
    cout<<desc<<endl;
    exit(EXIT_FAILURE);
  }

  if(g_vm["daemon"].as<bool>()) 
    daemonize();
  else {
    infolog("Running in the %s", "foreground");
    g_console=true;
  }

  vector<string> remotes = g_vm["remotes"].as<vector<string> >();

  g_numdownstreams = remotes.size();
  g_dstates = new DownstreamState[g_numdownstreams];
  int pos=0;
  BOOST_FOREACH(const string& remote, remotes) {
    DownstreamState& dss = g_dstates[pos++];
 
    dss.remote = ComboAddress(remote, 53);
    
    dss.fd = SSocket(dss.remote.sin4.sin_family, SOCK_DGRAM, 0);
    SConnect(dss.fd, dss.remote);

    dss.idStates.resize(g_maxOutstanding);


    infolog("Added downstream server %s", dss.remote.toStringWithPort());

    pthread_create(&dss.tid, 0, responderThread, (void*)&dss);
  }

  pthread_t tid;
  vector<string> locals;
  if(g_vm.count("local"))
    locals = g_vm["local"].as<vector<string> >();
  else
    locals.push_back("::");

  BOOST_FOREACH(const string& local, locals) {
    ClientState* cs = new ClientState;
    cs->local= ComboAddress(local, 53);
    cs->udpFD = SSocket(cs->local.sin4.sin_family, SOCK_DGRAM, 0);
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    SBind(cs->udpFD, cs->local);    

    pthread_create(&tid, 0, udpClientThread, (void*) cs);
  }

  BOOST_FOREACH(const string& local, locals) {
    ClientState* cs = new ClientState;
    cs->local= ComboAddress(local, 53);

    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);

    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
    SSetsockopt(cs->tcpFD, SOL_TCP,TCP_DEFER_ACCEPT, 1);
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->tcpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }

    SBind(cs->tcpFD, cs->local);
    SListen(cs->tcpFD, 64);
    warnlog("Listening on %s",cs->local.toStringWithPort());

    pthread_create(&tid, 0, tcpAcceptorThread, (void*) cs);
  }

  pthread_t stattid;
  pthread_create(&stattid, 0, statThread, 0);
  void* status;

  pthread_join(tid, &status);
}
catch(std::exception &e)
{
  errlog("Fatal: %s", e.what());
}
catch(AhuException &ae)
{
  errlog("Fatal: %s", ae.reason);
}
