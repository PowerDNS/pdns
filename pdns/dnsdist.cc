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
#include "ext/luawrapper/include/LuaContext.hpp"
#include <boost/circular_buffer.hpp>
#include "sstuff.hh"
#include "misc.hh"
#include <mutex>
#include "statbag.hh"
#include <netinet/tcp.h>
#include <boost/program_options.hpp>


#include <thread>
#include <limits>
#include <atomic>
#include "arguments.hh"
#include "dolog.hh"
#include <readline/readline.h>
#include <readline/history.h>
#include "dnsname.hh"
#include "dnswriter.hh"
#include "base64.hh"
#include <fstream>
#include <sodium.h>
#include "sodcrypto.hh"
#undef L

/* Known sins:
   We replace g_ACL w/o locking, might crash
     g_policy too probably
   No centralized statistics
   We neglect to do recvfromto() on 0.0.0.0
   Receiver is currently singlethreaded (not that bad actually)
   We can't compile w/o crypto
   our naming is as inconsistent as only ahu can make it
   lack of help()
   we offer now way to log from Lua
   our startup fails *after* fork on most cases, which is not overly helpful
*/

ArgvMap& arg()
{
  static ArgvMap a;
  return a;
}
StatBag S;
namespace po = boost::program_options;
po::variables_map g_vm;
using std::atomic;
using std::thread;
bool g_verbose;
atomic<uint64_t> g_pos;
atomic<uint64_t> g_regexBlocks;
uint16_t g_maxOutstanding;
bool g_console;
NetmaskGroup g_ACL;
string g_outputBuffer;


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

/* for our load balancing, we want to support:
   Round-robin
   Round-robin with basic uptime checks
   Send to least loaded server (least outstanding)
   Send it to the first server that is not overloaded
*/

/* Idea:
   Multiple server groups, by default we load balance to the group with no name.
   Each instance is either 'up', 'down' or 'auto', where 'auto' means that dnsdist 
   determines if the instance is up or not. Auto should be the default and very very good.

   In addition, to each instance you can attach a QPS object with rate & burst, which will optionally
   limit the amount of queries we send there.

   If all downstreams are over QPS, we pick the fastest server */

struct StopWatch
{
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif
  struct timespec d_start{0,0};
  void start() {  
    if(clock_gettime(CLOCK_MONOTONIC_RAW, &d_start) < 0)
      unixDie("Getting timestamp");
    
  }
  
  double udiff() const {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC_RAW, &now) < 0)
      unixDie("Getting timestamp");
    
    return 1000000.0*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec)/1000.0;
  }

  double udiffAndSet() {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC_RAW, &now) < 0)
      unixDie("Getting timestamp");
    
    auto ret= 1000000.0*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec)/1000.0;
    d_start = now;
    return ret;
  }

};

class QPSLimiter
{
public:
  QPSLimiter()
  {
  }

  QPSLimiter(unsigned int rate, unsigned int burst) : d_rate(rate), d_burst(burst), d_tokens(burst)
  {
    d_passthrough=false;
    d_prev.start();
  }

  unsigned int getRate() const
  {
    return d_passthrough? 0 : d_rate;
  }

  int getPassed() const
  {
    return d_passed;
  }
  int getBlocked() const
  {
    return d_blocked;
  }

  bool check()
  {
    if(d_passthrough)
      return true;
    auto delta = d_prev.udiffAndSet();
  
    d_tokens += 1.0*d_rate * (delta/1000000.0);

    if(d_tokens > d_burst)
      d_tokens = d_burst;

    bool ret=false;
    if(d_tokens >= 1.0) { // we need this because burst=1 is weird otherwise
      ret=true;
      --d_tokens;
      d_passed++;
    }
    else
      d_blocked++;

    return ret; 
  }
private:
  bool d_passthrough{true};
  unsigned int d_rate;
  unsigned int d_burst;
  double d_tokens;
  StopWatch d_prev;
  unsigned int d_passed{0};
  unsigned int d_blocked{0};
};

vector<pair<boost::variant<SuffixMatchNode,NetmaskGroup>, QPSLimiter> > g_limiters;
vector<pair<boost::variant<SuffixMatchNode,NetmaskGroup>, string> > g_poolrules;

struct IDState
{
  IDState() : origFD(-1) {}
  IDState(const IDState& orig)
  {
    origFD = orig.origFD;
    origID = orig.origID;
    origRemote = orig.origRemote;
    age.store(orig.age.load());
  }

  int origFD;  // set to <0 to indicate this state is empty
  uint16_t origID;
  ComboAddress origRemote;
  StopWatch sentTime;
  DNSName qname;
  uint16_t qtype;
  atomic<uint64_t> age;
};

struct Rings {
  Rings()
  {
    clientRing.set_capacity(10000);
    queryRing.set_capacity(10000);
    respRing.set_capacity(10000);
  }
  boost::circular_buffer<ComboAddress> clientRing;
  boost::circular_buffer<DNSName> queryRing;
  struct Response
  {
    DNSName name;
    uint16_t qtype;
    uint8_t rcode;
    unsigned int usec;
  };
  boost::circular_buffer<Response> respRing;
  std::mutex respMutex;
} g_rings;

struct DownstreamState
{
  DownstreamState(const ComboAddress& remote_);

  int fd;            
  thread tid;
  ComboAddress remote;
  QPSLimiter qps;
  vector<IDState> idStates;
  atomic<uint64_t> idOffset{0};
  atomic<uint64_t> sendErrors{0};
  atomic<uint64_t> outstanding{0};
  atomic<uint64_t> reuseds{0};
  atomic<uint64_t> queries{0};
  struct {
    atomic<uint64_t> sendErrors{0};
    atomic<uint64_t> reuseds{0};
    atomic<uint64_t> queries{0};
  } prev;
  double queryLoad{0.0};
  double dropRate{0.0};
  double latencyUsec{0.0};
  int order{1};
  int weight{1};
  StopWatch sw;
  set<string> pools;
  enum class Availability { Up, Down, Auto} availability{Availability::Auto};
  bool upStatus{false};
  bool isUp() const
  {
    if(availability == Availability::Down)
      return false;
    if(availability == Availability::Up)
      return true;
    return upStatus;
  }
  void setUp() { availability = Availability::Up; }
  void setDown() { availability = Availability::Down; }
  void setAuto() { availability = Availability::Auto; }
};

vector<std::shared_ptr<DownstreamState> > g_dstates;

// listens on a dedicated socket, lobs answers from downstream servers to original requestors
void* responderThread(std::shared_ptr<DownstreamState> state)
{
  char packet[4096];
  
  struct dnsheader* dh = (struct dnsheader*)packet;
  int len;
  for(;;) {
    len = recv(state->fd, packet, sizeof(packet), 0);
    if(len < (signed)sizeof(dnsheader))
      continue;

    if(dh->id >= state->idStates.size())
      continue;

    IDState* ids = &state->idStates[dh->id];
    if(ids->origFD < 0) // duplicate
      continue;
    else
      --state->outstanding;  // you'd think an attacker could game this, but we're using connected socket

    dh->id = ids->origID;
    sendto(ids->origFD, packet, len, 0, (struct sockaddr*)&ids->origRemote, ids->origRemote.getSocklen());
    double udiff = ids->sentTime.udiff();
    vinfolog("Got answer from %s, relayed to %s, took %f usec", state->remote.toStringWithPort(), ids->origRemote.toStringWithPort(), udiff);

    std::lock_guard<std::mutex> lock(g_rings.respMutex);
    g_rings.respRing.push_back({ids->qname, ids->qtype, (uint8_t)dh->rcode, (unsigned int)udiff});
    
    state->latencyUsec = (127.0 * state->latencyUsec / 128.0) + udiff/128.0;

    ids->origFD = -1;
  }
  return 0;
}

DownstreamState::DownstreamState(const ComboAddress& remote_)
{
  remote = remote_;
  
  fd = SSocket(remote.sin4.sin_family, SOCK_DGRAM, 0);
  SConnect(fd, remote);
  
  idStates.resize(g_maxOutstanding);
  sw.start();
  infolog("Added downstream server %s", remote.toStringWithPort());
}


struct ClientState
{
  ComboAddress local;
  int udpFD;
  int tcpFD;
};


std::mutex g_luamutex;
LuaContext g_lua;

typedef std::function<shared_ptr<DownstreamState>(const vector<shared_ptr<DownstreamState>>& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)> policy_t;

struct ServerPolicy
{
  string name;
  policy_t policy;
} g_policy;

shared_ptr<DownstreamState> firstAvailable(const vector<shared_ptr<DownstreamState>>& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  for(auto& d : servers) {
    if(d->isUp() && d->qps.check())
      return d;
  }
  static int counter=0;
  ++counter;
  if(g_dstates.empty())
    return shared_ptr<DownstreamState>();
  return g_dstates[counter % g_dstates.size()];
}

shared_ptr<DownstreamState> leastOutstanding(const vector<shared_ptr<DownstreamState>>& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  vector<pair<pair<int,int>, shared_ptr<DownstreamState>>> poss;

  for(auto& d : servers) {      // w=1, w=10 -> 1, 11
    if(d->isUp()) {
      poss.push_back({make_pair(d->outstanding.load(), d->order), d});
    }
  }
  if(poss.empty())
    return shared_ptr<DownstreamState>();
  nth_element(poss.begin(), poss.begin(), poss.end(), [](const decltype(poss)::value_type& a, const decltype(poss)::value_type& b) { return a.first < b.first; });
  return poss.begin()->second;
}

shared_ptr<DownstreamState> wrandom(const vector<shared_ptr<DownstreamState>>& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  vector<pair<int, shared_ptr<DownstreamState>>> poss;
  int sum=0;
  for(auto& d : servers) {      // w=1, w=10 -> 1, 11
    if(d->isUp()) {
      sum+=d->weight;
      poss.push_back({sum, d});

    }
  }
  int r = random() % sum;
  auto p = upper_bound(poss.begin(), poss.end(),r, [](int r, const decltype(poss)::value_type& a) { return  r < a.first;});
  if(p==poss.end())
    return shared_ptr<DownstreamState>();
  return p->second;
}

shared_ptr<DownstreamState> roundrobin(const vector<shared_ptr<DownstreamState>>& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  vector<shared_ptr<DownstreamState>> poss;

  for(auto& d : servers) {
    if(d->isUp()) {
      poss.push_back(d);
    }
  }

  auto *res=&poss;
  if(poss.empty())
    res = &g_dstates;

  if(res->empty())
    return shared_ptr<DownstreamState>();

  static unsigned int counter;
 
  return (*res)[(counter++) % res->size()];
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

SuffixMatchNode g_suffixMatchNodeFilter;

ComboAddress g_serverControl{"127.0.0.1:5199"};

using servers_t =vector<shared_ptr<DownstreamState>>;
servers_t getDownstreamCandidates(const std::string& pool)
{
  if(pool.empty())
    return g_dstates;
  
  servers_t ret;
  for(auto& s : g_dstates) 
    if(s->pools.count(pool))
      ret.push_back(s);
  
  return ret;

}

// listens to incoming queries, sends out to downstream servers, noting the intended return path 
void* udpClientThread(ClientState* cs)
try
{
  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;
  socklen_t socklen = cs->local.getSocklen();
  
  char packet[1500];
  struct dnsheader* dh = (struct dnsheader*) packet;
  int len;

  string qname;
  uint16_t qtype;

  Regex* re=0;
  if(g_vm.count("regex-drop"))
    re=new Regex(g_vm["regex-drop"].as<string>());

  typedef std::function<bool(ComboAddress, DNSName, uint16_t, dnsheader*)> blockfilter_t;
  blockfilter_t blockFilter = 0;

  
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    auto candidate = g_lua.readVariable<boost::optional<blockfilter_t> >("blockFilter");
    if(candidate)
      blockFilter = *candidate;
  }
  for(;;) {
    try {
      len = recvfrom(cs->udpFD, packet, sizeof(packet), 0, (struct sockaddr*) &remote, &socklen);
      if(len < (int)sizeof(struct dnsheader)) 
	continue;
      
      if(!g_ACL.match(remote))
	continue;
      
      if(dh->qr)    // don't respond to responses
	continue;
      
      
      DNSName qname(packet, len, 12, false, &qtype);
      
      g_rings.queryRing.push_back(qname);
      
      bool blocked=false;
      for(auto& lim : g_limiters) {
	if(auto nmg=boost::get<NetmaskGroup>(&lim.first)) {
	  if(nmg->match(remote) && !lim.second.check()) {
	    blocked=true;
	    break;
	  }
	}
	else if(auto smn=boost::get<SuffixMatchNode>(&lim.first)) {
	  if(smn->check(qname) && !lim.second.check()) {
	    blocked=true;
	    break;
	  }
	}
      }
      if(blocked)
	continue;


      
      if(blockFilter) {
	std::lock_guard<std::mutex> lock(g_luamutex);
	
	if(blockFilter(remote, qname, qtype, dh))
	  continue;
      }
      
      if(g_suffixMatchNodeFilter.check(qname))
	continue;
      
      if(re && re->match(qname.toString())) {
	g_regexBlocks++;
	continue;
      }
      
      if(dh->qr) { // something turned it into a response
	sendto(cs->udpFD, packet, len, 0, (struct sockaddr*)&remote, remote.getSocklen());
	continue;
      }

      string pool;
      for(auto& pr : g_poolrules) {
	if(auto nmg=boost::get<NetmaskGroup>(&pr.first)) {
	  if(nmg->match(remote)) {
	    pool=pr.second;
	    break;
	  }
	}
	else if(auto smn=boost::get<SuffixMatchNode>(&pr.first)) {
	  if(smn->check(qname)) {
	    pool=pr.second;
	    break;
	  }
	}
      }
      DownstreamState* ss = 0;
      {
	std::lock_guard<std::mutex> lock(g_luamutex);
	auto candidates=getDownstreamCandidates(pool);
	ss = g_policy.policy(candidates, remote, qname, qtype, dh).get();
      }

      if(!ss)
	continue;
      
      ss->queries++;
      
      unsigned int idOffset = (ss->idOffset++) % ss->idStates.size();
      IDState* ids = &ss->idStates[idOffset];
      
      if(ids->origFD < 0) // if we are reusing, no change in outstanding
	ss->outstanding++;
      else
	ss->reuseds++;
      
      ids->origFD = cs->udpFD;
      ids->age = 0;
      ids->origID = dh->id;
      ids->origRemote = remote;
      ids->sentTime.start();
      ids->qname = qname;
      ids->qtype = qtype;
      dh->id = idOffset;
      
      len = send(ss->fd, packet, len, 0);
      if(len < 0) 
	ss->sendErrors++;
      
      vinfolog("Got query from %s, relayed to %s", remote.toStringWithPort(), ss->remote.toStringWithPort());
    }
    catch(std::exception& e){
      errlog("Got an error: %s", e.what());
    }
  }
  return 0;
}
catch(std::exception &e)
{
  errlog("UDP client thread died because of exception: %s", e.what());
  return 0;
}
catch(PDNSException &e)
{
  errlog("UDP client thread died because of PowerDNS exception: %s", e.reason);
  return 0;
}
catch(...)
{
  errlog("UDP client thread died because of an exception: %s", "unknown");
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

int getTCPDownstream(DownstreamState** ds, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    *ds = g_policy.policy(g_dstates, remote, qname, qtype, dh).get();
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

class TCPClientCollection {
  vector<int> d_tcpclientthreads;
  atomic<uint64_t> d_pos;
public:
  atomic<uint64_t> d_queued, d_numthreads;

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
    vinfolog("Adding TCP Client thread");

    int pipefds[2];
    if(pipe(pipefds) < 0)
      unixDie("Creating pipe");

    d_tcpclientthreads.push_back(pipefds[1]);    
    thread t1(tcpClientThread, pipefds[0]);
    t1.detach();
    ++d_numthreads;
  }
} g_tcpclientthreads;


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
    try {
      for(;;) {      
        if(!getMsgLen(ci.fd, &qlen))
          break;
        
        ds->queries++;
        ds->outstanding++;
        char query[qlen];
        readn2(ci.fd, query, qlen);
	uint16_t qtype;
	DNSName qname(query, qlen, 12, false, &qtype);
	struct dnsheader* dh =(dnsheader*)query;
	if(dsock == -1) {
	  dsock = getTCPDownstream(&ds, ci.remote, qname, qtype, dh);
	}
	else {
	  vinfolog("Reusing existing TCP connection to %s", ds->remote.toStringWithPort());
	}

        // FIXME: drop AXFR queries here, they confuse us
      retry:; 
        if(!putMsgLen(dsock, qlen)) {
	  vinfolog("Downstream connection to %s died on us, getting a new one!", ds->remote.toStringWithPort());
          close(dsock);
          dsock=getTCPDownstream(&ds, ci.remote, qname, qtype, dh);
          goto retry;
        }
      
        writen2(dsock, query, qlen);
      
        if(!getMsgLen(dsock, &rlen)) {
	  vinfolog("Downstream connection to %s died on us phase 2, getting a new one!", ds->remote.toStringWithPort());
          close(dsock);
          dsock=getTCPDownstream(&ds, ci.remote, qname, qtype, dh);
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

bool upCheck(const ComboAddress& remote)
try
{
  vector<uint8_t> packet;
  DNSPacketWriter dpw(packet, "a.root-servers.net.", QType::A);
  dpw.getHeader()->rd=true;

  Socket sock(remote.sin4.sin_family, SOCK_DGRAM);
  sock.setNonBlocking();
  sock.connect(remote);
  sock.write((char*)&packet[0], packet.size());  
  int ret=waitForRWData(sock.getHandle(), true, 1, 0);
  if(ret < 0 || !ret) // error, timeout, both are down!
    return false;
  string reply;
  ComboAddress dest=remote;
  sock.recvFrom(reply, dest);

  // XXX fixme do bunch of checking here etc 
  return true;
}
catch(...)
{
  return false;
}

void* maintThread()
{
  int interval = 2;

  for(;;) {
    sleep(interval);

    if(g_tcpclientthreads.d_queued > 1 && g_tcpclientthreads.d_numthreads < 10)
      g_tcpclientthreads.addTCPClientThread();

    for(auto& dss : g_dstates) {
      if(dss->availability==DownstreamState::Availability::Auto) {
	bool newState=upCheck(dss->remote);
	if(newState != dss->upStatus) {
	  cout<<endl;
	  warnlog("Marking downstream %s as '%s'", dss->remote.toStringWithPort(), newState ? "up" : "down");
	  cout<<"> ";
	  cout.flush();
	}
	dss->upStatus = newState;
      }

      auto delta = dss->sw.udiffAndSet()/1000000.0;
      dss->queryLoad = 1.0*(dss->queries.load() - dss->prev.queries.load())/delta;
      dss->dropRate = 1.0*(dss->reuseds.load() - dss->prev.reuseds.load())/delta;
      dss->prev.queries.store(dss->queries.load());
      dss->prev.reuseds.store(dss->reuseds.load());
      
      for(IDState& ids  : dss->idStates) { // timeouts
        if(ids.origFD >=0 && ids.age++ > 2) {
          ids.age = 0;
          ids.origFD = -1;
          dss->reuseds++;
          --dss->outstanding;
	  std::lock_guard<std::mutex> lock(g_rings.respMutex);
	  g_rings.respRing.push_back({ids.qname, ids.qtype, 0, 2000000});
        }          
      }
    }
  }
  return 0;
}

string g_key;

void controlClientThread(int fd, ComboAddress client)
try
{
  SodiumNonce theirs;
  readn2(fd, (char*)theirs.value, sizeof(theirs.value));
  SodiumNonce ours;
  ours.init();
  writen2(fd, (char*)ours.value, sizeof(ours.value));

  for(;;) {
    uint16_t len;
    if(!getMsgLen(fd, &len))
      break;
    char msg[len];
    readn2(fd, msg, len);
    
    string line(msg, len);
    line = sodDecryptSym(line, g_key, theirs);
    //    cerr<<"Have decrypted line: "<<line<<endl;
    string response;
    try {
      std::lock_guard<std::mutex> lock(g_luamutex);
      g_outputBuffer.clear();
      auto ret=g_lua.executeCode<
	boost::optional<
	  boost::variant<
	    string, 
	    shared_ptr<DownstreamState>
	    >
	  >
	>(line);

      if(ret) {
	if (const auto strValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
	  response=(*strValue)->remote.toStringWithPort();
	}
	else if (const auto strValue = boost::get<string>(&*ret)) {
	  response=*strValue;
	}
      }
      else
	response=g_outputBuffer;


    }
    catch(std::exception& e) {
      response="Error: "+string(e.what());
    }
    response = sodEncryptSym(response, g_key, ours);
    putMsgLen(fd, response.length());
    writen2(fd, response.c_str(), (uint16_t)response.length());
  }
  infolog("Closed control connection from %s", client.toStringWithPort());
  close(fd);
  fd=-1;
}
catch(std::exception& e)
{
  errlog("Got an exception in client connection from %s: %s", client.toStringWithPort(), e.what());
  if(fd >= 0)
    close(fd);
}


void controlThread(int fd, ComboAddress local)
try
{
  ComboAddress client;
  int sock;
  warnlog("Accepting control connections on %s", local.toStringWithPort());
  while((sock=SAccept(fd, client)) >= 0) {
    warnlog("Got control connection from %s", client.toStringWithPort());
    thread t(controlClientThread, sock, client);
    t.detach();
  }
}
catch(std::exception& e) 
{
  close(fd);
  errlog("Control connection died: %s", e.what());
}

void setupLua(bool client)
{
  g_lua.writeFunction("newServer", 
		      [](boost::variant<string,std::unordered_map<std::string, std::string>> pvars, boost::optional<int> qps)
		      { 
			if(auto address = boost::get<string>(&pvars)) {
			  auto ret=std::make_shared<DownstreamState>(ComboAddress(*address, 53));
			  ret->tid = move(thread(responderThread, ret));
			  if(qps) {
			    ret->qps=QPSLimiter(*qps, *qps);
			  }
			  g_dstates.push_back(ret);
			  return ret;
			}
			auto vars=boost::get<std::unordered_map<std::string, std::string>>(pvars);
			auto ret=std::make_shared<DownstreamState>(ComboAddress(vars["address"], 53));

			ret->tid = move(thread(responderThread, ret));

			if(vars.count("qps")) {
			  ret->qps=QPSLimiter(boost::lexical_cast<int>(vars["qps"]),boost::lexical_cast<int>(vars["qps"]));
			}

			if(vars.count("pool")) {
			  ret->pools.insert(vars["pool"]);
			}

			if(vars.count("order")) {
			  ret->order=boost::lexical_cast<int>(vars["order"]);
			}

			if(vars.count("weight")) {
			  ret->weight=boost::lexical_cast<int>(vars["weight"]);
			}


			g_dstates.push_back(ret);
			std::stable_sort(g_dstates.begin(), g_dstates.end(), [](const decltype(ret)& a, const decltype(ret)& b) {
			    return a->order < b->order;
			  });
			return ret;
		      } );




  g_lua.writeFunction("rmServer", 
		      [](boost::variant<std::shared_ptr<DownstreamState>, int> var)
		      { 
			if(auto* rem = boost::get<shared_ptr<DownstreamState>>(&var))
			  g_dstates.erase(remove(g_dstates.begin(), g_dstates.end(), *rem), g_dstates.end());
			else
			  g_dstates.erase(g_dstates.begin() + boost::get<int>(var));
		      } );


  g_lua.writeFunction("setServerPolicy", [](ServerPolicy policy)  {
      g_policy=policy;
    });

  g_lua.writeFunction("setServerPolicyLua", [](string name, policy_t policy)  {
      g_policy=ServerPolicy{name, policy};
    });

  g_lua.writeFunction("showServerPolicy", []() {
      g_outputBuffer=g_policy.name+"\n";
    });


  g_lua.registerMember("name", &ServerPolicy::name);
  g_lua.registerMember("policy", &ServerPolicy::policy);
  g_lua.writeFunction("newServerPolicy", [](string name, policy_t policy) { return ServerPolicy{name, policy};});
  g_lua.writeVariable("firstAvailable", ServerPolicy{"firstAvailable", firstAvailable});
  g_lua.writeVariable("roundrobin", ServerPolicy{"roundrobin", roundrobin});
  g_lua.writeVariable("wrandom", ServerPolicy{"wrandom", wrandom});
  g_lua.writeVariable("leastOutstanding", ServerPolicy{"leastOutstanding", leastOutstanding});
  g_lua.writeFunction("addACL", [](const std::string& domain) {
      g_ACL.addMask(domain);
    });
  g_lua.writeFunction("setACL", [](const vector<pair<int, string>>& parts) {
    NetmaskGroup nmg;
    for(const auto& p : parts) {
      nmg.addMask(p.second);
    }
    g_ACL=nmg;
  });
  g_lua.writeFunction("showACL", []() {
      vector<string> vec;
      g_ACL.toStringVector(&vec);
      string ret;
      for(const auto& s : vec)
	ret+=s+"\n";
      return ret;
    });
  g_lua.writeFunction("shutdown", []() { _exit(0);} );


  g_lua.writeFunction("addDomainBlock", [](const std::string& domain) { g_suffixMatchNodeFilter.add(DNSName(domain)); });
  g_lua.writeFunction("showServers", []() {  
      try {
      ostringstream ret;
      
      boost::format fmt("%1$-3d %2% %|30t|%3$5s %|36t|%4$7.1f %|41t|%5$7d %|44t|%6$3d %|53t|%7$2d %|55t|%8$10d %|61t|%9$7d %|76t|%10$5.1f %|84t|%11$5.1f %12%" );
      //             1        2          3       4        5       6       7       8           9        10        11
      ret << (fmt % "#" % "Address" % "State" % "Qps" % "Qlim" % "Ord" % "Wt" % "Queries" % "Drops" % "Drate" % "Lat" % "Pools") << endl;

      uint64_t totQPS{0}, totQueries{0}, totDrops{0};
      int counter=0;
      for(auto& s : g_dstates) {
	string status;
	if(s->availability == DownstreamState::Availability::Up) 
	  status = "UP";
	else if(s->availability == DownstreamState::Availability::Down) 
	  status = "DOWN";
	else 
	  status = (s->upStatus ? "up" : "down");

	string pools;
	for(auto& p : s->pools) {
	  if(!pools.empty())
	    pools+=" ";
	  pools+=p;
	}

	ret << (fmt % counter % s->remote.toStringWithPort() % 
		status % 
		s->queryLoad % s->qps.getRate() % s->order % s->weight % s->queries.load() % s->reuseds.load() % (s->dropRate) % (s->latencyUsec/1000.0) % pools) << endl;

	totQPS += s->queryLoad;
	totQueries += s->queries.load();
	totDrops += s->reuseds.load();
	++counter;
      }
      ret<< (fmt % "All" % "" % "" 
		% 
	     (double)totQPS % "" % "" % "" % totQueries % totDrops % "" % "" % "" ) << endl;

      g_outputBuffer=ret.str();
      }catch(std::exception& e) { g_outputBuffer=e.what(); throw; }
    });

  g_lua.writeFunction("addPoolRule", [](boost::variant<string,vector<pair<int, string>> > var, string pool) {
      SuffixMatchNode smn;
      NetmaskGroup nmg;

      auto add=[&](string src) {
	try {
	  smn.add(DNSName(src));
	} catch(...) {
	  nmg.addMask(src);
	}
      };
      if(auto src = boost::get<string>(&var))
	add(*src);
      else {
	for(auto& a : boost::get<vector<pair<int, string>>>(var)) {
	  add(a.second);
	}
      }
      if(nmg.empty())
	g_poolrules.push_back({smn, pool});
      else
	g_poolrules.push_back({nmg, pool});

    });

  g_lua.writeFunction("showPoolRules", []() {
      boost::format fmt("%-3d %-50s %s\n");
      g_outputBuffer += (fmt % "#" % "Object" % "Pool").str();
      int num=0;
      for(const auto& lim : g_poolrules) {
	string name;
	if(auto nmg=boost::get<NetmaskGroup>(&lim.first)) {
	  name=nmg->toString();
	}
	else if(auto smn=boost::get<SuffixMatchNode>(&lim.first)) {
	  name=smn->toString(); 
	}
	g_outputBuffer += (fmt % num % name % lim.second).str();
	++num;
      }
    });


  g_lua.writeFunction("addQPSLimit", [](boost::variant<string,vector<pair<int, string>> > var, int lim) {
      SuffixMatchNode smn;
      NetmaskGroup nmg;

      auto add=[&](string src) {
	try {
	  smn.add(DNSName(src));
	} catch(...) {
	  nmg.addMask(src);
	}
      };
      if(auto src = boost::get<string>(&var))
	add(*src);
      else {
	for(auto& a : boost::get<vector<pair<int, string>>>(var)) {
	  add(a.second);
	}
      }
      if(nmg.empty())
	g_limiters.push_back({smn, QPSLimiter(lim, lim)});
      else
	g_limiters.push_back({nmg, QPSLimiter(lim, lim)});
    });

  g_lua.writeFunction("rmQPSLimit", [](int i) {
      g_limiters.erase(g_limiters.begin() + i);
    });

  g_lua.writeFunction("showQPSLimits", []() {
      boost::format fmt("%-3d %-50s %7d %8d %8d\n");
      g_outputBuffer += (fmt % "#" % "Object" % "Lim" % "Passed" % "Blocked").str();
      int num=0;
      for(const auto& lim : g_limiters) {
	string name;
	if(auto nmg=boost::get<NetmaskGroup>(&lim.first)) {
	  name=nmg->toString();
	}
	else if(auto smn=boost::get<SuffixMatchNode>(&lim.first)) {
	  name=smn->toString(); 
	}
	g_outputBuffer += (fmt % num % name % lim.second.getRate() % lim.second.getPassed() % lim.second.getBlocked()).str();
	++num;
      }
    });


  g_lua.writeFunction("getServers", []() {
      vector<pair<int, std::shared_ptr<DownstreamState> > > ret;
      int count=1;
      for(auto& s : g_dstates) {
	ret.push_back(make_pair(count++, s));
      }
      return ret;
    });

  g_lua.writeFunction("getServer", [](int i) { return g_dstates[i]; });

  g_lua.registerFunction<bool(DownstreamState::*)()>("checkQPS", [](DownstreamState& s) { return s.qps.check(); });
  g_lua.registerFunction<void(DownstreamState::*)(int)>("setQPS", [](DownstreamState& s, int lim) { s.qps = lim ? QPSLimiter(lim, lim) : QPSLimiter(); });
  g_lua.registerFunction<void(DownstreamState::*)(string)>("addPool", [](DownstreamState& s, string pool) { s.pools.insert(pool);});
  g_lua.registerFunction<void(DownstreamState::*)(string)>("rmPool", [](DownstreamState& s, string pool) { s.pools.erase(pool);});

  g_lua.registerFunction<void(DownstreamState::*)()>("getOutstanding", [](const DownstreamState& s) { g_outputBuffer=std::to_string(s.outstanding.load()); });


  g_lua.registerFunction("isUp", &DownstreamState::isUp);
  g_lua.registerFunction("setDown", &DownstreamState::setDown);
  g_lua.registerFunction("setUp", &DownstreamState::setUp);
  g_lua.registerFunction("setAuto", &DownstreamState::setAuto);
  g_lua.registerMember("upstatus", &DownstreamState::upStatus);
  g_lua.registerMember("weight", &DownstreamState::weight);
  g_lua.registerMember("order", &DownstreamState::order);
  
  g_lua.writeFunction("show", [](const string& arg) {
      g_outputBuffer+=arg;
      g_outputBuffer+="\n";
    });

  g_lua.registerFunction<void(dnsheader::*)(bool)>("setRD", [](dnsheader& dh, bool v) {
      dh.rd=v;
    });

  g_lua.registerFunction<bool(dnsheader::*)()>("getRD", [](dnsheader& dh) {
      return (bool)dh.rd;
    });


  g_lua.registerFunction<void(dnsheader::*)(bool)>("setTC", [](dnsheader& dh, bool v) {
      dh.tc=v;
    });

  g_lua.registerFunction<void(dnsheader::*)(bool)>("setQR", [](dnsheader& dh, bool v) {
      dh.qr=v;
    });

  std::ifstream ifs(g_vm["config"].as<string>());
  if(!ifs) 
    warnlog("Unable to read configuration from '%s'", g_vm["config"].as<string>());
  else
    infolog("Read configuration from '%s'", g_vm["config"].as<string>());

  g_lua.registerFunction("tostring", &ComboAddress::toString);

  g_lua.registerFunction("isPartOf", &DNSName::isPartOf);
  g_lua.registerFunction("tostring", &DNSName::toString);
  g_lua.writeFunction("newDNSName", [](const std::string& name) { return DNSName(name); });
  g_lua.writeFunction("newSuffixNode", []() { return SuffixMatchNode(); });

  g_lua.registerFunction("add",(void (SuffixMatchNode::*)(const DNSName&)) &SuffixMatchNode::add);
  g_lua.registerFunction("check",(bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);

  g_lua.writeFunction("controlSocket", [client](const std::string& str) {
      ComboAddress local(str, 5199);

      if(client) {
	g_serverControl = local;
	return;
      }
      
      try {
	int sock = socket(local.sin4.sin_family, SOCK_STREAM, 0);
	SSetsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
	SBind(sock, local);
	SListen(sock, 5);
	thread t(controlThread, sock, local);
	t.detach();
      }
      catch(std::exception& e) {
	errlog("Unable to bind to control socket on %s: %s", local.toStringWithPort(), e.what());
      }
    });

  g_lua.writeFunction("getTopQueries", [](unsigned int top, boost::optional<int> labels) {
      map<DNSName, int> counts;
      unsigned int total=0;
      if(!labels) {
	for(const auto& a : g_rings.queryRing) {
	  counts[a]++;
	  total++;
	}
      }
      else {
	unsigned int lab = *labels;
	for(auto a : g_rings.queryRing) {
	  a.trimToLabels(lab);
	  counts[a]++;
	  total++;
	}

      }
      cout<<"Looked at "<<total<<" queries, "<<counts.size()<<" different ones"<<endl;
      vector<pair<int, DNSName>> rcounts;
      for(const auto& c : counts) 
	rcounts.push_back(make_pair(c.second, c.first));

      sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a, 
					      const decltype(rcounts)::value_type& b) {
	     return b.first < a.first;
	   });

      std::unordered_map<int, vector<boost::variant<string,double>>> ret;
      unsigned int count=1, rest=0;
      for(const auto& rc : rcounts) {
	if(count==top+1)
	  rest+=rc.first;
	else
	  ret.insert({count++, {rc.second.toString(), rc.first, 100.0*rc.first/total}});
      }
      ret.insert({count, {"Rest", rest, 100.0*rest/total}});
      return ret;

    });
  
  g_lua.executeCode(R"(function topQueries(top, labels) for k,v in ipairs(getTopQueries(top,labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2], v[3])) end end)");

  g_lua.writeFunction("getTopResponses", [](unsigned int top, unsigned int kind, boost::optional<int> labels) {
      map<DNSName, int> counts;
      unsigned int total=0;
      {
	std::lock_guard<std::mutex> lock(g_rings.respMutex);
	if(!labels) {
	  for(const auto& a : g_rings.respRing) {
	    if(a.rcode!=kind)
	      continue;
	    counts[a.name]++;
	    total++;
	  }
	}
	else {
	  unsigned int lab = *labels;
	  for(auto a : g_rings.respRing) {
	    if(a.rcode!=kind)
	      continue;

	    a.name.trimToLabels(lab);
	    counts[a.name]++;
	    total++;
	  }
	  
	}
      }
      //      cout<<"Looked at "<<total<<" responses, "<<counts.size()<<" different ones"<<endl;
      vector<pair<int, DNSName>> rcounts;
      for(const auto& c : counts) 
	rcounts.push_back(make_pair(c.second, c.first));

      sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a, 
					      const decltype(rcounts)::value_type& b) {
	     return b.first < a.first;
	   });

      std::unordered_map<int, vector<boost::variant<string,double>>> ret;
      unsigned int count=1, rest=0;
      for(const auto& rc : rcounts) {
	if(count==top+1)
	  rest+=rc.first;
	else
	  ret.insert({count++, {rc.second.toString(), rc.first, 100.0*rc.first/total}});
      }
      ret.insert({count, {"Rest", rest, 100.0*rest/total}});
      return ret;

    });
  
  g_lua.executeCode(R"(function topResponses(top, kind, labels) for k,v in ipairs(getTopResponses(top, kind, labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2], v[3])) end end)");


  g_lua.writeFunction("showResponseLatency", []() {

      map<double, unsigned int> histo;
      double bin=100;
      for(int i=0; i < 15; ++i) {
	histo[bin];
	bin*=2;
      }

      double totlat=0;
      int size=0;
      {
	std::lock_guard<std::mutex> lock(g_rings.respMutex);
	for(const auto& r : g_rings.respRing) {
	  ++size;
	  auto iter = histo.lower_bound(r.usec);
	  if(iter != histo.end())
	    iter->second++;
	  else
	    histo.rbegin()++;
	  totlat+=r.usec;
	}
      }

      g_outputBuffer = (boost::format("Average response latency: %.02f msec\n") % (0.001*totlat/size)).str();
      double highest=0;
      
      for(auto iter = histo.cbegin(); iter != histo.cend(); ++iter) {
	highest=std::max(highest, iter->second*1.0);
      }
      boost::format fmt("%7.2f\t%s\n");
      g_outputBuffer += (fmt % "msec" % "").str();

      for(auto iter = histo.cbegin(); iter != histo.cend(); ++iter) {
	int stars = (70.0 * iter->second/highest);
	char c='*';
	if(!stars && iter->second) {
	  stars=1; // you get 1 . to show something is there..
	  if(70.0*iter->second/highest > 0.5)
	    c=':';
	  else
	    c='.';
	}
	g_outputBuffer += (fmt % (iter->first/1000.0) % string(stars, c)).str();
      }
    });

  g_lua.writeFunction("newQPSLimiter", [](int rate, int burst) { return QPSLimiter(rate, burst); });
  g_lua.registerFunction("check", &QPSLimiter::check);


  g_lua.writeFunction("makeKey", []() {
      g_outputBuffer="setKey("+newKey()+")\n";
    });
  
  g_lua.writeFunction("setKey", [](const std::string& key) {
      if(B64Decode(key, g_key)) 
	throw std::runtime_error("Unable to decode "+key+" as Base64");
    });

  
  g_lua.writeFunction("testCrypto", [](string testmsg)
   {
     SodiumNonce sn, sn2;
     sn.init();
     sn2=sn;
     string encrypted = sodEncryptSym(testmsg, g_key, sn);
     string decrypted = sodDecryptSym(encrypted, g_key, sn2);
     
     if(testmsg == decrypted)
       cerr<<"Everything is ok!"<<endl;
     else
       cerr<<"Crypto failed.."<<endl;
     
   });

  

  g_lua.executeCode(ifs);
}


void doClient(ComboAddress server)
{
  cout<<"Connecting to "<<server.toStringWithPort()<<endl;
  int fd=socket(server.sin4.sin_family, SOCK_STREAM, 0);
  SConnect(fd, server);

  SodiumNonce theirs, ours;
  ours.init();

  writen2(fd, (const char*)ours.value, sizeof(ours.value));
  readn2(fd, (char*)theirs.value, sizeof(theirs.value));

  set<string> dupper;
  {
    ifstream history(".history");
    string line;
    while(getline(history, line))
      add_history(line.c_str());
  }
  ofstream history(".history", std::ios_base::app);
  string lastline;
  for(;;) {
    char* sline = readline("> ");
    if(!sline)
      break;

    string line(sline);
    if(!line.empty() && line != lastline) {
      add_history(sline);
      history << sline <<endl;
      history.flush();
    }
    lastline=line;
    free(sline);
    
    if(line=="quit")
      break;

    string response;
    string msg=sodEncryptSym(line, g_key, ours);
    putMsgLen(fd, msg.length());
    writen2(fd, msg);
    uint16_t len;
    getMsgLen(fd, &len);
    char resp[len];
    readn2(fd, resp, len);
    msg.assign(resp, len);
    msg=sodDecryptSym(msg, g_key, theirs);
    cout<<msg<<endl;
  }
}

void doConsole()
{
  set<string> dupper;
  {
    ifstream history(".history");
    string line;
    while(getline(history, line))
      add_history(line.c_str());
  }
  ofstream history(".history", std::ios_base::app);
  string lastline;
  for(;;) {
    char* sline = readline("> ");
    if(!sline)
      break;

    string line(sline);
    if(!line.empty() && line != lastline) {
      add_history(sline);
      history << sline <<endl;
      history.flush();
    }
    lastline=line;
    free(sline);
    
    if(line=="quit")
      break;

    string response;
    try {
      std::lock_guard<std::mutex> lock(g_luamutex);
      g_outputBuffer.clear();
      auto ret=g_lua.executeCode<
	boost::optional<
	  boost::variant<
	    string, 
	    shared_ptr<DownstreamState>
	    >
	  >
	>(line);

      if(ret) {
	if (const auto strValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
	  cout<<(*strValue)->remote.toStringWithPort()<<endl;
	}
	else if (const auto strValue = boost::get<string>(&*ret)) {
	  cout<<*strValue<<endl;
	}
      }
      else 
	cout << g_outputBuffer;

    }
    catch(std::exception& e) {
      cerr<<"Error: "<<e.what()<<endl;
    }   
  }
}

int main(int argc, char** argv)
try
{
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  openlog("dnsdist", LOG_PID, LOG_DAEMON);
  g_console=true;

  if (sodium_init() == -1) {
    cerr<<"Unable to initialize crypto library"<<endl;
    exit(EXIT_FAILURE);
  }

  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("config", po::value<string>()->default_value("/etc/dnsdist.conf"), "Filename with our configuration")
    ("client", "be a client")
    ("daemon", po::value<bool>()->default_value(true), "run in background")
    ("local", po::value<vector<string> >(), "Listen on which addresses")
    ("max-outstanding", po::value<uint16_t>()->default_value(65535), "maximum outstanding queries per downstream")
    ("regex-drop", po::value<string>(), "If set, block queries matching this regex. Mind trailing dot!")
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

  ServerPolicy leastOutstandingPol{"leastOutstanding", leastOutstanding};

  g_policy = leastOutstandingPol;


  if(g_vm.count("client")) {
    setupLua(true);
    doClient(g_serverControl);
    exit(EXIT_SUCCESS);
  }
  if(g_vm["daemon"].as<bool>())  {
    g_console=false;
    daemonize();
  }
  else {
    vinfolog("Running in the foreground");
  }

  for(auto& addr : {"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})
    g_ACL.addMask(addr);

  setupLua(false);
  if(g_vm.count("remotes")) {
    for(const auto& address : g_vm["remotes"].as<vector<string>>()) {
      auto ret=std::make_shared<DownstreamState>(ComboAddress(address, 53));
      ret->tid = move(thread(responderThread, ret));
      g_dstates.push_back(ret);
    }
  }

  for(auto& dss : g_dstates) {
    if(dss->availability==DownstreamState::Availability::Auto) {
      bool newState=upCheck(dss->remote);
      warnlog("Marking downstream %s as '%s'", dss->remote.toStringWithPort(), newState ? "up" : "down");
      dss->upStatus = newState;
    }
  }

  vector<string> locals;
  if(g_vm.count("local"))
    locals = g_vm["local"].as<vector<string> >();
  else
    locals.push_back("::");

  for(const string& local : locals) {
    ClientState* cs = new ClientState;
    cs->local= ComboAddress(local, 53);
    cs->udpFD = SSocket(cs->local.sin4.sin_family, SOCK_DGRAM, 0);
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    SBind(cs->udpFD, cs->local);    

    thread t1(udpClientThread, cs);
    t1.detach();
  }

  for(const string& local : locals) {
    ClientState* cs = new ClientState;
    cs->local= ComboAddress(local, 53);

    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);

    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(cs->tcpFD, SOL_TCP,TCP_DEFER_ACCEPT, 1);
#endif
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->tcpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }

    SBind(cs->tcpFD, cs->local);
    SListen(cs->tcpFD, 64);
    warnlog("Listening on %s",cs->local.toStringWithPort());
    
    thread t1(tcpAcceptorThread, cs);
    t1.detach();
  }

  thread stattid(maintThread);
  
  if(!g_vm["daemon"].as<bool>())  {
    stattid.detach();
    doConsole();
  }
  else {
    stattid.join();
  }
  _exit(EXIT_SUCCESS);

}
catch(std::exception &e)
{
  errlog("Fatal error: %s", e.what());
}
catch(PDNSException &ae)
{
  errlog("Fatal pdns error: %s", ae.reason);
}
