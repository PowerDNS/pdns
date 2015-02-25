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
#include "sstuff.hh"
#include "misc.hh"
#include <mutex>
#include "statbag.hh"
#include <netinet/tcp.h>
#include <boost/program_options.hpp>
#include <boost/foreach.hpp>
#include <thread>
#include <limits>
#include <atomic>
#include "arguments.hh"
#include "dolog.hh"
#include <readline/readline.h>
#include <readline/history.h>
#include "dnsname.hh"
#include "dnswriter.hh"
#include <fstream>

#undef L


/* syntax: dnsdist 8.8.8.8 8.8.4.4 208.67.222.222 208.67.220.220
   Added downstream server 8.8.8.8:53
   Added downstream server 8.8.4.4:53
   Added downstream server 208.67.222.222:53
   Added downstream server 208.67.220.220:53
   Listening on [::]:53

   And you are in business!
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

  bool check()
  {
    if(d_passthrough)
      return true;
    d_tokens += 1.0*d_rate * (d_prev.udiffAndSet()/1000000.0);

    if(d_tokens > d_burst)
      d_tokens = d_burst;

    bool ret=false;
    if(d_tokens >= 1.0) { // we need this because burst=1 is weird otherwise
      ret=true;
      --d_tokens;
    }
    return ret; 
  }
private:
  bool d_passthrough{true};
  unsigned int d_rate;
  unsigned int d_burst;
  double d_tokens;
  StopWatch d_prev;
};

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
  atomic<uint64_t> age;
};


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
  StopWatch sw;
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

std::function<shared_ptr<DownstreamState>(const ComboAddress& remote, const DNSName& qname, uint16_t qtype)> g_policy;

shared_ptr<DownstreamState> getLuaDownstream(const ComboAddress& remote, const DNSName& qname, uint16_t qtype)
{
  //auto pickServer=g_lua.readVariable<LuaContext::LuaFunctionCaller<std::shared_ptr<DownstreamState> (void)> >("pickServer");

  std::lock_guard<std::mutex> lock(g_luamutex);

  auto pickServer=g_lua.readVariable<std::function<std::shared_ptr<DownstreamState>(ComboAddress, DNSName, uint16_t)> >("pickServer");
  return pickServer(remote, DNSName(qname), qtype);
}

shared_ptr<DownstreamState> firstAvailable(const ComboAddress& remote, const DNSName& qname, uint16_t qtype)
{
  for(auto& d : g_dstates) {
    if(d->isUp() && d->qps.check())
      return d;
  }
  static int counter=0;
  ++counter;
  return g_dstates[counter % g_dstates.size()];
}

#if 0
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
#endif

SuffixMatchNode g_abuseSMN;
NetmaskGroup g_abuseNMG;
shared_ptr<DownstreamState> g_abuseDSS;

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

  typedef std::function<bool(ComboAddress, DNSName, uint16_t)> blockfilter_t;
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

    DNSName qname(packet, len, 12, false, &qtype);
    if(blockFilter)
    {
      std::lock_guard<std::mutex> lock(g_luamutex);
      if(blockFilter(remote, qname, qtype))
	continue;
    }

    if(re && re->match(qname.toString())) {
      g_regexBlocks++;
      continue;
    }
   
    DownstreamState* ss = 0;
    if(g_abuseSMN.check(qname) || g_abuseNMG.match(remote)) {
      ss = &*g_abuseDSS;
    }
    else
      ss = g_policy(remote, qname, qtype).get();
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

    dh->id = idOffset;
    
    len = send(ss->fd, packet, len, 0);
    if(len < 0) 
      ss->sendErrors++;

    vinfolog("Got query from %s, relayed to %s", remote.toStringWithPort(), ss->remote.toStringWithPort());
    }
    catch(...){}
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

int getTCPDownstream(DownstreamState** ds, const ComboAddress& remote, const std::string& qname, uint16_t qtype)
{
  *ds = g_policy(remote, qname, qtype).get();
  
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
    ComboAddress fixme;
    readn2(pipefd, &citmp, sizeof(citmp));
    --g_tcpclientthreads.d_queued;
    ci=*citmp;
    delete citmp;
     
    if(dsock == -1) {

      dsock = getTCPDownstream(&ds, fixme, "", 0);
    }
    else {
      vinfolog("Reusing existing TCP connection to %s", ds->remote.toStringWithPort());
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
	  vinfolog("Downstream connection to %s died on us, getting a new one!", ds->remote.toStringWithPort());
          close(dsock);
          dsock=getTCPDownstream(&ds, fixme, "", 0);
          goto retry;
        }
      
        writen2(dsock, query, qlen);
      
        if(!getMsgLen(dsock, &rlen)) {
	  vinfolog("Downstream connection to %s died on us phase 2, getting a new one!", ds->remote.toStringWithPort());
          close(dsock);
          dsock=getTCPDownstream(&ds, fixme, "", 0);
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
        }          
      }
    }
  }
  return 0;
}



void setupLua()
{
  g_lua.writeFunction("newServer", 
		      [](const std::string& address, boost::optional<int> qps)
		      { 
			auto ret=std::shared_ptr<DownstreamState>(new DownstreamState(ComboAddress(address, 53)));
			ret->tid = move(thread(responderThread, ret));
			if(qps) {
			  ret->qps=QPSLimiter(*qps, *qps);
			}
			g_dstates.push_back(ret);
			return ret;
		      } );

  g_lua.writeFunction("newServer2", 
		      [](std::unordered_map<std::string, std::string> vars)
		      { 
			auto ret=std::shared_ptr<DownstreamState>(new DownstreamState(ComboAddress(vars["address"], 53)));

			ret->tid = move(thread(responderThread, ret));

			if(vars.count("qps")) {
			  ret->qps=QPSLimiter(boost::lexical_cast<int>(vars["qps"]),boost::lexical_cast<int>(vars["qps"]));
			}

			if(vars.count("order")) {
			  ret->order=boost::lexical_cast<int>(vars["order"]);
			}

			g_dstates.push_back(ret);
			std::stable_sort(g_dstates.begin(), g_dstates.end(), [](const decltype(ret)& a, const decltype(ret)& b) {
			    return a->order < b->order;
			  });
			return ret;
		       

		      } );


  g_lua.writeFunction("deleteServer", 
		      [](std::shared_ptr<DownstreamState> rem)
		      { 
			g_dstates.erase(remove(g_dstates.begin(), g_dstates.end(), rem), g_dstates.end());
		      } );


  g_lua.writeFunction("setServerPolicy", [](std::function<shared_ptr<DownstreamState>(const ComboAddress&, const DNSName&, uint16_t)> func) {
      g_policy = func;
    });

  g_lua.writeFunction("unsetServerPolicy", []() {
      g_policy = firstAvailable;
    });

  g_lua.writeFunction("listServers", []() {  
      try {
      string ret;
      
      boost::format fmt("%1$-3d %2% %|30t|%3$5s %|36t|%4$7.1f %|41t|%5$7d %|48t|%6$10d %|59t|%7$7d %|69t|%8$2.1f %|78t|%9$5.1f" );

      cout << (fmt % "#" % "Address" % "State" % "Qps" % "Qlim" % "Queries" % "Drops" % "Drate" % "Lat") << endl;

      uint64_t totQPS{0}, totQueries{0}, totDrops{0};
      int counter=0;
      for(auto& s : g_dstates) {
	if(!ret.empty()) ret+="\n";
	ret+=s->remote.toStringWithPort() + " " + std::to_string(s->queries.load()) + " " + std::to_string(s->outstanding.load());

	string status;
	if(s->availability == DownstreamState::Availability::Up) 
	  status = "UP";
	else if(s->availability == DownstreamState::Availability::Down) 
	  status = "DOWN";
	else 
	  status = (s->upStatus ? "up" : "down");

	cout<< (fmt % counter % s->remote.toStringWithPort() % 
		status % 
		s->queryLoad % s->qps.getRate() % s->queries.load() % s->reuseds.load() % (s->dropRate) % (s->latencyUsec/1000.0)) << endl;

	totQPS += s->queryLoad;
	totQueries += s->queries.load();
	totDrops += s->reuseds.load();
	++counter;
      }
      cout<< (fmt % "All" % "" % "" 
		% 
	      (double)totQPS % "" % totQueries % totDrops % "" % "") << endl;

      return ret;
      }catch(std::exception& e) { cerr<<e.what()<<endl; throw; }
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

  g_lua.registerFunction<string(DownstreamState::*)()>("tostring", [](const DownstreamState& s) { return s.remote.toStringWithPort(); });
  g_lua.registerFunction<bool(DownstreamState::*)()>("checkQPS", [](DownstreamState& s) { return s.qps.check(); });
  g_lua.registerFunction<void(DownstreamState::*)(int)>("setQPS", [](DownstreamState& s, int lim) { s.qps = lim ? QPSLimiter(lim, lim) : QPSLimiter(); });
  g_lua.registerFunction("isUp", &DownstreamState::isUp);
  g_lua.registerFunction("setDown", &DownstreamState::setDown);
  g_lua.registerFunction("setUp", &DownstreamState::setUp);
  g_lua.registerFunction("setAuto", &DownstreamState::setAuto);
  g_lua.registerMember("upstatus", &DownstreamState::upStatus);

  std::ifstream ifs(g_vm["config"].as<string>());

  g_lua.registerFunction("tostring", &ComboAddress::toString);

  g_lua.registerFunction("isPartOf", &DNSName::isPartOf);
  g_lua.registerFunction("tostring", &DNSName::toString);
  g_lua.writeFunction("newDNSName", [](const std::string& name) { return DNSName(name); });
  g_lua.writeFunction("newSuffixNode", []() { return SuffixMatchNode(); });



  g_lua.registerFunction("add",(void (SuffixMatchNode::*)(const DNSName&)) &SuffixMatchNode::add);
  g_lua.registerFunction("check",(bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);



  g_lua.writeFunction("newQPSLimiter", [](int rate, int burst) { return QPSLimiter(rate, burst); });
  g_lua.registerFunction("check", &QPSLimiter::check);

  g_lua.writeFunction("usleep", [](int usec) { usleep(usec); });

  g_lua.writeFunction("abuseShuntSMN", [](const std::string& name) {
      g_abuseSMN.add(DNSName(name));
    });

  g_lua.writeFunction("abuseShuntNM", [](const std::string& str) {
      g_abuseNMG.addMask(str);
    });

  g_lua.writeFunction("abuseServer", [](shared_ptr<DownstreamState> dss) {
      g_abuseDSS=dss;
    });

  g_lua.executeCode(ifs);
}


int main(int argc, char** argv)
try
{
  signal(SIGPIPE, SIG_IGN);
  openlog("dnsdist", LOG_PID, LOG_DAEMON);
  g_console=true;
  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("config", po::value<string>()->default_value("dnsdistconf.lua"), "Filename with our configuration")
    //    ("daemon", po::value<bool>()->default_value(true), "run in background")
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

  g_policy = firstAvailable;
  setupLua();

  if(g_vm.count("remotes")) {
    for(const auto& address : g_vm["remotes"].as<vector<string>>()) {
      auto ret=std::shared_ptr<DownstreamState>(new DownstreamState(ComboAddress(address, 53)));
      ret->tid = move(thread(responderThread, ret));
      g_dstates.push_back(ret);
    }
  }

  /*
  if(g_vm["daemon"].as<bool>())  {
    g_console=false;
    daemonize();
  }
  else {
    vinfolog("Running in the foreground");
  }
  */

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
  stattid.detach();

  set<string> dupper;
  {
    ifstream history(".history");
    string line;
    while(getline(history, line))
      add_history(line.c_str());
  }
  ofstream history(".history");
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

    try {
      std::lock_guard<std::mutex> lock(g_luamutex);
      g_lua.executeCode(line);
    }
    catch(std::exception& e) {
      cerr<<"Error: "<<e.what()<<endl;
    }
    
  }

  // stattid.join();
}

catch(std::exception &e)
{
  errlog("Fatal: %s", e.what());
}

catch(PDNSException &ae)
{
  errlog("Fatal: %s", ae.reason);
}
