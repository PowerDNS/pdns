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
#include "sstuff.hh"
#include "misc.hh"
#include <netinet/tcp.h>
#include <limits>
#include "dolog.hh"
#include <readline/readline.h>
#include <readline/history.h>
#include "dnsname.hh"
#include "dnswriter.hh"
#include "base64.hh"
#include <fstream>
#include "sodcrypto.hh"
#include "dnsrulactions.hh"
#undef L

/* Known sins:
   No centralized statistics
   Receiver is currently singlethreaded
      not *that* bad actually, but now that we are thread safe, might want to scale
   TCP is a bit wonky and may pick the wrong downstream
   ringbuffers are on a wing & a prayer because partially unlocked
*/

/* the Rulaction plan
   Set of Rules, if one matches, it leads to an Action
   Both rules and actions could conceivably be Lua based. 
   On the C++ side, both could be inherited from a class Rule and a class Action, 
   on the Lua side we can't do that. */

namespace po = boost::program_options;
po::variables_map g_vm;
using std::atomic;
using std::thread;
bool g_verbose;
atomic<uint64_t> g_pos;

uint16_t g_maxOutstanding;
bool g_console;

GlobalStateHolder<NetmaskGroup> g_ACL;
string g_outputBuffer;
vector<ComboAddress> g_locals;

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

GlobalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSAction> > > > g_rulactions;
Rings g_rings;

GlobalStateHolder<servers_t> g_dstates;

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
    
    if(ids->origDest.sin4.sin_family == 0)
      sendto(ids->origFD, packet, len, 0, (struct sockaddr*)&ids->origRemote, ids->origRemote.getSocklen());
    else
      sendfromto(ids->origFD, packet, len, 0, ids->origDest, ids->origRemote);
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


GlobalStateHolder<ServerPolicy> g_policy;

shared_ptr<DownstreamState> firstAvailable(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  for(auto& d : servers) {
    if(d.second->isUp() && d.second->qps.check())
      return d.second;
  }
  return leastOutstanding(servers, remote, qname, qtype, dh);
}

shared_ptr<DownstreamState> leastOutstanding(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  vector<pair<pair<int,int>, shared_ptr<DownstreamState>>> poss;
  poss.reserve(servers.size());
  for(auto& d : servers) {    
    if(d.second->isUp()) {
      poss.push_back({make_pair(d.second->outstanding.load(), d.second->order), d.second});
    }
  }
  if(poss.empty())
    return shared_ptr<DownstreamState>();
  nth_element(poss.begin(), poss.begin(), poss.end(), [](const decltype(poss)::value_type& a, const decltype(poss)::value_type& b) { return a.first < b.first; });
  return poss.begin()->second;
}

shared_ptr<DownstreamState> wrandom(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  vector<pair<int, shared_ptr<DownstreamState>>> poss;
  int sum=0;
  for(auto& d : servers) {      // w=1, w=10 -> 1, 11
    if(d.second->isUp()) {
      sum+=d.second->weight;
      poss.push_back({sum, d.second});

    }
  }
  int r = random() % sum;
  auto p = upper_bound(poss.begin(), poss.end(),r, [](int r, const decltype(poss)::value_type& a) { return  r < a.first;});
  if(p==poss.end())
    return shared_ptr<DownstreamState>();
  return p->second;
}

shared_ptr<DownstreamState> roundrobin(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  NumberedServerVector poss;

  for(auto& d : servers) {
    if(d.second->isUp()) {
      poss.push_back(d);
    }
  }

  const auto *res=&poss;
  if(poss.empty())
    res = &servers;

  if(res->empty())
    return shared_ptr<DownstreamState>();

  static unsigned int counter;
 
  return (*res)[(counter++) % res->size()].second;
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

ComboAddress g_serverControl{"127.0.0.1:5199"};


NumberedServerVector getDownstreamCandidates(const servers_t& servers, const std::string& pool)
{
  NumberedServerVector ret;
  int count=0;
  for(const auto& s : servers) 
    if((pool.empty() && s->pools.empty()) || s->pools.count(pool))
      ret.push_back(make_pair(++count, s));
  
  return ret;
}



// listens to incoming queries, sends out to downstream servers, noting the intended return path 
void* udpClientThread(ClientState* cs)
try
{
  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;
  char packet[1500];
  struct dnsheader* dh = (struct dnsheader*) packet;
  int len;

  string qname;
  uint16_t qtype;

  typedef std::function<bool(ComboAddress, DNSName, uint16_t, dnsheader*)> blockfilter_t;
  blockfilter_t blockFilter = 0;

  
  {
    std::lock_guard<std::mutex> lock(g_luamutex);
    auto candidate = g_lua.readVariable<boost::optional<blockfilter_t> >("blockFilter");
    if(candidate)
      blockFilter = *candidate;
  }
  auto acl = g_ACL.getLocal();
  auto localPolicy = g_policy.getLocal();

  auto localRulactions = g_rulactions.getLocal();
  auto localServers = g_dstates.getLocal();
  struct msghdr msgh;
  struct iovec iov;
  char cbuf[256];

  remote.sin6.sin6_family=cs->local.sin6.sin6_family;
  fillMSGHdr(&msgh, &iov, cbuf, sizeof(cbuf), packet, sizeof(packet), &remote);

  for(;;) {
    try {
      len = recvmsg(cs->udpFD, &msgh, 0);
      g_rings.clientRing.push_back(remote);
      if(len < (int)sizeof(struct dnsheader)) 
	continue;

      if(!acl->match(remote))
	continue;
      
      if(dh->qr)    // don't respond to responses
	continue;
      
      
      DNSName qname(packet, len, 12, false, &qtype);

      g_rings.queryRing.push_back(qname);
            
      if(blockFilter) {
	std::lock_guard<std::mutex> lock(g_luamutex);
	
	if(blockFilter(remote, qname, qtype, dh))
	  continue;
      }
      

      DNSAction::Action action=DNSAction::Action::None;
      string ruleresult;
      string pool;
      for(const auto& lr : *localRulactions) {
	if(lr.first->matches(remote, qname, qtype, dh)) {
	  lr.first->d_matches++;
	  action=(*lr.second)(remote, qname, qtype, dh, &ruleresult);
	  if(action != DNSAction::Action::None)
	    break;
	}
      }
      switch(action) {
      case DNSAction::Action::Drop:
	continue;
      case DNSAction::Action::Nxdomain:
	dh->rcode = RCode::NXDomain;
	dh->qr=true;
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
	break;
      }

      if(dh->qr) { // something turned it into a response
	ComboAddress dest;
	if(HarvestDestinationAddress(&msgh, &dest)) 
	  sendfromto(cs->udpFD, packet, len, 0, dest, remote);
	else
	  sendto(cs->udpFD, packet, len, 0, (struct sockaddr*)&remote, remote.getSocklen());

	continue;
      }

      DownstreamState* ss = 0;
      auto candidates=getDownstreamCandidates(*localServers, pool);
      auto policy=localPolicy->policy;
      {
	std::lock_guard<std::mutex> lock(g_luamutex);
	ss = policy(candidates, remote, qname, qtype, dh).get();
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
      ids->origDest.sin4.sin_family=0;
      HarvestDestinationAddress(&msgh, &ids->origDest);
      
      dh->id = idOffset;
      
      len = send(ss->fd, packet, len, 0);
      if(len < 0) 
	ss->sendErrors++;
      
      vinfolog("Got query from %s, relayed to %s", remote.toStringWithPort(), ss->remote.toStringWithPort());
    }
    catch(std::exception& e){
      errlog("Got an error in UDP question thread: %s", e.what());
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

    for(auto& dss : g_dstates.getCopy()) { // this points to the actual shared_ptrs!
      if(dss->availability==DownstreamState::Availability::Auto) {
	bool newState=upCheck(dss->remote);
	if(newState != dss->upStatus) {
	  warnlog("Marking downstream %s as '%s'", dss->remote.toStringWithPort(), newState ? "up" : "down");
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
    catch(const LuaContext::ExecutionErrorException& e) {
      response = "Error: " + string(e.what()) + ": ";
      try {
        std::rethrow_if_nested(e);
      } catch(const std::exception& e) {
        // e is the exception that was thrown from inside the lambda
        response+= string(e.what());
      }
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



void doClient(ComboAddress server)
{
  cout<<"Connecting to "<<server.toStringWithPort()<<endl;
  int fd=socket(server.sin4.sin_family, SOCK_STREAM, 0);
  SConnect(fd, server);

  SodiumNonce theirs, ours;
  ours.init();

  writen2(fd, (const char*)ours.value, sizeof(ours.value));
  readn2(fd, (char*)theirs.value, sizeof(theirs.value));

  if(g_vm.count("command")) {
    auto command = g_vm["command"].as<string>();
    string response;
    string msg=sodEncryptSym(command, g_key, ours);
    putMsgLen(fd, msg.length());
    writen2(fd, msg);
    uint16_t len;
    getMsgLen(fd, &len);
    char resp[len];
    readn2(fd, resp, len);
    msg.assign(resp, len);
    msg=sodDecryptSym(msg, g_key, theirs);
    cout<<msg<<endl;
    return; 
  }

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
    rl_bind_key('\t',rl_complete);
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
    rl_bind_key('\t',rl_complete);
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
    catch(const LuaContext::ExecutionErrorException& e) {
      std::cerr << e.what() << ": ";
      try {
        std::rethrow_if_nested(e);
      } catch(const std::exception& e) {
        // e is the exception that was thrown from inside the lambda
        std::cerr << e.what() << std::endl;      
      }
    }
    catch(const std::exception& e) {
      // e is the exception that was thrown from inside the lambda
      std::cerr << e.what() << std::endl;      
    }
  }
}

static void bindAny(int af, int sock)
{
  int one = 1;

#ifdef IP_FREEBIND
  if (setsockopt(sock, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) < 0)
    warnlog("Warning: IP_FREEBIND setsockopt failed: %s", strerror(errno));
#endif

#ifdef IP_BINDANY
  if (af == AF_INET)
    if (setsockopt(sock, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) < 0)
      warnlog("Warning: IP_BINDANY setsockopt failed: %s", strerror(errno));
#endif
#ifdef IPV6_BINDANY
  if (af == AF_INET6)
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) < 0)
      warnlog("Warning: IPV6_BINDANY setsockopt failed: %s", strerror(errno));
#endif
#ifdef SO_BINDANY
  if (setsockopt(sock, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) < 0)
    warnlog("Warning: SO_BINDANY setsockopt failed: %s", strerror(errno));
#endif
}

/**** CARGO CULT CODE AHEAD ****/
extern "C" {
char* my_generator(const char* text, int state)
{
  string t(text);
  vector<string> words{"showRules()", "shutdown()", "rmRule(", "mvRule(", "addACL(", "addLocal(", "setServerPolicy(", "setServerPolicyLua(",
      "newServer(", "rmServer(", "showServers()", "show(", "newDNSName(", "newSuffixMatchNode(", "controlSocket(", "topClients(", "showResponseLatency()", 
      "newQPSLimiter(", "makeKey()", "setKey(", "testCrypto()", "addAnyTCRule()", "showServerPolicy()", "setACL(", "showACL()", "addDomainBlock(", 
      "addPoolRule(", "addQPSLimit(", "topResponses(", "topQueries("};
  static int s_counter=0;
  int counter=0;
  if(!state)
    s_counter=0;

  for(auto w : words) {
    if(boost::starts_with(w, t) && counter++ == s_counter)  {
      s_counter++;
      return strdup(w.c_str());
    }
  }
  return 0;
}

static char** my_completion( const char * text , int start,  int end)
{
  char **matches=0;
  if (start == 0)
    matches = rl_completion_matches ((char*)text, &my_generator);
  else
    rl_bind_key('\t',rl_abort);
 
  if(!matches)
    rl_bind_key('\t', rl_abort);
  return matches;
}
}

int main(int argc, char** argv)
try
{
  rl_attempted_completion_function = my_completion;
  rl_completion_append_character = 0;

  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  openlog("dnsdist", LOG_PID, LOG_DAEMON);
  g_console=true;

#ifdef HAVE_LIBSODIUM
  if (sodium_init() == -1) {
    cerr<<"Unable to initialize crypto library"<<endl;
    exit(EXIT_FAILURE);
  }
#endif

  po::options_description desc("Allowed options"), hidden, alloptions;
  desc.add_options()
    ("help,h", "produce help message")
    ("bind-non-local", "allow binding to non-local addresses")
    ("config", po::value<string>()->default_value("/etc/dnsdist.conf"), "Filename with our configuration")
    ("client", "be a client")
    ("command,c", po::value<string>(), "Execute this command on a running dnsdist")
    ("daemon", po::value<bool>()->default_value(true), "run in background")
    ("local", po::value<vector<string> >(), "Listen on which addresses")
    ("max-outstanding", po::value<uint16_t>()->default_value(1024), "maximum outstanding queries per downstream")
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

  g_policy.setState(leastOutstandingPol);
  if(g_vm.count("client") || g_vm.count("command")) {
    setupLua(true);
    doClient(g_serverControl);
    exit(EXIT_SUCCESS);
  }

  auto todo=setupLua(false);

  if(g_vm.count("local")) {
    g_locals.clear();
    for(auto loc : g_vm["local"].as<vector<string> >())
      g_locals.push_back(ComboAddress(loc, 53));
  }
  
  if(g_locals.empty())
    g_locals.push_back(ComboAddress("0.0.0.0", 53));
  

  vector<ClientState*> toLaunch;
  for(const auto& local : g_locals) {
    ClientState* cs = new ClientState;
    cs->local= local;
    cs->udpFD = SSocket(cs->local.sin4.sin_family, SOCK_DGRAM, 0);
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    if(g_vm.count("bind-non-local"))
      bindAny(local.sin4.sin_family, cs->udpFD);

    //    setSocketTimestamps(cs->udpFD);

    if(IsAnyAddress(local)) {
      int one=1;
      setsockopt(cs->udpFD, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one));     // linux supports this, so why not - might fail on other systems
      setsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)); 
    }

    SBind(cs->udpFD, cs->local);    
    toLaunch.push_back(cs);
  }

  if(g_vm["daemon"].as<bool>())  {
    g_console=false;
    daemonize();
  }
  else {
    vinfolog("Running in the foreground");
  }

  for(auto& t : todo)
    t();

  auto acl = g_ACL.getCopy();
  for(auto& addr : {"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})
    acl.addMask(addr);
  g_ACL.setState(acl);

  if(g_vm.count("remotes")) {
    for(const auto& address : g_vm["remotes"].as<vector<string>>()) {
      auto ret=std::make_shared<DownstreamState>(ComboAddress(address, 53));
      ret->tid = move(thread(responderThread, ret));
      g_dstates.modify([ret](servers_t& servers) { servers.push_back(ret); });
    }
  }

  for(auto& dss : g_dstates.getCopy()) { // it is a copy, but the internal shared_ptrs are the real deal
    if(dss->availability==DownstreamState::Availability::Auto) {
      bool newState=upCheck(dss->remote);
      warnlog("Marking downstream %s as '%s'", dss->remote.toStringWithPort(), newState ? "up" : "down");
      dss->upStatus = newState;
    }
  }


  for(auto& cs : toLaunch) {
    thread t1(udpClientThread, cs);
    t1.detach();
  }

  for(const auto& local : g_locals) {
    ClientState* cs = new ClientState;
    cs->local= local;

    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);

    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(cs->tcpFD, SOL_TCP,TCP_DEFER_ACCEPT, 1);
#endif
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->tcpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    if(g_vm.count("bind-non-local"))
      bindAny(cs->local.sin4.sin_family, cs->tcpFD);
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
