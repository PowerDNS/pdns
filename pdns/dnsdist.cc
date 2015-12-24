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
#include "delaypipe.hh"
#include <unistd.h>
#include "sodcrypto.hh"
#include "dnsrulactions.hh"
#include <grp.h>
#include <pwd.h>
#include "lock.hh"
#include <getopt.h>

/* Known sins:

   Receiver is currently single threaded
      not *that* bad actually, but now that we are thread safe, might want to scale
*/

/* the Rulaction plan
   Set of Rules, if one matches, it leads to an Action
   Both rules and actions could conceivably be Lua based. 
   On the C++ side, both could be inherited from a class Rule and a class Action, 
   on the Lua side we can't do that. */

using std::atomic;
using std::thread;
bool g_verbose;

struct DNSDistStats g_stats;
uint16_t g_maxOutstanding;
bool g_console;

GlobalStateHolder<NetmaskGroup> g_ACL;
string g_outputBuffer;
vector<std::pair<ComboAddress, bool>> g_locals;
#ifdef HAVE_DNSCRYPT
std::vector<std::pair<ComboAddress,DnsCryptContext>> g_dnsCryptLocals;
#endif
vector<ClientState *> g_frontends;

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
   Hashed weighted random
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
GlobalStateHolder<NetmaskTree<DynBlock>> g_dynblockNMG;
int g_tcpRecvTimeout{2};
int g_tcpSendTimeout{2};

bool g_truncateTC{1};
bool g_fixupCase{0};
static void truncateTC(const char* packet, unsigned int* len)
try
{
  unsigned int consumed;
  DNSName qname(packet, *len, sizeof(dnsheader), false, 0, 0, &consumed);
  *len=sizeof(dnsheader)+consumed+DNS_TYPE_SIZE+DNS_CLASS_SIZE;
  struct dnsheader* dh =(struct dnsheader*)packet;
  dh->ancount = dh->arcount = dh->nscount=0;
}
catch(...)
{
  g_stats.truncFail++;
}

struct DelayedPacket
{
  int fd;
  string packet;
  ComboAddress destination;
  ComboAddress origDest;
  void operator()()
  {
    if(origDest.sin4.sin_family == 0)
      sendto(fd, packet.c_str(), packet.size(), 0, (struct sockaddr*)&destination, destination.getSocklen());
    else
      sendfromto(fd, packet.c_str(), packet.size(), 0, origDest, destination);
  }
};

DelayPipe<DelayedPacket> * g_delay = 0;


// listens on a dedicated socket, lobs answers from downstream servers to original requestors
void* responderThread(std::shared_ptr<DownstreamState> state)
{
#ifdef HAVE_DNSCRYPT
  char packet[4096 + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE];
#else
  char packet[4096];
#endif
  const uint16_t rdMask = 1 << FLAGS_RD_OFFSET;
  const uint16_t cdMask = 1 << FLAGS_CD_OFFSET;
  const uint16_t restoreFlagsMask = UINT16_MAX & ~(rdMask | cdMask);
  vector<uint8_t> rewrittenResponse;
  
  struct dnsheader* dh = (struct dnsheader*)packet;
  int len;
  for(;;) {
    len = recv(state->fd, packet, sizeof(packet), 0);
    char * response = packet;
    size_t responseLen = len;
#ifdef HAVE_DNSCRYPT
    uint16_t responseSize = sizeof(packet);
#endif

    if(len < (signed)sizeof(dnsheader))
      continue;

    if(dh->id >= state->idStates.size())
      continue;

    IDState* ids = &state->idStates[dh->id];
    int origFD = ids->origFD;

    if(origFD < 0) // duplicate
      continue;
    else
      --state->outstanding;  // you'd think an attacker could game this, but we're using connected socket

    if(g_fixupCase) {
      string realname = ids->qname.toDNSString();
      memcpy(packet+12, realname.c_str(), realname.length());
    }

    if(dh->tc && g_truncateTC) {
      truncateTC(packet, (unsigned int*)&len);
    }
    uint16_t * flags = getFlagsFromDNSHeader(dh);
    uint16_t origFlags = ids->origFlags;
    /* clear the flags we are about to restore */
    *flags &= restoreFlagsMask;
    /* only keep the flags we want to restore */
    origFlags &= ~restoreFlagsMask;
    /* set the saved flags as they were */
    *flags |= origFlags;

    dh->id = ids->origID;

    if (ids->ednsAdded) {
      const char * optStart = NULL;
      size_t optLen = 0;
      bool last = false;

      int res = locateEDNSOptRR(response, responseLen, &optStart, &optLen, &last);

      if (res == 0) {
        if (last) {
          /* simply remove the last AR */
          responseLen -= optLen;
          uint16_t arcount = ntohs(dh->arcount);
          arcount--;
          dh->arcount = htons(arcount);
        }
        else {
          /* Removing an intermediary RR could lead to compression error */
          if (rewriteResponseWithoutEDNS(response, responseLen, rewrittenResponse) == 0) {
            responseLen = rewrittenResponse.size();
#ifdef HAVE_DNSCRYPT
            if (ids->dnsCryptQuery && (UINT16_MAX - DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE) > responseLen) {
              rewrittenResponse.reserve(responseLen + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE);
            }
            responseSize = rewrittenResponse.capacity();
#endif
            response = reinterpret_cast<char*>(rewrittenResponse.data());
          }
          else {
            warnlog("Error rewriting content");
          }
        }
      }
    }

    g_stats.responses++;

#ifdef HAVE_DNSCRYPT
    uint16_t encryptedResponseLen = 0;
    if(ids->dnsCryptQuery) {
      int res = ids->dnsCryptQuery->ctx->encryptResponse(response, responseLen, responseSize, ids->dnsCryptQuery, false, &encryptedResponseLen);

      if (res == 0) {
        responseLen = encryptedResponseLen;
      } else {
        /* dropping response */
        vinfolog("Error encrypting the response, dropping.");
        continue;
      }
    }
#endif

    if(ids->delayMsec && g_delay) {
      DelayedPacket dp{origFD, string(response,responseLen), ids->origRemote, ids->origDest};
      g_delay->submit(dp, ids->delayMsec);
    }
    else {
      if(ids->origDest.sin4.sin_family == 0)
	sendto(origFD, response, responseLen, 0, (struct sockaddr*)&ids->origRemote, ids->origRemote.getSocklen());
      else
	sendfromto(origFD, response, responseLen, 0, ids->origDest, ids->origRemote);
    }

    double udiff = ids->sentTime.udiff();
    vinfolog("Got answer from %s, relayed to %s, took %f usec", state->remote.toStringWithPort(), ids->origRemote.toStringWithPort(), udiff);

    {
      struct timespec ts;
      clock_gettime(CLOCK_MONOTONIC, &ts);
      std::lock_guard<std::mutex> lock(g_rings.respMutex);
      g_rings.respRing.push_back({ts, ids->origRemote, ids->qname, ids->qtype, (unsigned int)udiff, (unsigned int)len, *dh});
    }
    if(dh->rcode == RCode::ServFail)
      g_stats.servfailResponses++;
    state->latencyUsec = (127.0 * state->latencyUsec / 128.0) + udiff/128.0;

    if(udiff < 1000) g_stats.latency0_1++;
    else if(udiff < 10000) g_stats.latency1_10++;
    else if(udiff < 50000) g_stats.latency10_50++;
    else if(udiff < 100000) g_stats.latency50_100++;
    else if(udiff < 1000000) g_stats.latency100_1000++;
    else g_stats.latencySlow++;
    
    auto doAvg = [](double& var, double n, double weight) {
      var = (weight -1) * var/weight + n/weight;
    };

    doAvg(g_stats.latencyAvg100,     udiff,     100);
    doAvg(g_stats.latencyAvg1000,    udiff,    1000);
    doAvg(g_stats.latencyAvg10000,   udiff,   10000);
    doAvg(g_stats.latencyAvg1000000, udiff, 1000000);

    if (ids->origFD == origFD) {
#ifdef HAVE_DNSCRYPT
      ids->dnsCryptQuery = 0;
#endif
      ids->origFD = -1;
    }

    rewrittenResponse.clear();
  }
  return 0;
}

DownstreamState::DownstreamState(const ComboAddress& remote_): checkName("a.root-servers.net."), checkType(QType::A), mustResolve(false)
{
  remote = remote_;
  
  fd = SSocket(remote.sin4.sin_family, SOCK_DGRAM, 0);
  SConnect(fd, remote);
  idStates.resize(g_maxOutstanding);
  sw.start();
  infolog("Added downstream server %s", remote.toStringWithPort());
}

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

// get server with least outstanding queries, and within those, with the lowest order, and within those: the fastest
shared_ptr<DownstreamState> leastOutstanding(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  vector<pair<tuple<int,int,double>, shared_ptr<DownstreamState>>> poss;
  /* so you might wonder, why do we go through this trouble? The data on which we sort could change during the sort,
     which would suck royally and could even lead to crashes. So first we snapshot on what we sort, and then we sort */
  poss.reserve(servers.size());
  for(auto& d : servers) {
    if(d.second->isUp()) {
      poss.push_back({make_tuple(d.second->outstanding.load(), d.second->order, d.second->latencyUsec), d.second});
    }
  }
  if(poss.empty())
    return shared_ptr<DownstreamState>();
  nth_element(poss.begin(), poss.begin(), poss.end(), [](const decltype(poss)::value_type& a, const decltype(poss)::value_type& b) { return a.first < b.first; });
  return poss.begin()->second;
}

shared_ptr<DownstreamState> valrandom(unsigned int val, const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  vector<pair<int, shared_ptr<DownstreamState>>> poss;
  int sum=0;
  for(auto& d : servers) {      // w=1, w=10 -> 1, 11
    if(d.second->isUp()) {
      sum+=d.second->weight;
      poss.push_back({sum, d.second});
    }
  }

  // Catch poss & sum are empty to avoid SIGFPE
  if(poss.empty())
    return shared_ptr<DownstreamState>();

  int r = val % sum;
  auto p = upper_bound(poss.begin(), poss.end(),r, [](int r, const decltype(poss)::value_type& a) { return  r < a.first;});
  if(p==poss.end())
    return shared_ptr<DownstreamState>();
  return p->second;
}

shared_ptr<DownstreamState> wrandom(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  return valrandom(random(), servers, remote, qname, qtype, dh);
}

static uint32_t g_hashperturb;
shared_ptr<DownstreamState> whashed(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)
{
  return valrandom(qname.hash(g_hashperturb), servers, remote, qname, qtype, dh);
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

static void writepid(string pidfile) {
  if (!pidfile.empty()) {
    // Clean up possible stale file
    unlink(pidfile.c_str());

    // Write the pidfile
    ofstream of(pidfile.c_str());
    if (of) {
      of << getpid();
    } else {
      errlog("Unable to write PID-file to '%s'.", pidfile);
    }
    of.close();
  }
}

static void daemonize(void)
{
  if(fork())
    _exit(0); // bye bye
  /* We are child */

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

// goal in life - if you send us a reasonably normal packet, we'll get Z for you, otherwise 0
int getEDNSZ(const char* packet, unsigned int len)
{
  struct dnsheader* dh =(struct dnsheader*)packet;

  if(ntohs(dh->qdcount) != 1 || dh->ancount!=0 || ntohs(dh->arcount)!=1 || dh->nscount!=0)
    return 0;

  if (len <= sizeof(dnsheader))
    return 0;

  unsigned int consumed;
  DNSName qname(packet, len, sizeof(dnsheader), false, 0, 0, &consumed);
  size_t pos = consumed + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
  uint16_t qtype, qclass;

  if (len <= (sizeof(dnsheader)+pos))
    return 0;

  DNSName aname(packet, len, sizeof(dnsheader)+pos, true, &qtype, &qclass, &consumed);

  if(qtype!=QType::OPT || sizeof(dnsheader)+pos+consumed+DNS_TYPE_SIZE+DNS_CLASS_SIZE+EDNS_EXTENDED_RCODE_SIZE+EDNS_VERSION_SIZE+1 >= len)
    return 0;

  uint8_t* z = (uint8_t*)packet+sizeof(dnsheader)+pos+consumed+DNS_TYPE_SIZE+DNS_CLASS_SIZE+EDNS_EXTENDED_RCODE_SIZE+EDNS_VERSION_SIZE;
  return 0x100 * (*z) + *(z+1);
}

// listens to incoming queries, sends out to downstream servers, noting the intended return path 
static void* udpClientThread(ClientState* cs)
try
{
  ComboAddress remote;
  remote.sin4.sin_family = cs->local.sin4.sin_family;
  char packet[1500];
  string largerQuery;
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
  auto localDynBlock = g_dynblockNMG.getLocal();
  struct msghdr msgh;
  struct iovec iov;
  /* used by HarvestDestinationAddress */
  char cbuf[256];
  remote.sin6.sin6_family=cs->local.sin6.sin6_family;
  fillMSGHdr(&msgh, &iov, cbuf, sizeof(cbuf), packet, sizeof(packet), &remote);

  for(;;) {
    try {
#ifdef HAVE_DNSCRYPT
      std::shared_ptr<DnsCryptQuery> dnsCryptQuery = 0;
#endif
      char* query = packet;
      size_t querySize = sizeof(packet);
      ssize_t ret = recvmsg(cs->udpFD, &msgh, 0);

      cs->queries++;
      g_stats.queries++;

      if(ret < (int)sizeof(struct dnsheader)) {
	g_stats.nonCompliantQueries++;
	continue;
      }

      if (msgh.msg_flags & MSG_TRUNC) {
        /* message was too large for our buffer */
        vinfolog("Dropping message too large for our buffer");
        g_stats.nonCompliantQueries++;
        continue;
      }

      if(!acl->match(remote)) {
	vinfolog("Query from %s dropped because of ACL", remote.toStringWithPort());
	g_stats.aclDrops++;
	continue;
      }

      uint16_t len = ret;

#ifdef HAVE_DNSCRYPT
      if (cs->dnscryptCtx) {
        vector<uint8_t> response;
        uint16_t decryptedQueryLen = 0;
        dnsCryptQuery = std::make_shared<DnsCryptQuery>();

        bool decrypted = handleDnsCryptQuery(cs->dnscryptCtx, query, len, dnsCryptQuery, &decryptedQueryLen, false, response);

        if (!decrypted) {
          if (response.size() > 0) {
            ComboAddress dest;
            if(HarvestDestinationAddress(&msgh, &dest))
              sendfromto(cs->udpFD, (const char *) response.data(), response.size(), 0, dest, remote);
            else
              sendto(cs->udpFD, response.data(), response.size(), 0, (struct sockaddr*)&remote, remote.getSocklen());
          }
          continue;
        }
        len = decryptedQueryLen;
      }
#endif

      struct dnsheader* dh = (struct dnsheader*) query;

      if(dh->qr) {   // don't respond to responses
	g_stats.nonCompliantQueries++;
	continue;
      }

      if (dh->rd) {
        g_stats.rdQueries++;
      }

      const uint16_t * flags = getFlagsFromDNSHeader(dh);
      const uint16_t origFlags = *flags;
      unsigned int consumed = 0;
      DNSName qname(query, len, sizeof(dnsheader), false, &qtype, NULL, &consumed);
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      {
        WriteLock wl(&g_rings.queryLock);
        g_rings.queryRing.push_back({now,remote,qname,len,qtype,*dh});
      }

      if(auto got=localDynBlock->lookup(remote)) {
	if(now < got->second.until) {
	  vinfolog("Query from %s dropped because of dynamic block", remote.toStringWithPort());
	  g_stats.dynBlocked++;
	  got->second.blocks++;
	  continue;
	}
      }

      if(blockFilter) {
	std::lock_guard<std::mutex> lock(g_luamutex);
	
	if(blockFilter(remote, qname, qtype, dh)) {
	  g_stats.blockFilter++;
	  continue;
	}
      }

      DNSAction::Action action=DNSAction::Action::None;
      string ruleresult;
      string pool;

      for(const auto& lr : *localRulactions) {
	if(lr.first->matches(remote, qname, qtype, dh, len)) {
	  action=(*lr.second)(remote, qname, qtype, dh, len, &ruleresult);
	  if(action != DNSAction::Action::None) {
	    lr.first->d_matches++;
	    break;
	  }
	}
      }
      int delayMsec=0;
      switch(action) {
      case DNSAction::Action::Drop:
	g_stats.ruleDrop++;
	continue;
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
	break;
      case DNSAction::Action::Delay:
	delayMsec = static_cast<int>(pdns_stou(ruleresult)); // sorry
	break;
      case DNSAction::Action::Allow:
      case DNSAction::Action::None:
	break;
      }

      if(dh->qr) { // something turned it into a response
        char* response = query;
        uint16_t responseLen = len;
#ifdef HAVE_DNSCRYPT
        uint16_t responseSize = querySize;
#endif
        g_stats.selfAnswered++;

#ifdef HAVE_DNSCRYPT
        uint16_t encryptedResponseLen = 0;

        if(dnsCryptQuery) {
          int res = cs->dnscryptCtx->encryptResponse(response, responseLen, responseSize, dnsCryptQuery, false, &encryptedResponseLen);

          if (res == 0) {
            responseLen = encryptedResponseLen;
          } else {
            /* dropping response */
            continue;
          }
        }
#endif
        ComboAddress dest;
        if(HarvestDestinationAddress(&msgh, &dest))
          sendfromto(cs->udpFD, response, responseLen, 0, dest, remote);
        else
          sendto(cs->udpFD, response, responseLen, 0, (struct sockaddr*)&remote, remote.getSocklen());

        continue;
      }

      DownstreamState* ss = 0;
      auto candidates=getDownstreamCandidates(*localServers, pool);
      auto policy=localPolicy->policy;
      {
	std::lock_guard<std::mutex> lock(g_luamutex);
	ss = policy(candidates, remote, qname, qtype, dh).get();
      }

      if(!ss) {
	g_stats.noPolicy++;
	continue;
      }

      ss->queries++;

      unsigned int idOffset = (ss->idOffset++) % ss->idStates.size();
      IDState* ids = &ss->idStates[idOffset];
      ids->age = 0;

      if(ids->origFD < 0) // if we are reusing, no change in outstanding
        ss->outstanding++;
      else {
        ss->reuseds++;
        g_stats.downstreamTimeouts++;
      }

      ids->origFD = cs->udpFD;
      ids->origID = dh->id;
      ids->origRemote = remote;
      ids->sentTime.start();
      ids->qname = qname;
      ids->qtype = qtype;
      ids->origDest.sin4.sin_family=0;
      ids->delayMsec = delayMsec;
      ids->origFlags = origFlags;
      ids->ednsAdded = false;
#ifdef HAVE_DNSCRYPT
      ids->dnsCryptQuery = dnsCryptQuery;
#endif
      HarvestDestinationAddress(&msgh, &ids->origDest);

      dh->id = idOffset;

      if (ss->useECS) {
        handleEDNSClientSubnet(query, querySize, consumed, &len, largerQuery, &(ids->ednsAdded), remote);
      }

      if (largerQuery.empty()) {
        ret = send(ss->fd, query, len, 0);
      }
      else {
        ret = send(ss->fd, largerQuery.c_str(), largerQuery.size(), 0);
        largerQuery.clear();
      }

      if(ret < 0) {
	ss->sendErrors++;
	g_stats.downstreamSendErrors++;
      }

      vinfolog("Got query from %s, relayed to %s", remote.toStringWithPort(), ss->getName());
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


bool upCheck(const ComboAddress& remote, const DNSName& checkName, const QType& checkType, bool mustResolve)
try
{
  vector<uint8_t> packet;
  DNSPacketWriter dpw(packet, checkName, checkType.getCode());
  dnsheader * requestHeader = dpw.getHeader();
  requestHeader->rd=true;

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

  const dnsheader * responseHeader = (const dnsheader *) reply.c_str();

  if (reply.size() < sizeof(*responseHeader))
    return false;

  if (responseHeader->id != requestHeader->id)
    return false;
  if (!responseHeader->qr)
    return false;
  if (responseHeader->rcode == RCode::ServFail)
    return false;
  if (mustResolve && (responseHeader->rcode == RCode::NXDomain || responseHeader->rcode == RCode::Refused))
    return false;

  // XXX fixme do bunch of checking here etc 
  return true;
}
catch(...)
{
  return false;
}

std::atomic<uint64_t> g_maxTCPClientThreads{10};

void* maintThread()
{
  int interval = 1;

  for(;;) {
    sleep(interval);

    if(g_tcpclientthreads.d_queued > 1 && g_tcpclientthreads.d_numthreads < g_maxTCPClientThreads)
      g_tcpclientthreads.addTCPClientThread();

    for(auto& dss : g_dstates.getCopy()) { // this points to the actual shared_ptrs!
      if(dss->availability==DownstreamState::Availability::Auto) {
	bool newState=upCheck(dss->remote, dss->checkName, dss->checkType, dss->mustResolve);
	if(newState != dss->upStatus) {
	  warnlog("Marking downstream %s as '%s'", dss->getNameWithAddr(), newState ? "up" : "down");
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
	  struct timespec ts;
	  clock_gettime(CLOCK_MONOTONIC, &ts);
	  std::lock_guard<std::mutex> lock(g_rings.respMutex);
	  g_rings.respRing.push_back({ts, ids.origRemote, ids.qname, ids.qtype, 0, 2000000, 0});
        }          
      }
    }
    
    std::lock_guard<std::mutex> lock(g_luamutex);
    auto f =g_lua.readVariable<boost::optional<std::function<void()> > >("maintenance");
    if(f)
      (*f)();
    

    // ponder pruning g_dynblocks of expired entries here
  }
  return 0;
}

string g_key;


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

static void dropGroupPrivs(gid_t gid)
{
  if (gid) {
    if (setgid(gid) == 0) {
      if (setgroups(0, NULL) < 0) {
        warnlog("Warning: Unable to drop supplementary gids: %s", strerror(errno));
      }
    }
    else {
      warnlog("Warning: Unable to set group ID to %d: %s", gid, strerror(errno));
    }
  }
}

static void dropUserPrivs(uid_t uid)
{
  if(uid) {
    if(setuid(uid) < 0) {
      warnlog("Warning: Unable to set user ID to %d: %s", uid, strerror(errno));
    }
  }
}


struct 
{
  vector<string> locals;
  vector<string> remotes;
  bool beDaemon{false};
  bool beClient{false};
  bool beSupervised{false};
  string pidfile;
  string command;
  string config;
  string uid;
  string gid;
} g_cmdLine;

std::atomic<bool> g_configurationDone{false};

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
  g_hashperturb=randombytes_uniform(0xffffffff);
  srandom(randombytes_uniform(0xffffffff));
#else
  {
    struct timeval tv;
    gettimeofday(&tv, 0);
    srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());
    g_hashperturb=random();
  }
  
#endif
  g_cmdLine.config=SYSCONFDIR "/dnsdist.conf";
  struct option longopts[]={ 
    {"acl", required_argument, 0, 'a'},
    {"config", required_argument, 0, 'C'},
    {"execute", required_argument, 0, 'e'},
    {"client", 0, 0, 'c'},
    {"gid",  required_argument, 0, 'g'},
    {"local",  required_argument, 0, 'l'},
    {"daemon", 0, 0, 'd'},
    {"pidfile",  required_argument, 0, 'p'},
    {"supervised", 0, 0, 's'},
    {"uid",  required_argument, 0, 'u'},
    {"verbose", 0, 0, 'v'},
    {"version", 0, 0, 'V'},
    {"help", 0, 0, 'h'},
    {0,0,0,0} 
  };
  int longindex=0;
  string optstring;
  for(;;) {
    int c=getopt_long(argc, argv, "a:hcde:C:l:vp:g:u:V", longopts, &longindex);
    if(c==-1)
      break;
    switch(c) {
    case 'C':
      g_cmdLine.config=optarg;
      break;
    case 'c':
      g_cmdLine.beClient=true;
      break;
    case 'd':
      g_cmdLine.beDaemon=true;
      break;
    case 'e':
      g_cmdLine.command=optarg;
      break;
    case 'g':
      g_cmdLine.gid=optarg;
      break;
    case 'h':
      cout<<"dnsdist "<<VERSION<<endl;
      cout<<endl;
      cout<<"Syntax: dnsdist [-C,--config file] [-c,--client] [-d,--daemon]\n";
      cout<<"[-p,--pidfile file] [-e,--execute cmd] [-h,--help] [-l,--local addr]\n";
      cout<<"[-v,--verbose]\n";
      cout<<"\n";
      cout<<"-a,--acl netmask      Add this netmask to the ACL\n";
      cout<<"-C,--config file      Load configuration from 'file'\n";
      cout<<"-c,--client           Operate as a client, connect to dnsdist\n";
      cout<<"-d,--daemon           Operate as a daemon\n";
      cout<<"-e,--execute cmd      Connect to dnsdist and execute 'cmd'\n";
      cout<<"-g,--gid gid          Change the process group ID after binding sockets\n";
      cout<<"-h,--help             Display this helpful message\n";
      cout<<"-l,--local address    Listen on this local address\n";
      cout<<"--supervised          Don't open a console, I'm supervised\n";
      cout<<"                        (use with e.g. systemd and daemontools)\n";
      cout<<"-p,--pidfile file     Write a pidfile, works only with --daemon\n";
      cout<<"-u,--uid uid          Change the process user ID after binding sockets\n";
      cout<<"-v,--verbose          Enable verbose mode\n";
      cout<<"\n";
      exit(EXIT_SUCCESS);
      break;
    case 'a':
      optstring=optarg;
      g_ACL.modify([optstring](NetmaskGroup& nmg) { nmg.addMask(optstring); });
      break;
    case 'l':
      g_cmdLine.locals.push_back(trim_copy(string(optarg)));
      break;
    case 'p':
      g_cmdLine.pidfile=optarg;
      break;
    case 's':
      g_cmdLine.beSupervised=true;
      break;
    case 'u':
      g_cmdLine.uid=optarg;
      break;
    case 'v':
      g_verbose=true;
      break;
    case 'V':
      cout<<"dnsdist "<<VERSION<<endl;
      exit(EXIT_SUCCESS);
      break;
    }
  }
  argc-=optind;
  argv+=optind;
  for(auto p = argv; *p; ++p) {
    g_cmdLine.remotes.push_back(*p);
  }

  g_maxOutstanding = 1024;

  ServerPolicy leastOutstandingPol{"leastOutstanding", leastOutstanding};

  g_policy.setState(leastOutstandingPol);
  if(g_cmdLine.beClient || !g_cmdLine.command.empty()) {
    setupLua(true, g_cmdLine.config);
    doClient(g_serverControl, g_cmdLine.command);
    _exit(EXIT_SUCCESS);
  }

  auto acl = g_ACL.getCopy();
  if(acl.empty()) {
    for(auto& addr : {"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})
      acl.addMask(addr);
    g_ACL.setState(acl);
  }

  auto todo=setupLua(false, g_cmdLine.config);

  if(g_cmdLine.locals.size()) {
    g_locals.clear();
    for(auto loc : g_cmdLine.locals)
      g_locals.push_back({ComboAddress(loc, 53), true});
  }
  
  if(g_locals.empty())
    g_locals.push_back({ComboAddress("127.0.0.1", 53), true});
  

  g_configurationDone = true;

  vector<ClientState*> toLaunch;
  for(const auto& local : g_locals) {
    ClientState* cs = new ClientState;
    cs->local= local.first;
    cs->udpFD = SSocket(cs->local.sin4.sin_family, SOCK_DGRAM, 0);
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    //if(g_vm.count("bind-non-local"))
    bindAny(local.first.sin4.sin_family, cs->udpFD);

    //    if (!setSocketTimestamps(cs->udpFD))
    //      L<<Logger::Warning<<"Unable to enable timestamp reporting for socket"<<endl;


    if(IsAnyAddress(local.first)) {
      int one=1;
      setsockopt(cs->udpFD, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one));     // linux supports this, so why not - might fail on other systems
#ifdef IPV6_RECVPKTINFO
      setsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
#endif
    }

    SBind(cs->udpFD, cs->local);
    toLaunch.push_back(cs);
    g_frontends.push_back(cs);
  }

  for(const auto& local : g_locals) {
    if(!local.second) { // no TCP/IP
      warnlog("Not providing TCP/IP service on local address '%s'", local.first.toStringWithPort());
      continue;
    }
    ClientState* cs = new ClientState;
    cs->local= local.first;

    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);

    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(cs->tcpFD, SOL_TCP,TCP_DEFER_ACCEPT, 1);
#endif
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->tcpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    //    if(g_vm.count("bind-non-local"))
      bindAny(cs->local.sin4.sin_family, cs->tcpFD);
    SBind(cs->tcpFD, cs->local);
    SListen(cs->tcpFD, 64);
    warnlog("Listening on %s",cs->local.toStringWithPort());

    toLaunch.push_back(cs);
    g_frontends.push_back(cs);
  }

#ifdef HAVE_DNSCRYPT
  for(auto& dcLocal : g_dnsCryptLocals) {
    ClientState* cs = new ClientState;
    cs->local = dcLocal.first;
    cs->dnscryptCtx = &dcLocal.second;
    cs->udpFD = SSocket(cs->local.sin4.sin_family, SOCK_DGRAM, 0);
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    bindAny(cs->local.sin4.sin_family, cs->udpFD);
    if(IsAnyAddress(cs->local)) {
      int one=1;
      setsockopt(cs->udpFD, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one));     // linux supports this, so why not - might fail on other systems
#ifdef IPV6_RECVPKTINFO
      setsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)); 
#endif
    }
    SBind(cs->udpFD, cs->local);    
    toLaunch.push_back(cs);
    g_frontends.push_back(cs);

    cs = new ClientState;
    cs->local = dcLocal.first;
    cs->dnscryptCtx = &dcLocal.second;
    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);
    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(cs->tcpFD, SOL_TCP,TCP_DEFER_ACCEPT, 1);
#endif
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->tcpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    bindAny(cs->local.sin4.sin_family, cs->tcpFD);
    SBind(cs->tcpFD, cs->local);
    SListen(cs->tcpFD, 64);
    warnlog("Listening on %s", cs->local.toStringWithPort());
    toLaunch.push_back(cs);
    g_frontends.push_back(cs);
  }
#endif

  uid_t newgid=0;
  gid_t newuid=0;

  if(!g_cmdLine.gid.empty())
    newgid = strToGID(g_cmdLine.gid.c_str());

  if(!g_cmdLine.uid.empty())
    newuid = strToUID(g_cmdLine.uid.c_str());

  dropGroupPrivs(newgid);
  dropUserPrivs(newuid);

  if(g_cmdLine.beDaemon) {
    g_console=false;
    daemonize();
    writepid(g_cmdLine.pidfile);
  }
  else {
    vinfolog("Running in the foreground");
    warnlog("dnsdist %s comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2", VERSION);
  }

  /* this need to be done _after_ dropping privileges */
  g_delay = new DelayPipe<DelayedPacket>();

  for(auto& t : todo)
    t();


  if(g_cmdLine.remotes.size()) {
    for(const auto& address : g_cmdLine.remotes) {
      auto ret=std::make_shared<DownstreamState>(ComboAddress(address, 53));
      ret->tid = move(thread(responderThread, ret));
      g_dstates.modify([ret](servers_t& servers) { servers.push_back(ret); });
    }
  }

  if(g_dstates.getCopy().empty()) {
    errlog("No downstream servers defined: all packets will get dropped");
    // you might define them later, but you need to know
  }

  for(auto& dss : g_dstates.getCopy()) { // it is a copy, but the internal shared_ptrs are the real deal
    if(dss->availability==DownstreamState::Availability::Auto) {
      bool newState=upCheck(dss->remote, dss->checkName, dss->checkType, dss->mustResolve);
      warnlog("Marking downstream %s as '%s'", dss->getNameWithAddr(), newState ? "up" : "down");
      dss->upStatus = newState;
    }
  }

  for(auto& cs : toLaunch) {
    if (cs->udpFD >= 0) {
      thread t1(udpClientThread, cs);
      t1.detach();
    }
    else if (cs->tcpFD >= 0) {
      thread t1(tcpAcceptorThread, cs);
      t1.detach();
    }
  }

  thread carbonthread(carbonDumpThread);
  carbonthread.detach();

  thread stattid(maintThread);
  
  if(g_cmdLine.beDaemon || g_cmdLine.beSupervised) {
    stattid.join();
  }
  else {
    stattid.detach();
    doConsole();
  }
  _exit(EXIT_SUCCESS);

}
catch(std::exception &e)
{
  errlog("Fatal error: %s", e.what());
  _exit(EXIT_FAILURE);
}
catch(PDNSException &ae)
{
  errlog("Fatal pdns error: %s", ae.reason);
  _exit(EXIT_FAILURE);
}
