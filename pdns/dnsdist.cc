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
#include "sstuff.hh"
#include "misc.hh"
#include <netinet/tcp.h>
#include <limits>
#include "dolog.hh"

#if defined (__OpenBSD__)
#include <readline/readline.h>
#else
#include <editline/readline.h>
#endif

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
#include <sys/resource.h>
#include "dnsdist-cache.hh"
#include "gettime.hh"

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#ifdef HAVE_PROTOBUF
thread_local boost::uuids::random_generator t_uuidGenerator;
#endif

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
uint16_t g_maxOutstanding{10240};
bool g_console;
bool g_verboseHealthChecks{false};
uint32_t g_staleCacheEntriesTTL{0};
bool g_syslog{true};

GlobalStateHolder<NetmaskGroup> g_ACL;
string g_outputBuffer;
vector<std::tuple<ComboAddress, bool, bool, int, string, std::set<int>>> g_locals;
#ifdef HAVE_DNSCRYPT
std::vector<std::tuple<ComboAddress,DnsCryptContext,bool, int, string, std::set<int>>> g_dnsCryptLocals;
#endif
#ifdef HAVE_EBPF
shared_ptr<BPFFilter> g_defaultBPFFilter;
std::vector<std::shared_ptr<DynBPFFilter> > g_dynBPFFilters;
#endif /* HAVE_EBPF */
vector<ClientState *> g_frontends;
GlobalStateHolder<pools_t> g_pools;
size_t g_udpVectorSize{1};

bool g_snmpEnabled{false};
bool g_snmpTrapsEnabled{false};
DNSDistSNMPAgent* g_snmpAgent{nullptr};

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
GlobalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSResponseAction> > > > g_resprulactions;
GlobalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSResponseAction> > > > g_cachehitresprulactions;
Rings g_rings;
QueryCount g_qcount;

GlobalStateHolder<servers_t> g_dstates;
GlobalStateHolder<NetmaskTree<DynBlock>> g_dynblockNMG;
GlobalStateHolder<SuffixMatchTree<DynBlock>> g_dynblockSMT;
DNSAction::Action g_dynBlockAction = DNSAction::Action::Drop;
int g_tcpRecvTimeout{2};
int g_tcpSendTimeout{2};
int g_udpTimeout{2};

bool g_servFailOnNoPolicy{false};
bool g_truncateTC{false};
bool g_fixupCase{0};

static const size_t s_udpIncomingBufferSize{1500};

static void truncateTC(const char* packet, uint16_t* len)
try
{
  unsigned int consumed;
  DNSName qname(packet, *len, sizeof(dnsheader), false, 0, 0, &consumed);
  *len=(uint16_t) (sizeof(dnsheader)+consumed+DNS_TYPE_SIZE+DNS_CLASS_SIZE);
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
    ssize_t res;
    if(origDest.sin4.sin_family == 0) {
      res = sendto(fd, packet.c_str(), packet.size(), 0, (struct sockaddr*)&destination, destination.getSocklen());
    }
    else {
      res = sendfromto(fd, packet.c_str(), packet.size(), 0, origDest, destination);
    }
    if (res == -1) {
      int err = errno;
      vinfolog("Error sending delayed response to %s: %s", destination.toStringWithPort(), strerror(err));
    }
  }
};

DelayPipe<DelayedPacket> * g_delay = 0;

static void doLatencyAverages(double udiff)
{
  auto doAvg = [](double& var, double n, double weight) {
    var = (weight -1) * var/weight + n/weight;
  };

  doAvg(g_stats.latencyAvg100,     udiff,     100);
  doAvg(g_stats.latencyAvg1000,    udiff,    1000);
  doAvg(g_stats.latencyAvg10000,   udiff,   10000);
  doAvg(g_stats.latencyAvg1000000, udiff, 1000000);
}

bool responseContentMatches(const char* response, const uint16_t responseLen, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& remote)
{
  uint16_t rqtype, rqclass;
  unsigned int consumed;
  DNSName rqname;
  const struct dnsheader* dh = (struct dnsheader*) response;

  if (responseLen < sizeof(dnsheader)) {
    return false;
  }

  if (dh->qdcount == 0) {
    if (dh->rcode != RCode::NoError && dh->rcode != RCode::NXDomain) {
      return true;
    }
    else {
      g_stats.nonCompliantResponses++;
      return false;
    }
  }

  try {
    rqname=DNSName(response, responseLen, sizeof(dnsheader), false, &rqtype, &rqclass, &consumed);
  }
  catch(std::exception& e) {
    if(responseLen > (ssize_t)sizeof(dnsheader))
      infolog("Backend %s sent us a response with id %d that did not parse: %s", remote.toStringWithPort(), ntohs(dh->id), e.what());
    g_stats.nonCompliantResponses++;
    return false;
  }

  if (rqtype != qtype || rqclass != qclass || rqname != qname) {
    return false;
  }

  return true;
}

void restoreFlags(struct dnsheader* dh, uint16_t origFlags)
{
  static const uint16_t rdMask = 1 << FLAGS_RD_OFFSET;
  static const uint16_t cdMask = 1 << FLAGS_CD_OFFSET;
  static const uint16_t restoreFlagsMask = UINT16_MAX & ~(rdMask | cdMask);
  uint16_t * flags = getFlagsFromDNSHeader(dh);
  /* clear the flags we are about to restore */
  *flags &= restoreFlagsMask;
  /* only keep the flags we want to restore */
  origFlags &= ~restoreFlagsMask;
  /* set the saved flags as they were */
  *flags |= origFlags;
}

bool fixUpResponse(char** response, uint16_t* responseLen, size_t* responseSize, const DNSName& qname, uint16_t origFlags, bool ednsAdded, bool ecsAdded, std::vector<uint8_t>& rewrittenResponse, uint16_t addRoom)
{
  struct dnsheader* dh = (struct dnsheader*) *response;

  if (*responseLen < sizeof(dnsheader)) {
    return false;
  }

  restoreFlags(dh, origFlags);

  if (*responseLen == sizeof(dnsheader)) {
    return true;
  }

  if(g_fixupCase) {
    string realname = qname.toDNSString();
    if (*responseLen >= (sizeof(dnsheader) + realname.length())) {
      memcpy(*response + sizeof(dnsheader), realname.c_str(), realname.length());
    }
  }

  if (ednsAdded || ecsAdded) {
    char * optStart = NULL;
    size_t optLen = 0;
    bool last = false;

    int res = locateEDNSOptRR(*response, *responseLen, &optStart, &optLen, &last);

    if (res == 0) {
      if (ednsAdded) {
        /* we added the entire OPT RR,
           therefore we need to remove it entirely */
        if (last) {
          /* simply remove the last AR */
          *responseLen -= optLen;
          uint16_t arcount = ntohs(dh->arcount);
          arcount--;
          dh->arcount = htons(arcount);
        }
        else {
          /* Removing an intermediary RR could lead to compression error */
          if (rewriteResponseWithoutEDNS(*response, *responseLen, rewrittenResponse) == 0) {
            *responseLen = rewrittenResponse.size();
            if (addRoom && (UINT16_MAX - *responseLen) > addRoom) {
              rewrittenResponse.reserve(*responseLen + addRoom);
            }
            *responseSize = rewrittenResponse.capacity();
            *response = reinterpret_cast<char*>(rewrittenResponse.data());
          }
          else {
            warnlog("Error rewriting content");
          }
        }
      }
      else {
        /* the OPT RR was already present, but without ECS,
           we need to remove the ECS option if any */
        if (last) {
          /* nothing after the OPT RR, we can simply remove the
             ECS option */
          size_t existingOptLen = optLen;
          removeEDNSOptionFromOPT(optStart, &optLen, EDNSOptionCode::ECS);
          *responseLen -= (existingOptLen - optLen);
        }
        else {
          /* Removing an intermediary RR could lead to compression error */
          if (rewriteResponseWithoutEDNSOption(*response, *responseLen, EDNSOptionCode::ECS, rewrittenResponse) == 0) {
            *responseLen = rewrittenResponse.size();
            if (addRoom && (UINT16_MAX - *responseLen) > addRoom) {
              rewrittenResponse.reserve(*responseLen + addRoom);
            }
            *responseSize = rewrittenResponse.capacity();
            *response = reinterpret_cast<char*>(rewrittenResponse.data());
          }
          else {
            warnlog("Error rewriting content");
          }
        }
      }
    }
  }

  return true;
}

#ifdef HAVE_DNSCRYPT
bool encryptResponse(char* response, uint16_t* responseLen, size_t responseSize, bool tcp, std::shared_ptr<DnsCryptQuery> dnsCryptQuery, dnsheader** dh, dnsheader* dhCopy)
{
  if (dnsCryptQuery) {
    uint16_t encryptedResponseLen = 0;

    /* save the original header before encrypting it in place */
    if (dh != nullptr && *dh != nullptr && dhCopy != nullptr) {
      memcpy(dhCopy, *dh, sizeof(dnsheader));
      *dh = dhCopy;
    }

    int res = dnsCryptQuery->ctx->encryptResponse(response, *responseLen, responseSize, dnsCryptQuery, tcp, &encryptedResponseLen);
    if (res == 0) {
      *responseLen = encryptedResponseLen;
    } else {
      /* dropping response */
      vinfolog("Error encrypting the response, dropping.");
      return false;
    }
  }
  return true;
}
#endif

static bool sendUDPResponse(int origFD, char* response, uint16_t responseLen, int delayMsec, const ComboAddress& origDest, const ComboAddress& origRemote)
{
  if(delayMsec && g_delay) {
    DelayedPacket dp{origFD, string(response,responseLen), origRemote, origDest};
    g_delay->submit(dp, delayMsec);
  }
  else {
    ssize_t res;
    if(origDest.sin4.sin_family == 0) {
      res = sendto(origFD, response, responseLen, 0, (struct sockaddr*)&origRemote, origRemote.getSocklen());
    }
    else {
      res = sendfromto(origFD, response, responseLen, 0, origDest, origRemote);
    }
    if (res == -1) {
      int err = errno;
      vinfolog("Error sending response to %s: %s", origRemote.toStringWithPort(), strerror(err));
    }
  }

  return true;
}

// listens on a dedicated socket, lobs answers from downstream servers to original requestors
void* responderThread(std::shared_ptr<DownstreamState> state)
try {
  auto localRespRulactions = g_resprulactions.getLocal();
#ifdef HAVE_DNSCRYPT
  char packet[4096 + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE];
  /* when the answer is encrypted in place, we need to get a copy
     of the original header before encryption to fill the ring buffer */
  dnsheader dhCopy;
#else
  char packet[4096];
#endif
  static_assert(sizeof(packet) <= UINT16_MAX, "Packet size should fit in a uint16_t");
  vector<uint8_t> rewrittenResponse;

  uint16_t queryId = 0;
  for(;;) {
    dnsheader* dh = reinterpret_cast<struct dnsheader*>(packet);
    try {
      ssize_t got = recv(state->fd, packet, sizeof(packet), 0);
      char * response = packet;
      size_t responseSize = sizeof(packet);

      if (got < (ssize_t) sizeof(dnsheader))
        continue;

      uint16_t responseLen = (uint16_t) got;
      queryId = dh->id;

      if(queryId >= state->idStates.size())
        continue;

      IDState* ids = &state->idStates[queryId];
      int origFD = ids->origFD;

      if(origFD < 0) // duplicate
        continue;

      /* setting age to 0 to prevent the maintainer thread from
         cleaning this IDS while we process the response.
         We have already a copy of the origFD, so it would
         mostly mess up the outstanding counter.
      */
      ids->age = 0;

      if (!responseContentMatches(response, responseLen, ids->qname, ids->qtype, ids->qclass, state->remote)) {
        continue;
      }

      --state->outstanding;  // you'd think an attacker could game this, but we're using connected socket

      if(dh->tc && g_truncateTC) {
        truncateTC(response, &responseLen);
      }

      dh->id = ids->origID;

      uint16_t addRoom = 0;
      DNSResponse dr(&ids->qname, ids->qtype, ids->qclass, &ids->origDest, &ids->origRemote, dh, sizeof(packet), responseLen, false, &ids->sentTime.d_start);
#ifdef HAVE_PROTOBUF
      dr.uniqueId = ids->uniqueId;
#endif
      if (!processResponse(localRespRulactions, dr, &ids->delayMsec)) {
        continue;
      }

#ifdef HAVE_DNSCRYPT
      if (ids->dnsCryptQuery) {
        addRoom = DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
      }
#endif
      if (!fixUpResponse(&response, &responseLen, &responseSize, ids->qname, ids->origFlags, ids->ednsAdded, ids->ecsAdded, rewrittenResponse, addRoom)) {
        continue;
      }

      if (ids->packetCache && !ids->skipCache) {
        ids->packetCache->insert(ids->cacheKey, ids->qname, ids->qtype, ids->qclass, response, responseLen, false, dh->rcode);
      }

      if (ids->cs && !ids->cs->muted) {
#ifdef HAVE_DNSCRYPT
        if (!encryptResponse(response, &responseLen, responseSize, false, ids->dnsCryptQuery, &dh, &dhCopy)) {
          continue;
        }
#endif

        ComboAddress empty;
        empty.sin4.sin_family = 0;
        /* if ids->destHarvested is false, origDest holds the listening address.
           We don't want to use that as a source since it could be 0.0.0.0 for example. */
        sendUDPResponse(origFD, response, responseLen, ids->delayMsec, ids->destHarvested ? ids->origDest : empty, ids->origRemote);
      }

      g_stats.responses++;

      double udiff = ids->sentTime.udiff();
      vinfolog("Got answer from %s, relayed to %s, took %f usec", state->remote.toStringWithPort(), ids->origRemote.toStringWithPort(), udiff);

      {
        struct timespec ts;
        gettime(&ts);
        std::lock_guard<std::mutex> lock(g_rings.respMutex);
        g_rings.respRing.push_back({ts, ids->origRemote, ids->qname, ids->qtype, (unsigned int)udiff, (unsigned int)got, *dh, state->remote});
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
    
      doLatencyAverages(udiff);

      if (ids->origFD == origFD) {
#ifdef HAVE_DNSCRYPT
        ids->dnsCryptQuery = nullptr;
#endif
        ids->origFD = -1;
      }

      rewrittenResponse.clear();
    }
    catch(std::exception& e){
      vinfolog("Got an error in UDP responder thread while parsing a response from %s, id %d: %s", state->remote.toStringWithPort(), queryId, e.what());
    }
  }
  return 0;
}
catch(const std::exception& e)
{
  errlog("UDP responder thread died because of exception: %s", e.what());
  return 0;
}
catch(const PDNSException& e)
{
  errlog("UDP responder thread died because of PowerDNS exception: %s", e.reason);
  return 0;
}
catch(...)
{
  errlog("UDP responder thread died because of an exception: %s", "unknown");
  return 0;
}

void DownstreamState::reconnect()
{
  connected = false;
  if (fd != -1) {
    /* shutdown() is needed to wake up recv() in the responderThread */
    shutdown(fd, SHUT_RDWR);
    close(fd);
    fd = -1;
  }
  if (!IsAnyAddress(remote)) {
    fd = SSocket(remote.sin4.sin_family, SOCK_DGRAM, 0);
    if (!IsAnyAddress(sourceAddr)) {
      SSetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 1);
      SBind(fd, sourceAddr);
    }
    try {
      SConnect(fd, remote);
      connected = true;
    }
    catch(const std::runtime_error& error) {
      infolog("Error connecting to new server with address %s: %s", remote.toStringWithPort(), error.what());
    }
  }
}

DownstreamState::DownstreamState(const ComboAddress& remote_, const ComboAddress& sourceAddr_, unsigned int sourceItf_): remote(remote_), sourceAddr(sourceAddr_), sourceItf(sourceItf_)
{
  if (!IsAnyAddress(remote)) {
    reconnect();
    idStates.resize(g_maxOutstanding);
    sw.start();
    infolog("Added downstream server %s", remote.toStringWithPort());
  }
}

std::mutex g_luamutex;
LuaContext g_lua;

GlobalStateHolder<ServerPolicy> g_policy;

shared_ptr<DownstreamState> firstAvailable(const NumberedServerVector& servers, const DNSQuestion* dq)
{
  for(auto& d : servers) {
    if(d.second->isUp() && d.second->qps.check())
      return d.second;
  }
  return leastOutstanding(servers, dq);
}

// get server with least outstanding queries, and within those, with the lowest order, and within those: the fastest
shared_ptr<DownstreamState> leastOutstanding(const NumberedServerVector& servers, const DNSQuestion* dq)
{
  if (servers.size() == 1 && servers[0].second->isUp()) {
    return servers[0].second;
  }

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

shared_ptr<DownstreamState> valrandom(unsigned int val, const NumberedServerVector& servers, const DNSQuestion* dq)
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
  auto p = upper_bound(poss.begin(), poss.end(),r, [](int r_, const decltype(poss)::value_type& a) { return  r_ < a.first;});
  if(p==poss.end())
    return shared_ptr<DownstreamState>();
  return p->second;
}

shared_ptr<DownstreamState> wrandom(const NumberedServerVector& servers, const DNSQuestion* dq)
{
  return valrandom(random(), servers, dq);
}

uint32_t g_hashperturb;
shared_ptr<DownstreamState> whashed(const NumberedServerVector& servers, const DNSQuestion* dq)
{
  return valrandom(dq->qname->hash(g_hashperturb), servers, dq);
}


shared_ptr<DownstreamState> roundrobin(const NumberedServerVector& servers, const DNSQuestion* dq)
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

std::shared_ptr<ServerPool> createPoolIfNotExists(pools_t& pools, const string& poolName)
{
  std::shared_ptr<ServerPool> pool;
  pools_t::iterator it = pools.find(poolName);
  if (it != pools.end()) {
    pool = it->second;
  }
  else {
    if (!poolName.empty())
      vinfolog("Creating pool %s", poolName);
    pool = std::make_shared<ServerPool>();
    pools.insert(std::pair<std::string,std::shared_ptr<ServerPool> >(poolName, pool));
  }
  return pool;
}

void setPoolPolicy(pools_t& pools, const string& poolName, std::shared_ptr<ServerPolicy> policy)
{
  std::shared_ptr<ServerPool> pool = createPoolIfNotExists(pools, poolName);
  if (!poolName.empty()) {
    vinfolog("Setting pool %s server selection policy to %s", poolName, policy->name);
  } else {
    vinfolog("Setting default pool server selection policy to %s", policy->name);
  }
  pool->policy = policy;
}

void addServerToPool(pools_t& pools, const string& poolName, std::shared_ptr<DownstreamState> server)
{
  std::shared_ptr<ServerPool> pool = createPoolIfNotExists(pools, poolName);
  unsigned int count = (unsigned int) pool->servers.size();
  if (!poolName.empty()) {
    vinfolog("Adding server to pool %s", poolName);
  } else {
    vinfolog("Adding server to default pool");
  }
  pool->servers.push_back(make_pair(++count, server));
  /* we need to reorder based on the server 'order' */
  std::stable_sort(pool->servers.begin(), pool->servers.end(), [](const std::pair<unsigned int,std::shared_ptr<DownstreamState> >& a, const std::pair<unsigned int,std::shared_ptr<DownstreamState> >& b) {
      return a.second->order < b.second->order;
    });
  /* and now we need to renumber for Lua (custom policies) */
  size_t idx = 1;
  for (auto& serv : pool->servers) {
    serv.first = idx++;
  }
}

void removeServerFromPool(pools_t& pools, const string& poolName, std::shared_ptr<DownstreamState> server)
{
  std::shared_ptr<ServerPool> pool = getPool(pools, poolName);

  if (!poolName.empty()) {
    vinfolog("Removing server from pool %s", poolName);
  }
  else {
    vinfolog("Removing server from default pool");
  }

  size_t idx = 1;
  bool found = false;
  for (NumberedVector<shared_ptr<DownstreamState> >::iterator it = pool->servers.begin(); it != pool->servers.end();) {
    if (found) {
      /* we need to renumber the servers placed
         after the removed one, for Lua (custom policies) */
      it->first = idx++;
      it++;
    }
    else if (it->second == server) {
      it = pool->servers.erase(it);
      found = true;
    } else {
      idx++;
      it++;
    }
  }
}

std::shared_ptr<ServerPool> getPool(const pools_t& pools, const std::string& poolName)
{
  pools_t::const_iterator it = pools.find(poolName);

  if (it == pools.end()) {
    throw std::out_of_range("No pool named " + poolName);
  }

  return it->second;
}

const NumberedServerVector& getDownstreamCandidates(const pools_t& pools, const std::string& poolName)
{
  std::shared_ptr<ServerPool> pool = getPool(pools, poolName);
  return pool->servers;
}

// goal in life - if you send us a reasonably normal packet, we'll get Z for you, otherwise 0
int getEDNSZ(const char* packet, unsigned int len)
try
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
catch(...)
{
  return 0;
}

static void spoofResponseFromString(DNSQuestion& dq, const string& spoofContent)
{
  string result;

  std::vector<std::string> addrs;
  stringtok(addrs, spoofContent, " ,");

  if (addrs.size() == 1) {
    try {
      ComboAddress spoofAddr(spoofContent);
      SpoofAction sa({spoofAddr});
      sa(&dq, &result);
    }
    catch(const PDNSException &e) {
      SpoofAction sa(spoofContent); // CNAME then
      sa(&dq, &result);
    }
  } else {
    std::vector<ComboAddress> cas;
    for (const auto& addr : addrs) {
      try {
        cas.push_back(ComboAddress(addr));
      }
      catch (...) {
      }
    }
    SpoofAction sa(cas);
    sa(&dq, &result);
  }
}

bool processQuery(LocalHolders& holders, DNSQuestion& dq, string& poolname, int* delayMsec, const struct timespec& now)
{
  {
    WriteLock wl(&g_rings.queryLock);
    g_rings.queryRing.push_back({now,*dq.remote,*dq.qname,dq.len,dq.qtype,*dq.dh});
  }

  if(g_qcount.enabled) {
    string qname = (*dq.qname).toString(".");
    bool countQuery{true};
    if(g_qcount.filter) {
      std::lock_guard<std::mutex> lock(g_luamutex);
      std::tie (countQuery, qname) = g_qcount.filter(dq);
    }

    if(countQuery) {
      WriteLock wl(&g_qcount.queryLock);
      if(!g_qcount.records.count(qname)) {
        g_qcount.records[qname] = 0;
      }
      g_qcount.records[qname]++;
    }
  }

  if(auto got = holders.dynNMGBlock->lookup(*dq.remote)) {
    auto updateBlockStats = [&got]() {
      g_stats.dynBlocked++;
      got->second.blocks++;
    };

    if(now < got->second.until) {
      DNSAction::Action action = got->second.action;
      if (action == DNSAction::Action::None) {
        action = g_dynBlockAction;
      }
      if (action == DNSAction::Action::Refused) {
        vinfolog("Query from %s refused because of dynamic block", dq.remote->toStringWithPort());
        updateBlockStats();
      
        dq.dh->rcode = RCode::Refused;
        dq.dh->qr=true;
        return true;
      }
      else if (action == DNSAction::Action::Truncate) {
        if(!dq.tcp) {
          updateBlockStats();
          vinfolog("Query from %s truncated because of dynamic block", dq.remote->toStringWithPort());
          dq.dh->tc = true;
          dq.dh->qr = true;
          return true;
        }
        else {
          vinfolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toString());
        }

      }
      else {
        updateBlockStats();
        vinfolog("Query from %s dropped because of dynamic block", dq.remote->toStringWithPort());
        return false;
      }
    }
  }

  if(auto got = holders.dynSMTBlock->lookup(*dq.qname)) {
    auto updateBlockStats = [&got]() {
      g_stats.dynBlocked++;
      got->blocks++;
    };

    if(now < got->until) {
      DNSAction::Action action = got->action;
      if (action == DNSAction::Action::None) {
        action = g_dynBlockAction;
      }
      if (action == DNSAction::Action::Refused) {
        vinfolog("Query from %s for %s refused because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toString());
        updateBlockStats();

        dq.dh->rcode = RCode::Refused;
        dq.dh->qr=true;
        return true;
      }
      else if (action == DNSAction::Action::Truncate) {
        if(!dq.tcp) {
          updateBlockStats();
      
          vinfolog("Query from %s for %s truncated because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toString());
          dq.dh->tc = true;
          dq.dh->qr = true;
          return true;
        }
        else {
          vinfolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toString());
        }
      }
      else {
        updateBlockStats();
        vinfolog("Query from %s for %s dropped because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toString());
        return false;
      }
    }
  }

  DNSAction::Action action=DNSAction::Action::None;
  string ruleresult;
  for(const auto& lr : *holders.rulactions) {
    if(lr.first->matches(&dq)) {
      lr.first->d_matches++;
      action=(*lr.second)(&dq, &ruleresult);

      switch(action) {
      case DNSAction::Action::Allow:
        return true;
        break;
      case DNSAction::Action::Drop:
        g_stats.ruleDrop++;
        return false;
        break;
      case DNSAction::Action::Nxdomain:
        dq.dh->rcode = RCode::NXDomain;
        dq.dh->qr=true;
        g_stats.ruleNXDomain++;
        return true;
        break;
      case DNSAction::Action::Refused:
        dq.dh->rcode = RCode::Refused;
        dq.dh->qr=true;
        g_stats.ruleRefused++;
        return true;
        break;
      case DNSAction::Action::Spoof:
        spoofResponseFromString(dq, ruleresult);
        return true;
        break;
      case DNSAction::Action::Truncate:
        dq.dh->tc = true;
        dq.dh->qr = true;
        return true;
        break;
      case DNSAction::Action::HeaderModify:
        return true;
        break;
      case DNSAction::Action::Pool:
        poolname=ruleresult;
        return true;
        break;
        /* non-terminal actions follow */
      case DNSAction::Action::Delay:
        *delayMsec = static_cast<int>(pdns_stou(ruleresult)); // sorry
        break;
      case DNSAction::Action::None:
        break;
      }
    }
  }

  return true;
}

bool processResponse(LocalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSResponseAction> > > >& localRespRulactions, DNSResponse& dr, int* delayMsec)
{
  DNSResponseAction::Action action=DNSResponseAction::Action::None;
  std::string ruleresult;
  for(const auto& lr : *localRespRulactions) {
    if(lr.first->matches(&dr)) {
      lr.first->d_matches++;
      action=(*lr.second)(&dr, &ruleresult);
      switch(action) {
      case DNSResponseAction::Action::Allow:
        return true;
        break;
      case DNSResponseAction::Action::Drop:
        return false;
        break;
      case DNSResponseAction::Action::HeaderModify:
        return true;
        break;
        /* non-terminal actions follow */
      case DNSResponseAction::Action::Delay:
        *delayMsec = static_cast<int>(pdns_stou(ruleresult)); // sorry
        break;
      case DNSResponseAction::Action::None:
        break;
      }
    }
  }

  return true;
}

static ssize_t udpClientSendRequestToBackend(DownstreamState* ss, const int sd, const char* request, const size_t requestLen)
{
  ssize_t result;

  if (ss->sourceItf == 0) {
    result = send(sd, request, requestLen, 0);
  }
  else {
    struct msghdr msgh;
    struct iovec iov;
    char cbuf[256];
    fillMSGHdr(&msgh, &iov, cbuf, sizeof(cbuf), const_cast<char*>(request), requestLen, &ss->remote);
    addCMsgSrcAddr(&msgh, cbuf, &ss->sourceAddr, ss->sourceItf);
    result = sendmsg(sd, &msgh, 0);
  }

  if (result == -1) {
    int savederrno = errno;
    vinfolog("Error sending request to backend %s: %d", ss->remote.toStringWithPort(), savederrno);

    /* This might sound silly, but on Linux send() might fail with EINVAL
       if the interface the socket was bound to doesn't exist anymore. */
    if (savederrno == EINVAL) {
      ss->reconnect();
    }
  }

  return result;
}

static bool isUDPQueryAcceptable(ClientState& cs, LocalHolders& holders, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest)
{
  if (msgh->msg_flags & MSG_TRUNC) {
    /* message was too large for our buffer */
    vinfolog("Dropping message too large for our buffer");
    g_stats.nonCompliantQueries++;
    return false;
  }

  if(!holders.acl->match(remote)) {
    vinfolog("Query from %s dropped because of ACL", remote.toStringWithPort());
    g_stats.aclDrops++;
    return false;
  }

  cs.queries++;
  g_stats.queries++;

  if (HarvestDestinationAddress(msgh, &dest)) {
    /* we don't get the port, only the address */
    dest.sin4.sin_port = cs.local.sin4.sin_port;
  }
  else {
    dest.sin4.sin_family = 0;
  }

  return true;
}

#ifdef HAVE_DNSCRYPT
static bool checkDNSCryptQuery(const ClientState& cs, const char* query, uint16_t& len, std::shared_ptr<DnsCryptQuery>& dnsCryptQuery, const ComboAddress& dest, const ComboAddress& remote)
{
  if (cs.dnscryptCtx) {
    vector<uint8_t> response;
    uint16_t decryptedQueryLen = 0;

    dnsCryptQuery = std::make_shared<DnsCryptQuery>();

    bool decrypted = handleDnsCryptQuery(cs.dnscryptCtx, const_cast<char*>(query), len, dnsCryptQuery, &decryptedQueryLen, false, response);

    if (!decrypted) {
      if (response.size() > 0) {
        sendUDPResponse(cs.udpFD, reinterpret_cast<char*>(response.data()), static_cast<uint16_t>(response.size()), 0, dest, remote);
      }
      return false;
    }

    len = decryptedQueryLen;
  }
  return true;
}
#endif /* HAVE_DNSCRYPT */

bool checkQueryHeaders(const struct dnsheader* dh)
{
  if (dh->qr) {   // don't respond to responses
    g_stats.nonCompliantQueries++;
    return false;
  }

  if (dh->qdcount == 0) {
    g_stats.emptyQueries++;
    return false;
  }

  if (dh->rd) {
    g_stats.rdQueries++;
  }

  return true;
}

#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
static void queueResponse(const ClientState& cs, const char* response, uint16_t responseLen, const ComboAddress& dest, const ComboAddress& remote, struct mmsghdr& outMsg, struct iovec* iov, char* cbuf)
{
  outMsg.msg_len = 0;
  fillMSGHdr(&outMsg.msg_hdr, iov, nullptr, 0, const_cast<char*>(response), responseLen, const_cast<ComboAddress*>(&remote));

  if (dest.sin4.sin_family == 0) {
    outMsg.msg_hdr.msg_control = nullptr;
  }
  else {
    addCMsgSrcAddr(&outMsg.msg_hdr, cbuf, &dest, 0);
  }
}
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */

static void processUDPQuery(ClientState& cs, LocalHolders& holders, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, char* query, uint16_t len, size_t queryBufferSize, struct mmsghdr* responsesVect, unsigned int* queuedResponses, struct iovec* respIOV, char* respCBuf)
{
  assert(responsesVect == nullptr || (queuedResponses != nullptr && respIOV != nullptr && respCBuf != nullptr));
  uint16_t queryId = 0;

  try {
    if (!isUDPQueryAcceptable(cs, holders, msgh, remote, dest)) {
      return;
    }

#ifdef HAVE_DNSCRYPT
    std::shared_ptr<DnsCryptQuery> dnsCryptQuery = nullptr;

    if (!checkDNSCryptQuery(cs, query, len, dnsCryptQuery, dest, remote)) {
      return;
    }
#endif

    struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query);
    queryId = ntohs(dh->id);

    if (!checkQueryHeaders(dh)) {
      return;
    }

    const uint16_t * flags = getFlagsFromDNSHeader(dh);
    const uint16_t origFlags = *flags;
    uint16_t qtype, qclass;
    unsigned int consumed = 0;
    DNSName qname(query, len, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dq(&qname, qtype, qclass, dest.sin4.sin_family != 0 ? &dest : &cs.local, &remote, dh, queryBufferSize, len, false);

    string poolname;
    int delayMsec = 0;
    /* we need an accurate ("real") value for the response and
       to store into the IDS, but not for insertion into the
       rings for example */
    struct timespec realTime;
    struct timespec now;
    gettime(&now);
    gettime(&realTime, true);

    if (!processQuery(holders, dq, poolname, &delayMsec, now))
    {
      return;
    }

    if(dq.dh->qr) { // something turned it into a response
      g_stats.selfAnswered++;
      restoreFlags(dh, origFlags);

      if (!cs.muted) {
        char* response = query;
        uint16_t responseLen = dq.len;

#ifdef HAVE_DNSCRYPT
        if (!encryptResponse(response, &responseLen, dq.size, false, dnsCryptQuery, nullptr, nullptr)) {
          return;
        }
#endif
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
        if (delayMsec == 0 && responsesVect != nullptr) {
          queueResponse(cs, response, responseLen, dest, remote, responsesVect[*queuedResponses], respIOV, respCBuf);
          (*queuedResponses)++;
        }
        else
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
        {
          sendUDPResponse(cs.udpFD, response, responseLen, delayMsec, dest, remote);
        }
      }

      return;
    }

    DownstreamState* ss = nullptr;
    std::shared_ptr<ServerPool> serverPool = getPool(*holders.pools, poolname);
    std::shared_ptr<DNSDistPacketCache> packetCache = nullptr;
    auto policy = holders.policy->policy;
    if (serverPool->policy != nullptr) {
      policy = serverPool->policy->policy;
    }
    {
      std::lock_guard<std::mutex> lock(g_luamutex);
      ss = policy(serverPool->servers, &dq).get();
      packetCache = serverPool->packetCache;
    }

    bool ednsAdded = false;
    bool ecsAdded = false;
    if (dq.useECS && ss && ss->useECS) {
      if (!handleEDNSClientSubnet(query, dq.size, consumed, &dq.len, &(ednsAdded), &(ecsAdded), remote, dq.ecsOverride, dq.ecsPrefixLength)) {
        vinfolog("Dropping query from %s because we couldn't insert the ECS value", remote.toStringWithPort());
        return;
      }
    }

    uint32_t cacheKey = 0;
    if (packetCache && !dq.skipCache) {
      uint16_t cachedResponseSize = dq.size;
      uint32_t allowExpired = ss ? 0 : g_staleCacheEntriesTTL;
      if (packetCache->get(dq, consumed, dh->id, query, &cachedResponseSize, &cacheKey, allowExpired)) {
        DNSResponse dr(dq.qname, dq.qtype, dq.qclass, dq.local, dq.remote, reinterpret_cast<dnsheader*>(query), dq.size, cachedResponseSize, false, &realTime);
#ifdef HAVE_PROTOBUF
        dr.uniqueId = dq.uniqueId;
#endif
        if (!processResponse(holders.cacheHitRespRulactions, dr, &delayMsec)) {
          return;
        }

        if (!cs.muted) {
#ifdef HAVE_DNSCRYPT
          if (!encryptResponse(query, &cachedResponseSize, dq.size, false, dnsCryptQuery, nullptr, nullptr)) {
            return;
          }
#endif
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
          if (delayMsec == 0 && responsesVect != nullptr) {
            queueResponse(cs, query, cachedResponseSize, dest, remote, responsesVect[*queuedResponses], respIOV, respCBuf);
            (*queuedResponses)++;
          }
          else
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
          {
            sendUDPResponse(cs.udpFD, query, cachedResponseSize, delayMsec, dest, remote);
          }
        }

        g_stats.cacheHits++;
        g_stats.latency0_1++;  // we're not going to measure this
        doLatencyAverages(0);  // same
        return;
      }
      g_stats.cacheMisses++;
    }

    if(!ss) {
      g_stats.noPolicy++;

      if (g_servFailOnNoPolicy && !cs.muted) {
        char* response = query;
        uint16_t responseLen = dq.len;
        restoreFlags(dh, origFlags);

        dq.dh->rcode = RCode::ServFail;
        dq.dh->qr = true;

#ifdef HAVE_DNSCRYPT
        if (!encryptResponse(response, &responseLen, dq.size, false, dnsCryptQuery, nullptr, nullptr)) {
          return;
        }
#endif
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
        if (responsesVect != nullptr) {
          queueResponse(cs, response, responseLen, dest, remote, responsesVect[*queuedResponses], respIOV, respCBuf);
          (*queuedResponses)++;
        }
        else
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
        {
          sendUDPResponse(cs.udpFD, response, responseLen, 0, dest, remote);
        }
      }
      vinfolog("%s query for %s|%s from %s, no policy applied", g_servFailOnNoPolicy ? "ServFailed" : "Dropped", dq.qname->toString(), QType(dq.qtype).getName(), remote.toStringWithPort());
      return;
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

    ids->cs = &cs;
    ids->origFD = cs.udpFD;
    ids->origID = dh->id;
    ids->origRemote = remote;
    ids->sentTime.set(realTime);
    ids->qname = qname;
    ids->qtype = dq.qtype;
    ids->qclass = dq.qclass;
    ids->delayMsec = delayMsec;
    ids->origFlags = origFlags;
    ids->cacheKey = cacheKey;
    ids->skipCache = dq.skipCache;
    ids->packetCache = packetCache;
    ids->ednsAdded = ednsAdded;
    ids->ecsAdded = ecsAdded;

    /* If we couldn't harvest the real dest addr, still
       write down the listening addr since it will be useful
       (especially if it's not an 'any' one).
       We need to keep track of which one it is since we may
       want to use the real but not the listening addr to reply.
    */
    if (dest.sin4.sin_family != 0) {
      ids->origDest = dest;
      ids->destHarvested = true;
    }
    else {
      ids->origDest = cs.local;
      ids->destHarvested = false;
    }
#ifdef HAVE_DNSCRYPT
    ids->dnsCryptQuery = dnsCryptQuery;
#endif
#ifdef HAVE_PROTOBUF
    ids->uniqueId = dq.uniqueId;
#endif

    dh->id = idOffset;

    ssize_t ret = udpClientSendRequestToBackend(ss, ss->fd, query, dq.len);

    if(ret < 0) {
      ss->sendErrors++;
      g_stats.downstreamSendErrors++;
    }

    vinfolog("Got query for %s|%s from %s, relayed to %s", ids->qname.toString(), QType(ids->qtype).getName(), remote.toStringWithPort(), ss->getName());
  }
  catch(const std::exception& e){
    vinfolog("Got an error in UDP question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
  }
}

#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
static void MultipleMessagesUDPClientThread(ClientState* cs, LocalHolders& holders)
{
  struct MMReceiver
  {
    char packet[4096];
    /* used by HarvestDestinationAddress */
    char cbuf[256];
    ComboAddress remote;
    ComboAddress dest;
    struct iovec iov;
  };
  const size_t vectSize = g_udpVectorSize;
  /* the actual buffer is larger because:
     - we may have to add EDNS and/or ECS
     - we use it for self-generated responses (from rule or cache)
     but we only accept incoming payloads up to that size
  */
  static_assert(s_udpIncomingBufferSize <= sizeof(MMReceiver::packet), "the incoming buffer size should not be larger than sizeof(MMReceiver::packet)");

  auto recvData = std::unique_ptr<MMReceiver[]>(new MMReceiver[vectSize]);
  auto msgVec = std::unique_ptr<struct mmsghdr[]>(new struct mmsghdr[vectSize]);
  auto outMsgVec = std::unique_ptr<struct mmsghdr[]>(new struct mmsghdr[vectSize]);

  /* initialize the structures needed to receive our messages */
  for (size_t idx = 0; idx < vectSize; idx++) {
    recvData[idx].remote.sin4.sin_family = cs->local.sin4.sin_family;
    fillMSGHdr(&msgVec[idx].msg_hdr, &recvData[idx].iov, recvData[idx].cbuf, sizeof(recvData[idx].cbuf), recvData[idx].packet, s_udpIncomingBufferSize, &recvData[idx].remote);
  }

  /* go now */
  for(;;) {

    /* reset the IO vector, since it's also used to send the vector of responses
       to avoid having to copy the data around */
    for (size_t idx = 0; idx < vectSize; idx++) {
      recvData[idx].iov.iov_base = recvData[idx].packet;
      recvData[idx].iov.iov_len = sizeof(recvData[idx].packet);
    }

    /* block until we have at least one message ready, but return
       as many as possible to save the syscall costs */
    int msgsGot = recvmmsg(cs->udpFD, msgVec.get(), vectSize, MSG_WAITFORONE | MSG_TRUNC, nullptr);

    if (msgsGot <= 0) {
      vinfolog("Getting UDP messages via recvmmsg() failed with: %s", strerror(errno));
      continue;
    }

    unsigned int msgsToSend = 0;

    /* process the received messages */
    for (int msgIdx = 0; msgIdx < msgsGot; msgIdx++) {
      const struct msghdr* msgh = &msgVec[msgIdx].msg_hdr;
      unsigned int got = msgVec[msgIdx].msg_len;
      const ComboAddress& remote = recvData[msgIdx].remote;

      if (got < sizeof(struct dnsheader)) {
        g_stats.nonCompliantQueries++;
        continue;
      }

      processUDPQuery(*cs, holders, msgh, remote, recvData[msgIdx].dest, recvData[msgIdx].packet, static_cast<uint16_t>(got), sizeof(recvData[msgIdx].packet), outMsgVec.get(), &msgsToSend, &recvData[msgIdx].iov, recvData[msgIdx].cbuf);

    }

    /* immediate (not delayed or sent to a backend) responses (mostly from a rule, dynamic block
       or the cache) can be sent in batch too */

    if (msgsToSend > 0 && msgsToSend <= static_cast<unsigned int>(msgsGot)) {
      int sent = sendmmsg(cs->udpFD, outMsgVec.get(), msgsToSend, 0);

      if (sent < 0 || static_cast<unsigned int>(sent) != msgsToSend) {
        vinfolog("Error sending responses with sendmmsg() (%d on %u): %s", sent, msgsToSend, strerror(errno));
      }
    }

  }
}
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */

// listens to incoming queries, sends out to downstream servers, noting the intended return path
static void* udpClientThread(ClientState* cs)
try
{
  LocalHolders holders;

#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
  if (g_udpVectorSize > 1) {
    MultipleMessagesUDPClientThread(cs, holders);

  }
  else
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
  {
    char packet[4096];
    /* the actual buffer is larger because:
       - we may have to add EDNS and/or ECS
       - we use it for self-generated responses (from rule or cache)
       but we only accept incoming payloads up to that size
    */
    static_assert(s_udpIncomingBufferSize <= sizeof(packet), "the incoming buffer size should not be larger than sizeof(MMReceiver::packet)");
    struct msghdr msgh;
    struct iovec iov;
    /* used by HarvestDestinationAddress */
    char cbuf[256];

    ComboAddress remote;
    ComboAddress dest;
    remote.sin4.sin_family = cs->local.sin4.sin_family;
    fillMSGHdr(&msgh, &iov, cbuf, sizeof(cbuf), packet, sizeof(packet), &remote);

    for(;;) {
      ssize_t got = recvmsg(cs->udpFD, &msgh, 0);

      if (got < 0 || static_cast<size_t>(got) < sizeof(struct dnsheader)) {
        g_stats.nonCompliantQueries++;
        continue;
      }

      processUDPQuery(*cs, holders, &msgh, remote, dest, packet, static_cast<uint16_t>(got), s_udpIncomingBufferSize, nullptr, nullptr, nullptr, nullptr);
    }
  }

  return nullptr;
}
catch(const std::exception &e)
{
  errlog("UDP client thread died because of exception: %s", e.what());
  return nullptr;
}
catch(const PDNSException &e)
{
  errlog("UDP client thread died because of PowerDNS exception: %s", e.reason);
  return nullptr;
}
catch(...)
{
  errlog("UDP client thread died because of an exception: %s", "unknown");
  return nullptr;
}

static bool upCheck(DownstreamState& ds)
try
{
  vector<uint8_t> packet;
  DNSPacketWriter dpw(packet, ds.checkName, ds.checkType.getCode());
  dnsheader * requestHeader = dpw.getHeader();
  requestHeader->rd=true;
  if (ds.setCD) {
    requestHeader->cd = true;
  }

  Socket sock(ds.remote.sin4.sin_family, SOCK_DGRAM);
  sock.setNonBlocking();
  if (!IsAnyAddress(ds.sourceAddr)) {
    sock.setReuseAddr();
    sock.bind(ds.sourceAddr);
  }
  sock.connect(ds.remote);
  ssize_t sent = udpClientSendRequestToBackend(&ds, sock.getHandle(), (char*)&packet[0], packet.size());
  if (sent < 0) {
    int ret = errno;
    if (g_verboseHealthChecks)
      infolog("Error while sending a health check query to backend %s: %d", ds.getNameWithAddr(), ret);
    return false;
  }

  int ret=waitForRWData(sock.getHandle(), true, 1, 0);
  if(ret < 0 || !ret) { // error, timeout, both are down!
    if (ret < 0) {
      ret = errno;
      if (g_verboseHealthChecks)
        infolog("Error while waiting for the health check response from backend %s: %d", ds.getNameWithAddr(), ret);
    }
    else {
      if (g_verboseHealthChecks)
        infolog("Timeout while waiting for the health check response from backend %s", ds.getNameWithAddr());
    }
    return false;
  }

  string reply;
  sock.recvFrom(reply, ds.remote);

  const dnsheader * responseHeader = (const dnsheader *) reply.c_str();

  if (reply.size() < sizeof(*responseHeader)) {
    if (g_verboseHealthChecks)
      infolog("Invalid health check response of size %d from backend %s, expecting at least %d", reply.size(), ds.getNameWithAddr(), sizeof(*responseHeader));
    return false;
  }

  if (responseHeader->id != requestHeader->id) {
    if (g_verboseHealthChecks)
      infolog("Invalid health check response id %d from backend %s, expecting %d", responseHeader->id, ds.getNameWithAddr(), requestHeader->id);
    return false;
  }

  if (!responseHeader->qr) {
    if (g_verboseHealthChecks)
      infolog("Invalid health check response from backend %s, expecting QR to be set", ds.getNameWithAddr());
    return false;
  }

  if (responseHeader->rcode == RCode::ServFail) {
    if (g_verboseHealthChecks)
      infolog("Backend %s responded to health check with ServFail", ds.getNameWithAddr());
    return false;
  }

  if (ds.mustResolve && (responseHeader->rcode == RCode::NXDomain || responseHeader->rcode == RCode::Refused)) {
    if (g_verboseHealthChecks)
      infolog("Backend %s responded to health check with %s while mustResolve is set", ds.getNameWithAddr(), responseHeader->rcode == RCode::NXDomain ? "NXDomain" : "Refused");
    return false;
  }

  // XXX fixme do bunch of checking here etc 
  return true;
}
catch(const std::exception& e)
{
  if (g_verboseHealthChecks)
    infolog("Error checking the health of backend %s: %s", ds.getNameWithAddr(), e.what());
  return false;
}
catch(...)
{
  if (g_verboseHealthChecks)
    infolog("Unknown exception while checking the health of backend %s", ds.getNameWithAddr());
  return false;
}

uint64_t g_maxTCPClientThreads{10};
std::atomic<uint16_t> g_cacheCleaningDelay{60};
std::atomic<uint16_t> g_cacheCleaningPercentage{100};

void* maintThread()
{
  int interval = 1;
  size_t counter = 0;
  int32_t secondsToWaitLog = 0;

  for(;;) {
    sleep(interval);

    {
      std::lock_guard<std::mutex> lock(g_luamutex);
      auto f = g_lua.readVariable<boost::optional<std::function<void()> > >("maintenance");
      if(f) {
        try {
          (*f)();
          secondsToWaitLog = 0;
        }
        catch(std::exception &e) {
          if (secondsToWaitLog <= 0) {
            infolog("Error during execution of maintenance function: %s", e.what());
            secondsToWaitLog = 61;
          }
          secondsToWaitLog -= interval;
        }
      }
    }

    counter++;
    if (counter >= g_cacheCleaningDelay) {
      const auto localPools = g_pools.getCopy();
      std::shared_ptr<DNSDistPacketCache> packetCache = nullptr;
      for (const auto& entry : localPools) {
        {
          std::lock_guard<std::mutex> lock(g_luamutex);
          packetCache = entry.second->packetCache;
        }
        if (packetCache) {
          size_t upTo = (packetCache->getMaxEntries()* (100 - g_cacheCleaningPercentage)) / 100;
          packetCache->purgeExpired(upTo);
        }
      }
      counter = 0;
    }

    // ponder pruning g_dynblocks of expired entries here
  }
  return 0;
}

void* healthChecksThread()
{
  int interval = 1;

  for(;;) {
    sleep(interval);

    if(g_tcpclientthreads->getQueuedCount() > 1 && !g_tcpclientthreads->hasReachedMaxThreads())
      g_tcpclientthreads->addTCPClientThread();

    for(auto& dss : g_dstates.getCopy()) { // this points to the actual shared_ptrs!
      if(dss->availability==DownstreamState::Availability::Auto) {
        bool newState=upCheck(*dss);
        if (newState) {
          if (dss->currentCheckFailures != 0) {
            dss->currentCheckFailures = 0;
          }
        }
        else if (!newState && dss->upStatus) {
          dss->currentCheckFailures++;
          if (dss->currentCheckFailures < dss->maxCheckFailures) {
            newState = true;
          }
        }

        if(newState != dss->upStatus) {
          warnlog("Marking downstream %s as '%s'", dss->getNameWithAddr(), newState ? "up" : "down");

          if (newState && !dss->connected) {
            try {
              SConnect(dss->fd, dss->remote);
              dss->connected = true;
              dss->tid = thread(responderThread, dss);
            }
            catch(const std::runtime_error& error) {
              infolog("Error connecting to new server with address %s: %s", dss->remote.toStringWithPort(), error.what());
              newState = false;
              dss->connected = false;
            }
          }

          dss->upStatus = newState;
          dss->currentCheckFailures = 0;
          if (g_snmpAgent && g_snmpTrapsEnabled) {
            g_snmpAgent->sendBackendStatusChangeTrap(dss);
          }
        }
      }

      auto delta = dss->sw.udiffAndSet()/1000000.0;
      dss->queryLoad = 1.0*(dss->queries.load() - dss->prev.queries.load())/delta;
      dss->dropRate = 1.0*(dss->reuseds.load() - dss->prev.reuseds.load())/delta;
      dss->prev.queries.store(dss->queries.load());
      dss->prev.reuseds.store(dss->reuseds.load());
      
      for(IDState& ids  : dss->idStates) { // timeouts
        if(ids.origFD >=0 && ids.age++ > g_udpTimeout) {
          /* We set origFD to -1 as soon as possible
             to limit the risk of racing with the
             responder thread.
             The UDP client thread only checks origFD to
             know whether outstanding has to be incremented,
             so the sooner the better any way since we _will_
             decrement it.
          */
          ids.origFD = -1;
          ids.age = 0;
          dss->reuseds++;
          --dss->outstanding;
          g_stats.downstreamTimeouts++; // this is an 'actively' discovered timeout
          vinfolog("Had a downstream timeout from %s (%s) for query for %s|%s from %s",
                   dss->remote.toStringWithPort(), dss->name,
                   ids.qname.toString(), QType(ids.qtype).getName(), ids.origRemote.toStringWithPort());

          struct timespec ts;
          gettime(&ts);

          struct dnsheader fake;
          memset(&fake, 0, sizeof(fake));
          fake.id = ids.origID;

          std::lock_guard<std::mutex> lock(g_rings.respMutex);
          g_rings.respRing.push_back({ts, ids.origRemote, ids.qname, ids.qtype, std::numeric_limits<unsigned int>::max(), 0, fake, dss->remote});
        }          
      }
    }
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
    if (g_logConsoleConnections) {
      warnlog("Got control connection from %s", client.toStringWithPort());
    }

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

static void checkFileDescriptorsLimits(size_t udpBindsCount, size_t tcpBindsCount)
{
  /* stdin, stdout, stderr */
  size_t requiredFDsCount = 3;
  size_t backendsCount = g_dstates.getCopy().size();
  /* listening sockets */
  requiredFDsCount += udpBindsCount;
  requiredFDsCount += tcpBindsCount;
  /* max TCP connections currently served */
  requiredFDsCount += g_maxTCPClientThreads;
  /* max pipes for communicating between TCP acceptors and client threads */
  requiredFDsCount += (g_maxTCPClientThreads * 2);
  /* UDP sockets to backends */
  requiredFDsCount += backendsCount;
  /* TCP sockets to backends */
  requiredFDsCount += (backendsCount * g_maxTCPClientThreads);
  /* max TCP queued connections */
  requiredFDsCount += g_maxTCPQueuedConnections;
  /* DelayPipe pipe */
  requiredFDsCount += 2;
  /* syslog socket */
  requiredFDsCount++;
  /* webserver main socket */
  requiredFDsCount++;
  /* console main socket */
  requiredFDsCount++;
  /* carbon export */
  requiredFDsCount++;
  /* history file */
  requiredFDsCount++;
  struct rlimit rl;
  getrlimit(RLIMIT_NOFILE, &rl);
  if (rl.rlim_cur <= requiredFDsCount) {
    warnlog("Warning, this configuration can use more than %d file descriptors, web server and console connections not included, and the current limit is %d.", std::to_string(requiredFDsCount), std::to_string(rl.rlim_cur));
#ifdef HAVE_SYSTEMD
    warnlog("You can increase this value by using LimitNOFILE= in the systemd unit file or ulimit.");
#else
    warnlog("You can increase this value by using ulimit.");
#endif
  }
}

struct 
{
  vector<string> locals;
  vector<string> remotes;
  bool checkConfig{false};
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
  size_t udpBindsCount = 0;
  size_t tcpBindsCount = 0;
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
  ComboAddress clientAddress = ComboAddress();
  g_cmdLine.config=SYSCONFDIR "/dnsdist.conf";
  struct option longopts[]={ 
    {"acl", required_argument, 0, 'a'},
    {"config", required_argument, 0, 'C'},
    {"check-config", 0, 0, 1},
    {"execute", required_argument, 0, 'e'},
    {"client", 0, 0, 'c'},
    {"gid",  required_argument, 0, 'g'},
#ifdef HAVE_LIBSODIUM
    {"setkey",  required_argument, 0, 'k'},
#endif
    {"local",  required_argument, 0, 'l'},
    {"daemon", 0, 0, 'd'},
    {"pidfile",  required_argument, 0, 'p'},
    {"supervised", 0, 0, 's'},
    {"disable-syslog", 0, 0, 2},
    {"uid",  required_argument, 0, 'u'},
    {"verbose", 0, 0, 'v'},
    {"version", 0, 0, 'V'},
    {"help", 0, 0, 'h'},
    {0,0,0,0} 
  };
  int longindex=0;
  string optstring;
  for(;;) {
#ifdef HAVE_LIBSODIUM
    int c=getopt_long(argc, argv, "a:hcde:C:k:l:vp:g:u:V", longopts, &longindex);
#else
    int c=getopt_long(argc, argv, "a:hcde:C:l:vp:g:u:V", longopts, &longindex);
#endif
    if(c==-1)
      break;
    switch(c) {
    case 1:
      g_cmdLine.checkConfig=true;
      break;
    case 2:
      g_syslog=false;
      break;
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
      cout<<"Syntax: dnsdist [-C,--config file] [-c,--client [IP[:PORT]]] [-d,--daemon]\n";
      cout<<"[-p,--pidfile file] [-e,--execute cmd] [-h,--help] [-l,--local addr]\n";
      cout<<"[-v,--verbose] [--check-config]\n";
      cout<<"\n";
      cout<<"-a,--acl netmask      Add this netmask to the ACL\n";
      cout<<"-C,--config file      Load configuration from 'file'\n";
      cout<<"-c,--client           Operate as a client, connect to dnsdist. This reads\n";
      cout<<"                      controlSocket from your configuration file, but also\n";
      cout<<"                      accepts an IP:PORT argument\n";
#ifdef HAVE_LIBSODIUM
      cout<<"-k,--setkey KEY       Use KEY for encrypted communication to dnsdist. This\n";
      cout<<"                      is similar to setting setKey in the configuration file.\n";
      cout<<"                      NOTE: this will leak this key in your shell's history!\n";
#endif
      cout<<"--check-config        Validate the configuration file and exit. The exit-code\n";
      cout<<"                      reflects the validation, 0 is OK, 1 means an error.\n";
      cout<<"                      Any errors are printed as well.\n";
      cout<<"-d,--daemon           Operate as a daemon\n";
      cout<<"-e,--execute cmd      Connect to dnsdist and execute 'cmd'\n";
      cout<<"-g,--gid gid          Change the process group ID after binding sockets\n";
      cout<<"-h,--help             Display this helpful message\n";
      cout<<"-l,--local address    Listen on this local address\n";
      cout<<"--supervised          Don't open a console, I'm supervised\n";
      cout<<"                        (use with e.g. systemd and daemontools)\n";
      cout<<"--disable-syslog      Don't log to syslog, only to stdout\n";
      cout<<"                        (use with e.g. systemd)\n";
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
#ifdef HAVE_LIBSODIUM
    case 'k':
      if (B64Decode(string(optarg), g_key) < 0) {
        cerr<<"Unable to decode key '"<<optarg<<"'."<<endl;
        exit(EXIT_FAILURE);
      }
      break;
#endif
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
#ifdef LUAJIT_VERSION
      cout<<"dnsdist "<<VERSION<<" ("<<LUA_RELEASE<<" ["<<LUAJIT_VERSION<<"])"<<endl;
#else
      cout<<"dnsdist "<<VERSION<<" ("<<LUA_RELEASE<<")"<<endl;
#endif
      cout<<"Enabled features: ";
#ifdef HAVE_DNSCRYPT
      cout<<"dnscrypt ";
#endif
#ifdef HAVE_EBPF
      cout<<"ebpf ";
#endif
#ifdef HAVE_LIBSODIUM
      cout<<"libsodium ";
#endif
#ifdef HAVE_PROTOBUF
      cout<<"protobuf ";
#endif
#ifdef HAVE_RE2
      cout<<"re2 ";
#endif
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
      cout<<"recvmmsg/sendmmsg ";
#endif
#ifdef HAVE_NET_SNMP
      cout<<"snmp ";
#endif
#ifdef HAVE_SYSTEMD
      cout<<"systemd";
#endif
      cout<<endl;
      exit(EXIT_SUCCESS);
      break;
    }
  }

  argc-=optind;
  argv+=optind;
  for(auto p = argv; *p; ++p) {
    if(g_cmdLine.beClient) {
      clientAddress = ComboAddress(*p, 5199);
    } else {
      g_cmdLine.remotes.push_back(*p);
    }
  }

  ServerPolicy leastOutstandingPol{"leastOutstanding", leastOutstanding};

  g_policy.setState(leastOutstandingPol);
  if(g_cmdLine.beClient || !g_cmdLine.command.empty()) {
    setupLua(true, g_cmdLine.config);
    if (clientAddress != ComboAddress())
      g_serverControl = clientAddress;
    doClient(g_serverControl, g_cmdLine.command);
    _exit(EXIT_SUCCESS);
  }

  auto acl = g_ACL.getCopy();
  if(acl.empty()) {
    for(auto& addr : {"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"})
      acl.addMask(addr);
    g_ACL.setState(acl);
  }

  if (g_cmdLine.checkConfig) {
    setupLua(true, g_cmdLine.config);
    // No exception was thrown
    infolog("Configuration '%s' OK!", g_cmdLine.config);
    _exit(EXIT_SUCCESS);
  }

  auto todo=setupLua(false, g_cmdLine.config);

  if(g_cmdLine.locals.size()) {
    g_locals.clear();
    for(auto loc : g_cmdLine.locals)
      g_locals.push_back(std::make_tuple(ComboAddress(loc, 53), true, false, 0, "", std::set<int>()));
  }
  
  if(g_locals.empty())
    g_locals.push_back(std::make_tuple(ComboAddress("127.0.0.1", 53), true, false, 0, "", std::set<int>()));

  g_configurationDone = true;

  vector<ClientState*> toLaunch;
  for(const auto& local : g_locals) {
    ClientState* cs = new ClientState;
    cs->local= std::get<0>(local);
    cs->udpFD = SSocket(cs->local.sin4.sin_family, SOCK_DGRAM, 0);
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
    //if(g_vm.count("bind-non-local"))
    bindAny(cs->local.sin4.sin_family, cs->udpFD);

    //    if (!setSocketTimestamps(cs->udpFD))
    //      L<<Logger::Warning<<"Unable to enable timestamp reporting for socket"<<endl;


    if(IsAnyAddress(cs->local)) {
      int one=1;
      setsockopt(cs->udpFD, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one));     // linux supports this, so why not - might fail on other systems
#ifdef IPV6_RECVPKTINFO
      setsockopt(cs->udpFD, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
#endif
    }

    if (std::get<2>(local)) {
#ifdef SO_REUSEPORT
      SSetsockopt(cs->udpFD, SOL_SOCKET, SO_REUSEPORT, 1);
#else
      warnlog("SO_REUSEPORT has been configured on local address '%s' but is not supported", std::get<0>(local).toStringWithPort());
#endif
    }

    const std::string& itf = std::get<4>(local);
    if (!itf.empty()) {
#ifdef SO_BINDTODEVICE
      int res = setsockopt(cs->udpFD, SOL_SOCKET, SO_BINDTODEVICE, itf.c_str(), itf.length());
      if (res != 0) {
        warnlog("Error setting up the interface on local address '%s': %s", std::get<0>(local).toStringWithPort(), strerror(errno));
      }
#else
      warnlog("An interface has been configured on local address '%s' but SO_BINDTODEVICE is not supported", std::get<0>(local).toStringWithPort());
#endif
    }

#ifdef HAVE_EBPF
    if (g_defaultBPFFilter) {
      cs->attachFilter(g_defaultBPFFilter);
      vinfolog("Attaching default BPF Filter to UDP frontend %s", cs->local.toStringWithPort());
    }
#endif /* HAVE_EBPF */

    cs->cpus = std::get<5>(local);

    SBind(cs->udpFD, cs->local);
    toLaunch.push_back(cs);
    g_frontends.push_back(cs);
    udpBindsCount++;
  }

  for(const auto& local : g_locals) {
    if(!std::get<1>(local)) { // no TCP/IP
      warnlog("Not providing TCP/IP service on local address '%s'", std::get<0>(local).toStringWithPort());
      continue;
    }
    ClientState* cs = new ClientState;
    cs->local= std::get<0>(local);

    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);

    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(cs->tcpFD, SOL_TCP,TCP_DEFER_ACCEPT, 1);
#endif
    if (std::get<3>(local) > 0) {
#ifdef TCP_FASTOPEN
      SSetsockopt(cs->tcpFD, IPPROTO_TCP, TCP_FASTOPEN, std::get<3>(local));
#else
      warnlog("TCP Fast Open has been configured on local address '%s' but is not supported", std::get<0>(local).toStringWithPort());
#endif
    }
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->tcpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
#ifdef SO_REUSEPORT
    /* no need to warn again if configured but support is not available, we already did for UDP */
    if (std::get<2>(local)) {
      SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEPORT, 1);
    }
#endif

    const std::string& itf = std::get<4>(local);
    if (!itf.empty()) {
#ifdef SO_BINDTODEVICE
      int res = setsockopt(cs->tcpFD, SOL_SOCKET, SO_BINDTODEVICE, itf.c_str(), itf.length());
      if (res != 0) {
        warnlog("Error setting up the interface on local address '%s': %s", std::get<0>(local).toStringWithPort(), strerror(errno));
      }
#else
      warnlog("An interface has been configured on local address '%s' but SO_BINDTODEVICE is not supported", std::get<0>(local).toStringWithPort());
#endif
    }

#ifdef HAVE_EBPF
    if (g_defaultBPFFilter) {
      cs->attachFilter(g_defaultBPFFilter);
      vinfolog("Attaching default BPF Filter to TCP frontend %s", cs->local.toStringWithPort());
    }
#endif /* HAVE_EBPF */

    //    if(g_vm.count("bind-non-local"))
      bindAny(cs->local.sin4.sin_family, cs->tcpFD);
    SBind(cs->tcpFD, cs->local);
    SListen(cs->tcpFD, 64);
    warnlog("Listening on %s", cs->local.toStringWithPort());

    toLaunch.push_back(cs);
    g_frontends.push_back(cs);
    tcpBindsCount++;
  }

#ifdef HAVE_DNSCRYPT
  for(auto& dcLocal : g_dnsCryptLocals) {
    ClientState* cs = new ClientState;
    cs->local = std::get<0>(dcLocal);
    cs->dnscryptCtx = &(std::get<1>(dcLocal));
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
    if (std::get<2>(dcLocal)) {
#ifdef SO_REUSEPORT
      SSetsockopt(cs->udpFD, SOL_SOCKET, SO_REUSEPORT, 1);
#else
      warnlog("SO_REUSEPORT has been configured on local address '%s' but is not supported", std::get<0>(dcLocal).toStringWithPort());
#endif
    }

    const std::string& itf = std::get<4>(dcLocal);
    if (!itf.empty()) {
#ifdef SO_BINDTODEVICE
      int res = setsockopt(cs->udpFD, SOL_SOCKET, SO_BINDTODEVICE, itf.c_str(), itf.length());
      if (res != 0) {
        warnlog("Error setting up the interface on local address '%s': %s", std::get<0>(dcLocal).toStringWithPort(), strerror(errno));
      }
#else
      warnlog("An interface has been configured on local address '%s' but SO_BINDTODEVICE is not supported", std::get<0>(dcLocal).toStringWithPort());
#endif
    }

#ifdef HAVE_EBPF
    if (g_defaultBPFFilter) {
      cs->attachFilter(g_defaultBPFFilter);
      vinfolog("Attaching default BPF Filter to UDP DNSCrypt frontend %s", cs->local.toStringWithPort());
    }
#endif /* HAVE_EBPF */
    SBind(cs->udpFD, cs->local);    
    toLaunch.push_back(cs);
    g_frontends.push_back(cs);
    udpBindsCount++;

    cs = new ClientState;
    cs->local = std::get<0>(dcLocal);
    cs->dnscryptCtx = &(std::get<1>(dcLocal));
    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);
    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(cs->tcpFD, SOL_TCP,TCP_DEFER_ACCEPT, 1);
#endif
    if (std::get<3>(dcLocal) > 0) {
#ifdef TCP_FASTOPEN
      SSetsockopt(cs->tcpFD, IPPROTO_TCP, TCP_FASTOPEN, std::get<3>(dcLocal));
#else
      warnlog("TCP Fast Open has been configured on local address '%s' but is not supported", std::get<0>(dcLocal).toStringWithPort());
#endif
    }

#ifdef SO_REUSEPORT
    /* no need to warn again if configured but support is not available, we already did for UDP */
    if (std::get<2>(dcLocal)) {
      SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEPORT, 1);
    }
#endif

    if (!itf.empty()) {
#ifdef SO_BINDTODEVICE
      int res = setsockopt(cs->tcpFD, SOL_SOCKET, SO_BINDTODEVICE, itf.c_str(), itf.length());
      if (res != 0) {
        warnlog("Error setting up the interface on local address '%s': %s", std::get<0>(dcLocal).toStringWithPort(), strerror(errno));
      }
#else
      warnlog("An interface has been configured on local address '%s' but SO_BINDTODEVICE is not supported", std::get<0>(dcLocal).toStringWithPort());
#endif
    }

    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->tcpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }
#ifdef HAVE_EBPF
    if (g_defaultBPFFilter) {
      cs->attachFilter(g_defaultBPFFilter);
      vinfolog("Attaching default BPF Filter to TCP DNSCrypt frontend %s", cs->local.toStringWithPort());
    }
#endif /* HAVE_EBPF */

    cs->cpus = std::get<5>(dcLocal);

    bindAny(cs->local.sin4.sin_family, cs->tcpFD);
    SBind(cs->tcpFD, cs->local);
    SListen(cs->tcpFD, 64);
    warnlog("Listening on %s", cs->local.toStringWithPort());
    toLaunch.push_back(cs);
    g_frontends.push_back(cs);
    tcpBindsCount++;
  }
#endif

  if(g_cmdLine.beDaemon) {
    g_console=false;
    daemonize();
    writepid(g_cmdLine.pidfile);
  }
  else {
    vinfolog("Running in the foreground");
    warnlog("dnsdist %s comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2", VERSION);
    vector<string> vec;
    std::string acls;
    g_ACL.getCopy().toStringVector(&vec);
    for(const auto& s : vec) {
      if (!acls.empty())
        acls += ", ";
      acls += s;
    }
    infolog("ACL allowing queries from: %s", acls.c_str());
  }

  uid_t newgid=0;
  gid_t newuid=0;

  if(!g_cmdLine.gid.empty())
    newgid = strToGID(g_cmdLine.gid.c_str());

  if(!g_cmdLine.uid.empty())
    newuid = strToUID(g_cmdLine.uid.c_str());

  dropGroupPrivs(newgid);
  dropUserPrivs(newuid);

  /* this need to be done _after_ dropping privileges */
  g_delay = new DelayPipe<DelayedPacket>();

  if (g_snmpAgent) {
    g_snmpAgent->run();
  }

  g_tcpclientthreads = std::make_shared<TCPClientCollection>(g_maxTCPClientThreads, g_useTCPSinglePipe);

  for(auto& t : todo)
    t();

  auto localPools = g_pools.getCopy();
  /* create the default pool no matter what */
  createPoolIfNotExists(localPools, "");
  if(g_cmdLine.remotes.size()) {
    for(const auto& address : g_cmdLine.remotes) {
      auto ret=std::make_shared<DownstreamState>(ComboAddress(address, 53));
      addServerToPool(localPools, "", ret);
      if (ret->connected) {
        ret->tid = thread(responderThread, ret);
      }
      g_dstates.modify([ret](servers_t& servers) { servers.push_back(ret); });
    }
  }
  g_pools.setState(localPools);

  if(g_dstates.getCopy().empty()) {
    errlog("No downstream servers defined: all packets will get dropped");
    // you might define them later, but you need to know
  }

  checkFileDescriptorsLimits(udpBindsCount, tcpBindsCount);

  for(auto& dss : g_dstates.getCopy()) { // it is a copy, but the internal shared_ptrs are the real deal
    if(dss->availability==DownstreamState::Availability::Auto) {
      bool newState=upCheck(*dss);
      warnlog("Marking downstream %s as '%s'", dss->getNameWithAddr(), newState ? "up" : "down");
      dss->upStatus = newState;
    }
  }

  for(auto& cs : toLaunch) {
    if (cs->udpFD >= 0) {
      thread t1(udpClientThread, cs);
      if (!cs->cpus.empty()) {
        mapThreadToCPUList(t1.native_handle(), cs->cpus);
      }
      t1.detach();
    }
    else if (cs->tcpFD >= 0) {
      thread t1(tcpAcceptorThread, cs);
      if (!cs->cpus.empty()) {
        mapThreadToCPUList(t1.native_handle(), cs->cpus);
      }
      t1.detach();
    }
  }

  thread carbonthread(carbonDumpThread);
  carbonthread.detach();

  thread stattid(maintThread);
  stattid.detach();
  
  thread healththread(healthChecksThread);

  if(g_cmdLine.beDaemon || g_cmdLine.beSupervised) {
#ifdef HAVE_SYSTEMD
    sd_notify(0, "READY=1");
#endif
    healththread.join();
  }
  else {
    healththread.detach();
    doConsole();
  }
  _exit(EXIT_SUCCESS);

}
catch(const LuaContext::ExecutionErrorException& e) {
  try {
    errlog("Fatal Lua error: %s", e.what());
    std::rethrow_if_nested(e);
  } catch(const std::exception& ne) {
    errlog("Details: %s", ne.what());
  }
  catch(PDNSException &ae)
  {
    errlog("Fatal pdns error: %s", ae.reason);
  }
  _exit(EXIT_FAILURE);
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
