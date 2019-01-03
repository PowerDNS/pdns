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

#include "config.h"

#include <fstream>
#include <getopt.h>
#include <grp.h>
#include <limits>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/resource.h>
#include <unistd.h>

#if defined (__OpenBSD__) || defined(__NetBSD__)
#include <readline/readline.h>
#else
#include <editline/readline.h>
#endif

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "dnsdist.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-console.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-secpoll.hh"
#include "dnsdist-xpf.hh"

#include "base64.hh"
#include "delaypipe.hh"
#include "dolog.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "gettime.hh"
#include "lock.hh"
#include "misc.hh"
#include "sodcrypto.hh"
#include "sstuff.hh"
#include "threadname.hh"

thread_local boost::uuids::random_generator t_uuidGenerator;

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
MetricDefinitionStorage g_metricDefinitions;

uint16_t g_maxOutstanding{10240};
bool g_verboseHealthChecks{false};
uint32_t g_staleCacheEntriesTTL{0};
bool g_syslog{true};

GlobalStateHolder<NetmaskGroup> g_ACL;
string g_outputBuffer;

vector<std::tuple<ComboAddress, bool, bool, int, string, std::set<int>>> g_locals;
std::vector<std::shared_ptr<TLSFrontend>> g_tlslocals;
#ifdef HAVE_DNSCRYPT
std::vector<std::tuple<ComboAddress,std::shared_ptr<DNSCryptContext>,bool, int, string, std::set<int> >> g_dnsCryptLocals;
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

GlobalStateHolder<vector<DNSDistRuleAction> > g_rulactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_resprulactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_cachehitresprulactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_selfansweredresprulactions;

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
bool g_fixupCase{false};
bool g_preserveTrailingData{false};

static void truncateTC(char* packet, uint16_t* len, size_t responseSize, unsigned int consumed)
try
{
  bool hadEDNS = false;
  uint16_t payloadSize = 0;
  uint16_t z = 0;

  if (g_addEDNSToSelfGeneratedResponses) {
    hadEDNS = getEDNSUDPPayloadSizeAndZ(packet, *len, &payloadSize, &z);
  }

  *len=(uint16_t) (sizeof(dnsheader)+consumed+DNS_TYPE_SIZE+DNS_CLASS_SIZE);
  struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(packet);
  dh->ancount = dh->arcount = dh->nscount = 0;

  if (hadEDNS) {
    addEDNS(dh, *len, responseSize, z & EDNS_HEADER_FLAG_DO, payloadSize);
  }
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

void doLatencyStats(double udiff)
{
  if(udiff < 1000) ++g_stats.latency0_1;
  else if(udiff < 10000) ++g_stats.latency1_10;
  else if(udiff < 50000) ++g_stats.latency10_50;
  else if(udiff < 100000) ++g_stats.latency50_100;
  else if(udiff < 1000000) ++g_stats.latency100_1000;
  else ++g_stats.latencySlow;

  auto doAvg = [](double& var, double n, double weight) {
    var = (weight -1) * var/weight + n/weight;
  };

  doAvg(g_stats.latencyAvg100,     udiff,     100);
  doAvg(g_stats.latencyAvg1000,    udiff,    1000);
  doAvg(g_stats.latencyAvg10000,   udiff,   10000);
  doAvg(g_stats.latencyAvg1000000, udiff, 1000000);
}

bool responseContentMatches(const char* response, const uint16_t responseLen, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& remote, unsigned int& consumed)
{
  uint16_t rqtype, rqclass;
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
      ++g_stats.nonCompliantResponses;
      return false;
    }
  }

  try {
    rqname=DNSName(response, responseLen, sizeof(dnsheader), false, &rqtype, &rqclass, &consumed);
  }
  catch(std::exception& e) {
    if(responseLen > (ssize_t)sizeof(dnsheader))
      infolog("Backend %s sent us a response with id %d that did not parse: %s", remote.toStringWithPort(), ntohs(dh->id), e.what());
    ++g_stats.nonCompliantResponses;
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

bool fixUpQueryTurnedResponse(DNSQuestion& dq, const uint16_t origFlags)
{
  restoreFlags(dq.dh, origFlags);

  return addEDNSToQueryTurnedResponse(dq);
}

bool fixUpResponse(char** response, uint16_t* responseLen, size_t* responseSize, const DNSName& qname, uint16_t origFlags, bool ednsAdded, bool ecsAdded, std::vector<uint8_t>& rewrittenResponse, uint16_t addRoom, bool* zeroScope)
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
    uint16_t optStart;
    size_t optLen = 0;
    bool last = false;

    const std::string responseStr(*response, *responseLen);
    int res = locateEDNSOptRR(responseStr, &optStart, &optLen, &last);

    if (res == 0) {
      if (zeroScope) { // this finds if an EDNS Client Subnet scope was set, and if it is 0
        size_t optContentStart = 0;
        uint16_t optContentLen = 0;
        /* we need at least 4 bytes after the option length (family: 2, source prefix-length: 1, scope prefix-length: 1) */
        if (isEDNSOptionInOpt(responseStr, optStart, optLen, EDNSOptionCode::ECS, &optContentStart, &optContentLen) && optContentLen >= 4) {
          /* see if the EDNS Client Subnet SCOPE PREFIX-LENGTH byte in position 3 is set to 0, which is the only thing
             we care about. */
          *zeroScope = responseStr.at(optContentStart + 3) == 0;
        }
      }

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
          if (rewriteResponseWithoutEDNS(responseStr, rewrittenResponse) == 0) {
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
          removeEDNSOptionFromOPT(*response + optStart, &optLen, EDNSOptionCode::ECS);
          *responseLen -= (existingOptLen - optLen);
        }
        else {
          /* Removing an intermediary RR could lead to compression error */
          if (rewriteResponseWithoutEDNSOption(responseStr, EDNSOptionCode::ECS, rewrittenResponse) == 0) {
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
bool encryptResponse(char* response, uint16_t* responseLen, size_t responseSize, bool tcp, std::shared_ptr<DNSCryptQuery> dnsCryptQuery, dnsheader** dh, dnsheader* dhCopy)
{
  if (dnsCryptQuery) {
    uint16_t encryptedResponseLen = 0;

    /* save the original header before encrypting it in place */
    if (dh != nullptr && *dh != nullptr && dhCopy != nullptr) {
      memcpy(dhCopy, *dh, sizeof(dnsheader));
      *dh = dhCopy;
    }

    int res = dnsCryptQuery->encryptResponse(response, *responseLen, responseSize, tcp, &encryptedResponseLen);
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


static int pickBackendSocketForSending(DownstreamState* state)
{
  return state->sockets[state->socketsOffset++ % state->sockets.size()];
}

static void pickBackendSocketsReadyForReceiving(const std::shared_ptr<DownstreamState>& state, std::vector<int>& ready)
{
  ready.clear();

  if (state->sockets.size() == 1) {
    ready.push_back(state->sockets[0]);
    return ;
  }

  {
    std::lock_guard<std::mutex> lock(state->socketsLock);
    state->mplexer->getAvailableFDs(ready, -1);
  }
}

// listens on a dedicated socket, lobs answers from downstream servers to original requestors
void responderThread(std::shared_ptr<DownstreamState> dss)
try {
  setThreadName("dnsdist/respond");
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
  std::vector<int> sockets;
  sockets.reserve(dss->sockets.size());

  for(;;) {
    dnsheader* dh = reinterpret_cast<struct dnsheader*>(packet);
    try {
      pickBackendSocketsReadyForReceiving(dss, sockets);
      for (const auto& fd : sockets) {
        ssize_t got = recv(fd, packet, sizeof(packet), 0);
        char * response = packet;
        size_t responseSize = sizeof(packet);

        if (got < (ssize_t) sizeof(dnsheader))
          continue;

        uint16_t responseLen = (uint16_t) got;
        queryId = dh->id;

        if(queryId >= dss->idStates.size())
          continue;

        IDState* ids = &dss->idStates[queryId];
        int origFD = ids->origFD;

        if(origFD < 0) // duplicate
          continue;

        /* setting age to 0 to prevent the maintainer thread from
           cleaning this IDS while we process the response.
           We have already a copy of the origFD, so it would
           mostly mess up the outstanding counter.
        */
        ids->age = 0;

        unsigned int consumed = 0;
        if (!responseContentMatches(response, responseLen, ids->qname, ids->qtype, ids->qclass, dss->remote, consumed)) {
          continue;
        }

        int oldFD = ids->origFD.exchange(-1);
        if (oldFD == origFD) {
          /* we only decrement the outstanding counter if the value was not
             altered in the meantime, which would mean that the state has been actively reused
             and the other thread has not incremented the outstanding counter, so we don't
             want it to be decremented twice. */
          --dss->outstanding;  // you'd think an attacker could game this, but we're using connected socket
        }

        if(dh->tc && g_truncateTC) {
          truncateTC(response, &responseLen, responseSize, consumed);
        }

        dh->id = ids->origID;

        uint16_t addRoom = 0;
        DNSResponse dr(&ids->qname, ids->qtype, ids->qclass, consumed, &ids->origDest, &ids->origRemote, dh, sizeof(packet), responseLen, false, &ids->sentTime.d_start);
#ifdef HAVE_PROTOBUF
        dr.uniqueId = ids->uniqueId;
#endif
        dr.qTag = ids->qTag;

        if (!processResponse(localRespRulactions, dr, &ids->delayMsec)) {
          continue;
        }

#ifdef HAVE_DNSCRYPT
        if (ids->dnsCryptQuery) {
          addRoom = DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
        }
#endif
        bool zeroScope = false;
        if (!fixUpResponse(&response, &responseLen, &responseSize, ids->qname, ids->origFlags, ids->ednsAdded, ids->ecsAdded, rewrittenResponse, addRoom, ids->useZeroScope ? &zeroScope : nullptr)) {
          continue;
        }

        if (ids->packetCache && !ids->skipCache) {
          if (!ids->useZeroScope) {
            /* if the query was not suitable for zero-scope, for
               example because it had an existing ECS entry so the hash is
               not really 'no ECS', so just insert it for the existing subnet
               since:
               - we don't have the correct hash for a non-ECS query
               - inserting with hash computed before the ECS replacement but with
               the subnet extracted _after_ the replacement would not work.
            */
            zeroScope = false;
          }
          // if zeroScope, pass the pre-ECS hash-key and do not pass the subnet to the cache
          ids->packetCache->insert(zeroScope ? ids->cacheKeyNoECS : ids->cacheKey, zeroScope ? boost::none : ids->subnet, ids->origFlags, ids->dnssecOK, ids->qname, ids->qtype, ids->qclass, response, responseLen, false, dh->rcode, ids->tempFailureTTL);
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

        ++g_stats.responses;

        double udiff = ids->sentTime.udiff();
        vinfolog("Got answer from %s, relayed to %s, took %f usec", dss->remote.toStringWithPort(), ids->origRemote.toStringWithPort(), udiff);

        struct timespec ts;
        gettime(&ts);
        g_rings.insertResponse(ts, ids->origRemote, ids->qname, ids->qtype, (unsigned int)udiff, (unsigned int)got, *dh, dss->remote);

        if(dh->rcode == RCode::ServFail) {
          ++g_stats.servfailResponses;
        }
        dss->latencyUsec = (127.0 * dss->latencyUsec / 128.0) + udiff/128.0;

        doLatencyStats(udiff);

        /* if the FD is not -1, the state has been actively reused and we should
           not alter anything */
        if (ids->origFD == -1) {
#ifdef HAVE_DNSCRYPT
          ids->dnsCryptQuery = nullptr;
#endif
        }

        rewrittenResponse.clear();
      }
    }
    catch(const std::exception& e){
      vinfolog("Got an error in UDP responder thread while parsing a response from %s, id %d: %s", dss->remote.toStringWithPort(), queryId, e.what());
    }
  }
}
catch(const std::exception& e)
{
  errlog("UDP responder thread died because of exception: %s", e.what());
}
catch(const PDNSException& e)
{
  errlog("UDP responder thread died because of PowerDNS exception: %s", e.reason);
}
catch(...)
{
  errlog("UDP responder thread died because of an exception: %s", "unknown");
}

bool DownstreamState::reconnect()
{
  std::unique_lock<std::mutex> tl(connectLock, std::try_to_lock);
  if (!tl.owns_lock()) {
    /* we are already reconnecting */
    return false;
  }

  connected = false;
  for (auto& fd : sockets) {
    if (fd != -1) {
      if (sockets.size() > 1) {
        std::lock_guard<std::mutex> lock(socketsLock);
        mplexer->removeReadFD(fd);
      }
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
        if (sockets.size() > 1) {
          std::lock_guard<std::mutex> lock(socketsLock);
          mplexer->addReadFD(fd, [](int, boost::any) {});
        }
        connected = true;
      }
      catch(const std::runtime_error& error) {
        infolog("Error connecting to new server with address %s: %s", remote.toStringWithPort(), error.what());
        connected = false;
        break;
      }
    }
  }

  /* if at least one (re-)connection failed, close all sockets */
  if (!connected) {
    for (auto& fd : sockets) {
      if (fd != -1) {
        if (sockets.size() > 1) {
          std::lock_guard<std::mutex> lock(socketsLock);
          mplexer->removeReadFD(fd);
        }
        /* shutdown() is needed to wake up recv() in the responderThread */
        shutdown(fd, SHUT_RDWR);
        close(fd);
        fd = -1;
      }
    }
  }

  return connected;
}
void DownstreamState::hash()
{
  vinfolog("Computing hashes for id=%s and weight=%d", id, weight);
  auto w = weight;
  WriteLock wl(&d_lock);
  hashes.clear();
  while (w > 0) {
    std::string uuid = boost::str(boost::format("%s-%d") % id % w);
    unsigned int wshash = burtleCI((const unsigned char*)uuid.c_str(), uuid.size(), g_hashperturb);
    hashes.insert(wshash);
    --w;
  }
}

void DownstreamState::setId(const boost::uuids::uuid& newId)
{
  id = newId;
  // compute hashes only if already done
  if (!hashes.empty()) {
    hash();
  }
}

void DownstreamState::setWeight(int newWeight)
{
  if (newWeight < 1) {
    errlog("Error setting server's weight: downstream weight value must be greater than 0.");
    return ;
  }
  weight = newWeight;
  if (!hashes.empty()) {
    hash();
  }
}

DownstreamState::DownstreamState(const ComboAddress& remote_, const ComboAddress& sourceAddr_, unsigned int sourceItf_, size_t numberOfSockets): remote(remote_), sourceAddr(sourceAddr_), sourceItf(sourceItf_)
{
  pthread_rwlock_init(&d_lock, nullptr);
  id = t_uuidGenerator();
  threadStarted.clear();

  mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());

  sockets.resize(numberOfSockets);
  for (auto& fd : sockets) {
    fd = -1;
  }

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
  int sum = 0;
  int max = std::numeric_limits<int>::max();

  for(auto& d : servers) {      // w=1, w=10 -> 1, 11
    if(d.second->isUp()) {
      // Don't overflow sum when adding high weights
      if(d.second->weight > max - sum) {
        sum = max;
      } else {
        sum += d.second->weight;
      }

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

shared_ptr<DownstreamState> chashed(const NumberedServerVector& servers, const DNSQuestion* dq)
{
  unsigned int qhash = dq->qname->hash(g_hashperturb);
  unsigned int sel = std::numeric_limits<unsigned int>::max();
  unsigned int min = std::numeric_limits<unsigned int>::max();
  shared_ptr<DownstreamState> ret = nullptr, first = nullptr;

  for (const auto& d: servers) {
    if (d.second->isUp()) {
      // make sure hashes have been computed
      if (d.second->hashes.empty()) {
        d.second->hash();
      }
      {
        ReadLock rl(&(d.second->d_lock));
        const auto& server = d.second;
        // we want to keep track of the last hash
        if (min > *(server->hashes.begin())) {
          min = *(server->hashes.begin());
          first = server;
        }

        auto hash_it = server->hashes.lower_bound(qhash);
        if (hash_it != server->hashes.end()) {
          if (*hash_it < sel) {
            sel = *hash_it;
            ret = server;
          }
        }
      }
    }
  }
  if (ret != nullptr) {
    return ret;
  }
  if (first != nullptr) {
    return first;
  }
  return shared_ptr<DownstreamState>();
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
  if (!poolName.empty()) {
    vinfolog("Adding server to pool %s", poolName);
  } else {
    vinfolog("Adding server to default pool");
  }
  pool->addServer(server);
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

  pool->removeServer(server);
}

std::shared_ptr<ServerPool> getPool(const pools_t& pools, const std::string& poolName)
{
  pools_t::const_iterator it = pools.find(poolName);

  if (it == pools.end()) {
    throw std::out_of_range("No pool named " + poolName);
  }

  return it->second;
}

NumberedServerVector getDownstreamCandidates(const pools_t& pools, const std::string& poolName)
{
  std::shared_ptr<ServerPool> pool = getPool(pools, poolName);
  return pool->getServers();
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
  g_rings.insertQuery(now,*dq.remote,*dq.qname,dq.qtype,dq.len,*dq.dh);

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
      ++g_stats.dynBlocked;
      got->second.blocks++;
    };

    if(now < got->second.until) {
      DNSAction::Action action = got->second.action;
      if (action == DNSAction::Action::None) {
        action = g_dynBlockAction;
      }
      switch (action) {
      case DNSAction::Action::NoOp:
        /* do nothing */
        break;

      case DNSAction::Action::Nxdomain:
        vinfolog("Query from %s turned into NXDomain because of dynamic block", dq.remote->toStringWithPort());
        updateBlockStats();

        dq.dh->rcode = RCode::NXDomain;
        dq.dh->qr=true;
        return true;

      case DNSAction::Action::Refused:
        vinfolog("Query from %s refused because of dynamic block", dq.remote->toStringWithPort());
        updateBlockStats();
      
        dq.dh->rcode = RCode::Refused;
        dq.dh->qr = true;
        return true;

      case DNSAction::Action::Truncate:
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
        break;
      case DNSAction::Action::NoRecurse:
        updateBlockStats();
        vinfolog("Query from %s setting rd=0 because of dynamic block", dq.remote->toStringWithPort());
        dq.dh->rd = false;
        return true;
      default:
        updateBlockStats();
        vinfolog("Query from %s dropped because of dynamic block", dq.remote->toStringWithPort());
        return false;
      }
    }
  }

  if(auto got = holders.dynSMTBlock->lookup(*dq.qname)) {
    auto updateBlockStats = [&got]() {
      ++g_stats.dynBlocked;
      got->blocks++;
    };

    if(now < got->until) {
      DNSAction::Action action = got->action;
      if (action == DNSAction::Action::None) {
        action = g_dynBlockAction;
      }
      switch (action) {
      case DNSAction::Action::NoOp:
        /* do nothing */
        break;
      case DNSAction::Action::Nxdomain:
        vinfolog("Query from %s for %s turned into NXDomain because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toString());
        updateBlockStats();

        dq.dh->rcode = RCode::NXDomain;
        dq.dh->qr=true;
        return true;
      case DNSAction::Action::Refused:
        vinfolog("Query from %s for %s refused because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toString());
        updateBlockStats();

        dq.dh->rcode = RCode::Refused;
        dq.dh->qr=true;
        return true;
      case DNSAction::Action::Truncate:
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
        break;
      case DNSAction::Action::NoRecurse:
        updateBlockStats();
        vinfolog("Query from %s setting rd=0 because of dynamic block", dq.remote->toStringWithPort());
        dq.dh->rd = false;
        return true;
      default:
        updateBlockStats();
        vinfolog("Query from %s for %s dropped because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toString());
        return false;
      }
    }
  }

  DNSAction::Action action=DNSAction::Action::None;
  string ruleresult;
  for(const auto& lr : *holders.rulactions) {
    if(lr.d_rule->matches(&dq)) {
      lr.d_rule->d_matches++;
      action=(*lr.d_action)(&dq, &ruleresult);

      switch(action) {
      case DNSAction::Action::Allow:
        return true;
        break;
      case DNSAction::Action::Drop:
        ++g_stats.ruleDrop;
        return false;
        break;
      case DNSAction::Action::Nxdomain:
        dq.dh->rcode = RCode::NXDomain;
        dq.dh->qr=true;
        ++g_stats.ruleNXDomain;
        return true;
        break;
      case DNSAction::Action::Refused:
        dq.dh->rcode = RCode::Refused;
        dq.dh->qr=true;
        ++g_stats.ruleRefused;
        return true;
        break;
      case DNSAction::Action::ServFail:
        dq.dh->rcode = RCode::ServFail;
        dq.dh->qr=true;
        ++g_stats.ruleServFail;
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
        /* fall-through */
      case DNSAction::Action::NoOp:
        break;
      case DNSAction::Action::NoRecurse:
        dq.dh->rd = false;
        return true;
        break;
      }
    }
  }

  return true;
}

bool processResponse(LocalStateHolder<vector<DNSDistResponseRuleAction> >& localRespRulactions, DNSResponse& dr, int* delayMsec)
{
  DNSResponseAction::Action action=DNSResponseAction::Action::None;
  std::string ruleresult;
  for(const auto& lr : *localRespRulactions) {
    if(lr.d_rule->matches(&dr)) {
      lr.d_rule->d_matches++;
      action=(*lr.d_action)(&dr, &ruleresult);
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
      case DNSResponseAction::Action::ServFail:
        dr.dh->rcode = RCode::ServFail;
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

static ssize_t udpClientSendRequestToBackend(DownstreamState* ss, const int sd, const char* request, const size_t requestLen, bool healthCheck=false)
{
  ssize_t result;

  if (ss->sourceItf == 0) {
    result = send(sd, request, requestLen, 0);
  }
  else {
    struct msghdr msgh;
    struct iovec iov;
    char cbuf[256];
    ComboAddress remote(ss->remote);
    fillMSGHdr(&msgh, &iov, cbuf, sizeof(cbuf), const_cast<char*>(request), requestLen, &remote);
    addCMsgSrcAddr(&msgh, cbuf, &ss->sourceAddr, ss->sourceItf);
    result = sendmsg(sd, &msgh, 0);
  }

  if (result == -1) {
    int savederrno = errno;
    vinfolog("Error sending request to backend %s: %d", ss->remote.toStringWithPort(), savederrno);

    /* This might sound silly, but on Linux send() might fail with EINVAL
       if the interface the socket was bound to doesn't exist anymore.
       We don't want to reconnect the real socket if the healthcheck failed,
       because it's not using the same socket.
    */
    if (!healthCheck && (savederrno == EINVAL || savederrno == ENODEV)) {
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
    ++g_stats.nonCompliantQueries;
    return false;
  }

  if(!holders.acl->match(remote)) {
    vinfolog("Query from %s dropped because of ACL", remote.toStringWithPort());
    ++g_stats.aclDrops;
    return false;
  }

  cs.queries++;
  ++g_stats.queries;

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
static bool checkDNSCryptQuery(const ClientState& cs, const char* query, uint16_t& len, std::shared_ptr<DNSCryptQuery>& dnsCryptQuery, const ComboAddress& dest, const ComboAddress& remote, time_t now)
{
  if (cs.dnscryptCtx) {
    vector<uint8_t> response;
    uint16_t decryptedQueryLen = 0;

    dnsCryptQuery = std::make_shared<DNSCryptQuery>(cs.dnscryptCtx);

    bool decrypted = handleDNSCryptQuery(const_cast<char*>(query), len, dnsCryptQuery, &decryptedQueryLen, false, now, response);

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
    ++g_stats.nonCompliantQueries;
    return false;
  }

  if (dh->qdcount == 0) {
    ++g_stats.emptyQueries;
    return false;
  }

  if (dh->rd) {
    ++g_stats.rdQueries;
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

static int sendAndEncryptUDPResponse(LocalHolders& holders, ClientState& cs, const DNSQuestion& dq, char* response, uint16_t responseLen, std::shared_ptr<DNSCryptQuery>& dnsCryptQuery, int delayMsec, const ComboAddress& dest, struct mmsghdr* responsesVect, unsigned int* queuedResponses, struct iovec* respIOV, char* respCBuf, bool cacheHit)
{
  DNSResponse dr(dq.qname, dq.qtype, dq.qclass, dq.consumed, dq.local, dq.remote, reinterpret_cast<dnsheader*>(response), dq.size, responseLen, false, dq.queryTime);
#ifdef HAVE_PROTOBUF
  dr.uniqueId = dq.uniqueId;
#endif
  dr.qTag = dq.qTag;

  if (!processResponse(cacheHit ? holders.cacheHitRespRulactions : holders.selfAnsweredRespRulactions, dr, &delayMsec)) {
    return -1;
  }

  if (!cs.muted) {
#ifdef HAVE_DNSCRYPT
    if (!encryptResponse(response, &responseLen, dq.size, false, dnsCryptQuery, nullptr, nullptr)) {
      return -1;
    }
#endif
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
    if (delayMsec == 0 && responsesVect != nullptr) {
      queueResponse(cs, response, responseLen, dest, *dq.remote, responsesVect[*queuedResponses], respIOV, respCBuf);
      (*queuedResponses)++;
    }
    else
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
      {
        sendUDPResponse(cs.udpFD, response, responseLen, delayMsec, dest, *dq.remote);
      }
  }

  if (cacheHit) {
    ++g_stats.cacheHits;
  }
  doLatencyStats(0);  // we're not going to measure this
  return 0;
}

static void processUDPQuery(ClientState& cs, LocalHolders& holders, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, char* query, uint16_t len, size_t queryBufferSize, struct mmsghdr* responsesVect, unsigned int* queuedResponses, struct iovec* respIOV, char* respCBuf)
{
  assert(responsesVect == nullptr || (queuedResponses != nullptr && respIOV != nullptr && respCBuf != nullptr));
  uint16_t queryId = 0;

  try {
    if (!isUDPQueryAcceptable(cs, holders, msgh, remote, dest)) {
      return;
    }

    /* we need an accurate ("real") value for the response and
       to store into the IDS, but not for insertion into the
       rings for example */
    struct timespec queryRealTime;
    struct timespec now;
    gettime(&now);
    gettime(&queryRealTime, true);

#ifdef HAVE_DNSCRYPT
    std::shared_ptr<DNSCryptQuery> dnsCryptQuery = nullptr;

    if (!checkDNSCryptQuery(cs, query, len, dnsCryptQuery, dest, remote, queryRealTime.tv_sec)) {
      return;
    }
#endif

    struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query);
    queryId = ntohs(dh->id);

    if (!checkQueryHeaders(dh)) {
      return;
    }

    string poolname;
    int delayMsec = 0;
    const uint16_t * flags = getFlagsFromDNSHeader(dh);
    const uint16_t origFlags = *flags;
    uint16_t qtype, qclass;
    unsigned int consumed = 0;
    DNSName qname(query, len, sizeof(dnsheader), false, &qtype, &qclass, &consumed);
    DNSQuestion dq(&qname, qtype, qclass, consumed, dest.sin4.sin_family != 0 ? &dest : &cs.local, &remote, dh, queryBufferSize, len, false, &queryRealTime);
    bool dnssecOK = false;

    if (!processQuery(holders, dq, poolname, &delayMsec, now))
    {
      return;
    }

    if(dq.dh->qr) { // something turned it into a response
      fixUpQueryTurnedResponse(dq, origFlags);

      if (!cs.muted) {
        char* response = query;
        uint16_t responseLen = dq.len;

        sendAndEncryptUDPResponse(holders, cs, dq, response, responseLen, dnsCryptQuery, delayMsec, dest, responsesVect, queuedResponses, respIOV, respCBuf, false);

        ++g_stats.selfAnswered;
      }

      return;
    }

    DownstreamState* ss = nullptr;
    std::shared_ptr<ServerPool> serverPool = getPool(*holders.pools, poolname);
    std::shared_ptr<DNSDistPacketCache> packetCache = serverPool->packetCache;
    auto policy = *(holders.policy);
    if (serverPool->policy != nullptr) {
      policy = *(serverPool->policy);
    }
    auto servers = serverPool->getServers();
    if (policy.isLua) {
      std::lock_guard<std::mutex> lock(g_luamutex);
      ss = policy.policy(servers, &dq).get();
    }
    else {
      ss = policy.policy(servers, &dq).get();
    }

    bool ednsAdded = false;
    bool ecsAdded = false;
    uint32_t cacheKeyNoECS = 0;
    uint32_t cacheKey = 0;
    boost::optional<Netmask> subnet;
    uint16_t cachedResponseSize = dq.size;
    uint32_t allowExpired = ss ? 0 : g_staleCacheEntriesTTL;
    bool useZeroScope = false;

    if (packetCache && !dq.skipCache) {
      dnssecOK = (getEDNSZ(dq) & EDNS_HEADER_FLAG_DO);
    }

    if (dq.useECS && ((ss && ss->useECS) || (!ss && serverPool->getECS()))) {
      // we special case our cache in case a downstream explicitly gave us a universally valid response with a 0 scope
      if (packetCache && !dq.skipCache && (!ss || !ss->disableZeroScope) && packetCache->isECSParsingEnabled()) {
        if (packetCache->get(dq, consumed, dh->id, query, &cachedResponseSize, &cacheKeyNoECS, subnet, dnssecOK, allowExpired)) {
          sendAndEncryptUDPResponse(holders, cs, dq, query, cachedResponseSize, dnsCryptQuery, delayMsec, dest, responsesVect, queuedResponses, respIOV, respCBuf, true);
          return;
        }

        if (!subnet) {
          /* there was no existing ECS on the query, enable the zero-scope feature */
          useZeroScope = true;
        }
      }

      if (!handleEDNSClientSubnet(dq, &(ednsAdded), &(ecsAdded), g_preserveTrailingData)) {
        vinfolog("Dropping query from %s because we couldn't insert the ECS value", remote.toStringWithPort());
        return;
      }
    }

    if (packetCache && !dq.skipCache) {
      if (packetCache->get(dq, consumed, dh->id, query, &cachedResponseSize, &cacheKey, subnet, dnssecOK, allowExpired)) {
        sendAndEncryptUDPResponse(holders, cs, dq, query, cachedResponseSize, dnsCryptQuery, delayMsec, dest, responsesVect, queuedResponses, respIOV, respCBuf, true);
        return;
      }
      ++g_stats.cacheMisses;
    }

    if(!ss) {
      ++g_stats.noPolicy;

      if (g_servFailOnNoPolicy && !cs.muted) {
        char* response = query;
        uint16_t responseLen = dq.len;
        restoreFlags(dh, origFlags);

        dq.dh->rcode = RCode::ServFail;
        dq.dh->qr = true;

        sendAndEncryptUDPResponse(holders, cs, dq, response, responseLen, dnsCryptQuery, delayMsec, dest, responsesVect, queuedResponses, respIOV, respCBuf, false);

        // no response-only statistics counter to update.
      }
      vinfolog("%s query for %s|%s from %s, no policy applied", g_servFailOnNoPolicy ? "ServFailed" : "Dropped", dq.qname->toString(), QType(dq.qtype).getName(), remote.toStringWithPort());
      return;
    }

    if (dq.addXPF && ss->xpfRRCode != 0) {
      addXPF(dq, ss->xpfRRCode, g_preserveTrailingData);
    }

    ss->queries++;

    unsigned int idOffset = (ss->idOffset++) % ss->idStates.size();
    IDState* ids = &ss->idStates[idOffset];
    ids->age = 0;

    int oldFD = ids->origFD.exchange(cs.udpFD);
    if(oldFD < 0) {
      // if we are reusing, no change in outstanding
      ss->outstanding++;
    }
    else {
      ss->reuseds++;
      ++g_stats.downstreamTimeouts;
    }

    ids->cs = &cs;
    ids->origID = dh->id;
    ids->origRemote = remote;
    ids->sentTime.set(queryRealTime);
    ids->qname = qname;
    ids->qtype = dq.qtype;
    ids->qclass = dq.qclass;
    ids->delayMsec = delayMsec;
    ids->tempFailureTTL = dq.tempFailureTTL;
    ids->origFlags = origFlags;
    ids->cacheKey = cacheKey;
    ids->cacheKeyNoECS = cacheKeyNoECS;
    ids->subnet = subnet;
    ids->skipCache = dq.skipCache;
    ids->packetCache = packetCache;
    ids->ednsAdded = ednsAdded;
    ids->ecsAdded = ecsAdded;
    ids->useZeroScope = useZeroScope;
    ids->qTag = dq.qTag;
    ids->dnssecOK = dnssecOK;

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

    int fd = pickBackendSocketForSending(ss);
    ssize_t ret = udpClientSendRequestToBackend(ss, fd, query, dq.len);

    if(ret < 0) {
      ss->sendErrors++;
      ++g_stats.downstreamSendErrors;
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
static void udpClientThread(ClientState* cs)
try
{
  setThreadName("dnsdist/udpClie");
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
        ++g_stats.nonCompliantQueries;
        continue;
      }

      processUDPQuery(*cs, holders, &msgh, remote, dest, packet, static_cast<uint16_t>(got), s_udpIncomingBufferSize, nullptr, nullptr, nullptr, nullptr);
    }
  }
}
catch(const std::exception &e)
{
  errlog("UDP client thread died because of exception: %s", e.what());
}
catch(const PDNSException &e)
{
  errlog("UDP client thread died because of PowerDNS exception: %s", e.reason);
}
catch(...)
{
  errlog("UDP client thread died because of an exception: %s", "unknown");
}

uint16_t getRandomDNSID()
{
#ifdef HAVE_LIBSODIUM
  return (randombytes_random() % 65536);
#else
  return (random() % 65536);
#endif
}

static bool upCheck(DownstreamState& ds)
try
{
  DNSName checkName = ds.checkName;
  uint16_t checkType = ds.checkType.getCode();
  uint16_t checkClass = ds.checkClass;
  dnsheader checkHeader;
  memset(&checkHeader, 0, sizeof(checkHeader));

  checkHeader.qdcount = htons(1);
  checkHeader.id = getRandomDNSID();

  checkHeader.rd = true;
  if (ds.setCD) {
    checkHeader.cd = true;
  }

  if (ds.checkFunction) {
    std::lock_guard<std::mutex> lock(g_luamutex);
    auto ret = ds.checkFunction(checkName, checkType, checkClass, &checkHeader);
    checkName = std::get<0>(ret);
    checkType = std::get<1>(ret);
    checkClass = std::get<2>(ret);
  }

  vector<uint8_t> packet;
  DNSPacketWriter dpw(packet, checkName, checkType, checkClass);
  dnsheader * requestHeader = dpw.getHeader();
  *requestHeader = checkHeader;

  Socket sock(ds.remote.sin4.sin_family, SOCK_DGRAM);
  sock.setNonBlocking();
  if (!IsAnyAddress(ds.sourceAddr)) {
    sock.setReuseAddr();
    sock.bind(ds.sourceAddr);
  }
  sock.connect(ds.remote);
  ssize_t sent = udpClientSendRequestToBackend(&ds, sock.getHandle(), (char*)&packet[0], packet.size(), true);
  if (sent < 0) {
    int ret = errno;
    if (g_verboseHealthChecks)
      infolog("Error while sending a health check query to backend %s: %d", ds.getNameWithAddr(), ret);
    return false;
  }

  int ret = waitForRWData(sock.getHandle(), true, /* ms to seconds */ ds.checkTimeout / 1000, /* remaining ms to us */ (ds.checkTimeout % 1000) * 1000);
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
  ComboAddress from;
  sock.recvFrom(reply, from);

  /* we are using a connected socket but hey.. */
  if (from != ds.remote) {
    if (g_verboseHealthChecks)
      infolog("Invalid health check response received from %s, expecting one from %s", from.toStringWithPort(), ds.remote.toStringWithPort());
    return false;
  }

  const dnsheader * responseHeader = reinterpret_cast<const dnsheader *>(reply.c_str());

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

  uint16_t receivedType;
  uint16_t receivedClass;
  DNSName receivedName(reply.c_str(), reply.size(), sizeof(dnsheader), false, &receivedType, &receivedClass);

  if (receivedName != checkName || receivedType != checkType || receivedClass != checkClass) {
    if (g_verboseHealthChecks)
      infolog("Backend %s responded to health check with an invalid qname (%s vs %s), qtype (%s vs %s) or qclass (%d vs %d)", ds.getNameWithAddr(), receivedName.toLogString(), checkName.toLogString(), QType(receivedType).getName(), QType(checkType).getName(), receivedClass, checkClass);
    return false;
  }

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

void maintThread()
{
  setThreadName("dnsdist/main");
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
      /* keep track, for each cache, of whether we should keep
       expired entries */
      std::map<std::shared_ptr<DNSDistPacketCache>, bool> caches;

      /* gather all caches actually used by at least one pool, and see
         if something prevents us from cleaning the expired entries */
      auto localPools = g_pools.getLocal();
      for (const auto& entry : *localPools) {
        auto& pool = entry.second;

        auto packetCache = pool->packetCache;
        if (!packetCache) {
          continue;
        }

        auto pair = caches.insert({packetCache, false});
        auto& iter = pair.first;
        /* if we need to keep stale data for this cache (ie, not clear
           expired entries when at least one pool using this cache
           has all its backends down) */
        if (packetCache->keepStaleData() && iter->second == false) {
          /* so far all pools had at least one backend up */
          if (pool->countServers(true) == 0) {
            iter->second = true;
          }
        }
      }

      for (auto pair : caches) {
        /* shall we keep expired entries ? */
        if (pair.second == true) {
          continue;
        }
        auto& packetCache = pair.first;
        size_t upTo = (packetCache->getMaxEntries()* (100 - g_cacheCleaningPercentage)) / 100;
        packetCache->purgeExpired(upTo);
      }
      counter = 0;
    }

    // ponder pruning g_dynblocks of expired entries here
  }
}

static void secPollThread()
{
  setThreadName("dnsdist/secpoll");

  for (;;) {
    try {
      doSecPoll(g_secPollSuffix);
    }
    catch(...) {
    }
    sleep(g_secPollInterval);
  }
}

static void healthChecksThread()
{
  setThreadName("dnsdist/healthC");

  int interval = 1;

  for(;;) {
    sleep(interval);

    if(g_tcpclientthreads->getQueuedCount() > 1 && !g_tcpclientthreads->hasReachedMaxThreads())
      g_tcpclientthreads->addTCPClientThread();

    auto states = g_dstates.getLocal(); // this points to the actual shared_ptrs!
    for(auto& dss : *states) {
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
            newState = dss->reconnect();

            if (dss->connected && !dss->threadStarted.test_and_set()) {
              dss->tid = thread(responderThread, dss);
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
        int origFD = ids.origFD;
        if(origFD >=0 && ids.age++ > g_udpTimeout) {
          /* We set origFD to -1 as soon as possible
             to limit the risk of racing with the
             responder thread.
             The UDP client thread only checks origFD to
             know whether outstanding has to be incremented,
             so the sooner the better any way since we _will_
             decrement it.
          */
          if (ids.origFD.exchange(-1) != origFD) {
            /* this state has been altered in the meantime,
               don't go anywhere near it */
            continue;
          }
          ids.age = 0;
          dss->reuseds++;
          --dss->outstanding;
          ++g_stats.downstreamTimeouts; // this is an 'actively' discovered timeout
          vinfolog("Had a downstream timeout from %s (%s) for query for %s|%s from %s",
                   dss->remote.toStringWithPort(), dss->name,
                   ids.qname.toString(), QType(ids.qtype).getName(), ids.origRemote.toStringWithPort());

          struct timespec ts;
          gettime(&ts);

          struct dnsheader fake;
          memset(&fake, 0, sizeof(fake));
          fake.id = ids.origID;

          g_rings.insertResponse(ts, ids.origRemote, ids.qname, ids.qtype, std::numeric_limits<unsigned int>::max(), 0, fake, dss->remote);
        }          
      }
    }
  }
}

static void bindAny(int af, int sock)
{
  __attribute__((unused)) int one = 1;

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
  auto backends = g_dstates.getLocal();
  /* UDP sockets to backends */
  size_t backendUDPSocketsCount = 0;
  for (const auto& backend : *backends) {
    backendUDPSocketsCount += backend->sockets.size();
  }
  requiredFDsCount += backendUDPSocketsCount;
  /* TCP sockets to backends */
  requiredFDsCount += (backends->size() * g_maxTCPClientThreads);
  /* listening sockets */
  requiredFDsCount += udpBindsCount;
  requiredFDsCount += tcpBindsCount;
  /* max TCP connections currently served */
  requiredFDsCount += g_maxTCPClientThreads;
  /* max pipes for communicating between TCP acceptors and client threads */
  requiredFDsCount += (g_maxTCPClientThreads * 2);
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
  bool beClient{false};
  bool beSupervised{false};
  string command;
  string config;
  string uid;
  string gid;
} g_cmdLine;

std::atomic<bool> g_configurationDone{false};

static void usage()
{
  cout<<endl;
  cout<<"Syntax: dnsdist [-C,--config file] [-c,--client [IP[:PORT]]]\n";
  cout<<"[-e,--execute cmd] [-h,--help] [-l,--local addr]\n";
  cout<<"[-v,--verbose] [--check-config] [--version]\n";
  cout<<"\n";
  cout<<"-a,--acl netmask      Add this netmask to the ACL\n";
  cout<<"-C,--config file      Load configuration from 'file'\n";
  cout<<"-c,--client           Operate as a client, connect to dnsdist. This reads\n";
  cout<<"                      controlSocket from your configuration file, but also\n";
  cout<<"                      accepts an IP:PORT argument\n";
#ifdef HAVE_LIBSODIUM
  cout<<"-k,--setkey KEY       Use KEY for encrypted communication to dnsdist. This\n";
  cout<<"                      is similar to setting setKey in the configuration file.\n";
  cout<<"                      NOTE: this will leak this key in your shell's history\n";
  cout<<"                      and in the systems running process list.\n";
#endif
  cout<<"--check-config        Validate the configuration file and exit. The exit-code\n";
  cout<<"                      reflects the validation, 0 is OK, 1 means an error.\n";
  cout<<"                      Any errors are printed as well.\n";
  cout<<"-e,--execute cmd      Connect to dnsdist and execute 'cmd'\n";
  cout<<"-g,--gid gid          Change the process group ID after binding sockets\n";
  cout<<"-h,--help             Display this helpful message\n";
  cout<<"-l,--local address    Listen on this local address\n";
  cout<<"--supervised          Don't open a console, I'm supervised\n";
  cout<<"                        (use with e.g. systemd and daemontools)\n";
  cout<<"--disable-syslog      Don't log to syslog, only to stdout\n";
  cout<<"                        (use with e.g. systemd)\n";
  cout<<"-u,--uid uid          Change the process user ID after binding sockets\n";
  cout<<"-v,--verbose          Enable verbose mode\n";
  cout<<"-V,--version          Show dnsdist version information and exit\n";
}

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
    {"check-config", no_argument, 0, 1},
    {"client", no_argument, 0, 'c'},
    {"config", required_argument, 0, 'C'},
    {"disable-syslog", no_argument, 0, 2},
    {"execute", required_argument, 0, 'e'},
    {"gid", required_argument, 0, 'g'},
    {"help", no_argument, 0, 'h'},
    {"local", required_argument, 0, 'l'},
    {"setkey", required_argument, 0, 'k'},
    {"supervised", no_argument, 0, 3},
    {"uid", required_argument, 0, 'u'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0,0,0,0}
  };
  int longindex=0;
  string optstring;
  for(;;) {
    int c=getopt_long(argc, argv, "a:cC:e:g:hk:l:u:vV", longopts, &longindex);
    if(c==-1)
      break;
    switch(c) {
    case 1:
      g_cmdLine.checkConfig=true;
      break;
    case 2:
      g_syslog=false;
      break;
    case 3:
      g_cmdLine.beSupervised=true;
      break;
    case 'C':
      g_cmdLine.config=optarg;
      break;
    case 'c':
      g_cmdLine.beClient=true;
      break;
    case 'e':
      g_cmdLine.command=optarg;
      break;
    case 'g':
      g_cmdLine.gid=optarg;
      break;
    case 'h':
      cout<<"dnsdist "<<VERSION<<endl;
      usage();
      cout<<"\n";
      exit(EXIT_SUCCESS);
      break;
    case 'a':
      optstring=optarg;
      g_ACL.modify([optstring](NetmaskGroup& nmg) { nmg.addMask(optstring); });
      break;
    case 'k':
#ifdef HAVE_LIBSODIUM
      if (B64Decode(string(optarg), g_consoleKey) < 0) {
        cerr<<"Unable to decode key '"<<optarg<<"'."<<endl;
        exit(EXIT_FAILURE);
      }
#else
      cerr<<"dnsdist has been built without libsodium, -k/--setkey is unsupported."<<endl;
      exit(EXIT_FAILURE);
#endif
      break;
    case 'l':
      g_cmdLine.locals.push_back(trim_copy(string(optarg)));
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
#ifdef HAVE_DNS_OVER_TLS
      cout<<"dns-over-tls(";
#ifdef HAVE_GNUTLS
      cout<<"gnutls";
  #ifdef HAVE_LIBSSL
      cout<<" ";
  #endif
#endif
#ifdef HAVE_LIBSSL
      cout<<"openssl";
#endif
      cout<<") ";
#endif
#ifdef HAVE_DNSCRYPT
      cout<<"dnscrypt ";
#endif
#ifdef HAVE_EBPF
      cout<<"ebpf ";
#endif
#ifdef HAVE_FSTRM
      cout<<"fstrm ";
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
    case '?':
      //getopt_long printed an error message.
      usage();
      exit(EXIT_FAILURE);
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

  ServerPolicy leastOutstandingPol{"leastOutstanding", leastOutstanding, false};

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

  auto consoleACL = g_consoleACL.getCopy();
  for (const auto& mask : { "127.0.0.1/8", "::1/128" }) {
    consoleACL.addMask(mask);
  }
  g_consoleACL.setState(consoleACL);

  if (g_cmdLine.checkConfig) {
    setupLua(true, g_cmdLine.config);
    // No exception was thrown
    infolog("Configuration '%s' OK!", g_cmdLine.config);
    _exit(EXIT_SUCCESS);
  }

  auto todo=setupLua(false, g_cmdLine.config);

  auto localPools = g_pools.getCopy();
  {
    bool precompute = false;
    if (g_policy.getLocal()->name == "chashed") {
      precompute = true;
    } else {
      for (const auto& entry: localPools) {
        if (entry.second->policy != nullptr && entry.second->policy->name == "chashed") {
          precompute = true;
          break ;
        }
      }
    }
    if (precompute) {
      vinfolog("Pre-computing hashes for consistent hash load-balancing policy");
      // pre compute hashes
      auto backends = g_dstates.getLocal();
      for (auto& backend: *backends) {
        backend->hash();
      }
    }
  }

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
    //      g_log<<Logger::Warning<<"Unable to enable timestamp reporting for socket"<<endl;


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
    SSetsockopt(cs->tcpFD, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1);
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
    cs->dnscryptCtx = std::get<1>(dcLocal);
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
    cs->dnscryptCtx = std::get<1>(dcLocal);
    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);
    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(cs->tcpFD, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1);
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

  for(auto& frontend : g_tlslocals) {
    ClientState* cs = new ClientState;
    cs->local = frontend->d_addr;
    cs->tcpFD = SSocket(cs->local.sin4.sin_family, SOCK_STREAM, 0);
    SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(cs->tcpFD, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1);
#endif
    if (frontend->d_tcpFastOpenQueueSize > 0) {
#ifdef TCP_FASTOPEN
      SSetsockopt(cs->tcpFD, IPPROTO_TCP, TCP_FASTOPEN, frontend->d_tcpFastOpenQueueSize);
#else
      warnlog("TCP Fast Open has been configured on local address '%s' but is not supported", cs->local.toStringWithPort());
#endif
    }
    if (frontend->d_reusePort) {
#ifdef SO_REUSEPORT
      SSetsockopt(cs->tcpFD, SOL_SOCKET, SO_REUSEPORT, 1);
#else
      warnlog("SO_REUSEPORT has been configured on local address '%s' but is not supported", cs->local.toStringWithPort());
#endif
    }
    if(cs->local.sin4.sin_family == AF_INET6) {
      SSetsockopt(cs->tcpFD, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }

    if (!frontend->d_interface.empty()) {
#ifdef SO_BINDTODEVICE
      int res = setsockopt(cs->tcpFD, SOL_SOCKET, SO_BINDTODEVICE, frontend->d_interface.c_str(), frontend->d_interface.length());
      if (res != 0) {
        warnlog("Error setting up the interface on local address '%s': %s", cs->local.toStringWithPort(), strerror(errno));
      }
#else
      warnlog("An interface has been configured on local address '%s' but SO_BINDTODEVICE is not supported", cs->local.toStringWithPort());
#endif
    }

    cs->cpus = frontend->d_cpus;

    bindAny(cs->local.sin4.sin_family, cs->tcpFD);
    if (frontend->setupTLS()) {
      cs->tlsFrontend = frontend;
      SBind(cs->tcpFD, cs->local);
      SListen(cs->tcpFD, 64);
      warnlog("Listening on %s for TLS", cs->local.toStringWithPort());
      toLaunch.push_back(cs);
      g_frontends.push_back(cs);
      tcpBindsCount++;
    }
    else {
      delete cs;
      errlog("Error while setting up TLS on local address '%s', exiting", cs->local.toStringWithPort());
      _exit(EXIT_FAILURE);
    }
  }

  warnlog("dnsdist %s comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2", VERSION);

  vector<string> vec;
  std::string acls;
  g_ACL.getLocal()->toStringVector(&vec);
  for(const auto& s : vec) {
    if (!acls.empty())
      acls += ", ";
    acls += s;
  }
  infolog("ACL allowing queries from: %s", acls.c_str());
  vec.clear();
  acls.clear();
  g_consoleACL.getLocal()->toStringVector(&vec);
  for (const auto& entry : vec) {
    if (!acls.empty()) {
      acls += ", ";
    }
    acls += entry;
  }
  infolog("Console ACL allowing connections from: %s", acls.c_str());

#ifdef HAVE_LIBSODIUM
  if (g_consoleEnabled && g_consoleKey.empty()) {
    warnlog("Warning, the console has been enabled via 'controlSocket()' but no key has been set with 'setKey()' so all connections will fail until a key has been set");
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
  try {
    /* we might still have capabilities remaining,
       for example if we have been started as root
       without --uid or --gid (please don't do that)
       or as an unprivileged user with ambient
       capabilities like CAP_NET_BIND_SERVICE.
    */
    dropCapabilities();
  }
  catch(const std::exception& e) {
    warnlog("%s", e.what());
  }

  /* this need to be done _after_ dropping privileges */
  g_delay = new DelayPipe<DelayedPacket>();

  if (g_snmpAgent) {
    g_snmpAgent->run();
  }

  g_tcpclientthreads = std::make_shared<TCPClientCollection>(g_maxTCPClientThreads, g_useTCPSinglePipe);

  for(auto& t : todo)
    t();

  localPools = g_pools.getCopy();
  /* create the default pool no matter what */
  createPoolIfNotExists(localPools, "");
  if(g_cmdLine.remotes.size()) {
    for(const auto& address : g_cmdLine.remotes) {
      auto ret=std::make_shared<DownstreamState>(ComboAddress(address, 53));
      addServerToPool(localPools, "", ret);
      if (ret->connected && !ret->threadStarted.test_and_set()) {
        ret->tid = thread(responderThread, ret);
      }
      g_dstates.modify([ret](servers_t& servers) { servers.push_back(ret); });
    }
  }
  g_pools.setState(localPools);

  if(g_dstates.getLocal()->empty()) {
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

  if (!g_secPollSuffix.empty()) {
    thread secpollthread(secPollThread);
    secpollthread.detach();
  }

  if(g_cmdLine.beSupervised) {
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
