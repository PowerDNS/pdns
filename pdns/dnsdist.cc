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
// If this is not undeffed, __attribute__ wil be redefined by /usr/include/readline/rlstdc.h
#undef __STRICT_ANSI__
#include <readline/readline.h>
#else
#include <editline/readline.h>
#endif

#include "dnsdist-systemd.hh"
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "dnsdist.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-console.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-healthchecks.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-secpoll.hh"
#include "dnsdist-web.hh"
#include "dnsdist-xpf.hh"

#include "base64.hh"
#include "delaypipe.hh"
#include "dolog.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "ednsoptions.hh"
#include "gettime.hh"
#include "lock.hh"
#include "misc.hh"
#include "sodcrypto.hh"
#include "sstuff.hh"
#include "threadname.hh"

/* Known sins:

   Receiver is currently single threaded
      not *that* bad actually, but now that we are thread safe, might want to scale
*/

/* the RuleAction plan
   Set of Rules, if one matches, it leads to an Action
   Both rules and actions could conceivably be Lua based. 
   On the C++ side, both could be inherited from a class Rule and a class Action, 
   on the Lua side we can't do that. */

using std::thread;
bool g_verbose;

struct DNSDistStats g_stats;

uint16_t g_maxOutstanding{std::numeric_limits<uint16_t>::max()};
uint32_t g_staleCacheEntriesTTL{0};
bool g_syslog{true};
bool g_allowEmptyResponse{false};

GlobalStateHolder<NetmaskGroup> g_ACL;
string g_outputBuffer;

std::vector<std::shared_ptr<TLSFrontend>> g_tlslocals;
std::vector<std::shared_ptr<DOHFrontend>> g_dohlocals;
std::vector<std::shared_ptr<DNSCryptContext>> g_dnsCryptLocals;

shared_ptr<BPFFilter> g_defaultBPFFilter{nullptr};
std::vector<std::shared_ptr<DynBPFFilter> > g_dynBPFFilters;

std::vector<std::unique_ptr<ClientState>> g_frontends;
GlobalStateHolder<pools_t> g_pools;
size_t g_udpVectorSize{1};

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

GlobalStateHolder<vector<DNSDistRuleAction> > g_ruleactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_respruleactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_cachehitrespruleactions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_selfansweredrespruleactions;

Rings g_rings;
QueryCount g_qcount;

GlobalStateHolder<servers_t> g_dstates;
GlobalStateHolder<NetmaskTree<DynBlock>> g_dynblockNMG;
GlobalStateHolder<SuffixMatchTree<DynBlock>> g_dynblockSMT;
DNSAction::Action g_dynBlockAction = DNSAction::Action::Drop;
int g_udpTimeout{2};

bool g_servFailOnNoPolicy{false};
bool g_truncateTC{false};
bool g_fixupCase{false};
bool g_dropEmptyQueries{false};

std::set<std::string> g_capabilitiesToRetain;

static size_t const s_initialUDPPacketBufferSize = s_maxPacketCacheEntrySize + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
static_assert(s_initialUDPPacketBufferSize <= UINT16_MAX, "Packet size should fit in a uint16_t");

static void truncateTC(PacketBuffer& packet, size_t maximumSize, unsigned int qnameWireLength)
{
  try
  {
    bool hadEDNS = false;
    uint16_t payloadSize = 0;
    uint16_t z = 0;

    if (g_addEDNSToSelfGeneratedResponses) {
      hadEDNS = getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(packet.data()), packet.size(), &payloadSize, &z);
    }

    packet.resize(static_cast<uint16_t>(sizeof(dnsheader)+qnameWireLength+DNS_TYPE_SIZE+DNS_CLASS_SIZE));
    struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(packet.data());
    dh->ancount = dh->arcount = dh->nscount = 0;

    if (hadEDNS) {
      addEDNS(packet, maximumSize, z & EDNS_HEADER_FLAG_DO, payloadSize, 0);
    }
  }
  catch(...)
  {
    ++g_stats.truncFail;
  }
}

struct DelayedPacket
{
  int fd;
  PacketBuffer packet;
  ComboAddress destination;
  ComboAddress origDest;
  void operator()()
  {
    ssize_t res;
    if(origDest.sin4.sin_family == 0) {
      res = sendto(fd, packet.data(), packet.size(), 0, (struct sockaddr*)&destination, destination.getSocklen());
    }
    else {
      res = sendfromto(fd, packet.data(), packet.size(), 0, origDest, destination);
    }
    if (res == -1) {
      int err = errno;
      vinfolog("Error sending delayed response to %s: %s", destination.toStringWithPort(), strerror(err));
    }
  }
};

DelayPipe<DelayedPacket>* g_delay = nullptr;

std::string DNSQuestion::getTrailingData() const
{
  const char* message = reinterpret_cast<const char*>(this->getHeader());
  const uint16_t messageLen = getDNSPacketLength(message, this->data.size());
  return std::string(message + messageLen, this->getData().size() - messageLen);
}

bool DNSQuestion::setTrailingData(const std::string& tail)
{
  const char* message = reinterpret_cast<const char*>(this->data.data());
  const uint16_t messageLen = getDNSPacketLength(message, this->data.size());
  this->data.resize(messageLen);
  if (tail.size() > 0) {
    if (!hasRoomFor(tail.size())) {
      return false;
    }
    this->data.insert(this->data.end(), tail.begin(), tail.end());
  }
  return true;
}

void doLatencyStats(double udiff)
{
  if(udiff < 1000) ++g_stats.latency0_1;
  else if(udiff < 10000) ++g_stats.latency1_10;
  else if(udiff < 50000) ++g_stats.latency10_50;
  else if(udiff < 100000) ++g_stats.latency50_100;
  else if(udiff < 1000000) ++g_stats.latency100_1000;
  else ++g_stats.latencySlow;
  g_stats.latencySum += udiff / 1000;

  auto doAvg = [](double& var, double n, double weight) {
    var = (weight -1) * var/weight + n/weight;
  };

  doAvg(g_stats.latencyAvg100,     udiff,     100);
  doAvg(g_stats.latencyAvg1000,    udiff,    1000);
  doAvg(g_stats.latencyAvg10000,   udiff,   10000);
  doAvg(g_stats.latencyAvg1000000, udiff, 1000000);
}

bool responseContentMatches(const PacketBuffer& response, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const ComboAddress& remote, unsigned int& qnameWireLength)
{
  if (response.size() < sizeof(dnsheader)) {
    return false;
  }

  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(response.data());
  if (dh->qr == 0) {
    ++g_stats.nonCompliantResponses;
    return false;
  }

  if (dh->qdcount == 0) {
    if ((dh->rcode != RCode::NoError && dh->rcode != RCode::NXDomain) || g_allowEmptyResponse) {
      return true;
    }
    else {
      ++g_stats.nonCompliantResponses;
      return false;
    }
  }

  uint16_t rqtype, rqclass;
  DNSName rqname;
  try {
    rqname = DNSName(reinterpret_cast<const char*>(response.data()), response.size(), sizeof(dnsheader), false, &rqtype, &rqclass, &qnameWireLength);
  }
  catch (const std::exception& e) {
    if(response.size() > 0 && static_cast<size_t>(response.size()) > sizeof(dnsheader)) {
      infolog("Backend %s sent us a response with id %d that did not parse: %s", remote.toStringWithPort(), ntohs(dh->id), e.what());
    }
    ++g_stats.nonCompliantResponses;
    return false;
  }

  if (rqtype != qtype || rqclass != qclass || rqname != qname) {
    return false;
  }

  return true;
}

static void restoreFlags(struct dnsheader* dh, uint16_t origFlags)
{
  static const uint16_t rdMask = 1 << FLAGS_RD_OFFSET;
  static const uint16_t cdMask = 1 << FLAGS_CD_OFFSET;
  static const uint16_t restoreFlagsMask = UINT16_MAX & ~(rdMask | cdMask);
  uint16_t* flags = getFlagsFromDNSHeader(dh);
  /* clear the flags we are about to restore */
  *flags &= restoreFlagsMask;
  /* only keep the flags we want to restore */
  origFlags &= ~restoreFlagsMask;
  /* set the saved flags as they were */
  *flags |= origFlags;
}

static bool fixUpQueryTurnedResponse(DNSQuestion& dq, const uint16_t origFlags)
{
  restoreFlags(dq.getHeader(), origFlags);

  return addEDNSToQueryTurnedResponse(dq);
}

static bool fixUpResponse(PacketBuffer& response, const DNSName& qname, uint16_t origFlags, bool ednsAdded, bool ecsAdded, bool* zeroScope)
{
  if (response.size() < sizeof(dnsheader)) {
    return false;
  }

  struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(response.data());
  restoreFlags(dh, origFlags);

  if (response.size() == sizeof(dnsheader)) {
    return true;
  }

  if (g_fixupCase) {
    const auto& realname = qname.getStorage();
    if (response.size() >= (sizeof(dnsheader) + realname.length())) {
      memcpy(&response.at(sizeof(dnsheader)), realname.c_str(), realname.length());
    }
  }

  if (ednsAdded || ecsAdded) {
    uint16_t optStart;
    size_t optLen = 0;
    bool last = false;

    int res = locateEDNSOptRR(response, &optStart, &optLen, &last);

    if (res == 0) {
      if (zeroScope) { // this finds if an EDNS Client Subnet scope was set, and if it is 0
        size_t optContentStart = 0;
        uint16_t optContentLen = 0;
        /* we need at least 4 bytes after the option length (family: 2, source prefix-length: 1, scope prefix-length: 1) */
        if (isEDNSOptionInOpt(response, optStart, optLen, EDNSOptionCode::ECS, &optContentStart, &optContentLen) && optContentLen >= 4) {
          /* see if the EDNS Client Subnet SCOPE PREFIX-LENGTH byte in position 3 is set to 0, which is the only thing
             we care about. */
          *zeroScope = response.at(optContentStart + 3) == 0;
        }
      }

      if (ednsAdded) {
        /* we added the entire OPT RR,
           therefore we need to remove it entirely */
        if (last) {
          /* simply remove the last AR */
          response.resize(response.size() - optLen);
          dh = reinterpret_cast<struct dnsheader*>(response.data());
          uint16_t arcount = ntohs(dh->arcount);
          arcount--;
          dh->arcount = htons(arcount);
        }
        else {
          /* Removing an intermediary RR could lead to compression error */
          PacketBuffer rewrittenResponse;
          if (rewriteResponseWithoutEDNS(response, rewrittenResponse) == 0) {
            response = std::move(rewrittenResponse);
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
          removeEDNSOptionFromOPT(reinterpret_cast<char*>(&response.at(optStart)), &optLen, EDNSOptionCode::ECS);
          response.resize(response.size() - (existingOptLen - optLen));
        }
        else {
          PacketBuffer rewrittenResponse;
          /* Removing an intermediary RR could lead to compression error */
          if (rewriteResponseWithoutEDNSOption(response, EDNSOptionCode::ECS, rewrittenResponse) == 0) {
            response = std::move(rewrittenResponse);
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
static bool encryptResponse(PacketBuffer& response, size_t maximumSize, bool tcp, std::shared_ptr<DNSCryptQuery> dnsCryptQuery)
{
  if (dnsCryptQuery) {
    int res = dnsCryptQuery->encryptResponse(response, maximumSize, tcp);
    if (res != 0) {
      /* dropping response */
      vinfolog("Error encrypting the response, dropping.");
      return false;
    }
  }
  return true;
}
#endif /* HAVE_DNSCRYPT */

static bool applyRulesToResponse(LocalStateHolder<vector<DNSDistResponseRuleAction> >& localRespRuleActions, DNSResponse& dr)
{
  DNSResponseAction::Action action=DNSResponseAction::Action::None;
  std::string ruleresult;
  for(const auto& lr : *localRespRuleActions) {
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
        dr.getHeader()->rcode = RCode::ServFail;
        return true;
        break;
        /* non-terminal actions follow */
      case DNSResponseAction::Action::Delay:
        dr.delayMsec = static_cast<int>(pdns_stou(ruleresult)); // sorry
        break;
      case DNSResponseAction::Action::None:
        break;
      }
    }
  }

  return true;
}

// whether the query was received over TCP or not (for rules, dnstap, protobuf, ...) will be taken from the DNSResponse, but receivedOverUDP is used to insert into the cache,
// so that answers received over UDP for DoH are still cached with UDP answers.
bool processResponse(PacketBuffer& response, LocalStateHolder<vector<DNSDistResponseRuleAction> >& localRespRuleActions, DNSResponse& dr, bool muted, bool receivedOverUDP)
{
  if (!applyRulesToResponse(localRespRuleActions, dr)) {
    return false;
  }

  bool zeroScope = false;
  if (!fixUpResponse(response, *dr.qname, dr.origFlags, dr.ednsAdded, dr.ecsAdded, dr.useZeroScope ? &zeroScope : nullptr)) {
    return false;
  }

  if (dr.packetCache && !dr.skipCache && response.size() <= s_maxPacketCacheEntrySize) {
    if (!dr.useZeroScope) {
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
    dr.packetCache->insert(zeroScope ? dr.cacheKeyNoECS : dr.cacheKey, zeroScope ? boost::none : dr.subnet, dr.origFlags, dr.dnssecOK, *dr.qname, dr.qtype, dr.qclass, response, receivedOverUDP, dr.getHeader()->rcode, dr.tempFailureTTL);
  }

#ifdef HAVE_DNSCRYPT
  if (!muted) {
    if (!encryptResponse(response, dr.getMaximumSize(), dr.overTCP(), dr.dnsCryptQuery)) {
      return false;
    }
  }
#endif /* HAVE_DNSCRYPT */

  return true;
}

static size_t getInitialUDPPacketBufferSize()
{
  static_assert(s_udpIncomingBufferSize <= s_initialUDPPacketBufferSize, "The incoming buffer size should not be larger than s_initialUDPPacketBufferSize");

  if (g_proxyProtocolACL.empty()) {
    return s_initialUDPPacketBufferSize;
  }

  return s_initialUDPPacketBufferSize + g_proxyProtocolMaximumSize;
}

static size_t getMaximumIncomingPacketSize(const ClientState& cs)
{
  if (cs.dnscryptCtx) {
    return getInitialUDPPacketBufferSize();
  }

  if (g_proxyProtocolACL.empty()) {
    return s_udpIncomingBufferSize;
  }

  return s_udpIncomingBufferSize + g_proxyProtocolMaximumSize;
}

static bool sendUDPResponse(int origFD, const PacketBuffer& response, const int delayMsec, const ComboAddress& origDest, const ComboAddress& origRemote)
{
  if(delayMsec && g_delay) {
    DelayedPacket dp{origFD, response, origRemote, origDest};
    g_delay->submit(dp, delayMsec);
  }
  else {
    ssize_t res;
    if (origDest.sin4.sin_family == 0) {
      res = sendto(origFD, response.data(), response.size(), 0, reinterpret_cast<const struct sockaddr*>(&origRemote), origRemote.getSocklen());
    }
    else {
      res = sendfromto(origFD, response.data(), response.size(), 0, origDest, origRemote);
    }
    if (res == -1) {
      int err = errno;
      vinfolog("Error sending response to %s: %s", origRemote.toStringWithPort(), stringerror(err));
    }
  }

  return true;
}

int pickBackendSocketForSending(std::shared_ptr<DownstreamState>& state)
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

  (*state->mplexer.lock())->getAvailableFDs(ready, 1000);
}

// listens on a dedicated socket, lobs answers from downstream servers to original requestors
void responderThread(std::shared_ptr<DownstreamState> dss)
{
  try {
  setThreadName("dnsdist/respond");
  auto localRespRuleActions = g_respruleactions.getLocal();
  const size_t initialBufferSize = getInitialUDPPacketBufferSize();
  PacketBuffer response(initialBufferSize);

  /* when the answer is encrypted in place, we need to get a copy
     of the original header before encryption to fill the ring buffer */
  dnsheader cleartextDH;
  uint16_t queryId = 0;
  std::vector<int> sockets;
  sockets.reserve(dss->sockets.size());

  for(;;) {
    try {
      pickBackendSocketsReadyForReceiving(dss, sockets);
      if (dss->isStopped()) {
        break;
      }

      for (const auto& fd : sockets) {
        response.resize(initialBufferSize);
        ssize_t got = recv(fd, response.data(), response.size(), 0);

        if (got == 0 && dss->isStopped()) {
          break;
        }

        if (got < 0 || static_cast<size_t>(got) < sizeof(dnsheader)) {
          continue;
        }

        response.resize(static_cast<size_t>(got));
        dnsheader* dh = reinterpret_cast<struct dnsheader*>(response.data());
        queryId = dh->id;

        if (queryId >= dss->idStates.size()) {
          continue;
        }

        IDState* ids = &dss->idStates[queryId];
        int64_t usageIndicator = ids->usageIndicator;

        if (!IDState::isInUse(usageIndicator)) {
          /* the corresponding state is marked as not in use, meaning that:
             - it was already cleaned up by another thread and the state is gone ;
             - we already got a response for this query and this one is a duplicate.
             Either way, we don't touch it.
          */
          continue;
        }

        /* read the potential DOHUnit state as soon as possible, but don't use it
           until we have confirmed that we own this state by updating usageIndicator */
        auto du = ids->du;
        /* setting age to 0 to prevent the maintainer thread from
           cleaning this IDS while we process the response.
        */
        ids->age = 0;
        int origFD = ids->origFD;

        unsigned int qnameWireLength = 0;
        if (!responseContentMatches(response, ids->qname, ids->qtype, ids->qclass, dss->remote, qnameWireLength)) {
          continue;
        }

        bool isDoH = du != nullptr;
        /* atomically mark the state as available, but only if it has not been altered
           in the meantime */
        if (ids->tryMarkUnused(usageIndicator)) {
          /* clear the potential DOHUnit asap, it's ours now
           and since we just marked the state as unused,
           someone could overwrite it. */
          ids->du = nullptr;
          /* we only decrement the outstanding counter if the value was not
             altered in the meantime, which would mean that the state has been actively reused
             and the other thread has not incremented the outstanding counter, so we don't
             want it to be decremented twice. */
          --dss->outstanding;  // you'd think an attacker could game this, but we're using connected socket
        } else {
          /* someone updated the state in the meantime, we can't touch the existing pointer */
          du = nullptr;
          /* since the state has been updated, we can't safely access it so let's just drop
             this response */
          continue;
        }

        dh->id = ids->origID;

        DNSResponse dr = makeDNSResponseFromIDState(*ids, response);
        if (dh->tc && g_truncateTC) {
          truncateTC(response, dr.getMaximumSize(), qnameWireLength);
        }
        memcpy(&cleartextDH, dr.getHeader(), sizeof(cleartextDH));

        if (!processResponse(response, localRespRuleActions, dr, ids->cs && ids->cs->muted, true)) {
          continue;
        }

        if (ids->cs && !ids->cs->muted) {
          if (du) {
#ifdef HAVE_DNS_OVER_HTTPS
            // DoH query
            du->response = std::move(response);
            static_assert(sizeof(du) <= PIPE_BUF, "Writes up to PIPE_BUF are guaranteed not to be interleaved and to either fully succeed or fail");
            ssize_t sent = write(du->rsock, &du, sizeof(du));
            if (sent != sizeof(du)) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) {
                ++g_stats.dohResponsePipeFull;
                vinfolog("Unable to pass a DoH response to the DoH worker thread because the pipe is full");
              }
              else {
                vinfolog("Unable to pass a DoH response to the DoH worker thread because we couldn't write to the pipe: %s", stringerror());
              }

              /* at this point we have the only remaining pointer on this
                 DOHUnit object since we did set ids->du to nullptr earlier,
                 except if we got the response before the pointer could be
                 released by the frontend */
              du->release();
            }
#endif /* HAVE_DNS_OVER_HTTPS */
            du = nullptr;
          }
          else {
            ComboAddress empty;
            empty.sin4.sin_family = 0;
            sendUDPResponse(origFD, response, dr.delayMsec, ids->hopLocal, ids->hopRemote);
          }
        }

        ++g_stats.responses;
        if (ids->cs) {
          ++ids->cs->responses;
        }
        ++dss->responses;

        double udiff = ids->sentTime.udiff();
        vinfolog("Got answer from %s, relayed to %s%s, took %f usec", dss->remote.toStringWithPort(), ids->origRemote.toStringWithPort(),
                 isDoH ? " (https)": "", udiff);

        struct timespec ts;
        gettime(&ts);
        g_rings.insertResponse(ts, *dr.remote, *dr.qname, dr.qtype, static_cast<unsigned int>(udiff), static_cast<unsigned int>(got), cleartextDH, dss->remote);

        switch (cleartextDH.rcode) {
        case RCode::NXDomain:
          ++g_stats.frontendNXDomain;
          break;
        case RCode::ServFail:
          ++g_stats.servfailResponses;
          ++g_stats.frontendServFail;
          break;
        case RCode::NoError:
          ++g_stats.frontendNoError;
          break;
        }
        dss->latencyUsec = (127.0 * dss->latencyUsec / 128.0) + udiff/128.0;

        doLatencyStats(udiff);
      }
    }
    catch (const std::exception& e){
      vinfolog("Got an error in UDP responder thread while parsing a response from %s, id %d: %s", dss->remote.toStringWithPort(), queryId, e.what());
    }
  }
}
catch (const std::exception& e)
{
  errlog("UDP responder thread died because of exception: %s", e.what());
}
catch (const PDNSException& e)
{
  errlog("UDP responder thread died because of PowerDNS exception: %s", e.reason);
}
catch (...)
{
  errlog("UDP responder thread died because of an exception: %s", "unknown");
}
}

LockGuarded<LuaContext> g_lua{LuaContext()};
ComboAddress g_serverControl{"127.0.0.1:5199"};


static void spoofResponseFromString(DNSQuestion& dq, const string& spoofContent, bool raw)
{
  string result;

  if (raw) {
    std::vector<std::string> raws;
    stringtok(raws, spoofContent, ",");
    SpoofAction sa(raws);
    sa(&dq, &result);
  }
  else {
    std::vector<std::string> addrs;
    stringtok(addrs, spoofContent, " ,");

    if (addrs.size() == 1) {
      try {
        ComboAddress spoofAddr(spoofContent);
        SpoofAction sa({spoofAddr});
        sa(&dq, &result);
      }
      catch(const PDNSException &e) {
        DNSName cname(spoofContent);
        SpoofAction sa(cname); // CNAME then
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
}

bool processRulesResult(const DNSAction::Action& action, DNSQuestion& dq, std::string& ruleresult, bool& drop)
{
  switch(action) {
  case DNSAction::Action::Allow:
    return true;
    break;
  case DNSAction::Action::Drop:
    ++g_stats.ruleDrop;
    drop = true;
    return true;
    break;
  case DNSAction::Action::Nxdomain:
    dq.getHeader()->rcode = RCode::NXDomain;
    dq.getHeader()->qr=true;
    ++g_stats.ruleNXDomain;
    return true;
    break;
  case DNSAction::Action::Refused:
    dq.getHeader()->rcode = RCode::Refused;
    dq.getHeader()->qr=true;
    ++g_stats.ruleRefused;
    return true;
    break;
  case DNSAction::Action::ServFail:
    dq.getHeader()->rcode = RCode::ServFail;
    dq.getHeader()->qr=true;
    ++g_stats.ruleServFail;
    return true;
    break;
  case DNSAction::Action::Spoof:
    spoofResponseFromString(dq, ruleresult, false);
    return true;
    break;
  case DNSAction::Action::SpoofRaw:
    spoofResponseFromString(dq, ruleresult, true);
    return true;
    break;
  case DNSAction::Action::Truncate:
    dq.getHeader()->tc = true;
    dq.getHeader()->qr = true;
    dq.getHeader()->ra = dq.getHeader()->rd;
    dq.getHeader()->aa = false;
    dq.getHeader()->ad = false;
    ++g_stats.ruleTruncated;
    return true;
    break;
  case DNSAction::Action::HeaderModify:
    return true;
    break;
  case DNSAction::Action::Pool:
    dq.poolname=ruleresult;
    return true;
    break;
  case DNSAction::Action::NoRecurse:
    dq.getHeader()->rd = false;
    return true;
    break;
    /* non-terminal actions follow */
  case DNSAction::Action::Delay:
    dq.delayMsec = static_cast<int>(pdns_stou(ruleresult)); // sorry
    break;
  case DNSAction::Action::None:
    /* fall-through */
  case DNSAction::Action::NoOp:
    break;
  }

  /* false means that we don't stop the processing */
  return false;
}


static bool applyRulesToQuery(LocalHolders& holders, DNSQuestion& dq, const struct timespec& now)
{
  g_rings.insertQuery(now, *dq.remote, *dq.qname, dq.qtype, dq.getData().size(), *dq.getHeader());

  if (g_qcount.enabled) {
    string qname = (*dq.qname).toLogString();
    bool countQuery{true};
    if (g_qcount.filter) {
      auto lock = g_lua.lock();
      std::tie (countQuery, qname) = g_qcount.filter(&dq);
    }

    if (countQuery) {
      auto records = g_qcount.records.write_lock();
      if (!records->count(qname)) {
        (*records)[qname] = 0;
      }
      (*records)[qname]++;
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

        dq.getHeader()->rcode = RCode::NXDomain;
        dq.getHeader()->qr=true;
        return true;

      case DNSAction::Action::Refused:
        vinfolog("Query from %s refused because of dynamic block", dq.remote->toStringWithPort());
        updateBlockStats();
      
        dq.getHeader()->rcode = RCode::Refused;
        dq.getHeader()->qr = true;
        return true;

      case DNSAction::Action::Truncate:
        if (!dq.overTCP()) {
          updateBlockStats();
          vinfolog("Query from %s truncated because of dynamic block", dq.remote->toStringWithPort());
          dq.getHeader()->tc = true;
          dq.getHeader()->qr = true;
          dq.getHeader()->ra = dq.getHeader()->rd;
          dq.getHeader()->aa = false;
          dq.getHeader()->ad = false;
          return true;
        }
        else {
          vinfolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toLogString());
        }
        break;
      case DNSAction::Action::NoRecurse:
        updateBlockStats();
        vinfolog("Query from %s setting rd=0 because of dynamic block", dq.remote->toStringWithPort());
        dq.getHeader()->rd = false;
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
        vinfolog("Query from %s for %s turned into NXDomain because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toLogString());
        updateBlockStats();

        dq.getHeader()->rcode = RCode::NXDomain;
        dq.getHeader()->qr=true;
        return true;
      case DNSAction::Action::Refused:
        vinfolog("Query from %s for %s refused because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toLogString());
        updateBlockStats();

        dq.getHeader()->rcode = RCode::Refused;
        dq.getHeader()->qr=true;
        return true;
      case DNSAction::Action::Truncate:
        if (!dq.overTCP()) {
          updateBlockStats();
      
          vinfolog("Query from %s for %s truncated because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toLogString());
          dq.getHeader()->tc = true;
          dq.getHeader()->qr = true;
          dq.getHeader()->ra = dq.getHeader()->rd;
          dq.getHeader()->aa = false;
          dq.getHeader()->ad = false;
          return true;
        }
        else {
          vinfolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toLogString());
        }
        break;
      case DNSAction::Action::NoRecurse:
        updateBlockStats();
        vinfolog("Query from %s setting rd=0 because of dynamic block", dq.remote->toStringWithPort());
        dq.getHeader()->rd = false;
        return true;
      default:
        updateBlockStats();
        vinfolog("Query from %s for %s dropped because of dynamic block", dq.remote->toStringWithPort(), dq.qname->toLogString());
        return false;
      }
    }
  }

  DNSAction::Action action=DNSAction::Action::None;
  string ruleresult;
  bool drop = false;
  for(const auto& lr : *holders.ruleactions) {
    if(lr.d_rule->matches(&dq)) {
      lr.d_rule->d_matches++;
      action=(*lr.d_action)(&dq, &ruleresult);
      if (processRulesResult(action, dq, ruleresult, drop)) {
        break;
      }
    }
  }

  if (drop) {
    return false;
  }

  return true;
}

ssize_t udpClientSendRequestToBackend(const std::shared_ptr<DownstreamState>& ss, const int sd, const PacketBuffer& request, bool healthCheck)
{
  ssize_t result;

  if (ss->sourceItf == 0) {
    result = send(sd, request.data(), request.size(), 0);
  }
  else {
    struct msghdr msgh;
    struct iovec iov;
    cmsgbuf_aligned cbuf;
    ComboAddress remote(ss->remote);
    fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), const_cast<char*>(reinterpret_cast<const char *>(request.data())), request.size(), &remote);
    addCMsgSrcAddr(&msgh, &cbuf, &ss->sourceAddr, ss->sourceItf);
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

static bool isUDPQueryAcceptable(ClientState& cs, LocalHolders& holders, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, bool& expectProxyProtocol)
{
  if (msgh->msg_flags & MSG_TRUNC) {
    /* message was too large for our buffer */
    vinfolog("Dropping message too large for our buffer");
    ++g_stats.nonCompliantQueries;
    return false;
  }

  expectProxyProtocol = expectProxyProtocolFrom(remote);
  if (!holders.acl->match(remote) && !expectProxyProtocol) {
    vinfolog("Query from %s dropped because of ACL", remote.toStringWithPort());
    ++g_stats.aclDrops;
    return false;
  }

  if (HarvestDestinationAddress(msgh, &dest)) {
    /* we don't get the port, only the address */
    dest.sin4.sin_port = cs.local.sin4.sin_port;
  }
  else {
    dest.sin4.sin_family = 0;
  }

  cs.queries++;
  ++g_stats.queries;

  return true;
}

bool checkDNSCryptQuery(const ClientState& cs, PacketBuffer& query, std::shared_ptr<DNSCryptQuery>& dnsCryptQuery, time_t now, bool tcp)
{
  if (cs.dnscryptCtx) {
#ifdef HAVE_DNSCRYPT
    PacketBuffer response;
    dnsCryptQuery = std::make_shared<DNSCryptQuery>(cs.dnscryptCtx);

    bool decrypted = handleDNSCryptQuery(query, dnsCryptQuery, tcp, now, response);

    if (!decrypted) {
      if (response.size() > 0) {
        query = std::move(response);
        return true;
      }
      throw std::runtime_error("Unable to decrypt DNSCrypt query, dropping.");
    }
#endif /* HAVE_DNSCRYPT */
  }
  return false;
}

bool checkQueryHeaders(const struct dnsheader* dh)
{
  if (dh->qr) {   // don't respond to responses
    ++g_stats.nonCompliantQueries;
    return false;
  }

  if (dh->qdcount == 0) {
    ++g_stats.emptyQueries;
    if (g_dropEmptyQueries) {
      return false;
    }
  }

  if (dh->rd) {
    ++g_stats.rdQueries;
  }

  return true;
}

#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
static void queueResponse(const ClientState& cs, const PacketBuffer& response, const ComboAddress& dest, const ComboAddress& remote, struct mmsghdr& outMsg, struct iovec* iov, cmsgbuf_aligned* cbuf)
{
  outMsg.msg_len = 0;
  fillMSGHdr(&outMsg.msg_hdr, iov, nullptr, 0, const_cast<char*>(reinterpret_cast<const char *>(&response.at(0))), response.size(), const_cast<ComboAddress*>(&remote));

  if (dest.sin4.sin_family == 0) {
    outMsg.msg_hdr.msg_control = nullptr;
  }
  else {
    addCMsgSrcAddr(&outMsg.msg_hdr, cbuf, &dest, 0);
  }
}
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */

/* self-generated responses or cache hits */
static bool prepareOutgoingResponse(LocalHolders& holders, ClientState& cs, DNSQuestion& dq, bool cacheHit)
{
  DNSResponse dr(dq.qname, dq.qtype, dq.qclass, dq.local, dq.remote, dq.getMutableData(), dq.protocol, dq.queryTime);

  dr.uniqueId = dq.uniqueId;
  dr.qTag = dq.qTag;
  dr.delayMsec = dq.delayMsec;

  if (!applyRulesToResponse(cacheHit ? holders.cacheHitRespRuleactions : holders.selfAnsweredRespRuleactions, dr)) {
    return false;
  }

  /* in case a rule changed it */
  dq.delayMsec = dr.delayMsec;

#ifdef HAVE_DNSCRYPT
  if (!cs.muted) {
    if (!encryptResponse(dq.getMutableData(), dq.getMaximumSize(), dq.overTCP(), dq.dnsCryptQuery)) {
      return false;
    }
  }
#endif /* HAVE_DNSCRYPT */

  if (cacheHit) {
    ++g_stats.cacheHits;
  }

  switch (dr.getHeader()->rcode) {
  case RCode::NXDomain:
    ++g_stats.frontendNXDomain;
    break;
  case RCode::ServFail:
    ++g_stats.frontendServFail;
    break;
  case RCode::NoError:
    ++g_stats.frontendNoError;
    break;
  }

  doLatencyStats(0);  // we're not going to measure this
  return true;
}

ProcessQueryResult processQuery(DNSQuestion& dq, ClientState& cs, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend)
{
  const uint16_t queryId = ntohs(dq.getHeader()->id);

  try {
    /* we need an accurate ("real") value for the response and
       to store into the IDS, but not for insertion into the
       rings for example */
    struct timespec now;
    gettime(&now);

    if (!applyRulesToQuery(holders, dq, now)) {
      return ProcessQueryResult::Drop;
    }

    if (dq.getHeader()->qr) { // something turned it into a response
      fixUpQueryTurnedResponse(dq, dq.origFlags);

      if (!prepareOutgoingResponse(holders, cs, dq, false)) {
        return ProcessQueryResult::Drop;
      }

      ++g_stats.selfAnswered;
      ++cs.responses;
      return ProcessQueryResult::SendAnswer;
    }

    std::shared_ptr<ServerPool> serverPool = getPool(*holders.pools, dq.poolname);
    std::shared_ptr<ServerPolicy> poolPolicy = serverPool->policy;
    dq.packetCache = serverPool->packetCache;
    const auto& policy = poolPolicy != nullptr ? *poolPolicy : *(holders.policy);
    const auto servers = serverPool->getServers();
    selectedBackend = policy.getSelectedBackend(*servers, dq);

    uint32_t allowExpired = selectedBackend ? 0 : g_staleCacheEntriesTTL;

    if (dq.packetCache && !dq.skipCache) {
      dq.dnssecOK = (getEDNSZ(dq) & EDNS_HEADER_FLAG_DO);
    }

    if (dq.useECS && ((selectedBackend && selectedBackend->useECS) || (!selectedBackend && serverPool->getECS()))) {
      // we special case our cache in case a downstream explicitly gave us a universally valid response with a 0 scope
      // we need ECS parsing (parseECS) to be true so we can be sure that the initial incoming query did not have an existing
      // ECS option, which would make it unsuitable for the zero-scope feature.
      if (dq.packetCache && !dq.skipCache && (!selectedBackend || !selectedBackend->disableZeroScope) && dq.packetCache->isECSParsingEnabled()) {
        if (dq.packetCache->get(dq, dq.getHeader()->id, &dq.cacheKeyNoECS, dq.subnet, dq.dnssecOK, !dq.overTCP() || dq.getProtocol() == DNSQuestion::Protocol::DoH, allowExpired)) {

          if (!prepareOutgoingResponse(holders, cs, dq, true)) {
            return ProcessQueryResult::Drop;
          }

          return ProcessQueryResult::SendAnswer;
        }

        if (!dq.subnet) {
          /* there was no existing ECS on the query, enable the zero-scope feature */
          dq.useZeroScope = true;
        }
      }

      if (!handleEDNSClientSubnet(dq, dq.ednsAdded, dq.ecsAdded)) {
        vinfolog("Dropping query from %s because we couldn't insert the ECS value", dq.remote->toStringWithPort());
        return ProcessQueryResult::Drop;
      }
    }

    if (dq.packetCache && !dq.skipCache) {
      if (dq.packetCache->get(dq, dq.getHeader()->id, &dq.cacheKey, dq.subnet, dq.dnssecOK, !dq.overTCP() || dq.getProtocol() == DNSQuestion::Protocol::DoH, allowExpired)) {

        if (!prepareOutgoingResponse(holders, cs, dq, true)) {
          return ProcessQueryResult::Drop;
        }

        return ProcessQueryResult::SendAnswer;
      }
      ++g_stats.cacheMisses;
    }

    if (!selectedBackend) {
      ++g_stats.noPolicy;

      vinfolog("%s query for %s|%s from %s, no policy applied", g_servFailOnNoPolicy ? "ServFailed" : "Dropped", dq.qname->toLogString(), QType(dq.qtype).toString(), dq.remote->toStringWithPort());
      if (g_servFailOnNoPolicy) {
        dq.getHeader()->rcode = RCode::ServFail;
        dq.getHeader()->qr = true;

        fixUpQueryTurnedResponse(dq, dq.origFlags);

        if (!prepareOutgoingResponse(holders, cs, dq, false)) {
          return ProcessQueryResult::Drop;
        }
        // no response-only statistics counter to update.
        return ProcessQueryResult::SendAnswer;
      }

      return ProcessQueryResult::Drop;
    }

    if (dq.addXPF && selectedBackend->xpfRRCode != 0) {
      addXPF(dq, selectedBackend->xpfRRCode);
    }

    selectedBackend->incQueriesCount();
    return ProcessQueryResult::PassToBackend;
  }
  catch (const std::exception& e){
    vinfolog("Got an error while parsing a %s query from %s, id %d: %s", (dq.overTCP() ? "TCP" : "UDP"), dq.remote->toStringWithPort(), queryId, e.what());
  }
  return ProcessQueryResult::Drop;
}

static void processUDPQuery(ClientState& cs, LocalHolders& holders, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, PacketBuffer& query, struct mmsghdr* responsesVect, unsigned int* queuedResponses, struct iovec* respIOV, cmsgbuf_aligned* respCBuf)
{
  assert(responsesVect == nullptr || (queuedResponses != nullptr && respIOV != nullptr && respCBuf != nullptr));
  uint16_t queryId = 0;
  ComboAddress proxiedRemote = remote;
  ComboAddress proxiedDestination = dest;

  try {
    bool expectProxyProtocol = false;
    if (!isUDPQueryAcceptable(cs, holders, msgh, remote, dest, expectProxyProtocol)) {
      return;
    }
    /* dest might have been updated, if we managed to harvest the destination address */
    proxiedDestination = dest;

    std::vector<ProxyProtocolValue> proxyProtocolValues;
    if (expectProxyProtocol && !handleProxyProtocol(remote, false, *holders.acl, query, proxiedRemote, proxiedDestination, proxyProtocolValues)) {
      return;
    }

    /* we need an accurate ("real") value for the response and
       to store into the IDS, but not for insertion into the
       rings for example */
    struct timespec queryRealTime;
    gettime(&queryRealTime, true);

    std::shared_ptr<DNSCryptQuery> dnsCryptQuery = nullptr;
    auto dnsCryptResponse = checkDNSCryptQuery(cs, query, dnsCryptQuery, queryRealTime.tv_sec, false);
    if (dnsCryptResponse) {
      sendUDPResponse(cs.udpFD, query, 0, dest, remote);
      return;
    }

    {
      /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
      struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query.data());
      queryId = ntohs(dh->id);

      if (!checkQueryHeaders(dh)) {
        return;
      }

      if (dh->qdcount == 0) {
        dh->rcode = RCode::NotImp;
        dh->qr = true;
        sendUDPResponse(cs.udpFD, query, 0, dest, remote);
        return;
      }
    }

    uint16_t qtype, qclass;
    unsigned int qnameWireLength = 0;
    DNSName qname(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false, &qtype, &qclass, &qnameWireLength);
    DNSQuestion dq(&qname, qtype, qclass, proxiedDestination.sin4.sin_family != 0 ? &proxiedDestination : &cs.local, &proxiedRemote, query, dnsCryptQuery ? DNSQuestion::Protocol::DNSCryptUDP : DNSQuestion::Protocol::DoUDP, &queryRealTime);
    dq.dnsCryptQuery = std::move(dnsCryptQuery);
    if (!proxyProtocolValues.empty()) {
      dq.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
    }
    dq.hopRemote = &remote;
    dq.hopLocal = &dest;
    std::shared_ptr<DownstreamState> ss{nullptr};
    auto result = processQuery(dq, cs, holders, ss);

    if (result == ProcessQueryResult::Drop) {
      return;
    }

    // the buffer might have been invalidated by now (resized)
    struct dnsheader* dh = dq.getHeader();
    if (result == ProcessQueryResult::SendAnswer) {
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
      if (dq.delayMsec == 0 && responsesVect != nullptr) {
        queueResponse(cs, query, dest, remote, responsesVect[*queuedResponses], respIOV, respCBuf);
        (*queuedResponses)++;
        return;
      }
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
      /* we use dest, always, because we don't want to use the listening address to send a response since it could be 0.0.0.0 */
      sendUDPResponse(cs.udpFD, query, dq.delayMsec, dest, remote);
      return;
    }

    if (result != ProcessQueryResult::PassToBackend || ss == nullptr) {
      return;
    }

    unsigned int idOffset = (ss->idOffset++) % ss->idStates.size();
    IDState* ids = &ss->idStates[idOffset];
    ids->age = 0;
    DOHUnit* du = nullptr;

    /* that means that the state was in use, possibly with an allocated
       DOHUnit that we will need to handle, but we can't touch it before
       confirming that we now own this state */
    if (ids->isInUse()) {
      du = ids->du;
    }

    /* we atomically replace the value, we now own this state */
    if (!ids->markAsUsed()) {
      /* the state was not in use.
         we reset 'du' because it might have still been in use when we read it. */
      du = nullptr;
      ++ss->outstanding;
    }
    else {
      /* we are reusing a state, no change in outstanding but if there was an existing DOHUnit we need
         to handle it because it's about to be overwritten. */
      ids->du = nullptr;
      ++ss->reuseds;
      ++g_stats.downstreamTimeouts;
      handleDOHTimeout(du);
    }

    ids->cs = &cs;
    ids->origFD = cs.udpFD;
    ids->origID = dh->id;
    setIDStateFromDNSQuestion(*ids, dq, std::move(qname));

    if (dest.sin4.sin_family != 0) {
      ids->origDest = dest;
    }
    else {
      ids->origDest = cs.local;
    }

    dh = dq.getHeader();
    dh->id = idOffset;

    if (ss->useProxyProtocol) {
      addProxyProtocol(dq);
    }

    int fd = pickBackendSocketForSending(ss);
    ssize_t ret = udpClientSendRequestToBackend(ss, fd, query);

    if(ret < 0) {
      ++ss->sendErrors;
      ++g_stats.downstreamSendErrors;
    }

    vinfolog("Got query for %s|%s from %s, relayed to %s", ids->qname.toLogString(), QType(ids->qtype).toString(), proxiedRemote.toStringWithPort(), ss->getName());
  }
  catch(const std::exception& e){
    vinfolog("Got an error in UDP question thread while parsing a query from %s, id %d: %s", proxiedRemote.toStringWithPort(), queryId, e.what());
  }
}

#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
static void MultipleMessagesUDPClientThread(ClientState* cs, LocalHolders& holders)
{
  struct MMReceiver
  {
    PacketBuffer packet;
    ComboAddress remote;
    ComboAddress dest;
    struct iovec iov;
    /* used by HarvestDestinationAddress */
    cmsgbuf_aligned cbuf;
  };
  const size_t vectSize = g_udpVectorSize;

  auto recvData = std::unique_ptr<MMReceiver[]>(new MMReceiver[vectSize]);
  auto msgVec = std::unique_ptr<struct mmsghdr[]>(new struct mmsghdr[vectSize]);
  auto outMsgVec = std::unique_ptr<struct mmsghdr[]>(new struct mmsghdr[vectSize]);

  /* the actual buffer is larger because:
     - we may have to add EDNS and/or ECS
     - we use it for self-generated responses (from rule or cache)
     but we only accept incoming payloads up to that size
  */
  const size_t initialBufferSize = getInitialUDPPacketBufferSize();
  const size_t maxIncomingPacketSize = getMaximumIncomingPacketSize(*cs);

  /* initialize the structures needed to receive our messages */
  for (size_t idx = 0; idx < vectSize; idx++) {
    recvData[idx].remote.sin4.sin_family = cs->local.sin4.sin_family;
    recvData[idx].packet.resize(initialBufferSize);
    fillMSGHdr(&msgVec[idx].msg_hdr, &recvData[idx].iov, &recvData[idx].cbuf, sizeof(recvData[idx].cbuf), reinterpret_cast<char*>(&recvData[idx].packet.at(0)), maxIncomingPacketSize, &recvData[idx].remote);
  }

  /* go now */
  for(;;) {

    /* reset the IO vector, since it's also used to send the vector of responses
       to avoid having to copy the data around */
    for (size_t idx = 0; idx < vectSize; idx++) {
      recvData[idx].packet.resize(initialBufferSize);
      recvData[idx].iov.iov_base = &recvData[idx].packet.at(0);
      recvData[idx].iov.iov_len = recvData[idx].packet.size();
    }

    /* block until we have at least one message ready, but return
       as many as possible to save the syscall costs */
    int msgsGot = recvmmsg(cs->udpFD, msgVec.get(), vectSize, MSG_WAITFORONE | MSG_TRUNC, nullptr);

    if (msgsGot <= 0) {
      vinfolog("Getting UDP messages via recvmmsg() failed with: %s", stringerror());
      continue;
    }

    unsigned int msgsToSend = 0;

    /* process the received messages */
    for (int msgIdx = 0; msgIdx < msgsGot; msgIdx++) {
      const struct msghdr* msgh = &msgVec[msgIdx].msg_hdr;
      unsigned int got = msgVec[msgIdx].msg_len;
      const ComboAddress& remote = recvData[msgIdx].remote;

      if (static_cast<size_t>(got) < sizeof(struct dnsheader)) {
        ++g_stats.nonCompliantQueries;
        continue;
      }

      recvData[msgIdx].packet.resize(got);
      processUDPQuery(*cs, holders, msgh, remote, recvData[msgIdx].dest, recvData[msgIdx].packet, outMsgVec.get(), &msgsToSend, &recvData[msgIdx].iov, &recvData[msgIdx].cbuf);
    }

    /* immediate (not delayed or sent to a backend) responses (mostly from a rule, dynamic block
       or the cache) can be sent in batch too */

    if (msgsToSend > 0 && msgsToSend <= static_cast<unsigned int>(msgsGot)) {
      int sent = sendmmsg(cs->udpFD, outMsgVec.get(), msgsToSend, 0);

      if (sent < 0 || static_cast<unsigned int>(sent) != msgsToSend) {
        vinfolog("Error sending responses with sendmmsg() (%d on %u): %s", sent, msgsToSend, stringerror());
      }
    }

  }
}
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */

// listens to incoming queries, sends out to downstream servers, noting the intended return path
static void udpClientThread(ClientState* cs)
{
  try {
    setThreadName("dnsdist/udpClie");
    LocalHolders holders;

#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
    if (g_udpVectorSize > 1) {
      MultipleMessagesUDPClientThread(cs, holders);
    }
    else
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
    {
      /* the actual buffer is larger because:
         - we may have to add EDNS and/or ECS
         - we use it for self-generated responses (from rule or cache)
         but we only accept incoming payloads up to that size
      */
      const size_t initialBufferSize = getInitialUDPPacketBufferSize();
      const size_t maxIncomingPacketSize = getMaximumIncomingPacketSize(*cs);
      PacketBuffer packet(initialBufferSize);

      struct msghdr msgh;
      struct iovec iov;
      /* used by HarvestDestinationAddress */
      cmsgbuf_aligned cbuf;

      ComboAddress remote;
      ComboAddress dest;
      remote.sin4.sin_family = cs->local.sin4.sin_family;
      fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), reinterpret_cast<char*>(&packet.at(0)), maxIncomingPacketSize, &remote);

      for(;;) {
        packet.resize(initialBufferSize);
        iov.iov_base = &packet.at(0);
        iov.iov_len = packet.size();

        ssize_t got = recvmsg(cs->udpFD, &msgh, 0);

        if (got < 0 || static_cast<size_t>(got) < sizeof(struct dnsheader)) {
          ++g_stats.nonCompliantQueries;
          continue;
        }

        packet.resize(static_cast<size_t>(got));

        processUDPQuery(*cs, holders, &msgh, remote, dest, packet, nullptr, nullptr, nullptr, nullptr);
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
}


uint16_t getRandomDNSID()
{
#ifdef HAVE_LIBSODIUM
  return randombytes_uniform(65536);
#else
  return (random() % 65536);
#endif
}

boost::optional<uint64_t> g_maxTCPClientThreads{boost::none};
pdns::stat16_t g_cacheCleaningDelay{60};
pdns::stat16_t g_cacheCleaningPercentage{100};

static void maintThread()
{
  setThreadName("dnsdist/main");
  int interval = 1;
  size_t counter = 0;
  int32_t secondsToWaitLog = 0;

  for (;;) {
    sleep(interval);

    {
      auto lua = g_lua.lock();
      auto f = lua->readVariable<boost::optional<std::function<void()> > >("maintenance");
      if (f) {
        try {
          (*f)();
          secondsToWaitLog = 0;
        }
        catch(const std::exception &e) {
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

      const time_t now = time(nullptr);
      for (auto pair : caches) {
        /* shall we keep expired entries ? */
        if (pair.second == true) {
          continue;
        }
        auto& packetCache = pair.first;
        size_t upTo = (packetCache->getMaxEntries()* (100 - g_cacheCleaningPercentage)) / 100;
        packetCache->purgeExpired(upTo, now);
      }
      counter = 0;
    }
  }
}

static void dynBlockMaintenanceThread()
{
  setThreadName("dnsdist/dynBloc");

  DynBlockMaintenance::run();
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

  static const int interval = 1;

  for(;;) {
    sleep(interval);

    auto mplexer = std::shared_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());
    auto states = g_dstates.getLocal(); // this points to the actual shared_ptrs!
    for(auto& dss : *states) {
      if (++dss->lastCheck < dss->checkInterval) {
        continue;
      }

      dss->lastCheck = 0;

      if (dss->availability == DownstreamState::Availability::Auto) {
        if (!queueHealthCheck(mplexer, dss)) {
          updateHealthCheckResult(dss, false);
        }
      }

      auto delta = dss->sw.udiffAndSet()/1000000.0;
      dss->queryLoad.store(1.0*(dss->queries.load() - dss->prev.queries.load())/delta);
      dss->dropRate.store(1.0*(dss->reuseds.load() - dss->prev.reuseds.load())/delta);
      dss->prev.queries.store(dss->queries.load());
      dss->prev.reuseds.store(dss->reuseds.load());
      
      for (IDState& ids  : dss->idStates) { // timeouts
        int64_t usageIndicator = ids.usageIndicator;
        if(IDState::isInUse(usageIndicator) && ids.age++ > g_udpTimeout) {
          /* We mark the state as unused as soon as possible
             to limit the risk of racing with the
             responder thread.
          */
          auto oldDU = ids.du;

          if (!ids.tryMarkUnused(usageIndicator)) {
            /* this state has been altered in the meantime,
               don't go anywhere near it */
            continue;
          }
          ids.du = nullptr;
          handleDOHTimeout(oldDU);
          ids.age = 0;
          dss->reuseds++;
          --dss->outstanding;
          ++g_stats.downstreamTimeouts; // this is an 'actively' discovered timeout
          vinfolog("Had a downstream timeout from %s (%s) for query for %s|%s from %s",
                   dss->remote.toStringWithPort(), dss->getName(),
                   ids.qname.toLogString(), QType(ids.qtype).toString(), ids.origRemote.toStringWithPort());

          struct timespec ts;
          gettime(&ts);

          struct dnsheader fake;
          memset(&fake, 0, sizeof(fake));
          fake.id = ids.origID;

          g_rings.insertResponse(ts, ids.origRemote, ids.qname, ids.qtype, std::numeric_limits<unsigned int>::max(), 0, fake, dss->remote);
        }          
      }
    }

    handleQueuedHealthChecks(mplexer);
  }
}

static void bindAny(int af, int sock)
{
  __attribute__((unused)) int one = 1;

#ifdef IP_FREEBIND
  if (setsockopt(sock, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) < 0)
    warnlog("Warning: IP_FREEBIND setsockopt failed: %s", stringerror());
#endif

#ifdef IP_BINDANY
  if (af == AF_INET)
    if (setsockopt(sock, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) < 0)
      warnlog("Warning: IP_BINDANY setsockopt failed: %s", stringerror());
#endif
#ifdef IPV6_BINDANY
  if (af == AF_INET6)
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) < 0)
      warnlog("Warning: IPV6_BINDANY setsockopt failed: %s", stringerror());
#endif
#ifdef SO_BINDANY
  if (setsockopt(sock, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) < 0)
    warnlog("Warning: SO_BINDANY setsockopt failed: %s", stringerror());
#endif
}

static void dropGroupPrivs(gid_t gid)
{
  if (gid) {
    if (setgid(gid) == 0) {
      if (setgroups(0, NULL) < 0) {
        warnlog("Warning: Unable to drop supplementary gids: %s", stringerror());
      }
    }
    else {
      warnlog("Warning: Unable to set group ID to %d: %s", gid, stringerror());
    }
  }
}

static void dropUserPrivs(uid_t uid)
{
  if(uid) {
    if(setuid(uid) < 0) {
      warnlog("Warning: Unable to set user ID to %d: %s", uid, stringerror());
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
  if (g_maxTCPClientThreads) {
    requiredFDsCount += (backends->size() * (*g_maxTCPClientThreads));
  }
  /* listening sockets */
  requiredFDsCount += udpBindsCount;
  requiredFDsCount += tcpBindsCount;
  /* number of TCP connections currently served, assuming 1 connection per worker thread which is of course not right */
  if (g_maxTCPClientThreads) {
    requiredFDsCount += *g_maxTCPClientThreads;
    /* max pipes for communicating between TCP acceptors and client threads */
    requiredFDsCount += (*g_maxTCPClientThreads * 2);
  }
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

static void setUpLocalBind(std::unique_ptr<ClientState>& cs)
{
  /* skip some warnings if there is an identical UDP context */
  bool warn = cs->tcp == false || cs->tlsFrontend != nullptr || cs->dohFrontend != nullptr;
  int& fd = cs->tcp == false ? cs->udpFD : cs->tcpFD;
  (void) warn;

  fd = SSocket(cs->local.sin4.sin_family, cs->tcp == false ? SOCK_DGRAM : SOCK_STREAM, 0);

  if (cs->tcp) {
    SSetsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1);
#endif
    if (cs->fastOpenQueueSize > 0) {
#ifdef TCP_FASTOPEN
      SSetsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, cs->fastOpenQueueSize);
#else
      if (warn) {
        warnlog("TCP Fast Open has been configured on local address '%s' but is not supported", cs->local.toStringWithPort());
      }
#endif
    }
  }

  if(cs->local.sin4.sin_family == AF_INET6) {
    SSetsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, 1);
  }

  bindAny(cs->local.sin4.sin_family, fd);

  if(!cs->tcp && IsAnyAddress(cs->local)) {
    int one=1;
    setsockopt(fd, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one));     // linux supports this, so why not - might fail on other systems
#ifdef IPV6_RECVPKTINFO
    setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
#endif
  }

  if (cs->reuseport) {
    if (!setReusePort(fd)) {
      if (warn) {
        /* no need to warn again if configured but support is not available, we already did for UDP */
        warnlog("SO_REUSEPORT has been configured on local address '%s' but is not supported", cs->local.toStringWithPort());
      }
    }
  }

  /* Only set this on IPv4 UDP sockets.
     Don't set it for DNSCrypt binds. DNSCrypt pads queries for privacy
     purposes, so we do receive large, sometimes fragmented datagrams. */
  if (!cs->tcp && !cs->dnscryptCtx) {
    try {
      setSocketIgnorePMTU(cs->udpFD, cs->local.sin4.sin_family);
    }
    catch(const std::exception& e) {
      warnlog("Failed to set IP_MTU_DISCOVER on UDP server socket for local address '%s': %s", cs->local.toStringWithPort(), e.what());
    }
  }

  const std::string& itf = cs->interface;
  if (!itf.empty()) {
#ifdef SO_BINDTODEVICE
    int res = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, itf.c_str(), itf.length());
    if (res != 0) {
      warnlog("Error setting up the interface on local address '%s': %s", cs->local.toStringWithPort(), stringerror());
    }
#else
    if (warn) {
      warnlog("An interface has been configured on local address '%s' but SO_BINDTODEVICE is not supported", cs->local.toStringWithPort());
    }
#endif
  }

#ifdef HAVE_EBPF
  if (g_defaultBPFFilter) {
    cs->attachFilter(g_defaultBPFFilter);
    vinfolog("Attaching default BPF Filter to %s frontend %s", (!cs->tcp ? "UDP" : "TCP"), cs->local.toStringWithPort());
  }
#endif /* HAVE_EBPF */

  if (cs->tlsFrontend != nullptr) {
    if (!cs->tlsFrontend->setupTLS()) {
      errlog("Error while setting up TLS on local address '%s', exiting", cs->local.toStringWithPort());
      _exit(EXIT_FAILURE);
    }
  }

  if (cs->dohFrontend != nullptr) {
    cs->dohFrontend->setup();
  }

  SBind(fd, cs->local);

  if (cs->tcp) {
    SListen(cs->tcpFD, cs->tcpListenQueueSize);

    if (cs->tlsFrontend != nullptr) {
      warnlog("Listening on %s for TLS", cs->local.toStringWithPort());
    }
    else if (cs->dohFrontend != nullptr) {
      warnlog("Listening on %s for DoH", cs->local.toStringWithPort());
    }
    else if (cs->dnscryptCtx != nullptr) {
      warnlog("Listening on %s for DNSCrypt", cs->local.toStringWithPort());
    }
    else {
      warnlog("Listening on %s", cs->local.toStringWithPort());
    }
  }

  cs->ready = true;
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

#ifdef COVERAGE
static void sighandler(int sig)
{
  exit(EXIT_SUCCESS);
}
#endif

int main(int argc, char** argv)
{
  try {
    size_t udpBindsCount = 0;
    size_t tcpBindsCount = 0;
    rl_attempted_completion_function = my_completion;
    rl_completion_append_character = 0;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
#ifdef COVERAGE
    signal(SIGTERM, sighandler);
#endif

    openlog("dnsdist", LOG_PID|LOG_NDELAY, LOG_DAEMON);

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
        g_cmdLine.locals.push_back(boost::trim_copy(string(optarg)));
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
#ifdef HAVE_CDB
        cout<<"cdb ";
#endif
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
#ifdef HAVE_DNS_OVER_HTTPS
        cout<<"dns-over-https(DOH) ";
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
#ifdef HAVE_LIBCRYPTO
        cout<<"ipcipher ";
#endif
#ifdef HAVE_LIBSODIUM
        cout<<"libsodium ";
#endif
#ifdef HAVE_LMDB
        cout<<"lmdb ";
#endif
        cout<<"protobuf ";
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

    argc -= optind;
    argv += optind;
    (void) argc;

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
      setupLua(*(g_lua.lock()), true, false, g_cmdLine.config);
      if (clientAddress != ComboAddress())
        g_serverControl = clientAddress;
      doClient(g_serverControl, g_cmdLine.command);
#ifdef COVERAGE
      exit(EXIT_SUCCESS);
#else
      _exit(EXIT_SUCCESS);
#endif
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
    registerBuiltInWebHandlers();

    if (g_cmdLine.checkConfig) {
      setupLua(*(g_lua.lock()), false, true, g_cmdLine.config);
      // No exception was thrown
      infolog("Configuration '%s' OK!", g_cmdLine.config);
#ifdef COVERAGE
      exit(EXIT_SUCCESS);
#else
      _exit(EXIT_SUCCESS);
#endif
    }

    auto todo = setupLua(*(g_lua.lock()), false, false, g_cmdLine.config);

    auto localPools = g_pools.getCopy();
    {
      bool precompute = false;
      if (g_policy.getLocal()->getName() == "chashed") {
        precompute = true;
      } else {
        for (const auto& entry: localPools) {
          if (entry.second->policy != nullptr && entry.second->policy->getName() == "chashed") {
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
          if (backend->weight < 100) {
            vinfolog("Warning, the backend '%s' has a very low weight (%d), which will not yield a good distribution of queries with the 'chashed' policy. Please consider raising it to at least '100'.", backend->getName(), backend->weight);
          }

          backend->hash();
        }
      }
    }

    if (!g_cmdLine.locals.empty()) {
      for (auto it = g_frontends.begin(); it != g_frontends.end(); ) {
        /* DoH, DoT and DNSCrypt frontends are separate */
        if ((*it)->dohFrontend == nullptr && (*it)->tlsFrontend == nullptr && (*it)->dnscryptCtx == nullptr) {
          it = g_frontends.erase(it);
        }
        else {
          ++it;
        }
      }

      for(const auto& loc : g_cmdLine.locals) {
        /* UDP */
        g_frontends.push_back(std::unique_ptr<ClientState>(new ClientState(ComboAddress(loc, 53), false, false, 0, "", {})));
        /* TCP */
        g_frontends.push_back(std::unique_ptr<ClientState>(new ClientState(ComboAddress(loc, 53), true, false, 0, "", {})));
      }
    }

    if (g_frontends.empty()) {
      /* UDP */
      g_frontends.push_back(std::unique_ptr<ClientState>(new ClientState(ComboAddress("127.0.0.1", 53), false, false, 0, "", {})));
      /* TCP */
      g_frontends.push_back(std::unique_ptr<ClientState>(new ClientState(ComboAddress("127.0.0.1", 53), true, false, 0, "", {})));
    }

    g_configurationDone = true;

    for(auto& frontend : g_frontends) {
      setUpLocalBind(frontend);

      if (frontend->tcp == false) {
        ++udpBindsCount;
      }
      else {
        ++tcpBindsCount;
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

    uid_t newgid=getegid();
    gid_t newuid=geteuid();

    if(!g_cmdLine.gid.empty())
      newgid = strToGID(g_cmdLine.gid.c_str());

    if(!g_cmdLine.uid.empty())
      newuid = strToUID(g_cmdLine.uid.c_str());

    if (getegid() != newgid) {
      if (running_in_service_mgr()) {
        errlog("--gid/-g set on command-line, but dnsdist was started as a systemd service. Use the 'Group' setting in the systemd unit file to set the group to run as");
        _exit(EXIT_FAILURE);
      }
      dropGroupPrivs(newgid);
    }

    if (geteuid() != newuid) {
      if (running_in_service_mgr()) {
        errlog("--uid/-u set on command-line, but dnsdist was started as a systemd service. Use the 'User' setting in the systemd unit file to set the user to run as");
        _exit(EXIT_FAILURE);
      }
      dropUserPrivs(newuid);
    }

    try {
      /* we might still have capabilities remaining,
         for example if we have been started as root
         without --uid or --gid (please don't do that)
         or as an unprivileged user with ambient
         capabilities like CAP_NET_BIND_SERVICE.
      */
      dropCapabilities(g_capabilitiesToRetain);
    }
    catch (const std::exception& e) {
      warnlog("%s", e.what());
    }

    /* this need to be done _after_ dropping privileges */
    g_delay = new DelayPipe<DelayedPacket>();

    if (g_snmpAgent) {
      g_snmpAgent->run();
    }

    if (!g_maxTCPClientThreads) {
      g_maxTCPClientThreads = std::max(tcpBindsCount, static_cast<size_t>(10));
    }
    else if (*g_maxTCPClientThreads == 0 && tcpBindsCount > 0) {
      warnlog("setMaxTCPClientThreads() has been set to 0 while we are accepting TCP connections, raising to 1");
      g_maxTCPClientThreads = 1;
    }

    g_tcpclientthreads = std::unique_ptr<TCPClientCollection>(new TCPClientCollection(*g_maxTCPClientThreads, g_useTCPSinglePipe));

    for (auto& t : todo) {
      t();
    }

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

    auto mplexer = std::shared_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent());
    for(auto& dss : g_dstates.getCopy()) { // it is a copy, but the internal shared_ptrs are the real deal
      if (dss->availability == DownstreamState::Availability::Auto) {
        if (!queueHealthCheck(mplexer, dss, true)) {
          dss->setUpStatus(false);
          warnlog("Marking downstream %s as 'down'", dss->getNameWithAddr());
        }
      }
    }
    handleQueuedHealthChecks(mplexer, true);

    /* we need to create the TCP worker threads before the
       acceptor ones, otherwise we might crash when processing
       the first TCP query */
    while (!g_tcpclientthreads->hasReachedMaxThreads()) {
      g_tcpclientthreads->addTCPClientThread();
    }

    for(auto& cs : g_frontends) {
      if (cs->dohFrontend != nullptr) {
#ifdef HAVE_DNS_OVER_HTTPS
        std::thread t1(dohThread, cs.get());
        if (!cs->cpus.empty()) {
          mapThreadToCPUList(t1.native_handle(), cs->cpus);
        }
        t1.detach();
#endif /* HAVE_DNS_OVER_HTTPS */
        continue;
      }
      if (cs->udpFD >= 0) {
        thread t1(udpClientThread, cs.get());
        if (!cs->cpus.empty()) {
          mapThreadToCPUList(t1.native_handle(), cs->cpus);
        }
        t1.detach();
      }
      else if (cs->tcpFD >= 0) {
        thread t1(tcpAcceptorThread, cs.get());
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

    thread dynBlockMaintThread(dynBlockMaintenanceThread);
    dynBlockMaintThread.detach();

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
#ifdef COVERAGE
    exit(EXIT_SUCCESS);
#else
    _exit(EXIT_SUCCESS);
#endif
  }
  catch (const LuaContext::ExecutionErrorException& e) {
    try {
      errlog("Fatal Lua error: %s", e.what());
      std::rethrow_if_nested(e);
    } catch(const std::exception& ne) {
      errlog("Details: %s", ne.what());
    }
    catch (const PDNSException &ae)
    {
      errlog("Fatal pdns error: %s", ae.reason);
    }
#ifdef COVERAGE
    exit(EXIT_FAILURE);
#else
    _exit(EXIT_FAILURE);
#endif
  }
  catch (const std::exception &e)
  {
    errlog("Fatal error: %s", e.what());
#ifdef COVERAGE
    exit(EXIT_FAILURE);
#else
    _exit(EXIT_FAILURE);
#endif
  }
  catch (const PDNSException &ae)
  {
    errlog("Fatal pdns error: %s", ae.reason);
#ifdef COVERAGE
    exit(EXIT_FAILURE);
#else
    _exit(EXIT_FAILURE);
#endif
  }
}

uint64_t getLatencyCount(const std::string&)
{
    return g_stats.responses + g_stats.selfAnswered + g_stats.cacheHits;
}
