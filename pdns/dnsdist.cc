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

#include <cstdint>
#include <fstream>
#include <getopt.h>
#include <grp.h>
#include <limits>
#include <netinet/tcp.h>
#include <pwd.h>
#include <sys/resource.h>
#include <unistd.h>

#ifdef HAVE_LIBEDIT
#if defined (__OpenBSD__) || defined(__NetBSD__)
// If this is not undeffed, __attribute__ wil be redefined by /usr/include/readline/rlstdc.h
#undef __STRICT_ANSI__
#include <readline/readline.h>
#else
#include <editline/readline.h>
#endif
#endif /* HAVE_LIBEDIT */

#include "dnsdist-systemd.hh"
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "dnsdist.hh"
#include "dnsdist-async.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-carbon.hh"
#include "dnsdist-console.hh"
#include "dnsdist-discovery.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-healthchecks.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-random.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-secpoll.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-web.hh"
#include "dnsdist-xpf.hh"

#include "base64.hh"
#include "capabilities.hh"
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
std::optional<std::ofstream> g_verboseStream{std::nullopt};

struct DNSDistStats g_stats;

uint16_t g_maxOutstanding{std::numeric_limits<uint16_t>::max()};
uint32_t g_staleCacheEntriesTTL{0};
bool g_syslog{true};
bool g_logtimestamps{false};
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
std::vector<uint32_t> g_TCPFastOpenKey;
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
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_cacheInsertedRespRuleActions;
GlobalStateHolder<vector<DNSDistResponseRuleAction> > g_selfansweredrespruleactions;

Rings g_rings;
QueryCount g_qcount;

GlobalStateHolder<servers_t> g_dstates;

bool g_servFailOnNoPolicy{false};
bool g_truncateTC{false};
bool g_fixupCase{false};
bool g_dropEmptyQueries{false};
uint32_t g_socketUDPSendBuffer{0};
uint32_t g_socketUDPRecvBuffer{0};

std::set<std::string> g_capabilitiesToRetain;

static size_t const s_initialUDPPacketBufferSize = s_maxPacketCacheEntrySize + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
static_assert(s_initialUDPPacketBufferSize <= UINT16_MAX, "Packet size should fit in a uint16_t");

static ssize_t sendfromto(int sock, const void* data, size_t len, int flags, const ComboAddress& from, const ComboAddress& to)
{
  if (from.sin4.sin_family == 0) {
    return sendto(sock, data, len, flags, reinterpret_cast<const struct sockaddr*>(&to), to.getSocklen());
  }
  struct msghdr msgh;
  struct iovec iov;
  cmsgbuf_aligned cbuf;

  /* Set up iov and msgh structures. */
  memset(&msgh, 0, sizeof(struct msghdr));
  iov.iov_base = const_cast<void*>(data);
  iov.iov_len = len;
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  msgh.msg_name = (struct sockaddr*)&to;
  msgh.msg_namelen = to.getSocklen();

  if (from.sin4.sin_family) {
    addCMsgSrcAddr(&msgh, &cbuf, &from, 0);
  }
  else {
    msgh.msg_control=nullptr;
  }
  return sendmsg(sock, &msgh, flags);
}

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

#ifndef DISABLE_DELAY_PIPE
struct DelayedPacket
{
  int fd;
  PacketBuffer packet;
  ComboAddress destination;
  ComboAddress origDest;
  void operator()()
  {
    ssize_t res = sendfromto(fd, packet.data(), packet.size(), 0, origDest, destination);
    if (res == -1) {
      int err = errno;
      vinfolog("Error sending delayed response to %s: %s", destination.toStringWithPort(), strerror(err));
    }
  }
};

static DelayPipe<DelayedPacket>* g_delay = nullptr;
#endif /* DISABLE_DELAY_PIPE */

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

static void doLatencyStats(dnsdist::Protocol protocol, double udiff)
{
  constexpr auto doAvg = [](double& var, double n, double weight) {
    var = (weight -1) * var/weight + n/weight;
  };

  if (protocol == dnsdist::Protocol::DoUDP || protocol == dnsdist::Protocol::DNSCryptUDP) {
    if (udiff < 1000) {
      ++g_stats.latency0_1;
    }
    else if (udiff < 10000) {
      ++g_stats.latency1_10;
    }
    else if (udiff < 50000) {
      ++g_stats.latency10_50;
    }
    else if (udiff < 100000) {
      ++g_stats.latency50_100;
    }
    else if (udiff < 1000000) {
      ++g_stats.latency100_1000;
    }
    else {
      ++g_stats.latencySlow;
    }

    g_stats.latencySum += udiff / 1000;
    ++g_stats.latencyCount;

    doAvg(g_stats.latencyAvg100,     udiff,     100);
    doAvg(g_stats.latencyAvg1000,    udiff,    1000);
    doAvg(g_stats.latencyAvg10000,   udiff,   10000);
    doAvg(g_stats.latencyAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoTCP || protocol == dnsdist::Protocol::DNSCryptTCP) {
    doAvg(g_stats.latencyTCPAvg100,     udiff,     100);
    doAvg(g_stats.latencyTCPAvg1000,    udiff,    1000);
    doAvg(g_stats.latencyTCPAvg10000,   udiff,   10000);
    doAvg(g_stats.latencyTCPAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoT) {
    doAvg(g_stats.latencyDoTAvg100,     udiff,     100);
    doAvg(g_stats.latencyDoTAvg1000,    udiff,    1000);
    doAvg(g_stats.latencyDoTAvg10000,   udiff,   10000);
    doAvg(g_stats.latencyDoTAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoH) {
    doAvg(g_stats.latencyDoHAvg100,     udiff,     100);
    doAvg(g_stats.latencyDoHAvg1000,    udiff,    1000);
    doAvg(g_stats.latencyDoHAvg10000,   udiff,   10000);
    doAvg(g_stats.latencyDoHAvg1000000, udiff, 1000000);
  }
}

bool responseContentMatches(const PacketBuffer& response, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const std::shared_ptr<DownstreamState>& remote, unsigned int& qnameWireLength)
{
  if (response.size() < sizeof(dnsheader)) {
    return false;
  }

  const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(response.data());
  if (dh->qr == 0) {
    ++g_stats.nonCompliantResponses;
    if (remote) {
      ++remote->nonCompliantResponses;
    }
    return false;
  }

  if (dh->qdcount == 0) {
    if ((dh->rcode != RCode::NoError && dh->rcode != RCode::NXDomain) || g_allowEmptyResponse) {
      return true;
    }
    else {
      ++g_stats.nonCompliantResponses;
      if (remote) {
        ++remote->nonCompliantResponses;
      }
      return false;
    }
  }

  uint16_t rqtype, rqclass;
  DNSName rqname;
  try {
    rqname = DNSName(reinterpret_cast<const char*>(response.data()), response.size(), sizeof(dnsheader), false, &rqtype, &rqclass, &qnameWireLength);
  }
  catch (const std::exception& e) {
    if (remote && response.size() > 0 && static_cast<size_t>(response.size()) > sizeof(dnsheader)) {
      infolog("Backend %s sent us a response with id %d that did not parse: %s", remote->d_config.remote.toStringWithPort(), ntohs(dh->id), e.what());
    }
    ++g_stats.nonCompliantResponses;
    if (remote) {
      ++remote->nonCompliantResponses;
    }
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
static bool encryptResponse(PacketBuffer& response, size_t maximumSize, bool tcp, std::unique_ptr<DNSCryptQuery>& dnsCryptQuery)
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

static bool applyRulesToResponse(const std::vector<DNSDistResponseRuleAction>& respRuleActions, DNSResponse& dr)
{
  DNSResponseAction::Action action = DNSResponseAction::Action::None;
  std::string ruleresult;
  for (const auto& lr : respRuleActions) {
    if (lr.d_rule->matches(&dr)) {
      ++lr.d_rule->d_matches;
      action = (*lr.d_action)(&dr, &ruleresult);
      switch (action) {
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
        pdns::checked_stoi_into(dr.ids.delayMsec, ruleresult); // sorry
        break;
      case DNSResponseAction::Action::None:
        break;
      }
    }
  }

  return true;
}

bool processResponseAfterRules(PacketBuffer& response, const std::vector<DNSDistResponseRuleAction>& cacheInsertedRespRuleActions, DNSResponse& dr, bool muted)
{
  bool zeroScope = false;
  if (!fixUpResponse(response, dr.ids.qname, dr.ids.origFlags, dr.ids.ednsAdded, dr.ids.ecsAdded, dr.ids.useZeroScope ? &zeroScope : nullptr)) {
    return false;
  }

  if (dr.ids.packetCache && !dr.ids.selfGenerated && !dr.ids.skipCache && response.size() <= s_maxPacketCacheEntrySize) {
    if (!dr.ids.useZeroScope) {
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
    uint32_t cacheKey = dr.ids.cacheKey;
    if (dr.ids.protocol == dnsdist::Protocol::DoH && dr.ids.forwardedOverUDP) {
      cacheKey = dr.ids.cacheKeyUDP;
    }
    else if (zeroScope) {
      // if zeroScope, pass the pre-ECS hash-key and do not pass the subnet to the cache
      cacheKey = dr.ids.cacheKeyNoECS;
    }

    dr.ids.packetCache->insert(cacheKey, zeroScope ? boost::none : dr.ids.subnet, dr.ids.cacheFlags, dr.ids.dnssecOK, dr.ids.qname, dr.ids.qtype, dr.ids.qclass, response, dr.ids.forwardedOverUDP, dr.getHeader()->rcode, dr.ids.tempFailureTTL);

    if (!applyRulesToResponse(cacheInsertedRespRuleActions, dr)) {
      return false;
    }
  }

  if (dr.ids.ttlCap > 0) {
    std::string result;
    LimitTTLResponseAction ac(0, dr.ids.ttlCap, {});
    ac(&dr, &result);
  }

#ifdef HAVE_DNSCRYPT
  if (!muted) {
    if (!encryptResponse(response, dr.getMaximumSize(), dr.overTCP(), dr.ids.dnsCryptQuery)) {
      return false;
    }
  }
#endif /* HAVE_DNSCRYPT */

  return true;
}

bool processResponse(PacketBuffer& response, const std::vector<DNSDistResponseRuleAction>& respRuleActions, const std::vector<DNSDistResponseRuleAction>& cacheInsertedRespRuleActions, DNSResponse& dr, bool muted)
{
  if (!applyRulesToResponse(respRuleActions, dr)) {
    return false;
  }

  if (dr.isAsynchronous()) {
    return true;
  }

  return processResponseAfterRules(response, cacheInsertedRespRuleActions, dr, muted);
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

bool sendUDPResponse(int origFD, const PacketBuffer& response, const int delayMsec, const ComboAddress& origDest, const ComboAddress& origRemote)
{
#ifndef DISABLE_DELAY_PIPE
  if (delayMsec && g_delay) {
    DelayedPacket dp{origFD, response, origRemote, origDest};
    g_delay->submit(dp, delayMsec);
    return true;
  }
#endif /* DISABLE_DELAY_PIPE */
  ssize_t res = sendfromto(origFD, response.data(), response.size(), 0, origDest, origRemote);
  if (res == -1) {
    int err = errno;
    vinfolog("Error sending response to %s: %s", origRemote.toStringWithPort(), stringerror(err));
  }

  return true;
}

void handleResponseSent(const InternalQueryState& ids, double udiff, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH, dnsdist::Protocol outgoingProtocol, bool fromBackend)
{
  handleResponseSent(ids.qname, ids.qtype, udiff, client, backend, size, cleartextDH, outgoingProtocol, ids.protocol, fromBackend);
}

void handleResponseSent(const DNSName& qname, const QType& qtype, double udiff, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH, dnsdist::Protocol outgoingProtocol, dnsdist::Protocol incomingProtocol, bool fromBackend)
{
  if (g_rings.shouldRecordResponses()) {
    struct timespec ts;
    gettime(&ts);
    g_rings.insertResponse(ts, client, qname, qtype, static_cast<unsigned int>(udiff), size, cleartextDH, backend, outgoingProtocol);
  }

  switch (cleartextDH.rcode) {
  case RCode::NXDomain:
    ++g_stats.frontendNXDomain;
    break;
  case RCode::ServFail:
    if (fromBackend) {
      ++g_stats.servfailResponses;
    }
    ++g_stats.frontendServFail;
    break;
  case RCode::NoError:
    ++g_stats.frontendNoError;
    break;
  }

  doLatencyStats(incomingProtocol, udiff);
}

static void handleResponseForUDPClient(InternalQueryState& ids, PacketBuffer& response, const std::vector<DNSDistResponseRuleAction>& respRuleActions, const std::vector<DNSDistResponseRuleAction>& cacheInsertedRespRuleActions, const std::shared_ptr<DownstreamState>& ds, bool isAsync, bool selfGenerated)
{
  DNSResponse dr(ids, response, ds);

  if (ids.udpPayloadSize > 0 && response.size() > ids.udpPayloadSize) {
    vinfolog("Got a response of size %d while the initial UDP payload size was %d, truncating", response.size(), ids.udpPayloadSize);
    truncateTC(dr.getMutableData(), dr.getMaximumSize(), dr.ids.qname.wirelength());
    dr.getHeader()->tc = true;
  }
  else if (dr.getHeader()->tc && g_truncateTC) {
    truncateTC(response, dr.getMaximumSize(), dr.ids.qname.wirelength());
  }

  /* when the answer is encrypted in place, we need to get a copy
     of the original header before encryption to fill the ring buffer */
  dnsheader cleartextDH;
  memcpy(&cleartextDH, dr.getHeader(), sizeof(cleartextDH));

  if (!isAsync) {
    if (!processResponse(response, respRuleActions, cacheInsertedRespRuleActions, dr, ids.cs && ids.cs->muted)) {
      return;
    }

    if (dr.isAsynchronous()) {
      return;
    }
  }

  ++g_stats.responses;
  if (ids.cs) {
    ++ids.cs->responses;
  }

  bool muted = true;
  if (ids.cs && !ids.cs->muted) {
    ComboAddress empty;
    empty.sin4.sin_family = 0;
    sendUDPResponse(ids.cs->udpFD, response, dr.ids.delayMsec, ids.hopLocal, ids.hopRemote);
    muted = false;
  }

  if (!selfGenerated) {
    double udiff = ids.queryRealTime.udiff();
    if (!muted) {
      vinfolog("Got answer from %s, relayed to %s (UDP), took %f us", ds->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), udiff);
    }
    else {
      vinfolog("Got answer from %s, NOT relayed to %s (UDP) since that frontend is muted, took %f us", ds->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), udiff);
    }

    handleResponseSent(ids, udiff, dr.ids.origRemote, ds->d_config.remote, response.size(), cleartextDH, ds->getProtocol(), true);
  }
  else {
    handleResponseSent(ids, 0., dr.ids.origRemote, ComboAddress(), response.size(), cleartextDH, dnsdist::Protocol::DoUDP, false);
  }
}

// listens on a dedicated socket, lobs answers from downstream servers to original requestors
void responderThread(std::shared_ptr<DownstreamState> dss)
{
  try {
  setThreadName("dnsdist/respond");
  auto localRespRuleActions = g_respruleactions.getLocal();
  auto localCacheInsertedRespRuleActions = g_cacheInsertedRespRuleActions.getLocal();
  const size_t initialBufferSize = getInitialUDPPacketBufferSize();
  PacketBuffer response(initialBufferSize);
  uint16_t queryId = 0;
  std::vector<int> sockets;
  sockets.reserve(dss->sockets.size());

  for(;;) {
    try {
      dss->pickSocketsReadyForReceiving(sockets);
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

        auto ids = dss->getState(queryId);
        if (!ids) {
          continue;
        }

        unsigned int qnameWireLength = 0;
        if (fd != ids->backendFD || !responseContentMatches(response, ids->qname, ids->qtype, ids->qclass, dss, qnameWireLength)) {
          dss->restoreState(queryId, std::move(*ids));
          continue;
        }

        auto du = std::move(ids->du);

        dh->id = ids->origID;
        ++dss->responses;

        double udiff = ids->queryRealTime.udiff();
        // do that _before_ the processing, otherwise it's not fair to the backend
        dss->latencyUsec = (127.0 * dss->latencyUsec / 128.0) + udiff / 128.0;
        dss->reportResponse(dh->rcode);

        /* don't call processResponse for DOH */
        if (du) {
#ifdef HAVE_DNS_OVER_HTTPS
          // DoH query, we cannot touch du after that
          handleUDPResponseForDoH(std::move(du), std::move(response), std::move(*ids));
#endif
          continue;
        }

        handleResponseForUDPClient(*ids, response, *localRespRuleActions, *localCacheInsertedRespRuleActions, dss, false, false);
      }
    }
    catch (const std::exception& e) {
      vinfolog("Got an error in UDP responder thread while parsing a response from %s, id %d: %s", dss->d_config.remote.toStringWithPort(), queryId, e.what());
    }
  }
}
catch (const std::exception& e) {
  errlog("UDP responder thread died because of exception: %s", e.what());
}
catch (const PDNSException& e) {
  errlog("UDP responder thread died because of PowerDNS exception: %s", e.reason);
}
catch (...) {
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

static void spoofPacketFromString(DNSQuestion& dq, const string& spoofContent)
{
  string result;

  SpoofAction sa(spoofContent.c_str(), spoofContent.size());
  sa(&dq, &result);
}

bool processRulesResult(const DNSAction::Action& action, DNSQuestion& dq, std::string& ruleresult, bool& drop)
{
  if (dq.isAsynchronous()) {
    return false;
  }

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
    dq.getHeader()->qr = true;
    return true;
    break;
  case DNSAction::Action::Refused:
    dq.getHeader()->rcode = RCode::Refused;
    dq.getHeader()->qr = true;
    return true;
    break;
  case DNSAction::Action::ServFail:
    dq.getHeader()->rcode = RCode::ServFail;
    dq.getHeader()->qr = true;
    return true;
    break;
  case DNSAction::Action::Spoof:
    spoofResponseFromString(dq, ruleresult, false);
    return true;
    break;
  case DNSAction::Action::SpoofPacket:
    spoofPacketFromString(dq, ruleresult);
    return true;
    break;
  case DNSAction::Action::SpoofRaw:
    spoofResponseFromString(dq, ruleresult, true);
    return true;
    break;
  case DNSAction::Action::Truncate:
    if (!dq.overTCP()) {
      dq.getHeader()->tc = true;
      dq.getHeader()->qr = true;
      dq.getHeader()->ra = dq.getHeader()->rd;
      dq.getHeader()->aa = false;
      dq.getHeader()->ad = false;
      ++g_stats.ruleTruncated;
      return true;
    }
    break;
  case DNSAction::Action::HeaderModify:
    return true;
    break;
  case DNSAction::Action::Pool:
    /* we need to keep this because a custom Lua action can return
       DNSAction.Spoof, 'poolname' */
    dq.ids.poolName = ruleresult;
    return true;
    break;
  case DNSAction::Action::NoRecurse:
    dq.getHeader()->rd = false;
    return true;
    break;
    /* non-terminal actions follow */
  case DNSAction::Action::Delay:
    pdns::checked_stoi_into(dq.ids.delayMsec, ruleresult); // sorry
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
  if (g_rings.shouldRecordQueries()) {
    g_rings.insertQuery(now, dq.ids.origRemote, dq.ids.qname, dq.ids.qtype, dq.getData().size(), *dq.getHeader(), dq.getProtocol());
  }

  if (g_qcount.enabled) {
    string qname = dq.ids.qname.toLogString();
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

#ifndef DISABLE_DYNBLOCKS
  /* the Dynamic Block mechanism supports address and port ranges, so we need to pass the full address and port */
  if (auto got = holders.dynNMGBlock->lookup(AddressAndPortRange(dq.ids.origRemote, dq.ids.origRemote.isIPv4() ? 32 : 128, 16))) {
    auto updateBlockStats = [&got]() {
      ++g_stats.dynBlocked;
      got->second.blocks++;
    };

    if (now < got->second.until) {
      DNSAction::Action action = got->second.action;
      if (action == DNSAction::Action::None) {
        action = g_dynBlockAction;
      }
      switch (action) {
      case DNSAction::Action::NoOp:
        /* do nothing */
        break;

      case DNSAction::Action::Nxdomain:
        vinfolog("Query from %s turned into NXDomain because of dynamic block", dq.ids.origRemote.toStringWithPort());
        updateBlockStats();

        dq.getHeader()->rcode = RCode::NXDomain;
        dq.getHeader()->qr=true;
        return true;

      case DNSAction::Action::Refused:
        vinfolog("Query from %s refused because of dynamic block", dq.ids.origRemote.toStringWithPort());
        updateBlockStats();

        dq.getHeader()->rcode = RCode::Refused;
        dq.getHeader()->qr = true;
        return true;

      case DNSAction::Action::Truncate:
        if (!dq.overTCP()) {
          updateBlockStats();
          vinfolog("Query from %s truncated because of dynamic block", dq.ids.origRemote.toStringWithPort());
          dq.getHeader()->tc = true;
          dq.getHeader()->qr = true;
          dq.getHeader()->ra = dq.getHeader()->rd;
          dq.getHeader()->aa = false;
          dq.getHeader()->ad = false;
          return true;
        }
        else {
          vinfolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dq.ids.origRemote.toStringWithPort(), dq.ids.qname.toLogString());
        }
        break;
      case DNSAction::Action::NoRecurse:
        updateBlockStats();
        vinfolog("Query from %s setting rd=0 because of dynamic block", dq.ids.origRemote.toStringWithPort());
        dq.getHeader()->rd = false;
        return true;
      default:
        updateBlockStats();
        vinfolog("Query from %s dropped because of dynamic block", dq.ids.origRemote.toStringWithPort());
        return false;
      }
    }
  }

  if (auto got = holders.dynSMTBlock->lookup(dq.ids.qname)) {
    auto updateBlockStats = [&got]() {
      ++g_stats.dynBlocked;
      got->blocks++;
    };

    if (now < got->until) {
      DNSAction::Action action = got->action;
      if (action == DNSAction::Action::None) {
        action = g_dynBlockAction;
      }
      switch (action) {
      case DNSAction::Action::NoOp:
        /* do nothing */
        break;
      case DNSAction::Action::Nxdomain:
        vinfolog("Query from %s for %s turned into NXDomain because of dynamic block", dq.ids.origRemote.toStringWithPort(), dq.ids.qname.toLogString());
        updateBlockStats();

        dq.getHeader()->rcode = RCode::NXDomain;
        dq.getHeader()->qr = true;
        return true;
      case DNSAction::Action::Refused:
        vinfolog("Query from %s for %s refused because of dynamic block", dq.ids.origRemote.toStringWithPort(), dq.ids.qname.toLogString());
        updateBlockStats();

        dq.getHeader()->rcode = RCode::Refused;
        dq.getHeader()->qr = true;
        return true;
      case DNSAction::Action::Truncate:
        if (!dq.overTCP()) {
          updateBlockStats();

          vinfolog("Query from %s for %s truncated because of dynamic block", dq.ids.origRemote.toStringWithPort(), dq.ids.qname.toLogString());
          dq.getHeader()->tc = true;
          dq.getHeader()->qr = true;
          dq.getHeader()->ra = dq.getHeader()->rd;
          dq.getHeader()->aa = false;
          dq.getHeader()->ad = false;
          return true;
        }
        else {
          vinfolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dq.ids.origRemote.toStringWithPort(), dq.ids.qname.toLogString());
        }
        break;
      case DNSAction::Action::NoRecurse:
        updateBlockStats();
        vinfolog("Query from %s setting rd=0 because of dynamic block", dq.ids.origRemote.toStringWithPort());
        dq.getHeader()->rd = false;
        return true;
      default:
        updateBlockStats();
        vinfolog("Query from %s for %s dropped because of dynamic block", dq.ids.origRemote.toStringWithPort(), dq.ids.qname.toLogString());
        return false;
      }
    }
  }
#endif /* DISABLE_DYNBLOCKS */

  DNSAction::Action action = DNSAction::Action::None;
  string ruleresult;
  bool drop = false;
  for (const auto& lr : *holders.ruleactions) {
    if (lr.d_rule->matches(&dq)) {
      lr.d_rule->d_matches++;
      action = (*lr.d_action)(&dq, &ruleresult);
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

  if (ss->d_config.sourceItf == 0) {
    result = send(sd, request.data(), request.size(), 0);
  }
  else {
    struct msghdr msgh;
    struct iovec iov;
    cmsgbuf_aligned cbuf;
    ComboAddress remote(ss->d_config.remote);
    fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), const_cast<char*>(reinterpret_cast<const char *>(request.data())), request.size(), &remote);
    addCMsgSrcAddr(&msgh, &cbuf, &ss->d_config.sourceAddr, ss->d_config.sourceItf);
    result = sendmsg(sd, &msgh, 0);
  }

  if (result == -1) {
    int savederrno = errno;
    vinfolog("Error sending request to backend %s: %s", ss->d_config.remote.toStringWithPort(), stringerror(savederrno));

    /* This might sound silly, but on Linux send() might fail with EINVAL
       if the interface the socket was bound to doesn't exist anymore.
       We don't want to reconnect the real socket if the healthcheck failed,
       because it's not using the same socket.
    */
    if (!healthCheck && (savederrno == EINVAL || savederrno == ENODEV || savederrno == ENETUNREACH)) {
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
    ++cs.nonCompliantQueries;
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
    /* so it turns out that sometimes the kernel lies to us:
       the address is set to 0.0.0.0:0 which makes our sendfromto() use
       the wrong address. In that case it's better to let the kernel
       do the work by itself and use sendto() instead.
       This is indicated by setting the family to 0 which is acted upon
       in sendUDPResponse() and DelayedPacket::().
    */
    const ComboAddress bogusV4("0.0.0.0:0");
    const ComboAddress bogusV6("[::]:0");
    if (dest.sin4.sin_family == AF_INET && dest == bogusV4) {
      dest.sin4.sin_family = 0;
    }
    else if (dest.sin4.sin_family == AF_INET6 && dest == bogusV6) {
      dest.sin4.sin_family = 0;
    }
    else {
      /* we don't get the port, only the address */
      dest.sin4.sin_port = cs.local.sin4.sin_port;
    }
  }
  else {
    dest.sin4.sin_family = 0;
  }

  ++cs.queries;
  ++g_stats.queries;

  return true;
}

bool checkDNSCryptQuery(const ClientState& cs, PacketBuffer& query, std::unique_ptr<DNSCryptQuery>& dnsCryptQuery, time_t now, bool tcp)
{
  if (cs.dnscryptCtx) {
#ifdef HAVE_DNSCRYPT
    PacketBuffer response;
    dnsCryptQuery = std::make_unique<DNSCryptQuery>(cs.dnscryptCtx);

    bool decrypted = handleDNSCryptQuery(query, *dnsCryptQuery, tcp, now, response);

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

bool checkQueryHeaders(const struct dnsheader* dh, ClientState& cs)
{
  if (dh->qr) {   // don't respond to responses
    ++g_stats.nonCompliantQueries;
    ++cs.nonCompliantQueries;
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

#ifndef DISABLE_RECVMMSG
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
#endif /* DISABLE_RECVMMSG */

/* self-generated responses or cache hits */
static bool prepareOutgoingResponse(LocalHolders& holders, const ClientState& cs, DNSQuestion& dq, bool cacheHit)
{
  std::shared_ptr<DownstreamState> ds{nullptr};
  DNSResponse dr(dq.ids, dq.getMutableData(), ds);
  dr.d_incomingTCPState = dq.d_incomingTCPState;
  dr.ids.selfGenerated = true;

  if (!applyRulesToResponse(cacheHit ? *holders.cacheHitRespRuleactions : *holders.selfAnsweredRespRuleactions, dr)) {
    return false;
  }

  if (dr.ids.ttlCap > 0) {
    std::string result;
    LimitTTLResponseAction ac(0, dr.ids.ttlCap, {});
    ac(&dr, &result);
  }

  if (cacheHit) {
    ++g_stats.cacheHits;
  }

  if (dr.isAsynchronous()) {
    return false;
  }

#ifdef HAVE_DNSCRYPT
  if (!cs.muted) {
    if (!encryptResponse(dq.getMutableData(), dq.getMaximumSize(), dq.overTCP(), dq.ids.dnsCryptQuery)) {
      return false;
    }
  }
#endif /* HAVE_DNSCRYPT */

  return true;
}

ProcessQueryResult processQueryAfterRules(DNSQuestion& dq, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend)
{
  const uint16_t queryId = ntohs(dq.getHeader()->id);

  try {
    if (dq.getHeader()->qr) { // something turned it into a response
      fixUpQueryTurnedResponse(dq, dq.ids.origFlags);

      if (!prepareOutgoingResponse(holders, *dq.ids.cs, dq, false)) {
        return ProcessQueryResult::Drop;
      }

      const auto rcode = dq.getHeader()->rcode;
      if (rcode == RCode::NXDomain) {
        ++g_stats.ruleNXDomain;
      }
      else if (rcode == RCode::Refused) {
        ++g_stats.ruleRefused;
      }
      else if (rcode == RCode::ServFail) {
        ++g_stats.ruleServFail;
      }

      ++g_stats.selfAnswered;
      ++dq.ids.cs->responses;
      return ProcessQueryResult::SendAnswer;
    }

    std::shared_ptr<ServerPool> serverPool = getPool(*holders.pools, dq.ids.poolName);
    std::shared_ptr<ServerPolicy> poolPolicy = serverPool->policy;
    dq.ids.packetCache = serverPool->packetCache;
    const auto& policy = poolPolicy != nullptr ? *poolPolicy : *(holders.policy);
    const auto servers = serverPool->getServers();
    selectedBackend = policy.getSelectedBackend(*servers, dq);

    uint32_t allowExpired = selectedBackend ? 0 : g_staleCacheEntriesTTL;

    if (dq.ids.packetCache && !dq.ids.skipCache) {
      dq.ids.dnssecOK = (getEDNSZ(dq) & EDNS_HEADER_FLAG_DO);
    }

    if (dq.useECS && ((selectedBackend && selectedBackend->d_config.useECS) || (!selectedBackend && serverPool->getECS()))) {
      // we special case our cache in case a downstream explicitly gave us a universally valid response with a 0 scope
      // we need ECS parsing (parseECS) to be true so we can be sure that the initial incoming query did not have an existing
      // ECS option, which would make it unsuitable for the zero-scope feature.
      if (dq.ids.packetCache && !dq.ids.skipCache && (!selectedBackend || !selectedBackend->d_config.disableZeroScope) && dq.ids.packetCache->isECSParsingEnabled()) {
        if (dq.ids.packetCache->get(dq, dq.getHeader()->id, &dq.ids.cacheKeyNoECS, dq.ids.subnet, dq.ids.dnssecOK, !dq.overTCP(), allowExpired, false, true, false)) {

          vinfolog("Packet cache hit for query for %s|%s from %s (%s, %d bytes)", dq.ids.qname.toLogString(), QType(dq.ids.qtype).toString(), dq.ids.origRemote.toStringWithPort(), dq.ids.protocol.toString(), dq.getData().size());

          if (!prepareOutgoingResponse(holders, *dq.ids.cs, dq, true)) {
            return ProcessQueryResult::Drop;
          }

          ++g_stats.responses;
          ++dq.ids.cs->responses;
          return ProcessQueryResult::SendAnswer;
        }

        if (!dq.ids.subnet) {
          /* there was no existing ECS on the query, enable the zero-scope feature */
          dq.ids.useZeroScope = true;
        }
      }

      if (!handleEDNSClientSubnet(dq, dq.ids.ednsAdded, dq.ids.ecsAdded)) {
        vinfolog("Dropping query from %s because we couldn't insert the ECS value", dq.ids.origRemote.toStringWithPort());
        return ProcessQueryResult::Drop;
      }
    }

    if (dq.ids.packetCache && !dq.ids.skipCache) {
      bool forwardedOverUDP = !dq.overTCP();
      if (selectedBackend && selectedBackend->isTCPOnly()) {
        forwardedOverUDP = false;
      }

      if (dq.ids.packetCache->get(dq, dq.getHeader()->id, &dq.ids.cacheKey, dq.ids.subnet, dq.ids.dnssecOK, forwardedOverUDP, allowExpired, false, true, true)) {

        restoreFlags(dq.getHeader(), dq.ids.origFlags);

        vinfolog("Packet cache hit for query for %s|%s from %s (%s, %d bytes)", dq.ids.qname.toLogString(), QType(dq.ids.qtype).toString(), dq.ids.origRemote.toStringWithPort(), dq.ids.protocol.toString(), dq.getData().size());

        if (!prepareOutgoingResponse(holders, *dq.ids.cs, dq, true)) {
          return ProcessQueryResult::Drop;
        }

        ++g_stats.responses;
        ++dq.ids.cs->responses;
        return ProcessQueryResult::SendAnswer;
      }
      else if (dq.ids.protocol == dnsdist::Protocol::DoH && !forwardedOverUDP) {
        /* do a second-lookup for UDP responses, but we do not want TC=1 answers */
        if (dq.ids.packetCache->get(dq, dq.getHeader()->id, &dq.ids.cacheKeyUDP, dq.ids.subnet, dq.ids.dnssecOK, true, allowExpired, false, false, false)) {
          if (!prepareOutgoingResponse(holders, *dq.ids.cs, dq, true)) {
            return ProcessQueryResult::Drop;
          }

          ++g_stats.responses;
          ++dq.ids.cs->responses;
          return ProcessQueryResult::SendAnswer;
        }
      }

      vinfolog("Packet cache miss for query for %s|%s from %s (%s, %d bytes)", dq.ids.qname.toLogString(), QType(dq.ids.qtype).toString(), dq.ids.origRemote.toStringWithPort(), dq.ids.protocol.toString(), dq.getData().size());

      ++g_stats.cacheMisses;
    }

    if (!selectedBackend) {
      ++g_stats.noPolicy;

      vinfolog("%s query for %s|%s from %s, no downstream server available", g_servFailOnNoPolicy ? "ServFailed" : "Dropped", dq.ids.qname.toLogString(), QType(dq.ids.qtype).toString(), dq.ids.origRemote.toStringWithPort());
      if (g_servFailOnNoPolicy) {
        dq.getHeader()->rcode = RCode::ServFail;
        dq.getHeader()->qr = true;

        fixUpQueryTurnedResponse(dq, dq.ids.origFlags);

        if (!prepareOutgoingResponse(holders, *dq.ids.cs, dq, false)) {
          return ProcessQueryResult::Drop;
        }
        ++g_stats.responses;
        ++dq.ids.cs->responses;
        // no response-only statistics counter to update.
        return ProcessQueryResult::SendAnswer;
      }

      return ProcessQueryResult::Drop;
    }

    /* save the DNS flags as sent to the backend so we can cache the answer with the right flags later */
    dq.ids.cacheFlags = *getFlagsFromDNSHeader(dq.getHeader());

    if (dq.addXPF && selectedBackend->d_config.xpfRRCode != 0) {
      addXPF(dq, selectedBackend->d_config.xpfRRCode);
    }

    selectedBackend->incQueriesCount();
    return ProcessQueryResult::PassToBackend;
  }
  catch (const std::exception& e){
    vinfolog("Got an error while parsing a %s query (after applying rules)  from %s, id %d: %s", (dq.overTCP() ? "TCP" : "UDP"), dq.ids.origRemote.toStringWithPort(), queryId, e.what());
  }
  return ProcessQueryResult::Drop;
}

class UDPTCPCrossQuerySender : public TCPQuerySender
{
public:
  UDPTCPCrossQuerySender()
  {
  }

  ~UDPTCPCrossQuerySender()
  {
  }

  bool active() const override
  {
    return true;
  }

  void handleResponse(const struct timeval& now, TCPResponse&& response) override
  {
    if (!response.d_ds && !response.d_idstate.selfGenerated) {
      throw std::runtime_error("Passing a cross-protocol answer originated from UDP without a valid downstream");
    }

    auto& ids = response.d_idstate;

    static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localRespRuleActions = g_respruleactions.getLocal();
    static thread_local LocalStateHolder<vector<DNSDistResponseRuleAction>> localCacheInsertedRespRuleActions = g_cacheInsertedRespRuleActions.getLocal();

    handleResponseForUDPClient(ids, response.d_buffer, *localRespRuleActions, *localCacheInsertedRespRuleActions, response.d_ds, response.isAsync(), response.d_idstate.selfGenerated);
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    return handleResponse(now, std::move(response));
  }

  void notifyIOError(InternalQueryState&& query, const struct timeval& now) override
  {
    // nothing to do
  }
};

class UDPCrossProtocolQuery : public CrossProtocolQuery
{
public:
  UDPCrossProtocolQuery(PacketBuffer&& buffer_, InternalQueryState&& ids_, std::shared_ptr<DownstreamState> ds): CrossProtocolQuery(InternalQuery(std::move(buffer_), std::move(ids_)), ds)
  {
    auto& ids = query.d_idstate;
    const auto& buffer = query.d_buffer;

    if (ids.udpPayloadSize == 0) {
      uint16_t z = 0;
      getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(buffer.data()), buffer.size(), &ids.udpPayloadSize, &z);
      if (ids.udpPayloadSize < 512) {
        ids.udpPayloadSize = 512;
      }
    }
  }

  ~UDPCrossProtocolQuery()
  {
  }

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    return s_sender;
  }
private:
  static std::shared_ptr<UDPTCPCrossQuerySender> s_sender;
};

std::shared_ptr<UDPTCPCrossQuerySender> UDPCrossProtocolQuery::s_sender = std::make_shared<UDPTCPCrossQuerySender>();

std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dq);
std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dq)
{
  dq.ids.origID = dq.getHeader()->id;
  return std::make_unique<UDPCrossProtocolQuery>(std::move(dq.getMutableData()), std::move(dq.ids), nullptr);
}

ProcessQueryResult processQuery(DNSQuestion& dq, LocalHolders& holders, std::shared_ptr<DownstreamState>& selectedBackend)
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

    if (dq.isAsynchronous()) {
      return ProcessQueryResult::Asynchronous;
    }

    return processQueryAfterRules(dq, holders, selectedBackend);
  }
  catch (const std::exception& e){
    vinfolog("Got an error while parsing a %s query from %s, id %d: %s", (dq.overTCP() ? "TCP" : "UDP"), dq.ids.origRemote.toStringWithPort(), queryId, e.what());
  }
  return ProcessQueryResult::Drop;
}

bool assignOutgoingUDPQueryToBackend(std::shared_ptr<DownstreamState>& ds, uint16_t queryID, DNSQuestion& dq, PacketBuffer& query, ComboAddress& dest)
{
  bool doh = dq.ids.du != nullptr;

  bool failed = false;
  size_t proxyPayloadSize = 0;
  if (ds->d_config.useProxyProtocol) {
    try {
      if (addProxyProtocol(dq, &proxyPayloadSize)) {
        if (dq.ids.du) {
          dq.ids.du->proxyProtocolPayloadSize = proxyPayloadSize;
        }
      }
    }
    catch (const std::exception& e) {
      vinfolog("Adding proxy protocol payload to %s query from %s failed: %s", (dq.ids.du ? "DoH" : ""), dq.ids.origDest.toStringWithPort(), e.what());
      return false;
    }
  }

  try {
    int fd = ds->pickSocketForSending();
    dq.ids.backendFD = fd;
    dq.ids.origID = queryID;
    dq.ids.forwardedOverUDP = true;

    vinfolog("Got query for %s|%s from %s%s, relayed to %s", dq.ids.qname.toLogString(), QType(dq.ids.qtype).toString(), dq.ids.origRemote.toStringWithPort(), (doh ? " (https)" : ""), ds->getNameWithAddr());

    auto idOffset = ds->saveState(std::move(dq.ids));
    /* set the correct ID */
    memcpy(query.data() + proxyPayloadSize, &idOffset, sizeof(idOffset));

    /* you can't touch ids or du after this line, unless the call returned a non-negative value,
       because it might already have been freed */
    ssize_t ret = udpClientSendRequestToBackend(ds, fd, query);

    if (ret < 0) {
      failed = true;
    }

    if (failed) {
      /* clear up the state. In the very unlikely event it was reused
         in the meantime, so be it. */
      auto cleared = ds->getState(idOffset);
      if (cleared) {
        dq.ids.du = std::move(cleared->du);
        if (dq.ids.du) {
          dq.ids.du->status_code = 502;
        }
      }
      ++g_stats.downstreamSendErrors;
      ++ds->sendErrors;
      return false;
    }
  }
  catch (const std::exception& e) {
    throw;
  }

  return true;
}

static void processUDPQuery(ClientState& cs, LocalHolders& holders, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, PacketBuffer& query, struct mmsghdr* responsesVect, unsigned int* queuedResponses, struct iovec* respIOV, cmsgbuf_aligned* respCBuf)
{
  assert(responsesVect == nullptr || (queuedResponses != nullptr && respIOV != nullptr && respCBuf != nullptr));
  uint16_t queryId = 0;
  InternalQueryState ids;
  ids.cs = &cs;
  ids.origRemote = remote;
  ids.hopRemote = remote;
  ids.protocol = dnsdist::Protocol::DoUDP;

  try {
    bool expectProxyProtocol = false;
    if (!isUDPQueryAcceptable(cs, holders, msgh, remote, dest, expectProxyProtocol)) {
      return;
    }
    /* dest might have been updated, if we managed to harvest the destination address */
    if (dest.sin4.sin_family != 0) {
      ids.origDest = dest;
      ids.hopLocal = dest;
    }
    else {
      /* if we have not been able to harvest the destination address,
         we do NOT want to update dest or hopLocal, to let the kernel
         pick the less terrible option, but we want to update origDest
         which is used by rules and actions to at least the correct
         address family */
      ids.origDest = cs.local;
      ids.hopLocal.sin4.sin_family = 0;
    }

    std::vector<ProxyProtocolValue> proxyProtocolValues;
    if (expectProxyProtocol && !handleProxyProtocol(remote, false, *holders.acl, query, ids.origRemote, ids.origDest, proxyProtocolValues)) {
      return;
    }

    ids.queryRealTime.start();

    auto dnsCryptResponse = checkDNSCryptQuery(cs, query, ids.dnsCryptQuery, ids.queryRealTime.d_start.tv_sec, false);
    if (dnsCryptResponse) {
      sendUDPResponse(cs.udpFD, query, 0, dest, remote);
      return;
    }

    {
      /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
      struct dnsheader* dh = reinterpret_cast<struct dnsheader*>(query.data());
      queryId = ntohs(dh->id);

      if (!checkQueryHeaders(dh, cs)) {
        return;
      }

      if (dh->qdcount == 0) {
        dh->rcode = RCode::NotImp;
        dh->qr = true;
        sendUDPResponse(cs.udpFD, query, 0, dest, remote);
        return;
      }
    }

    ids.qname = DNSName(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
    if (ids.dnsCryptQuery) {
      ids.protocol = dnsdist::Protocol::DNSCryptUDP;
    }
    DNSQuestion dq(ids, query);
    const uint16_t* flags = getFlagsFromDNSHeader(dq.getHeader());
    ids.origFlags = *flags;

    if (!proxyProtocolValues.empty()) {
      dq.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
    }

    std::shared_ptr<DownstreamState> ss{nullptr};
    auto result = processQuery(dq, holders, ss);

    if (result == ProcessQueryResult::Drop || result == ProcessQueryResult::Asynchronous) {
      return;
    }

    // the buffer might have been invalidated by now (resized)
    struct dnsheader* dh = dq.getHeader();
    if (result == ProcessQueryResult::SendAnswer) {
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
      if (dq.ids.delayMsec == 0 && responsesVect != nullptr) {
        queueResponse(cs, query, dest, remote, responsesVect[*queuedResponses], respIOV, respCBuf);
        (*queuedResponses)++;
        return;
      }
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
#endif /* DISABLE_RECVMMSG */
      /* we use dest, always, because we don't want to use the listening address to send a response since it could be 0.0.0.0 */
      sendUDPResponse(cs.udpFD, query, dq.ids.delayMsec, dest, remote);

      handleResponseSent(dq.ids.qname, dq.ids.qtype, 0., remote, ComboAddress(), query.size(), *dh, dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoUDP, false);
      return;
    }

    if (result != ProcessQueryResult::PassToBackend || ss == nullptr) {
      return;
    }

    if (ss->isTCPOnly()) {
      std::string proxyProtocolPayload;
      /* we need to do this _before_ creating the cross protocol query because
         after that the buffer will have been moved */
      if (ss->d_config.useProxyProtocol) {
        proxyProtocolPayload = getProxyProtocolPayload(dq);
      }

      ids.origID = dh->id;
      auto cpq = std::make_unique<UDPCrossProtocolQuery>(std::move(query), std::move(ids), ss);
      cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

      ss->passCrossProtocolQuery(std::move(cpq));
      return;
    }

    assignOutgoingUDPQueryToBackend(ss, dh->id, dq, query, dest);
  }
  catch(const std::exception& e){
    vinfolog("Got an error in UDP question thread while parsing a query from %s, id %d: %s", ids.origRemote.toStringWithPort(), queryId, e.what());
  }
}

#ifndef DISABLE_RECVMMSG
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

  if (vectSize > std::numeric_limits<uint16_t>::max()) {
    throw std::runtime_error("The value of setUDPMultipleMessagesVectorSize is too high, the maximum value is " + std::to_string(std::numeric_limits<uint16_t>::max()));
  }

  auto recvData = std::make_unique<MMReceiver[]>(vectSize);
  auto msgVec = std::make_unique<struct mmsghdr[]>(vectSize);
  auto outMsgVec = std::make_unique<struct mmsghdr[]>(vectSize);

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
        ++cs->nonCompliantQueries;
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
#endif /* DISABLE_RECVMMSG */

// listens to incoming queries, sends out to downstream servers, noting the intended return path
static void udpClientThread(std::vector<ClientState*> states)
{
  try {
    setThreadName("dnsdist/udpClie");
    LocalHolders holders;
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
    if (g_udpVectorSize > 1) {
      MultipleMessagesUDPClientThread(states.at(0), holders);
    }
    else
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
#endif /* DISABLE_RECVMMSG */
    {
      /* the actual buffer is larger because:
         - we may have to add EDNS and/or ECS
         - we use it for self-generated responses (from rule or cache)
         but we only accept incoming payloads up to that size
      */
      struct UDPStateParam
      {
        ClientState* cs{nullptr};
        size_t maxIncomingPacketSize{0};
        int socket{-1};
      };
      const size_t initialBufferSize = getInitialUDPPacketBufferSize();
      PacketBuffer packet(initialBufferSize);

      struct msghdr msgh;
      struct iovec iov;
      ComboAddress remote;
      ComboAddress dest;

      auto handleOnePacket = [&packet, &iov, &holders, &msgh, &remote, &dest, initialBufferSize](const UDPStateParam& param) {
        packet.resize(initialBufferSize);
        iov.iov_base = &packet.at(0);
        iov.iov_len = packet.size();

        ssize_t got = recvmsg(param.socket, &msgh, 0);

        if (got < 0 || static_cast<size_t>(got) < sizeof(struct dnsheader)) {
          ++g_stats.nonCompliantQueries;
          ++param.cs->nonCompliantQueries;
          return;
        }

        packet.resize(static_cast<size_t>(got));

        processUDPQuery(*param.cs, holders, &msgh, remote, dest, packet, nullptr, nullptr, nullptr, nullptr);
      };

      std::vector<UDPStateParam> params;
      for (auto& state : states) {
        const size_t maxIncomingPacketSize = getMaximumIncomingPacketSize(*state);
        params.emplace_back(UDPStateParam{state, maxIncomingPacketSize, state->udpFD});
      }

      if (params.size() == 1) {
        auto param = params.at(0);
        remote.sin4.sin_family = param.cs->local.sin4.sin_family;
        /* used by HarvestDestinationAddress */
        cmsgbuf_aligned cbuf;
        fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), reinterpret_cast<char*>(&packet.at(0)), param.maxIncomingPacketSize, &remote);
        while (true) {
          try {
            handleOnePacket(param);
          }
          catch (const std::bad_alloc& e) {
            /* most exceptions are handled by handleOnePacket(), but we might be out of memory (std::bad_alloc)
               in which case we DO NOT want to log (as it would trigger another memory allocation attempt
               that might throw as well) but wait a bit (one millisecond) and then try to recover */
            usleep(1000);
          }
        }
      }
      else {
        auto callback = [&remote, &msgh, &iov, &packet, &handleOnePacket, initialBufferSize](int socket, FDMultiplexer::funcparam_t& funcparam) {
          auto param = boost::any_cast<const UDPStateParam*>(funcparam);
          try {
            remote.sin4.sin_family = param->cs->local.sin4.sin_family;
            packet.resize(initialBufferSize);
            /* used by HarvestDestinationAddress */
            cmsgbuf_aligned cbuf;
            fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), reinterpret_cast<char*>(&packet.at(0)), param->maxIncomingPacketSize, &remote);
            handleOnePacket(*param);
          }
          catch (const std::bad_alloc& e) {
            /* most exceptions are handled by handleOnePacket(), but we might be out of memory (std::bad_alloc)
               in which case we DO NOT want to log (as it would trigger another memory allocation attempt
               that might throw as well) but wait a bit (one millisecond) and then try to recover */
            usleep(1000);
          }
        };
        auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(params.size()));
        for (size_t idx = 0; idx < params.size(); idx++) {
          const auto& param = params.at(idx);
          mplexer->addReadFD(param.socket, callback, &param);
        }

        struct timeval tv;
        while (true) {
          mplexer->run(&tv, -1);
        }
      }
    }
  }
  catch (const std::exception &e) {
    errlog("UDP client thread died because of exception: %s", e.what());
  }
  catch (const PDNSException &e) {
    errlog("UDP client thread died because of PowerDNS exception: %s", e.reason);
  }
  catch (...) {
    errlog("UDP client thread died because of an exception: %s", "unknown");
  }
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
      for (const auto& pair : caches) {
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

#ifndef DISABLE_DYNBLOCKS
static void dynBlockMaintenanceThread()
{
  setThreadName("dnsdist/dynBloc");

  DynBlockMaintenance::run();
}
#endif

#ifndef DISABLE_SECPOLL
static void secPollThread()
{
  setThreadName("dnsdist/secpoll");

  for (;;) {
    try {
      doSecPoll(g_secPollSuffix);
    }
    catch(...) {
    }
    // coverity[store_truncates_time_t]
    sleep(g_secPollInterval);
  }
}
#endif /* DISABLE_SECPOLL */

static void healthChecksThread()
{
  setThreadName("dnsdist/healthC");

  constexpr int interval = 1;
  auto states = g_dstates.getLocal(); // this points to the actual shared_ptrs!

  for (;;) {
    sleep(interval);

    std::unique_ptr<FDMultiplexer> mplexer{nullptr};
    for (auto& dss : *states) {
      auto delta = dss->sw.udiffAndSet()/1000000.0;
      dss->queryLoad.store(1.0*(dss->queries.load() - dss->prev.queries.load())/delta);
      dss->dropRate.store(1.0*(dss->reuseds.load() - dss->prev.reuseds.load())/delta);
      dss->prev.queries.store(dss->queries.load());
      dss->prev.reuseds.store(dss->reuseds.load());

      dss->handleUDPTimeouts();

      if (!dss->healthCheckRequired()) {
        continue;
      }

      if (!mplexer) {
        mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(states->size()));
      }

      if (!queueHealthCheck(mplexer, dss)) {
        dss->submitHealthCheckResult(false, false);
      }
    }

    if (mplexer) {
      handleQueuedHealthChecks(*mplexer);
    }
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
  rlim_t requiredFDsCount = 3;
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

static bool g_warned_ipv6_recvpktinfo = false;

static void setUpLocalBind(std::unique_ptr<ClientState>& cstate)
{
  auto setupSocket = [](ClientState& cs, const ComboAddress& addr, int& socket, bool tcp, bool warn) {
    (void) warn;
    socket = SSocket(addr.sin4.sin_family, tcp == false ? SOCK_DGRAM : SOCK_STREAM, 0);

    if (tcp) {
      SSetsockopt(socket, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
      SSetsockopt(socket, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1);
#endif
      if (cs.fastOpenQueueSize > 0) {
#ifdef TCP_FASTOPEN
        SSetsockopt(socket, IPPROTO_TCP, TCP_FASTOPEN, cs.fastOpenQueueSize);
#ifdef TCP_FASTOPEN_KEY
        if (!g_TCPFastOpenKey.empty()) {
          auto res = setsockopt(socket, IPPROTO_IP, TCP_FASTOPEN_KEY, g_TCPFastOpenKey.data(), g_TCPFastOpenKey.size() * sizeof(g_TCPFastOpenKey[0]));
          if (res == -1) {
            throw runtime_error("setsockopt for level IPPROTO_TCP and opname TCP_FASTOPEN_KEY failed: " + stringerror());
          }
        }
#endif /* TCP_FASTOPEN_KEY */
#else /* TCP_FASTOPEN */
        if (warn) {
          warnlog("TCP Fast Open has been configured on local address '%s' but is not supported", addr.toStringWithPort());
        }
#endif /* TCP_FASTOPEN */
      }
    }

    if (addr.sin4.sin_family == AF_INET6) {
      SSetsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, 1);
    }

    bindAny(addr.sin4.sin_family, socket);

    if (!tcp && IsAnyAddress(addr)) {
      int one = 1;
      (void) setsockopt(socket, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one)); // linux supports this, so why not - might fail on other systems
#ifdef IPV6_RECVPKTINFO
      if (addr.isIPv6() && setsockopt(socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) < 0 &&
          !g_warned_ipv6_recvpktinfo) {
        warnlog("Warning: IPV6_RECVPKTINFO setsockopt failed: %s", stringerror());
        g_warned_ipv6_recvpktinfo = true;
      }
#endif
    }

    if (cs.reuseport) {
      if (!setReusePort(socket)) {
        if (warn) {
          /* no need to warn again if configured but support is not available, we already did for UDP */
          warnlog("SO_REUSEPORT has been configured on local address '%s' but is not supported", addr.toStringWithPort());
        }
      }
    }

    /* Only set this on IPv4 UDP sockets.
       Don't set it for DNSCrypt binds. DNSCrypt pads queries for privacy
       purposes, so we do receive large, sometimes fragmented datagrams. */
    if (!tcp && !cs.dnscryptCtx) {
      try {
        setSocketIgnorePMTU(socket, addr.sin4.sin_family);
      }
      catch (const std::exception& e) {
        warnlog("Failed to set IP_MTU_DISCOVER on UDP server socket for local address '%s': %s", addr.toStringWithPort(), e.what());
      }
    }

    if (!tcp) {
      if (g_socketUDPSendBuffer > 0) {
        try {
          setSocketSendBuffer(socket, g_socketUDPSendBuffer);
        }
        catch (const std::exception& e) {
          warnlog(e.what());
        }
      }

      if (g_socketUDPRecvBuffer > 0) {
        try {
          setSocketReceiveBuffer(socket, g_socketUDPRecvBuffer);
        }
        catch (const std::exception& e) {
          warnlog(e.what());
        }
      }
    }

    const std::string& itf = cs.interface;
    if (!itf.empty()) {
#ifdef SO_BINDTODEVICE
      int res = setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, itf.c_str(), itf.length());
      if (res != 0) {
        warnlog("Error setting up the interface on local address '%s': %s", addr.toStringWithPort(), stringerror());
      }
#else
      if (warn) {
        warnlog("An interface has been configured on local address '%s' but SO_BINDTODEVICE is not supported", addr.toStringWithPort());
      }
#endif
    }

#ifdef HAVE_EBPF
    if (g_defaultBPFFilter && !g_defaultBPFFilter->isExternal()) {
      cs.attachFilter(g_defaultBPFFilter, socket);
      vinfolog("Attaching default BPF Filter to %s frontend %s", (!tcp ? "UDP" : "TCP"), addr.toStringWithPort());
    }
#endif /* HAVE_EBPF */

    SBind(socket, addr);

    if (tcp) {
      SListen(socket, cs.tcpListenQueueSize);

      if (cs.tlsFrontend != nullptr) {
        infolog("Listening on %s for TLS", addr.toStringWithPort());
      }
      else if (cs.dohFrontend != nullptr) {
        infolog("Listening on %s for DoH", addr.toStringWithPort());
      }
      else if (cs.dnscryptCtx != nullptr) {
        infolog("Listening on %s for DNSCrypt", addr.toStringWithPort());
      }
      else {
        infolog("Listening on %s", addr.toStringWithPort());
      }
    }
  };

  /* skip some warnings if there is an identical UDP context */
  bool warn = cstate->tcp == false || cstate->tlsFrontend != nullptr || cstate->dohFrontend != nullptr;
  int& fd = cstate->tcp == false ? cstate->udpFD : cstate->tcpFD;
  (void) warn;

  setupSocket(*cstate, cstate->local, fd, cstate->tcp, warn);

  for (auto& [addr, socket] : cstate->d_additionalAddresses) {
    setupSocket(*cstate, addr, socket, true, false);
  }

  if (cstate->tlsFrontend != nullptr) {
    if (!cstate->tlsFrontend->setupTLS()) {
      errlog("Error while setting up TLS on local address '%s', exiting", cstate->local.toStringWithPort());
      _exit(EXIT_FAILURE);
    }
  }

  if (cstate->dohFrontend != nullptr) {
    cstate->dohFrontend->setup();
  }

  cstate->ready = true;
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
  cout<<"--log-timestamps      Prepend timestamps to messages logged to stdout.\n";
  cout<<"-u,--uid uid          Change the process user ID after binding sockets\n";
  cout<<"-v,--verbose          Enable verbose mode\n";
  cout<<"-V,--version          Show dnsdist version information and exit\n";
}

#ifdef COVERAGE
extern "C"
{
  void __gcov_dump(void);
}

static void cleanupLuaObjects()
{
  /* when our coverage mode is enabled, we need to make
     that the Lua objects destroyed before the Lua contexts. */
  g_ruleactions.setState({});
  g_respruleactions.setState({});
  g_cachehitrespruleactions.setState({});
  g_selfansweredrespruleactions.setState({});
  g_dstates.setState({});
  g_policy.setState(ServerPolicy());
  clearWebHandlers();
}

static void sigTermHandler(int)
{
  cleanupLuaObjects();
  __gcov_dump();
  _exit(EXIT_SUCCESS);
}
#else /* COVERAGE */

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#endif

static void sigTermHandler(int)
{
#if !defined(__SANITIZE_THREAD__)
  /* TSAN is rightfully unhappy about this:
     WARNING: ThreadSanitizer: signal-unsafe call inside of a signal
     This is not a real problem for us, as the worst case is that
     we crash trying to exit, but let's try to avoid the warnings
     in our tests.
  */
  if (g_syslog) {
    syslog(LOG_INFO, "Exiting on user request");
  }
  std::cout<<"Exiting on user request"<<std::endl;
#endif /* __SANITIZE_THREAD__ */

  _exit(EXIT_SUCCESS);
}
#endif /* COVERAGE */

int main(int argc, char** argv)
{
  try {
    size_t udpBindsCount = 0;
    size_t tcpBindsCount = 0;
#ifdef HAVE_LIBEDIT
#ifndef DISABLE_COMPLETION
    rl_attempted_completion_function = my_completion;
    rl_completion_append_character = 0;
#endif /* DISABLE_COMPLETION */
#endif /* HAVE_LIBEDIT */

    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, sigTermHandler);

    openlog("dnsdist", LOG_PID|LOG_NDELAY, LOG_DAEMON);

#ifdef HAVE_LIBSODIUM
    if (sodium_init() == -1) {
      cerr<<"Unable to initialize crypto library"<<endl;
      exit(EXIT_FAILURE);
    }
#endif
    dnsdist::initRandom();
    g_hashperturb = dnsdist::getRandomValue(0xffffffff);

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
      {"log-timestamps", no_argument, 0, 4},
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
      case 4:
        g_logtimestamps=true;
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
#ifdef HAVE_IPCIPHER
        cout<<"ipcipher ";
#endif
#ifdef HAVE_LIBEDIT
        cout<<"libeditr ";
#endif
#ifdef HAVE_LIBSODIUM
        cout<<"libsodium ";
#endif
#ifdef HAVE_LMDB
        cout<<"lmdb ";
#endif
#ifdef HAVE_NGHTTP2
        cout<<"outgoing-dns-over-https(nghttp2) ";
#endif
#ifndef DISABLE_PROTOBUF
        cout<<"protobuf ";
#endif
#ifdef HAVE_RE2
        cout<<"re2 ";
#endif
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
        cout<<"recvmmsg/sendmmsg ";
#endif
#endif /* DISABLE_RECVMMSG */
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

    for (auto p = argv; *p; ++p) {
      if(g_cmdLine.beClient) {
        clientAddress = ComboAddress(*p, 5199);
      } else {
        g_cmdLine.remotes.push_back(*p);
      }
    }

    ServerPolicy leastOutstandingPol{"leastOutstanding", leastOutstanding, false};

    g_policy.setState(leastOutstandingPol);
    if (g_cmdLine.beClient || !g_cmdLine.command.empty()) {
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
      cleanupLuaObjects();
      exit(EXIT_SUCCESS);
#else
      _exit(EXIT_SUCCESS);
#endif
    }

    infolog("dnsdist %s comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2", VERSION);

    dnsdist::g_asyncHolder = std::make_unique<dnsdist::AsynchronousHolder>();

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
          if (backend->d_config.d_weight < 100) {
            vinfolog("Warning, the backend '%s' has a very low weight (%d), which will not yield a good distribution of queries with the 'chashed' policy. Please consider raising it to at least '100'.", backend->getName(), backend->d_config.d_weight);
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

      for (const auto& loc : g_cmdLine.locals) {
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

    g_rings.init();

    for(auto& frontend : g_frontends) {
      setUpLocalBind(frontend);

      if (frontend->tcp == false) {
        ++udpBindsCount;
      }
      else {
        ++tcpBindsCount;
      }
    }

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

    if (!g_cmdLine.gid.empty()) {
      newgid = strToGID(g_cmdLine.gid);
    }

    if (!g_cmdLine.uid.empty()) {
      newuid = strToUID(g_cmdLine.uid);
    }

    bool retainedCapabilities = true;
    if (!g_capabilitiesToRetain.empty() &&
        (getegid() != newgid || geteuid() != newuid)) {
      retainedCapabilities = keepCapabilitiesAfterSwitchingIDs();
    }

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

    if (retainedCapabilities) {
      dropCapabilitiesAfterSwitchingIDs();
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
#ifndef DISABLE_DELAY_PIPE
    g_delay = new DelayPipe<DelayedPacket>();
#endif /* DISABLE_DELAY_PIPE */

    if (g_snmpAgent) {
      g_snmpAgent->run();
    }

    if (!g_maxTCPClientThreads) {
      g_maxTCPClientThreads = static_cast<size_t>(10);
    }
    else if (*g_maxTCPClientThreads == 0 && tcpBindsCount > 0) {
      warnlog("setMaxTCPClientThreads() has been set to 0 while we are accepting TCP connections, raising to 1");
      g_maxTCPClientThreads = 1;
    }

    /* we need to create the TCP worker threads before the
       acceptor ones, otherwise we might crash when processing
       the first TCP query */
#ifndef USE_SINGLE_ACCEPTOR_THREAD
    g_tcpclientthreads = std::make_unique<TCPClientCollection>(*g_maxTCPClientThreads, std::vector<ClientState*>());
#endif

    initDoHWorkers();

    for (auto& t : todo) {
      t();
    }

    localPools = g_pools.getCopy();
    /* create the default pool no matter what */
    createPoolIfNotExists(localPools, "");
    if (g_cmdLine.remotes.size()) {
      for (const auto& address : g_cmdLine.remotes) {
        DownstreamState::Config config;
        config.remote = ComboAddress(address, 53);
        auto ret = std::make_shared<DownstreamState>(std::move(config), nullptr, true);
        addServerToPool(localPools, "", ret);
        ret->start();
        g_dstates.modify([&ret](servers_t& servers) { servers.push_back(std::move(ret)); });
      }
    }
    g_pools.setState(localPools);

    if (g_dstates.getLocal()->empty()) {
      errlog("No downstream servers defined: all packets will get dropped");
      // you might define them later, but you need to know
    }

    checkFileDescriptorsLimits(udpBindsCount, tcpBindsCount);

    {
      auto states = g_dstates.getCopy(); // it is a copy, but the internal shared_ptrs are the real deal
      auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(states.size()));
      for (auto& dss : states) {
        if (dss->d_config.availability == DownstreamState::Availability::Auto || dss->d_config.availability == DownstreamState::Availability::Lazy) {
          if (dss->d_config.availability == DownstreamState::Availability::Auto) {
            dss->d_nextCheck = dss->d_config.checkInterval;
          }

          if (!queueHealthCheck(mplexer, dss, true)) {
            dss->setUpStatus(false);
            warnlog("Marking downstream %s as 'down'", dss->getNameWithAddr());
          }
        }
      }
      handleQueuedHealthChecks(*mplexer, true);
    }

    std::vector<ClientState*> tcpStates;
    std::vector<ClientState*> udpStates;
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
#ifdef USE_SINGLE_ACCEPTOR_THREAD
        udpStates.push_back(cs.get());
#else /* USE_SINGLE_ACCEPTOR_THREAD */
        thread t1(udpClientThread, std::vector<ClientState*>{ cs.get() });
        if (!cs->cpus.empty()) {
          mapThreadToCPUList(t1.native_handle(), cs->cpus);
        }
        t1.detach();
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
      }
      else if (cs->tcpFD >= 0) {
#ifdef USE_SINGLE_ACCEPTOR_THREAD
        tcpStates.push_back(cs.get());
#else /* USE_SINGLE_ACCEPTOR_THREAD */
        thread t1(tcpAcceptorThread, std::vector<ClientState*>{cs.get() });
        if (!cs->cpus.empty()) {
          mapThreadToCPUList(t1.native_handle(), cs->cpus);
        }
        t1.detach();
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
      }
    }
#ifdef USE_SINGLE_ACCEPTOR_THREAD
    if (!udpStates.empty()) {
      thread udp(udpClientThread, udpStates);
      udp.detach();
    }
    if (!tcpStates.empty()) {
      g_tcpclientthreads = std::make_unique<TCPClientCollection>(1, tcpStates);
    }
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
    dnsdist::ServiceDiscovery::run();

#ifndef DISABLE_CARBON
    dnsdist::Carbon::run();
#endif /* DISABLE_CARBON */

    thread stattid(maintThread);
    stattid.detach();

    thread healththread(healthChecksThread);

#ifndef DISABLE_DYNBLOCKS
    thread dynBlockMaintThread(dynBlockMaintenanceThread);
    dynBlockMaintThread.detach();
#endif /* DISABLE_DYNBLOCKS */

#ifndef DISABLE_SECPOLL
    if (!g_secPollSuffix.empty()) {
      thread secpollthread(secPollThread);
      secpollthread.detach();
    }
#endif /* DISABLE_SECPOLL */

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
    cleanupLuaObjects();
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
