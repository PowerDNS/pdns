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
#include <filesystem>
#include <fstream>
#include <getopt.h>
#include <grp.h>
#include <limits>
#include <netinet/tcp.h>
#include <pwd.h>
#include <set>
#include <sys/resource.h>
#include <unistd.h>

#include "dnsdist-systemd.hh"
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "dnsdist.hh"
#include "dnsdist-async.hh"
#include "dnsdist-cache.hh"
#include "dnsdist-carbon.hh"
#include "dnsdist-configuration.hh"
#include "dnsdist-configuration-yaml.hh"
#include "dnsdist-console.hh"
#include "dnsdist-console-completion.hh"
#include "dnsdist-crypto.hh"
#include "dnsdist-discovery.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-edns.hh"
#include "dnsdist-frontend.hh"
#include "dnsdist-healthchecks.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-hooks.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-nghttp2-in.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-random.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-secpoll.hh"
#include "dnsdist-self-answers.hh"
#include "dnsdist-snmp.hh"
#include "dnsdist-tcp.hh"
#include "dnsdist-tcp-downstream.hh"
#include "dnsdist-tcp-upstream.hh"
#include "dnsdist-web.hh"
#include "dnsdist-xsk.hh"

#include "base64.hh"
#include "capabilities.hh"
#include "coverage.hh"
#include "delaypipe.hh"
#include "doh.hh"
#include "dolog.hh"
#include "dnsname.hh"
#include "ednsoptions.hh"
#include "gettime.hh"
#include "lock.hh"
#include "misc.hh"
#include "sstuff.hh"
#include "threadname.hh"
#include "xsk.hh"

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

string g_outputBuffer;

shared_ptr<BPFFilter> g_defaultBPFFilter{nullptr};

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

Rings g_rings;

// we are not willing to receive a bigger UDP response than that, no matter what
static constexpr size_t s_maxUDPResponsePacketSize{4096U};
static size_t const s_initialUDPPacketBufferSize = s_maxUDPResponsePacketSize + DNSCRYPT_MAX_RESPONSE_PADDING_AND_MAC_SIZE;
static_assert(s_initialUDPPacketBufferSize <= UINT16_MAX, "Packet size should fit in a uint16_t");

static void sendfromto(int sock, const PacketBuffer& buffer, const ComboAddress& from, const ComboAddress& dest)
{
  const int flags = 0;
  if (from.sin4.sin_family == 0) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto ret = sendto(sock, buffer.data(), buffer.size(), flags, reinterpret_cast<const struct sockaddr*>(&dest), dest.getSocklen());
    if (ret == -1) {
      int error = errno;
      vinfolog("Error sending UDP response to %s: %s", dest.toStringWithPort(), stringerror(error));
    }
    return;
  }

  try {
    sendMsgWithOptions(sock, buffer.data(), buffer.size(), &dest, &from, 0, 0);
  }
  catch (const std::exception& exp) {
    vinfolog("Error sending UDP response from %s to %s: %s", from.toStringWithPort(), dest.toStringWithPort(), exp.what());
  }
}

static void truncateTC(PacketBuffer& packet, size_t maximumSize, unsigned int qnameWireLength, bool addEDNSToSelfGeneratedResponses)
{
  try {
    bool hadEDNS = false;
    uint16_t payloadSize = 0;
    uint16_t zValue = 0;

    if (addEDNSToSelfGeneratedResponses) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      hadEDNS = getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(packet.data()), packet.size(), &payloadSize, &zValue);
    }

    packet.resize(static_cast<uint16_t>(sizeof(dnsheader) + qnameWireLength + DNS_TYPE_SIZE + DNS_CLASS_SIZE));
    dnsdist::PacketMangling::editDNSHeaderFromPacket(packet, [](dnsheader& header) {
      header.ancount = 0;
      header.arcount = 0;
      header.nscount = 0;
      return true;
    });

    if (hadEDNS) {
      addEDNS(packet, maximumSize, (zValue & EDNS_HEADER_FLAG_DO) != 0, payloadSize, 0);
    }
  }
  catch (...) {
    ++dnsdist::metrics::g_stats.truncFail;
  }
}

#ifndef DISABLE_DELAY_PIPE
struct DelayedPacket
{
  int fd{-1};
  PacketBuffer packet;
  ComboAddress destination;
  ComboAddress origDest;
  void operator()() const
  {
    sendfromto(fd, packet, origDest, destination);
  }
};

static std::unique_ptr<DelayPipe<DelayedPacket>> g_delay{nullptr};
#endif /* DISABLE_DELAY_PIPE */

static void doLatencyStats(dnsdist::Protocol protocol, double udiff)
{
  constexpr auto doAvg = [](pdns::stat_double_t& var, double n, double weight) {
    var.store((weight - 1) * var.load() / weight + n / weight);
  };

  if (protocol == dnsdist::Protocol::DoUDP || protocol == dnsdist::Protocol::DNSCryptUDP) {
    if (udiff < 1000) {
      ++dnsdist::metrics::g_stats.latency0_1;
    }
    else if (udiff < 10000) {
      ++dnsdist::metrics::g_stats.latency1_10;
    }
    else if (udiff < 50000) {
      ++dnsdist::metrics::g_stats.latency10_50;
    }
    else if (udiff < 100000) {
      ++dnsdist::metrics::g_stats.latency50_100;
    }
    else if (udiff < 1000000) {
      ++dnsdist::metrics::g_stats.latency100_1000;
    }
    else {
      ++dnsdist::metrics::g_stats.latencySlow;
    }

    dnsdist::metrics::g_stats.latencySum += static_cast<unsigned long>(udiff) / 1000;
    ++dnsdist::metrics::g_stats.latencyCount;

    doAvg(dnsdist::metrics::g_stats.latencyAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoTCP || protocol == dnsdist::Protocol::DNSCryptTCP) {
    doAvg(dnsdist::metrics::g_stats.latencyTCPAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyTCPAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyTCPAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyTCPAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoT) {
    doAvg(dnsdist::metrics::g_stats.latencyDoTAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyDoTAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyDoTAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyDoTAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoH) {
    doAvg(dnsdist::metrics::g_stats.latencyDoHAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyDoHAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyDoHAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyDoHAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoQ) {
    doAvg(dnsdist::metrics::g_stats.latencyDoQAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyDoQAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyDoQAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyDoQAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoH3) {
    doAvg(dnsdist::metrics::g_stats.latencyDoH3Avg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyDoH3Avg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyDoH3Avg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyDoH3Avg1000000, udiff, 1000000);
  }
}

bool responseContentMatches(const PacketBuffer& response, const DNSName& qname, const uint16_t qtype, const uint16_t qclass, const std::shared_ptr<DownstreamState>& remote, bool allowEmptyResponse)
{
  if (response.size() < sizeof(dnsheader)) {
    return false;
  }

  const dnsheader_aligned dnsHeader(response.data());
  if (dnsHeader->qr == 0) {
    ++dnsdist::metrics::g_stats.nonCompliantResponses;
    if (remote) {
      ++remote->nonCompliantResponses;
    }
    return false;
  }

  if (dnsHeader->qdcount == 0) {
    if ((dnsHeader->rcode != RCode::NoError && dnsHeader->rcode != RCode::NXDomain) || allowEmptyResponse) {
      return true;
    }

    ++dnsdist::metrics::g_stats.nonCompliantResponses;
    if (remote) {
      ++remote->nonCompliantResponses;
    }
    return false;
  }

  try {
    uint16_t rqtype{};
    uint16_t rqclass{};
    if (response.size() < (sizeof(dnsheader) + qname.wirelength() + sizeof(rqtype) + sizeof(rqclass))) {
      return false;
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-bounds-pointer-arithmetic)
    const std::string_view packetView(reinterpret_cast<const char*>(response.data() + sizeof(dnsheader)), response.size() - sizeof(dnsheader));
    if (qname.matchesUncompressedName(packetView)) {
      size_t pos = sizeof(dnsheader) + qname.wirelength();
      rqtype = response.at(pos) * 256 + response.at(pos + 1);
      rqclass = response.at(pos + 2) * 256 + response.at(pos + 3);
      return rqtype == qtype && rqclass == qclass;
    }
    return false;
  }
  catch (const std::exception& e) {
    if (remote && !response.empty() && static_cast<size_t>(response.size()) > sizeof(dnsheader)) {
      infolog("Backend %s sent us a response with id %d that did not parse: %s", remote->d_config.remote.toStringWithPort(), ntohs(dnsHeader->id), e.what());
    }
    ++dnsdist::metrics::g_stats.nonCompliantResponses;
    if (remote) {
      ++remote->nonCompliantResponses;
    }
    return false;
  }
}

static void restoreFlags(struct dnsheader* dnsHeader, uint16_t origFlags)
{
  static const uint16_t rdMask = 1 << FLAGS_RD_OFFSET;
  static const uint16_t cdMask = 1 << FLAGS_CD_OFFSET;
  static const uint16_t restoreFlagsMask = UINT16_MAX & ~(rdMask | cdMask);
  uint16_t* flags = getFlagsFromDNSHeader(dnsHeader);
  /* clear the flags we are about to restore */
  *flags &= restoreFlagsMask;
  /* only keep the flags we want to restore */
  origFlags &= ~restoreFlagsMask;
  /* set the saved flags as they were */
  *flags |= origFlags;
}

static bool fixUpQueryTurnedResponse(DNSQuestion& dnsQuestion, const uint16_t origFlags)
{
  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [origFlags](dnsheader& header) {
    restoreFlags(&header, origFlags);
    return true;
  });

  if (dnsQuestion.d_selfGeneratedHandledEDNS) {
    return true;
  }
  return addEDNSToQueryTurnedResponse(dnsQuestion);
}

static bool fixUpResponse(PacketBuffer& response, const DNSName& qname, uint16_t origFlags, bool ednsAdded, bool ecsAdded, bool* zeroScope)
{
  if (response.size() < sizeof(dnsheader)) {
    return false;
  }

  dnsdist::PacketMangling::editDNSHeaderFromPacket(response, [origFlags](dnsheader& header) {
    restoreFlags(&header, origFlags);
    return true;
  });

  if (response.size() == sizeof(dnsheader)) {
    return true;
  }

  if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_fixupCase) {
    const auto& realname = qname.getStorage();
    if (response.size() >= (sizeof(dnsheader) + realname.length())) {
      memcpy(&response.at(sizeof(dnsheader)), realname.c_str(), realname.length());
    }
  }

  if (ednsAdded || ecsAdded) {
    uint16_t optStart{};
    size_t optLen = 0;
    bool last = false;

    int res = locateEDNSOptRR(response, &optStart, &optLen, &last);

    if (res == 0) {
      if (zeroScope != nullptr) { // this finds if an EDNS Client Subnet scope was set, and if it is 0
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
          dnsdist::PacketMangling::editDNSHeaderFromPacket(response, [](dnsheader& header) {
            uint16_t arcount = ntohs(header.arcount);
            arcount--;
            header.arcount = htons(arcount);
            return true;
          });
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
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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

bool applyRulesToResponse(const std::vector<dnsdist::rules::ResponseRuleAction>& respRuleActions, DNSResponse& dnsResponse)
{
  if (respRuleActions.empty()) {
    return true;
  }

  DNSResponseAction::Action action = DNSResponseAction::Action::None;
  std::string ruleresult;
  for (const auto& rrule : respRuleActions) {
    if (rrule.d_rule->matches(&dnsResponse)) {
      ++rrule.d_rule->d_matches;
      action = (*rrule.d_action)(&dnsResponse, &ruleresult);
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
        if (dnsResponse.getData().size() < sizeof(dnsheader)) {
          return false;
        }
        dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsResponse.getMutableData(), [](dnsheader& header) {
          header.rcode = RCode::ServFail;
          return true;
        });
        return true;
        break;
      case DNSResponseAction::Action::Truncate:
        if (dnsResponse.getData().size() < sizeof(dnsheader)) {
          return false;
        }
        if (!dnsResponse.overTCP()) {
          dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsResponse.getMutableData(), [](dnsheader& header) {
            header.tc = true;
            header.qr = true;
            return true;
          });
          truncateTC(dnsResponse.getMutableData(), dnsResponse.getMaximumSize(), dnsResponse.ids.qname.wirelength(), dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses);
          ++dnsdist::metrics::g_stats.ruleTruncated;
          return true;
        }
        break;
        /* non-terminal actions follow */
      case DNSResponseAction::Action::Delay:
        pdns::checked_stoi_into(dnsResponse.ids.delayMsec, ruleresult); // sorry
        break;
      case DNSResponseAction::Action::None:
        break;
      }
    }
  }

  return true;
}

bool processResponseAfterRules(PacketBuffer& response, DNSResponse& dnsResponse, [[maybe_unused]] bool muted)
{
  bool zeroScope = false;
  if (!fixUpResponse(response, dnsResponse.ids.qname, dnsResponse.ids.origFlags, dnsResponse.ids.ednsAdded, dnsResponse.ids.ecsAdded, dnsResponse.ids.useZeroScope ? &zeroScope : nullptr)) {
    return false;
  }

  if (dnsResponse.ids.packetCache && !dnsResponse.ids.selfGenerated && !dnsResponse.ids.skipCache && (!dnsResponse.ids.forwardedOverUDP || response.size() <= s_maxUDPResponsePacketSize)) {
    if (!dnsResponse.ids.useZeroScope) {
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
    uint32_t cacheKey = dnsResponse.ids.cacheKey;
    if (dnsResponse.ids.protocol == dnsdist::Protocol::DoH && !dnsResponse.ids.forwardedOverUDP) {
      // disable zeroScope in that case, as we only have the "no-ECS" cache key for UDP
      zeroScope = false;
    }
    if (zeroScope) {
      // if zeroScope, pass the pre-ECS hash-key and do not pass the subnet to the cache
      cacheKey = dnsResponse.ids.cacheKeyNoECS;
    }
    dnsResponse.ids.packetCache->insert(cacheKey, zeroScope ? boost::none : dnsResponse.ids.subnet, dnsResponse.ids.cacheFlags, dnsResponse.ids.dnssecOK ? *dnsResponse.ids.dnssecOK : false, dnsResponse.ids.qname, dnsResponse.ids.qtype, dnsResponse.ids.qclass, response, dnsResponse.getHeader()->rcode, dnsResponse.ids.tempFailureTTL);

    const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
    const auto& cacheInsertedRespRuleActions = dnsdist::rules::getResponseRuleChain(chains, dnsdist::rules::ResponseRuleChain::CacheInsertedResponseRules);
    if (!applyRulesToResponse(cacheInsertedRespRuleActions, dnsResponse)) {
      return false;
    }
  }

  if (dnsResponse.ids.ttlCap > 0) {
    dnsdist::PacketMangling::restrictDNSPacketTTLs(dnsResponse.getMutableData(), 0, dnsResponse.ids.ttlCap);
  }

  if (dnsResponse.ids.d_extendedError) {
    dnsdist::edns::addExtendedDNSError(dnsResponse.getMutableData(), dnsResponse.getMaximumSize(), dnsResponse.ids.d_extendedError->infoCode, dnsResponse.ids.d_extendedError->extraText);
  }

#ifdef HAVE_DNSCRYPT
  if (!muted) {
    if (!encryptResponse(response, dnsResponse.getMaximumSize(), dnsResponse.overTCP(), dnsResponse.ids.dnsCryptQuery)) {
      return false;
    }
  }
#endif /* HAVE_DNSCRYPT */

  return true;
}

bool processResponse(PacketBuffer& response, DNSResponse& dnsResponse, bool muted)
{
  const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
  const auto& respRuleActions = dnsdist::rules::getResponseRuleChain(chains, dnsdist::rules::ResponseRuleChain::ResponseRules);

  if (!applyRulesToResponse(respRuleActions, dnsResponse)) {
    return false;
  }

  if (dnsResponse.isAsynchronous()) {
    return true;
  }

  return processResponseAfterRules(response, dnsResponse, muted);
}

static size_t getInitialUDPPacketBufferSize(bool expectProxyProtocol)
{
  static_assert(dnsdist::configuration::s_udpIncomingBufferSize <= s_initialUDPPacketBufferSize, "The incoming buffer size should not be larger than s_initialUDPPacketBufferSize");

  const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (!expectProxyProtocol || runtimeConfig.d_proxyProtocolACL.empty()) {
    return s_initialUDPPacketBufferSize;
  }

  return s_initialUDPPacketBufferSize + runtimeConfig.d_proxyProtocolMaximumSize;
}

static size_t getMaximumIncomingPacketSize(const ClientState& clientState)
{
  if (clientState.dnscryptCtx) {
    return getInitialUDPPacketBufferSize(clientState.d_enableProxyProtocol);
  }

  const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (!clientState.d_enableProxyProtocol || runtimeConfig.d_proxyProtocolACL.empty()) {
    return dnsdist::configuration::s_udpIncomingBufferSize;
  }

  return dnsdist::configuration::s_udpIncomingBufferSize + runtimeConfig.d_proxyProtocolMaximumSize;
}

bool sendUDPResponse(int origFD, const PacketBuffer& response, [[maybe_unused]] const int delayMsec, const ComboAddress& origDest, const ComboAddress& origRemote)
{
#ifndef DISABLE_DELAY_PIPE
  if (delayMsec > 0 && g_delay != nullptr) {
    DelayedPacket delayed{origFD, response, origRemote, origDest};
    g_delay->submit(delayed, delayMsec);
    return true;
  }
#endif /* DISABLE_DELAY_PIPE */
  // NOLINTNEXTLINE(readability-suspicious-call-argument)
  sendfromto(origFD, response, origDest, origRemote);
  return true;
}

void handleResponseSent(const InternalQueryState& ids, double udiff, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH, dnsdist::Protocol outgoingProtocol, bool fromBackend)
{
  handleResponseSent(ids.qname, ids.qtype, udiff, client, backend, size, cleartextDH, outgoingProtocol, ids.protocol, fromBackend);
}

void handleResponseSent(const DNSName& qname, const QType& qtype, double udiff, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH, dnsdist::Protocol outgoingProtocol, dnsdist::Protocol incomingProtocol, bool fromBackend)
{
  if (g_rings.shouldRecordResponses()) {
    timespec now{};
    gettime(&now);
    g_rings.insertResponse(now, client, qname, qtype, static_cast<unsigned int>(udiff), size, cleartextDH, backend, outgoingProtocol);
  }

  switch (cleartextDH.rcode) {
  case RCode::NXDomain:
    ++dnsdist::metrics::g_stats.frontendNXDomain;
    break;
  case RCode::ServFail:
    if (fromBackend) {
      ++dnsdist::metrics::g_stats.servfailResponses;
    }
    ++dnsdist::metrics::g_stats.frontendServFail;
    break;
  case RCode::NoError:
    ++dnsdist::metrics::g_stats.frontendNoError;
    break;
  }

  doLatencyStats(incomingProtocol, udiff);
}

static void handleResponseTC4UDPClient(DNSQuestion& dnsQuestion, uint16_t udpPayloadSize, PacketBuffer& response)
{
  if (udpPayloadSize != 0 && response.size() > udpPayloadSize) {
    vinfolog("Got a response of size %d while the initial UDP payload size was %d, truncating", response.size(), udpPayloadSize);
    truncateTC(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnsQuestion.ids.qname.wirelength(), dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses);
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
      header.tc = true;
      return true;
    });
  }
  else if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_truncateTC && dnsQuestion.getHeader()->tc) {
    truncateTC(response, dnsQuestion.getMaximumSize(), dnsQuestion.ids.qname.wirelength(), dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses);
  }
}

static void handleResponseForUDPClient(InternalQueryState& ids, PacketBuffer& response, const std::shared_ptr<DownstreamState>& backend, bool isAsync, bool selfGenerated)
{
  DNSResponse dnsResponse(ids, response, backend);

  handleResponseTC4UDPClient(dnsResponse, ids.udpPayloadSize, response);

  /* when the answer is encrypted in place, we need to get a copy
     of the original header before encryption to fill the ring buffer */
  dnsheader cleartextDH{};
  memcpy(&cleartextDH, dnsResponse.getHeader().get(), sizeof(cleartextDH));

  if (!isAsync) {
    if (!processResponse(response, dnsResponse, ids.cs != nullptr && ids.cs->muted)) {
      return;
    }

    if (dnsResponse.isAsynchronous()) {
      return;
    }
  }

  ++dnsdist::metrics::g_stats.responses;
  if (ids.cs != nullptr) {
    ++ids.cs->responses;
  }

  bool muted = true;
  if (ids.cs != nullptr && !ids.cs->muted && !ids.isXSK()) {
    sendUDPResponse(ids.cs->udpFD, response, dnsResponse.ids.delayMsec, ids.hopLocal, ids.hopRemote);
    muted = false;
  }

  if (!selfGenerated) {
    double udiff = ids.queryRealTime.udiff();
    if (!muted) {
      vinfolog("Got answer from %s, relayed to %s (UDP), took %f us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), udiff);
    }
    else {
      if (!ids.isXSK()) {
        vinfolog("Got answer from %s, NOT relayed to %s (UDP) since that frontend is muted, took %f us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), udiff);
      }
      else {
        vinfolog("Got answer from %s, relayed to %s (UDP via XSK), took %f us", backend->d_config.remote.toStringWithPort(), ids.origRemote.toStringWithPort(), udiff);
      }
    }

    handleResponseSent(ids, udiff, dnsResponse.ids.origRemote, backend->d_config.remote, response.size(), cleartextDH, backend->getProtocol(), true);
  }
  else {
    handleResponseSent(ids, 0., dnsResponse.ids.origRemote, ComboAddress(), response.size(), cleartextDH, dnsdist::Protocol::DoUDP, false);
  }
}

bool processResponderPacket(std::shared_ptr<DownstreamState>& dss, PacketBuffer& response, InternalQueryState&& ids)
{

  const dnsheader_aligned dnsHeader(response.data());
  auto queryId = dnsHeader->id;

  if (!responseContentMatches(response, ids.qname, ids.qtype, ids.qclass, dss, dnsdist::configuration::getCurrentRuntimeConfiguration().d_allowEmptyResponse)) {
    dss->restoreState(queryId, std::move(ids));
    return false;
  }

  auto dohUnit = std::move(ids.du);
  dnsdist::PacketMangling::editDNSHeaderFromPacket(response, [&ids](dnsheader& header) {
    header.id = ids.origID;
    return true;
  });
  ++dss->responses;

  double udiff = ids.queryRealTime.udiff();
  // do that _before_ the processing, otherwise it's not fair to the backend
  dss->latencyUsec = (127.0 * dss->latencyUsec / 128.0) + udiff / 128.0;
  dss->reportResponse(dnsHeader->rcode);

  /* don't call processResponse for DOH */
  if (dohUnit) {
#ifdef HAVE_DNS_OVER_HTTPS
    // DoH query, we cannot touch dohUnit after that
    DOHUnitInterface::handleUDPResponse(std::move(dohUnit), std::move(response), std::move(ids), dss);
#endif
    return false;
  }

  handleResponseForUDPClient(ids, response, dss, false, false);
  return true;
}

// listens on a dedicated socket, lobs answers from downstream servers to original requestors
void responderThread(std::shared_ptr<DownstreamState> dss)
{
  try {
    setThreadName("dnsdist/respond");
    const size_t initialBufferSize = getInitialUDPPacketBufferSize(false);
    /* allocate one more byte so we can detect truncation */
    PacketBuffer response(initialBufferSize + 1);
    uint16_t queryId = 0;
    std::vector<int> sockets;
    sockets.reserve(dss->sockets.size());

    for (;;) {
      try {
        if (dss->isStopped()) {
          break;
        }

        if (!dss->connected) {
          /* the sockets are not connected yet, likely because we detected a problem,
             tried to reconnect and it failed. We will try to reconnect after the next
             successful health-check (unless reconnectOnUp is false), or when trying
             to send in the UDP listener thread, but until then we simply need to wait. */
          dss->waitUntilConnected();
          continue;
        }

        dss->pickSocketsReadyForReceiving(sockets);

        /* check a second time here because we might have waited quite a bit
           since the first check */
        if (dss->isStopped()) {
          break;
        }

        for (const auto& sockDesc : sockets) {
          /* allocate one more byte so we can detect truncation */
          // NOLINTNEXTLINE(bugprone-use-after-move): resizing a vector has no preconditions so it is valid to do so after moving it
          response.resize(initialBufferSize + 1);
          ssize_t got = recv(sockDesc, response.data(), response.size(), 0);

          if (got == 0 && dss->isStopped()) {
            break;
          }

          if (got < 0 || static_cast<size_t>(got) < sizeof(dnsheader) || static_cast<size_t>(got) == (initialBufferSize + 1)) {
            continue;
          }

          response.resize(static_cast<size_t>(got));
          const dnsheader_aligned dnsHeader(response.data());
          queryId = dnsHeader->id;

          auto ids = dss->getState(queryId);
          if (!ids) {
            continue;
          }

          if (!ids->isXSK() && sockDesc != ids->backendFD) {
            dss->restoreState(queryId, std::move(*ids));
            continue;
          }

          dnsdist::configuration::refreshLocalRuntimeConfiguration();
          if (processResponderPacket(dss, response, std::move(*ids)) && ids->isXSK() && ids->cs->xskInfoResponder) {
#ifdef HAVE_XSK
            auto& xskInfo = ids->cs->xskInfoResponder;
            auto xskPacket = xskInfo->getEmptyFrame();
            if (!xskPacket) {
              continue;
            }
            xskPacket->setHeader(ids->xskPacketHeader);
            if (!xskPacket->setPayload(response)) {
            }
            if (ids->delayMsec > 0) {
              xskPacket->addDelay(ids->delayMsec);
            }
            xskPacket->updatePacket();
            xskInfo->pushToSendQueue(*xskPacket);
            xskInfo->notifyXskSocket();
#endif /* HAVE_XSK */
          }
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

RecursiveLockGuarded<LuaContext> g_lua{LuaContext()};

static void spoofResponseFromString(DNSQuestion& dnsQuestion, const string& spoofContent, bool raw)
{
  string result;

  if (raw) {
    dnsdist::ResponseConfig config;
    std::vector<std::string> raws;
    stringtok(raws, spoofContent, ",");
    dnsdist::self_answers::generateAnswerFromRDataEntries(dnsQuestion, raws, std::nullopt, config);
  }
  else {
    std::vector<std::string> addrs;
    stringtok(addrs, spoofContent, " ,");

    if (addrs.size() == 1) {
      dnsdist::ResponseConfig config;
      try {
        ComboAddress spoofAddr(spoofContent);
        dnsdist::self_answers::generateAnswerFromIPAddresses(dnsQuestion, {spoofAddr}, config);
      }
      catch (const PDNSException& e) {
        DNSName cname(spoofContent);
        dnsdist::self_answers::generateAnswerFromCNAME(dnsQuestion, cname, config);
      }
    }
    else {
      dnsdist::ResponseConfig config;
      std::vector<ComboAddress> cas;
      for (const auto& addr : addrs) {
        try {
          cas.emplace_back(addr);
        }
        catch (...) {
        }
      }
      dnsdist::self_answers::generateAnswerFromIPAddresses(dnsQuestion, cas, config);
    }
  }
}

static void spoofPacketFromString(DNSQuestion& dnsQuestion, const string& spoofContent)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  dnsdist::self_answers::generateAnswerFromRawPacket(dnsQuestion, PacketBuffer(spoofContent.data(), spoofContent.data() + spoofContent.size()));
}

bool processRulesResult(const DNSAction::Action& action, DNSQuestion& dnsQuestion, std::string& ruleresult, bool& drop)
{
  if (dnsQuestion.isAsynchronous()) {
    return false;
  }

  auto setRCode = [&dnsQuestion](uint8_t rcode) {
    dnsdist::self_answers::removeRecordsAndSetRCode(dnsQuestion, rcode);
  };

  switch (action) {
  case DNSAction::Action::Allow:
    return true;
    break;
  case DNSAction::Action::Drop:
    ++dnsdist::metrics::g_stats.ruleDrop;
    drop = true;
    return true;
    break;
  case DNSAction::Action::Nxdomain:
    setRCode(RCode::NXDomain);
    return true;
    break;
  case DNSAction::Action::Refused:
    setRCode(RCode::Refused);
    return true;
    break;
  case DNSAction::Action::ServFail:
    setRCode(RCode::ServFail);
    return true;
    break;
  case DNSAction::Action::Spoof:
    spoofResponseFromString(dnsQuestion, ruleresult, false);
    return true;
    break;
  case DNSAction::Action::SpoofPacket:
    spoofPacketFromString(dnsQuestion, ruleresult);
    return true;
    break;
  case DNSAction::Action::SpoofRaw:
    spoofResponseFromString(dnsQuestion, ruleresult, true);
    return true;
    break;
  case DNSAction::Action::Truncate:
    if (!dnsQuestion.overTCP()) {
      dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
        header.tc = true;
        header.qr = true;
        header.ra = header.rd;
        header.aa = false;
        header.ad = false;
        return true;
      });
      ++dnsdist::metrics::g_stats.ruleTruncated;
      return true;
    }
    break;
  case DNSAction::Action::HeaderModify:
    return true;
    break;
  case DNSAction::Action::Pool:
    /* we need to keep this because a custom Lua action can return
       DNSAction.Spoof, 'poolname' */
    dnsQuestion.ids.poolName = ruleresult;
    return true;
    break;
  case DNSAction::Action::NoRecurse:
    dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
      header.rd = false;
      return true;
    });
    return true;
    break;
    /* non-terminal actions follow */
  case DNSAction::Action::Delay:
    pdns::checked_stoi_into(dnsQuestion.ids.delayMsec, ruleresult); // sorry
    break;
  case DNSAction::Action::SetTag:
    /* unsupported for non-dynamic block */
  case DNSAction::Action::None:
    /* fall-through */
  case DNSAction::Action::NoOp:
    break;
  }

  /* false means that we don't stop the processing */
  return false;
}

static bool applyRulesChainToQuery(const std::vector<dnsdist::rules::RuleAction>& rules, DNSQuestion& dnsQuestion)
{
  if (rules.empty()) {
    return true;
  }

  DNSAction::Action action = DNSAction::Action::None;
  string ruleresult;
  bool drop = false;

  for (const auto& rule : rules) {
    if (!rule.d_rule->matches(&dnsQuestion)) {
      continue;
    }

    rule.d_rule->d_matches++;
    action = (*rule.d_action)(&dnsQuestion, &ruleresult);
    if (processRulesResult(action, dnsQuestion, ruleresult, drop)) {
      break;
    }
  }

  return !drop;
}

static bool applyRulesToQuery(DNSQuestion& dnsQuestion, const timespec& now)
{
  if (g_rings.shouldRecordQueries()) {
    g_rings.insertQuery(now, dnsQuestion.ids.origRemote, dnsQuestion.ids.qname, dnsQuestion.ids.qtype, dnsQuestion.getData().size(), *dnsQuestion.getHeader(), dnsQuestion.getProtocol());
  }

  {
    const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
    if (runtimeConfig.d_queryCountConfig.d_enabled) {
      string qname = dnsQuestion.ids.qname.toLogString();
      bool countQuery{true};
      if (runtimeConfig.d_queryCountConfig.d_filter) {
        auto lock = g_lua.lock();
        std::tie(countQuery, qname) = runtimeConfig.d_queryCountConfig.d_filter(&dnsQuestion);
      }

      if (countQuery) {
        auto records = dnsdist::QueryCount::g_queryCountRecords.write_lock();
        if (records->count(qname) == 0) {
          (*records)[qname] = 0;
        }
        (*records)[qname]++;
      }
    }
  }

#ifndef DISABLE_DYNBLOCKS
  const auto defaultDynBlockAction = dnsdist::configuration::getCurrentRuntimeConfiguration().d_dynBlockAction;
  auto setRCode = [&dnsQuestion](uint8_t rcode) {
    dnsdist::self_answers::removeRecordsAndSetRCode(dnsQuestion, rcode);
  };

  /* the Dynamic Block mechanism supports address and port ranges, so we need to pass the full address and port */
  if (auto* got = dnsdist::DynamicBlocks::getClientAddressDynamicRules().lookup(AddressAndPortRange(dnsQuestion.ids.origRemote, dnsQuestion.ids.origRemote.isIPv4() ? 32 : 128, 16))) {
    auto updateBlockStats = [&got]() {
      ++dnsdist::metrics::g_stats.dynBlocked;
      got->second.blocks++;
    };

    if (now < got->second.until) {
      DNSAction::Action action = got->second.action;
      if (action == DNSAction::Action::None) {
        action = defaultDynBlockAction;
      }

      switch (action) {
      case DNSAction::Action::NoOp:
        /* do nothing */
        break;

      case DNSAction::Action::Nxdomain:
        vinfolog("Query from %s turned into NXDomain because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort());
        updateBlockStats();

        setRCode(RCode::NXDomain);
        return true;

      case DNSAction::Action::Refused:
        vinfolog("Query from %s refused because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort());
        updateBlockStats();

        setRCode(RCode::Refused);
        return true;

      case DNSAction::Action::Truncate:
        if (!dnsQuestion.overTCP()) {
          updateBlockStats();
          vinfolog("Query from %s truncated because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort());
          dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
            header.tc = true;
            header.qr = true;
            header.ra = header.rd;
            header.aa = false;
            header.ad = false;
            return true;
          });
          return true;
        }
        else {
          vinfolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.qname.toLogString());
        }
        break;
      case DNSAction::Action::NoRecurse:
        updateBlockStats();
        vinfolog("Query from %s setting rd=0 because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort());
        dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
          header.rd = false;
          return true;
        });
        return true;
      case DNSAction::Action::SetTag: {
        if (!got->second.tagSettings) {
          vinfolog("Skipping set tag dynamic block for query from %s because of missing options", dnsQuestion.ids.origRemote.toStringWithPort());
          break;
        }
        updateBlockStats();
        const auto& tagName = got->second.tagSettings->d_name;
        const auto& tagValue = got->second.tagSettings->d_value;
        dnsQuestion.setTag(tagName, tagValue);
        vinfolog("Query from %s setting tag %s to %s because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), tagName, tagValue);
        return true;
      }
      default:
        updateBlockStats();
        vinfolog("Query from %s dropped because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort());
        return false;
      }
    }
  }

  if (auto* got = dnsdist::DynamicBlocks::getSuffixDynamicRules().lookup(dnsQuestion.ids.qname)) {
    auto updateBlockStats = [&got]() {
      ++dnsdist::metrics::g_stats.dynBlocked;
      got->blocks++;
    };

    if (now < got->until) {
      DNSAction::Action action = got->action;
      if (action == DNSAction::Action::None) {
        action = defaultDynBlockAction;
      }
      switch (action) {
      case DNSAction::Action::NoOp:
        /* do nothing */
        break;
      case DNSAction::Action::Nxdomain:
        vinfolog("Query from %s for %s turned into NXDomain because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.qname.toLogString());
        updateBlockStats();

        setRCode(RCode::NXDomain);
        return true;
      case DNSAction::Action::Refused:
        vinfolog("Query from %s for %s refused because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.qname.toLogString());
        updateBlockStats();

        setRCode(RCode::Refused);
        return true;
      case DNSAction::Action::Truncate:
        if (!dnsQuestion.overTCP()) {
          updateBlockStats();

          vinfolog("Query from %s for %s truncated because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.qname.toLogString());
          dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
            header.tc = true;
            header.qr = true;
            header.ra = header.rd;
            header.aa = false;
            header.ad = false;
            return true;
          });
          return true;
        }
        else {
          vinfolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.qname.toLogString());
        }
        break;
      case DNSAction::Action::NoRecurse:
        updateBlockStats();
        vinfolog("Query from %s setting rd=0 because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort());
        dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
          header.rd = false;
          return true;
        });
        return true;
      case DNSAction::Action::SetTag: {
        if (!got->tagSettings) {
          vinfolog("Skipping set tag dynamic block for query from %s because of missing options", dnsQuestion.ids.origRemote.toStringWithPort());
          break;
        }
        updateBlockStats();
        const auto& tagName = got->tagSettings->d_name;
        const auto& tagValue = got->tagSettings->d_value;
        dnsQuestion.setTag(tagName, tagValue);
        vinfolog("Query from %s setting tag %s to %s because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), tagName, tagValue);
        return true;
      }
      default:
        updateBlockStats();
        vinfolog("Query from %s for %s dropped because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.qname.toLogString());
        return false;
      }
    }
  }
#endif /* DISABLE_DYNBLOCKS */

  const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
  const auto& queryRules = dnsdist::rules::getRuleChain(chains, dnsdist::rules::RuleChain::Rules);
  return applyRulesChainToQuery(queryRules, dnsQuestion);
}

ssize_t udpClientSendRequestToBackend(const std::shared_ptr<DownstreamState>& backend, const int socketDesc, const PacketBuffer& request, bool healthCheck)
{
  ssize_t result = 0;

  if (backend->d_config.sourceItf == 0) {
    result = send(socketDesc, request.data(), request.size(), 0);
  }
  else {
    msghdr msgh{};
    iovec iov{};
    cmsgbuf_aligned cbuf;
    ComboAddress remote(backend->d_config.remote);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,cppcoreguidelines-pro-type-const-cast)
    fillMSGHdr(&msgh, &iov, &cbuf, sizeof(cbuf), const_cast<char*>(reinterpret_cast<const char*>(request.data())), request.size(), &remote);
    addCMsgSrcAddr(&msgh, &cbuf, &backend->d_config.sourceAddr, static_cast<int>(backend->d_config.sourceItf));
    result = sendmsg(socketDesc, &msgh, 0);
  }

  if (result == -1) {
    int savederrno = errno;
    vinfolog("Error sending request to backend %s: %s", backend->d_config.remote.toStringWithPort(), stringerror(savederrno));

    /* This might sound silly, but on Linux send() might fail with EINVAL
       if the interface the socket was bound to doesn't exist anymore.
       We don't want to reconnect the real socket if the healthcheck failed,
       because it's not using the same socket.
    */
    if (!healthCheck) {
      if (savederrno == EINVAL || savederrno == ENODEV || savederrno == ENETUNREACH || savederrno == EHOSTUNREACH || savederrno == EBADF) {
        backend->reconnect();
      }
      backend->reportTimeoutOrError();
    }
  }

  return result;
}

static bool isUDPQueryAcceptable(ClientState& clientState, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, bool& expectProxyProtocol)
{
  if ((msgh->msg_flags & MSG_TRUNC) != 0) {
    /* message was too large for our buffer */
    vinfolog("Dropping message too large for our buffer");
    ++clientState.nonCompliantQueries;
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    return false;
  }

  expectProxyProtocol = clientState.d_enableProxyProtocol && expectProxyProtocolFrom(remote);
  if (!dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.match(remote) && !expectProxyProtocol) {
    vinfolog("Query from %s dropped because of ACL", remote.toStringWithPort());
    ++dnsdist::metrics::g_stats.aclDrops;
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
    if ((dest.sin4.sin_family == AF_INET && dest == bogusV4) || (dest.sin4.sin_family == AF_INET6 && dest == bogusV6)) {
      dest.sin4.sin_family = 0;
    }
    else {
      /* we don't get the port, only the address */
      dest.sin4.sin_port = clientState.local.sin4.sin_port;
    }
  }
  else {
    dest.sin4.sin_family = 0;
  }

  ++clientState.queries;
  ++dnsdist::metrics::g_stats.queries;

  return true;
}

bool checkDNSCryptQuery(const ClientState& clientState, [[maybe_unused]] PacketBuffer& query, [[maybe_unused]] std::unique_ptr<DNSCryptQuery>& dnsCryptQuery, [[maybe_unused]] time_t now, [[maybe_unused]] bool tcp)
{
  if (clientState.dnscryptCtx) {
#ifdef HAVE_DNSCRYPT
    PacketBuffer response;
    dnsCryptQuery = std::make_unique<DNSCryptQuery>(clientState.dnscryptCtx);

    bool decrypted = handleDNSCryptQuery(query, *dnsCryptQuery, tcp, now, response);

    if (!decrypted) {
      if (!response.empty()) {
        query = std::move(response);
        return true;
      }
      throw std::runtime_error("Unable to decrypt DNSCrypt query, dropping.");
    }
#endif /* HAVE_DNSCRYPT */
  }
  return false;
}

bool checkQueryHeaders(const struct dnsheader& dnsHeader, ClientState& clientState)
{
  if (dnsHeader.qr) { // don't respond to responses
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    ++clientState.nonCompliantQueries;
    return false;
  }

  if (dnsHeader.qdcount == 0) {
    ++dnsdist::metrics::g_stats.emptyQueries;
    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_dropEmptyQueries) {
      return false;
    }
  }

  if (dnsHeader.rd) {
    ++dnsdist::metrics::g_stats.rdQueries;
  }

  return true;
}

#if !defined(DISABLE_RECVMMSG) && defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
static void queueResponse(const PacketBuffer& response, const ComboAddress& dest, const ComboAddress& remote, struct mmsghdr& outMsg, struct iovec* iov, cmsgbuf_aligned* cbuf)
{
  outMsg.msg_len = 0;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-pro-type-reinterpret-cast): API
  fillMSGHdr(&outMsg.msg_hdr, iov, nullptr, 0, const_cast<char*>(reinterpret_cast<const char*>(&response.at(0))), response.size(), const_cast<ComboAddress*>(&remote));

  if (dest.sin4.sin_family == 0) {
    outMsg.msg_hdr.msg_control = nullptr;
  }
  else {
    addCMsgSrcAddr(&outMsg.msg_hdr, cbuf, &dest, 0);
  }
}
#elif !defined(HAVE_RECVMMSG)
struct mmsghdr
{
  msghdr msg_hdr;
  unsigned int msg_len{0};
};
#endif

/* self-generated responses or cache hits */
static bool prepareOutgoingResponse([[maybe_unused]] const ClientState& clientState, DNSQuestion& dnsQuestion, bool cacheHit)
{
  std::shared_ptr<DownstreamState> backend{nullptr};
  DNSResponse dnsResponse(dnsQuestion.ids, dnsQuestion.getMutableData(), backend);
  dnsResponse.d_incomingTCPState = dnsQuestion.d_incomingTCPState;
  dnsResponse.ids.selfGenerated = true;
  dnsResponse.ids.cacheHit = cacheHit;

  const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
  const auto& cacheHitRespRules = dnsdist::rules::getResponseRuleChain(chains, dnsdist::rules::ResponseRuleChain::CacheHitResponseRules);
  const auto& selfAnsweredRespRules = dnsdist::rules::getResponseRuleChain(chains, dnsdist::rules::ResponseRuleChain::SelfAnsweredResponseRules);
  if (!applyRulesToResponse(cacheHit ? cacheHitRespRules : selfAnsweredRespRules, dnsResponse)) {
    return false;
  }

  if (dnsResponse.ids.ttlCap > 0) {
    dnsdist::PacketMangling::restrictDNSPacketTTLs(dnsResponse.getMutableData(), 0, dnsResponse.ids.ttlCap);
  }

  if (dnsResponse.ids.d_extendedError) {
    dnsdist::edns::addExtendedDNSError(dnsResponse.getMutableData(), dnsResponse.getMaximumSize(), dnsResponse.ids.d_extendedError->infoCode, dnsResponse.ids.d_extendedError->extraText);
  }

  if (cacheHit) {
    ++dnsdist::metrics::g_stats.cacheHits;
  }

  if (dnsResponse.isAsynchronous()) {
    return false;
  }

#ifdef HAVE_DNSCRYPT
  if (!clientState.muted) {
    if (!encryptResponse(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnsQuestion.overTCP(), dnsQuestion.ids.dnsCryptQuery)) {
      return false;
    }
  }
#endif /* HAVE_DNSCRYPT */

  return true;
}

static ProcessQueryResult handleQueryTurnedIntoSelfAnsweredResponse(DNSQuestion& dnsQuestion)
{
  fixUpQueryTurnedResponse(dnsQuestion, dnsQuestion.ids.origFlags);

  if (!prepareOutgoingResponse(*dnsQuestion.ids.cs, dnsQuestion, false)) {
    return ProcessQueryResult::Drop;
  }

  const auto rcode = dnsQuestion.getHeader()->rcode;
  if (rcode == RCode::NXDomain) {
    ++dnsdist::metrics::g_stats.ruleNXDomain;
  }
  else if (rcode == RCode::Refused) {
    ++dnsdist::metrics::g_stats.ruleRefused;
  }
  else if (rcode == RCode::ServFail) {
    ++dnsdist::metrics::g_stats.ruleServFail;
  }

  ++dnsdist::metrics::g_stats.selfAnswered;
  ++dnsQuestion.ids.cs->responses;
  return ProcessQueryResult::SendAnswer;
}

static void selectBackendForOutgoingQuery(DNSQuestion& dnsQuestion, const std::shared_ptr<ServerPool>& serverPool, std::shared_ptr<DownstreamState>& selectedBackend)
{
  std::shared_ptr<ServerPolicy> poolPolicy = serverPool->policy;
  const auto& policy = poolPolicy != nullptr ? *poolPolicy : *dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy;
  const auto servers = serverPool->getServers();
  selectedBackend = policy.getSelectedBackend(*servers, dnsQuestion);
}

enum class CacheRecordMissPolicy : uint8_t
{
  DoNotRecordMiss = 0,
  RecordMiss = 1,
};

static std::optional<ProcessQueryResult> doCacheLookup(DNSQuestion& dnsQuestion, uint32_t allowExpired, CacheRecordMissPolicy recordMiss, uint32_t* cacheKeyOut)
{
  if (!dnsQuestion.ids.packetCache->get(dnsQuestion, dnsQuestion.getHeader()->id, cacheKeyOut, dnsQuestion.ids.subnet, *dnsQuestion.ids.dnssecOK, allowExpired, false, recordMiss == CacheRecordMissPolicy::RecordMiss)) {
    return std::nullopt;
  }

  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [flags = dnsQuestion.ids.origFlags](dnsheader& header) {
    restoreFlags(&header, flags);
    return true;
  });

  vinfolog("Packet cache hit for query for %s|%s from %s (%s, %d bytes)", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.protocol.toString(), dnsQuestion.getData().size());

  if (!prepareOutgoingResponse(*dnsQuestion.ids.cs, dnsQuestion, true)) {
    return ProcessQueryResult::Drop;
  }

  ++dnsdist::metrics::g_stats.responses;
  ++dnsQuestion.ids.cs->responses;
  return ProcessQueryResult::SendAnswer;
}

static std::optional<ProcessQueryResult> handleCacheLookups(DNSQuestion& dnsQuestion, std::shared_ptr<ServerPool>& serverPool, std::shared_ptr<DownstreamState>& selectedBackend, bool zeroScopeLookup)
{
  if (!dnsQuestion.ids.packetCache || dnsQuestion.ids.skipCache) {
    return std::nullopt;
  }

  uint32_t allowExpired = selectedBackend ? 0 : dnsdist::configuration::getCurrentRuntimeConfiguration().d_staleCacheEntriesTTL;

  uint32_t* cacheKey = zeroScopeLookup ? &dnsQuestion.ids.cacheKeyNoECS : &dnsQuestion.ids.cacheKey;
  auto cacheResult = doCacheLookup(dnsQuestion, allowExpired, zeroScopeLookup ? CacheRecordMissPolicy::DoNotRecordMiss : CacheRecordMissPolicy::RecordMiss, cacheKey);
  if (cacheResult) {
    return *cacheResult;
  }

  if (zeroScopeLookup) {
    return std::nullopt;
  }

  vinfolog("Packet cache miss for query for %s|%s from %s (%s, %d bytes)", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.protocol.toString(), dnsQuestion.getData().size());

  ++dnsdist::metrics::g_stats.cacheMisses;

  // coverity[auto_causes_copy]
  const auto existingPool = dnsQuestion.ids.poolName;
  const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
  const auto& cacheMissRuleActions = dnsdist::rules::getRuleChain(chains, dnsdist::rules::RuleChain::CacheMissRules);

  if (!applyRulesChainToQuery(cacheMissRuleActions, dnsQuestion)) {
    return ProcessQueryResult::Drop;
  }
  if (dnsQuestion.getHeader()->qr) { // something turned it into a response
    return handleQueryTurnedIntoSelfAnsweredResponse(dnsQuestion);
  }
  /* let's be nice and allow the selection of a different pool,
     but no second cache-lookup for you */
  if (dnsQuestion.ids.poolName != existingPool) {
    serverPool = getPool(dnsQuestion.ids.poolName);
    dnsQuestion.ids.packetCache = serverPool->packetCache;
    selectBackendForOutgoingQuery(dnsQuestion, serverPool, selectedBackend);
  }

  return std::nullopt;
}

ProcessQueryResult processQueryAfterRules(DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend)
{
  const uint16_t queryId = ntohs(dnsQuestion.getHeader()->id);

  try {
    if (dnsQuestion.getHeader()->qr) { // something turned it into a response
      return handleQueryTurnedIntoSelfAnsweredResponse(dnsQuestion);
    }

    std::shared_ptr<ServerPool> serverPool = getPool(dnsQuestion.ids.poolName);
    dnsQuestion.ids.packetCache = serverPool->packetCache;
    selectBackendForOutgoingQuery(dnsQuestion, serverPool, selectedBackend);

    if (dnsQuestion.ids.packetCache && !dnsQuestion.ids.skipCache && !dnsQuestion.ids.dnssecOK) {
      dnsQuestion.ids.dnssecOK = (dnsdist::getEDNSZ(dnsQuestion) & EDNS_HEADER_FLAG_DO) != 0;
    }

    if (dnsQuestion.useECS && ((selectedBackend && selectedBackend->d_config.useECS) || (!selectedBackend && serverPool->getECS()))) {
      // we special case our cache in case a downstream explicitly gave us a universally valid response with a 0 scope
      // we need ECS parsing (parseECS) to be true so we can be sure that the initial incoming query did not have an existing
      // ECS option, which would make it unsuitable for the zero-scope feature.
      if ((!selectedBackend || !selectedBackend->d_config.disableZeroScope) && dnsQuestion.ids.packetCache && dnsQuestion.ids.packetCache->isECSParsingEnabled()) {
        auto cacheLookupResult = handleCacheLookups(dnsQuestion, serverPool, selectedBackend, true);
        if (cacheLookupResult) {
          return *cacheLookupResult;
        }

        if (!dnsQuestion.ids.subnet) {
          /* there was no existing ECS on the query, enable the zero-scope feature */
          dnsQuestion.ids.useZeroScope = true;
        }
      }

      if (!handleEDNSClientSubnet(dnsQuestion, dnsQuestion.ids.ednsAdded, dnsQuestion.ids.ecsAdded)) {
        vinfolog("Dropping query from %s because we couldn't insert the ECS value", dnsQuestion.ids.origRemote.toStringWithPort());
        return ProcessQueryResult::Drop;
      }
    }

    auto cacheLookupResult = handleCacheLookups(dnsQuestion, serverPool, selectedBackend, false);
    if (cacheLookupResult) {
      return *cacheLookupResult;
    }

    if (!selectedBackend) {
      auto servFailOnNoPolicy = dnsdist::configuration::getCurrentRuntimeConfiguration().d_servFailOnNoPolicy;
      ++dnsdist::metrics::g_stats.noPolicy;

      vinfolog("%s query for %s|%s from %s, no downstream server available", servFailOnNoPolicy ? "ServFailed" : "Dropped", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort());
      if (servFailOnNoPolicy) {
        dnsdist::self_answers::removeRecordsAndSetRCode(dnsQuestion, RCode::ServFail);

        fixUpQueryTurnedResponse(dnsQuestion, dnsQuestion.ids.origFlags);

        if (!prepareOutgoingResponse(*dnsQuestion.ids.cs, dnsQuestion, false)) {
          return ProcessQueryResult::Drop;
        }
        ++dnsdist::metrics::g_stats.responses;
        ++dnsQuestion.ids.cs->responses;
        // no response-only statistics counter to update.
        return ProcessQueryResult::SendAnswer;
      }

      return ProcessQueryResult::Drop;
    }

    /* save the DNS flags as sent to the backend so we can cache the answer with the right flags later */
    dnsQuestion.ids.cacheFlags = *getFlagsFromDNSHeader(dnsQuestion.getHeader().get());

    if (selectedBackend->d_config.useProxyProtocol && dnsQuestion.getProtocol().isEncrypted() && selectedBackend->d_config.d_proxyProtocolAdvertiseTLS) {
      if (!dnsQuestion.proxyProtocolValues) {
        dnsQuestion.proxyProtocolValues = std::make_unique<std::vector<ProxyProtocolValue>>();
      }
      dnsQuestion.proxyProtocolValues->push_back(ProxyProtocolValue{"", static_cast<uint8_t>(ProxyProtocolValue::Types::PP_TLV_SSL)});
    }

    selectedBackend->incQueriesCount();
    return ProcessQueryResult::PassToBackend;
  }
  catch (const std::exception& e) {
    vinfolog("Got an error while parsing a %s query (after applying rules)  from %s, id %d: %s", (dnsQuestion.overTCP() ? "TCP" : "UDP"), dnsQuestion.ids.origRemote.toStringWithPort(), queryId, e.what());
  }
  return ProcessQueryResult::Drop;
}

bool handleTimeoutResponseRules(const std::vector<dnsdist::rules::ResponseRuleAction>& rules, InternalQueryState& ids, const std::shared_ptr<DownstreamState>& d_ds, const std::shared_ptr<TCPQuerySender>& sender)
{
  PacketBuffer empty;
  DNSResponse dnsResponse(ids, empty, d_ds);
  auto protocol = dnsResponse.getProtocol();

  vinfolog("Handling timeout response rules for incoming protocol = %s", protocol.toString());
  if (protocol == dnsdist::Protocol::DoH) {
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    dnsResponse.d_incomingTCPState = std::dynamic_pointer_cast<IncomingHTTP2Connection>(sender);
#endif
    if (!dnsResponse.d_incomingTCPState || !sender || !sender->active()) {
      return false;
    }
  }
  else if (protocol == dnsdist::Protocol::DoTCP || protocol == dnsdist::Protocol::DNSCryptTCP || protocol == dnsdist::Protocol::DoT) {
    dnsResponse.d_incomingTCPState = std::dynamic_pointer_cast<IncomingTCPConnectionState>(sender);
    if (!dnsResponse.d_incomingTCPState || !sender || !sender->active()) {
      return false;
    }
  }
  (void)applyRulesToResponse(rules, dnsResponse);
  return dnsResponse.isAsynchronous();
}

void handleServerStateChange(const string& nameWithAddr, bool newResult)
{
  try {
    auto lua = g_lua.lock();
    dnsdist::lua::hooks::runServerStateChangeHooks(*lua, nameWithAddr, newResult);
  }
  catch (const std::exception& exp) {
    warnlog("Error calling the Lua hook for Server State Change: %s", exp.what());
  }
}

class UDPTCPCrossQuerySender : public TCPQuerySender
{
public:
  UDPTCPCrossQuerySender() = default;
  UDPTCPCrossQuerySender(const UDPTCPCrossQuerySender&) = delete;
  UDPTCPCrossQuerySender& operator=(const UDPTCPCrossQuerySender&) = delete;
  UDPTCPCrossQuerySender(UDPTCPCrossQuerySender&&) = default;
  UDPTCPCrossQuerySender& operator=(UDPTCPCrossQuerySender&&) = default;
  ~UDPTCPCrossQuerySender() override = default;

  [[nodiscard]] bool active() const override
  {
    return true;
  }

  void handleResponse(const struct timeval& now, TCPResponse&& response) override
  {
    (void)now;
    if (!response.d_ds && !response.d_idstate.selfGenerated) {
      throw std::runtime_error("Passing a cross-protocol answer originated from UDP without a valid downstream");
    }

    auto& ids = response.d_idstate;

    handleResponseForUDPClient(ids, response.d_buffer, response.d_ds, response.isAsync(), response.d_idstate.selfGenerated);
  }

  void handleXFRResponse(const struct timeval& now, TCPResponse&& response) override
  {
    return handleResponse(now, std::move(response));
  }

  void notifyIOError([[maybe_unused]] const struct timeval& now, [[maybe_unused]] TCPResponse&& response) override
  {
    // nothing to do
  }
};

class UDPCrossProtocolQuery : public CrossProtocolQuery
{
public:
  UDPCrossProtocolQuery(PacketBuffer&& buffer_, InternalQueryState&& ids_, std::shared_ptr<DownstreamState> backend) :
    CrossProtocolQuery(InternalQuery(std::move(buffer_), std::move(ids_)), backend)
  {
    auto& ids = query.d_idstate;
    const auto& buffer = query.d_buffer;

    if (ids.udpPayloadSize == 0) {
      uint16_t zValue = 0;
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(buffer.data()), buffer.size(), &ids.udpPayloadSize, &zValue);
      if (!ids.dnssecOK) {
        ids.dnssecOK = (zValue & EDNS_HEADER_FLAG_DO) != 0;
      }
      if (ids.udpPayloadSize < 512) {
        ids.udpPayloadSize = 512;
      }
    }
  }
  UDPCrossProtocolQuery(const UDPCrossProtocolQuery&) = delete;
  UDPCrossProtocolQuery& operator=(const UDPCrossProtocolQuery&) = delete;
  UDPCrossProtocolQuery(UDPCrossProtocolQuery&&) = delete;
  UDPCrossProtocolQuery& operator=(UDPCrossProtocolQuery&&) = delete;
  ~UDPCrossProtocolQuery() override = default;

  std::shared_ptr<TCPQuerySender> getTCPQuerySender() override
  {
    return s_sender;
  }

private:
  static std::shared_ptr<UDPTCPCrossQuerySender> s_sender;
};

std::shared_ptr<UDPTCPCrossQuerySender> UDPCrossProtocolQuery::s_sender = std::make_shared<UDPTCPCrossQuerySender>();

std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion);
std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dnsQuestion)
{
  dnsQuestion.ids.origID = dnsQuestion.getHeader()->id;
  return std::make_unique<UDPCrossProtocolQuery>(std::move(dnsQuestion.getMutableData()), std::move(dnsQuestion.ids), nullptr);
}

ProcessQueryResult processQuery(DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend)
{
  const uint16_t queryId = ntohs(dnsQuestion.getHeader()->id);

  try {
    /* we need an accurate ("real") value for the response and
       to store into the IDS, but not for insertion into the
       rings for example */
    timespec now{};
    gettime(&now);

    if ((dnsQuestion.ids.qtype == QType::AXFR || dnsQuestion.ids.qtype == QType::IXFR) && (dnsQuestion.getProtocol() == dnsdist::Protocol::DoH || dnsQuestion.getProtocol() == dnsdist::Protocol::DoQ || dnsQuestion.getProtocol() == dnsdist::Protocol::DoH3)) {
      dnsdist::self_answers::removeRecordsAndSetRCode(dnsQuestion, RCode::NotImp);
      return processQueryAfterRules(dnsQuestion, selectedBackend);
    }

    if (!applyRulesToQuery(dnsQuestion, now)) {
      return ProcessQueryResult::Drop;
    }

    if (dnsQuestion.isAsynchronous()) {
      return ProcessQueryResult::Asynchronous;
    }

    return processQueryAfterRules(dnsQuestion, selectedBackend);
  }
  catch (const std::exception& e) {
    vinfolog("Got an error while parsing a %s query from %s, id %d: %s", (dnsQuestion.overTCP() ? "TCP" : "UDP"), dnsQuestion.ids.origRemote.toStringWithPort(), queryId, e.what());
  }
  return ProcessQueryResult::Drop;
}

bool assignOutgoingUDPQueryToBackend(std::shared_ptr<DownstreamState>& downstream, uint16_t queryID, DNSQuestion& dnsQuestion, PacketBuffer& query, bool actuallySend)
{
  bool doh = dnsQuestion.ids.du != nullptr;

  bool failed = false;
  dnsQuestion.ids.d_proxyProtocolPayloadSize = 0;
  if (downstream->d_config.useProxyProtocol) {
    try {
      size_t proxyProtocolPayloadSize = 0;
      if (addProxyProtocol(dnsQuestion, &proxyProtocolPayloadSize)) {
        dnsQuestion.ids.d_proxyProtocolPayloadSize += proxyProtocolPayloadSize;
      }
    }
    catch (const std::exception& e) {
      vinfolog("Adding proxy protocol payload to %s query from %s failed: %s", (dnsQuestion.ids.du ? "DoH" : ""), dnsQuestion.ids.origDest.toStringWithPort(), e.what());
      return false;
    }
  }

  if (doh && !dnsQuestion.ids.d_packet) {
    dnsQuestion.ids.d_packet = std::make_unique<PacketBuffer>(query);
  }

  try {
    int descriptor = downstream->pickSocketForSending();
    if (actuallySend) {
      dnsQuestion.ids.backendFD = descriptor;
    }
    dnsQuestion.ids.origID = queryID;
    dnsQuestion.ids.forwardedOverUDP = true;

    vinfolog("Got query for %s|%s from %s%s, relayed to %s%s", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort(), (doh ? " (https)" : ""), downstream->getNameWithAddr(), actuallySend ? "" : " (xsk)");

    /* make a copy since we cannot touch dnsQuestion.ids after the move */
    auto proxyProtocolPayloadSize = dnsQuestion.ids.d_proxyProtocolPayloadSize;
    auto idOffset = downstream->saveState(std::move(dnsQuestion.ids));
    /* set the correct ID */
    memcpy(&query.at(proxyProtocolPayloadSize), &idOffset, sizeof(idOffset));

    if (!actuallySend) {
      return true;
    }

    /* you can't touch ids or du after this line, unless the call returned a non-negative value,
       because it might already have been freed */
    ssize_t ret = udpClientSendRequestToBackend(downstream, descriptor, query);

    if (ret < 0) {
      failed = true;
    }

    if (failed) {
      /* clear up the state. In the very unlikely event it was reused
         in the meantime, so be it. */
      auto cleared = downstream->getState(idOffset);
      if (cleared) {
        dnsQuestion.ids.du = std::move(cleared->du);
      }
      ++dnsdist::metrics::g_stats.downstreamSendErrors;
      ++downstream->sendErrors;
      return false;
    }
  }
  catch (const std::exception& e) {
    throw;
  }

  return true;
}

static void processUDPQuery(ClientState& clientState, const struct msghdr* msgh, const ComboAddress& remote, ComboAddress& dest, PacketBuffer& query, std::vector<mmsghdr>* responsesVect, unsigned int* queuedResponses, struct iovec* respIOV, cmsgbuf_aligned* respCBuf)
{
  assert(responsesVect == nullptr || (queuedResponses != nullptr && respIOV != nullptr && respCBuf != nullptr));
  uint16_t queryId = 0;
  InternalQueryState ids;
  ids.cs = &clientState;
  ids.origRemote = remote;
  ids.hopRemote = remote;
  ids.protocol = dnsdist::Protocol::DoUDP;

  try {
    bool expectProxyProtocol = false;
    if (!isUDPQueryAcceptable(clientState, msgh, remote, dest, expectProxyProtocol)) {
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
      ids.origDest = clientState.local;
      ids.hopLocal.sin4.sin_family = 0;
    }

    std::vector<ProxyProtocolValue> proxyProtocolValues;
    if (expectProxyProtocol && !handleProxyProtocol(remote, false, dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL, query, ids.origRemote, ids.origDest, proxyProtocolValues)) {
      return;
    }

    ids.queryRealTime.start();

    auto dnsCryptResponse = checkDNSCryptQuery(clientState, query, ids.dnsCryptQuery, ids.queryRealTime.d_start.tv_sec, false);
    if (dnsCryptResponse) {
      sendUDPResponse(clientState.udpFD, query, 0, dest, remote);
      return;
    }

    {
      /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
      const dnsheader_aligned dnsHeader(query.data());
      queryId = ntohs(dnsHeader->id);

      if (!checkQueryHeaders(*dnsHeader, clientState)) {
        return;
      }

      if (dnsHeader->qdcount == 0) {
        dnsdist::PacketMangling::editDNSHeaderFromPacket(query, [](dnsheader& header) {
          header.rcode = RCode::NotImp;
          header.qr = true;
          return true;
        });

        sendUDPResponse(clientState.udpFD, query, 0, dest, remote);
        return;
      }
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
    if (ids.dnsCryptQuery) {
      ids.protocol = dnsdist::Protocol::DNSCryptUDP;
    }
    DNSQuestion dnsQuestion(ids, query);
    const uint16_t* flags = getFlagsFromDNSHeader(dnsQuestion.getHeader().get());
    ids.origFlags = *flags;

    if (!proxyProtocolValues.empty()) {
      dnsQuestion.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
    }

    // save UDP payload size from origin query
    uint16_t udpPayloadSize = 0;
    uint16_t zValue = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    getEDNSUDPPayloadSizeAndZ(reinterpret_cast<const char*>(query.data()), query.size(), &udpPayloadSize, &zValue);
    if (!ids.dnssecOK) {
      ids.dnssecOK = (zValue & EDNS_HEADER_FLAG_DO) != 0;
    }
    if (udpPayloadSize < 512) {
      udpPayloadSize = 512;
    }

    std::shared_ptr<DownstreamState> backend{nullptr};
    auto result = processQuery(dnsQuestion, backend);

    if (result == ProcessQueryResult::Drop || result == ProcessQueryResult::Asynchronous) {
      return;
    }

    // the buffer might have been invalidated by now (resized)
    const auto dnsHeader = dnsQuestion.getHeader();
    if (result == ProcessQueryResult::SendAnswer) {
      /* ensure payload size is not exceeded */
      handleResponseTC4UDPClient(dnsQuestion, udpPayloadSize, query);
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
      if (dnsQuestion.ids.delayMsec == 0 && responsesVect != nullptr) {
        queueResponse(query, dest, remote, (*responsesVect)[*queuedResponses], respIOV, respCBuf);
        (*queuedResponses)++;
        handleResponseSent(dnsQuestion.ids.qname, dnsQuestion.ids.qtype, 0., remote, ComboAddress(), query.size(), *dnsHeader, dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoUDP, false);
        return;
      }
#endif /* defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE) */
#endif /* DISABLE_RECVMMSG */
      /* we use dest, always, because we don't want to use the listening address to send a response since it could be 0.0.0.0 */
      sendUDPResponse(clientState.udpFD, query, dnsQuestion.ids.delayMsec, dest, remote);

      handleResponseSent(dnsQuestion.ids.qname, dnsQuestion.ids.qtype, 0., remote, ComboAddress(), query.size(), *dnsHeader, dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoUDP, false);
      return;
    }

    if (result != ProcessQueryResult::PassToBackend || backend == nullptr) {
      return;
    }

    if (backend->isTCPOnly()) {
      std::string proxyProtocolPayload;
      /* we need to do this _before_ creating the cross protocol query because
         after that the buffer will have been moved */
      if (backend->d_config.useProxyProtocol) {
        proxyProtocolPayload = getProxyProtocolPayload(dnsQuestion);
      }

      ids.origID = dnsHeader->id;
      auto cpq = std::make_unique<UDPCrossProtocolQuery>(std::move(query), std::move(ids), backend);
      cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

      backend->passCrossProtocolQuery(std::move(cpq));
      return;
    }

    assignOutgoingUDPQueryToBackend(backend, dnsHeader->id, dnsQuestion, query);
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in UDP question thread while parsing a query from %s, id %d: %s", ids.origRemote.toStringWithPort(), queryId, e.what());
  }
}

#ifdef HAVE_XSK
namespace dnsdist::xsk
{
bool XskProcessQuery(ClientState& clientState, XskPacket& packet)
{
  uint16_t queryId = 0;
  const auto& remote = packet.getFromAddr();
  const auto& dest = packet.getToAddr();
  InternalQueryState ids;
  ids.cs = &clientState;
  ids.origRemote = remote;
  ids.hopRemote = remote;
  ids.origDest = dest;
  ids.hopLocal = dest;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.xskPacketHeader = packet.cloneHeaderToPacketBuffer();

  try {
    bool expectProxyProtocol = false;
    if (!XskIsQueryAcceptable(packet, clientState, expectProxyProtocol)) {
      return false;
    }

    auto query = packet.clonePacketBuffer();
    std::vector<ProxyProtocolValue> proxyProtocolValues;
    if (expectProxyProtocol && !handleProxyProtocol(remote, false, dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL, query, ids.origRemote, ids.origDest, proxyProtocolValues)) {
      return false;
    }

    ids.queryRealTime.start();

    auto dnsCryptResponse = checkDNSCryptQuery(clientState, query, ids.dnsCryptQuery, ids.queryRealTime.d_start.tv_sec, false);
    if (dnsCryptResponse) {
      packet.setPayload(query);
      return true;
    }

    {
      /* this pointer will be invalidated the second the buffer is resized, don't hold onto it! */
      dnsheader_aligned dnsHeader(query.data());
      queryId = ntohs(dnsHeader->id);

      if (!checkQueryHeaders(*dnsHeader, clientState)) {
        return false;
      }

      if (dnsHeader->qdcount == 0) {
        dnsdist::PacketMangling::editDNSHeaderFromPacket(query, [](dnsheader& header) {
          header.rcode = RCode::NotImp;
          header.qr = true;
          return true;
        });
        packet.setPayload(query);
        return true;
      }
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    ids.qname = DNSName(reinterpret_cast<const char*>(query.data()), query.size(), sizeof(dnsheader), false, &ids.qtype, &ids.qclass);
    if (ids.origDest.sin4.sin_family == 0) {
      ids.origDest = clientState.local;
    }
    if (ids.dnsCryptQuery) {
      ids.protocol = dnsdist::Protocol::DNSCryptUDP;
    }
    DNSQuestion dnsQuestion(ids, query);
    if (!proxyProtocolValues.empty()) {
      dnsQuestion.proxyProtocolValues = make_unique<std::vector<ProxyProtocolValue>>(std::move(proxyProtocolValues));
    }
    std::shared_ptr<DownstreamState> backend{nullptr};
    auto result = processQuery(dnsQuestion, backend);

    if (result == ProcessQueryResult::Drop) {
      return false;
    }

    if (result == ProcessQueryResult::SendAnswer) {
      packet.setPayload(query);
      if (dnsQuestion.ids.delayMsec > 0) {
        packet.addDelay(dnsQuestion.ids.delayMsec);
      }
      const auto dnsHeader = dnsQuestion.getHeader();
      handleResponseSent(ids.qname, ids.qtype, 0., remote, ComboAddress(), query.size(), *dnsHeader, dnsdist::Protocol::DoUDP, dnsdist::Protocol::DoUDP, false);
      return true;
    }

    if (result != ProcessQueryResult::PassToBackend || backend == nullptr) {
      return false;
    }

    // the buffer might have been invalidated by now (resized)
    const auto dnsHeader = dnsQuestion.getHeader();
    if (backend->isTCPOnly()) {
      std::string proxyProtocolPayload;
      /* we need to do this _before_ creating the cross protocol query because
         after that the buffer will have been moved */
      if (backend->d_config.useProxyProtocol) {
        proxyProtocolPayload = getProxyProtocolPayload(dnsQuestion);
      }

      ids.origID = dnsHeader->id;
      auto cpq = std::make_unique<UDPCrossProtocolQuery>(std::move(query), std::move(ids), backend);
      cpq->query.d_proxyProtocolPayload = std::move(proxyProtocolPayload);

      backend->passCrossProtocolQuery(std::move(cpq));
      return false;
    }

    if (backend->d_xskInfos.empty()) {
      assignOutgoingUDPQueryToBackend(backend, dnsHeader->id, dnsQuestion, query, true);
      return false;
    }

    assignOutgoingUDPQueryToBackend(backend, dnsHeader->id, dnsQuestion, query, false);
    auto sourceAddr = backend->pickSourceAddressForSending();
    packet.setAddr(sourceAddr, backend->d_config.sourceMACAddr, backend->d_config.remote, backend->d_config.destMACAddr);
    packet.setPayload(query);
    packet.rewrite();
    return true;
  }
  catch (const std::exception& e) {
    vinfolog("Got an error in UDP question thread while parsing a query from %s, id %d: %s", remote.toStringWithPort(), queryId, e.what());
  }
  return false;
}

}
#endif /* HAVE_XSK */

#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
static void MultipleMessagesUDPClientThread(ClientState* clientState)
{
  struct MMReceiver
  {
    PacketBuffer packet;
    ComboAddress remote;
    ComboAddress dest;
    iovec iov{};
    /* used by HarvestDestinationAddress */
    cmsgbuf_aligned cbuf{};
  };
  const size_t vectSize = dnsdist::configuration::getImmutableConfiguration().d_udpVectorSize;

  if (vectSize > std::numeric_limits<uint16_t>::max()) {
    throw std::runtime_error("The value of setUDPMultipleMessagesVectorSize is too high, the maximum value is " + std::to_string(std::numeric_limits<uint16_t>::max()));
  }

  auto recvData = std::vector<MMReceiver>(vectSize);
  auto msgVec = std::vector<mmsghdr>(vectSize);
  auto outMsgVec = std::vector<mmsghdr>(vectSize);

  /* the actual buffer is larger because:
     - we may have to add EDNS and/or ECS
     - we use it for self-generated responses (from rule or cache)
     but we only accept incoming payloads up to that size
  */
  const size_t initialBufferSize = getInitialUDPPacketBufferSize(clientState->d_enableProxyProtocol);
  const size_t maxIncomingPacketSize = getMaximumIncomingPacketSize(*clientState);

  /* initialize the structures needed to receive our messages */
  for (size_t idx = 0; idx < vectSize; idx++) {
    recvData[idx].remote.sin4.sin_family = clientState->local.sin4.sin_family;
    recvData[idx].packet.resize(initialBufferSize);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    fillMSGHdr(&msgVec[idx].msg_hdr, &recvData[idx].iov, &recvData[idx].cbuf, sizeof(recvData[idx].cbuf), reinterpret_cast<char*>(recvData[idx].packet.data()), maxIncomingPacketSize, &recvData[idx].remote);
  }

  /* go now */
  for (;;) {

    /* reset the IO vector, since it's also used to send the vector of responses
       to avoid having to copy the data around */
    for (size_t idx = 0; idx < vectSize; idx++) {
      recvData[idx].packet.resize(initialBufferSize);
      recvData[idx].iov.iov_base = &recvData[idx].packet.at(0);
      recvData[idx].iov.iov_len = recvData[idx].packet.size();
    }

    /* block until we have at least one message ready, but return
       as many as possible to save the syscall costs */
    int msgsGot = recvmmsg(clientState->udpFD, msgVec.data(), vectSize, MSG_WAITFORONE | MSG_TRUNC, nullptr);

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
        ++dnsdist::metrics::g_stats.nonCompliantQueries;
        ++clientState->nonCompliantQueries;
        continue;
      }

      recvData[msgIdx].packet.resize(got);
      dnsdist::configuration::refreshLocalRuntimeConfiguration();
      processUDPQuery(*clientState, msgh, remote, recvData[msgIdx].dest, recvData[msgIdx].packet, &outMsgVec, &msgsToSend, &recvData[msgIdx].iov, &recvData[msgIdx].cbuf);
    }

    /* immediate (not delayed or sent to a backend) responses (mostly from a rule, dynamic block
       or the cache) can be sent in batch too */

    if (msgsToSend > 0 && msgsToSend <= static_cast<unsigned int>(msgsGot)) {
      int sent = sendmmsg(clientState->udpFD, outMsgVec.data(), msgsToSend, 0);

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
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
    if (dnsdist::configuration::getImmutableConfiguration().d_udpVectorSize > 1) {
      MultipleMessagesUDPClientThread(states.at(0));
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
      const size_t initialBufferSize = getInitialUDPPacketBufferSize(true);
      PacketBuffer packet(initialBufferSize);

      msghdr msgh{};
      iovec iov{};
      ComboAddress remote;
      ComboAddress dest;

      auto handleOnePacket = [&packet, &iov, &msgh, &remote, &dest, initialBufferSize](const UDPStateParam& param) {
        packet.resize(initialBufferSize);
        iov.iov_base = &packet.at(0);
        iov.iov_len = packet.size();

        ssize_t got = recvmsg(param.socket, &msgh, 0);

        if (got < 0 || static_cast<size_t>(got) < sizeof(struct dnsheader)) {
          ++dnsdist::metrics::g_stats.nonCompliantQueries;
          ++param.cs->nonCompliantQueries;
          return;
        }

        packet.resize(static_cast<size_t>(got));

        dnsdist::configuration::refreshLocalRuntimeConfiguration();
        processUDPQuery(*param.cs, &msgh, remote, dest, packet, nullptr, nullptr, nullptr, nullptr);
      };

      std::vector<UDPStateParam> params;
      for (auto& state : states) {
        const size_t maxIncomingPacketSize = getMaximumIncomingPacketSize(*state);
        params.emplace_back(UDPStateParam{state, maxIncomingPacketSize, state->udpFD});
      }

      if (params.size() == 1) {
        const auto& param = params.at(0);
        remote.sin4.sin_family = param.cs->local.sin4.sin_family;
        /* used by HarvestDestinationAddress */
        cmsgbuf_aligned cbuf;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
          (void)socket;
          const auto* param = boost::any_cast<const UDPStateParam*>(funcparam);
          try {
            remote.sin4.sin_family = param->cs->local.sin4.sin_family;
            packet.resize(initialBufferSize);
            /* used by HarvestDestinationAddress */
            cmsgbuf_aligned cbuf;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
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
        for (const auto& param : params) {
          mplexer->addReadFD(param.socket, callback, &param);
        }

        timeval now{};
        while (true) {
          mplexer->run(&now, -1);
        }
      }
    }
  }
  catch (const std::exception& e) {
    errlog("UDP client thread died because of exception: %s", e.what());
  }
  catch (const PDNSException& e) {
    errlog("UDP client thread died because of PowerDNS exception: %s", e.reason);
  }
  catch (...) {
    errlog("UDP client thread died because of an exception: %s", "unknown");
  }
}

static void maintThread()
{
  setThreadName("dnsdist/main");
  constexpr int interval = 1;
  size_t counter = 0;
  int32_t secondsToWaitLog = 0;

  for (;;) {
    std::this_thread::sleep_for(std::chrono::seconds(interval));

    dnsdist::configuration::refreshLocalRuntimeConfiguration();
    {
      auto lua = g_lua.lock();
      try {
        auto maintenanceCallback = lua->readVariable<boost::optional<std::function<void()>>>("maintenance");
        if (maintenanceCallback) {
          (*maintenanceCallback)();
        }
        dnsdist::lua::hooks::runMaintenanceHooks(*lua);
#if !defined(DISABLE_DYNBLOCKS)
        dnsdist::DynamicBlocks::runRegisteredGroups(*lua);
#endif /* DISABLE_DYNBLOCKS */
        secondsToWaitLog = 0;
      }
      catch (const std::exception& e) {
        if (secondsToWaitLog <= 0) {
          warnlog("Error during execution of maintenance function(s): %s", e.what());
          secondsToWaitLog = 61;
        }
        secondsToWaitLog -= interval;
      }
    }

    counter++;
    if (counter >= dnsdist::configuration::getCurrentRuntimeConfiguration().d_cacheCleaningDelay) {
      /* keep track, for each cache, of whether we should keep
       expired entries */
      std::map<std::shared_ptr<DNSDistPacketCache>, bool> caches;

      /* gather all caches actually used by at least one pool, and see
         if something prevents us from cleaning the expired entries */
      const auto& pools = dnsdist::configuration::getCurrentRuntimeConfiguration().d_pools;
      for (const auto& entry : pools) {
        const auto& pool = entry.second;

        auto packetCache = pool->packetCache;
        if (!packetCache) {
          continue;
        }

        auto pair = caches.insert({packetCache, false});
        auto& iter = pair.first;
        /* if we need to keep stale data for this cache (ie, not clear
           expired entries when at least one pool using this cache
           has all its backends down) */
        if (packetCache->keepStaleData() && !iter->second) {
          /* so far all pools had at least one backend up */
          if (pool->countServers(true) == 0) {
            iter->second = true;
          }
        }
      }

      const time_t now = time(nullptr);
      for (const auto& pair : caches) {
        /* shall we keep expired entries ? */
        if (pair.second) {
          continue;
        }
        const auto& packetCache = pair.first;
        size_t upTo = (packetCache->getMaxEntries() * (100 - dnsdist::configuration::getCurrentRuntimeConfiguration().d_cacheCleaningPercentage)) / 100;
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

  dnsdist::configuration::refreshLocalRuntimeConfiguration();
  DynBlockMaintenance::run();
}
#endif

#ifndef DISABLE_SECPOLL
static void secPollThread()
{
  setThreadName("dnsdist/secpoll");

  for (;;) {
    const auto& runtimeConfig = dnsdist::configuration::refreshLocalRuntimeConfiguration();

    try {
      dnsdist::secpoll::doSecPoll(runtimeConfig.d_secPollSuffix);
    }
    catch (...) {
    }
    // coverity[store_truncates_time_t]
    std::this_thread::sleep_for(std::chrono::seconds(runtimeConfig.d_secPollInterval));
  }
}
#endif /* DISABLE_SECPOLL */

static std::atomic<bool> s_exiting{false};
void doExitNicely(int exitCode = EXIT_SUCCESS);

static void checkExiting()
{
  if (s_exiting) {
    doExitNicely();
  }
}

static void healthChecksThread()
{
  setThreadName("dnsdist/healthC");

  constexpr int intervalUsec = 1000 * 1000;
  struct timeval lastRound{
    .tv_sec = 0,
    .tv_usec = 0};

  for (;;) {
    checkExiting();

    timeval now{};
    gettimeofday(&now, nullptr);
    auto elapsedTimeUsec = uSec(now - lastRound);
    if (elapsedTimeUsec < intervalUsec) {
      usleep(intervalUsec - elapsedTimeUsec);
      gettimeofday(&lastRound, nullptr);
    }
    else {
      lastRound = now;
    }

    std::unique_ptr<FDMultiplexer> mplexer{nullptr};
    const auto& runtimeConfig = dnsdist::configuration::refreshLocalRuntimeConfiguration();

    // this points to the actual shared_ptrs!
    // coverity[auto_causes_copy]
    const auto servers = runtimeConfig.d_backends;
    for (const auto& dss : servers) {
      dss->updateStatisticsInfo();

      dss->handleUDPTimeouts();

      if (!dss->healthCheckRequired()) {
        continue;
      }

      if (!mplexer) {
        mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(servers.size()));
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

static void bindAny([[maybe_unused]] int addressFamily, [[maybe_unused]] int sock)
{
  __attribute__((unused)) int one = 1;

#ifdef IP_FREEBIND
  if (setsockopt(sock, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) < 0) {
    warnlog("Warning: IP_FREEBIND setsockopt failed: %s", stringerror());
  }
#endif

#ifdef IP_BINDANY
  if (addressFamily == AF_INET) {
    if (setsockopt(sock, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) < 0) {
      warnlog("Warning: IP_BINDANY setsockopt failed: %s", stringerror());
    }
  }
#endif
#ifdef IPV6_BINDANY
  if (addressFamily == AF_INET6) {
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) < 0) {
      warnlog("Warning: IPV6_BINDANY setsockopt failed: %s", stringerror());
    }
  }
#endif
#ifdef SO_BINDANY
  if (setsockopt(sock, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) < 0) {
    warnlog("Warning: SO_BINDANY setsockopt failed: %s", stringerror());
  }
#endif
}

static void dropGroupPrivs(gid_t gid)
{
  if (gid != 0) {
    if (setgid(gid) == 0) {
      if (setgroups(0, nullptr) < 0) {
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
  if (uid != 0) {
    if (setuid(uid) < 0) {
      warnlog("Warning: Unable to set user ID to %d: %s", uid, stringerror());
    }
  }
}

static void checkFileDescriptorsLimits(size_t udpBindsCount, size_t tcpBindsCount)
{
  const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
  /* stdin, stdout, stderr */
  rlim_t requiredFDsCount = 3;
  const auto& backends = dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends;
  /* UDP sockets to backends */
  size_t backendUDPSocketsCount = 0;
  for (const auto& backend : backends) {
    backendUDPSocketsCount += backend->sockets.size();
  }
  requiredFDsCount += backendUDPSocketsCount;
  /* TCP sockets to backends */
  if (immutableConfig.d_maxTCPClientThreads > 0) {
    requiredFDsCount += (backends.size() * immutableConfig.d_maxTCPClientThreads);
  }
  /* listening sockets */
  requiredFDsCount += udpBindsCount;
  requiredFDsCount += tcpBindsCount;
  /* number of TCP connections currently served, assuming 1 connection per worker thread which is of course not right */
  if (immutableConfig.d_maxTCPClientThreads > 0) {
    requiredFDsCount += immutableConfig.d_maxTCPClientThreads;
    /* max pipes for communicating between TCP acceptors and client threads */
    requiredFDsCount += (immutableConfig.d_maxTCPClientThreads * 2);
  }
  /* max TCP queued connections */
  requiredFDsCount += immutableConfig.d_maxTCPQueuedConnections;
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
  rlimit resourceLimits{};
  getrlimit(RLIMIT_NOFILE, &resourceLimits);
  if (resourceLimits.rlim_cur <= requiredFDsCount) {
    warnlog("Warning, this configuration can use more than %d file descriptors, web server and console connections not included, and the current limit is %d.", std::to_string(requiredFDsCount), std::to_string(resourceLimits.rlim_cur));
#ifdef HAVE_SYSTEMD
    warnlog("You can increase this value by using LimitNOFILE= in the systemd unit file or ulimit.");
#else
    warnlog("You can increase this value by using ulimit.");
#endif
  }
}

static void setupLocalSocket(ClientState& clientState, const ComboAddress& addr, int& socket, bool tcp, bool warn)
{
  const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
  static bool s_warned_ipv6_recvpktinfo = false;
  (void)warn;
  socket = SSocket(addr.sin4.sin_family, !tcp ? SOCK_DGRAM : SOCK_STREAM, 0);

  if (tcp) {
    SSetsockopt(socket, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef TCP_DEFER_ACCEPT
    SSetsockopt(socket, IPPROTO_TCP, TCP_DEFER_ACCEPT, 1);
#endif
    if (clientState.fastOpenQueueSize > 0) {
#ifdef TCP_FASTOPEN
      SSetsockopt(socket, IPPROTO_TCP, TCP_FASTOPEN, clientState.fastOpenQueueSize);
#ifdef TCP_FASTOPEN_KEY
      if (!immutableConfig.d_tcpFastOpenKey.empty()) {
        auto res = setsockopt(socket, IPPROTO_IP, TCP_FASTOPEN_KEY, immutableConfig.d_tcpFastOpenKey.data(), immutableConfig.d_tcpFastOpenKey.size() * sizeof(immutableConfig.d_tcpFastOpenKey[0]));
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
    (void)setsockopt(socket, IPPROTO_IP, GEN_IP_PKTINFO, &one, sizeof(one)); // linux supports this, so why not - might fail on other systems
#ifdef IPV6_RECVPKTINFO
    if (addr.isIPv6() && setsockopt(socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) < 0 && !s_warned_ipv6_recvpktinfo) {
      warnlog("Warning: IPV6_RECVPKTINFO setsockopt failed: %s", stringerror());
      s_warned_ipv6_recvpktinfo = true;
    }
#endif
  }

  if (clientState.reuseport) {
    if (!setReusePort(socket)) {
      if (warn) {
        /* no need to warn again if configured but support is not available, we already did for UDP */
        warnlog("SO_REUSEPORT has been configured on local address '%s' but is not supported", addr.toStringWithPort());
      }
    }
  }

  const bool isQUIC = clientState.doqFrontend != nullptr || clientState.doh3Frontend != nullptr;
  if (isQUIC) {
    /* disable fragmentation and force PMTU discovery for QUIC-enabled sockets */
    try {
      setSocketForcePMTU(socket, addr.sin4.sin_family);
    }
    catch (const std::exception& e) {
      warnlog("Failed to set IP_MTU_DISCOVER on QUIC server socket for local address '%s': %s", addr.toStringWithPort(), e.what());
    }
  }
  else if (!tcp && !clientState.dnscryptCtx) {
    /* Only set this on IPv4 UDP sockets.
       Don't set it for DNSCrypt binds. DNSCrypt pads queries for privacy
       purposes, so we do receive large, sometimes fragmented datagrams. */
    try {
      setSocketIgnorePMTU(socket, addr.sin4.sin_family);
    }
    catch (const std::exception& e) {
      warnlog("Failed to set IP_MTU_DISCOVER on UDP server socket for local address '%s': %s", addr.toStringWithPort(), e.what());
    }
  }

  if (!tcp) {
    if (immutableConfig.d_socketUDPSendBuffer > 0) {
      try {
        setSocketSendBuffer(socket, immutableConfig.d_socketUDPSendBuffer);
      }
      catch (const std::exception& e) {
        warnlog(e.what());
      }
    }
    else {
      try {
        auto result = raiseSocketSendBufferToMax(socket);
        if (result > 0) {
          infolog("Raised send buffer to %u for local address '%s'", result, addr.toStringWithPort());
        }
      }
      catch (const std::exception& e) {
        warnlog(e.what());
      }
    }

    if (immutableConfig.d_socketUDPRecvBuffer > 0) {
      try {
        setSocketReceiveBuffer(socket, immutableConfig.d_socketUDPRecvBuffer);
      }
      catch (const std::exception& e) {
        warnlog(e.what());
      }
    }
    else {
      try {
        auto result = raiseSocketReceiveBufferToMax(socket);
        if (result > 0) {
          infolog("Raised receive buffer to %u for local address '%s'", result, addr.toStringWithPort());
        }
      }
      catch (const std::exception& e) {
        warnlog(e.what());
      }
    }
  }

  const std::string& itf = clientState.interface;
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
  /* for now eBPF filtering is not enabled on QUIC sockets because the eBPF code tries
     to parse the QNAME from the payload for all UDP datagrams, which obviously does not
     work well for these. */
  if (!isQUIC && g_defaultBPFFilter && !g_defaultBPFFilter->isExternal()) {
    clientState.attachFilter(g_defaultBPFFilter, socket);
    vinfolog("Attaching default BPF Filter to %s frontend %s", (!tcp ? std::string("UDP") : std::string("TCP")), addr.toStringWithPort());
  }
#endif /* HAVE_EBPF */

  SBind(socket, addr);

  if (tcp) {
    SListen(socket, clientState.tcpListenQueueSize);

    if (clientState.tlsFrontend != nullptr) {
      infolog("Listening on %s for TLS", addr.toStringWithPort());
    }
    else if (clientState.dohFrontend != nullptr) {
      infolog("Listening on %s for DoH", addr.toStringWithPort());
    }
    else if (clientState.dnscryptCtx != nullptr) {
      infolog("Listening on %s for DNSCrypt", addr.toStringWithPort());
    }
    else {
      infolog("Listening on %s", addr.toStringWithPort());
    }
  }
  else {
    if (clientState.doqFrontend != nullptr) {
      infolog("Listening on %s for DoQ", addr.toStringWithPort());
    }
    else if (clientState.doh3Frontend != nullptr) {
      infolog("Listening on %s for DoH3", addr.toStringWithPort());
    }
#ifdef HAVE_XSK
    else if (clientState.xskInfo != nullptr) {
      infolog("Listening on %s (XSK-enabled)", addr.toStringWithPort());
    }
#endif
  }
}

static void setUpLocalBind(ClientState& cstate)
{
  /* skip some warnings if there is an identical UDP context */
  bool warn = !cstate.tcp || cstate.tlsFrontend != nullptr || cstate.dohFrontend != nullptr;
  int& descriptor = !cstate.tcp ? cstate.udpFD : cstate.tcpFD;
  (void)warn;

  setupLocalSocket(cstate, cstate.local, descriptor, cstate.tcp, warn);

  for (auto& [addr, socket] : cstate.d_additionalAddresses) {
    setupLocalSocket(cstate, addr, socket, true, false);
  }

  if (cstate.tlsFrontend != nullptr) {
    if (!cstate.tlsFrontend->setupTLS()) {
      errlog("Error while setting up TLS on local address '%s', exiting", cstate.local.toStringWithPort());
      _exit(EXIT_FAILURE);
    }
  }

  if (cstate.dohFrontend != nullptr) {
    cstate.dohFrontend->setup();
  }
  if (cstate.doqFrontend != nullptr) {
    cstate.doqFrontend->setup();
  }
  if (cstate.doh3Frontend != nullptr) {
    cstate.doh3Frontend->setup();
  }

  cstate.ready = true;
}

struct CommandLineParameters
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
};

static void usage()
{
  cout << endl;
  cout << "Syntax: dnsdist [-C,--config file] [-c,--client [IP[:PORT]]]\n";
  cout << "[-e,--execute cmd] [-h,--help] [-l,--local addr]\n";
  cout << "[-v,--verbose] [--check-config] [--version]\n";
  cout << "\n";
  cout << "-a,--acl netmask      Add this netmask to the ACL\n";
  cout << "-C,--config file      Load configuration from 'file'\n";
  cout << "-c,--client           Operate as a client, connect to dnsdist. This reads\n";
  cout << "                      controlSocket from your configuration file, but also\n";
  cout << "                      accepts an IP:PORT argument\n";
#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO)
  cout << "-k,--setkey KEY       Use KEY for encrypted communication to dnsdist. This\n";
  cout << "                      is similar to setting setKey in the configuration file.\n";
  cout << "                      NOTE: this will leak this key in your shell's history\n";
  cout << "                      and in the systems running process list.\n";
#endif
  cout << "--check-config        Validate the configuration file and exit. The exit-code\n";
  cout << "                      reflects the validation, 0 is OK, 1 means an error.\n";
  cout << "                      Any errors are printed as well.\n";
  cout << "-e,--execute cmd      Connect to dnsdist and execute 'cmd'\n";
  cout << "-g,--gid gid          Change the process group ID after binding sockets\n";
  cout << "-h,--help             Display this helpful message\n";
  cout << "-l,--local address    Listen on this local address\n";
  cout << "--supervised          Don't open a console, I'm supervised\n";
  cout << "                        (use with e.g. systemd and daemontools)\n";
  cout << "--disable-syslog      Don't log to syslog, only to stdout\n";
  cout << "                        (use with e.g. systemd)\n";
  cout << "--log-timestamps      Prepend timestamps to messages logged to stdout.\n";
  cout << "-u,--uid uid          Change the process user ID after binding sockets\n";
  cout << "-v,--verbose          Enable verbose mode\n";
  cout << "-V,--version          Show dnsdist version information and exit\n";
}

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

#if defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE)
#include <sanitizer/lsan_interface.h>
#endif

#if defined(COVERAGE) || (defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE))
static void cleanupLuaObjects(LuaContext& /* luaCtx */)
{
  dnsdist::lua::hooks::clearExitCallbacks();
  /* when our coverage mode is enabled, we need to make sure
     that the Lua objects are destroyed before the Lua contexts. */
  dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
    config.d_ruleChains = dnsdist::rules::RuleChains();
    config.d_lbPolicy = std::make_shared<ServerPolicy>();
    config.d_pools.clear();
    config.d_backends.clear();
  });
  dnsdist::webserver::clearWebHandlers();
  dnsdist::lua::hooks::clearMaintenanceHooks();
  dnsdist::lua::hooks::clearServerStateChangeCallbacks();
}
#endif /* defined(COVERAGE) || (defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE)) */

void doExitNicely(int exitCode)
{
  if (s_exiting) {
    if (dnsdist::logging::LoggingConfiguration::getSyslog()) {
      syslog(LOG_INFO, "Exiting on user request");
    }
    std::cout << "Exiting on user request" << std::endl;
  }

#ifdef HAVE_SYSTEMD
  sd_notify(0, "STOPPING=1");
#endif /* HAVE_SYSTEMD */

#if defined(COVERAGE) || (defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE))
  if (dnsdist::g_asyncHolder) {
    dnsdist::g_asyncHolder->stop();
  }

  for (auto& backend : dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends) {
    backend->stop();
  }
#endif

  {
    auto lock = g_lua.lock();
    dnsdist::lua::hooks::runExitCallbacks(*lock);
#if defined(COVERAGE) || (defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE))
    cleanupLuaObjects(*lock);
    *lock = LuaContext();
#endif
  }

#if defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE)
  __lsan_do_leak_check();
#endif /* __SANITIZE_ADDRESS__ && HAVE_LEAK_SANITIZER_INTERFACE */

#ifdef COVERAGE
  pdns::coverage::dumpCoverageData();
#endif

  /* do not call destructors, because we have some
     dependencies between objects that are not trivial
     to solve.
  */
  _exit(exitCode);
}

static void sigTermHandler(int /* sig */)
{
  s_exiting.store(true);
}

static void reportFeatures()
{
#ifdef LUAJIT_VERSION
  cout << "dnsdist " << VERSION << " (" << LUA_RELEASE << " [" << LUAJIT_VERSION << "])" << endl;
#else
  cout << "dnsdist " << VERSION << " (" << LUA_RELEASE << ")" << endl;
#endif
  cout << "Enabled features: ";
#ifdef HAVE_XSK
  cout << "AF_XDP ";
#endif
#ifdef HAVE_CDB
  cout << "cdb ";
#endif
#ifdef HAVE_DNS_OVER_QUIC
  cout << "dns-over-quic ";
#endif
#ifdef HAVE_DNS_OVER_HTTP3
  cout << "dns-over-http3 ";
#endif
#ifdef HAVE_DNS_OVER_TLS
  cout << "dns-over-tls(";
#ifdef HAVE_GNUTLS
  cout << "gnutls";
#ifdef HAVE_LIBSSL
  cout << " ";
#endif
#endif /* HAVE_GNUTLS */
#ifdef HAVE_LIBSSL
  cout << "openssl";
#endif
  cout << ") ";
#endif /* HAVE_DNS_OVER_TLS */
#ifdef HAVE_DNS_OVER_HTTPS
  cout << "dns-over-https(";
#ifdef HAVE_LIBH2OEVLOOP
  cout << "h2o";
#endif /* HAVE_LIBH2OEVLOOP */
#if defined(HAVE_LIBH2OEVLOOP) && defined(HAVE_NGHTTP2)
  cout << " ";
#endif /* defined(HAVE_LIBH2OEVLOOP) && defined(HAVE_NGHTTP2) */
#ifdef HAVE_NGHTTP2
  cout << "nghttp2";
#endif /* HAVE_NGHTTP2 */
  cout << ") ";
#endif /* HAVE_DNS_OVER_HTTPS */
#ifdef HAVE_DNSCRYPT
  cout << "dnscrypt ";
#endif
#ifdef HAVE_EBPF
  cout << "ebpf ";
#endif
#ifdef HAVE_FSTRM
  cout << "fstrm ";
#endif
#ifdef HAVE_IPCIPHER
  cout << "ipcipher ";
#endif
#ifdef HAVE_LIBEDIT
  cout << "libedit ";
#endif
#ifdef HAVE_LIBSODIUM
  cout << "libsodium ";
#endif
#ifdef HAVE_LMDB
  cout << "lmdb ";
#endif
#ifndef DISABLE_PROTOBUF
  cout << "protobuf ";
#endif
#ifdef HAVE_RE2
  cout << "re2 ";
#endif
#ifndef DISABLE_RECVMMSG
#if defined(HAVE_RECVMMSG) && defined(HAVE_SENDMMSG) && defined(MSG_WAITFORONE)
  cout << "recvmmsg/sendmmsg ";
#endif
#endif /* DISABLE_RECVMMSG */
#ifdef HAVE_NET_SNMP
  cout << "snmp ";
#endif
#ifdef HAVE_SYSTEMD
  cout << "systemd ";
#endif
#ifdef HAVE_YAML_CONFIGURATION
  cout << "yaml ";
#endif
  cout << endl;
// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#ifdef DNSDIST_CONFIG_ARGS
#define double_escape(s) #s
#define escape_quotes(s) double_escape(s)
  // NOLINTEND(cppcoreguidelines-macro-usage)
  cout << "Configured with: " << escape_quotes(DNSDIST_CONFIG_ARGS) << endl;
#undef escape_quotes
#undef double_escape
#endif
}

static void parseParameters(int argc, char** argv, CommandLineParameters& cmdLine, ComboAddress& clientAddress)
{
  const std::array<struct option, 16> longopts{{{"acl", required_argument, nullptr, 'a'},
                                                {"check-config", no_argument, nullptr, 1},
                                                {"client", no_argument, nullptr, 'c'},
                                                {"config", required_argument, nullptr, 'C'},
                                                {"disable-syslog", no_argument, nullptr, 2},
                                                {"execute", required_argument, nullptr, 'e'},
                                                {"gid", required_argument, nullptr, 'g'},
                                                {"help", no_argument, nullptr, 'h'},
                                                {"local", required_argument, nullptr, 'l'},
                                                {"log-timestamps", no_argument, nullptr, 4},
                                                {"setkey", required_argument, nullptr, 'k'},
                                                {"supervised", no_argument, nullptr, 3},
                                                {"uid", required_argument, nullptr, 'u'},
                                                {"verbose", no_argument, nullptr, 'v'},
                                                {"version", no_argument, nullptr, 'V'},
                                                {nullptr, 0, nullptr, 0}}};
  int longindex = 0;
  string optstring;
  dnsdist::configuration::RuntimeConfiguration newConfig;

  while (true) {
    // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
    int gotChar = getopt_long(argc, argv, "a:cC:e:g:hk:l:u:vV", longopts.data(), &longindex);
    if (gotChar == -1) {
      break;
    }
    switch (gotChar) {
    case 1:
      cmdLine.checkConfig = true;
      break;
    case 2:
      dnsdist::logging::LoggingConfiguration::setSyslog(false);
      break;
    case 3:
      cmdLine.beSupervised = true;
      break;
    case 4:
      dnsdist::logging::LoggingConfiguration::setLogTimestamps(true);
      break;
    case 'C':
      cmdLine.config = optarg;
      break;
    case 'c':
      cmdLine.beClient = true;
      break;
    case 'e':
      cmdLine.command = optarg;
      break;
    case 'g':
      cmdLine.gid = optarg;
      break;
    case 'h':
      cout << "dnsdist " << VERSION << endl;
      usage();
      cout << "\n";
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      exit(EXIT_SUCCESS);
      break;
    case 'a':
      optstring = optarg;
      newConfig.d_ACL.addMask(optstring);
      break;
    case 'k':
#if defined HAVE_LIBSODIUM || defined(HAVE_LIBCRYPTO)
    {
      std::string consoleKey;
      if (B64Decode(string(optarg), consoleKey) < 0) {
        cerr << "Unable to decode key '" << optarg << "'." << endl;
        // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
        exit(EXIT_FAILURE);
      }
      dnsdist::configuration::updateRuntimeConfiguration([&consoleKey](dnsdist::configuration::RuntimeConfiguration& config) {
        config.d_consoleKey = std::move(consoleKey);
      });
    }
#else
      cerr << "dnsdist has been built without libsodium or libcrypto, -k/--setkey is unsupported." << endl;
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      exit(EXIT_FAILURE);
#endif
    break;
    case 'l':
      cmdLine.locals.push_back(boost::trim_copy(string(optarg)));
      break;
    case 'u':
      cmdLine.uid = optarg;
      break;
    case 'v':
      newConfig.d_verbose = true;
      break;
    case 'V':
      reportFeatures();
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      exit(EXIT_SUCCESS);
      break;
    case '?':
      // getopt_long printed an error message.
      usage();
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only one thread at this point
      exit(EXIT_FAILURE);
      break;
    }
  }

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): argv
  argv += optind;

  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic): argv
  for (const auto* ptr = argv; *ptr != nullptr; ++ptr) {
    if (cmdLine.beClient) {
      clientAddress = ComboAddress(*ptr, 5199);
    }
    else {
      cmdLine.remotes.emplace_back(*ptr);
    }
  }

  dnsdist::configuration::updateRuntimeConfiguration([&newConfig](dnsdist::configuration::RuntimeConfiguration& config) {
    config = std::move(newConfig);
  });
}
static void setupPools()
{
  bool precompute = false;
  const auto& currentConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
  if (currentConfig.d_lbPolicy->getName() == "chashed") {
    precompute = true;
  }
  else {
    for (const auto& entry : currentConfig.d_pools) {
      if (entry.second->policy != nullptr && entry.second->policy->getName() == "chashed") {
        precompute = true;
        break;
      }
    }
  }
  if (precompute) {
    vinfolog("Pre-computing hashes for consistent hash load-balancing policy");
    // pre compute hashes
    for (const auto& backend : currentConfig.d_backends) {
      if (backend->d_config.d_weight < 100) {
        vinfolog("Warning, the backend '%s' has a very low weight (%d), which will not yield a good distribution of queries with the 'chashed' policy. Please consider raising it to at least '100'.", backend->getName(), backend->d_config.d_weight);
      }

      backend->hash();
    }
  }
}

static void dropPrivileges(const CommandLineParameters& cmdLine)
{
  uid_t newgid = getegid();
  gid_t newuid = geteuid();

  if (!cmdLine.gid.empty()) {
    newgid = strToGID(cmdLine.gid);
  }

  if (!cmdLine.uid.empty()) {
    newuid = strToUID(cmdLine.uid);
  }

  bool retainedCapabilities = true;
  if (!dnsdist::configuration::getImmutableConfiguration().d_capabilitiesToRetain.empty() && (getegid() != newgid || geteuid() != newuid)) {
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
    dropCapabilities(dnsdist::configuration::getImmutableConfiguration().d_capabilitiesToRetain);
  }
  catch (const std::exception& e) {
    warnlog("%s", e.what());
  }
}

static void initFrontends(const CommandLineParameters& cmdLine)
{
  auto frontends = dnsdist::configuration::getImmutableConfiguration().d_frontends;

  if (!cmdLine.locals.empty()) {
    for (auto it = frontends.begin(); it != frontends.end();) {
      /* DoH, DoT and DNSCrypt frontends are separate */
      if ((*it)->dohFrontend == nullptr && (*it)->tlsFrontend == nullptr && (*it)->dnscryptCtx == nullptr && (*it)->doqFrontend == nullptr && (*it)->doh3Frontend == nullptr) {
        it = frontends.erase(it);
      }
      else {
        ++it;
      }
    }

    for (const auto& loc : cmdLine.locals) {
      /* UDP */
      frontends.emplace_back(std::make_unique<ClientState>(ComboAddress(loc, 53), false, false, 0, "", std::set<int>{}, true));
      /* TCP */
      frontends.emplace_back(std::make_unique<ClientState>(ComboAddress(loc, 53), true, false, 0, "", std::set<int>{}, true));
    }
  }

  if (frontends.empty()) {
    /* UDP */
    frontends.emplace_back(std::make_unique<ClientState>(ComboAddress("127.0.0.1", 53), false, false, 0, "", std::set<int>{}, true));
    /* TCP */
    frontends.emplace_back(std::make_unique<ClientState>(ComboAddress("127.0.0.1", 53), true, false, 0, "", std::set<int>{}, true));
  }

  dnsdist::configuration::updateImmutableConfiguration([&frontends](dnsdist::configuration::ImmutableConfiguration& config) {
    config.d_frontends = std::move(frontends);
  });
}

namespace dnsdist
{
static void startFrontends()
{
#ifdef HAVE_XSK
  for (auto& xskContext : dnsdist::xsk::g_xsk) {
    std::thread xskThread(dnsdist::xsk::XskRouter, std::move(xskContext));
    xskThread.detach();
  }
#endif /* HAVE_XSK */

  std::vector<ClientState*> tcpStates;
  std::vector<ClientState*> udpStates;
  for (const auto& clientState : dnsdist::getFrontends()) {
#ifdef HAVE_XSK
    if (clientState->xskInfo) {
      dnsdist::xsk::addDestinationAddress(clientState->local);

      std::thread xskCT(dnsdist::xsk::XskClientThread, clientState.get());
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(xskCT.native_handle(), clientState->cpus);
      }
      xskCT.detach();
    }
#endif /* HAVE_XSK */

    if (clientState->dohFrontend != nullptr && clientState->dohFrontend->d_library == "h2o") {
#ifdef HAVE_DNS_OVER_HTTPS
#ifdef HAVE_LIBH2OEVLOOP
      std::thread dohThreadHandle(dohThread, clientState.get());
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(dohThreadHandle.native_handle(), clientState->cpus);
      }
      dohThreadHandle.detach();
#endif /* HAVE_LIBH2OEVLOOP */
#endif /* HAVE_DNS_OVER_HTTPS */
      continue;
    }
    if (clientState->doqFrontend != nullptr) {
#ifdef HAVE_DNS_OVER_QUIC
      std::thread doqThreadHandle(doqThread, clientState.get());
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(doqThreadHandle.native_handle(), clientState->cpus);
      }
      doqThreadHandle.detach();
#endif /* HAVE_DNS_OVER_QUIC */
      continue;
    }
    if (clientState->doh3Frontend != nullptr) {
#ifdef HAVE_DNS_OVER_HTTP3
      std::thread doh3ThreadHandle(doh3Thread, clientState.get());
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(doh3ThreadHandle.native_handle(), clientState->cpus);
      }
      doh3ThreadHandle.detach();
#endif /* HAVE_DNS_OVER_HTTP3 */
      continue;
    }
    if (clientState->udpFD >= 0) {
#ifdef USE_SINGLE_ACCEPTOR_THREAD
      udpStates.push_back(clientState.get());
#else /* USE_SINGLE_ACCEPTOR_THREAD */
      std::thread udpClientThreadHandle(udpClientThread, std::vector<ClientState*>{clientState.get()});
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(udpClientThreadHandle.native_handle(), clientState->cpus);
      }
      udpClientThreadHandle.detach();
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
    }
    else if (clientState->tcpFD >= 0) {
#ifdef USE_SINGLE_ACCEPTOR_THREAD
      tcpStates.push_back(clientState.get());
#else /* USE_SINGLE_ACCEPTOR_THREAD */
      std::thread tcpAcceptorThreadHandle(tcpAcceptorThread, std::vector<ClientState*>{clientState.get()});
      if (!clientState->cpus.empty()) {
        mapThreadToCPUList(tcpAcceptorThreadHandle.native_handle(), clientState->cpus);
      }
      tcpAcceptorThreadHandle.detach();
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
    }
  }
#ifdef USE_SINGLE_ACCEPTOR_THREAD
  if (!udpStates.empty()) {
    std::thread udpThreadHandle(udpClientThread, udpStates);
    udpThreadHandle.detach();
  }
  if (!tcpStates.empty()) {
    g_tcpclientthreads = std::make_unique<TCPClientCollection>(1, tcpStates);
  }
#endif /* USE_SINGLE_ACCEPTOR_THREAD */
}
}

struct ListeningSockets
{
  Socket d_consoleSocket{-1};
  std::vector<std::pair<ComboAddress, Socket>> d_webServerSockets;
};

static ListeningSockets initListeningSockets()
{
  ListeningSockets result;
  const auto& currentConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();

  if (currentConfig.d_consoleEnabled) {
    const auto& local = currentConfig.d_consoleServerAddress;
    try {
      result.d_consoleSocket = Socket(local.sin4.sin_family, SOCK_STREAM, 0);
      result.d_consoleSocket.bind(local, true);
      result.d_consoleSocket.listen(5);
    }
    catch (const std::exception& exp) {
      errlog("Unable to bind to control socket on %s: %s", local.toStringWithPort(), exp.what());
    }
  }

  for (const auto& local : currentConfig.d_webServerAddresses) {
    try {
      auto webServerSocket = Socket(local.sin4.sin_family, SOCK_STREAM, 0);
      webServerSocket.bind(local, true);
      webServerSocket.listen(5);
      result.d_webServerSockets.emplace_back(local, std::move(webServerSocket));
    }
    catch (const std::exception& exp) {
      errlog("Unable to bind to web server socket on %s: %s", local.toStringWithPort(), exp.what());
    }
  }

  return result;
}

static std::optional<std::string> lookForTentativeConfigurationFileWithExtension(const std::string& configurationFile, const std::string& extension)
{
  auto dotPos = configurationFile.rfind('.');
  if (dotPos == std::string::npos) {
    return std::nullopt;
  }
  auto tentativeFile = configurationFile.substr(0, dotPos + 1) + extension;
  if (!std::filesystem::exists(tentativeFile)) {
    return std::nullopt;
  }
  return tentativeFile;
}

static bool loadConfigurationFromFile(const std::string& configurationFile, bool isClient, bool configCheck)
{
  if (boost::ends_with(configurationFile, ".yml")) {
    // the bindings are always needed, for example for inline Lua
    dnsdist::lua::setupLuaBindingsOnly(*(g_lua.lock()), isClient, configCheck);

    if (auto tentativeLuaConfFile = lookForTentativeConfigurationFileWithExtension(configurationFile, "lua")) {
      vinfolog("Loading configuration from auto-discovered Lua file %s", *tentativeLuaConfFile);
      dnsdist::configuration::lua::loadLuaConfigurationFile(*(g_lua.lock()), *tentativeLuaConfFile, configCheck);
    }
    vinfolog("Loading configuration from YAML file %s", configurationFile);
    if (!dnsdist::configuration::yaml::loadConfigurationFromFile(configurationFile, isClient, configCheck)) {
      return false;
    }
    if (!isClient && !configCheck) {
      dnsdist::lua::setupLuaConfigurationOptions(*(g_lua.lock()), false, false);
    }
    return true;
  }

  dnsdist::lua::setupLua(*(g_lua.lock()), isClient, configCheck);
  if (boost::ends_with(configurationFile, ".lua")) {
    vinfolog("Loading configuration from Lua file %s", configurationFile);
    dnsdist::configuration::lua::loadLuaConfigurationFile(*(g_lua.lock()), configurationFile, configCheck);
    if (auto tentativeYamlConfFile = lookForTentativeConfigurationFileWithExtension(configurationFile, "yml")) {
      vinfolog("Loading configuration from auto-discovered YAML file %s", *tentativeYamlConfFile);
      return dnsdist::configuration::yaml::loadConfigurationFromFile(*tentativeYamlConfFile, isClient, configCheck);
    }
  }
  else {
    vinfolog("Loading configuration from Lua file %s", configurationFile);
    dnsdist::configuration::lua::loadLuaConfigurationFile(*(g_lua.lock()), configurationFile, configCheck);
  }
  return true;
}

int main(int argc, char** argv)
{
  try {
    CommandLineParameters cmdLine{};
    size_t udpBindsCount = 0;
    size_t tcpBindsCount = 0;

    dnsdist::console::completion::setupCompletion();

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast): SIG_IGN macro
    signal(SIGPIPE, SIG_IGN);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast): SIG_IGN macro
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, sigTermHandler);

    openlog("dnsdist", LOG_PID | LOG_NDELAY, LOG_DAEMON);

#ifdef HAVE_LIBSODIUM
    if (sodium_init() == -1) {
      cerr << "Unable to initialize crypto library" << endl;
      // NOLINTNEXTLINE(concurrency-mt-unsafe): only on thread at this point
      exit(EXIT_FAILURE);
    }
#endif
    dnsdist::initRandom();
    dnsdist::configuration::updateImmutableConfiguration([](dnsdist::configuration::ImmutableConfiguration& config) {
      config.d_hashPerturbation = dnsdist::getRandomValue(0xffffffff);
    });

#ifdef HAVE_XSK
    try {
      dnsdist::xsk::clearDestinationAddresses();
    }
    catch (const std::exception& exp) {
      /* silently handle failures: at this point we don't even know if XSK is enabled,
         and we might not have the correct map (not the default one). */
    }
#endif /* HAVE_XSK */

    ComboAddress clientAddress = ComboAddress();
    cmdLine.config = SYSCONFDIR "/dnsdist.conf";

    parseParameters(argc, argv, cmdLine, clientAddress);

    dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
      config.d_lbPolicy = std::make_shared<ServerPolicy>("leastOutstanding", leastOutstanding, false);
    });

    if (cmdLine.beClient || !cmdLine.command.empty()) {
      if (!loadConfigurationFromFile(cmdLine.config, true, false)) {
#ifdef COVERAGE
        exit(EXIT_FAILURE);
#else
        _exit(EXIT_FAILURE);
#endif
      }
      if (clientAddress != ComboAddress()) {
        dnsdist::configuration::updateRuntimeConfiguration([&clientAddress](dnsdist::configuration::RuntimeConfiguration& config) {
          config.d_consoleServerAddress = clientAddress;
        });
      }
      dnsdist::console::doClient(cmdLine.command);
#ifdef COVERAGE
      exit(EXIT_SUCCESS);
#else
      _exit(EXIT_SUCCESS);
#endif
    }

    dnsdist::configuration::updateRuntimeConfiguration([](dnsdist::configuration::RuntimeConfiguration& config) {
      auto& acl = config.d_ACL;
      if (acl.empty()) {
        for (const auto& addr : {"127.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.168.0.0/16", "172.16.0.0/12", "::1/128", "fc00::/7", "fe80::/10"}) {
          acl.addMask(addr);
        }
      }
      for (const auto& mask : {"127.0.0.1/8", "::1/128"}) {
        config.d_consoleACL.addMask(mask);
      }
      config.d_webServerACL.toMasks("127.0.0.1, ::1");
    });

    dnsdist::webserver::registerBuiltInWebHandlers();

    if (cmdLine.checkConfig) {
      if (!loadConfigurationFromFile(cmdLine.config, false, true)) {
#ifdef COVERAGE
        exit(EXIT_FAILURE);
#else
        _exit(EXIT_FAILURE);
#endif
      }
      // No exception was thrown
      infolog("Configuration '%s' OK!", cmdLine.config);
      doExitNicely();
    }

    infolog("dnsdist %s comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome to redistribute it according to the terms of the GPL version 2", VERSION);

    dnsdist::g_asyncHolder = std::make_unique<dnsdist::AsynchronousHolder>();

    /* create the default pool no matter what */
    createPoolIfNotExists("");

    if (!loadConfigurationFromFile(cmdLine.config, false, false)) {
#ifdef COVERAGE
      exit(EXIT_FAILURE);
#else
      _exit(EXIT_FAILURE);
#endif
    }

    setupPools();

    initFrontends(cmdLine);

    for (const auto& frontend : dnsdist::getFrontends()) {
      if (!frontend->tcp) {
        ++udpBindsCount;
      }
      else {
        ++tcpBindsCount;
      }
    }

    dnsdist::configuration::setImmutableConfigurationDone();

    {
      const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
      setTCPDownstreamMaxIdleConnectionsPerBackend(immutableConfig.d_outgoingTCPMaxIdlePerBackend);
      setTCPDownstreamMaxIdleTime(immutableConfig.d_outgoingTCPMaxIdleTime);
      setTCPDownstreamCleanupInterval(immutableConfig.d_outgoingTCPCleanupInterval);
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
      setDoHDownstreamMaxIdleConnectionsPerBackend(immutableConfig.d_outgoingDoHMaxIdlePerBackend);
      setDoHDownstreamMaxIdleTime(immutableConfig.d_outgoingDoHMaxIdleTime);
      setDoHDownstreamCleanupInterval(immutableConfig.d_outgoingDoHCleanupInterval);
#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
    }

    {
      const auto& config = dnsdist::configuration::getImmutableConfiguration();
      g_rings.init(config.d_ringsCapacity, config.d_ringsNumberOfShards, config.d_ringsNbLockTries, config.d_ringsRecordQueries, config.d_ringsRecordResponses);
    }

    for (const auto& frontend : dnsdist::getFrontends()) {
      setUpLocalBind(*frontend);
    }

    {
      std::string acls;
      auto aclEntries = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ACL.toStringVector();
      for (const auto& aclEntry : aclEntries) {
        if (!acls.empty()) {
          acls += ", ";
        }
        acls += aclEntry;
      }
      infolog("ACL allowing queries from: %s", acls);
    }
    {
      std::string acls;
      auto aclEntries = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleACL.toStringVector();
      for (const auto& entry : aclEntries) {
        if (!acls.empty()) {
          acls += ", ";
        }
        acls += entry;
      }
      infolog("Console ACL allowing connections from: %s", acls.c_str());
    }

    auto listeningSockets = initListeningSockets();

#if defined(HAVE_LIBSODIUM) || defined(HAVE_LIBCRYPTO)
    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleEnabled && dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey.empty()) {
      warnlog("Warning, the console has been enabled via 'controlSocket()' but no key has been set with 'setKey()' so all connections will fail until a key has been set");
    }
#endif

    dropPrivileges(cmdLine);

    /* this need to be done _after_ dropping privileges */
#ifndef DISABLE_DELAY_PIPE
    g_delay = std::make_unique<DelayPipe<DelayedPacket>>();
#endif /* DISABLE_DELAY_PIPE */

#if defined(HAVE_NET_SNMP)
    if (dnsdist::configuration::getImmutableConfiguration().d_snmpEnabled) {
      g_snmpAgent = std::make_unique<DNSDistSNMPAgent>("dnsdist", dnsdist::configuration::getImmutableConfiguration().d_snmpDaemonSocketPath);
      g_snmpAgent->run();
    }
#endif /* HAVE_NET_SNMP */

    /* we need to create the TCP worker threads before the
       acceptor ones, otherwise we might crash when processing
       the first TCP query */
#ifndef USE_SINGLE_ACCEPTOR_THREAD
    const auto maxTCPClientThreads = dnsdist::configuration::getImmutableConfiguration().d_maxTCPClientThreads;
    /* the limit is completely arbitrary: hopefully high enough not to trigger too many false positives
       but low enough to be useful */
    if (maxTCPClientThreads >= 50U) {
      warnlog("setMaxTCPClientThreads(%d) might create a large number of TCP connections to backends, and is probably not needed, please consider lowering it", maxTCPClientThreads);
    }
    g_tcpclientthreads = std::make_unique<TCPClientCollection>(maxTCPClientThreads, std::vector<ClientState*>());
#endif

#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    initDoHWorkers();
#endif

    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleEnabled) {
      std::thread consoleControlThread(dnsdist::console::controlThread, std::move(listeningSockets.d_consoleSocket));
      consoleControlThread.detach();
    }
    for (auto& [listeningAddress, socket] : listeningSockets.d_webServerSockets) {
      std::thread webServerThread(dnsdist::webserver::WebserverThread, listeningAddress, std::move(socket));
      webServerThread.detach();
    }

    for (const auto& backend : dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends) {
      if (backend->connected) {
        backend->start();
      }
    }

    if (!cmdLine.remotes.empty()) {
      for (const auto& address : cmdLine.remotes) {
        DownstreamState::Config config;
        config.remote = ComboAddress(address, 53);
        auto ret = std::make_shared<DownstreamState>(std::move(config), nullptr, true);
        addServerToPool("", ret);
        ret->start();
        dnsdist::configuration::updateRuntimeConfiguration([&ret](dnsdist::configuration::RuntimeConfiguration& runtimeConfig) {
          runtimeConfig.d_backends.push_back(std::move(ret));
        });
      }
    }

    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends.empty()) {
      errlog("No downstream servers defined: all packets will get dropped");
      // you might define them later, but you need to know
    }

    checkFileDescriptorsLimits(udpBindsCount, tcpBindsCount);

    {
      // coverity[auto_causes_copy]
      const auto states = dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends; // it is a copy, but the internal shared_ptrs are the real deal
      auto mplexer = std::unique_ptr<FDMultiplexer>(FDMultiplexer::getMultiplexerSilent(states.size()));
      for (auto& dss : states) {

        if (dss->d_config.d_availability == DownstreamState::Availability::Auto) {
          if (dss->d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active) {
            dss->d_nextCheck = dss->d_config.checkInterval;
          }

          if (!queueHealthCheck(mplexer, dss, true)) {
            dss->submitHealthCheckResult(true, false);
            dss->setUpStatus(false);
            warnlog("Marking downstream %s as 'down'", dss->getNameWithAddr());
          }
        }
      }
      handleQueuedHealthChecks(*mplexer, true);
    }

    dnsdist::startFrontends();

    dnsdist::ServiceDiscovery::run();

#ifndef DISABLE_CARBON
    dnsdist::Carbon::run(dnsdist::configuration::getCurrentRuntimeConfiguration().d_carbonEndpoints);
#endif /* DISABLE_CARBON */

    thread stattid(maintThread);
    stattid.detach();

    thread healththread(healthChecksThread);

#ifndef DISABLE_DYNBLOCKS
    thread dynBlockMaintThread(dynBlockMaintenanceThread);
    dynBlockMaintThread.detach();
#endif /* DISABLE_DYNBLOCKS */

#ifndef DISABLE_SECPOLL
    if (!dnsdist::configuration::getCurrentRuntimeConfiguration().d_secPollSuffix.empty()) {
      thread secpollthread(secPollThread);
      secpollthread.detach();
    }
#endif /* DISABLE_SECPOLL */

    if (cmdLine.beSupervised) {
#ifdef HAVE_SYSTEMD
      sd_notify(0, "READY=1");
#endif
      healththread.join();
    }
    else {
      healththread.detach();
      dnsdist::console::doConsole();
    }
    doExitNicely();
  }
  catch (const LuaContext::ExecutionErrorException& e) {
    try {
      errlog("Fatal Lua error: %s", e.what());
      std::rethrow_if_nested(e);
    }
    catch (const std::exception& ne) {
      errlog("Details: %s", ne.what());
    }
    catch (const PDNSException& ae) {
      errlog("Fatal pdns error: %s", ae.reason);
    }
    doExitNicely(EXIT_FAILURE);
  }
  catch (const std::exception& e) {
    errlog("Fatal error: %s", e.what());
    doExitNicely(EXIT_FAILURE);
  }
  catch (const PDNSException& ae) {
    errlog("Fatal pdns error: %s", ae.reason);
    doExitNicely(EXIT_FAILURE);
  }
}
