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
#include "dnsdist-cache.hh"
#include "dnsdist-delay-pipe.hh"
#include "dnsdist-dnscrypt.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-metrics.hh"
#include "dnsdist-nghttp2-in.hh"
#include "dnsdist-proxy-protocol.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-self-answers.hh"
#include "dnsdist-tcp-upstream.hh"
#include "dnsdist-udp.hh"

#ifndef DISABLE_DELAY_PIPE
namespace dnsdist::delay_pipe
{
std::unique_ptr<DelayPipe<DelayedPacket>> g_delay{nullptr};
}
#endif /* DISABLE_DELAY_PIPE */

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
      VERBOSESLOG(infolog("Backend %s sent us a response with id %d that did not parse: %s", remote->d_config.remote.toStringWithPort(), ntohs(dnsHeader->id), e.what()),
                  dnsdist::logging::getTopLogger("udp-response-worker")->error(Logr::Info, e.what(), "Received a DNS response from a backend that we could not parse", "backend.address", Logging::Loggable(remote->d_config.remote), "dns.query.id", Logging::Loggable(ntohs(dnsHeader->id))));
    }
    ++dnsdist::metrics::g_stats.nonCompliantResponses;
    if (remote) {
      ++remote->nonCompliantResponses;
    }
    return false;
  }
}

static bool fixUpQueryTurnedResponse(DNSQuestion& dnsQuestion, const uint16_t origFlags)
{
  dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [origFlags](dnsheader& header) {
    dnsdist::PacketMangling::restoreFlags(&header, origFlags);
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
    dnsdist::PacketMangling::restoreFlags(&header, origFlags);
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
            SLOG(warnlog("Error rewriting content"),
                 dnsdist::logging::getTopLogger("fixup-response")->info(Logr::Error, "Error rewriting response content", "dns.question.name", Logging::Loggable(qname)));
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
            SLOG(warnlog("Error rewriting content"),
                 dnsdist::logging::getTopLogger("fixup-response")->info(Logr::Error, "Error rewriting response content", "dns.question.name", Logging::Loggable(qname)));
          }
        }
      }
    }
  }

  return true;
}

bool applyRulesToResponse(const std::vector<dnsdist::rules::ResponseRuleAction>& respRuleActions, DNSResponse& dnsResponse)
{
  auto closer = dnsResponse.ids.getCloser(__func__); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  if (respRuleActions.empty()) {
    return true;
  }

  DNSResponseAction::Action action = DNSResponseAction::Action::None;
  std::string ruleresult;
  static const std::string ruleType = "Response";

  for (const auto& rrule : respRuleActions) {
    auto ruleCloser = dnsResponse.ids.getRulesCloser(rrule.d_name, ruleType);
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
          dnsdist::udp::truncateTC(dnsResponse.getMutableData(), dnsResponse.getMaximumSize(), dnsResponse.ids.qname.wirelength(), dnsdist::configuration::getCurrentRuntimeConfiguration().d_addEDNSToSelfGeneratedResponses);
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
  auto closer = dnsResponse.ids.getCloser(__func__); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  bool zeroScope = false;
  if (!fixUpResponse(response, dnsResponse.ids.qname, dnsResponse.ids.origFlags, dnsResponse.ids.ednsAdded, dnsResponse.ids.ecsAdded, dnsResponse.ids.useZeroScope ? &zeroScope : nullptr)) {
    if (closer) {
      closer->setAttribute("result", AnyValue{"fixUpResponse->false"});
    }
    return false;
  }

  if (dnsResponse.ids.packetCache && !dnsResponse.ids.selfGenerated && !dnsResponse.ids.skipCache && (!dnsResponse.ids.forwardedOverUDP || response.size() <= dnsdist::udp::s_maxUDPResponsePacketSize)) {
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
      cacheKey = dnsResponse.ids.cacheKeyTCP;
      // disable zeroScope in that case, as we only have the "no-ECS" cache key for UDP
      zeroScope = false;
    }
    if (zeroScope) {
      // if zeroScope, pass the pre-ECS hash-key and do not pass the subnet to the cache
      cacheKey = dnsResponse.ids.cacheKeyNoECS;
    }
    {
      auto cacheInsertCloser = dnsResponse.ids.getCloser("packetCacheInsert"); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
      dnsResponse.ids.packetCache->insert(cacheKey, zeroScope ? std::nullopt : dnsResponse.ids.subnet, dnsResponse.ids.cacheFlags, dnsResponse.ids.dnssecOK ? *dnsResponse.ids.dnssecOK : false, dnsResponse.ids.qname, dnsResponse.ids.qtype, dnsResponse.ids.qclass, response, dnsResponse.ids.forwardedOverUDP, dnsResponse.getHeader()->rcode, dnsResponse.ids.tempFailureTTL);
    }
    const auto& chains = dnsdist::configuration::getCurrentRuntimeConfiguration().d_ruleChains;
    const auto& cacheInsertedRespRuleActions = dnsdist::rules::getResponseRuleChain(chains, dnsdist::rules::ResponseRuleChain::CacheInsertedResponseRules);
    if (!applyRulesToResponse(cacheInsertedRespRuleActions, dnsResponse)) {
      return false;
    }
  }

  if (dnsResponse.ids.ttlCap > 0) {
    dnsdist::PacketMangling::restrictDNSPacketTTLs(dnsResponse.getMutableData(), 0, dnsResponse.ids.ttlCap);
  }

  if (dnsResponse.ids.d_extendedErrors) {
    for (const auto& ede : *dnsResponse.ids.d_extendedErrors) {
      dnsdist::edns::addExtendedDNSError(dnsResponse.getMutableData(), dnsResponse.getMaximumSize(), ede);
    }
  }

  if (dnsResponse.ids.cs->d_padResponses && !dnsResponse.ids.ednsAdded) {
    dnsdist::edns::addEDNSPadding(dnsResponse.getMutableData(), dnsResponse.getMaximumSize());
  }

  if (!muted) {
    if (!dnsdist::dnscrypt::encryptResponse(response, dnsResponse.getMaximumSize(), dnsResponse.overTCP(), dnsResponse.ids.dnsCryptQuery)) {
      return false;
    }
  }

  return true;
}

bool processResponse(PacketBuffer& response, DNSResponse& dnsResponse, bool muted)
{
  // This is a new root span
  auto closer = dnsResponse.ids.getCloser(__func__); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

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

bool sendUDPResponse(int origFD, const PacketBuffer& response, [[maybe_unused]] const int delayMsec, const ComboAddress& origDest, const ComboAddress& origRemote)
{
#ifndef DISABLE_DELAY_PIPE
  if (delayMsec > 0 && dnsdist::delay_pipe::g_delay != nullptr) {
    dnsdist::delay_pipe::DelayedPacket delayed{origFD, response, origRemote, origDest};
    dnsdist::delay_pipe::g_delay->submit(delayed, delayMsec);
    return true;
  }
#endif /* DISABLE_DELAY_PIPE */
  // NOLINTNEXTLINE(readability-suspicious-call-argument)
  dnsdist::udp::sendfromto(origFD, response, origDest, origRemote);
  return true;
}

void handleResponseSent(InternalQueryState& ids, double latencyUs, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH, dnsdist::Protocol outgoingProtocol, bool fromBackend)
{
  handleResponseSent(std::move(ids.qname), ids.qtype, latencyUs, client, backend, size, cleartextDH, outgoingProtocol, ids.protocol, fromBackend);
}

void handleResponseSent(DNSName&& qname, const QType& qtype, double latencyUs, const ComboAddress& client, const ComboAddress& backend, unsigned int size, const dnsheader& cleartextDH, dnsdist::Protocol outgoingProtocol, dnsdist::Protocol incomingProtocol, bool fromBackend)
{
  if (g_rings.shouldRecordResponses()) {
    timespec now{};
    gettime(&now);
    g_rings.insertResponse(now, client, std::move(qname), qtype, static_cast<unsigned int>(latencyUs), size, cleartextDH, backend, outgoingProtocol);
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

  dnsdist::metrics::doLatencyStats(incomingProtocol, latencyUs);
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

  double latencyUs = ids.queryRealTime.udiff();
  // do that _before_ the processing, otherwise it's not fair to the backend
  dss->latencyUsec = (127.0 * dss->latencyUsec / 128.0) + latencyUs / 128.0;
  dss->reportResponse(dnsHeader->rcode);

  /* don't call processResponse for DOH */
  if (dohUnit) {
#ifdef HAVE_DNS_OVER_HTTPS
    // DoH query, we cannot touch dohUnit after that
    DOHUnitInterface::handleUDPResponse(std::move(dohUnit), std::move(response), std::move(ids), dss);
#endif
    return false;
  }

  dnsdist::udp::handleResponseForUDPClient(ids, response, dss, false, false);
  return true;
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

  auto closer = dnsQuestion.ids.getCloser(__func__); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
  static const std::string ruleType; // Empty string

  for (const auto& rule : rules) {
    auto ruleCloser = dnsQuestion.ids.getRulesCloser(rule.d_name, ruleType);

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
  InternalQueryState::rulesAppliedToQuerySetter tpprs(dnsQuestion.ids.rulesAppliedToQuery); // Ensure IDS knows we are past the rules processing when we exit this function
  auto closer = dnsQuestion.ids.getCloser(__func__); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
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
        VERBOSESLOG(infolog("Query from %s turned into NXDomain because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Query turned into NXDomain because of a dynamic rule"));
        updateBlockStats();

        setRCode(RCode::NXDomain);
        return true;

      case DNSAction::Action::Refused:
        VERBOSESLOG(infolog("Query from %s refused because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Query refused because of a dynamic rule"));
        updateBlockStats();

        setRCode(RCode::Refused);
        return true;

      case DNSAction::Action::Truncate:
        if (!dnsQuestion.overTCP()) {
          VERBOSESLOG(infolog("Query from %s truncated because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                      dnsQuestion.getLogger()->info(Logr::Info, "Query truncated because of a dynamic rule"));
          updateBlockStats();
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
          VERBOSESLOG(infolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.qname.toLogString()),
                      dnsQuestion.getLogger()->info(Logr::Info, "Query received over TCP *not* truncated because of a dynamic rule"));
        }
        break;
      case DNSAction::Action::NoRecurse:
        VERBOSESLOG(infolog("Query from %s setting rd=0 because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Setting RD=0 because of a dynamic rule"));
        updateBlockStats();
        dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
          header.rd = false;
          return true;
        });
        return true;
      case DNSAction::Action::SetTag: {
        if (!got->second.tagSettings) {
          VERBOSESLOG(infolog("Skipping set tag dynamic block for query from %s because of missing options", dnsQuestion.ids.origRemote.toStringWithPort()),
                      dnsQuestion.getLogger()->info(Logr::Info, "Skipping 'set tag' dynamic rule because of missing options"));
          break;
        }
        const auto& tagName = got->second.tagSettings->d_name;
        const auto& tagValue = got->second.tagSettings->d_value;
        VERBOSESLOG(infolog("Query from %s setting tag %s to %s because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), tagName, tagValue),
                    dnsQuestion.getLogger()->info(Logr::Info, "Setting tag on query because of a dynamic rule", "dnsdist.tag.name", Logging::Loggable(tagName), "dnsdist.tag.value", Logging::Loggable(tagValue)));
        updateBlockStats();
        dnsQuestion.setTag(tagName, tagValue);
        // do not return, the whole point it to set a Tag to be able to do further processing in rules
        break;
      }
      default:
        VERBOSESLOG(infolog("Query from %s dropped because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Query dropped because of a dynamic rule"));
        updateBlockStats();
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
        VERBOSESLOG(infolog("Query from %s turned into NXDomain because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Query turned into NXDomain because of a suffix-based dynamic rule"));
        updateBlockStats();

        setRCode(RCode::NXDomain);
        return true;
      case DNSAction::Action::Refused:
        VERBOSESLOG(infolog("Query from %s refused because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Query refused because of a suffix-based dynamic rule"));
        updateBlockStats();
        setRCode(RCode::Refused);
        return true;
      case DNSAction::Action::Truncate:
        if (!dnsQuestion.overTCP()) {
          VERBOSESLOG(infolog("Query from %s truncated because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                      dnsQuestion.getLogger()->info(Logr::Info, "Query truncated because of a suffix-based dynamic rule"));
          updateBlockStats();
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
          VERBOSESLOG(infolog("Query from %s for %s over TCP *not* truncated because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.qname.toLogString()),
                      dnsQuestion.getLogger()->info(Logr::Info, "Query received over TCP *not* truncated because of a dynamic rule"));
        }
        break;
      case DNSAction::Action::NoRecurse:
        VERBOSESLOG(infolog("Query from %s setting rd=0 because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Setting RD=0 because of a suffix-based dynamic rule"));
        updateBlockStats();
        dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [](dnsheader& header) {
          header.rd = false;
          return true;
        });
        return true;
      case DNSAction::Action::SetTag: {
        if (!got->tagSettings) {
          VERBOSESLOG(infolog("Skipping set tag dynamic block for query from %s because of missing options", dnsQuestion.ids.origRemote.toStringWithPort()),
                      dnsQuestion.getLogger()->info(Logr::Info, "Skipping 'set tag' suffix-based dynamic rule because of missing options"));
          break;
        }
        const auto& tagName = got->tagSettings->d_name;
        const auto& tagValue = got->tagSettings->d_value;
        VERBOSESLOG(infolog("Query from %s setting tag %s to %s because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort(), tagName, tagValue),
                    dnsQuestion.getLogger()->info(Logr::Info, "Setting tag on query because of a suffix-based dynamic rule", "dnsdist.tag.name", Logging::Loggable(tagName), "dnsdist.tag.value", Logging::Loggable(tagValue)));
        updateBlockStats();
        dnsQuestion.setTag(tagName, tagValue);
        // do not return, the whole point it to set a Tag to be able to do further processing in rules
        break;
      }
      default:
        updateBlockStats();
        VERBOSESLOG(infolog("Query from %s dropped because of dynamic block", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Query dropped because of a suffix-based dynamic rule"));
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
    VERBOSESLOG(infolog("Error sending request to backend %s: %s", backend->d_config.remote.toStringWithPort(), stringerror(savederrno)),
                dnsdist::logging::getTopLogger("udp-frontend")->error(Logr::Info, savederrno, "Error sending request to the backend", "backend.address", Logging::Loggable(backend->d_config.remote)));

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

bool checkQueryHeaders(const struct dnsheader& dnsHeader, ClientState& clientState)
{
  if (dnsHeader.qr) { // don't respond to responses
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    ++clientState.nonCompliantQueries;
    return false;
  }

  if (dnsHeader.tc != 0) { // don't respond to truncated queries
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

  if (dnsResponse.ids.d_extendedErrors) {
    for (const auto& ede : *dnsResponse.ids.d_extendedErrors) {
      dnsdist::edns::addExtendedDNSError(dnsResponse.getMutableData(), dnsResponse.getMaximumSize(), ede);
    }
  }

  if (dnsResponse.ids.cs->d_padResponses && !dnsResponse.ids.ednsAdded) {
    dnsdist::edns::addEDNSPadding(dnsResponse.getMutableData(), dnsResponse.getMaximumSize());
  }

  if (cacheHit) {
    ++dnsdist::metrics::g_stats.cacheHits;
  }

  if (dnsResponse.isAsynchronous()) {
    return false;
  }

  if (!clientState.muted) {
    if (!dnsdist::dnscrypt::encryptResponse(dnsQuestion.getMutableData(), dnsQuestion.getMaximumSize(), dnsQuestion.overTCP(), dnsQuestion.ids.dnsCryptQuery)) {
      return false;
    }
  }

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

static ServerPolicy::SelectedBackend selectBackendForOutgoingQuery(DNSQuestion& dnsQuestion, const ServerPool& serverPool)
{
  // Not exactly processQuery, but it works for now
  auto closer = dnsQuestion.ids.getCloser(__func__); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

  const auto& policy = serverPool.policy != nullptr ? *serverPool.policy : *dnsdist::configuration::getCurrentRuntimeConfiguration().d_lbPolicy;
  const auto& servers = serverPool.getServers();
  auto selectedBackend = policy.getSelectedBackend(servers, dnsQuestion);

  if (closer && selectedBackend) {
    closer->setAttribute("backend.name", AnyValue{selectedBackend->getNameWithAddr()});
    closer->setAttribute("backend.id", AnyValue{boost::uuids::to_string(selectedBackend->getID())});
  }

  return selectedBackend;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): refactoring will be done in https://github.com/PowerDNS/pdns/pull/16124
ProcessQueryResult processQueryAfterRules(DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& outgoingBackend)
{
  const auto sendAnswer = [](DNSQuestion& dnsQ) -> ProcessQueryResult {
    ++dnsdist::metrics::g_stats.responses;
    ++dnsQ.ids.cs->responses;
    return ProcessQueryResult::SendAnswer;
  };
  const uint16_t queryId = ntohs(dnsQuestion.getHeader()->id);

  try {
    if (dnsQuestion.getHeader()->qr) { // something turned it into a response
      return handleQueryTurnedIntoSelfAnsweredResponse(dnsQuestion);
    }
    bool backendLookupDone = false;
    const auto& serverPool = getPool(dnsQuestion.ids.poolName);
    ServerPolicy::SelectedBackend selectedBackend(serverPool.getServers());
    if (!serverPool.packetCache || !serverPool.isConsistent()) {
      selectedBackend = selectBackendForOutgoingQuery(dnsQuestion, serverPool);
      backendLookupDone = true;
    }

    bool willBeForwardedOverUDP = !dnsQuestion.overTCP() || dnsQuestion.ids.protocol == dnsdist::Protocol::DoH;
    if (selectedBackend) {
      if (selectedBackend->isTCPOnly()) {
        willBeForwardedOverUDP = false;
      }
    }
    else if (serverPool.isTCPOnly()) {
      willBeForwardedOverUDP = false;
    }

    uint32_t allowExpired = 0;
    if (!selectedBackend && dnsdist::configuration::getCurrentRuntimeConfiguration().d_staleCacheEntriesTTL > 0 && (backendLookupDone || !serverPool.hasAtLeastOneServerAvailable())) {
      allowExpired = dnsdist::configuration::getCurrentRuntimeConfiguration().d_staleCacheEntriesTTL;
    }

    if (serverPool.packetCache && !dnsQuestion.ids.skipCache && !dnsQuestion.ids.dnssecOK) {
      dnsQuestion.ids.dnssecOK = (dnsdist::getEDNSZ(dnsQuestion) & EDNS_HEADER_FLAG_DO) != 0;
    }

    const bool useECS = dnsQuestion.useECS && ((selectedBackend && selectedBackend->d_config.useECS) || (!selectedBackend && serverPool.getECS()));
    if (useECS) {
      const bool useZeroScope = (selectedBackend && !selectedBackend->d_config.disableZeroScope) || (!selectedBackend && serverPool.getZeroScope());
      // we special case our cache in case a downstream explicitly gave us a universally valid response with a 0 scope
      // we need ECS parsing (parseECS) to be true so we can be sure that the initial incoming query did not have an existing
      // ECS option, which would make it unsuitable for the zero-scope feature.
      if (serverPool.packetCache && !dnsQuestion.ids.skipCache && useZeroScope && serverPool.packetCache->isECSParsingEnabled()) {
        if (serverPool.packetCache->get(dnsQuestion, dnsQuestion.getHeader()->id, &dnsQuestion.ids.cacheKeyNoECS, dnsQuestion.ids.subnet, *dnsQuestion.ids.dnssecOK, willBeForwardedOverUDP, allowExpired, false, true, false)) {

          VERBOSESLOG(infolog("Packet cache hit for query for %s|%s from %s (%s, %d bytes)", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.protocol.toString(), dnsQuestion.getData().size()),
                      dnsQuestion.getLogger()->info(Logr::Info, "Packet cache hit"));

          if (!prepareOutgoingResponse(*dnsQuestion.ids.cs, dnsQuestion, true)) {
            return ProcessQueryResult::Drop;
          }

          return sendAnswer(dnsQuestion);
        }

        if (!dnsQuestion.ids.subnet) {
          /* there was no existing ECS on the query, enable the zero-scope feature */
          dnsQuestion.ids.useZeroScope = true;
        }
      }

      if (!handleEDNSClientSubnet(dnsQuestion, dnsQuestion.ids.ednsAdded, dnsQuestion.ids.ecsAdded)) {
        VERBOSESLOG(infolog("Dropping query from %s because we couldn't insert the ECS value", dnsQuestion.ids.origRemote.toStringWithPort()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Dropping query because we couldn't insert the ECS value"));
        return ProcessQueryResult::Drop;
      }
    }

    if (serverPool.packetCache && !dnsQuestion.ids.skipCache) {
      /* First lookup, which takes into account how the protocol over which the query will be forwarded.
         For DoH, this lookup is done with the protocol set to TCP but we will retry over UDP below,
         therefore we do not record a miss for queries received over DoH and forwarded over TCP
         yet, as we will do a second-lookup */
      if (serverPool.packetCache->get(dnsQuestion, dnsQuestion.getHeader()->id, dnsQuestion.ids.protocol == dnsdist::Protocol::DoH ? &dnsQuestion.ids.cacheKeyTCP : &dnsQuestion.ids.cacheKey, dnsQuestion.ids.subnet, *dnsQuestion.ids.dnssecOK, dnsQuestion.ids.protocol != dnsdist::Protocol::DoH && willBeForwardedOverUDP, allowExpired, false, true, dnsQuestion.ids.protocol != dnsdist::Protocol::DoH || !willBeForwardedOverUDP)) {

        dnsdist::PacketMangling::editDNSHeaderFromPacket(dnsQuestion.getMutableData(), [flags = dnsQuestion.ids.origFlags](dnsheader& header) {
          dnsdist::PacketMangling::restoreFlags(&header, flags);
          return true;
        });

        VERBOSESLOG(infolog("Packet cache hit for query for %s|%s from %s (%s, %d bytes)", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.protocol.toString(), dnsQuestion.getData().size()),
                    dnsQuestion.getLogger()->info(Logr::Info, "Packet cache hit"));

        if (!prepareOutgoingResponse(*dnsQuestion.ids.cs, dnsQuestion, true)) {
          return ProcessQueryResult::Drop;
        }

        return sendAnswer(dnsQuestion);
      }
      if (dnsQuestion.ids.protocol == dnsdist::Protocol::DoH && willBeForwardedOverUDP) {
        /* do a second-lookup for responses received over UDP, but we do not want TC=1 answers */
        /* we need to be careful to keep the existing cache-key (TCP) */
        if (serverPool.packetCache->get(dnsQuestion, dnsQuestion.getHeader()->id, &dnsQuestion.ids.cacheKey, dnsQuestion.ids.subnet, *dnsQuestion.ids.dnssecOK, true, allowExpired, false, false, true)) {
          if (!prepareOutgoingResponse(*dnsQuestion.ids.cs, dnsQuestion, true)) {
            return ProcessQueryResult::Drop;
          }

          return sendAnswer(dnsQuestion);
        }
      }

      VERBOSESLOG(infolog("Packet cache miss for query for %s|%s from %s (%s, %d bytes)", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort(), dnsQuestion.ids.protocol.toString(), dnsQuestion.getData().size()),
                  dnsQuestion.getLogger()->info(Logr::Info, "Packet cache miss"));

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
        const auto& newServerPool = getPool(dnsQuestion.ids.poolName);
        dnsQuestion.ids.packetCache = newServerPool.packetCache;
        selectedBackend = selectBackendForOutgoingQuery(dnsQuestion, newServerPool);
        backendLookupDone = true;
      }
      else {
        dnsQuestion.ids.packetCache = serverPool.packetCache;
      }
    }

    if (!backendLookupDone) {
      selectedBackend = selectBackendForOutgoingQuery(dnsQuestion, serverPool);
    }

    if (!selectedBackend) {
      auto servFailOnNoPolicy = dnsdist::configuration::getCurrentRuntimeConfiguration().d_servFailOnNoPolicy;
      ++dnsdist::metrics::g_stats.noPolicy;

      VERBOSESLOG(infolog("%s query for %s|%s from %s, no downstream server available", servFailOnNoPolicy ? "ServFailed" : "Dropped", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort()),
                  dnsQuestion.getLogger()->info(Logr::Info, "No downstream server available", "dnsdist.action", Logging::Loggable(servFailOnNoPolicy ? "ServFailed" : "Dropped")));

      if (servFailOnNoPolicy) {
        dnsdist::self_answers::removeRecordsAndSetRCode(dnsQuestion, RCode::ServFail);

        fixUpQueryTurnedResponse(dnsQuestion, dnsQuestion.ids.origFlags);

        if (!prepareOutgoingResponse(*dnsQuestion.ids.cs, dnsQuestion, false)) {
          return ProcessQueryResult::Drop;
        }
        return sendAnswer(dnsQuestion);
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
    outgoingBackend = selectedBackend.get();
    return ProcessQueryResult::PassToBackend;
  }
  catch (const std::exception& e) {
    VERBOSESLOG(infolog("Got an error while parsing a %s query (after applying rules)  from %s, id %d: %s", (dnsQuestion.overTCP() ? "TCP" : "UDP"), dnsQuestion.ids.origRemote.toStringWithPort(), queryId, e.what()),
                dnsQuestion.getLogger()->error(Logr::Info, e.what(), "Got an error while parsing a query (after applying rules)"));
  }
  return ProcessQueryResult::Drop;
}

bool handleTimeoutResponseRules(const std::vector<dnsdist::rules::ResponseRuleAction>& rules, InternalQueryState& ids, const std::shared_ptr<DownstreamState>& d_ds, const std::shared_ptr<TCPQuerySender>& sender)
{
  /* let's be nice and restore the original DNS header as well as we can with what we have */
  PacketBuffer payload(sizeof(dnsheader));
  dnsdist::PacketMangling::editDNSHeaderFromPacket(payload, [&ids](dnsheader& header) {
    memset(&header, 0, sizeof(header));
    header.id = ids.origID;
    dnsdist::PacketMangling::restoreFlags(&header, ids.origFlags);
    // set QR=1 since this is a response rule
    header.qr = 1;
    // do not set the qdcount, otherwise the protobuf code will choke on it
    // while trying to parse the response RRs
    return true;
  });
  DNSResponse dnsResponse(ids, payload, d_ds);
  auto protocol = dnsResponse.getProtocol();

  VERBOSESLOG(infolog("Handling timeout response rules for incoming protocol = %s", protocol.toString()),
              dnsResponse.getLogger()->info(Logr::Info, "Handling timeout response rules"));

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

  try {
    (void)applyRulesToResponse(rules, dnsResponse);
  }
  catch (const std::exception& exp) {
    VERBOSESLOG(infolog("Exception while processing timeout response rules: %s", exp.what()),
                dnsResponse.getLogger()->error(Logr::Info, exp.what(), "Exception while processing timeout response rules"));
  }

  return dnsResponse.isAsynchronous();
}

ProcessQueryResult processQuery(DNSQuestion& dnsQuestion, std::shared_ptr<DownstreamState>& selectedBackend)
{
  auto closer = dnsQuestion.ids.getCloser(__func__); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
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
    VERBOSESLOG(infolog("Got an error while parsing a %s query from %s, id %d: %s", (dnsQuestion.overTCP() ? "TCP" : "UDP"), dnsQuestion.ids.origRemote.toStringWithPort(), queryId, e.what()),
                dnsQuestion.getLogger()->error(Logr::Info, e.what(), "Got and error while parsing a query", "dns.question.id", Logging::Loggable(queryId)));
  }
  return ProcessQueryResult::Drop;
}

bool assignOutgoingUDPQueryToBackend(std::shared_ptr<DownstreamState>& downstream, uint16_t queryID, DNSQuestion& dnsQuestion, PacketBuffer& query, bool actuallySend)
{
  auto closer = dnsQuestion.ids.getCloser(__func__); // NOLINT(cppcoreguidelines-pro-bounds-array-to-pointer-decay)

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
      VERBOSESLOG(infolog("Adding proxy protocol payload to %s query from %s failed: %s", (dnsQuestion.ids.du ? "DoH" : ""), dnsQuestion.ids.origDest.toStringWithPort(), e.what()),
                  dnsQuestion.getLogger()->error(Logr::Info, e.what(), "Adding a proxy protocol payload to the query failed"));
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

    VERBOSESLOG(infolog("Got query for %s|%s from %s%s, relayed to %s%s", dnsQuestion.ids.qname.toLogString(), QType(dnsQuestion.ids.qtype).toString(), dnsQuestion.ids.origRemote.toStringWithPort(), (doh ? " (https)" : ""), downstream->getNameWithAddr(), actuallySend ? "" : " (xsk)"),
                dnsQuestion.getLogger()->info(Logr::Info, "Relayed query to backend", "backend.name", Logging::Loggable(downstream->getName()), "backend.address", Logging::Loggable(downstream->d_config.remote), "dnsdist.xsk", Logging::Loggable(!actuallySend)));

#ifndef DISABLE_PROTOBUF
    if (auto& tracer = dnsQuestion.ids.getTracer(); dnsQuestion.ids.sendTraceParentToDownstreamID != 0 && tracer != nullptr) {
      auto ednsAdded = pdns::trace::dnsdist::addTraceparentEdnsOptionToPacketBuffer(
        dnsQuestion.getMutableData(),
        tracer,
        dnsQuestion.ids.qname.wirelength(),
        dnsQuestion.ids.d_proxyProtocolPayloadSize,
        dnsQuestion.ids.sendTraceParentToDownstreamID,
        false);
      dnsQuestion.ids.ednsAdded = dnsQuestion.ids.ednsAdded || ednsAdded;
    }
#endif

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
