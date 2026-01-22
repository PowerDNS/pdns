#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-metrics.hh"
#include "sholder.hh"

#ifndef DISABLE_DYNBLOCKS
static GlobalStateHolder<ClientAddressDynamicRules> s_dynblockNMG;
static GlobalStateHolder<SuffixDynamicRules> s_dynblockSMT;

void DynBlockRulesGroup::apply(const timespec& now)
{
  counts_t counts;
  StatNode statNodeRoot;

  size_t entriesCount = 0;
  if (hasQueryRules()) {
    entriesCount += g_rings.getNumberOfQueryEntries();
  }
  if (hasResponseRules()) {
    entriesCount += g_rings.getNumberOfResponseEntries();
  }
  counts.reserve(entriesCount);

  processQueryRules(counts, now);
  processResponseRules(counts, statNodeRoot, now);

  if (counts.empty() && statNodeRoot.empty()) {
    return;
  }

  std::optional<ClientAddressDynamicRules> blocks;
  bool updated = false;

  for (const auto& entry : counts) {
    const auto& requestor = entry.first;
    const auto& counters = entry.second;

    if (d_queryRateRule.warningRateExceeded(g_rings.adjustForSamplingRate(counters.queries), now)) {
      handleWarning(blocks, now, requestor, d_queryRateRule, updated);
    }

    if (d_queryRateRule.rateExceeded(g_rings.adjustForSamplingRate(counters.queries), now)) {
      addBlock(blocks, now, requestor, d_queryRateRule, updated);
      continue;
    }

    if (d_respRateRule.warningRateExceeded(g_rings.adjustForSamplingRate(counters.respBytes), now)) {
      handleWarning(blocks, now, requestor, d_respRateRule, updated);
    }

    if (d_respRateRule.rateExceeded(g_rings.adjustForSamplingRate(counters.respBytes), now)) {
      addBlock(blocks, now, requestor, d_respRateRule, updated);
      continue;
    }

    if (d_respCacheMissRatioRule.warningRatioExceeded(counters.responses, counters.cacheMisses)) {
      handleWarning(blocks, now, requestor, d_respCacheMissRatioRule, updated);
      continue;
    }

    if (d_respCacheMissRatioRule.ratioExceeded(counters.responses, counters.cacheMisses)) {
      addBlock(blocks, now, requestor, d_respCacheMissRatioRule, updated);
      continue;
    }

    for (const auto& pair : d_qtypeRules) {
      const auto qtype = pair.first;

      const auto& typeIt = counters.d_qtypeCounts.find(qtype);
      if (typeIt != counters.d_qtypeCounts.cend()) {

        if (pair.second.warningRateExceeded(g_rings.adjustForSamplingRate(typeIt->second), now)) {
          handleWarning(blocks, now, requestor, pair.second, updated);
        }

        if (pair.second.rateExceeded(g_rings.adjustForSamplingRate(typeIt->second), now)) {
          addBlock(blocks, now, requestor, pair.second, updated);
          break;
        }
      }
    }

    for (const auto& pair : d_rcodeRules) {
      const auto rcode = pair.first;

      const auto& rcodeIt = counters.d_rcodeCounts.find(rcode);
      if (rcodeIt != counters.d_rcodeCounts.cend()) {
        if (pair.second.warningRateExceeded(g_rings.adjustForSamplingRate(rcodeIt->second), now)) {
          handleWarning(blocks, now, requestor, pair.second, updated);
        }

        if (pair.second.rateExceeded(g_rings.adjustForSamplingRate(rcodeIt->second), now)) {
          addBlock(blocks, now, requestor, pair.second, updated);
          break;
        }
      }
    }

    for (const auto& pair : d_rcodeRatioRules) {
      const auto rcode = pair.first;

      const auto& rcodeIt = counters.d_rcodeCounts.find(rcode);
      if (rcodeIt != counters.d_rcodeCounts.cend()) {
        if (pair.second.warningRatioExceeded(counters.responses, rcodeIt->second)) {
          handleWarning(blocks, now, requestor, pair.second, updated);
        }

        if (pair.second.ratioExceeded(counters.responses, rcodeIt->second)) {
          addBlock(blocks, now, requestor, pair.second, updated);
          break;
        }
      }
    }
  }

  if (updated && blocks) {
    s_dynblockNMG.setState(std::move(*blocks));
  }

  applySMT(now, statNodeRoot);
}

void DynBlockRulesGroup::applySMT(const struct timespec& now, StatNode& statNodeRoot)
{
  if (statNodeRoot.empty()) {
    return;
  }

  bool updated = false;
  StatNode::Stat node;
  std::unordered_map<DNSName, SMTBlockParameters> namesToBlock;
  statNodeRoot.visit([this, &namesToBlock](const StatNode* node_, const StatNode::Stat& self, const StatNode::Stat& children) {
    bool block = false;
    SMTBlockParameters blockParameters;
    if (d_smtVisitorFFI) {
      dnsdist_ffi_stat_node_t tmp(*node_, self, children, blockParameters);
      block = d_smtVisitorFFI(&tmp);
    }
    else {
      auto ret = d_smtVisitor(*node_, self, children);
      block = std::get<0>(ret);
      if (block) {
        if (std::optional<std::string> tmp = std::get<1>(ret)) {
          blockParameters.d_reason = std::move(*tmp);
        }
        if (std::optional<int> tmp = std::get<2>(ret)) {
          blockParameters.d_action = static_cast<DNSAction::Action>(*tmp);
        }
      }
    }
    if (block) {
      namesToBlock.insert({DNSName(node_->fullname), std::move(blockParameters)});
    }
  },
                     node);

  if (!namesToBlock.empty()) {
    updated = false;
    auto smtBlocks = dnsdist::DynamicBlocks::getSuffixDynamicRulesCopy();
    for (auto& [name, parameters] : namesToBlock) {
      if (parameters.d_reason || parameters.d_action) {
        DynBlockRule rule(d_suffixMatchRule);
        if (parameters.d_reason) {
          rule.d_blockReason = std::move(*parameters.d_reason);
        }
        if (parameters.d_action) {
          rule.d_action = *parameters.d_action;
        }
        addOrRefreshBlockSMT(smtBlocks, now, name, rule, updated);
      }
      else {
        addOrRefreshBlockSMT(smtBlocks, now, name, d_suffixMatchRule, updated);
      }
    }
    if (updated) {
      s_dynblockSMT.setState(std::move(smtBlocks));
    }
  }
}

bool DynBlockRulesGroup::checkIfQueryTypeMatches(const Rings::Query& query)
{
  auto rule = d_qtypeRules.find(query.qtype);
  if (rule == d_qtypeRules.end()) {
    return false;
  }

  return rule->second.matches(query.when);
}

bool DynBlockRulesGroup::checkIfResponseCodeMatches(const Rings::Response& response)
{
  auto rule = d_rcodeRules.find(response.dh.rcode);
  if (rule != d_rcodeRules.end() && rule->second.matches(response.when)) {
    return true;
  }

  auto ratio = d_rcodeRatioRules.find(response.dh.rcode);
  return ratio != d_rcodeRatioRules.end() && ratio->second.matches(response.when);
}

/* return the actual action that will be taken by that block:
   - either the one set on that block, if any
   - or the one set with setDynBlocksAction
*/
static DNSAction::Action getActualAction(const DynBlock& block)
{
  if (block.action != DNSAction::Action::None) {
    return block.action;
  }
  return dnsdist::configuration::getCurrentRuntimeConfiguration().d_dynBlockAction;
}

namespace dnsdist::DynamicBlocks
{
bool addOrRefreshBlock(ClientAddressDynamicRules& blocks, const timespec& now, const AddressAndPortRange& requestor, DynBlock&& dblock, bool beQuiet)
{
  unsigned int count = 0;
  bool expired = false;
  bool wasWarning = false;
  bool bpf = false;

  const auto& got = blocks.lookup(requestor);
  if (got != nullptr) {
    bpf = got->second.bpf;

    if (dblock.warning && !got->second.warning) {
      /* we have an existing entry which is not a warning,
         don't override it */
      return false;
    }
    if (!dblock.warning && got->second.warning) {
      wasWarning = true;
    }
    else {
      if (dblock.until < got->second.until) {
        // had a longer policy
        return false;
      }
    }

    if (now < got->second.until) {
      // only inherit count on fresh query we are extending
      count = got->second.blocks;
    }
    else {
      expired = true;
    }
  }

  dblock.blocks = count;

  if (got == nullptr || expired || wasWarning) {
    const auto actualAction = getActualAction(dblock);
    if (g_defaultBPFFilter && ((requestor.isIPv4() && requestor.getBits() == 32) || (requestor.isIPv6() && requestor.getBits() == 128)) && (actualAction == DNSAction::Action::Drop || actualAction == DNSAction::Action::Truncate)) {
      try {
        BPFFilter::MatchAction bpfAction = actualAction == DNSAction::Action::Drop ? BPFFilter::MatchAction::Drop : BPFFilter::MatchAction::Truncate;
        if (g_defaultBPFFilter->supportsMatchAction(bpfAction)) {
          /* the current BPF filter implementation only supports full addresses (/32 or /128) and no port */
          g_defaultBPFFilter->block(requestor.getNetwork(), bpfAction);
          bpf = true;
        }
      }
      catch (const std::exception& e) {
        VERBOSESLOG(infolog("Unable to insert eBPF dynamic block for %s, falling back to regular dynamic block: %s", requestor.toString(), e.what()),
                    dnsdist::logging::getTopLogger("dynamic-rules")->error(Logr::Info, e.what(), "Unable to insert eBPF dynamic block, falling back to regular dynamic block", "client.address", Logging::Loggable(requestor)));
      }
    }

    if (!beQuiet) {
      SLOG(warnlog("Inserting %s%sdynamic block for %s for %d seconds: %s", dblock.warning ? "(warning) " : "", bpf ? "eBPF " : "", requestor.toString(), dblock.until.tv_sec - now.tv_sec, dblock.reason),
           dnsdist::logging::getTopLogger("dynamic-rules")->info(Logr::Warning, "Inserting dynamic rule", "dynamic_rule.warning_rule", Logging::Loggable(dblock.warning), "client.address", Logging::Loggable(requestor), "dynamic_rule.use_bpf", Logging::Loggable(bpf), "dynamic_rule.reason", Logging::Loggable(dblock.reason), "dynamic_rule.duration", Logging::Loggable(dblock.until.tv_sec - now.tv_sec)));
    }
  }

  dblock.bpf = bpf;

  blocks.insert(requestor).second = std::move(dblock);

  return true;
}

bool addOrRefreshBlockSMT(SuffixDynamicRules& blocks, const timespec& now, DynBlock&& dblock, bool beQuiet)
{
  unsigned int count = 0;
  /* be careful, if you try to insert a longer suffix
     lookup() might return a shorter one if it is
     already in the tree as a final node */
  const DynBlock* got = blocks.lookup(dblock.domain);
  if (got != nullptr && got->domain != dblock.domain) {
    got = nullptr;
  }
  bool expired = false;

  if (got != nullptr) {
    if (dblock.until < got->until) {
      // had a longer policy
      return false;
    }

    if (now < got->until) {
      // only inherit count on fresh query we are extending
      count = got->blocks;
    }
    else {
      expired = true;
    }
  }

  dblock.blocks = count;

  if (!beQuiet && (got == nullptr || expired)) {
    SLOG(warnlog("Inserting dynamic block for %s for %d seconds: %s", dblock.domain, dblock.until.tv_sec - now.tv_sec, dblock.reason),
         dnsdist::logging::getTopLogger("dynamic-rules")->info(Logr::Warning, "Inserting dynamic rule", "dynamic_rule.warning_rule", Logging::Loggable(false), "dns.query.name", Logging::Loggable(dblock.domain), "dynamic_rule.use_bpf", Logging::Loggable(false), "dynamic_rule.reason", Logging::Loggable(dblock.reason), "dynamic_rule.duration", Logging::Loggable(dblock.until.tv_sec - now.tv_sec)));
  }

  auto domain = dblock.domain;
  blocks.add(domain, std::move(dblock));
  return true;
}
}

void DynBlockRulesGroup::addOrRefreshBlock(std::optional<ClientAddressDynamicRules>& blocks, const struct timespec& now, const AddressAndPortRange& requestor, const DynBlockRule& rule, bool& updated, bool warning)
{
  /* network exclusions are address-based only (no port) */
  if (d_excludedSubnets.match(requestor.getNetwork())) {
    /* do not add a block for excluded subnets */
    return;
  }

  timespec until{now};
  until.tv_sec += rule.d_blockDuration;
  DynBlock dblock{rule.d_blockReason, until, DNSName(), warning ? DNSAction::Action::NoOp : rule.d_action};
  dblock.warning = warning;
  if (!warning && rule.d_action == DNSAction::Action::SetTag) {
    dblock.tagSettings = rule.d_tagSettings;
  }
  if (!blocks) {
    blocks = dnsdist::DynamicBlocks::getClientAddressDynamicRulesCopy();
  }

  updated = dnsdist::DynamicBlocks::addOrRefreshBlock(*blocks, now, requestor, std::move(dblock), d_beQuiet);
  if (updated && d_newBlockHook) {
    try {
      d_newBlockHook(dnsdist_ffi_dynamic_block_type_nmt, requestor.toString().c_str(), rule.d_blockReason.c_str(), static_cast<uint8_t>(rule.d_action), rule.d_blockDuration, warning);
    }
    catch (const std::exception& exp) {
      SLOG(warnlog("Error calling the Lua hook after a dynamic block insertion: %s", exp.what()),
           dnsdist::logging::getTopLogger("dynamic-rules")->error(Logr::Warning, exp.what(), "Error calling the Lua hook after a dynamic rule insertion"));
    }
  }
}

void DynBlockRulesGroup::addOrRefreshBlockSMT(SuffixDynamicRules& blocks, const struct timespec& now, const DNSName& name, const DynBlockRule& rule, bool& updated)
{
  if (d_excludedDomains.check(name)) {
    /* do not add a block for excluded domains */
    return;
  }

  timespec until{now};
  until.tv_sec += rule.d_blockDuration;
  DynBlock dblock{rule.d_blockReason, until, name.makeLowerCase(), rule.d_action};
  if (rule.d_action == DNSAction::Action::SetTag) {
    dblock.tagSettings = rule.d_tagSettings;
  }
  updated = dnsdist::DynamicBlocks::addOrRefreshBlockSMT(blocks, now, std::move(dblock), d_beQuiet);
  if (updated && d_newBlockHook) {
    try {
      d_newBlockHook(dnsdist_ffi_dynamic_block_type_smt, name.toString().c_str(), rule.d_blockReason.c_str(), static_cast<uint8_t>(rule.d_action), rule.d_blockDuration, false);
    }
    catch (const std::exception& exp) {
      SLOG(warnlog("Error calling the Lua hook after a dynamic block insertion: %s", exp.what()),
           dnsdist::logging::getTopLogger("dynamic-rules")->error(Logr::Warning, exp.what(), "Error calling the Lua hook after a suffix-based dynamic rule insertion"));
    }
  }
}

void DynBlockRulesGroup::processQueryRules(counts_t& counts, const struct timespec& now)
{
  if (!hasQueryRules()) {
    return;
  }

  d_queryRateRule.d_cutOff = d_queryRateRule.d_minTime = now;
  d_queryRateRule.d_cutOff.tv_sec -= d_queryRateRule.d_seconds;

  for (auto& rule : d_qtypeRules) {
    rule.second.d_cutOff = rule.second.d_minTime = now;
    rule.second.d_cutOff.tv_sec -= rule.second.d_seconds;
  }

  for (const auto& shard : g_rings.d_shards) {
    auto queryRing = shard->queryRing.lock();
    for (const auto& ringEntry : *queryRing) {
      if (now < ringEntry.when) {
        continue;
      }

      bool qRateMatches = d_queryRateRule.matches(ringEntry.when);
      bool typeRuleMatches = checkIfQueryTypeMatches(ringEntry);

      if (qRateMatches || typeRuleMatches) {
        auto& entry = counts[AddressAndPortRange(ringEntry.requestor, ringEntry.requestor.isIPv4() ? d_v4Mask : d_v6Mask, d_portMask)];
        if (qRateMatches) {
          ++entry.queries;
        }
        if (typeRuleMatches) {
          ++entry.d_qtypeCounts[ringEntry.qtype];
        }
      }
    }
  }
}

void DynBlockRulesGroup::processResponseRules(counts_t& counts, StatNode& root, const struct timespec& now)
{
  if (!hasResponseRules() && !hasSuffixMatchRules()) {
    return;
  }

  struct timespec responseCutOff = now;

  d_respRateRule.d_cutOff = d_respRateRule.d_minTime = now;
  d_respRateRule.d_cutOff.tv_sec -= d_respRateRule.d_seconds;
  if (d_respRateRule.d_cutOff < responseCutOff) {
    responseCutOff = d_respRateRule.d_cutOff;
  }

  d_suffixMatchRule.d_cutOff = d_suffixMatchRule.d_minTime = now;
  d_suffixMatchRule.d_cutOff.tv_sec -= d_suffixMatchRule.d_seconds;
  if (d_suffixMatchRule.d_cutOff < responseCutOff) {
    responseCutOff = d_suffixMatchRule.d_cutOff;
  }

  d_respCacheMissRatioRule.d_cutOff = d_respCacheMissRatioRule.d_minTime = now;
  d_respCacheMissRatioRule.d_cutOff.tv_sec -= d_respCacheMissRatioRule.d_seconds;
  if (d_respCacheMissRatioRule.d_cutOff < responseCutOff) {
    responseCutOff = d_respCacheMissRatioRule.d_cutOff;
  }

  for (auto& rule : d_rcodeRules) {
    rule.second.d_cutOff = rule.second.d_minTime = now;
    rule.second.d_cutOff.tv_sec -= rule.second.d_seconds;
    if (rule.second.d_cutOff < responseCutOff) {
      responseCutOff = rule.second.d_cutOff;
    }
  }

  for (auto& rule : d_rcodeRatioRules) {
    rule.second.d_cutOff = rule.second.d_minTime = now;
    rule.second.d_cutOff.tv_sec -= rule.second.d_seconds;
    if (rule.second.d_cutOff < responseCutOff) {
      responseCutOff = rule.second.d_cutOff;
    }
  }

  for (const auto& shard : g_rings.d_shards) {
    auto responseRing = shard->respRing.lock();
    for (const auto& ringEntry : *responseRing) {
      if (now < ringEntry.when) {
        continue;
      }

      if (ringEntry.when < responseCutOff) {
        continue;
      }

      auto& entry = counts[AddressAndPortRange(ringEntry.requestor, ringEntry.requestor.isIPv4() ? d_v4Mask : d_v6Mask, d_portMask)];
      ++entry.responses;

      bool respRateMatches = d_respRateRule.matches(ringEntry.when);
      bool suffixMatchRuleMatches = d_suffixMatchRule.matches(ringEntry.when);
      bool rcodeRuleMatches = checkIfResponseCodeMatches(ringEntry);
      bool respCacheMissRatioRuleMatches = d_respCacheMissRatioRule.matches(ringEntry.when);

      if (respRateMatches) {
        entry.respBytes += ringEntry.size;
      }
      if (rcodeRuleMatches) {
        ++entry.d_rcodeCounts[ringEntry.dh.rcode];
      }
      if (respCacheMissRatioRuleMatches && !ringEntry.isACacheHit()) {
        ++entry.cacheMisses;
      }

      if (suffixMatchRuleMatches) {
        const bool hit = ringEntry.isACacheHit();
        root.submit(ringEntry.name, ((ringEntry.dh.rcode == 0 && ringEntry.usec == std::numeric_limits<uint32_t>::max()) ? -1 : ringEntry.dh.rcode), ringEntry.size, hit, std::nullopt, g_rings.getSamplingRate());
      }
    }
  }
}

void DynBlockMaintenance::purgeExpired(const struct timespec& now)
{
  // we need to increase the dynBlocked counter when removing
  // eBPF blocks, as otherwise it does not get incremented for these
  // since the block happens in kernel space.
  uint64_t bpfBlocked = 0;
  {
    auto blocks = s_dynblockNMG.getLocal();
    std::vector<AddressAndPortRange> toRemove;
    for (const auto& entry : *blocks) {
      if (!(now < entry.second.until)) {
        toRemove.push_back(entry.first);
        if (g_defaultBPFFilter && entry.second.bpf) {
          const auto& network = entry.first.getNetwork();
          try {
            bpfBlocked += g_defaultBPFFilter->getHits(network);
          }
          catch (const std::exception& e) {
            VERBOSESLOG(infolog("Error while getting block count before removing eBPF dynamic block for %s: %s", entry.first.toString(), e.what()),
                        dnsdist::logging::getTopLogger("dynamic-rules")->error(Logr::Info, e.what(), "Error while getting block count before removing eBPF dynamic block", "dynamic_rule.key", Logging::Loggable(entry.first)));
          }

          try {
            g_defaultBPFFilter->unblock(network);
          }
          catch (const std::exception& e) {
            VERBOSESLOG(infolog("Error while removing eBPF dynamic block for %s: %s", entry.first.toString(), e.what()),
                        dnsdist::logging::getTopLogger("dynamic-rules")->error(Logr::Info, e.what(), "Error while removing eBPF dynamic block", "dynamic_rule.key", Logging::Loggable(entry.first)));
          }
        }
      }
    }
    if (!toRemove.empty()) {
      auto updated = dnsdist::DynamicBlocks::getClientAddressDynamicRulesCopy();
      for (const auto& entry : toRemove) {
        updated.erase(entry);
      }
      s_dynblockNMG.setState(std::move(updated));
      dnsdist::metrics::g_stats.dynBlocked += bpfBlocked;
    }
  }

  {
    std::vector<DNSName> toRemove;
    auto blocks = s_dynblockSMT.getLocal();
    blocks->visit([&toRemove, now](const SuffixDynamicRules& node) {
      if (!(now < node.d_value.until)) {
        toRemove.push_back(node.d_value.domain);
      }
    });
    if (!toRemove.empty()) {
      auto updated = dnsdist::DynamicBlocks::getSuffixDynamicRulesCopy();
      for (const auto& entry : toRemove) {
        updated.remove(entry);
      }
      s_dynblockSMT.setState(std::move(updated));
    }
  }
}

std::map<std::string, std::list<std::pair<AddressAndPortRange, unsigned int>>> DynBlockMaintenance::getTopNetmasks(size_t topN)
{
  std::map<std::string, std::list<std::pair<AddressAndPortRange, unsigned int>>> results;
  if (topN == 0) {
    return results;
  }

  auto blocks = s_dynblockNMG.getLocal();
  for (const auto& entry : *blocks) {
    auto& topsForReason = results[entry.second.reason];
    uint64_t value = entry.second.blocks.load();

    if (g_defaultBPFFilter && entry.second.bpf) {
      value += g_defaultBPFFilter->getHits(entry.first.getNetwork());
    }

    if (topsForReason.size() < topN || topsForReason.front().second < value) {
      auto newEntry = std::pair(entry.first, value);

      if (topsForReason.size() >= topN) {
        topsForReason.pop_front();
      }

      topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<AddressAndPortRange, unsigned int>& rhs, const std::pair<AddressAndPortRange, unsigned int>& lhs) {
                             return rhs.second < lhs.second;
                           }),
                           newEntry);
    }
  }

  return results;
}

std::map<std::string, std::list<std::pair<DNSName, unsigned int>>> DynBlockMaintenance::getTopSuffixes(size_t topN)
{
  std::map<std::string, std::list<std::pair<DNSName, unsigned int>>> results;
  if (topN == 0) {
    return results;
  }

  auto blocks = s_dynblockSMT.getLocal();
  blocks->visit([&results, topN](const SuffixDynamicRules& node) {
    auto& topsForReason = results[node.d_value.reason];
    if (topsForReason.size() < topN || topsForReason.front().second < node.d_value.blocks) {
      auto newEntry = std::pair(node.d_value.domain, node.d_value.blocks.load());

      if (topsForReason.size() >= topN) {
        topsForReason.pop_front();
      }

      topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<DNSName, unsigned int>& rhs, const std::pair<DNSName, unsigned int>& lhs) {
                             return rhs.second < lhs.second;
                           }),
                           newEntry);
    }
  });

  return results;
}

struct DynBlockEntryStat
{
  size_t sum{0};
  unsigned int lastSeenValue{0};
};

std::list<DynBlockMaintenance::MetricsSnapshot> DynBlockMaintenance::s_metricsData;

LockGuarded<DynBlockMaintenance::Tops> DynBlockMaintenance::s_tops;

void DynBlockMaintenance::collectMetrics()
{
  MetricsSnapshot snapshot;
  /* over sampling to get entries that are not in the top N
     every time a chance to be at the end */
  snapshot.smtData = getTopSuffixes(s_topN * 5);
  snapshot.nmgData = getTopNetmasks(s_topN * 5);

  if (s_metricsData.size() >= 7) {
    s_metricsData.pop_front();
  }
  s_metricsData.push_back(std::move(snapshot));
}

void DynBlockMaintenance::generateMetrics()
{
  if (s_metricsData.empty()) {
    return;
  }

  /* do NMG */
  std::map<std::string, std::map<AddressAndPortRange, DynBlockEntryStat>> netmasks;
  for (const auto& reason : s_metricsData.front().nmgData) {
    auto& reasonStat = netmasks[reason.first];

    /* prepare the counters by scanning the oldest entry (N+1) */
    for (const auto& entry : reason.second) {
      auto& stat = reasonStat[entry.first];
      stat.sum = 0;
      stat.lastSeenValue = entry.second;
    }
  }

  /* scan all the N entries, updating the counters */
  bool first = true;
  for (const auto& snap : s_metricsData) {
    if (first) {
      first = false;
      continue;
    }

    const auto& nmgData = snap.nmgData;
    for (const auto& reason : nmgData) {
      auto& reasonStat = netmasks[reason.first];
      for (const auto& entry : reason.second) {
        auto& stat = reasonStat[entry.first];
        if (entry.second < stat.lastSeenValue) {
          /* it wrapped, or we did not have a last value */
          stat.sum += entry.second;
        }
        else {
          stat.sum += entry.second - stat.lastSeenValue;
        }
        stat.lastSeenValue = entry.second;
      }
    }
  }

  /* now we need to get the top N entries (for each "reason") based on our counters (sum of the last N entries) */
  std::map<std::string, std::list<std::pair<AddressAndPortRange, unsigned int>>> topNMGs;
  {
    for (const auto& reason : netmasks) {
      auto& topsForReason = topNMGs[reason.first];
      for (const auto& entry : reason.second) {
        if (topsForReason.size() < s_topN || topsForReason.front().second < entry.second.sum) {
          /* Note that this is a gauge, so we need to divide by the number of elapsed seconds */
          auto newEntry = std::pair<AddressAndPortRange, unsigned int>(entry.first, std::round(static_cast<double>(entry.second.sum) / 60.0));
          if (topsForReason.size() >= s_topN) {
            topsForReason.pop_front();
          }

          topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<AddressAndPortRange, unsigned int>& rhs, const std::pair<AddressAndPortRange, unsigned int>& lhs) {
                                 return rhs.second < lhs.second;
                               }),
                               newEntry);
        }
      }
    }
  }

  /* do SMT */
  std::map<std::string, std::map<DNSName, DynBlockEntryStat>> smt;
  for (const auto& reason : s_metricsData.front().smtData) {
    auto& reasonStat = smt[reason.first];

    /* prepare the counters by scanning the oldest entry (N+1) */
    for (const auto& entry : reason.second) {
      auto& stat = reasonStat[entry.first];
      stat.sum = 0;
      stat.lastSeenValue = entry.second;
    }
  }

  /* scan all the N entries, updating the counters */
  first = true;
  for (const auto& snap : s_metricsData) {
    if (first) {
      first = false;
      continue;
    }

    const auto& smtData = snap.smtData;
    for (const auto& reason : smtData) {
      auto& reasonStat = smt[reason.first];
      for (const auto& entry : reason.second) {
        auto& stat = reasonStat[entry.first];
        if (entry.second < stat.lastSeenValue) {
          /* it wrapped, or we did not have a last value */
          stat.sum = entry.second;
        }
        else {
          stat.sum = entry.second - stat.lastSeenValue;
        }
        stat.lastSeenValue = entry.second;
      }
    }
  }

  /* now we need to get the top N entries (for each "reason") based on our counters (sum of the last N entries) */
  std::map<std::string, std::list<std::pair<DNSName, unsigned int>>> topSMTs;
  {
    for (const auto& reason : smt) {
      auto& topsForReason = topSMTs[reason.first];
      for (const auto& entry : reason.second) {
        if (topsForReason.size() < s_topN || topsForReason.front().second < entry.second.sum) {
          /* Note that this is a gauge, so we need to divide by the number of elapsed seconds */
          auto newEntry = std::pair<DNSName, unsigned int>(entry.first, std::round(static_cast<double>(entry.second.sum) / 60.0));
          if (topsForReason.size() >= s_topN) {
            topsForReason.pop_front();
          }

          topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<DNSName, unsigned int>& lhs, const std::pair<DNSName, unsigned int>& rhs) {
                                 return lhs.second < rhs.second;
                               }),
                               newEntry);
        }
      }
    }
  }

  {
    auto tops = s_tops.lock();
    tops->topNMGsByReason = std::move(topNMGs);
    tops->topSMTsByReason = std::move(topSMTs);
  }
}

void DynBlockMaintenance::run()
{
  /* alright, so the main idea is to:
     1/ clean up the NMG and SMT from expired entries from time to time
     2/ generate metrics that can be used in the API and prometheus endpoints
  */

  static const time_t metricsCollectionInterval = 10;
  static const time_t metricsGenerationInterval = 60;

  time_t now = time(nullptr);
  auto purgeInterval = dnsdist::configuration::getCurrentRuntimeConfiguration().d_dynBlocksPurgeInterval;
  time_t nextExpiredPurge = now + static_cast<time_t>(purgeInterval);
  time_t nextMetricsCollect = now + static_cast<time_t>(metricsCollectionInterval);
  time_t nextMetricsGeneration = now + metricsGenerationInterval;

  while (true) {
    time_t sleepDelay = std::numeric_limits<time_t>::max();
    if (purgeInterval > 0) {
      sleepDelay = std::min(sleepDelay, (nextExpiredPurge - now));
    }
    sleepDelay = std::min(sleepDelay, (nextMetricsCollect - now));
    sleepDelay = std::min(sleepDelay, (nextMetricsGeneration - now));

    // coverity[store_truncates_time_t]
    std::this_thread::sleep_for(std::chrono::seconds(sleepDelay));

    try {
      now = time(nullptr);
      if (now >= nextMetricsCollect) {
        /* every ten seconds we store the top N entries */
        collectMetrics();

        now = time(nullptr);
        nextMetricsCollect = now + metricsCollectionInterval;
      }

      if (now >= nextMetricsGeneration) {
        generateMetrics();

        now = time(nullptr);
        /* every minute we compute the averaged top N entries of the last 60 seconds,
           and update the cached entry. */
        nextMetricsGeneration = now + metricsGenerationInterval;
      }

      purgeInterval = dnsdist::configuration::getCurrentRuntimeConfiguration().d_dynBlocksPurgeInterval;
      if (purgeInterval > 0 && now >= nextExpiredPurge) {
        timespec tspec{};
        gettime(&tspec);
        purgeExpired(tspec);

        now = time(nullptr);
        nextExpiredPurge = now + static_cast<time_t>(purgeInterval);
      }
    }
    catch (const std::exception& e) {
      SLOG(warnlog("Error in the dynamic block maintenance thread: %s", e.what()),
           dnsdist::logging::getTopLogger("dynamic-rules")->error(Logr::Warning, e.what(), "Error in the dynamic block maintenance thread"));
    }
    catch (...) {
      VERBOSESLOG(infolog("Unhandled error in the dynamic block maintenance thread"),
                  dnsdist::logging::getTopLogger("dynamic-rules")->info(Logr::Info, "Unhandled error in the dynamic block maintenance thread"));
    }
  }
}

std::map<std::string, std::list<std::pair<AddressAndPortRange, unsigned int>>> DynBlockMaintenance::getHitsForTopNetmasks()
{
  return s_tops.lock()->topNMGsByReason;
}

std::map<std::string, std::list<std::pair<DNSName, unsigned int>>> DynBlockMaintenance::getHitsForTopSuffixes()
{
  return s_tops.lock()->topSMTsByReason;
}

std::string DynBlockRulesGroup::DynBlockRule::toString() const
{
  if (!isEnabled()) {
    return "";
  }

  std::stringstream result;
  if (d_action != DNSAction::Action::None) {
    result << DNSAction::typeToString(d_action) << " ";
  }
  else {
    result << "Apply the global DynBlock action ";
  }
  result << "for " << std::to_string(d_blockDuration) << " seconds when over " << std::to_string(d_rate) << " during the last " << d_seconds << " seconds, reason: '" << d_blockReason << "'";

  return result.str();
}

bool DynBlockRulesGroup::DynBlockRule::matches(const struct timespec& when)
{
  if (!d_enabled) {
    return false;
  }

  if (d_seconds > 0 && when < d_cutOff) {
    return false;
  }

  if (when < d_minTime) {
    d_minTime = when;
  }

  return true;
}

bool DynBlockRulesGroup::DynBlockRule::rateExceeded(unsigned int count, const struct timespec& now) const
{
  if (!d_enabled) {
    return false;
  }

  double delta = d_seconds > 0 ? d_seconds : DiffTime(now, d_minTime);
  double limit = delta * d_rate;
  return (count > limit);
}

bool DynBlockRulesGroup::DynBlockRule::warningRateExceeded(unsigned int count, const struct timespec& now) const
{
  if (!d_enabled) {
    return false;
  }

  if (d_warningRate == 0) {
    return false;
  }

  double delta = d_seconds > 0 ? d_seconds : DiffTime(now, d_minTime);
  double limit = delta * d_warningRate;
  return (count > limit);
}

bool DynBlockRulesGroup::DynBlockRatioRule::ratioExceeded(unsigned int total, unsigned int count) const
{
  if (!d_enabled) {
    return false;
  }

  if (total < d_minimumNumberOfResponses) {
    return false;
  }

  double allowed = d_ratio * static_cast<double>(total);
  return (count > allowed);
}

bool DynBlockRulesGroup::DynBlockRatioRule::warningRatioExceeded(unsigned int total, unsigned int count) const
{
  if (!d_enabled) {
    return false;
  }

  if (d_warningRatio == 0.0) {
    return false;
  }

  if (total < d_minimumNumberOfResponses) {
    return false;
  }

  double allowed = d_warningRatio * static_cast<double>(total);
  return (count > allowed);
}

std::string DynBlockRulesGroup::DynBlockRatioRule::toString() const
{
  if (!isEnabled()) {
    return "";
  }

  std::stringstream result;
  if (d_action != DNSAction::Action::None) {
    result << DNSAction::typeToString(d_action) << " ";
  }
  else {
    result << "Apply the global DynBlock action ";
  }
  result << "for " << std::to_string(d_blockDuration) << " seconds when over " << std::to_string(d_ratio) << " ratio during the last " << d_seconds << " seconds, reason: '" << d_blockReason << "'";

  return result.str();
}

bool DynBlockRulesGroup::DynBlockCacheMissRatioRule::checkGlobalCacheHitRatio() const
{
  auto globalMisses = dnsdist::metrics::g_stats.cacheMisses.load();
  auto globalHits = dnsdist::metrics::g_stats.cacheHits.load();
  if (globalMisses == 0 || globalHits == 0) {
    return false;
  }
  double globalCacheHitRatio = static_cast<double>(globalHits) / static_cast<double>(globalHits + globalMisses);
  return globalCacheHitRatio >= d_minimumGlobalCacheHitRatio;
}

bool DynBlockRulesGroup::DynBlockCacheMissRatioRule::ratioExceeded(unsigned int total, unsigned int count) const
{
  if (!DynBlockRulesGroup::DynBlockRatioRule::ratioExceeded(total, count)) {
    return false;
  }

  return checkGlobalCacheHitRatio();
}

bool DynBlockRulesGroup::DynBlockCacheMissRatioRule::warningRatioExceeded(unsigned int total, unsigned int count) const
{
  if (!DynBlockRulesGroup::DynBlockRatioRule::warningRatioExceeded(total, count)) {
    return false;
  }

  return checkGlobalCacheHitRatio();
}

std::string DynBlockRulesGroup::DynBlockCacheMissRatioRule::toString() const
{
  if (!isEnabled()) {
    return "";
  }

  std::stringstream result;
  if (d_action != DNSAction::Action::None) {
    result << DNSAction::typeToString(d_action) << " ";
  }
  else {
    result << "Apply the global DynBlock action ";
  }
  result << "for " << std::to_string(d_blockDuration) << " seconds when over " << std::to_string(d_ratio) << " ratio during the last " << d_seconds << " seconds, with a global cache-hit ratio of at least " << d_minimumGlobalCacheHitRatio << ", reason: '" << d_blockReason << "'";

  return result.str();
}

namespace dnsdist::DynamicBlocks
{
const ClientAddressDynamicRules& getClientAddressDynamicRules()
{
  static thread_local auto t_localRules = s_dynblockNMG.getLocal();
  return *t_localRules;
}

ClientAddressDynamicRules getClientAddressDynamicRulesCopy()
{
  return s_dynblockNMG.getCopy();
}

const SuffixDynamicRules& getSuffixDynamicRules()
{
  static thread_local auto t_localRules = s_dynblockSMT.getLocal();
  return *t_localRules;
}

SuffixDynamicRules getSuffixDynamicRulesCopy()
{
  return s_dynblockSMT.getCopy();
}

void setClientAddressDynamicRules(ClientAddressDynamicRules&& rules)
{
  s_dynblockNMG.setState(std::move(rules));
}

void setSuffixDynamicRules(SuffixDynamicRules&& rules)
{
  s_dynblockSMT.setState(std::move(rules));
}

void clearClientAddressDynamicRules()
{
  ClientAddressDynamicRules emptyNMG;
  setClientAddressDynamicRules(std::move(emptyNMG));
}

void clearSuffixDynamicRules()
{
  SuffixDynamicRules emptySMT;
  setSuffixDynamicRules(std::move(emptySMT));
}

LockGuarded<std::vector<std::shared_ptr<DynBlockRulesGroup>>> s_registeredDynamicBlockGroups;

void registerGroup(std::shared_ptr<DynBlockRulesGroup>& group)
{
  s_registeredDynamicBlockGroups.lock()->push_back(group);
}

void runRegisteredGroups(LuaContext& luaCtx)
{
  // only used to make sure we hold the Lua context lock
  (void)luaCtx;
  timespec now{};
  gettime(&now);
  for (auto& group : *s_registeredDynamicBlockGroups.lock()) {
    group->apply(now);
  }
}

}

#endif /* DISABLE_DYNBLOCKS */
