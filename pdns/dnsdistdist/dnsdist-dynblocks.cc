
#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-metrics.hh"

GlobalStateHolder<NetmaskTree<DynBlock, AddressAndPortRange>> g_dynblockNMG;
GlobalStateHolder<SuffixMatchTree<DynBlock>> g_dynblockSMT;
DNSAction::Action g_dynBlockAction = DNSAction::Action::Drop;

#ifndef DISABLE_DYNBLOCKS

void DynBlockRulesGroup::apply(const struct timespec& now)
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

  boost::optional<NetmaskTree<DynBlock, AddressAndPortRange> > blocks;
  bool updated = false;

  for (const auto& entry : counts) {
    const auto& requestor = entry.first;
    const auto& counters = entry.second;

    if (d_queryRateRule.warningRateExceeded(counters.queries, now)) {
      handleWarning(blocks, now, requestor, d_queryRateRule, updated);
    }

    if (d_queryRateRule.rateExceeded(counters.queries, now)) {
      addBlock(blocks, now, requestor, d_queryRateRule, updated);
      continue;
    }

    if (d_respRateRule.warningRateExceeded(counters.respBytes, now)) {
      handleWarning(blocks, now, requestor, d_respRateRule, updated);
    }

    if (d_respRateRule.rateExceeded(counters.respBytes, now)) {
      addBlock(blocks, now, requestor, d_respRateRule, updated);
      continue;
    }

    for (const auto& pair : d_qtypeRules) {
      const auto qtype = pair.first;

      const auto& typeIt = counters.d_qtypeCounts.find(qtype);
      if (typeIt != counters.d_qtypeCounts.cend()) {

        if (pair.second.warningRateExceeded(typeIt->second, now)) {
          handleWarning(blocks, now, requestor, pair.second, updated);
        }

        if (pair.second.rateExceeded(typeIt->second, now)) {
          addBlock(blocks, now, requestor, pair.second, updated);
          break;
        }
      }
    }

    for (const auto& pair : d_rcodeRules) {
      const auto rcode = pair.first;

      const auto& rcodeIt = counters.d_rcodeCounts.find(rcode);
      if (rcodeIt != counters.d_rcodeCounts.cend()) {
        if (pair.second.warningRateExceeded(rcodeIt->second, now)) {
          handleWarning(blocks, now, requestor, pair.second, updated);
        }

        if (pair.second.rateExceeded(rcodeIt->second, now)) {
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
    g_dynblockNMG.setState(std::move(*blocks));
  }

  if (!statNodeRoot.empty()) {
    StatNode::Stat node;
    std::unordered_map<DNSName, std::optional<std::string>> namesToBlock;
    statNodeRoot.visit([this,&namesToBlock](const StatNode* node_, const StatNode::Stat& self, const StatNode::Stat& children) {
                         bool block = false;
                         std::optional<std::string> reason;

                         if (d_smtVisitorFFI) {
                           dnsdist_ffi_stat_node_t tmp(*node_, self, children, reason);
                           block = d_smtVisitorFFI(&tmp);
                         }
                         else {
                           auto ret = d_smtVisitor(*node_, self, children);
                           block = std::get<0>(ret);
                           if (block) {
                             if (boost::optional<std::string> tmp = std::get<1>(ret)) {
                               reason = std::move(*tmp);
                             }
                           }
                         }

                         if (block) {
                           namesToBlock.insert({DNSName(node_->fullname), std::move(reason)});
                         }
                       },
      node);

    if (!namesToBlock.empty()) {
      updated = false;
      SuffixMatchTree<DynBlock> smtBlocks = g_dynblockSMT.getCopy();
      for (auto& [name, reason] : namesToBlock) {
        if (reason) {
          DynBlockRule rule(d_suffixMatchRule);
          rule.d_blockReason = std::move(*reason);
          addOrRefreshBlockSMT(smtBlocks, now, std::move(name), std::move(rule), updated);
        }
        else {
          addOrRefreshBlockSMT(smtBlocks, now, std::move(name), d_suffixMatchRule, updated);
        }
      }
      if (updated) {
        g_dynblockSMT.setState(std::move(smtBlocks));
      }
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
  if (ratio != d_rcodeRatioRules.end() && ratio->second.matches(response.when)) {
    return true;
  }

  return false;
}

/* return the actual action that will be taken by that block:
   - either the one set on that block, if any
   - or the one set with setDynBlocksAction in g_dynBlockAction
*/
static DNSAction::Action getActualAction(const DynBlock& block)
{
  if (block.action != DNSAction::Action::None) {
    return block.action;
  }
  return g_dynBlockAction;
}

void DynBlockRulesGroup::addOrRefreshBlock(boost::optional<NetmaskTree<DynBlock, AddressAndPortRange> >& blocks, const struct timespec& now, const AddressAndPortRange& requestor, const DynBlockRule& rule, bool& updated, bool warning)
{
  /* network exclusions are address-based only (no port) */
  if (d_excludedSubnets.match(requestor.getNetwork())) {
    /* do not add a block for excluded subnets */
    return;
  }

  if (!blocks) {
    blocks = g_dynblockNMG.getCopy();
  }
  struct timespec until = now;
  until.tv_sec += rule.d_blockDuration;
  unsigned int count = 0;
  const auto& got = blocks->lookup(requestor);
  bool expired = false;
  bool wasWarning = false;
  bool bpf = false;

  if (got) {
    bpf = got->second.bpf;

    if (warning && !got->second.warning) {
      /* we have an existing entry which is not a warning,
         don't override it */
      return;
    }
    else if (!warning && got->second.warning) {
      wasWarning = true;
    }
    else {
      if (until < got->second.until) {
        // had a longer policy
        return;
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

  DynBlock db{rule.d_blockReason, until, DNSName(), warning ? DNSAction::Action::NoOp : rule.d_action};
  db.blocks = count;
  db.warning = warning;
  if (!got || expired || wasWarning) {
    const auto actualAction = getActualAction(db);
    if (g_defaultBPFFilter &&
        ((requestor.isIPv4() && requestor.getBits() == 32) || (requestor.isIPv6() && requestor.getBits() == 128)) &&
        (actualAction == DNSAction::Action::Drop || actualAction == DNSAction::Action::Truncate)) {
      try {
        BPFFilter::MatchAction bpfAction = actualAction == DNSAction::Action::Drop ? BPFFilter::MatchAction::Drop : BPFFilter::MatchAction::Truncate;
        if (g_defaultBPFFilter->supportsMatchAction(bpfAction)) {
          /* the current BPF filter implementation only supports full addresses (/32 or /128) and no port */
          g_defaultBPFFilter->block(requestor.getNetwork(), bpfAction);
          bpf = true;
        }
      }
      catch (const std::exception& e) {
        vinfolog("Unable to insert eBPF dynamic block for %s, falling back to regular dynamic block: %s", requestor.toString(), e.what());
      }
    }

    if (!d_beQuiet) {
      warnlog("Inserting %sdynamic block for %s for %d seconds: %s", warning ? "(warning) " :"", requestor.toString(), rule.d_blockDuration, rule.d_blockReason);
    }
  }

  db.bpf = bpf;

  blocks->insert(requestor).second = std::move(db);

  updated = true;
}

void DynBlockRulesGroup::addOrRefreshBlockSMT(SuffixMatchTree<DynBlock>& blocks, const struct timespec& now, const DNSName& name, const DynBlockRule& rule, bool& updated)
{
  if (d_excludedDomains.check(name)) {
    /* do not add a block for excluded domains */
    return;
  }

  struct timespec until = now;
  until.tv_sec += rule.d_blockDuration;
  unsigned int count = 0;
  /* be careful, if you try to insert a longer suffix
     lookup() might return a shorter one if it is
     already in the tree as a final node */
  const DynBlock* got = blocks.lookup(name);
  if (got && got->domain != name) {
    got = nullptr;
  }
  bool expired = false;

  if (got) {
    if (until < got->until) {
      // had a longer policy
      return;
    }

    if (now < got->until) {
      // only inherit count on fresh query we are extending
      count = got->blocks;
    }
    else {
      expired = true;
    }
  }

  DynBlock db{rule.d_blockReason, until, name.makeLowerCase(), rule.d_action};
  db.blocks = count;

  if (!d_beQuiet && (!got || expired)) {
    warnlog("Inserting dynamic block for %s for %d seconds: %s", name, rule.d_blockDuration, rule.d_blockReason);
  }
  blocks.add(name, std::move(db));
  updated = true;
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
    auto rl = shard->queryRing.lock();
    for(const auto& c : *rl) {
      if (now < c.when) {
        continue;
      }

      bool qRateMatches = d_queryRateRule.matches(c.when);
      bool typeRuleMatches = checkIfQueryTypeMatches(c);

      if (qRateMatches || typeRuleMatches) {
        auto& entry = counts[AddressAndPortRange(c.requestor, c.requestor.isIPv4() ? d_v4Mask : d_v6Mask, d_portMask)];
        if (qRateMatches) {
          ++entry.queries;
        }
        if (typeRuleMatches) {
          ++entry.d_qtypeCounts[c.qtype];
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
    auto rl = shard->respRing.lock();
    for(const auto& c : *rl) {
      if (now < c.when) {
        continue;
      }

      if (c.when < responseCutOff) {
        continue;
      }

      auto& entry = counts[AddressAndPortRange(c.requestor, c.requestor.isIPv4() ? d_v4Mask : d_v6Mask, d_portMask)];
      ++entry.responses;

      bool respRateMatches = d_respRateRule.matches(c.when);
      bool suffixMatchRuleMatches = d_suffixMatchRule.matches(c.when);
      bool rcodeRuleMatches = checkIfResponseCodeMatches(c);

      if (respRateMatches || rcodeRuleMatches) {
        if (respRateMatches) {
          entry.respBytes += c.size;
        }
        if (rcodeRuleMatches) {
          ++entry.d_rcodeCounts[c.dh.rcode];
        }
      }

      if (suffixMatchRuleMatches) {
        bool hit = c.ds.sin4.sin_family == 0;
        if (!hit && c.ds.isIPv4() && c.ds.sin4.sin_addr.s_addr == 0 && c.ds.sin4.sin_port == 0) {
          hit = true;
        }

        root.submit(c.name, ((c.dh.rcode == 0 && c.usec == std::numeric_limits<unsigned int>::max()) ? -1 : c.dh.rcode), c.size, hit, boost::none);
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
    auto blocks = g_dynblockNMG.getLocal();
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
            vinfolog("Error while getting block count before removing eBPF dynamic block for %s: %s", entry.first.toString(), e.what());
          }
          try {
            g_defaultBPFFilter->unblock(network);
          }
          catch (const std::exception& e) {
            vinfolog("Error while removing eBPF dynamic block for %s: %s", entry.first.toString(), e.what());
          }
        }
      }
    }
    if (!toRemove.empty()) {
      auto updated = g_dynblockNMG.getCopy();
      for (const auto& entry : toRemove) {
        updated.erase(entry);
      }
      g_dynblockNMG.setState(std::move(updated));
      dnsdist::metrics::g_stats.dynBlocked += bpfBlocked;
    }
  }

  {
    std::vector<DNSName> toRemove;
    auto blocks = g_dynblockSMT.getLocal();
    blocks->visit([&toRemove, now](const SuffixMatchTree<DynBlock>& node) {
      if (!(now < node.d_value.until)) {
        toRemove.push_back(node.d_value.domain);
      }
    });
    if (!toRemove.empty()) {
      auto updated = g_dynblockSMT.getCopy();
      for (const auto& entry : toRemove) {
        updated.remove(entry);
      }
      g_dynblockSMT.setState(std::move(updated));
    }
  }
}

std::map<std::string, std::list<std::pair<AddressAndPortRange, unsigned int>>> DynBlockMaintenance::getTopNetmasks(size_t topN)
{
  std::map<std::string, std::list<std::pair<AddressAndPortRange, unsigned int>>> results;
  if (topN == 0) {
    return results;
  }

  auto blocks = g_dynblockNMG.getLocal();
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

      topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<AddressAndPortRange, unsigned int>& a, const std::pair<AddressAndPortRange, unsigned int>& b) {
        return a.second < b.second;
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

  auto blocks = g_dynblockSMT.getLocal();
  blocks->visit([&results, topN](const SuffixMatchTree<DynBlock>& node) {
    auto& topsForReason = results[node.d_value.reason];
    if (topsForReason.size() < topN || topsForReason.front().second < node.d_value.blocks) {
      auto newEntry = std::pair(node.d_value.domain, node.d_value.blocks.load());

      if (topsForReason.size() >= topN) {
        topsForReason.pop_front();
      }

      topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<DNSName, unsigned int>& a, const std::pair<DNSName, unsigned int>& b) {
        return a.second < b.second;
      }),
        newEntry);
    }
  });

  return results;
}

struct DynBlockEntryStat
{
  size_t sum;
  unsigned int lastSeenValue{0};
};

std::list<DynBlockMaintenance::MetricsSnapshot> DynBlockMaintenance::s_metricsData;

LockGuarded<DynBlockMaintenance::Tops> DynBlockMaintenance::s_tops;
size_t DynBlockMaintenance::s_topN{20};
time_t DynBlockMaintenance::s_expiredDynBlocksPurgeInterval{60};

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
  std::map<std::string, std::map<AddressAndPortRange, DynBlockEntryStat>> nm;
  for (const auto& reason : s_metricsData.front().nmgData) {
    auto& reasonStat = nm[reason.first];

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

    auto& nmgData = snap.nmgData;
    for (const auto& reason : nmgData) {
      auto& reasonStat = nm[reason.first];
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
    for (const auto& reason : nm) {
      auto& topsForReason = topNMGs[reason.first];
      for (const auto& entry : reason.second) {
        if (topsForReason.size() < s_topN || topsForReason.front().second < entry.second.sum) {
          /* Note that this is a gauge, so we need to divide by the number of elapsed seconds */
          auto newEntry = std::pair<AddressAndPortRange, unsigned int>(entry.first, std::round(entry.second.sum / 60.0));
          if (topsForReason.size() >= s_topN) {
            topsForReason.pop_front();
          }

          topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<AddressAndPortRange, unsigned int>& a, const std::pair<AddressAndPortRange, unsigned int>& b) {
            return a.second < b.second;
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

    auto& smtData = snap.smtData;
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
          auto newEntry = std::pair<DNSName, unsigned int>(entry.first, std::round(entry.second.sum / 60.0));
          if (topsForReason.size() >= s_topN) {
            topsForReason.pop_front();
          }

          topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<DNSName, unsigned int>& a, const std::pair<DNSName, unsigned int>& b) {
            return a.second < b.second;
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
  time_t nextExpiredPurge = now + s_expiredDynBlocksPurgeInterval;
  time_t nextMetricsCollect = now + metricsCollectionInterval;
  time_t nextMetricsGeneration = now + metricsGenerationInterval;

  while (true) {
    time_t sleepDelay = std::numeric_limits<time_t>::max();
    if (s_expiredDynBlocksPurgeInterval > 0) {
      sleepDelay = std::min(sleepDelay, (nextExpiredPurge - now));
    }
    sleepDelay = std::min(sleepDelay, (nextMetricsCollect - now));
    sleepDelay = std::min(sleepDelay, (nextMetricsGeneration - now));

    // coverity[store_truncates_time_t]
    sleep(sleepDelay);

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

      if (s_expiredDynBlocksPurgeInterval > 0 && now >= nextExpiredPurge) {
        struct timespec tspec;
        gettime(&tspec);
        purgeExpired(tspec);

        now = time(nullptr);
        nextExpiredPurge = now + s_expiredDynBlocksPurgeInterval;
      }
    }
    catch (const std::exception& e) {
      warnlog("Error in the dynamic block maintenance thread: %s", e.what());
    }
    catch (...) {
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
#endif /* DISABLE_DYNBLOCKS */
