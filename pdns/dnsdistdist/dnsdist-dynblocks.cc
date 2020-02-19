
#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"

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

  boost::optional<NetmaskTree<DynBlock>> blocks;
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
        if (pair.second.warningRatioExceeded(counters.queries, rcodeIt->second)) {
          handleWarning(blocks, now, requestor, pair.second, updated);
        }

        if (pair.second.ratioExceeded(counters.queries, rcodeIt->second)) {
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
    std::unordered_set<DNSName> namesToBlock;
    statNodeRoot.visit([this, &namesToBlock](const StatNode* node_, const StatNode::Stat& self, const StatNode::Stat& children) {
      bool block = false;

      if (d_smtVisitorFFI) {
        dnsdist_ffi_stat_node_t tmp(*node_, self, children);
        block = d_smtVisitorFFI(&tmp);
      }
      else {
        block = d_smtVisitor(*node_, self, children);
      }

      if (block) {
        namesToBlock.insert(DNSName(node_->fullname));
      }
    },
      node);

    if (!namesToBlock.empty()) {
      updated = false;
      SuffixMatchTree<DynBlock> smtBlocks = g_dynblockSMT.getCopy();
      for (const auto& name : namesToBlock) {
        addOrRefreshBlockSMT(smtBlocks, now, name, d_suffixMatchRule, updated);
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

void DynBlockRulesGroup::addOrRefreshBlock(boost::optional<NetmaskTree<DynBlock>>& blocks, const struct timespec& now, const ComboAddress& requestor, const DynBlockRule& rule, bool& updated, bool warning)
{
  if (d_excludedSubnets.match(requestor)) {
    /* do not add a block for excluded subnets */
    return;
  }

  if (!blocks) {
    blocks = g_dynblockNMG.getCopy();
  }
  struct timespec until = now;
  until.tv_sec += rule.d_blockDuration;
  unsigned int count = 0;
  const auto& got = blocks->lookup(Netmask(requestor));
  bool expired = false;
  bool wasWarning = false;

  if (got) {
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
  if (!d_beQuiet && (!got || expired || wasWarning)) {
    warnlog("Inserting %sdynamic block for %s for %d seconds: %s", warning ? "(warning) " : "", requestor.toString(), rule.d_blockDuration, rule.d_blockReason);
  }
  blocks->insert(Netmask(requestor)).second = db;
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
  const auto& got = blocks.lookup(name);
  bool expired = false;
  DNSName domain(name.makeLowerCase());

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

  DynBlock db{rule.d_blockReason, until, domain, rule.d_action};
  db.blocks = count;

  if (!d_beQuiet && (!got || expired)) {
    warnlog("Inserting dynamic block for %s for %d seconds: %s", domain, rule.d_blockDuration, rule.d_blockReason);
  }
  blocks.add(domain, db);
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
    std::lock_guard<std::mutex> rl(shard->queryLock);
    for (const auto& c : shard->queryRing) {
      if (now < c.when) {
        continue;
      }

      bool qRateMatches = d_queryRateRule.matches(c.when);
      bool typeRuleMatches = checkIfQueryTypeMatches(c);

      if (qRateMatches || typeRuleMatches) {
        auto& entry = counts[c.requestor];
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

  d_respRateRule.d_cutOff = d_respRateRule.d_minTime = now;
  d_respRateRule.d_cutOff.tv_sec -= d_respRateRule.d_seconds;

  d_suffixMatchRule.d_cutOff = d_suffixMatchRule.d_minTime = now;
  d_suffixMatchRule.d_cutOff.tv_sec -= d_suffixMatchRule.d_seconds;

  for (auto& rule : d_rcodeRules) {
    rule.second.d_cutOff = rule.second.d_minTime = now;
    rule.second.d_cutOff.tv_sec -= rule.second.d_seconds;
  }

  for (auto& rule : d_rcodeRatioRules) {
    rule.second.d_cutOff = rule.second.d_minTime = now;
    rule.second.d_cutOff.tv_sec -= rule.second.d_seconds;
  }

  for (const auto& shard : g_rings.d_shards) {
    std::lock_guard<std::mutex> rl(shard->respLock);
    for (const auto& c : shard->respRing) {
      if (now < c.when) {
        continue;
      }

      auto& entry = counts[c.requestor];
      ++entry.queries;
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
        root.submit(c.name, ((c.dh.rcode == 0 && c.usec == std::numeric_limits<unsigned int>::max()) ? -1 : c.dh.rcode), c.size, boost::none);
      }
    }
  }
}
