
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

  boost::optional<NetmaskTree<DynBlock> > blocks;
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
    std::unordered_set<DNSName> namesToBlock;
    statNodeRoot.visit([this,&namesToBlock](const StatNode* node_, const StatNode::Stat& self, const StatNode::Stat& children) {
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

void DynBlockRulesGroup::addOrRefreshBlock(boost::optional<NetmaskTree<DynBlock> >& blocks, const struct timespec& now, const ComboAddress& requestor, const DynBlockRule& rule, bool& updated, bool warning)
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
    warnlog("Inserting %sdynamic block for %s for %d seconds: %s", warning ? "(warning) " :"", requestor.toString(), rule.d_blockDuration, rule.d_blockReason);
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
    std::lock_guard<std::mutex> rl(shard->queryLock);
    for(const auto& c : shard->queryRing) {
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
    std::lock_guard<std::mutex> rl(shard->respLock);
    for(const auto& c : shard->respRing) {
      if (now < c.when) {
        continue;
      }

      if (c.when < responseCutOff) {
        continue;
      }

      auto& entry = counts[c.requestor];
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
        root.submit(c.name, ((c.dh.rcode == 0 && c.usec == std::numeric_limits<unsigned int>::max()) ? -1 : c.dh.rcode), c.size, boost::none);
      }
    }
  }
}

void DynBlockMaintenance::purgeExpired(const struct timespec& now)
{
  {
    auto blocks = g_dynblockNMG.getLocal();
    std::vector<Netmask> toRemove;
    for (const auto& entry : *blocks) {
      if (!(now < entry.second.until)) {
        toRemove.push_back(entry.first);
      }
    }
    if (!toRemove.empty()) {
      auto updated = g_dynblockNMG.getCopy();
      for (const auto& entry : toRemove) {
        updated.erase(entry);
      }
      g_dynblockNMG.setState(std::move(updated));
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

std::map<std::string, std::list<std::pair<Netmask, unsigned int>>> DynBlockMaintenance::getTopNetmasks(size_t topN)
{
  std::map<std::string, std::list<std::pair<Netmask, unsigned int>>> results;
  if (topN == 0) {
    return results;
  }

  auto blocks = g_dynblockNMG.getLocal();
  for (const auto& entry : *blocks) {
    auto& topsForReason = results[entry.second.reason];
    if (topsForReason.size() < topN || topsForReason.front().second < entry.second.blocks) {
      auto newEntry = std::make_pair(entry.first, entry.second.blocks.load());

      if (topsForReason.size() >= topN) {
        topsForReason.pop_front();
      }

      topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<Netmask, unsigned int>& a, const std::pair<Netmask, unsigned int>& b) {
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
      auto newEntry = std::make_pair(node.d_value.domain, node.d_value.blocks.load());

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

std::mutex DynBlockMaintenance::s_topsMutex;
std::list<DynBlockMaintenance::MetricsSnapshot> DynBlockMaintenance::s_metricsData;
std::map<std::string, std::list<std::pair<Netmask, unsigned int>>> DynBlockMaintenance::s_topNMGsByReason;
std::map<std::string, std::list<std::pair<DNSName, unsigned int>>> DynBlockMaintenance::s_topSMTsByReason;
size_t DynBlockMaintenance::s_topN{20};
time_t DynBlockMaintenance::s_expiredDynBlocksPurgeInterval{300};

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
  std::map<std::string, std::map<Netmask, DynBlockEntryStat>> nm;
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
  std::map<std::string, std::list<std::pair<Netmask, unsigned int>>> topNMGs;
  {
    for (const auto& reason : nm) {
      auto& topsForReason = topNMGs[reason.first];
      for (const auto& entry : reason.second) {
        if (topsForReason.size() < s_topN || topsForReason.front().second < entry.second.sum) {
          /* Note that this is a gauge, so we need to divide by the number of elapsed seconds */
          auto newEntry = std::pair<Netmask, unsigned int>(entry.first, std::round(entry.second.sum / 60.0));
          if (topsForReason.size() >= s_topN) {
            topsForReason.pop_front();
          }

          topsForReason.insert(std::lower_bound(topsForReason.begin(), topsForReason.end(), newEntry, [](const std::pair<Netmask, unsigned int>& a, const std::pair<Netmask, unsigned int>& b) {
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
    std::lock_guard<std::mutex> lock(s_topsMutex);
    s_topNMGsByReason = std::move(topNMGs);
    s_topSMTsByReason = std::move(topSMTs);
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

std::map<std::string, std::list<std::pair<Netmask, unsigned int>>> DynBlockMaintenance::getHitsForTopNetmasks()
{
  std::lock_guard<std::mutex> lock(s_topsMutex);
  return s_topNMGsByReason;
}

std::map<std::string, std::list<std::pair<DNSName, unsigned int>>> DynBlockMaintenance::getHitsForTopSuffixes()
{
  std::lock_guard<std::mutex> lock(s_topsMutex);
  return s_topSMTsByReason;
}
