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
#pragma once

#include <unordered_set>

#include "dolog.hh"
#include "dnsdist-rings.hh"
#include "statnode.hh"

#include "dnsdist-lua-inspection-ffi.hh"

// dnsdist_ffi_stat_node_t is a lightuserdata
template<>
struct LuaContext::Pusher<dnsdist_ffi_stat_node_t*> {
    static const int minSize = 1;
    static const int maxSize = 1;

    static PushedObject push(lua_State* state, dnsdist_ffi_stat_node_t* ptr) noexcept {
        lua_pushlightuserdata(state, ptr);
        return PushedObject{state, 1};
    }
};

typedef std::function<bool(dnsdist_ffi_stat_node_t*)> dnsdist_ffi_stat_node_visitor_t;

struct dnsdist_ffi_stat_node_t
{
  dnsdist_ffi_stat_node_t(const StatNode& node_, const StatNode::Stat& self_, const StatNode::Stat& children_): node(node_), self(self_), children(children_)
  {
  }

  const StatNode& node;
  const StatNode::Stat& self;
  const StatNode::Stat& children;
};

class DynBlockRulesGroup
{
private:

  struct Counts
  {
    std::map<uint8_t, uint64_t> d_rcodeCounts;
    std::map<uint16_t, uint64_t> d_qtypeCounts;
    uint64_t queries{0};
    uint64_t respBytes{0};
  };

  struct DynBlockRule
  {
    DynBlockRule(): d_enabled(false)
    {
    }

    DynBlockRule(const std::string& blockReason, unsigned int blockDuration, unsigned int rate, unsigned int warningRate, unsigned int seconds, DNSAction::Action action): d_blockReason(blockReason), d_blockDuration(blockDuration), d_rate(rate), d_warningRate(warningRate), d_seconds(seconds), d_action(action), d_enabled(true)
    {
    }

    bool matches(const struct timespec& when)
    {
      if (!d_enabled) {
        return false;
      }

      if (d_seconds && when < d_cutOff) {
        return false;
      }

      if (when < d_minTime) {
        d_minTime = when;
      }

      return true;
    }

    bool rateExceeded(unsigned int count, const struct timespec& now) const
    {
      if (!d_enabled) {
        return false;
      }

      double delta = d_seconds ? d_seconds : DiffTime(now, d_minTime);
      double limit = delta * d_rate;
      return (count > limit);
    }

    bool warningRateExceeded(unsigned int count, const struct timespec& now) const
    {
      if (d_warningRate == 0) {
        return false;
      }

      double delta = d_seconds ? d_seconds : DiffTime(now, d_minTime);
      double limit = delta * d_warningRate;
      return (count > limit);
    }

    bool isEnabled() const
    {
      return d_enabled;
    }

    std::string toString() const
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

    std::string d_blockReason;
    struct timespec d_cutOff;
    struct timespec d_minTime;
    unsigned int d_blockDuration{0};
    unsigned int d_rate{0};
    unsigned int d_warningRate{0};
    unsigned int d_seconds{0};
    DNSAction::Action d_action{DNSAction::Action::None};
    bool d_enabled{false};
  };

  typedef std::unordered_map<ComboAddress, Counts, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual> counts_t;

public:
  DynBlockRulesGroup()
  {
  }

  void setQueryRate(unsigned int rate, unsigned int warningRate, unsigned int seconds, std::string reason, unsigned int blockDuration, DNSAction::Action action)
  {
    d_queryRateRule = DynBlockRule(reason, blockDuration, rate, warningRate, seconds, action);
  }

  /* rate is in bytes per second */
  void setResponseByteRate(unsigned int rate, unsigned int warningRate, unsigned int seconds, std::string reason, unsigned int blockDuration, DNSAction::Action action)
  {
    d_respRateRule = DynBlockRule(reason, blockDuration, rate, warningRate, seconds, action);
  }

  void setRCodeRate(uint8_t rcode, unsigned int rate, unsigned int warningRate, unsigned int seconds, std::string reason, unsigned int blockDuration, DNSAction::Action action)
  {
    auto& entry = d_rcodeRules[rcode];
    entry = DynBlockRule(reason, blockDuration, rate, warningRate, seconds, action);
  }

  void setQTypeRate(uint16_t qtype, unsigned int rate, unsigned int warningRate, unsigned int seconds, std::string reason, unsigned int blockDuration, DNSAction::Action action)
  {
    auto& entry = d_qtypeRules[qtype];
    entry = DynBlockRule(reason, blockDuration, rate, warningRate, seconds, action);
  }

  typedef std::function<bool(const StatNode&, const StatNode::Stat&, const StatNode::Stat&)> smtVisitor_t;

  void setSuffixMatchRule(unsigned int seconds, std::string reason, unsigned int blockDuration, DNSAction::Action action, smtVisitor_t visitor)
  {
    d_suffixMatchRule = DynBlockRule(reason, blockDuration, 0, 0, seconds, action);
    d_smtVisitor = visitor;
  }

  void setSuffixMatchRuleFFI(unsigned int seconds, std::string reason, unsigned int blockDuration, DNSAction::Action action, dnsdist_ffi_stat_node_visitor_t visitor)
  {
    d_suffixMatchRule = DynBlockRule(reason, blockDuration, 0, 0, seconds, action);
    d_smtVisitorFFI = visitor;
  }

  void apply()
  {
    struct timespec now;
    gettime(&now);

    apply(now);
  }

  void apply(const struct timespec& now)
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
    }

    if (updated && blocks) {
      g_dynblockNMG.setState(*blocks);
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
          g_dynblockSMT.setState(smtBlocks);
        }
      }
    }
  }

  void excludeRange(const Netmask& range)
  {
    d_excludedSubnets.addMask(range);
  }

  void includeRange(const Netmask& range)
  {
    d_excludedSubnets.addMask(range, false);
  }

  void excludeDomain(const DNSName& domain)
  {
    d_excludedDomains.add(domain);
  }

  std::string toString() const
  {
    std::stringstream result;

    result << "Query rate rule: " << d_queryRateRule.toString() << std::endl;
    result << "Response rate rule: " << d_respRateRule.toString() << std::endl;
    result << "SuffixMatch rule: " << d_suffixMatchRule.toString() << std::endl;
    result << "RCode rules: " << std::endl;
    for (const auto& rule : d_rcodeRules) {
      result << "- " << RCode::to_s(rule.first) << ": " << rule.second.toString() << std::endl;
    }
    result << "QType rules: " << std::endl;
    for (const auto& rule : d_qtypeRules) {
      result << "- " << QType(rule.first).getName() << ": " << rule.second.toString() << std::endl;
    }
    result << "Excluded Subnets: " << d_excludedSubnets.toString() << std::endl;
    result << "Excluded Domains: " << d_excludedDomains.toString() << std::endl;

    return result.str();
  }

  void setQuiet(bool quiet)
  {
    d_beQuiet = quiet;
  }

private:
  bool checkIfQueryTypeMatches(const Rings::Query& query)
  {
    auto rule = d_qtypeRules.find(query.qtype);
    if (rule == d_qtypeRules.end()) {
      return false;
    }

    return rule->second.matches(query.when);
  }

  bool checkIfResponseCodeMatches(const Rings::Response& response)
  {
    auto rule = d_rcodeRules.find(response.dh.rcode);
    if (rule == d_rcodeRules.end()) {
      return false;
    }

    return rule->second.matches(response.when);
  }

  void addOrRefreshBlock(boost::optional<NetmaskTree<DynBlock> >& blocks, const struct timespec& now, const ComboAddress& requestor, const DynBlockRule& rule, bool& updated, bool warning)
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

  void addOrRefreshBlockSMT(SuffixMatchTree<DynBlock>& blocks, const struct timespec& now, const DNSName& name, const DynBlockRule& rule, bool& updated)
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

    DynBlock db{rule.d_blockReason, until, name, rule.d_action};
    db.blocks = count;

    if (!d_beQuiet && (!got || expired)) {
      warnlog("Inserting dynamic block for %s for %d seconds: %s", name, rule.d_blockDuration, rule.d_blockReason);
    }
    blocks.add(name, db);
    updated = true;
  }

  void addBlock(boost::optional<NetmaskTree<DynBlock> >& blocks, const struct timespec& now, const ComboAddress& requestor, const DynBlockRule& rule, bool& updated)
  {
    addOrRefreshBlock(blocks, now, requestor, rule, updated, false);
  }

  void handleWarning(boost::optional<NetmaskTree<DynBlock> >& blocks, const struct timespec& now, const ComboAddress& requestor, const DynBlockRule& rule, bool& updated)
  {
    addOrRefreshBlock(blocks, now, requestor, rule, updated, true);
  }

  bool hasQueryRules() const
  {
    return d_queryRateRule.isEnabled() || !d_qtypeRules.empty();
  }

  bool hasResponseRules() const
  {
    return d_respRateRule.isEnabled() || !d_rcodeRules.empty();
  }

  bool hasSuffixMatchRules() const
  {
    return d_suffixMatchRule.isEnabled();
  }

  bool hasRules() const
  {
    return hasQueryRules() || hasResponseRules();
  }

  void processQueryRules(counts_t& counts, const struct timespec& now)
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
            entry.queries++;
          }
          if (typeRuleMatches) {
            entry.d_qtypeCounts[c.qtype]++;
          }
        }
      }
    }
  }

  void processResponseRules(counts_t& counts, StatNode& root, const struct timespec& now)
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

    for (const auto& shard : g_rings.d_shards) {
      std::lock_guard<std::mutex> rl(shard->respLock);
      for(const auto& c : shard->respRing) {
        if (now < c.when) {
          continue;
        }

        bool respRateMatches = d_respRateRule.matches(c.when);
        bool suffixMatchRuleMatches = d_suffixMatchRule.matches(c.when);
        bool rcodeRuleMatches = checkIfResponseCodeMatches(c);

        if (respRateMatches || rcodeRuleMatches) {
          auto& entry = counts[c.requestor];
          if (respRateMatches) {
            entry.respBytes += c.size;
          }
          if (rcodeRuleMatches) {
            entry.d_rcodeCounts[c.dh.rcode]++;
          }
        }

        if (suffixMatchRuleMatches) {
          root.submit(c.name, c.dh.rcode, boost::none);
        }
      }
    }
  }

  std::map<uint8_t, DynBlockRule> d_rcodeRules;
  std::map<uint16_t, DynBlockRule> d_qtypeRules;
  DynBlockRule d_queryRateRule;
  DynBlockRule d_respRateRule;
  DynBlockRule d_suffixMatchRule;
  NetmaskGroup d_excludedSubnets;
  SuffixMatchNode d_excludedDomains;
  smtVisitor_t d_smtVisitor;
  dnsdist_ffi_stat_node_visitor_t d_smtVisitorFFI;
  bool d_beQuiet{false};
};
