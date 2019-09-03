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

  struct DynBlockRatioRule: DynBlockRule
  {
    DynBlockRatioRule(): DynBlockRule()
    {
    }

    DynBlockRatioRule(const std::string& blockReason, unsigned int blockDuration, double ratio, double warningRatio, unsigned int seconds, DNSAction::Action action, size_t minimumNumberOfResponses): DynBlockRule(blockReason, blockDuration, 0, 0, seconds, action), d_minimumNumberOfResponses(minimumNumberOfResponses), d_ratio(ratio), d_warningRatio(warningRatio)
    {
    }

    bool ratioExceeded(unsigned int total, unsigned int count) const
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

    bool warningRatioExceeded(unsigned int total, unsigned int count) const
    {
      if (d_warningRate == 0) {
        return false;
      }

      if (total < d_minimumNumberOfResponses) {
        return false;
      }

      double allowed = d_warningRatio * static_cast<double>(total);
      return (count > allowed);
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
      result << "for " << std::to_string(d_blockDuration) << " seconds when over " << std::to_string(d_ratio) << " ratio during the last " << d_seconds << " seconds, reason: '" << d_blockReason << "'";

      return result.str();
    }

    size_t d_minimumNumberOfResponses{0};
    double d_ratio{0.0};
    double d_warningRatio{0.0};
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

  void setRCodeRatio(uint8_t rcode, double ratio, double warningRatio, unsigned int seconds, std::string reason, unsigned int blockDuration, DNSAction::Action action, size_t minimumNumberOfResponses)
  {
    auto& entry = d_rcodeRatioRules[rcode];
    entry = DynBlockRatioRule(reason, blockDuration, ratio, warningRatio, seconds, action, minimumNumberOfResponses);
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

  void apply(const struct timespec& now);

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
    for (const auto& rule : d_rcodeRatioRules) {
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

  bool checkIfQueryTypeMatches(const Rings::Query& query);
  bool checkIfResponseCodeMatches(const Rings::Response& response);
  void addOrRefreshBlock(boost::optional<NetmaskTree<DynBlock> >& blocks, const struct timespec& now, const ComboAddress& requestor, const DynBlockRule& rule, bool& updated, bool warning);
  void addOrRefreshBlockSMT(SuffixMatchTree<DynBlock>& blocks, const struct timespec& now, const DNSName& name, const DynBlockRule& rule, bool& updated);

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
    return d_respRateRule.isEnabled() || !d_rcodeRules.empty() || !d_rcodeRatioRules.empty();
  }

  bool hasSuffixMatchRules() const
  {
    return d_suffixMatchRule.isEnabled();
  }

  bool hasRules() const
  {
    return hasQueryRules() || hasResponseRules();
  }

  void processQueryRules(counts_t& counts, const struct timespec& now);
  void processResponseRules(counts_t& counts, StatNode& root, const struct timespec& now);

  std::map<uint8_t, DynBlockRule> d_rcodeRules;
  std::map<uint8_t, DynBlockRatioRule> d_rcodeRatioRules;
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
