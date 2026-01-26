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

#ifndef DISABLE_DYNBLOCKS
#include <unordered_set>

#include "dolog.hh"
#include "dnsdist-rings.hh"
#include "gettime.hh"
#include "statnode.hh"

extern "C"
{
#include "dnsdist-lua-inspection-ffi.h"
}

#include "ext/luawrapper/include/LuaContext.hpp"

// dnsdist_ffi_stat_node_t is a lightuserdata
template <>
struct LuaContext::Pusher<dnsdist_ffi_stat_node_t*>
{
  static const int minSize = 1;
  static const int maxSize = 1;

  static PushedObject push(lua_State* state, dnsdist_ffi_stat_node_t* ptr) noexcept
  {
    lua_pushlightuserdata(state, ptr);
    return PushedObject{state, 1};
  }
};

using dnsdist_ffi_stat_node_visitor_t = std::function<bool(dnsdist_ffi_stat_node_t*)>;

struct SMTBlockParameters
{
  std::optional<std::string> d_reason;
  std::optional<DNSAction::Action> d_action;
};

struct dnsdist_ffi_stat_node_t
{
  dnsdist_ffi_stat_node_t(const StatNode& node_, const StatNode::Stat& self_, const StatNode::Stat& children_, SMTBlockParameters& blockParameters) :
    node(node_), self(self_), children(children_), d_blockParameters(blockParameters)
  {
  }

  const StatNode& node;
  const StatNode::Stat& self;
  const StatNode::Stat& children;
  SMTBlockParameters& d_blockParameters;
};

struct DynBlock
{
  DynBlock()
  {
    until.tv_sec = 0;
    until.tv_nsec = 0;
  }

  DynBlock(const std::string& reason_, const struct timespec& until_, const DNSName& domain_, DNSAction::Action action_) :
    reason(reason_), domain(domain_), until(until_), action(action_)
  {
  }

  DynBlock(const DynBlock& rhs) :
    reason(rhs.reason), domain(rhs.domain), until(rhs.until), tagSettings(rhs.tagSettings), action(rhs.action), warning(rhs.warning), bpf(rhs.bpf)
  {
    blocks.store(rhs.blocks);
  }

  DynBlock(DynBlock&& rhs) :
    reason(std::move(rhs.reason)), domain(std::move(rhs.domain)), until(rhs.until), tagSettings(std::move(rhs.tagSettings)), action(rhs.action), warning(rhs.warning), bpf(rhs.bpf)
  {
    blocks.store(rhs.blocks);
  }

  DynBlock& operator=(const DynBlock& rhs)
  {
    reason = rhs.reason;
    until = rhs.until;
    domain = rhs.domain;
    action = rhs.action;
    blocks.store(rhs.blocks);
    warning = rhs.warning;
    bpf = rhs.bpf;
    tagSettings = rhs.tagSettings;
    return *this;
  }

  DynBlock& operator=(DynBlock&& rhs)
  {
    reason = std::move(rhs.reason);
    until = rhs.until;
    domain = std::move(rhs.domain);
    action = rhs.action;
    blocks.store(rhs.blocks);
    warning = rhs.warning;
    bpf = rhs.bpf;
    tagSettings = std::move(rhs.tagSettings);
    return *this;
  }

  struct TagSettings
  {
    std::string d_name;
    std::string d_value;
  };

  string reason;
  DNSName domain;
  timespec until{};
  std::shared_ptr<TagSettings> tagSettings{nullptr};
  mutable std::atomic<uint32_t> blocks{0};
  DNSAction::Action action{DNSAction::Action::None};
  bool warning{false};
  bool bpf{false};
};

using dnsdist_ffi_dynamic_block_inserted_hook = std::function<void(uint8_t type, const char* key, const char* reason, uint8_t action, uint64_t duration, bool warning)>;
using ClientAddressDynamicRules = NetmaskTree<DynBlock, AddressAndPortRange>;
using SuffixDynamicRules = SuffixMatchTree<DynBlock>;

class DynBlockRulesGroup
{
public:
  struct DynBlockRule
  {
    DynBlockRule() = default;
    DynBlockRule(const std::string& blockReason, uint32_t blockDuration, uint32_t rate, uint32_t warningRate, uint32_t seconds, DNSAction::Action action) :
      d_blockReason(blockReason), d_blockDuration(blockDuration), d_rate(rate), d_warningRate(warningRate), d_seconds(seconds), d_action(action), d_enabled(true)
    {
    }

    bool matches(const struct timespec& when);
    bool rateExceeded(uint32_t count, const struct timespec& now) const;
    bool warningRateExceeded(uint32_t count, const struct timespec& now) const;

    bool isEnabled() const
    {
      return d_enabled;
    }

    std::string toString() const;

    std::string d_blockReason;
    std::shared_ptr<DynBlock::TagSettings> d_tagSettings;
    struct timespec d_cutOff;
    struct timespec d_minTime;
    uint32_t d_blockDuration{0};
    uint32_t d_rate{0};
    uint32_t d_warningRate{0};
    uint32_t d_seconds{0};
    DNSAction::Action d_action{DNSAction::Action::None};
    bool d_enabled{false};
  };

  struct DynBlockRatioRule : DynBlockRule
  {
    DynBlockRatioRule() = default;
    DynBlockRatioRule(const std::string& blockReason, uint32_t blockDuration, double ratio, double warningRatio, uint32_t seconds, DNSAction::Action action, size_t minimumNumberOfResponses) :
      DynBlockRule(blockReason, blockDuration, 0, 0, seconds, action), d_minimumNumberOfResponses(minimumNumberOfResponses), d_ratio(ratio), d_warningRatio(warningRatio)
    {
    }

    bool ratioExceeded(uint32_t total, uint32_t count) const;
    bool warningRatioExceeded(uint32_t total, uint32_t count) const;
    std::string toString() const;

    size_t d_minimumNumberOfResponses{0};
    double d_ratio{0.0};
    double d_warningRatio{0.0};
  };

  struct DynBlockCacheMissRatioRule : public DynBlockRatioRule
  {
    DynBlockCacheMissRatioRule() = default;
    DynBlockCacheMissRatioRule(const std::string& blockReason, uint32_t blockDuration, double ratio, double warningRatio, uint32_t seconds, DNSAction::Action action, size_t minimumNumberOfResponses, double minimumGlobalCacheHitRatio) :
      DynBlockRatioRule(blockReason, blockDuration, ratio, warningRatio, seconds, action, minimumNumberOfResponses), d_minimumGlobalCacheHitRatio(minimumGlobalCacheHitRatio)
    {
    }

    bool checkGlobalCacheHitRatio() const;
    bool ratioExceeded(uint32_t total, uint32_t count) const;
    bool warningRatioExceeded(uint32_t total, uint32_t count) const;
    std::string toString() const;

    double d_minimumGlobalCacheHitRatio{0.0};
  };

private:
  struct Counts
  {
    std::map<uint8_t, uint64_t> d_rcodeCounts;
    std::map<uint16_t, uint64_t> d_qtypeCounts;
    uint64_t queries{0};
    uint64_t responses{0};
    uint64_t respBytes{0};
    uint64_t cacheMisses{0};
  };
  using counts_t = std::unordered_map<AddressAndPortRange, Counts, AddressAndPortRange::hash>;

public:
  DynBlockRulesGroup()
  {
  }

  void setQueryRate(DynBlockRule&& rule)
  {
    d_queryRateRule = std::move(rule);
  }

  /* rate is in bytes per second */
  void setResponseByteRate(DynBlockRule&& rule)
  {
    d_respRateRule = std::move(rule);
  }

  void setRCodeRate(uint8_t rcode, DynBlockRule&& rule)
  {
    d_rcodeRules[rcode] = std::move(rule);
  }

  void setRCodeRatio(uint8_t rcode, DynBlockRatioRule&& rule)
  {
    d_rcodeRatioRules[rcode] = std::move(rule);
  }

  void setQTypeRate(uint16_t qtype, DynBlockRule&& rule)
  {
    d_qtypeRules[qtype] = std::move(rule);
  }

  void setCacheMissRatio(DynBlockCacheMissRatioRule&& rule)
  {
    d_respCacheMissRatioRule = std::move(rule);
  }

  using smtVisitor_t = std::function<std::tuple<bool, std::optional<std::string>, std::optional<int>>(const StatNode&, const StatNode::Stat&, const StatNode::Stat&)>;

  void setSuffixMatchRule(DynBlockRule&& rule, smtVisitor_t visitor)
  {
    d_suffixMatchRule = std::move(rule);
    d_smtVisitor = std::move(visitor);
  }

  void setSuffixMatchRuleFFI(DynBlockRule&& rule, dnsdist_ffi_stat_node_visitor_t visitor)
  {
    d_suffixMatchRule = std::move(rule);
    d_smtVisitorFFI = std::move(visitor);
  }

  void setNewBlockHook(const dnsdist_ffi_dynamic_block_inserted_hook& callback)
  {
    d_newBlockHook = callback;
  }

  void setMasks(uint8_t v4, uint8_t v6, uint8_t port)
  {
    d_v4Mask = v4;
    d_v6Mask = v6;
    d_portMask = port;
  }

  void apply()
  {
    timespec now{};
    gettime(&now);

    apply(now);
  }

  void apply(const timespec& now);

  void excludeRange(const Netmask& range)
  {
    d_excludedSubnets.addMask(range);
  }

  void excludeRange(const NetmaskGroup& group)
  {
    d_excludedSubnets.addMasks(group, true);
  }

  void includeRange(const Netmask& range)
  {
    d_excludedSubnets.addMask(range, false);
  }

  void includeRange(const NetmaskGroup& group)
  {
    d_excludedSubnets.addMasks(group, false);
  }

  void removeRange(const Netmask& range)
  {
    d_excludedSubnets.deleteMask(range);
  }

  void removeRange(const NetmaskGroup& group)
  {
    d_excludedSubnets.deleteMasks(group);
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
    result << "Response cache-miss ratio rule: " << d_respCacheMissRatioRule.toString() << std::endl;
    result << "RCode rules: " << std::endl;
    for (const auto& rule : d_rcodeRules) {
      result << "- " << RCode::to_s(rule.first) << ": " << rule.second.toString() << std::endl;
    }
    for (const auto& rule : d_rcodeRatioRules) {
      result << "- " << RCode::to_s(rule.first) << ": " << rule.second.toString() << std::endl;
    }
    result << "QType rules: " << std::endl;
    for (const auto& rule : d_qtypeRules) {
      result << "- " << QType(rule.first).toString() << ": " << rule.second.toString() << std::endl;
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
  void applySMT(const struct timespec& now, StatNode& statNodeRoot);
  bool checkIfQueryTypeMatches(const Rings::Query& query);
  bool checkIfResponseCodeMatches(const Rings::Response& response);
  void addOrRefreshBlock(std::optional<ClientAddressDynamicRules>& blocks, const struct timespec& now, const AddressAndPortRange& requestor, const DynBlockRule& rule, bool& updated, bool warning);
  void addOrRefreshBlockSMT(SuffixDynamicRules& blocks, const struct timespec& now, const DNSName& name, const DynBlockRule& rule, bool& updated);

  void addBlock(std::optional<ClientAddressDynamicRules>& blocks, const struct timespec& now, const AddressAndPortRange& requestor, const DynBlockRule& rule, bool& updated)
  {
    addOrRefreshBlock(blocks, now, requestor, rule, updated, false);
  }

  void handleWarning(std::optional<ClientAddressDynamicRules>& blocks, const struct timespec& now, const AddressAndPortRange& requestor, const DynBlockRule& rule, bool& updated)
  {
    addOrRefreshBlock(blocks, now, requestor, rule, updated, true);
  }

  bool hasQueryRules() const
  {
    return d_queryRateRule.isEnabled() || !d_qtypeRules.empty();
  }

  bool hasResponseRules() const
  {
    return d_respRateRule.isEnabled() || !d_rcodeRules.empty() || !d_rcodeRatioRules.empty() || d_respCacheMissRatioRule.isEnabled();
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
  DynBlockCacheMissRatioRule d_respCacheMissRatioRule;
  NetmaskGroup d_excludedSubnets;
  SuffixMatchNode d_excludedDomains;
  smtVisitor_t d_smtVisitor;
  dnsdist_ffi_stat_node_visitor_t d_smtVisitorFFI;
  dnsdist_ffi_dynamic_block_inserted_hook d_newBlockHook;
  uint8_t d_v6Mask{128};
  uint8_t d_v4Mask{32};
  uint8_t d_portMask{0};
  bool d_beQuiet{false};
};

class DynBlockMaintenance
{
public:
  static void run();

  /* return the (cached) number of hits per second for the top offenders, averaged over 60s */
  static std::map<std::string, std::list<std::pair<AddressAndPortRange, uint32_t>>> getHitsForTopNetmasks();
  static std::map<std::string, std::list<std::pair<DNSName, uint32_t>>> getHitsForTopSuffixes();

  /* get the top offenders based on the current value of the counters */
  static std::map<std::string, std::list<std::pair<AddressAndPortRange, uint32_t>>> getTopNetmasks(size_t topN);
  static std::map<std::string, std::list<std::pair<DNSName, uint32_t>>> getTopSuffixes(size_t topN);
  static void purgeExpired(const struct timespec& now);

private:
  static void collectMetrics();
  static void generateMetrics();

  struct MetricsSnapshot
  {
    std::map<std::string, std::list<std::pair<AddressAndPortRange, uint32_t>>> nmgData;
    std::map<std::string, std::list<std::pair<DNSName, uint32_t>>> smtData;
  };

  struct Tops
  {
    std::map<std::string, std::list<std::pair<AddressAndPortRange, uint32_t>>> topNMGsByReason;
    std::map<std::string, std::list<std::pair<DNSName, uint32_t>>> topSMTsByReason;
  };

  static LockGuarded<Tops> s_tops;
  /* s_metricsData should only be accessed by the dynamic blocks maintenance thread so it does not need a lock */
  // need N+1 datapoints to be able to do the diff after a collection point has been reached
  static std::list<MetricsSnapshot> s_metricsData;
  static constexpr size_t s_topN{20};
};

namespace dnsdist::DynamicBlocks
{
bool addOrRefreshBlock(ClientAddressDynamicRules& blocks, const timespec& now, const AddressAndPortRange& requestor, DynBlock&& dblock, bool beQuiet);
bool addOrRefreshBlockSMT(SuffixDynamicRules& blocks, const timespec& now, DynBlock&& dblock, bool beQuiet);

const ClientAddressDynamicRules& getClientAddressDynamicRules();
const SuffixDynamicRules& getSuffixDynamicRules();
ClientAddressDynamicRules getClientAddressDynamicRulesCopy();
SuffixDynamicRules getSuffixDynamicRulesCopy();
void setClientAddressDynamicRules(ClientAddressDynamicRules&& rules);
void setSuffixDynamicRules(SuffixDynamicRules&& rules);
void clearClientAddressDynamicRules();
void clearSuffixDynamicRules();

void registerGroup(std::shared_ptr<DynBlockRulesGroup>& group);
void runRegisteredGroups(LuaContext& luaCtx);
}
#endif /* DISABLE_DYNBLOCKS */
