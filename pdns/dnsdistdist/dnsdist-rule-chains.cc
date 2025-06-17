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

#include "dnsdist-rule-chains.hh"

namespace dnsdist::rules
{
static const std::vector<ResponseRuleChainDescription> s_responseRuleChains{
  {"", "response", "response-rules", ResponseRuleChain::ResponseRules},
  {"CacheHit", "cache hit", "cache-hit-response-rules", ResponseRuleChain::CacheHitResponseRules},
  {"CacheInserted", "cache inserted", "cache-inserted-response-rules", ResponseRuleChain::CacheInsertedResponseRules},
  {"SelfAnswered", "self-answered", "self-answered-response-rules", ResponseRuleChain::SelfAnsweredResponseRules},
  {"XFR", "xfr", "xfr-response-rules", ResponseRuleChain::XFRResponseRules},
  {"Timeout", "timeout", "timeout-response-rules", ResponseRuleChain::TimeoutResponseRules},
};

const std::vector<ResponseRuleChainDescription>& getResponseRuleChainDescriptions()
{
  return s_responseRuleChains;
}

static const std::vector<RuleChainDescription> s_ruleChains{
  {"", "", "rules", RuleChain::Rules},
  {"CacheMiss", "cache-miss", "cache-miss-rules", RuleChain::CacheMissRules},
};

const std::vector<RuleChainDescription>& getRuleChainDescriptions()
{
  return s_ruleChains;
}

std::vector<RuleAction>& getRuleChain(RuleChains& chains, RuleChain chain)
{
  switch (chain) {
  case RuleChain::Rules:
    return chains.d_ruleActions;
  case RuleChain::CacheMissRules:
    return chains.d_cacheMissRuleActions;
  }

  throw std::runtime_error("Trying to accept an invalid rule chain");
}

const std::vector<RuleAction>& getRuleChain(const RuleChains& chains, RuleChain chain)
{
  switch (chain) {
  case RuleChain::Rules:
    return chains.d_ruleActions;
  case RuleChain::CacheMissRules:
    return chains.d_cacheMissRuleActions;
  }

  throw std::runtime_error("Trying to accept an invalid rule chain");
}

std::vector<ResponseRuleAction>& getRuleChain(RuleChains& chains, ResponseRuleChain chain)
{
  return getResponseRuleChain(chains, chain);
}

const std::vector<ResponseRuleAction>& getRuleChain(const RuleChains& chains, ResponseRuleChain chain)
{
  return getResponseRuleChain(chains, chain);
}

std::vector<ResponseRuleAction>& getResponseRuleChain(RuleChains& chains, ResponseRuleChain chain)
{
  switch (chain) {
  case ResponseRuleChain::ResponseRules:
    return chains.d_respruleactions;
  case ResponseRuleChain::CacheHitResponseRules:
    return chains.d_cachehitrespruleactions;
  case ResponseRuleChain::CacheInsertedResponseRules:
    return chains.d_cacheInsertedRespRuleActions;
  case ResponseRuleChain::SelfAnsweredResponseRules:
    return chains.d_selfansweredrespruleactions;
  case ResponseRuleChain::XFRResponseRules:
    return chains.d_XFRRespRuleActions;
  case ResponseRuleChain::TimeoutResponseRules:
    return chains.d_TimeoutRespRuleActions;
  }

  throw std::runtime_error("Trying to accept an invalid response rule chain");
}

const std::vector<ResponseRuleAction>& getResponseRuleChain(const RuleChains& chains, ResponseRuleChain chain)
{
  switch (chain) {
  case ResponseRuleChain::ResponseRules:
    return chains.d_respruleactions;
  case ResponseRuleChain::CacheHitResponseRules:
    return chains.d_cachehitrespruleactions;
  case ResponseRuleChain::CacheInsertedResponseRules:
    return chains.d_cacheInsertedRespRuleActions;
  case ResponseRuleChain::SelfAnsweredResponseRules:
    return chains.d_selfansweredrespruleactions;
  case ResponseRuleChain::XFRResponseRules:
    return chains.d_XFRRespRuleActions;
  case ResponseRuleChain::TimeoutResponseRules:
    return chains.d_TimeoutRespRuleActions;
  }

  throw std::runtime_error("Trying to accept an invalid response rule chain");
}

void add(RuleChains& chains, RuleChain identifier, const std::shared_ptr<DNSRule>& selector, const std::shared_ptr<DNSAction>& action, std::string&& name, const boost::uuids::uuid& uuid, uint64_t creationOrder)
{
  auto& chain = getRuleChain(chains, identifier);
  chain.push_back({selector, action, std::move(name), uuid, creationOrder});
}

void add(RuleChains& chains, ResponseRuleChain identifier, const std::shared_ptr<DNSRule>& selector, const std::shared_ptr<DNSResponseAction>& action, std::string&& name, const boost::uuids::uuid& uuid, uint64_t creationOrder)
{
  auto& chain = getResponseRuleChain(chains, identifier);
  chain.push_back({selector, action, std::move(name), uuid, creationOrder});
}

}
