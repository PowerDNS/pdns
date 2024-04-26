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
GlobalStateHolder<std::vector<RuleAction>> s_ruleActions;
GlobalStateHolder<std::vector<RuleAction>> s_cacheMissRuleActions;
GlobalStateHolder<std::vector<ResponseRuleAction>> s_respruleactions;
GlobalStateHolder<std::vector<ResponseRuleAction>> s_cachehitrespruleactions;
GlobalStateHolder<std::vector<ResponseRuleAction>> s_selfansweredrespruleactions;
GlobalStateHolder<std::vector<ResponseRuleAction>> s_cacheInsertedRespRuleActions;
GlobalStateHolder<std::vector<ResponseRuleAction>> s_XFRRespRuleActions;

static const std::vector<ResponseRuleChainDescription> s_responseRuleChains{
  {"", "response-rules", s_respruleactions},
  {"CacheHit", "cache-hit-response-rules", s_cachehitrespruleactions},
  {"CacheInserted", "cache-inserted-response-rules", s_selfansweredrespruleactions},
  {"SelfAnswered", "self-answered-response-rules", s_cacheInsertedRespRuleActions},
  {"XFR", "xfr-response-rules", s_XFRRespRuleActions},
};

const std::vector<ResponseRuleChainDescription>& getResponseRuleChains()
{
  return s_responseRuleChains;
}

GlobalStateHolder<std::vector<ResponseRuleAction>>& getResponseRuleChainHolder(ResponseRuleChain chain)
{
  return s_responseRuleChains.at(static_cast<size_t>(chain)).holder;
}

static const std::vector<RuleChainDescription> s_ruleChains{
  {"", "rules", s_ruleActions},
  {"CacheMiss", "cache-miss-rules", s_cacheMissRuleActions},
};

const std::vector<RuleChainDescription>& getRuleChains()
{
  return s_ruleChains;
}

GlobalStateHolder<std::vector<RuleAction>>& getRuleChainHolder(RuleChain chain)
{
  return s_ruleChains.at(static_cast<size_t>(chain)).holder;
}
}
