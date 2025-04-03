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

#include <memory>
#include <string>
#include <vector>

#include "uuid-utils.hh"

class DNSRule;
class DNSAction;
class DNSResponseAction;

namespace dnsdist::rules
{
struct RuleAction
{
  std::shared_ptr<DNSRule> d_rule;
  std::shared_ptr<DNSAction> d_action;
  std::string d_name;
  boost::uuids::uuid d_id;
  uint64_t d_creationOrder;
};

enum class RuleChain : uint8_t
{
  Rules = 0,
  CacheMissRules = 1,
};

struct RuleChainDescription
{
  const std::string prefix;
  const std::string metricName;
  const RuleChain identifier;
};

struct ResponseRuleAction
{
  std::shared_ptr<DNSRule> d_rule;
  std::shared_ptr<DNSResponseAction> d_action;
  std::string d_name;
  boost::uuids::uuid d_id;
  uint64_t d_creationOrder;
};

enum class ResponseRuleChain : uint8_t
{
  ResponseRules = 0,
  CacheHitResponseRules = 1,
  CacheInsertedResponseRules = 2,
  SelfAnsweredResponseRules = 3,
  XFRResponseRules = 4,
  TimeoutResponseRules = 5,
};

struct ResponseRuleChainDescription
{
  const std::string prefix;
  const std::string metricName;
  const ResponseRuleChain identifier;
};

struct RuleChains
{
  std::vector<RuleAction> d_ruleActions;
  std::vector<RuleAction> d_cacheMissRuleActions;
  std::vector<ResponseRuleAction> d_respruleactions;
  std::vector<ResponseRuleAction> d_cachehitrespruleactions;
  std::vector<ResponseRuleAction> d_selfansweredrespruleactions;
  std::vector<ResponseRuleAction> d_cacheInsertedRespRuleActions;
  std::vector<ResponseRuleAction> d_XFRRespRuleActions;
  std::vector<ResponseRuleAction> d_TimeoutRespRuleActions;
};

const std::vector<RuleChainDescription>& getRuleChainDescriptions();
std::vector<RuleAction>& getRuleChain(RuleChains& chains, RuleChain chain);
const std::vector<RuleAction>& getRuleChain(const RuleChains& chains, RuleChain chain);
const std::vector<ResponseRuleChainDescription>& getResponseRuleChainDescriptions();
std::vector<ResponseRuleAction>& getRuleChain(RuleChains& chains, ResponseRuleChain chain);
const std::vector<ResponseRuleAction>& getRuleChain(const RuleChains& chains, ResponseRuleChain chain);
std::vector<ResponseRuleAction>& getResponseRuleChain(RuleChains& chains, ResponseRuleChain chain);
const std::vector<ResponseRuleAction>& getResponseRuleChain(const RuleChains& chains, ResponseRuleChain chain);
void add(RuleChains& chains, RuleChain identifier, const std::shared_ptr<DNSRule>& selector, const std::shared_ptr<DNSAction>& action, std::string&& name, const boost::uuids::uuid& uuid, uint64_t creationOrder);
void add(RuleChains& chains, ResponseRuleChain identifier, const std::shared_ptr<DNSRule>& selector, const std::shared_ptr<DNSResponseAction>& action, std::string&& name, const boost::uuids::uuid& uuid, uint64_t creationOrder);
}
