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
#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-rules.hh"
#include "dnsdist-rule-chains.hh"
#include "dns_random.hh"

std::shared_ptr<DNSRule> makeRule(const luadnsrule_t& var, const std::string& calledFrom)
{
  if (var.type() == typeid(std::shared_ptr<DNSRule>)) {
    return *boost::get<std::shared_ptr<DNSRule>>(&var);
  }

  bool suffixSeen = false;
  SuffixMatchNode smn;
  NetmaskGroup nmg;
  auto add = [&nmg, &smn, &suffixSeen](const string& src) {
    try {
      nmg.addMask(src); // need to try mask first, all masks are domain names!
    }
    catch (...) {
      suffixSeen = true;
      smn.add(DNSName(src));
    }
  };

  if (var.type() == typeid(string)) {
    add(*boost::get<string>(&var));
  }
  else if (var.type() == typeid(LuaArray<std::string>)) {
    for (const auto& str : *boost::get<LuaArray<std::string>>(&var)) {
      add(str.second);
    }
  }
  else if (var.type() == typeid(DNSName)) {
    smn.add(*boost::get<DNSName>(&var));
  }
  else if (var.type() == typeid(LuaArray<DNSName>)) {
    smn = SuffixMatchNode();
    for (const auto& name : *boost::get<LuaArray<DNSName>>(&var)) {
      smn.add(name.second);
    }
  }

  if (nmg.empty()) {
    return std::make_shared<SuffixMatchNodeRule>(smn);
  }
  if (suffixSeen) {
    warnlog("At least one parameter to %s has been parsed as a domain name amongst network masks, and will be ignored!", calledFrom);
  }
  return std::make_shared<NetmaskGroupRule>(nmg, true);
}

static boost::uuids::uuid makeRuleID(std::string& identifier)
{
  if (identifier.empty()) {
    return getUniqueID();
  }

  return getUniqueID(identifier);
}

void parseRuleParams(boost::optional<luaruleparams_t>& params, boost::uuids::uuid& uuid, std::string& name, uint64_t& creationOrder)
{
  static uint64_t s_creationOrder = 0;

  string uuidStr;

  getOptionalValue<std::string>(params, "uuid", uuidStr);
  getOptionalValue<std::string>(params, "name", name);

  uuid = makeRuleID(uuidStr);
  creationOrder = s_creationOrder++;
}

using ruleparams_t = LuaAssociativeTable<boost::variant<bool, int, std::string, LuaArray<int>>>;

template <typename T>
static std::string rulesToString(const std::vector<T>& rules, boost::optional<ruleparams_t>& vars)
{
  int num = 0;
  bool showUUIDs = false;
  size_t truncateRuleWidth = string::npos;
  std::string result;

  getOptionalValue<bool>(vars, "showUUIDs", showUUIDs);
  getOptionalValue<int>(vars, "truncateRuleWidth", truncateRuleWidth);
  checkAllParametersConsumed("rulesToString", vars);

  if (showUUIDs) {
    boost::format fmt("%-3d %-30s %-38s %9d %9d %-56s %s\n");
    result += (fmt % "#" % "Name" % "UUID" % "Cr. Order" % "Matches" % "Rule" % "Action").str();
    for (const auto& lim : rules) {
      string desc = lim.d_rule->toString().substr(0, truncateRuleWidth);
      result += (fmt % num % lim.d_name % boost::uuids::to_string(lim.d_id) % lim.d_creationOrder % lim.d_rule->d_matches % desc % lim.d_action->toString()).str();
      ++num;
    }
  }
  else {
    boost::format fmt("%-3d %-30s %9d %-56s %s\n");
    result += (fmt % "#" % "Name" % "Matches" % "Rule" % "Action").str();
    for (const auto& lim : rules) {
      string desc = lim.d_rule->toString().substr(0, truncateRuleWidth);
      result += (fmt % num % lim.d_name % lim.d_rule->d_matches % desc % lim.d_action->toString()).str();
      ++num;
    }
  }
  return result;
}

template <typename T>
static void showRules(GlobalStateHolder<vector<T>>* someRuleActions, boost::optional<ruleparams_t>& vars)
{
  setLuaNoSideEffect();

  auto rules = someRuleActions->getLocal();
  g_outputBuffer += rulesToString(*rules, vars);
}

template <typename T>
static void rmRule(GlobalStateHolder<vector<T>>* someRuleActions, const boost::variant<unsigned int, std::string>& ruleID)
{
  setLuaSideEffect();
  auto rules = someRuleActions->getCopy();
  if (const auto* str = boost::get<std::string>(&ruleID)) {
    try {
      const auto uuid = getUniqueID(*str);
      auto removeIt = std::remove_if(rules.begin(),
                                     rules.end(),
                                     [&uuid](const T& rule) { return rule.d_id == uuid; });
      if (removeIt == rules.end()) {
        g_outputBuffer = "Error: no rule matched\n";
        return;
      }
      rules.erase(removeIt,
                  rules.end());
    }
    catch (const std::runtime_error& e) {
      /* it was not an UUID, let's see if it was a name instead */
      auto removeIt = std::remove_if(rules.begin(),
                                     rules.end(),
                                     [&str](const T& rule) { return rule.d_name == *str; });
      if (removeIt == rules.end()) {
        g_outputBuffer = "Error: no rule matched\n";
        return;
      }
      rules.erase(removeIt,
                  rules.end());
    }
  }
  else if (const auto* pos = boost::get<unsigned int>(&ruleID)) {
    if (*pos >= rules.size()) {
      g_outputBuffer = "Error: attempt to delete non-existing rule\n";
      return;
    }
    rules.erase(rules.begin() + *pos);
  }
  someRuleActions->setState(std::move(rules));
}

template <typename T>
static void moveRuleToTop(GlobalStateHolder<vector<T>>* someRuleActions)
{
  setLuaSideEffect();
  auto rules = someRuleActions->getCopy();
  if (rules.empty()) {
    return;
  }
  auto subject = *rules.rbegin();
  rules.erase(std::prev(rules.end()));
  rules.insert(rules.begin(), subject);
  someRuleActions->setState(std::move(rules));
}

template <typename T>
static void mvRule(GlobalStateHolder<vector<T>>* someRespRuleActions, unsigned int from, unsigned int destination)
{
  setLuaSideEffect();
  auto rules = someRespRuleActions->getCopy();
  if (from >= rules.size() || destination > rules.size()) {
    g_outputBuffer = "Error: attempt to move rules from/to invalid index\n";
    return;
  }
  auto subject = rules[from];
  rules.erase(rules.begin() + from);
  if (destination > rules.size()) {
    rules.push_back(subject);
  }
  else {
    if (from < destination) {
      --destination;
    }
    rules.insert(rules.begin() + destination, subject);
  }
  someRespRuleActions->setState(std::move(rules));
}

template <typename T>
static std::vector<T> getTopRules(const std::vector<T>& rules, unsigned int top)
{
  std::vector<std::pair<size_t, size_t>> counts;
  counts.reserve(rules.size());

  size_t pos = 0;
  for (const auto& rule : rules) {
    counts.push_back({rule.d_rule->d_matches.load(), pos});
    pos++;
  }

  sort(counts.begin(), counts.end(), [](const decltype(counts)::value_type& lhs, const decltype(counts)::value_type& rhs) {
    return rhs.first < lhs.first;
  });

  std::vector<T> results;
  results.reserve(top);

  size_t count = 0;
  for (const auto& entry : counts) {
    results.emplace_back(rules.at(entry.second));
    ++count;
    if (count == top) {
      break;
    }
  }

  return results;
}

template <typename T>
static LuaArray<T> toLuaArray(std::vector<T>&& rules)
{
  LuaArray<T> results;
  results.reserve(rules.size());

  size_t pos = 1;
  for (auto& rule : rules) {
    results.emplace_back(pos, std::move(rule));
    pos++;
  }

  return results;
}

template <typename T>
static boost::optional<T> getRuleFromSelector(const std::vector<T>& rules, const boost::variant<int, std::string>& selector)
{
  if (const auto* str = boost::get<std::string>(&selector)) {
    /* let's see if this a UUID */
    try {
      const auto uuid = getUniqueID(*str);
      for (const auto& rule : rules) {
        if (rule.d_id == uuid) {
          return rule;
        }
      }
    }
    catch (const std::exception& e) {
      /* a name, then */
      for (const auto& rule : rules) {
        if (rule.d_name == *str) {
          return rule;
        }
      }
    }
  }
  else if (const auto* pos = boost::get<int>(&selector)) {
    /* this will throw a std::out_of_range exception if the
       supplied position is out of bounds, this is fine */
    return rules.at(*pos);
  }
  return boost::none;
}

namespace
{
std::shared_ptr<DNSRule> qnameSuffixRule(const boost::variant<const SuffixMatchNode&, std::string, const LuaArray<std::string>> names, boost::optional<bool> quiet)
{
  if (names.type() == typeid(string)) {
    SuffixMatchNode smn;
    smn.add(DNSName(*boost::get<std::string>(&names)));
    return std::shared_ptr<DNSRule>(new SuffixMatchNodeRule(smn, quiet ? *quiet : false));
  }

  if (names.type() == typeid(LuaArray<std::string>)) {
    SuffixMatchNode smn;
    for (const auto& str : *boost::get<const LuaArray<std::string>>(&names)) {
      smn.add(DNSName(str.second));
    }
    return std::shared_ptr<DNSRule>(new SuffixMatchNodeRule(smn, quiet ? *quiet : false));
  }

  const auto& smn = *boost::get<const SuffixMatchNode&>(&names);
  return std::shared_ptr<DNSRule>(new SuffixMatchNodeRule(smn, quiet ? *quiet : false));
}
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
void setupLuaRules(LuaContext& luaCtx)
{
  luaCtx.writeFunction("makeRule", [](const luadnsrule_t& var) -> std::shared_ptr<DNSRule> {
    return makeRule(var, "makeRule");
  });

  luaCtx.registerFunction<string (std::shared_ptr<DNSRule>::*)() const>("toString", [](const std::shared_ptr<DNSRule>& rule) { return rule->toString(); });

  luaCtx.registerFunction<uint64_t (std::shared_ptr<DNSRule>::*)() const>("getMatches", [](const std::shared_ptr<DNSRule>& rule) { return rule->d_matches.load(); });

  luaCtx.registerFunction<std::shared_ptr<DNSRule> (dnsdist::rules::RuleAction::*)() const>("getSelector", [](const dnsdist::rules::RuleAction& rule) { return rule.d_rule; });

  luaCtx.registerFunction<std::shared_ptr<DNSAction> (dnsdist::rules::RuleAction::*)() const>("getAction", [](const dnsdist::rules::RuleAction& rule) { return rule.d_action; });

  luaCtx.registerFunction<std::shared_ptr<DNSRule> (dnsdist::rules::ResponseRuleAction::*)() const>("getSelector", [](const dnsdist::rules::ResponseRuleAction& rule) { return rule.d_rule; });

  luaCtx.registerFunction<std::shared_ptr<DNSResponseAction> (dnsdist::rules::ResponseRuleAction::*)() const>("getAction", [](const dnsdist::rules::ResponseRuleAction& rule) { return rule.d_action; });

  for (const auto& chain : dnsdist::rules::getResponseRuleChains()) {
    luaCtx.writeFunction("show" + chain.prefix + "ResponseRules", [&chain](boost::optional<ruleparams_t> vars) {
      showRules(&chain.holder, vars);
    });
    luaCtx.writeFunction("rm" + chain.prefix + "ResponseRule", [&chain](const boost::variant<unsigned int, std::string>& identifier) {
      rmRule(&chain.holder, identifier);
    });
    luaCtx.writeFunction("mv" + chain.prefix + "ResponseRuleToTop", [&chain]() {
      moveRuleToTop(&chain.holder);
    });
    luaCtx.writeFunction("mv" + chain.prefix + "ResponseRule", [&chain](unsigned int from, unsigned int dest) {
      mvRule(&chain.holder, from, dest);
    });
    luaCtx.writeFunction("get" + chain.prefix + "ResponseRule", [&chain](const boost::variant<int, std::string>& selector) -> boost::optional<dnsdist::rules::ResponseRuleAction> {
      auto rules = chain.holder.getLocal();
      return getRuleFromSelector(*rules, selector);
    });

    luaCtx.writeFunction("getTop" + chain.prefix + "ResponseRules", [&chain](boost::optional<unsigned int> top) {
      setLuaNoSideEffect();
      auto rules = chain.holder.getLocal();
      return toLuaArray(getTopRules(*rules, (top ? *top : 10)));
    });

    luaCtx.writeFunction("top" + chain.prefix + "ResponseRules", [&chain](boost::optional<unsigned int> top, boost::optional<ruleparams_t> vars) {
      setLuaNoSideEffect();
      auto rules = chain.holder.getLocal();
      return rulesToString(getTopRules(*rules, (top ? *top : 10)), vars);
    });

    luaCtx.writeFunction("clear" + chain.prefix + "ResponseRules", [&chain]() {
      setLuaSideEffect();
      chain.holder.modify([](std::remove_reference_t<decltype(chain.holder)>::value_type& ruleactions) {
        ruleactions.clear();
      });
    });
  }

  for (const auto& chain : dnsdist::rules::getRuleChains()) {
    luaCtx.writeFunction("show" + chain.prefix + "Rules", [&chain](boost::optional<ruleparams_t> vars) {
      showRules(&chain.holder, vars);
    });
    luaCtx.writeFunction("rm" + chain.prefix + "Rule", [&chain](const boost::variant<unsigned int, std::string>& identifier) {
      rmRule(&chain.holder, identifier);
    });
    luaCtx.writeFunction("mv" + chain.prefix + "RuleToTop", [&chain]() {
      moveRuleToTop(&chain.holder);
    });
    luaCtx.writeFunction("mv" + chain.prefix + "Rule", [&chain](unsigned int from, unsigned int dest) {
      mvRule(&chain.holder, from, dest);
    });
    luaCtx.writeFunction("get" + chain.prefix + "Rule", [&chain](const boost::variant<int, std::string>& selector) -> boost::optional<dnsdist::rules::RuleAction> {
      auto rules = chain.holder.getLocal();
      return getRuleFromSelector(*rules, selector);
    });

    luaCtx.writeFunction("getTop" + chain.prefix + "Rules", [&chain](boost::optional<unsigned int> top) {
      setLuaNoSideEffect();
      auto rules = chain.holder.getLocal();
      return toLuaArray(getTopRules(*rules, (top ? *top : 10)));
    });

    luaCtx.writeFunction("top" + chain.prefix + "Rules", [&chain](boost::optional<unsigned int> top, boost::optional<ruleparams_t> vars) {
      setLuaNoSideEffect();
      auto rules = chain.holder.getLocal();
      return rulesToString(getTopRules(*rules, (top ? *top : 10)), vars);
    });

    luaCtx.writeFunction("clear" + chain.prefix + "Rules", [&chain]() {
      setLuaSideEffect();
      chain.holder.modify([](std::remove_reference_t<decltype(chain.holder)>::value_type& ruleactions) {
        ruleactions.clear();
      });
    });

    luaCtx.writeFunction("set" + chain.prefix + "Rules", [&chain](const LuaArray<std::shared_ptr<dnsdist::rules::RuleAction>>& newruleactions) {
      setLuaSideEffect();
      chain.holder.modify([newruleactions](std::remove_reference_t<decltype(chain.holder)>::value_type& gruleactions) {
        gruleactions.clear();
        for (const auto& pair : newruleactions) {
          const auto& newruleaction = pair.second;
          if (newruleaction->d_action) {
            auto rule = newruleaction->d_rule;
            gruleactions.push_back({std::move(rule), newruleaction->d_action, newruleaction->d_name, newruleaction->d_id, newruleaction->d_creationOrder});
          }
        }
      });
    });
  }

  luaCtx.writeFunction("MaxQPSIPRule", [](unsigned int qps, boost::optional<unsigned int> ipv4trunc, boost::optional<unsigned int> ipv6trunc, boost::optional<unsigned int> burst, boost::optional<unsigned int> expiration, boost::optional<unsigned int> cleanupDelay, boost::optional<unsigned int> scanFraction, boost::optional<unsigned int> shards) {
    return std::shared_ptr<DNSRule>(new MaxQPSIPRule(qps, (burst ? *burst : qps), (ipv4trunc ? *ipv4trunc : 32), (ipv6trunc ? *ipv6trunc : 64), (expiration ? *expiration : 300), (cleanupDelay ? *cleanupDelay : 60), (scanFraction ? *scanFraction : 10), (shards ? *shards : 10)));
  });

  luaCtx.writeFunction("MaxQPSRule", [](unsigned int qps, boost::optional<unsigned int> burst) {
    if (!burst) {
      return std::shared_ptr<DNSRule>(new MaxQPSRule(qps));
    }
    return std::shared_ptr<DNSRule>(new MaxQPSRule(qps, *burst));
  });

  luaCtx.writeFunction("RegexRule", [](const std::string& str) {
    return std::shared_ptr<DNSRule>(new RegexRule(str));
  });

#ifdef HAVE_DNS_OVER_HTTPS
  luaCtx.writeFunction("HTTPHeaderRule", [](const std::string& header, const std::string& regex) {
    return std::shared_ptr<DNSRule>(new HTTPHeaderRule(header, regex));
  });
  luaCtx.writeFunction("HTTPPathRule", [](const std::string& path) {
    return std::shared_ptr<DNSRule>(new HTTPPathRule(path));
  });
  luaCtx.writeFunction("HTTPPathRegexRule", [](const std::string& regex) {
    return std::shared_ptr<DNSRule>(new HTTPPathRegexRule(regex));
  });
#endif

#ifdef HAVE_RE2
  luaCtx.writeFunction("RE2Rule", [](const std::string& str) {
    return std::shared_ptr<DNSRule>(new RE2Rule(str));
  });
#endif

  luaCtx.writeFunction("SNIRule", [](const std::string& name) {
    return std::shared_ptr<DNSRule>(new SNIRule(name));
  });

  luaCtx.writeFunction("SuffixMatchNodeRule", qnameSuffixRule);

  luaCtx.writeFunction("NetmaskGroupRule", [](const boost::variant<const NetmaskGroup&, std::string, const LuaArray<std::string>> netmasks, boost::optional<bool> src, boost::optional<bool> quiet) {
    if (netmasks.type() == typeid(string)) {
      NetmaskGroup nmg;
      nmg.addMask(*boost::get<std::string>(&netmasks));
      return std::shared_ptr<DNSRule>(new NetmaskGroupRule(nmg, src ? *src : true, quiet ? *quiet : false));
    }

    if (netmasks.type() == typeid(LuaArray<std::string>)) {
      NetmaskGroup nmg;
      for (const auto& str : *boost::get<const LuaArray<std::string>>(&netmasks)) {
        nmg.addMask(str.second);
      }
      return std::shared_ptr<DNSRule>(new NetmaskGroupRule(nmg, src ? *src : true, quiet ? *quiet : false));
    }

    const auto& nmg = *boost::get<const NetmaskGroup&>(&netmasks);
    return std::shared_ptr<DNSRule>(new NetmaskGroupRule(nmg, src ? *src : true, quiet ? *quiet : false));
  });

  luaCtx.writeFunction("benchRule", [](const std::shared_ptr<DNSRule>& rule, boost::optional<unsigned int> times_, boost::optional<string> suffix_) {
    setLuaNoSideEffect();
    unsigned int times = times_ ? *times_ : 100000;
    DNSName suffix(suffix_ ? *suffix_ : "powerdns.com");
    // NOLINTNEXTLINE(bugprone-exception-escape): not sure what clang-tidy smoked, but we do not really care here
    struct item
    {
      PacketBuffer packet;
      InternalQueryState ids;
    };
    vector<item> items;
    items.reserve(1000);
    for (int counter = 0; counter < 1000; ++counter) {
      item entry;
      entry.ids.qname = DNSName(std::to_string(dns_random_uint32()));
      entry.ids.qname += suffix;
      entry.ids.qtype = dns_random(0xff);
      entry.ids.qclass = QClass::IN;
      entry.ids.protocol = dnsdist::Protocol::DoUDP;
      entry.ids.origRemote = ComboAddress("127.0.0.1");
      entry.ids.origRemote.sin4.sin_addr.s_addr = random();
      entry.ids.queryRealTime.start();
      GenericDNSPacketWriter<PacketBuffer> writer(entry.packet, entry.ids.qname, entry.ids.qtype);
      items.push_back(std::move(entry));
    }

    int matches = 0;
    ComboAddress dummy("127.0.0.1");
    StopWatch swatch;
    swatch.start();
    for (unsigned int counter = 0; counter < times; ++counter) {
      item& entry = items[counter % items.size()];
      DNSQuestion dnsQuestion(entry.ids, entry.packet);

      if (rule->matches(&dnsQuestion)) {
        matches++;
      }
    }
    double udiff = swatch.udiff();
    g_outputBuffer = (boost::format("Had %d matches out of %d, %.1f qps, in %.1f us\n") % matches % times % (1000000 * (1.0 * times / udiff)) % udiff).str();
  });

  luaCtx.writeFunction("AllRule", []() {
    return std::shared_ptr<DNSRule>(new AllRule());
  });

  luaCtx.writeFunction("ProbaRule", [](double proba) {
    return std::shared_ptr<DNSRule>(new ProbaRule(proba));
  });

  luaCtx.writeFunction("QNameRule", [](const std::string& qname) {
    return std::shared_ptr<DNSRule>(new QNameRule(DNSName(qname)));
  });

  luaCtx.writeFunction("QNameSuffixRule", qnameSuffixRule);

  luaCtx.writeFunction("QTypeRule", [](boost::variant<unsigned int, std::string> str) {
    uint16_t qtype{};
    if (const auto* dir = boost::get<unsigned int>(&str)) {
      qtype = *dir;
    }
    else {
      string val = boost::get<string>(str);
      qtype = QType::chartocode(val.c_str());
      if (qtype == 0) {
        throw std::runtime_error("Unable to convert '" + val + "' to a DNS type");
      }
    }
    return std::shared_ptr<DNSRule>(new QTypeRule(qtype));
  });

  luaCtx.writeFunction("QClassRule", [](uint64_t cla) {
    checkParameterBound("QClassRule", cla, std::numeric_limits<uint16_t>::max());
    return std::shared_ptr<DNSRule>(new QClassRule(cla));
  });

  luaCtx.writeFunction("OpcodeRule", [](uint64_t code) {
    checkParameterBound("OpcodeRule", code, std::numeric_limits<uint8_t>::max());
    return std::shared_ptr<DNSRule>(new OpcodeRule(code));
  });

  luaCtx.writeFunction("AndRule", [](const LuaArray<std::shared_ptr<DNSRule>>& rules) {
    return std::shared_ptr<DNSRule>(new AndRule(rules));
  });

  luaCtx.writeFunction("OrRule", [](const LuaArray<std::shared_ptr<DNSRule>>& rules) {
    return std::shared_ptr<DNSRule>(new OrRule(rules));
  });

  luaCtx.writeFunction("DSTPortRule", [](uint64_t port) {
    checkParameterBound("DSTPortRule", port, std::numeric_limits<uint16_t>::max());
    return std::shared_ptr<DNSRule>(new DSTPortRule(port));
  });

  luaCtx.writeFunction("TCPRule", [](bool tcp) {
    return std::shared_ptr<DNSRule>(new TCPRule(tcp));
  });

  luaCtx.writeFunction("DNSSECRule", []() {
    return std::shared_ptr<DNSRule>(new DNSSECRule());
  });

  luaCtx.writeFunction("NotRule", [](const std::shared_ptr<DNSRule>& rule) {
    return std::shared_ptr<DNSRule>(new NotRule(rule));
  });

  luaCtx.writeFunction("RecordsCountRule", [](uint64_t section, uint64_t minCount, uint64_t maxCount) {
    checkParameterBound("RecordsCountRule", section, std::numeric_limits<uint8_t>::max());
    checkParameterBound("RecordsCountRule", minCount, std::numeric_limits<uint16_t>::max());
    checkParameterBound("RecordsCountRule", maxCount, std::numeric_limits<uint16_t>::max());
    return std::shared_ptr<DNSRule>(new RecordsCountRule(section, minCount, maxCount));
  });

  luaCtx.writeFunction("RecordsTypeCountRule", [](uint64_t section, uint64_t type, uint64_t minCount, uint64_t maxCount) {
    checkParameterBound("RecordsTypeCountRule", section, std::numeric_limits<uint8_t>::max());
    checkParameterBound("RecordsTypeCountRule", type, std::numeric_limits<uint16_t>::max());
    checkParameterBound("RecordsTypeCountRule", minCount, std::numeric_limits<uint16_t>::max());
    checkParameterBound("RecordsTypeCountRule", maxCount, std::numeric_limits<uint16_t>::max());
    return std::shared_ptr<DNSRule>(new RecordsTypeCountRule(section, type, minCount, maxCount));
  });

  luaCtx.writeFunction("TrailingDataRule", []() {
    return std::shared_ptr<DNSRule>(new TrailingDataRule());
  });

  luaCtx.writeFunction("QNameLabelsCountRule", [](uint64_t minLabelsCount, uint64_t maxLabelsCount) {
    checkParameterBound("QNameLabelsCountRule", minLabelsCount, std::numeric_limits<unsigned int>::max());
    checkParameterBound("QNameLabelsCountRule", maxLabelsCount, std::numeric_limits<unsigned int>::max());
    return std::shared_ptr<DNSRule>(new QNameLabelsCountRule(minLabelsCount, maxLabelsCount));
  });

  luaCtx.writeFunction("QNameWireLengthRule", [](uint64_t min, uint64_t max) {
    return std::shared_ptr<DNSRule>(new QNameWireLengthRule(min, max));
  });

  luaCtx.writeFunction("RCodeRule", [](uint64_t rcode) {
    checkParameterBound("RCodeRule", rcode, std::numeric_limits<uint8_t>::max());
    return std::shared_ptr<DNSRule>(new RCodeRule(rcode));
  });

  luaCtx.writeFunction("ERCodeRule", [](uint64_t rcode) {
    checkParameterBound("ERCodeRule", rcode, std::numeric_limits<uint8_t>::max());
    return std::shared_ptr<DNSRule>(new ERCodeRule(rcode));
  });

  luaCtx.writeFunction("EDNSVersionRule", [](uint64_t version) {
    checkParameterBound("EDNSVersionRule", version, std::numeric_limits<uint8_t>::max());
    return std::shared_ptr<DNSRule>(new EDNSVersionRule(version));
  });

  luaCtx.writeFunction("EDNSOptionRule", [](uint64_t optcode) {
    checkParameterBound("EDNSOptionRule", optcode, std::numeric_limits<uint16_t>::max());
    return std::shared_ptr<DNSRule>(new EDNSOptionRule(optcode));
  });

  luaCtx.writeFunction("RDRule", []() {
    return std::shared_ptr<DNSRule>(new RDRule());
  });

  luaCtx.writeFunction("TagRule", [](const std::string& tag, boost::optional<std::string> value) {
    return std::shared_ptr<DNSRule>(new TagRule(tag, std::move(value)));
  });

  luaCtx.writeFunction("TimedIPSetRule", []() {
    return std::make_shared<TimedIPSetRule>();
  });

  luaCtx.writeFunction("PoolAvailableRule", [](const std::string& poolname) {
    return std::shared_ptr<DNSRule>(new PoolAvailableRule(poolname));
  });

  luaCtx.writeFunction("PoolOutstandingRule", [](const std::string& poolname, uint64_t limit) {
    return std::shared_ptr<DNSRule>(new PoolOutstandingRule(poolname, limit));
  });

  luaCtx.registerFunction<void (std::shared_ptr<TimedIPSetRule>::*)()>("clear", [](const std::shared_ptr<TimedIPSetRule>& tisr) {
    tisr->clear();
  });

  luaCtx.registerFunction<void (std::shared_ptr<TimedIPSetRule>::*)()>("cleanup", [](const std::shared_ptr<TimedIPSetRule>& tisr) {
    tisr->cleanup();
  });

  luaCtx.registerFunction<void (std::shared_ptr<TimedIPSetRule>::*)(const ComboAddress&, int)>("add", [](const std::shared_ptr<TimedIPSetRule>& tisr, const ComboAddress& addr, int additional) {
    tisr->add(addr, time(nullptr) + additional);
  });

  luaCtx.registerFunction<std::shared_ptr<DNSRule> (std::shared_ptr<TimedIPSetRule>::*)()>("slice", [](const std::shared_ptr<TimedIPSetRule>& tisr) {
    return std::dynamic_pointer_cast<DNSRule>(tisr);
  });
  luaCtx.registerFunction<void (std::shared_ptr<TimedIPSetRule>::*)()>("__tostring", [](const std::shared_ptr<TimedIPSetRule>& tisr) {
    tisr->toString();
  });

  luaCtx.writeFunction("QNameSetRule", [](const DNSNameSet& names) {
    return std::shared_ptr<DNSRule>(new QNameSetRule(names));
  });

#if defined(HAVE_LMDB) || defined(HAVE_CDB)
  luaCtx.writeFunction("KeyValueStoreLookupRule", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey) {
    return std::shared_ptr<DNSRule>(new KeyValueStoreLookupRule(kvs, lookupKey));
  });

  luaCtx.writeFunction("KeyValueStoreRangeLookupRule", [](std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey) {
    return std::shared_ptr<DNSRule>(new KeyValueStoreRangeLookupRule(kvs, lookupKey));
  });
#endif /* defined(HAVE_LMDB) || defined(HAVE_CDB) */

  luaCtx.writeFunction("LuaRule", [](const LuaRule::func_t& func) {
    return std::shared_ptr<DNSRule>(new LuaRule(func));
  });

  luaCtx.writeFunction("LuaFFIRule", [](const LuaFFIRule::func_t& func) {
    return std::shared_ptr<DNSRule>(new LuaFFIRule(func));
  });

  luaCtx.writeFunction("LuaFFIPerThreadRule", [](const std::string& code) {
    return std::shared_ptr<DNSRule>(new LuaFFIPerThreadRule(code));
  });

  luaCtx.writeFunction("ProxyProtocolValueRule", [](uint8_t type, boost::optional<std::string> value) {
    return std::shared_ptr<DNSRule>(new ProxyProtocolValueRule(type, std::move(value)));
  });

  luaCtx.writeFunction("PayloadSizeRule", [](const std::string& comparison, uint16_t size) {
    return std::shared_ptr<DNSRule>(new PayloadSizeRule(comparison, size));
  });
}
