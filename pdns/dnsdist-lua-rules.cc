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
#include "dnsdist-ecs.hh"
#include "dnsdist-lua.hh"

#include "dnsparser.hh"

class MaxQPSIPRule : public DNSRule
{
public:
  MaxQPSIPRule(unsigned int qps, unsigned int burst, unsigned int ipv4trunc=32, unsigned int ipv6trunc=64) :
    d_qps(qps), d_burst(burst), d_ipv4trunc(ipv4trunc), d_ipv6trunc(ipv6trunc)
  {
    pthread_rwlock_init(&d_lock, 0);
  }

  bool matches(const DNSQuestion* dq) const override
  {
    ComboAddress zeroport(*dq->remote);
    zeroport.sin4.sin_port=0;
    zeroport.truncate(zeroport.sin4.sin_family == AF_INET ? d_ipv4trunc : d_ipv6trunc);
    {
      ReadLock r(&d_lock);
      const auto iter = d_limits.find(zeroport);
      if (iter != d_limits.end()) {
        return !iter->second.check();
      }
    }
    {
      WriteLock w(&d_lock);
      auto iter = d_limits.find(zeroport);
      if(iter == d_limits.end()) {
        iter=d_limits.insert({zeroport,QPSLimiter(d_qps, d_burst)}).first;
      }
      return !iter->second.check();
    }
  }

  string toString() const override
  {
    return "IP (/"+std::to_string(d_ipv4trunc)+", /"+std::to_string(d_ipv6trunc)+") match for QPS over " + std::to_string(d_qps) + " burst "+ std::to_string(d_burst);
  }


private:
  mutable pthread_rwlock_t d_lock;
  mutable std::map<ComboAddress, QPSLimiter> d_limits;
  unsigned int d_qps, d_burst, d_ipv4trunc, d_ipv6trunc;

};

class MaxQPSRule : public DNSRule
{
public:
  MaxQPSRule(unsigned int qps)
   : d_qps(qps, qps)
  {}

  MaxQPSRule(unsigned int qps, unsigned int burst)
   : d_qps(qps, burst)
  {}


  bool matches(const DNSQuestion* qd) const override
  {
    return d_qps.check();
  }

  string toString() const override
  {
    return "Max " + std::to_string(d_qps.getRate()) + " qps";
  }


private:
  mutable QPSLimiter d_qps;
};

class NMGRule : public DNSRule
{
public:
  NMGRule(const NetmaskGroup& nmg) : d_nmg(nmg) {}
protected:
  NetmaskGroup d_nmg;
};

class NetmaskGroupRule : public NMGRule
{
public:
  NetmaskGroupRule(const NetmaskGroup& nmg, bool src) : NMGRule(nmg)
  {
      d_src = src;
  }
  bool matches(const DNSQuestion* dq) const override
  {
    if(!d_src) {
        return d_nmg.match(*dq->local);
    }
    return d_nmg.match(*dq->remote);
  }

  string toString() const override
  {
    if(!d_src) {
        return "Dst: "+d_nmg.toString();
    }
    return "Src: "+d_nmg.toString();
  }
private:
  bool d_src;
};

class TimedIPSetRule : public DNSRule, boost::noncopyable
{
private:
  struct IPv6 {
    IPv6(const ComboAddress& ca)
    {
      static_assert(sizeof(*this)==16, "IPv6 struct has wrong size");
      memcpy((char*)this, ca.sin6.sin6_addr.s6_addr, 16);
    }
    bool operator==(const IPv6& rhs) const
    {
      return a==rhs.a && b==rhs.b;
    }
    uint64_t a, b;
  };

public:
  TimedIPSetRule()
  {
    pthread_rwlock_init(&d_lock4, 0);
    pthread_rwlock_init(&d_lock6, 0);
  }
  bool matches(const DNSQuestion* dq) const override
  {
    if(dq->remote->sin4.sin_family == AF_INET) {
      ReadLock rl(&d_lock4);
      auto fnd = d_ip4s.find(dq->remote->sin4.sin_addr.s_addr);
      if(fnd == d_ip4s.end()) {
        return false;
      }
      return time(0) < fnd->second;
    } else {
      ReadLock rl(&d_lock6);
      auto fnd = d_ip6s.find({*dq->remote});
      if(fnd == d_ip6s.end()) {
        return false;
      }
      return time(0) < fnd->second;
    }
  }

  void add(const ComboAddress& ca, time_t ttd)
  {
    // think twice before adding templates here
    if(ca.sin4.sin_family == AF_INET) {
      WriteLock rl(&d_lock4);
      auto res=d_ip4s.insert({ca.sin4.sin_addr.s_addr, ttd});
      if(!res.second && (time_t)res.first->second < ttd)
        res.first->second = (uint32_t)ttd;
    }
    else {
      WriteLock rl(&d_lock6);
      auto res=d_ip6s.insert({{ca}, ttd});
      if(!res.second && (time_t)res.first->second < ttd)
        res.first->second = (uint32_t)ttd;
    }
  }

  void remove(const ComboAddress& ca)
  {
    if(ca.sin4.sin_family == AF_INET) {
      WriteLock rl(&d_lock4);
      d_ip4s.erase(ca.sin4.sin_addr.s_addr);
    }
    else {
      WriteLock rl(&d_lock6);
      d_ip6s.erase({ca});
    }
  }

  void clear()
  {
    {
      WriteLock rl(&d_lock4);
      d_ip4s.clear();
    }
    WriteLock rl(&d_lock6);
    d_ip6s.clear();
  }

  void cleanup()
  {
    time_t now=time(0);
    {
      WriteLock rl(&d_lock4);

      for(auto iter = d_ip4s.begin(); iter != d_ip4s.end(); ) {
	if(iter->second < now)
	  iter=d_ip4s.erase(iter);
	else
	  ++iter;
      }

    }

    {
      WriteLock rl(&d_lock6);

      for(auto iter = d_ip6s.begin(); iter != d_ip6s.end(); ) {
	if(iter->second < now)
	  iter=d_ip6s.erase(iter);
	else
	  ++iter;
      }

    }

  }

  string toString() const override
  {
    time_t now=time(0);
    uint64_t count = 0;
    {
      ReadLock rl(&d_lock4);
      for(const auto& ip : d_ip4s)
        if(now < ip.second)
          ++count;
    }
    {
      ReadLock rl(&d_lock6);
      for(const auto& ip : d_ip6s)
        if(now < ip.second)
          ++count;
    }

    return "Src: "+std::to_string(count)+" ips";
  }
private:
  struct IPv6Hash
  {
    std::size_t operator()(const IPv6& ip) const
    {
      auto ah=std::hash<uint64_t>{}(ip.a);
      auto bh=std::hash<uint64_t>{}(ip.b);
      return ah & (bh<<1);
    }
  };
  std::unordered_map<IPv6, time_t, IPv6Hash> d_ip6s;
  std::unordered_map<uint32_t, time_t> d_ip4s;
  mutable pthread_rwlock_t d_lock4;
  mutable pthread_rwlock_t d_lock6;
};


class AllRule : public DNSRule
{
public:
  AllRule() {}
  bool matches(const DNSQuestion* dq) const override
  {
    return true;
  }

  string toString() const override
  {
    return "All";
  }

};


class DNSSECRule : public DNSRule
{
public:
  DNSSECRule()
  {

  }
  bool matches(const DNSQuestion* dq) const override
  {
    return dq->dh->cd || (getEDNSZ((const char*)dq->dh, dq->len) & EDNS_HEADER_FLAG_DO);    // turns out dig sets ad by default..
  }

  string toString() const override
  {
    return "DNSSEC";
  }
};

class AndRule : public DNSRule
{
public:
  AndRule(const vector<pair<int, shared_ptr<DNSRule> > >& rules)
  {
    for(const auto& r : rules)
      d_rules.push_back(r.second);
  }

  bool matches(const DNSQuestion* dq) const override
  {
    auto iter = d_rules.begin();
    for(; iter != d_rules.end(); ++iter)
      if(!(*iter)->matches(dq))
        break;
    return iter == d_rules.end();
  }

  string toString() const override
  {
    string ret;
    for(const auto& rule : d_rules) {
      if(!ret.empty())
        ret+= " && ";
      ret += "("+ rule->toString()+")";
    }
    return ret;
  }
private:

  vector<std::shared_ptr<DNSRule> > d_rules;

};


class OrRule : public DNSRule
{
public:
  OrRule(const vector<pair<int, shared_ptr<DNSRule> > >& rules)
  {
    for(const auto& r : rules)
      d_rules.push_back(r.second);
  }

  bool matches(const DNSQuestion* dq) const override
  {
    auto iter = d_rules.begin();
    for(; iter != d_rules.end(); ++iter)
      if((*iter)->matches(dq))
        return true;
    return false;
  }

  string toString() const override
  {
    string ret;
    for(const auto& rule : d_rules) {
      if(!ret.empty())
        ret+= " || ";
      ret += "("+ rule->toString()+")";
    }
    return ret;
  }
private:

  vector<std::shared_ptr<DNSRule> > d_rules;

};


class RegexRule : public DNSRule
{
public:
  RegexRule(const std::string& regex) : d_regex(regex), d_visual(regex)
  {

  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_regex.match(dq->qname->toStringNoDot());
  }

  string toString() const override
  {
    return "Regex: "+d_visual;
  }
private:
  Regex d_regex;
  string d_visual;
};

#ifdef HAVE_RE2
#include <re2/re2.h>
class RE2Rule : public DNSRule
{
public:
  RE2Rule(const std::string& re2) : d_re2(re2, RE2::Latin1), d_visual(re2)
  {

  }
  bool matches(const DNSQuestion* dq) const override
  {
    return RE2::FullMatch(dq->qname->toStringNoDot(), d_re2);
  }

  string toString() const override
  {
    return "RE2 match: "+d_visual;
  }
private:
  RE2 d_re2;
  string d_visual;
};
#endif


class SuffixMatchNodeRule : public DNSRule
{
public:
  SuffixMatchNodeRule(const SuffixMatchNode& smn, bool quiet=false) : d_smn(smn), d_quiet(quiet)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_smn.check(*dq->qname);
  }
  string toString() const override
  {
    if(d_quiet)
      return "qname==in-set";
    else
      return "qname in "+d_smn.toString();
  }
private:
  SuffixMatchNode d_smn;
  bool d_quiet;
};

class QNameRule : public DNSRule
{
public:
  QNameRule(const DNSName& qname) : d_qname(qname)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_qname==*dq->qname;
  }
  string toString() const override
  {
    return "qname=="+d_qname.toString();
  }
private:
  DNSName d_qname;
};


class QTypeRule : public DNSRule
{
public:
  QTypeRule(uint16_t qtype) : d_qtype(qtype)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_qtype == dq->qtype;
  }
  string toString() const override
  {
    QType qt(d_qtype);
    return "qtype=="+qt.getName();
  }
private:
  uint16_t d_qtype;
};

class QClassRule : public DNSRule
{
public:
  QClassRule(uint16_t qclass) : d_qclass(qclass)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_qclass == dq->qclass;
  }
  string toString() const override
  {
    return "qclass=="+std::to_string(d_qclass);
  }
private:
  uint16_t d_qclass;
};

class OpcodeRule : public DNSRule
{
public:
  OpcodeRule(uint8_t opcode) : d_opcode(opcode)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_opcode == dq->dh->opcode;
  }
  string toString() const override
  {
    return "opcode=="+std::to_string(d_opcode);
  }
private:
  uint8_t d_opcode;
};

class TCPRule : public DNSRule
{
public:
  TCPRule(bool tcp): d_tcp(tcp)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return dq->tcp == d_tcp;
  }
  string toString() const override
  {
    return (d_tcp ? "TCP" : "UDP");
  }
private:
  bool d_tcp;
};


class NotRule : public DNSRule
{
public:
  NotRule(shared_ptr<DNSRule>& rule): d_rule(rule)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return !d_rule->matches(dq);
  }
  string toString() const override
  {
    return "!("+ d_rule->toString()+")";
  }
private:
  shared_ptr<DNSRule> d_rule;
};

class RecordsCountRule : public DNSRule
{
public:
  RecordsCountRule(uint8_t section, uint16_t minCount, uint16_t maxCount): d_minCount(minCount), d_maxCount(maxCount), d_section(section)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    uint16_t count = 0;
    switch(d_section) {
    case 0:
      count = ntohs(dq->dh->qdcount);
      break;
    case 1:
      count = ntohs(dq->dh->ancount);
      break;
    case 2:
      count = ntohs(dq->dh->nscount);
      break;
    case 3:
      count = ntohs(dq->dh->arcount);
      break;
    }
    return count >= d_minCount && count <= d_maxCount;
  }
  string toString() const override
  {
    string section;
    switch(d_section) {
    case 0:
      section = "QD";
      break;
    case 1:
      section = "AN";
      break;
    case 2:
      section = "NS";
      break;
    case 3:
      section = "AR";
      break;
    }
    return std::to_string(d_minCount) + " <= records in " + section + " <= "+ std::to_string(d_maxCount);
  }
private:
  uint16_t d_minCount;
  uint16_t d_maxCount;
  uint8_t d_section;
};

class RecordsTypeCountRule : public DNSRule
{
public:
  RecordsTypeCountRule(uint8_t section, uint16_t type, uint16_t minCount, uint16_t maxCount): d_type(type), d_minCount(minCount), d_maxCount(maxCount), d_section(section)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    uint16_t count = 0;
    switch(d_section) {
    case 0:
      count = ntohs(dq->dh->qdcount);
      break;
    case 1:
      count = ntohs(dq->dh->ancount);
      break;
    case 2:
      count = ntohs(dq->dh->nscount);
      break;
    case 3:
      count = ntohs(dq->dh->arcount);
      break;
    }
    if (count < d_minCount) {
      return false;
    }
    count = getRecordsOfTypeCount(reinterpret_cast<const char*>(dq->dh), dq->len, d_section, d_type);
    return count >= d_minCount && count <= d_maxCount;
  }
  string toString() const override
  {
    string section;
    switch(d_section) {
    case 0:
      section = "QD";
      break;
    case 1:
      section = "AN";
      break;
    case 2:
      section = "NS";
      break;
    case 3:
      section = "AR";
      break;
    }
    return std::to_string(d_minCount) + " <= " + QType(d_type).getName() + " records in " + section + " <= "+ std::to_string(d_maxCount);
  }
private:
  uint16_t d_type;
  uint16_t d_minCount;
  uint16_t d_maxCount;
  uint8_t d_section;
};

class TrailingDataRule : public DNSRule
{
public:
  TrailingDataRule()
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    uint16_t length = getDNSPacketLength(reinterpret_cast<const char*>(dq->dh), dq->len);
    return length < dq->len;
  }
  string toString() const override
  {
    return "trailing data";
  }
};

class QNameLabelsCountRule : public DNSRule
{
public:
  QNameLabelsCountRule(unsigned int minLabelsCount, unsigned int maxLabelsCount): d_min(minLabelsCount), d_max(maxLabelsCount)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    unsigned int count = dq->qname->countLabels();
    return count < d_min || count > d_max;
  }
  string toString() const override
  {
    return "labels count < " + std::to_string(d_min) + " || labels count > " + std::to_string(d_max);
  }
private:
  unsigned int d_min;
  unsigned int d_max;
};

class QNameWireLengthRule : public DNSRule
{
public:
  QNameWireLengthRule(size_t min, size_t max): d_min(min), d_max(max)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    size_t const wirelength = dq->qname->wirelength();
    return wirelength < d_min || wirelength > d_max;
  }
  string toString() const override
  {
    return "wire length < " + std::to_string(d_min) + " || wire length > " + std::to_string(d_max);
  }
private:
  size_t d_min;
  size_t d_max;
};

class RCodeRule : public DNSRule
{
public:
  RCodeRule(uint8_t rcode) : d_rcode(rcode)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_rcode == dq->dh->rcode;
  }
  string toString() const override
  {
    return "rcode=="+RCode::to_s(d_rcode);
  }
private:
  uint8_t d_rcode;
};

class ERCodeRule : public DNSRule
{
public:
  ERCodeRule(uint8_t rcode) : d_rcode(rcode & 0xF), d_extrcode(rcode >> 4)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    // avoid parsing EDNS OPT RR when not needed.
    if (d_rcode != dq->dh->rcode) {
      return false;
    }

    char * optStart = NULL;
    size_t optLen = 0;
    bool last = false;
    int res = locateEDNSOptRR(const_cast<char*>(reinterpret_cast<const char*>(dq->dh)), dq->len, &optStart, &optLen, &last);
    if (res != 0) {
      // no EDNS OPT RR
      return d_extrcode == 0;
    }

    // root label (1), type (2), class (2), ttl (4) + rdlen (2)
    if (optLen < 11) {
      return false;
    }

    if (*optStart != 0) {
      // OPT RR Name != '.'
      return false;
    }
    EDNS0Record edns0;
    static_assert(sizeof(EDNS0Record) == sizeof(uint32_t), "sizeof(EDNS0Record) must match sizeof(uint32_t) AKA RR TTL size");
    // copy out 4-byte "ttl" (really the EDNS0 record), after root label (1) + type (2) + class (2).
    memcpy(&edns0, optStart + 5, sizeof edns0);

    return d_extrcode == edns0.extRCode;
  }
  string toString() const override
  {
    return "ercode=="+ERCode::to_s(d_rcode | (d_extrcode << 4));
  }
private:
  uint8_t d_rcode;     // plain DNS Rcode
  uint8_t d_extrcode;  // upper bits in EDNS0 record
};

class RDRule : public DNSRule
{
public:
  RDRule()
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return dq->dh->rd == 1;
  }
  string toString() const override
  {
    return "rd==1";
  }
};

class ProbaRule : public DNSRule
{
public:
  ProbaRule(double proba) : d_proba(proba)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    if(d_proba == 1.0)
      return true;
    double rnd = 1.0*random() / RAND_MAX;
    return rnd > (1.0 - d_proba);
  }
  string toString() const override
  {
    return "match with prob. " + (boost::format("%0.2f") % d_proba).str();
  }
private:
  double d_proba;
};

class TagRule : public DNSRule
{
public:
  TagRule(std::string tag, boost::optional<std::string> value) : d_value(value), d_tag(tag)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    if (!dq->qTag) {
      return false;
    }

    const auto it = dq->qTag->find(d_tag);
    if (it == dq->qTag->cend()) {
      return false;
    }

    if (!d_value) {
      return true;
    }

    return it->second == *d_value;
  }

  string toString() const override
  {
    return "tag '" + d_tag + "' is set" + (d_value ? (" to '" + *d_value + "'") : "");
  }

private:
  boost::optional<std::string> d_value;
  std::string d_tag;
};

std::shared_ptr<DNSRule> makeRule(const luadnsrule_t& var)
{
  if (var.type() == typeid(std::shared_ptr<DNSRule>))
    return *boost::get<std::shared_ptr<DNSRule>>(&var);

  SuffixMatchNode smn;
  NetmaskGroup nmg;
  auto add=[&](string src) {
    try {
      nmg.addMask(src); // need to try mask first, all masks are domain names!
    } catch(...) {
      smn.add(DNSName(src));
    }
  };

  if (var.type() == typeid(string))
    add(*boost::get<string>(&var));

  else if (var.type() == typeid(vector<pair<int, string>>))
    for(const auto& a : *boost::get<vector<pair<int, string>>>(&var))
      add(a.second);

  else if (var.type() == typeid(DNSName))
    smn.add(*boost::get<DNSName>(&var));

  else if (var.type() == typeid(vector<pair<int, DNSName>>))
    for(const auto& a : *boost::get<vector<pair<int, DNSName>>>(&var))
      smn.add(a.second);

  if(nmg.empty())
    return std::make_shared<SuffixMatchNodeRule>(smn);
  else
    return std::make_shared<NetmaskGroupRule>(nmg, true);
}

static boost::uuids::uuid makeRuleID(std::string& id)
{
  if (id.empty()) {
    return t_uuidGenerator();
  }

  boost::uuids::string_generator gen;
  return gen(id);
}

void parseRuleParams(boost::optional<luaruleparams_t> params, boost::uuids::uuid& uuid)
{
  string uuidStr;

  if (params) {
    if (params->count("uuid")) {
      uuidStr = boost::get<std::string>((*params)["uuid"]);
    }
  }

  uuid = makeRuleID(uuidStr);
}

template<typename T>
static void showRules(GlobalStateHolder<vector<T> > *someRulActions, boost::optional<bool> showUUIDs) {
  setLuaNoSideEffect();
  int num=0;
  if (showUUIDs.get_value_or(false)) {
    boost::format fmt("%-3d %-38s %9d %-56s %s\n");
    g_outputBuffer += (fmt % "#" % "UUID" % "Matches" % "Rule" % "Action").str();
    for(const auto& lim : someRulActions->getCopy()) {
      string name = lim.d_rule->toString();
      g_outputBuffer += (fmt % num % boost::uuids::to_string(lim.d_id) % lim.d_rule->d_matches % name % lim.d_action->toString()).str();
      ++num;
    }
  }
  else {
    boost::format fmt("%-3d %9d %-56s %s\n");
    g_outputBuffer += (fmt % "#" % "Matches" % "Rule" % "Action").str();
    for(const auto& lim : someRulActions->getCopy()) {
      string name = lim.d_rule->toString();
      g_outputBuffer += (fmt % num % lim.d_rule->d_matches % name % lim.d_action->toString()).str();
      ++num;
    }
  }
}

template<typename T>
static void rmRule(GlobalStateHolder<vector<T> > *someRulActions, boost::variant<unsigned int, std::string> id) {
  setLuaSideEffect();
  auto rules = someRulActions->getCopy();
  if (auto str = boost::get<std::string>(&id)) {
    boost::uuids::string_generator gen;
    const auto uuid = gen(*str);
    if (rules.erase(std::remove_if(rules.begin(),
                                    rules.end(),
                                    [uuid](const T& a) { return a.d_id == uuid; }),
                    rules.end()) == rules.end()) {
      g_outputBuffer = "Error: no rule matched\n";
      return;
    }
  }
  else if (auto pos = boost::get<unsigned int>(&id)) {
    if (*pos >= rules.size()) {
      g_outputBuffer = "Error: attempt to delete non-existing rule\n";
      return;
    }
    rules.erase(rules.begin()+*pos);
  }
  someRulActions->setState(rules);
}

template<typename T>
static void topRule(GlobalStateHolder<vector<T> > *someRulActions) {
  setLuaSideEffect();
  auto rules = someRulActions->getCopy();
  if(rules.empty())
    return;
  auto subject = *rules.rbegin();
  rules.erase(std::prev(rules.end()));
  rules.insert(rules.begin(), subject);
  someRulActions->setState(rules);
}

template<typename T>
static void mvRule(GlobalStateHolder<vector<T> > *someRespRulActions, unsigned int from, unsigned int to) {
  setLuaSideEffect();
  auto rules = someRespRulActions->getCopy();
  if(from >= rules.size() || to > rules.size()) {
    g_outputBuffer = "Error: attempt to move rules from/to invalid index\n";
    return;
  }
  auto subject = rules[from];
  rules.erase(rules.begin()+from);
  if(to == rules.size())
    rules.push_back(subject);
  else {
    if(from < to)
      --to;
    rules.insert(rules.begin()+to, subject);
  }
  someRespRulActions->setState(rules);
}

void setupLuaRules()
{
  g_lua.writeFunction("makeRule", makeRule);

  g_lua.registerFunction<string(std::shared_ptr<DNSRule>::*)()>("toString", [](const std::shared_ptr<DNSRule>& rule) { return rule->toString(); });

  g_lua.writeFunction("showResponseRules", [](boost::optional<bool> showUUIDs) {
      showRules(&g_resprulactions, showUUIDs);
    });

  g_lua.writeFunction("rmResponseRule", [](boost::variant<unsigned int, std::string> id) {
      rmRule(&g_resprulactions, id);
    });

  g_lua.writeFunction("topResponseRule", []() {
      topRule(&g_resprulactions);
    });

  g_lua.writeFunction("mvResponseRule", [](unsigned int from, unsigned int to) {
      mvRule(&g_resprulactions, from, to);
    });

  g_lua.writeFunction("showCacheHitResponseRules", [](boost::optional<bool> showUUIDs) {
      showRules(&g_cachehitresprulactions, showUUIDs);
    });

  g_lua.writeFunction("rmCacheHitResponseRule", [](boost::variant<unsigned int, std::string> id) {
      rmRule(&g_cachehitresprulactions, id);
    });

  g_lua.writeFunction("topCacheHitResponseRule", []() {
      topRule(&g_cachehitresprulactions);
    });

  g_lua.writeFunction("mvCacheHitResponseRule", [](unsigned int from, unsigned int to) {
      mvRule(&g_cachehitresprulactions, from, to);
    });

  g_lua.writeFunction("showSelfAnsweredResponseRules", [](boost::optional<bool> showUUIDs) {
      showRules(&g_selfansweredresprulactions, showUUIDs);
    });

  g_lua.writeFunction("rmSelfAnsweredResponseRule", [](boost::variant<unsigned int, std::string> id) {
      rmRule(&g_selfansweredresprulactions, id);
    });

  g_lua.writeFunction("topSelfAnsweredResponseRule", []() {
      topRule(&g_selfansweredresprulactions);
    });

  g_lua.writeFunction("mvSelfAnsweredResponseRule", [](unsigned int from, unsigned int to) {
      mvRule(&g_selfansweredresprulactions, from, to);
    });

  g_lua.writeFunction("rmRule", [](boost::variant<unsigned int, std::string> id) {
      rmRule(&g_rulactions, id);
    });

  g_lua.writeFunction("topRule", []() {
      topRule(&g_rulactions);
    });

  g_lua.writeFunction("mvRule", [](unsigned int from, unsigned int to) {
      mvRule(&g_rulactions, from, to);
    });

  g_lua.writeFunction("clearRules", []() {
      setLuaSideEffect();
      g_rulactions.modify([](decltype(g_rulactions)::value_type& rulactions) {
          rulactions.clear();
        });
    });

  g_lua.writeFunction("setRules", [](std::vector<DNSDistRuleAction>& newruleactions) {
      setLuaSideEffect();
      g_rulactions.modify([newruleactions](decltype(g_rulactions)::value_type& gruleactions) {
          gruleactions.clear();
          for (const auto& newruleaction : newruleactions) {
            if (newruleaction.d_action) {
              auto rule=makeRule(newruleaction.d_rule);
              gruleactions.push_back({rule, newruleaction.d_action, newruleaction.d_id});
            }
          }
        });
    });

  g_lua.writeFunction("MaxQPSIPRule", [](unsigned int qps, boost::optional<int> ipv4trunc, boost::optional<int> ipv6trunc, boost::optional<int> burst) {
      return std::shared_ptr<DNSRule>(new MaxQPSIPRule(qps, burst.get_value_or(qps), ipv4trunc.get_value_or(32), ipv6trunc.get_value_or(64)));
    });

  g_lua.writeFunction("MaxQPSRule", [](unsigned int qps, boost::optional<int> burst) {
      if(!burst)
        return std::shared_ptr<DNSRule>(new MaxQPSRule(qps));
      else
        return std::shared_ptr<DNSRule>(new MaxQPSRule(qps, *burst));
    });

  g_lua.writeFunction("RegexRule", [](const std::string& str) {
      return std::shared_ptr<DNSRule>(new RegexRule(str));
    });

#ifdef HAVE_RE2
  g_lua.writeFunction("RE2Rule", [](const std::string& str) {
      return std::shared_ptr<DNSRule>(new RE2Rule(str));
    });
#endif

  g_lua.writeFunction("SuffixMatchNodeRule", [](const SuffixMatchNode& smn, boost::optional<bool> quiet) {
      return std::shared_ptr<DNSRule>(new SuffixMatchNodeRule(smn, quiet ? *quiet : false));
    });

  g_lua.writeFunction("NetmaskGroupRule", [](const NetmaskGroup& nmg, boost::optional<bool> src) {
      return std::shared_ptr<DNSRule>(new NetmaskGroupRule(nmg, src ? *src : true));
    });

  g_lua.writeFunction("benchRule", [](std::shared_ptr<DNSRule> rule, boost::optional<int> times_, boost::optional<string> suffix_)  {
      setLuaNoSideEffect();
      int times = times_.get_value_or(100000);
      DNSName suffix(suffix_.get_value_or("powerdns.com"));
      struct item {
        vector<uint8_t> packet;
        ComboAddress rem;
        DNSName qname;
        uint16_t qtype, qclass;
      };
      vector<item> items;
      items.reserve(1000);
      for(int n=0; n < 1000; ++n) {
        struct item i;
        i.qname=DNSName(std::to_string(random()));
        i.qname += suffix;
        i.qtype = random() % 0xff;
        i.qclass = 1;
        i.rem=ComboAddress("127.0.0.1");
        i.rem.sin4.sin_addr.s_addr = random();
        DNSPacketWriter pw(i.packet, i.qname, i.qtype);
        items.push_back(i);
      }

      int matches=0;
      ComboAddress dummy("127.0.0.1");
      StopWatch sw;
      sw.start();
      for(int n=0; n < times; ++n) {
        const item& i = items[n % items.size()];
        DNSQuestion dq(&i.qname, i.qtype, i.qclass, &i.rem, &i.rem, (struct dnsheader*)&i.packet[0], i.packet.size(), i.packet.size(), false, &sw.d_start);
        if(rule->matches(&dq))
          matches++;
      }
      double udiff=sw.udiff();
      g_outputBuffer=(boost::format("Had %d matches out of %d, %.1f qps, in %.1f usec\n") % matches % times % (1000000*(1.0*times/udiff)) % udiff).str();

    });

  g_lua.writeFunction("AllRule", []() {
      return std::shared_ptr<DNSRule>(new AllRule());
    });

  g_lua.writeFunction("ProbaRule", [](double proba) {
      return std::shared_ptr<DNSRule>(new ProbaRule(proba));
    });

  g_lua.writeFunction("QNameRule", [](const std::string& qname) {
      return std::shared_ptr<DNSRule>(new QNameRule(DNSName(qname)));
    });

  g_lua.writeFunction("QTypeRule", [](boost::variant<int, std::string> str) {
      uint16_t qtype;
      if(auto dir = boost::get<int>(&str)) {
        qtype = *dir;
      }
      else {
        string val=boost::get<string>(str);
        qtype = QType::chartocode(val.c_str());
        if(!qtype)
          throw std::runtime_error("Unable to convert '"+val+"' to a DNS type");
      }
      return std::shared_ptr<DNSRule>(new QTypeRule(qtype));
    });

  g_lua.writeFunction("QClassRule", [](int c) {
      return std::shared_ptr<DNSRule>(new QClassRule(c));
    });

  g_lua.writeFunction("OpcodeRule", [](uint8_t code) {
      return std::shared_ptr<DNSRule>(new OpcodeRule(code));
    });

  g_lua.writeFunction("AndRule", [](vector<pair<int, std::shared_ptr<DNSRule> > >a) {
      return std::shared_ptr<DNSRule>(new AndRule(a));
    });

  g_lua.writeFunction("OrRule", [](vector<pair<int, std::shared_ptr<DNSRule> > >a) {
      return std::shared_ptr<DNSRule>(new OrRule(a));
    });

  g_lua.writeFunction("TCPRule", [](bool tcp) {
      return std::shared_ptr<DNSRule>(new TCPRule(tcp));
    });

  g_lua.writeFunction("DNSSECRule", []() {
      return std::shared_ptr<DNSRule>(new DNSSECRule());
    });

  g_lua.writeFunction("NotRule", [](std::shared_ptr<DNSRule>rule) {
      return std::shared_ptr<DNSRule>(new NotRule(rule));
    });

  g_lua.writeFunction("RecordsCountRule", [](uint8_t section, uint16_t minCount, uint16_t maxCount) {
      return std::shared_ptr<DNSRule>(new RecordsCountRule(section, minCount, maxCount));
    });

  g_lua.writeFunction("RecordsTypeCountRule", [](uint8_t section, uint16_t type, uint16_t minCount, uint16_t maxCount) {
      return std::shared_ptr<DNSRule>(new RecordsTypeCountRule(section, type, minCount, maxCount));
    });

  g_lua.writeFunction("TrailingDataRule", []() {
      return std::shared_ptr<DNSRule>(new TrailingDataRule());
    });

  g_lua.writeFunction("QNameLabelsCountRule", [](unsigned int minLabelsCount, unsigned int maxLabelsCount) {
      return std::shared_ptr<DNSRule>(new QNameLabelsCountRule(minLabelsCount, maxLabelsCount));
    });

  g_lua.writeFunction("QNameWireLengthRule", [](size_t min, size_t max) {
      return std::shared_ptr<DNSRule>(new QNameWireLengthRule(min, max));
    });

  g_lua.writeFunction("RCodeRule", [](uint8_t rcode) {
      return std::shared_ptr<DNSRule>(new RCodeRule(rcode));
    });

  g_lua.writeFunction("ERCodeRule", [](uint8_t rcode) {
      return std::shared_ptr<DNSRule>(new ERCodeRule(rcode));
    });

  g_lua.writeFunction("showRules", [](boost::optional<bool> showUUIDs) {
      showRules(&g_rulactions, showUUIDs);
    });

  g_lua.writeFunction("RDRule", []() {
      return std::shared_ptr<DNSRule>(new RDRule());
    });

  g_lua.writeFunction("TagRule", [](std::string tag, boost::optional<std::string> value) {
      return std::shared_ptr<DNSRule>(new TagRule(tag, value));
    });

  g_lua.writeFunction("TimedIPSetRule", []() {
      return std::shared_ptr<TimedIPSetRule>(new TimedIPSetRule());
    });

  g_lua.registerFunction<void(std::shared_ptr<TimedIPSetRule>::*)()>("clear", [](std::shared_ptr<TimedIPSetRule> tisr) {
      tisr->clear();
    });

  g_lua.registerFunction<void(std::shared_ptr<TimedIPSetRule>::*)()>("cleanup", [](std::shared_ptr<TimedIPSetRule> tisr) {
      tisr->cleanup();
    });

  g_lua.registerFunction<void(std::shared_ptr<TimedIPSetRule>::*)(const ComboAddress& ca, int t)>("add", [](std::shared_ptr<TimedIPSetRule> tisr, const ComboAddress& ca, int t) {
      tisr->add(ca, time(0)+t);
    });

  g_lua.registerFunction<std::shared_ptr<DNSRule>(std::shared_ptr<TimedIPSetRule>::*)()>("slice", [](std::shared_ptr<TimedIPSetRule> tisr) {
      return std::dynamic_pointer_cast<DNSRule>(tisr);
    });
}
