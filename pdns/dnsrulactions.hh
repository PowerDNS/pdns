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
#include "dnsname.hh"
#include "dolog.hh"
#include "ednsoptions.hh"
#include "lock.hh"
#include "remote_logger.hh"
#include "dnsdist-protobuf.hh"
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
  RCodeRule(int rcode) : d_rcode(rcode)
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
  int d_rcode;
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
  bool matches(const DNSQuestion* dq) const override;
  string toString() const override;
  double d_proba;
};


class DropAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    return Action::Drop;
  }
  string toString() const override
  {
    return "drop";
  }
};

class AllowAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    return Action::Allow;
  }
  string toString() const override
  {
    return "allow";
  }
};


class QPSAction : public DNSAction
{
public:
  QPSAction(int limit) : d_qps(limit, limit) 
  {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if(d_qps.check())
      return Action::None;
    else
      return Action::Drop;
  }
  string toString() const override
  {
    return "qps limit to "+std::to_string(d_qps.getRate()); 
  }
private:
  QPSLimiter d_qps;
};

class DelayAction : public DNSAction
{
public:
  DelayAction(int msec) : d_msec(msec)
  {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    *ruleresult=std::to_string(d_msec);
    return Action::Delay;
  }
  string toString() const override
  {
    return "delay by "+std::to_string(d_msec)+ " msec";
  }
private:
  int d_msec;
};


class TeeAction : public DNSAction
{
public:
  TeeAction(const ComboAddress& ca, bool addECS=false);
  ~TeeAction() override;
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override;
  string toString() const override;
  std::unordered_map<string, double> getStats() const override;

private:
  ComboAddress d_remote;
  std::thread d_worker;
  void worker();

  int d_fd;
  mutable std::atomic<unsigned long> d_senderrors{0};
  unsigned long d_recverrors{0};
  mutable std::atomic<unsigned long> d_queries{0};
  unsigned long d_responses{0};
  unsigned long d_nxdomains{0};
  unsigned long d_servfails{0};
  unsigned long d_refuseds{0};
  unsigned long d_formerrs{0};
  unsigned long d_notimps{0};
  unsigned long d_noerrors{0};
  mutable unsigned long d_tcpdrops{0};
  unsigned long d_otherrcode{0};
  std::atomic<bool> d_pleaseQuit{false};
  bool d_addECS{false};
};

class PoolAction : public DNSAction
{
public:
  PoolAction(const std::string& pool) : d_pool(pool) {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    *ruleresult=d_pool;
    return Action::Pool;
  }
  string toString() const override
  {
    return "to pool "+d_pool;
  }

private:
  string d_pool;
};


class QPSPoolAction : public DNSAction
{
public:
  QPSPoolAction(unsigned int limit, const std::string& pool) : d_qps(limit, limit), d_pool(pool) {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if(d_qps.check()) {
      *ruleresult=d_pool;
      return Action::Pool;
    }
    else 
      return Action::None;
  }
  string toString() const override
  {
    return "max " +std::to_string(d_qps.getRate())+" to pool "+d_pool;
  }

private:
  QPSLimiter d_qps;
  string d_pool;
};

class RCodeAction : public DNSAction
{
public:
  RCodeAction(int rcode) : d_rcode(rcode) {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->dh->rcode = d_rcode;
    dq->dh->qr = true; // for good measure
    return Action::HeaderModify;
  }
  string toString() const override
  {
    return "set rcode "+std::to_string(d_rcode);
  }

private:
  int d_rcode;
};

class TCAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    return Action::Truncate;
  }
  string toString() const override
  {
    return "tc=1 answer";
  }
};

class SpoofAction : public DNSAction
{
public:
  SpoofAction(const vector<ComboAddress>& addrs) : d_addrs(addrs)
  {
  }

  SpoofAction(const string& cname): d_cname(cname) { }

  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    uint16_t qtype = dq->qtype;
    // do we even have a response? 
    if(d_cname.empty() && !std::count_if(d_addrs.begin(), d_addrs.end(), [qtype](const ComboAddress& a)
                                    {
                                      return (qtype == QType::ANY || ((a.sin4.sin_family == AF_INET && qtype == QType::A) ||
                                                                      (a.sin4.sin_family == AF_INET6 && qtype == QType::AAAA)));
                                    })) 
      return Action::None;
    
    vector<ComboAddress> addrs;
    unsigned int totrdatalen=0;
    if (!d_cname.empty()) {
      qtype = QType::CNAME;
      totrdatalen += d_cname.toDNSString().size();
    } else {
      for(const auto& addr : d_addrs) {
        if(qtype != QType::ANY && ((addr.sin4.sin_family == AF_INET && qtype != QType::A) ||
                                   (addr.sin4.sin_family == AF_INET6 && qtype != QType::AAAA)))
          continue;
        totrdatalen += addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr);
        addrs.push_back(addr);
      }
    }

    if(addrs.size() > 1)
      random_shuffle(addrs.begin(), addrs.end());

    unsigned int consumed=0;
    DNSName ignore((char*)dq->dh, dq->len, sizeof(dnsheader), false, 0, 0, &consumed);

    if (dq->size < (sizeof(dnsheader) + consumed + 4 + ((d_cname.empty() ? 0 : 1) + addrs.size())*12 /* recordstart */ + totrdatalen)) {
      return Action::None;
    }

    dq->len = sizeof(dnsheader) + consumed + 4; // there goes your EDNS
    char* dest = ((char*)dq->dh) + dq->len;
    
    dq->dh->qr = true; // for good measure
    dq->dh->ra = dq->dh->rd; // for good measure
    dq->dh->ad = false;
    dq->dh->ancount = 0;
    dq->dh->arcount = 0; // for now, forget about your EDNS, we're marching over it

    if(qtype == QType::CNAME) {
      string wireData = d_cname.toDNSString(); // Note! This doesn't do compression!
      const unsigned char recordstart[]={0xc0, 0x0c,    // compressed name
                                         0, (unsigned char) qtype,
                                         0, QClass::IN, // IN
                                         0, 0, 0, 60,   // TTL
                                         0, (unsigned char)wireData.length()};
      static_assert(sizeof(recordstart) == 12, "sizeof(recordstart) must be equal to 12, otherwise the above check is invalid");

      memcpy(dest, recordstart, sizeof(recordstart));
      dest += sizeof(recordstart);
      memcpy(dest, wireData.c_str(), wireData.length());
      dq->len += wireData.length() + sizeof(recordstart);
      dq->dh->ancount++;
    }
    else {
      for(const auto& addr : addrs) {
        unsigned char rdatalen = addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4.sin_addr.s_addr) : sizeof(addr.sin6.sin6_addr.s6_addr);
        const unsigned char recordstart[]={0xc0, 0x0c,    // compressed name
                                           0, (unsigned char) (addr.sin4.sin_family == AF_INET ? QType::A : QType::AAAA),
                                           0, QClass::IN, // IN
                                           0, 0, 0, 60,   // TTL
                                           0, rdatalen};
        static_assert(sizeof(recordstart) == 12, "sizeof(recordstart) must be equal to 12, otherwise the above check is invalid");

        memcpy(dest, recordstart, sizeof(recordstart));
        dest += sizeof(recordstart);

        memcpy(dest,
               addr.sin4.sin_family == AF_INET ? (void*)&addr.sin4.sin_addr.s_addr : (void*)&addr.sin6.sin6_addr.s6_addr,
               rdatalen);
        dest += rdatalen;
        dq->len += rdatalen + sizeof(recordstart);
        dq->dh->ancount++;
      }
    }

    dq->dh->ancount = htons(dq->dh->ancount);
    
    return Action::HeaderModify;
  }

  string toString() const override
  {
    string ret = "spoof in ";
    if(!d_cname.empty()) {
      ret+=d_cname.toString()+ " ";
    } else {
      for(const auto& a : d_addrs)
        ret += a.toString()+" ";
    }
    return ret;
  }
private:
  std::vector<ComboAddress> d_addrs;
  DNSName d_cname;
};

class MacAddrAction : public DNSAction
{
public:
  MacAddrAction(uint16_t code) : d_code(code)
  {}
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if(dq->dh->arcount)
      return Action::None;

    string mac = getMACAddress(*dq->remote);
    if(mac.empty())
      return Action::None;

    string optRData;
    generateEDNSOption(d_code, mac, optRData);

    string res;
    generateOptRR(optRData, res);

    if ((dq->size - dq->len) < res.length())
      return Action::None;

    dq->dh->arcount = htons(1);
    char* dest = ((char*)dq->dh) + dq->len;
    memcpy(dest, res.c_str(), res.length());
    dq->len += res.length();

    return Action::None;
  }  
  string toString() const override
  {
    return "add EDNS MAC (code="+std::to_string(d_code)+")";
  }
private:
  uint16_t d_code{3};
};

class NoRecurseAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->dh->rd = false;
    return Action::None;
  }
  string toString() const override
  {
    return "set rd=0";
  }
};

class LogAction : public DNSAction, public boost::noncopyable
{
public:
  LogAction() : d_fp(0)
  {
  }
  LogAction(const std::string& str, bool binary=true, bool append=false, bool buffered=true) : d_fname(str), d_binary(binary)
  {
    if(str.empty())
      return;
    if(append)
      d_fp = fopen(str.c_str(), "a+");
    else
      d_fp = fopen(str.c_str(), "w");
    if(!d_fp)
      throw std::runtime_error("Unable to open file '"+str+"' for logging: "+string(strerror(errno)));
    if(!buffered)
      setbuf(d_fp, 0);
  }
  ~LogAction() override
  {
    if(d_fp)
      fclose(d_fp);
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if(!d_fp) {
      vinfolog("Packet from %s for %s %s with id %d", dq->remote->toStringWithPort(), dq->qname->toString(), QType(dq->qtype).getName(), dq->dh->id);
    }
    else {
      if(d_binary) {
        string out = dq->qname->toDNSString();
        fwrite(out.c_str(), 1, out.size(), d_fp);
        fwrite((void*)&dq->qtype, 1, 2, d_fp);
      }
      else {
        fprintf(d_fp, "Packet from %s for %s %s with id %d\n", dq->remote->toStringWithPort().c_str(), dq->qname->toString().c_str(), QType(dq->qtype).getName().c_str(), dq->dh->id);
      }
    }
    return Action::None;
  }
  string toString() const override
  {
    if (!d_fname.empty()) {
      return "log to " + d_fname;
    }
    return "log";
  }
private:
  string d_fname;
  FILE* d_fp{0};
  bool d_binary{true};
};


class DisableValidationAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->dh->cd = true;
    return Action::None;
  }
  string toString() const override
  {
    return "set cd=1";
  }
};

class SkipCacheAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->skipCache = true;
    return Action::None;
  }
  string toString() const override
  {
    return "skip cache";
  }
};

class ECSPrefixLengthAction : public DNSAction
{
public:
  ECSPrefixLengthAction(uint16_t v4Length, uint16_t v6Length) : d_v4PrefixLength(v4Length), d_v6PrefixLength(v6Length)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->ecsPrefixLength = dq->remote->sin4.sin_family == AF_INET ? d_v4PrefixLength : d_v6PrefixLength;
    return Action::None;
  }
  string toString() const override
  {
    return "set ECS prefix length to " + std::to_string(d_v4PrefixLength) + "/" + std::to_string(d_v6PrefixLength);
  }
private:
  uint16_t d_v4PrefixLength;
  uint16_t d_v6PrefixLength;
};

class ECSOverrideAction : public DNSAction
{
public:
  ECSOverrideAction(bool ecsOverride) : d_ecsOverride(ecsOverride)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->ecsOverride = d_ecsOverride;
    return Action::None;
  }
  string toString() const override
  {
    return "set ECS override to " + std::to_string(d_ecsOverride);
  }
private:
  bool d_ecsOverride;
};


class DisableECSAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->useECS = false;
    return Action::None;
  }
  string toString() const override
  {
    return "disable ECS";
  }
};

class RemoteLogAction : public DNSAction, public boost::noncopyable
{
public:
  RemoteLogAction(std::shared_ptr<RemoteLogger> logger, boost::optional<std::function<void(const DNSQuestion&, DNSDistProtoBufMessage*)> > alterFunc): d_logger(logger), d_alterFunc(alterFunc)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    if (!dq->uniqueId) {
      dq->uniqueId = t_uuidGenerator();
    }

    DNSDistProtoBufMessage message(*dq);
    {
      if (d_alterFunc) {
        std::lock_guard<std::mutex> lock(g_luamutex);
        (*d_alterFunc)(*dq, &message);
      }
    }
    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  string toString() const override
  {
    return "remote log to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::shared_ptr<RemoteLogger> d_logger;
  boost::optional<std::function<void(const DNSQuestion&, DNSDistProtoBufMessage*)> > d_alterFunc;
};

class SNMPTrapAction : public DNSAction
{
public:
  SNMPTrapAction(const std::string& reason): d_reason(reason)
  {
  }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    if (g_snmpAgent && g_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(*dq, d_reason);
    }

    return Action::None;
  }
  string toString() const override
  {
    return "send SNMP trap";
  }
private:
  std::string d_reason;
};

class RemoteLogResponseAction : public DNSResponseAction, public boost::noncopyable
{
public:
  RemoteLogResponseAction(std::shared_ptr<RemoteLogger> logger, boost::optional<std::function<void(const DNSResponse&, DNSDistProtoBufMessage*)> > alterFunc, bool includeCNAME): d_logger(logger), d_alterFunc(alterFunc), d_includeCNAME(includeCNAME)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
#ifdef HAVE_PROTOBUF
    if (!dr->uniqueId) {
      dr->uniqueId = t_uuidGenerator();
    }

    DNSDistProtoBufMessage message(*dr, d_includeCNAME);
    {
      if (d_alterFunc) {
        std::lock_guard<std::mutex> lock(g_luamutex);
        (*d_alterFunc)(*dr, &message);
      }
    }
    std::string data;
    message.serialize(data);
    d_logger->queueData(data);
#endif /* HAVE_PROTOBUF */
    return Action::None;
  }
  string toString() const override
  {
    return "remote log response to " + (d_logger ? d_logger->toString() : "");
  }
private:
  std::shared_ptr<RemoteLogger> d_logger;
  boost::optional<std::function<void(const DNSResponse&, DNSDistProtoBufMessage*)> > d_alterFunc;
  bool d_includeCNAME;
};

class DropResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    return Action::Drop;
  }
  string toString() const override
  {
    return "drop";
  }
};

class AllowResponseAction : public DNSResponseAction
{
public:
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    return Action::Allow;
  }
  string toString() const override
  {
    return "allow";
  }
};

class DelayResponseAction : public DNSResponseAction
{
public:
  DelayResponseAction(int msec) : d_msec(msec)
  {}
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    *ruleresult=std::to_string(d_msec);
    return Action::Delay;
  }
  string toString() const override
  {
    return "delay by "+std::to_string(d_msec)+ " msec";
  }
private:
  int d_msec;
};

class SNMPTrapResponseAction : public DNSResponseAction
{
public:
  SNMPTrapResponseAction(const std::string& reason): d_reason(reason)
  {
  }
  DNSResponseAction::Action operator()(DNSResponse* dr, string* ruleresult) const override
  {
    if (g_snmpAgent && g_snmpTrapsEnabled) {
      g_snmpAgent->sendDNSTrap(*dr, d_reason);
    }

    return Action::None;
  }
  string toString() const override
  {
    return "send SNMP trap";
  }
private:
  std::string d_reason;
};
