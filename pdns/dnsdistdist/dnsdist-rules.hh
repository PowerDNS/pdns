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

#include "cachecleaner.hh"
#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-kvs.hh"
#include "dnsparser.hh"

class MaxQPSIPRule : public DNSRule
{
public:
  MaxQPSIPRule(unsigned int qps, unsigned int burst, unsigned int ipv4trunc=32, unsigned int ipv6trunc=64, unsigned int expiration=300, unsigned int cleanupDelay=60, unsigned int scanFraction=10):
    d_qps(qps), d_burst(burst), d_ipv4trunc(ipv4trunc), d_ipv6trunc(ipv6trunc), d_cleanupDelay(cleanupDelay), d_expiration(expiration), d_scanFraction(scanFraction)
  {
    gettime(&d_lastCleanup, true);
  }

  void clear()
  {
    std::lock_guard<std::mutex> lock(d_lock);
    d_limits.clear();
  }

  size_t cleanup(const struct timespec& cutOff, size_t* scannedCount=nullptr) const
  {
    std::lock_guard<std::mutex> lock(d_lock);
    size_t toLook = d_limits.size() / d_scanFraction + 1;
    size_t lookedAt = 0;

    size_t removed = 0;
    auto& sequence = d_limits.get<SequencedTag>();
    for (auto entry = sequence.begin(); entry != sequence.end() && lookedAt < toLook; lookedAt++) {
      if (entry->d_limiter.seenSince(cutOff)) {
        /* entries are ordered from least recently seen to more recently
           seen, as soon as we see one that has not expired yet, we are
           done */
        lookedAt++;
        break;
      }

      entry = sequence.erase(entry);
      removed++;
    }

    if (scannedCount != nullptr) {
      *scannedCount = lookedAt;
    }

    return removed;
  }

  void cleanupIfNeeded(const struct timespec& now) const
  {
    if (d_cleanupDelay > 0) {
      struct timespec cutOff = d_lastCleanup;
      cutOff.tv_sec += d_cleanupDelay;

      if (cutOff < now) {
        /* the QPS Limiter doesn't use realtime, be careful! */
        gettime(&cutOff, false);
        cutOff.tv_sec -= d_expiration;

        cleanup(cutOff);

        d_lastCleanup = now;
      }
    }
  }

  bool matches(const DNSQuestion* dq) const override
  {
    cleanupIfNeeded(*dq->queryTime);

    ComboAddress zeroport(*dq->remote);
    zeroport.sin4.sin_port=0;
    zeroport.truncate(zeroport.sin4.sin_family == AF_INET ? d_ipv4trunc : d_ipv6trunc);
    {
      std::lock_guard<std::mutex> lock(d_lock);
      auto iter = d_limits.find(zeroport);
      if (iter == d_limits.end()) {
        Entry e(zeroport, QPSLimiter(d_qps, d_burst));
        iter = d_limits.insert(e).first;
      }

      moveCacheItemToBack(d_limits, iter);
      return !iter->d_limiter.check(d_qps, d_burst);
    }
  }

  string toString() const override
  {
    return "IP (/"+std::to_string(d_ipv4trunc)+", /"+std::to_string(d_ipv6trunc)+") match for QPS over " + std::to_string(d_qps) + " burst "+ std::to_string(d_burst);
  }

  size_t getEntriesCount() const
  {
    std::lock_guard<std::mutex> lock(d_lock);
    return d_limits.size();
  }

private:
  struct OrderedTag {};
  struct SequencedTag {};
  struct Entry
  {
    Entry(const ComboAddress& addr, BasicQPSLimiter&& limiter): d_limiter(limiter), d_addr(addr)
    {
    }
    mutable BasicQPSLimiter d_limiter;
    ComboAddress d_addr;
  };

  typedef multi_index_container<
    Entry,
    indexed_by <
      ordered_unique<tag<OrderedTag>, member<Entry,ComboAddress,&Entry::d_addr>, ComboAddress::addressOnlyLessThan >,
      sequenced<tag<SequencedTag> >
      >
  > qpsContainer_t;

  mutable std::mutex d_lock;
  mutable qpsContainer_t d_limits;
  mutable struct timespec d_lastCleanup;
  unsigned int d_qps, d_burst, d_ipv4trunc, d_ipv6trunc, d_cleanupDelay, d_expiration;
  unsigned int d_scanFraction{10};
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
  NetmaskGroupRule(const NetmaskGroup& nmg, bool src, bool quiet = false) : NMGRule(nmg)
  {
      d_src = src;
      d_quiet = quiet;
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
    string ret = "Src: ";
    if(!d_src) {
        ret = "Dst: ";
    }
    if (d_quiet) {
      return ret + "in-group";
    }
    return ret + d_nmg.toString();
  }
private:
  bool d_src;
  bool d_quiet;
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
    return dq->dh->cd || (getEDNSZ(*dq) & EDNS_HEADER_FLAG_DO);    // turns out dig sets ad by default..
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

#ifdef HAVE_DNS_OVER_HTTPS
class HTTPHeaderRule : public DNSRule
{
public:
  HTTPHeaderRule(const std::string& header, const std::string& regex);
  bool matches(const DNSQuestion* dq) const override;
  string toString() const override;
private:
  string d_header;
  Regex d_regex;
  string d_visual;
};

class HTTPPathRule : public DNSRule
{
public:
  HTTPPathRule(const std::string& path);
  bool matches(const DNSQuestion* dq) const override;
  string toString() const override;
private:
  string d_path;
};

class HTTPPathRegexRule : public DNSRule
{
public:
  HTTPPathRegexRule(const std::string& regex);
  bool matches(const DNSQuestion* dq) const override;
  string toString() const override;
private:
  Regex d_regex;
  std::string d_visual;
};
#endif

class SNIRule : public DNSRule
{
public:
  SNIRule(const std::string& name) : d_sni(name)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return dq->sni == d_sni;
  }
  string toString() const override
  {
    return "SNI == " + d_sni;
  }
private:
  std::string d_sni;
};

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

class QNameSetRule : public DNSRule {
public:
    QNameSetRule(const DNSNameSet& names) : qname_idx(names) {}

    bool matches(const DNSQuestion* dq) const override {
        return qname_idx.find(*dq->qname) != qname_idx.end();
    }

    string toString() const override {
        std::stringstream ss;
        ss << "qname in DNSNameSet(" << qname_idx.size() << " FQDNs)";
        return ss.str();
    }
private:
    DNSNameSet qname_idx;
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

class DSTPortRule : public DNSRule
{
public:
  DSTPortRule(uint16_t port) : d_port(port)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return htons(d_port) == dq->local->sin4.sin_port;
  }
  string toString() const override
  {
    return "dst port=="+std::to_string(d_port);
  }
private:
  uint16_t d_port;
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

    EDNS0Record edns0;
    if (!getEDNS0Record(*dq, edns0)) {
      return false;
    }

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

class EDNSVersionRule : public DNSRule
{
public:
  EDNSVersionRule(uint8_t version) : d_version(version)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    EDNS0Record edns0;
    if (!getEDNS0Record(*dq, edns0)) {
      return false;
    }

    return d_version < edns0.version;
  }
  string toString() const override
  {
    return "ednsversion>"+std::to_string(d_version);
  }
private:
  uint8_t d_version;
};

class EDNSOptionRule : public DNSRule
{
public:
  EDNSOptionRule(uint16_t optcode) : d_optcode(optcode)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    uint16_t optStart;
    size_t optLen = 0;
    bool last = false;
    const char * packet = reinterpret_cast<const char*>(dq->dh);
    std::string packetStr(packet, dq->len);
    int res = locateEDNSOptRR(packetStr, &optStart, &optLen, &last);
    if (res != 0) {
      // no EDNS OPT RR
      return false;
    }

    if (optLen < optRecordMinimumSize) {
      return false;
    }

    if (optStart < dq->len && packetStr.at(optStart) != 0) {
      // OPT RR Name != '.'
      return false;
    }

    return isEDNSOptionInOpt(packetStr, optStart, optLen, d_optcode);
  }
  string toString() const override
  {
    return "ednsoptcode=="+std::to_string(d_optcode);
  }
private:
  uint16_t d_optcode;
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
  TagRule(const std::string& tag, boost::optional<std::string> value) : d_value(value), d_tag(tag)
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

class PoolAvailableRule : public DNSRule
{
public:
  PoolAvailableRule(const std::string& poolname) : d_pools(&g_pools), d_poolname(poolname)
  {
  }

  bool matches(const DNSQuestion* dq) const override
  {
    return (getPool(*d_pools, d_poolname)->countServers(true) > 0);
  }

  string toString() const override
  {
    return "pool '" + d_poolname + "' is available";
  }
private:
  mutable LocalStateHolder<pools_t> d_pools;
  std::string d_poolname;
};

class KeyValueStoreLookupRule: public DNSRule
{
public:
  KeyValueStoreLookupRule(std::shared_ptr<KeyValueStore>& kvs, std::shared_ptr<KeyValueLookupKey>& lookupKey): d_kvs(kvs), d_key(lookupKey)
  {
  }

  bool matches(const DNSQuestion* dq) const override
  {
    std::vector<std::string> keys = d_key->getKeys(*dq);
    for (const auto& key : keys) {
      if (d_kvs->keyExists(key) == true) {
        return true;
      }
    }

    return false;
  }

  string toString() const override
  {
    return "lookup key-value store based on '" + d_key->toString() + "'";
  }

private:
  std::shared_ptr<KeyValueStore> d_kvs;
  std::shared_ptr<KeyValueLookupKey> d_key;
};
