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

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include "cachecleaner.hh"
#include "dnsdist-ecs.hh"
#include "dnsdist-kvs.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-lua-ffi.hh"
#include "dnsdist-rules.hh"
#include "dolog.hh"
#include "dnsparser.hh"
#include "dns_random.hh"
#include "uuid-utils.hh"

namespace dnsdist::selectors
{
using LuaSelectorFunction = std::function<bool(const DNSQuestion* dq)>;
using LuaSelectorFFIFunction = std::function<bool(dnsdist_ffi_dnsquestion_t* dq)>;
}

class MaxQPSIPRule : public DNSRule
{
public:
  MaxQPSIPRule(unsigned int qps, unsigned int ipv4trunc = 32, unsigned int ipv6trunc = 64, unsigned int burst = 0, unsigned int expiration = 300, unsigned int cleanupDelay = 60, unsigned int scanFraction = 10, size_t shardsCount = 10) :
    d_shards(shardsCount), d_qps(qps), d_burst(burst == 0 ? qps : burst), d_ipv4trunc(ipv4trunc), d_ipv6trunc(ipv6trunc), d_cleanupDelay(cleanupDelay), d_expiration(expiration), d_scanFraction(scanFraction)
  {
    d_cleaningUp.clear();
    gettime(&d_lastCleanup, true);
  }

  void clear()
  {
    for (auto& shard : d_shards) {
      shard.lock()->clear();
    }
  }

  size_t cleanup(const struct timespec& cutOff, size_t* scannedCount = nullptr) const
  {
    size_t removed = 0;
    if (scannedCount != nullptr) {
      *scannedCount = 0;
    }

    for (auto& shard : d_shards) {
      auto limits = shard.lock();
      const size_t toLook = std::round((1.0 * limits->size()) / d_scanFraction) + 1;
      size_t lookedAt = 0;

      auto& sequence = limits->get<SequencedTag>();
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
        *scannedCount += lookedAt;
      }
    }

    return removed;
  }

  void cleanupIfNeeded(const struct timespec& now) const
  {
    if (d_cleanupDelay > 0) {
      struct timespec cutOff = d_lastCleanup;
      cutOff.tv_sec += d_cleanupDelay;

      if (cutOff < now) {
        try {
          if (d_cleaningUp.test_and_set()) {
            return;
          }

          d_lastCleanup = now;
          /* the QPS Limiter doesn't use realtime, be careful! */
          gettime(&cutOff, false);
          cutOff.tv_sec -= d_expiration;

          cleanup(cutOff);
          d_cleaningUp.clear();
        }
        catch (...) {
          d_cleaningUp.clear();
          throw;
        }
      }
    }
  }

  bool matches(const DNSQuestion* dq) const override
  {
    cleanupIfNeeded(dq->getQueryRealTime());

    ComboAddress zeroport(dq->ids.origRemote);
    zeroport.sin4.sin_port = 0;
    zeroport.truncate(zeroport.sin4.sin_family == AF_INET ? d_ipv4trunc : d_ipv6trunc);
    auto hash = ComboAddress::addressOnlyHash()(zeroport);
    auto& shard = d_shards[hash % d_shards.size()];
    {
      auto limits = shard.lock();
      auto iter = limits->find(zeroport);
      if (iter == limits->end()) {
        Entry e(zeroport, QPSLimiter(d_qps, d_burst));
        iter = limits->insert(e).first;
      }

      moveCacheItemToBack<SequencedTag>(*limits, iter);
      return !iter->d_limiter.check(d_qps, d_burst);
    }
  }

  string toString() const override
  {
    return "IP (/" + std::to_string(d_ipv4trunc) + ", /" + std::to_string(d_ipv6trunc) + ") match for QPS over " + std::to_string(d_qps) + " burst " + std::to_string(d_burst);
  }

  size_t getEntriesCount() const
  {
    size_t count = 0;
    for (auto& shard : d_shards) {
      count += shard.lock()->size();
    }
    return count;
  }

  size_t getNumberOfShards() const
  {
    return d_shards.size();
  }

private:
  struct HashedTag
  {
  };
  struct SequencedTag
  {
  };
  struct Entry
  {
    Entry(const ComboAddress& addr, BasicQPSLimiter&& limiter) :
      d_limiter(limiter), d_addr(addr)
    {
    }
    mutable BasicQPSLimiter d_limiter;
    ComboAddress d_addr;
  };

  using qpsContainer_t = multi_index_container<
    Entry,
    indexed_by<
      hashed_unique<tag<HashedTag>, member<Entry, ComboAddress, &Entry::d_addr>, ComboAddress::addressOnlyHash>,
      sequenced<tag<SequencedTag>>>>;

  mutable std::vector<LockGuarded<qpsContainer_t>> d_shards;
  mutable struct timespec d_lastCleanup;
  const unsigned int d_qps, d_burst, d_ipv4trunc, d_ipv6trunc, d_cleanupDelay, d_expiration;
  const unsigned int d_scanFraction{10};
  mutable std::atomic_flag d_cleaningUp;
};

class MaxQPSRule : public DNSRule
{
public:
  MaxQPSRule(unsigned int qps) :
    d_qps(qps, qps)
  {
  }

  MaxQPSRule(unsigned int qps, unsigned int burst) :
    d_qps(qps, burst > 0 ? burst : qps)
  {
  }

  bool matches(const DNSQuestion* dnsQuestion) const override
  {
    (void)dnsQuestion;
    return d_qps.check();
  }

  string toString() const override
  {
    return "Max " + std::to_string(d_qps.getRate()) + " qps";
  }

private:
  mutable QPSLimiter d_qps;
};

class NetmaskGroupRule : public DNSRule
{
public:
  NetmaskGroupRule(const NetmaskGroup& nmg, bool src, bool quiet = false) :
    d_nmg(nmg)
  {
    d_src = src;
    d_quiet = quiet;
  }
  bool matches(const DNSQuestion* dq) const override
  {
    if (!d_src) {
      return d_nmg.match(dq->ids.origDest);
    }
    return d_nmg.match(dq->ids.origRemote);
  }

  string toString() const override
  {
    string ret = "Src: ";
    if (!d_src) {
      ret = "Dst: ";
    }
    if (d_quiet) {
      return ret + "in-group";
    }
    return ret + d_nmg.toString();
  }

private:
  NetmaskGroup d_nmg;
  bool d_src;
  bool d_quiet;
};

class TimedIPSetRule : public DNSRule, boost::noncopyable
{
private:
  struct IPv6
  {
    IPv6(const ComboAddress& ca)
    {
      static_assert(sizeof(*this) == 16, "IPv6 struct has wrong size");
      memcpy((char*)this, ca.sin6.sin6_addr.s6_addr, 16);
    }
    bool operator==(const IPv6& rhs) const
    {
      return a == rhs.a && b == rhs.b;
    }
    uint64_t a, b;
  };

public:
  TimedIPSetRule()
  {
  }
  ~TimedIPSetRule()
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    if (dq->ids.origRemote.sin4.sin_family == AF_INET) {
      auto ip4s = d_ip4s.read_lock();
      auto fnd = ip4s->find(dq->ids.origRemote.sin4.sin_addr.s_addr);
      if (fnd == ip4s->end()) {
        return false;
      }
      return time(nullptr) < fnd->second;
    }
    else {
      auto ip6s = d_ip6s.read_lock();
      auto fnd = ip6s->find({dq->ids.origRemote});
      if (fnd == ip6s->end()) {
        return false;
      }
      return time(nullptr) < fnd->second;
    }
  }

  void add(const ComboAddress& ca, time_t ttd)
  {
    // think twice before adding templates here
    if (ca.sin4.sin_family == AF_INET) {
      auto res = d_ip4s.write_lock()->insert({ca.sin4.sin_addr.s_addr, ttd});
      if (!res.second && (time_t)res.first->second < ttd) {
        res.first->second = (uint32_t)ttd;
      }
    }
    else {
      auto res = d_ip6s.write_lock()->insert({{ca}, ttd});
      if (!res.second && (time_t)res.first->second < ttd) {
        // coverity[store_truncates_time_t]
        res.first->second = (uint32_t)ttd;
      }
    }
  }

  void remove(const ComboAddress& ca)
  {
    if (ca.sin4.sin_family == AF_INET) {
      d_ip4s.write_lock()->erase(ca.sin4.sin_addr.s_addr);
    }
    else {
      d_ip6s.write_lock()->erase({ca});
    }
  }

  void clear()
  {
    d_ip4s.write_lock()->clear();
    d_ip6s.write_lock()->clear();
  }

  void cleanup()
  {
    time_t now = time(nullptr);
    {
      auto ip4s = d_ip4s.write_lock();
      for (auto iter = ip4s->begin(); iter != ip4s->end();) {
        if (iter->second < now) {
          iter = ip4s->erase(iter);
        }
        else {
          ++iter;
        }
      }
    }

    {
      auto ip6s = d_ip6s.write_lock();
      for (auto iter = ip6s->begin(); iter != ip6s->end();) {
        if (iter->second < now) {
          iter = ip6s->erase(iter);
        }
        else {
          ++iter;
        }
      }
    }
  }

  string toString() const override
  {
    time_t now = time(nullptr);
    uint64_t count = 0;

    for (const auto& ip : *(d_ip4s.read_lock())) {
      if (now < ip.second) {
        ++count;
      }
    }

    for (const auto& ip : *(d_ip6s.read_lock())) {
      if (now < ip.second) {
        ++count;
      }
    }

    return "Src: " + std::to_string(count) + " ips";
  }

private:
  struct IPv6Hash
  {
    std::size_t operator()(const IPv6& ip) const
    {
      auto ah = std::hash<uint64_t>{}(ip.a);
      auto bh = std::hash<uint64_t>{}(ip.b);
      return ah & (bh << 1);
    }
  };
  mutable SharedLockGuarded<std::unordered_map<IPv6, time_t, IPv6Hash>> d_ip6s;
  mutable SharedLockGuarded<std::unordered_map<uint32_t, time_t>> d_ip4s;
};

class AllRule : public DNSRule
{
public:
  AllRule() {}
  bool matches(const DNSQuestion* dnsQuestion) const override
  {
    (void)dnsQuestion;
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
    return dq->getHeader()->cd || (dnsdist::getEDNSZ(*dq) & EDNS_HEADER_FLAG_DO); // turns out dig sets ad by default..
  }

  string toString() const override
  {
    return "DNSSEC";
  }
};

class AndRule : public DNSRule
{
public:
  AndRule(const std::vector<std::shared_ptr<DNSRule>>& rules) :
    d_rules(rules)
  {
  }

  bool matches(const DNSQuestion* dq) const override
  {
    for (const auto& rule : d_rules) {
      if (!rule->matches(dq)) {
        return false;
      }
    }
    return true;
  }

  string toString() const override
  {
    string ret;
    for (const auto& rule : d_rules) {
      if (!ret.empty()) {
        ret += " && ";
      }
      ret += "(" + rule->toString() + ")";
    }
    return ret;
  }

private:
  std::vector<std::shared_ptr<DNSRule>> d_rules;
};

class OrRule : public DNSRule
{
public:
  OrRule(const std::vector<std::shared_ptr<DNSRule>>& rules) :
    d_rules(rules)
  {
  }

  bool matches(const DNSQuestion* dq) const override
  {
    for (const auto& rule : d_rules) {
      if (rule->matches(dq)) {
        return true;
      }
    }
    return false;
  }

  string toString() const override
  {
    string ret;
    for (const auto& rule : d_rules) {
      if (!ret.empty()) {
        ret += " || ";
      }
      ret += "(" + rule->toString() + ")";
    }
    return ret;
  }

private:
  std::vector<std::shared_ptr<DNSRule>> d_rules;
};

class RegexRule : public DNSRule
{
public:
  RegexRule(const std::string& regex) :
    d_regex(regex), d_visual(regex)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_regex.match(dq->ids.qname.toStringNoDot());
  }

  string toString() const override
  {
    return "Regex: " + d_visual;
  }

private:
  Regex d_regex;
  string d_visual;
};

#if defined(HAVE_RE2)
#include <re2/re2.h>
class RE2Rule : public DNSRule
{
public:
  RE2Rule(const std::string& re2) :
    d_re2(re2, RE2::Latin1), d_visual(re2)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return RE2::FullMatch(dq->ids.qname.toStringNoDot(), d_re2);
  }

  string toString() const override
  {
    return "RE2 match: " + d_visual;
  }

private:
  RE2 d_re2;
  string d_visual;
};
#else /* HAVE_RE2 */
class RE2Rule : public DNSRule
{
public:
  RE2Rule(const std::string& re2)
  {
    throw std::runtime_error("RE2 support is disabled");
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return false;
  }

  string toString() const override
  {
    return "Unsupported RE2";
  }
};
#endif /* HAVE_RE2 */

class HTTPHeaderRule : public DNSRule
{
public:
  HTTPHeaderRule(const std::string& header, const std::string& regex);
  bool matches(const DNSQuestion* dnsQuestion) const override;
  string toString() const override;

private:
  string d_header;
  Regex d_regex;
  string d_visual;
};

class HTTPPathRule : public DNSRule
{
public:
  HTTPPathRule(std::string path);
  bool matches(const DNSQuestion* dnsQuestion) const override;
  string toString() const override;

private:
  string d_path;
};

class HTTPPathRegexRule : public DNSRule
{
public:
  HTTPPathRegexRule(const std::string& regex);
  bool matches(const DNSQuestion* dnsQuestion) const override;
  string toString() const override;

private:
  Regex d_regex;
  std::string d_visual;
};

class SNIRule : public DNSRule
{
public:
  SNIRule(const std::string& name) :
    d_sni(name)
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
  SuffixMatchNodeRule(const SuffixMatchNode& smn, bool quiet = false) :
    d_smn(smn), d_quiet(quiet)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_smn.check(dq->ids.qname);
  }
  string toString() const override
  {
    if (d_quiet)
      return "qname==in-set";
    else
      return "qname in " + d_smn.toString();
  }

private:
  SuffixMatchNode d_smn;
  bool d_quiet;
};

class QNameRule : public DNSRule
{
public:
  QNameRule(const DNSName& qname) :
    d_qname(qname)
  {
  }

  bool matches(const DNSQuestion* dq) const override
  {
    return d_qname == dq->ids.qname;
  }
  string toString() const override
  {
    return "qname==" + d_qname.toString();
  }

private:
  DNSName d_qname;
};

class QNameSetRule : public DNSRule
{
public:
  QNameSetRule(const DNSNameSet& names) :
    qname_idx(names) {}

  bool matches(const DNSQuestion* dq) const override
  {
    return qname_idx.find(dq->ids.qname) != qname_idx.end();
  }

  string toString() const override
  {
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
  QTypeRule(uint16_t qtype) :
    d_qtype(qtype)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_qtype == dq->ids.qtype;
  }
  string toString() const override
  {
    QType qt(d_qtype);
    return "qtype==" + qt.toString();
  }

private:
  uint16_t d_qtype;
};

class QClassRule : public DNSRule
{
public:
  QClassRule(uint16_t qclass) :
    d_qclass(qclass)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_qclass == dq->ids.qclass;
  }
  string toString() const override
  {
    return "qclass==" + std::to_string(d_qclass);
  }

private:
  uint16_t d_qclass;
};

class OpcodeRule : public DNSRule
{
public:
  OpcodeRule(uint8_t opcode) :
    d_opcode(opcode)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_opcode == dq->getHeader()->opcode;
  }
  string toString() const override
  {
    return "opcode==" + std::to_string(d_opcode);
  }

private:
  uint8_t d_opcode;
};

class DSTPortRule : public DNSRule
{
public:
  DSTPortRule(uint16_t port) :
    d_port(port)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return htons(d_port) == dq->ids.origDest.sin4.sin_port;
  }
  string toString() const override
  {
    return "dst port==" + std::to_string(d_port);
  }

private:
  uint16_t d_port;
};

class TCPRule : public DNSRule
{
public:
  TCPRule(bool tcp) :
    d_tcp(tcp)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return dq->overTCP() == d_tcp;
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
  NotRule(const std::shared_ptr<DNSRule>& rule) :
    d_rule(rule)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return !d_rule->matches(dq);
  }
  string toString() const override
  {
    return "!(" + d_rule->toString() + ")";
  }

private:
  std::shared_ptr<DNSRule> d_rule;
};

class RecordsCountRule : public DNSRule
{
public:
  RecordsCountRule(uint8_t section, uint16_t minCount, uint16_t maxCount) :
    d_minCount(minCount), d_maxCount(maxCount), d_section(section)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    uint16_t count = 0;
    switch (d_section) {
    case 0:
      count = ntohs(dq->getHeader()->qdcount);
      break;
    case 1:
      count = ntohs(dq->getHeader()->ancount);
      break;
    case 2:
      count = ntohs(dq->getHeader()->nscount);
      break;
    case 3:
      count = ntohs(dq->getHeader()->arcount);
      break;
    }
    return count >= d_minCount && count <= d_maxCount;
  }
  string toString() const override
  {
    string section;
    switch (d_section) {
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
    return std::to_string(d_minCount) + " <= records in " + section + " <= " + std::to_string(d_maxCount);
  }

private:
  uint16_t d_minCount;
  uint16_t d_maxCount;
  uint8_t d_section;
};

class RecordsTypeCountRule : public DNSRule
{
public:
  RecordsTypeCountRule(uint8_t section, uint16_t type, uint16_t minCount, uint16_t maxCount) :
    d_type(type), d_minCount(minCount), d_maxCount(maxCount), d_section(section)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    uint16_t count = 0;
    switch (d_section) {
    case 0:
      count = ntohs(dq->getHeader()->qdcount);
      break;
    case 1:
      count = ntohs(dq->getHeader()->ancount);
      break;
    case 2:
      count = ntohs(dq->getHeader()->nscount);
      break;
    case 3:
      count = ntohs(dq->getHeader()->arcount);
      break;
    }
    if (count < d_minCount) {
      return false;
    }
    count = getRecordsOfTypeCount(reinterpret_cast<const char*>(dq->getData().data()), dq->getData().size(), d_section, d_type);
    return count >= d_minCount && count <= d_maxCount;
  }
  string toString() const override
  {
    string section;
    switch (d_section) {
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
    return std::to_string(d_minCount) + " <= " + QType(d_type).toString() + " records in " + section + " <= " + std::to_string(d_maxCount);
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
    uint16_t length = getDNSPacketLength(reinterpret_cast<const char*>(dq->getData().data()), dq->getData().size());
    return length < dq->getData().size();
  }
  string toString() const override
  {
    return "trailing data";
  }
};

class QNameLabelsCountRule : public DNSRule
{
public:
  QNameLabelsCountRule(unsigned int minLabelsCount, unsigned int maxLabelsCount) :
    d_min(minLabelsCount), d_max(maxLabelsCount)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    unsigned int count = dq->ids.qname.countLabels();
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
  QNameWireLengthRule(size_t min, size_t max) :
    d_min(min), d_max(max)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    size_t const wirelength = dq->ids.qname.wirelength();
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
  RCodeRule(uint8_t rcode) :
    d_rcode(rcode)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_rcode == dq->getHeader()->rcode;
  }
  string toString() const override
  {
    return "rcode==" + RCode::to_s(d_rcode);
  }

private:
  uint8_t d_rcode;
};

class ERCodeRule : public DNSRule
{
public:
  ERCodeRule(uint8_t rcode) :
    d_rcode(rcode & 0xF), d_extrcode(rcode >> 4)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    // avoid parsing EDNS OPT RR when not needed.
    if (d_rcode != dq->getHeader()->rcode) {
      return false;
    }

    EDNS0Record edns0;
    if (!getEDNS0Record(dq->getData(), edns0)) {
      return false;
    }

    return d_extrcode == edns0.extRCode;
  }
  string toString() const override
  {
    return "ercode==" + ERCode::to_s(d_rcode | (d_extrcode << 4));
  }

private:
  uint8_t d_rcode; // plain DNS Rcode
  uint8_t d_extrcode; // upper bits in EDNS0 record
};

class EDNSVersionRule : public DNSRule
{
public:
  EDNSVersionRule(uint8_t version) :
    d_version(version)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    EDNS0Record edns0;
    if (!getEDNS0Record(dq->getData(), edns0)) {
      return false;
    }

    return d_version < edns0.version;
  }
  string toString() const override
  {
    return "ednsversion>" + std::to_string(d_version);
  }

private:
  uint8_t d_version;
};

class EDNSOptionRule : public DNSRule
{
public:
  EDNSOptionRule(uint16_t optcode) :
    d_optcode(optcode)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    uint16_t optStart;
    size_t optLen = 0;
    bool last = false;
    int res = locateEDNSOptRR(dq->getData(), &optStart, &optLen, &last);
    if (res != 0) {
      // no EDNS OPT RR
      return false;
    }

    if (optLen < optRecordMinimumSize) {
      return false;
    }

    if (optStart < dq->getData().size() && dq->getData().at(optStart) != 0) {
      // OPT RR Name != '.'
      return false;
    }

    return isEDNSOptionInOpt(dq->getData(), optStart, optLen, d_optcode);
  }
  string toString() const override
  {
    return "ednsoptcode==" + std::to_string(d_optcode);
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
    return dq->getHeader()->rd == 1;
  }
  string toString() const override
  {
    return "rd==1";
  }
};

class ProbaRule : public DNSRule
{
public:
  ProbaRule(double proba) :
    d_proba(proba)
  {
  }
  bool matches(const DNSQuestion* dnsQuestion) const override
  {
    (void)dnsQuestion;
    if (d_proba == 1.0) {
      return true;
    }
    double rnd = 1.0 * dns_random_uint32() / UINT32_MAX;
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
  TagRule(const std::string& tag, boost::optional<std::string> value) :
    d_value(std::move(value)), d_tag(tag)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    if (!dq->ids.qTag) {
      return false;
    }

    const auto it = dq->ids.qTag->find(d_tag);
    if (it == dq->ids.qTag->cend()) {
      return false;
    }

    if (!d_value || d_value->empty()) {
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
  PoolAvailableRule(const std::string& poolname) :
    d_poolname(poolname)
  {
  }

  bool matches(const DNSQuestion* dnsQuestion) const override
  {
    (void)dnsQuestion;
    return (getPool(d_poolname)->countServers(true) > 0);
  }

  string toString() const override
  {
    return "pool '" + d_poolname + "' is available";
  }

private:
  std::string d_poolname;
};

class PoolOutstandingRule : public DNSRule
{
public:
  PoolOutstandingRule(const std::string& poolname, const size_t limit) :
    d_poolname(poolname), d_limit(limit)
  {
  }

  bool matches(const DNSQuestion* dnsQuestion) const override
  {
    (void)dnsQuestion;
    return (getPool(d_poolname)->poolLoad()) > d_limit;
  }

  string toString() const override
  {
    return "pool '" + d_poolname + "' outstanding > " + std::to_string(d_limit);
  }

private:
  std::string d_poolname;
  size_t d_limit;
};

class KeyValueStoreLookupRule : public DNSRule
{
public:
  KeyValueStoreLookupRule(const std::shared_ptr<KeyValueStore>& kvs, const std::shared_ptr<KeyValueLookupKey>& lookupKey) :
    d_kvs(kvs), d_key(lookupKey)
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

class KeyValueStoreRangeLookupRule : public DNSRule
{
public:
  KeyValueStoreRangeLookupRule(const std::shared_ptr<KeyValueStore>& kvs, const std::shared_ptr<KeyValueLookupKey>& lookupKey) :
    d_kvs(kvs), d_key(lookupKey)
  {
  }

  bool matches(const DNSQuestion* dq) const override
  {
    std::vector<std::string> keys = d_key->getKeys(*dq);
    for (const auto& key : keys) {
      std::string value;
      if (d_kvs->getRangeValue(key, value) == true) {
        return true;
      }
    }

    return false;
  }

  string toString() const override
  {
    return "range-based lookup key-value store based on '" + d_key->toString() + "'";
  }

private:
  std::shared_ptr<KeyValueStore> d_kvs;
  std::shared_ptr<KeyValueLookupKey> d_key;
};

class LuaRule : public DNSRule
{
public:
  LuaRule(const dnsdist::selectors::LuaSelectorFunction& func) :
    d_func(func)
  {}

  bool matches(const DNSQuestion* dq) const override
  {
    try {
      auto lock = g_lua.lock();
      return d_func(dq);
    }
    catch (const std::exception& e) {
      warnlog("LuaRule failed inside Lua: %s", e.what());
    }
    catch (...) {
      warnlog("LuaRule failed inside Lua: [unknown exception]");
    }
    return false;
  }

  string toString() const override
  {
    return "Lua script";
  }

private:
  dnsdist::selectors::LuaSelectorFunction d_func;
};

class LuaFFIRule : public DNSRule
{
public:
  LuaFFIRule(const dnsdist::selectors::LuaSelectorFFIFunction& func) :
    d_func(func)
  {}

  bool matches(const DNSQuestion* dq) const override
  {
    dnsdist_ffi_dnsquestion_t dqffi(const_cast<DNSQuestion*>(dq));
    try {
      auto lock = g_lua.lock();
      return d_func(&dqffi);
    }
    catch (const std::exception& e) {
      warnlog("LuaFFIRule failed inside Lua: %s", e.what());
    }
    catch (...) {
      warnlog("LuaFFIRule failed inside Lua: [unknown exception]");
    }
    return false;
  }

  string toString() const override
  {
    return "Lua FFI script";
  }

private:
  dnsdist::selectors::LuaSelectorFFIFunction d_func;
};

class LuaFFIPerThreadRule : public DNSRule
{
public:
  LuaFFIPerThreadRule(const std::string& code) :
    d_functionCode(code), d_functionID(s_functionsCounter++)
  {
  }

  bool matches(const DNSQuestion* dq) const override
  {
    try {
      auto& state = t_perThreadStates[d_functionID];
      if (!state.d_initialized) {
        setupLuaFFIPerThreadContext(state.d_luaContext);
        /* mark the state as initialized first so if there is a syntax error
           we only try to execute the code once */
        state.d_initialized = true;
        state.d_func = state.d_luaContext.executeCode<dnsdist::selectors::LuaSelectorFFIFunction>(d_functionCode);
      }

      if (!state.d_func) {
        /* the function was not properly initialized */
        return false;
      }

      dnsdist_ffi_dnsquestion_t dqffi(const_cast<DNSQuestion*>(dq));
      return state.d_func(&dqffi);
    }
    catch (const std::exception& e) {
      warnlog("LuaFFIPerthreadRule failed inside Lua: %s", e.what());
    }
    catch (...) {
      warnlog("LuaFFIPerThreadRule failed inside Lua: [unknown exception]");
    }
    return false;
  }

  string toString() const override
  {
    return "Lua FFI per-thread script";
  }

private:
  struct PerThreadState
  {
    LuaContext d_luaContext;
    dnsdist::selectors::LuaSelectorFFIFunction d_func;
    bool d_initialized{false};
  };

  static std::atomic<uint64_t> s_functionsCounter;
  static thread_local std::map<uint64_t, PerThreadState> t_perThreadStates;
  const std::string d_functionCode;
  const uint64_t d_functionID;
};

class ProxyProtocolValueRule : public DNSRule
{
public:
  ProxyProtocolValueRule(uint8_t type, boost::optional<std::string> value) :
    d_value(std::move(value)), d_type(type)
  {
  }

  bool matches(const DNSQuestion* dq) const override
  {
    if (!dq->proxyProtocolValues) {
      return false;
    }

    for (const auto& entry : *dq->proxyProtocolValues) {
      if (entry.type == d_type && (!d_value || d_value->empty() || entry.content == *d_value)) {
        return true;
      }
    }

    return false;
  }

  string toString() const override
  {
    if (d_value) {
      return "proxy protocol value of type " + std::to_string(d_type) + " matches";
    }
    return "proxy protocol value of type " + std::to_string(d_type) + " is present";
  }

private:
  boost::optional<std::string> d_value;
  uint8_t d_type;
};

class PayloadSizeRule : public DNSRule
{
  enum class Comparisons : uint8_t
  {
    equal,
    greater,
    greaterOrEqual,
    smaller,
    smallerOrEqual
  };

public:
  PayloadSizeRule(const std::string& comparison, uint16_t size) :
    d_size(size)
  {
    if (comparison == "equal") {
      d_comparison = Comparisons::equal;
    }
    else if (comparison == "greater") {
      d_comparison = Comparisons::greater;
    }
    else if (comparison == "greaterOrEqual") {
      d_comparison = Comparisons::greaterOrEqual;
    }
    else if (comparison == "smaller") {
      d_comparison = Comparisons::smaller;
    }
    else if (comparison == "smallerOrEqual") {
      d_comparison = Comparisons::smallerOrEqual;
    }
    else {
      throw std::runtime_error("Unsupported comparison '" + comparison + "'");
    }
  }

  bool matches(const DNSQuestion* dq) const override
  {
    const auto size = dq->getData().size();

    switch (d_comparison) {
    case Comparisons::equal:
      return size == d_size;
    case Comparisons::greater:
      return size > d_size;
    case Comparisons::greaterOrEqual:
      return size >= d_size;
    case Comparisons::smaller:
      return size < d_size;
    case Comparisons::smallerOrEqual:
      return size <= d_size;
    default:
      return false;
    }
  }

  string toString() const override
  {
    static const std::array<const std::string, 5> comparisonStr{
      "equal to",
      "greater than",
      "equal to or greater than",
      "smaller than",
      "equal to or smaller than"};
    return "payload size is " + comparisonStr.at(static_cast<size_t>(d_comparison)) + " " + std::to_string(d_size);
  }

private:
  uint16_t d_size;
  Comparisons d_comparison;
};

namespace dnsdist::selectors
{
std::shared_ptr<AndRule> getAndSelector(const std::vector<std::shared_ptr<DNSRule>>& rules);
std::shared_ptr<OrRule> getOrSelector(const std::vector<std::shared_ptr<DNSRule>>& rules);
std::shared_ptr<NotRule> getNotSelector(const std::shared_ptr<DNSRule>& rule);
std::shared_ptr<LuaRule> getLuaSelector(const dnsdist::selectors::LuaSelectorFunction& func);
std::shared_ptr<LuaFFIRule> getLuaFFISelector(const dnsdist::selectors::LuaSelectorFFIFunction& func);
std::shared_ptr<QNameRule> getQNameSelector(const DNSName& qname);
std::shared_ptr<QNameSetRule> getQNameSetSelector(const DNSNameSet& qnames);
std::shared_ptr<SuffixMatchNodeRule> getQNameSuffixSelector(const SuffixMatchNode& suffixes, bool quiet);
std::shared_ptr<QTypeRule> getQTypeSelector(const std::string& qtypeStr, uint16_t qtypeCode);
std::shared_ptr<QClassRule> getQClassSelector(const std::string& qclassStr, uint16_t qclassCode);
std::shared_ptr<NetmaskGroupRule> getNetmaskGroupSelector(const NetmaskGroup& nmg, bool source, bool quiet);
std::shared_ptr<KeyValueStoreLookupRule> getKeyValueStoreLookupSelector(const std::shared_ptr<KeyValueStore>& kvs, const std::shared_ptr<KeyValueLookupKey>& lookupKey);
std::shared_ptr<KeyValueStoreRangeLookupRule> getKeyValueStoreRangeLookupSelector(const std::shared_ptr<KeyValueStore>& kvs, const std::shared_ptr<KeyValueLookupKey>& lookupKey);

#include "dnsdist-selectors-factory-generated.hh"
}
