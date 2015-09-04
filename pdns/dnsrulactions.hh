#include "dnsdist.hh"
#include "dnsname.hh"

class MaxQPSIPRule : public DNSRule
{
public:
  MaxQPSIPRule(unsigned int qps, unsigned int ipv4trunc=32, unsigned int ipv6trunc=64) : 
    d_qps(qps), d_ipv4trunc(ipv4trunc), d_ipv6trunc(ipv6trunc)
  {}

  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    ComboAddress zeroport(remote);
    zeroport.sin4.sin_port=0;
    zeroport.truncate(zeroport.sin4.sin_family == AF_INET ? d_ipv4trunc : d_ipv6trunc);
    auto iter = d_limits.find(zeroport);
    if(iter == d_limits.end()) {
      iter=d_limits.insert({zeroport,QPSLimiter(d_qps, d_qps)}).first;
    }
    return !iter->second.check();
  }

  string toString() const override
  {
    return "IP (/"+std::to_string(d_ipv4trunc)+", /"+std::to_string(d_ipv6trunc)+") match for QPS over " + std::to_string(d_qps);
  }


private:
  mutable std::map<ComboAddress, QPSLimiter> d_limits;
  unsigned int d_qps, d_ipv4trunc, d_ipv6trunc;

};


class NetmaskGroupRule : public DNSRule
{
public:
  NetmaskGroupRule(const NetmaskGroup& nmg) : d_nmg(nmg)
  {

  }
  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    return d_nmg.match(remote);
  }

  string toString() const override
  {
    return d_nmg.toString();
  }
private:
  NetmaskGroup d_nmg;
};

class DNSSECRule : public DNSRule
{
public:
  DNSSECRule()
  {

  }
  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    return dh->cd || (getEDNSZ((const char*)dh, len) & 32768);    // turns out dig sets ad by default..
  }

  string toString() const override
  {
    return "DNSSEC";
  }
};


class SuffixMatchNodeRule : public DNSRule
{
public:
  SuffixMatchNodeRule(const SuffixMatchNode& smn) : d_smn(smn)
  {
  }
  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    return d_smn.check(qname);
  }
  string toString() const override
  {
    return d_smn.toString();
  }
private:
  SuffixMatchNode d_smn;
};

class QTypeRule : public DNSRule
{
public:
  QTypeRule(uint16_t qtype) : d_qtype(qtype)
  {
  }
  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    return d_qtype == qtype;
  }
  string toString() const override
  {
    QType qt(d_qtype);
    return "qtype=="+qt.getName();
  }
private:
  uint16_t d_qtype;
};

class DropAction : public DNSAction
{
public:
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const override
  {
    return Action::Drop;
  }
  string toString() const override
  {
    return "drop";
  }
};


class QPSAction : public DNSAction
{
public:
  QPSAction(int limit) : d_qps(limit, limit) 
  {}
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const override
  {
    if(d_qps.check())
      return Action::Allow;
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const override
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


class PoolAction : public DNSAction
{
public:
  PoolAction(const std::string& pool) : d_pool(pool) {}
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const override
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const override
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const override
  {
    dh->rcode = d_rcode;
    dh->qr = true; // for good measure
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const override
  {
    dh->tc = true;
    dh->qr = true; // for good measure
    return Action::HeaderModify;
  }
  string toString() const override
  {
    return "tc=1 answer";
  }
};

class NoRecurseAction : public DNSAction
{
public:
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const override
  {
    dh->rd = false;
    return Action::HeaderModify;
  }
  string toString() const override
  {
    return "set rd=0";
  }
};
