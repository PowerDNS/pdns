#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsname.hh"
#include "dolog.hh"

class MaxQPSIPRule : public DNSRule
{
public:
  MaxQPSIPRule(unsigned int qps, unsigned int ipv4trunc=32, unsigned int ipv6trunc=64) : 
    d_qps(qps), d_ipv4trunc(ipv4trunc), d_ipv6trunc(ipv6trunc)
  {}

  bool matches(const DNSQuestion* dq) const override
  {
    ComboAddress zeroport(*dq->remote);
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



class NetmaskGroupRule : public DNSRule
{
public:
  NetmaskGroupRule(const NetmaskGroup& nmg) : d_nmg(nmg)
  {

  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_nmg.match(*dq->remote);
  }

  string toString() const override
  {
    return "Src: "+d_nmg.toString();
  }
private:
  NetmaskGroup d_nmg;
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
    return "Regex qname: "+d_visual;
  }
private:
  Regex d_regex;
  string d_visual;
};


class SuffixMatchNodeRule : public DNSRule
{
public:
  SuffixMatchNodeRule(const SuffixMatchNode& smn) : d_smn(smn)
  {
  }
  bool matches(const DNSQuestion* dq) const override
  {
    return d_smn.check(*dq->qname);
  }
  string toString() const override
  {
    return "qname=="+d_smn.toString();
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
    return "!"+ d_rule->toString();
  }
private:
  shared_ptr<DNSRule> d_rule;
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
    dq->dh->tc = true;
    dq->dh->qr = true; // for good measure
    return Action::HeaderModify;
  }
  string toString() const override
  {
    return "tc=1 answer";
  }
};

class SpoofAction : public DNSAction
{
public:
  SpoofAction(const ComboAddress& a)
  {
    if (a.sin4.sin_family == AF_INET) {
      d_a = a;
      d_aaaa.sin4.sin_family = 0;
    } else {
      d_a.sin4.sin_family = 0;
      d_aaaa = a;
    }
  }
  SpoofAction(const ComboAddress& a, const ComboAddress& aaaa) : d_a(a), d_aaaa(aaaa) {}
  SpoofAction(const string& cname): d_cname(cname) { d_a.sin4.sin_family = 0; d_aaaa.sin4.sin_family = 0; }
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    uint16_t qtype = dq->qtype;
    if(d_cname.empty() &&
       ((qtype == QType::A && d_a.sin4.sin_family == 0) ||
        (qtype == QType::AAAA && d_aaaa.sin4.sin_family == 0) || (qtype != QType::A && qtype != QType::AAAA)))
      return Action::None;

    unsigned int consumed=0;
    uint8_t rdatalen = 0;
    if (!d_cname.empty()) {
      qtype = QType::CNAME;
      rdatalen = d_cname.wirelength();
    } else {
      rdatalen = qtype == QType::A ? 4 : 16;
    }

    const unsigned char recordstart[]={0xc0, 0x0c,    // compressed name
				       0, (unsigned char) qtype,
				       0, QClass::IN, // IN
				       0, 0, 0, 60,   // TTL
				       0, rdatalen};

    DNSName ignore((char*)dq->dh, dq->len, sizeof(dnsheader), false, 0, 0, &consumed);

    if (dq->size < (sizeof(dnsheader) + consumed + 4 + sizeof(recordstart) + rdatalen)) {
      return Action::None;
    }

    dq->dh->qr = true; // for good measure
    dq->dh->ra = dq->dh->rd; // for good measure
    dq->dh->ad = false;
    dq->dh->ancount = htons(1);
    dq->dh->arcount = 0; // for now, forget about your EDNS, we're marching over it

    char* dest = ((char*)dq->dh) +sizeof(dnsheader) + consumed + 4;
    memcpy(dest, recordstart, sizeof(recordstart));
    if(qtype==QType::A) 
      memcpy(dest+sizeof(recordstart), &d_a.sin4.sin_addr.s_addr, 4);
    else if (qtype==QType::AAAA)
      memcpy(dest+sizeof(recordstart), &d_aaaa.sin6.sin6_addr.s6_addr, 16);
    else if (qtype==QType::CNAME) {
      string wireData = d_cname.toDNSString();
      memcpy(dest+sizeof(recordstart), wireData.c_str(), wireData.length());
    }
    dq->len = (dest + sizeof(recordstart) + rdatalen) - (char*)dq->dh;
    return Action::HeaderModify;
  }
  string toString() const override
  {
    string ret;
    if(!d_cname.empty()) {
      if(!ret.empty()) ret += ", ";
      ret+="spoof in "+d_cname.toString();
    } else {
      if(d_a.sin4.sin_family)
        ret="spoof in "+d_a.toString();
      if(d_aaaa.sin6.sin6_family) {
        if(!ret.empty()) ret += ", ";
        ret+="spoof in "+d_aaaa.toString();
      }
    }
    return ret;
  }
private:
  ComboAddress d_a;
  ComboAddress d_aaaa;
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
    return Action::HeaderModify;
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
  LogAction(const std::string& str) : d_fname(str)
  {
    if(str.empty())
      return;
    d_fp = fopen(str.c_str(), "w");
    if(!d_fp)
      throw std::runtime_error("Unable to open file '"+str+"' for logging: "+string(strerror(errno)));
  }
  ~LogAction()
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
      string out = dq->qname->toDNSString();
      fwrite(out.c_str(), 1, out.size(), d_fp);
      fwrite((void*)&dq->qtype, 1, 2, d_fp);
    }
    return Action::None;
  }
  string toString() const override
  {
    return "log";
  }
private:
  string d_fname;
  FILE* d_fp{0};
};


class DisableValidationAction : public DNSAction
{
public:
  DNSAction::Action operator()(DNSQuestion* dq, string* ruleresult) const override
  {
    dq->dh->cd = true;
    return Action::HeaderModify;
  }
  string toString() const override
  {
    return "set cd=1";
  }
};
