#include "dnsdist.hh"
#include "dnsname.hh"
#include "dolog.hh"

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

class MaxQPSRule : public DNSRule
{
public:
  MaxQPSRule(unsigned int qps)
   : d_qps(qps, qps)
  {}

  MaxQPSRule(unsigned int qps, unsigned int burst)
   : d_qps(qps, burst)
  {}


  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
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
  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    return d_nmg.match(remote);
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
  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
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
  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    return dh->cd || (getEDNSZ((const char*)dh, len) & EDNS_HEADER_FLAG_DO);    // turns out dig sets ad by default..
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

  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    auto iter = d_rules.begin();
    for(; iter != d_rules.end(); ++iter)
      if(!(*iter)->matches(remote, qname, qtype, dh, len))
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


class RegexRule : public DNSRule
{
public:
  RegexRule(const std::string& regex) : d_regex(regex), d_visual(regex)
  {
    
  }
  bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const override
  {
    return d_regex.match(qname.toStringNoDot());
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
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

class SpoofAction : public DNSAction
{
public:
  SpoofAction(const ComboAddress& a) : d_a(a) { d_aaaa.sin4.sin_family = 0;}
  SpoofAction(const ComboAddress& a, const ComboAddress& aaaa) : d_a(a), d_aaaa(aaaa) {}
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
  {
    if((qtype == QType::A && d_a.sin4.sin_family == 0) ||
       (qtype == QType::AAAA && d_aaaa.sin4.sin_family == 0) || (qtype != QType::A && qtype != QType::AAAA))
      return Action::None;

    dh->qr = true; // for good measure
    dh->ra = dh->rd; // for good measure
    dh->ad = false;
    dh->ancount = htons(1);
    dh->arcount = 0; // for now, forget about your EDNS, we're marching over it 
    unsigned int consumed=0;

    DNSName ignore((char*)dh, len, sizeof(dnsheader), false, 0, 0, &consumed);

    char* dest = ((char*)dh) +sizeof(dnsheader) + consumed + 4;
    uint8_t addrlen = qtype == QType::A ? 4 : 16;

    const unsigned char recordstart[]={0xc0, 0x0c,  // compressed name
				       0, (unsigned char) qtype,       
				       0, 1,        // IN
				       0, 0, 0, 60, // TTL
				       0, addrlen};       
    memcpy(dest, recordstart, sizeof(recordstart));
    if(qtype==QType::A) 
      memcpy(dest+sizeof(recordstart), &d_a.sin4.sin_addr.s_addr, 4);
    else
      memcpy(dest+sizeof(recordstart), &d_aaaa.sin6.sin6_addr.s6_addr, 16);
    len = (dest + sizeof(recordstart) + addrlen) - (char*)dh;
    return Action::HeaderModify;
  }
  string toString() const override
  {
    string ret;
    if(d_a.sin4.sin_family)
      ret="spoof in "+d_a.toString();
    if(d_aaaa.sin6.sin6_family) {
      if(!ret.empty()) ret += ", ";
      ret+="spoof in "+d_aaaa.toString();
    }
    return ret;
  }
private:
  ComboAddress d_a;
  ComboAddress d_aaaa;
};


class NoRecurseAction : public DNSAction
{
public:
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
  {
    dh->rd = false;
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
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
  {
    if(!d_fp) 
      infolog("Packet from %s for %s %s with id %d", remote.toStringWithPort(), qname.toString(), QType(qtype).getName(), dh->id);
    else {
      string out = qname.toDNSString();
      fwrite(out.c_str(), 1, out.size(), d_fp);
      fwrite((void*)&qtype, 1, 2, d_fp);
    }
    return Action::None;
  }
  string toString() const override
  {
    return "log";
  }
private:
  string d_fname;
  FILE* d_fp;
};


class DisableValidationAction : public DNSAction
{
public:
  DNSAction::Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, uint16_t& len, string* ruleresult) const override
  {
    dh->cd = true;
    return Action::HeaderModify;
  }
  string toString() const override
  {
    return "set cd=1";
  }
};
