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
#include <fstream>
#include "syncres.hh"
#include "logger.hh"
#include "namespaces.hh"
#include "rec_channel.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "filterpo.hh"
#include "rec-snmp.hh"
#include <unordered_set>
#include "lua-recursor4.hh"

static int followCNAMERecords(vector<DNSRecord>& ret, const QType& qtype)
{
  vector<DNSRecord> resolved;
  DNSName target;
  for(const DNSRecord& rr :  ret) {
    if(rr.d_type == QType::CNAME) {
      auto rec = getRR<CNAMERecordContent>(rr);
      if(rec) {
        target=rec->getTarget();
        break;
      }
    }
  }
  if(target.empty())
    return 0;
  
  int rcode=directResolve(target, qtype, 1, resolved); // 1 == class
  
  for(const DNSRecord& rr :  resolved) {
    ret.push_back(rr);
  }
  return rcode;
 
}

static int getFakeAAAARecords(const DNSName& qname, const std::string& prefix, vector<DNSRecord>& ret)
{
  int rcode=directResolve(qname, QType(QType::A), 1, ret);

  ComboAddress prefixAddress(prefix);

  for(DNSRecord& rr :  ret)
  {
    if(rr.d_type == QType::A && rr.d_place==DNSResourceRecord::ANSWER) {
      if(auto rec = getRR<ARecordContent>(rr)) {
        ComboAddress ipv4(rec->getCA());
        uint32_t tmp;
        memcpy((void*)&tmp, &ipv4.sin4.sin_addr.s_addr, 4);
        // tmp=htonl(tmp);
        memcpy(((char*)&prefixAddress.sin6.sin6_addr.s6_addr)+12, &tmp, 4);
        rr.d_content = std::make_shared<AAAARecordContent>(prefixAddress);
        rr.d_type = QType::AAAA;
      }
    }
  }
  return rcode;
}

static int getFakePTRRecords(const DNSName& qname, const std::string& prefix, vector<DNSRecord>& ret)
{
  /* qname has a reverse ordered IPv6 address, need to extract the underlying IPv4 address from it
     and turn it into an IPv4 in-addr.arpa query */
  ret.clear();
  vector<string> parts = qname.getRawLabels();

  if(parts.size() < 8)
    return -1;

  string newquery;
  for(int n = 0; n < 4; ++n) {
    newquery +=
      std::to_string(stoll(parts[n*2], 0, 16) + 16*stoll(parts[n*2+1], 0, 16));
    newquery.append(1,'.');
  }
  newquery += "in-addr.arpa.";


  int rcode = directResolve(DNSName(newquery), QType(QType::PTR), 1, ret);
  for(DNSRecord& rr :  ret)
  {
    if(rr.d_type == QType::PTR && rr.d_place==DNSResourceRecord::ANSWER) {
      rr.d_name = qname;
    }
  }
  return rcode;

}

boost::optional<dnsheader> RecursorLua4::DNSQuestion::getDH() const
{
  if (dh)
    return *dh;
  return boost::optional<dnsheader>();
}

vector<string> RecursorLua4::DNSQuestion::getEDNSFlags() const
{
  vector<string> ret;
  if (ednsFlags) {
    if (*ednsFlags & EDNSOpts::DNSSECOK)
      ret.push_back("DO");
  }
  return ret;
}

bool RecursorLua4::DNSQuestion::getEDNSFlag(string flag) const
{
  if (ednsFlags) {
    if (flag == "DO" && (*ednsFlags & EDNSOpts::DNSSECOK))
      return true;
  }
  return false;
}

vector<pair<uint16_t, string> > RecursorLua4::DNSQuestion::getEDNSOptions() const
{
  if(ednsOptions)
    return *ednsOptions;
  else
    return vector<pair<uint16_t,string>>();
}

boost::optional<string>  RecursorLua4::DNSQuestion::getEDNSOption(uint16_t code) const
{
  if(ednsOptions)
    for(const auto& o : *ednsOptions)
      if(o.first==code)
        return o.second;
        
  return boost::optional<string>();
}

boost::optional<Netmask>  RecursorLua4::DNSQuestion::getEDNSSubnet() const
{

  if(ednsOptions) {
    for(const auto& o : *ednsOptions) {
      if(o.first==EDNSOptionCode::ECS) {
        EDNSSubnetOpts eso;
        if(getEDNSSubnetOptsFromString(o.second, &eso))
          return eso.source;
        else 
          break;
      }
    }
  }
  return boost::optional<Netmask>();
}


vector<pair<int, DNSRecord> > RecursorLua4::DNSQuestion::getRecords() const
{
  vector<pair<int, DNSRecord> > ret;
  int num=1;
  for(const auto& r : records) {
    ret.push_back({num++, r});
  }
  return ret;
}
void RecursorLua4::DNSQuestion::setRecords(const vector<pair<int, DNSRecord> >& recs)
{
  records.clear();
  for(const auto& p : recs) {
    records.push_back(p.second);
  }
}

void RecursorLua4::DNSQuestion::addRecord(uint16_t type, const std::string& content, DNSResourceRecord::Place place, boost::optional<int> ttl, boost::optional<string> name)
{
  DNSRecord dr;
  dr.d_name=name ? DNSName(*name) : qname;
  dr.d_ttl=ttl.get_value_or(3600);
  dr.d_type = type;
  dr.d_place = place;
  dr.d_content = DNSRecordContent::mastermake(type, 1, content);
  records.push_back(dr);
}

void RecursorLua4::DNSQuestion::addAnswer(uint16_t type, const std::string& content, boost::optional<int> ttl, boost::optional<string> name)
{
  addRecord(type, content, DNSResourceRecord::ANSWER, ttl, name);
}

struct DynMetric
{
  std::atomic<unsigned long>* ptr;
  void inc() { (*ptr)++; }
  void incBy(unsigned int by) { (*ptr)+= by; }
  unsigned long get() { return *ptr; }
  void set(unsigned long val) { *ptr =val; }
};

RecursorLua4::RecursorLua4(const std::string& fname)
{
  d_lw = std::unique_ptr<LuaContext>(new LuaContext);

  d_lw->registerFunction<int(dnsheader::*)()>("getID", [](dnsheader& dh) { return dh.id; });
  d_lw->registerFunction<bool(dnsheader::*)()>("getCD", [](dnsheader& dh) { return dh.cd; });
  d_lw->registerFunction<bool(dnsheader::*)()>("getTC", [](dnsheader& dh) { return dh.tc; });
  d_lw->registerFunction<bool(dnsheader::*)()>("getRA", [](dnsheader& dh) { return dh.ra; });
  d_lw->registerFunction<bool(dnsheader::*)()>("getAD", [](dnsheader& dh) { return dh.ad; });
  d_lw->registerFunction<bool(dnsheader::*)()>("getAA", [](dnsheader& dh) { return dh.aa; });
  d_lw->registerFunction<bool(dnsheader::*)()>("getRD", [](dnsheader& dh) { return dh.rd; });
  d_lw->registerFunction<int(dnsheader::*)()>("getRCODE", [](dnsheader& dh) { return dh.rcode; });
  d_lw->registerFunction<int(dnsheader::*)()>("getOPCODE", [](dnsheader& dh) { return dh.opcode; });
  d_lw->registerFunction<int(dnsheader::*)()>("getQDCOUNT", [](dnsheader& dh) { return ntohs(dh.qdcount); });
  d_lw->registerFunction<int(dnsheader::*)()>("getANCOUNT", [](dnsheader& dh) { return ntohs(dh.ancount); });
  d_lw->registerFunction<int(dnsheader::*)()>("getNSCOUNT", [](dnsheader& dh) { return ntohs(dh.nscount); });
  d_lw->registerFunction<int(dnsheader::*)()>("getARCOUNT", [](dnsheader& dh) { return ntohs(dh.arcount); });

  d_lw->writeFunction("newDN", [](boost::variant<const std::string, const DNSName> dom){
    if(dom.which() == 0)
      return DNSName(boost::get<const std::string>(dom));
    else
      return DNSName(boost::get<const DNSName>(dom));
  });
  d_lw->registerFunction("isPartOf", &DNSName::isPartOf);
  d_lw->registerFunction<unsigned int(DNSName::*)()>("countLabels", [](const DNSName& name) { return name.countLabels(); });
  d_lw->registerFunction<size_t(DNSName::*)()>("wirelength", [](const DNSName& name) { return name.wirelength(); });
  d_lw->registerFunction<bool(DNSName::*)(const std::string&)>(
    "equal",
     [](const DNSName& lhs, const std::string& rhs) {
       return lhs==DNSName(rhs);
    }
  );
  d_lw->registerFunction("__eq", &DNSName::operator==);

  d_lw->registerFunction<string(ComboAddress::*)()>("toString", [](const ComboAddress& ca) { return ca.toString(); });
  d_lw->registerFunction<string(ComboAddress::*)()>("toStringWithPort", [](const ComboAddress& ca) { return ca.toStringWithPort(); });
  d_lw->registerFunction<uint16_t(ComboAddress::*)()>("getPort", [](const ComboAddress& ca) { return ntohs(ca.sin4.sin_port); } );
  d_lw->registerFunction<string(ComboAddress::*)()>("getRaw", [](const ComboAddress& ca) { 
      if(ca.sin4.sin_family == AF_INET) {
        auto t=ca.sin4.sin_addr.s_addr; return string((const char*)&t, 4); 
      }
      else 
        return string((const char*)&ca.sin6.sin6_addr.s6_addr, 16);
    } );
  d_lw->registerFunction<bool(ComboAddress::*)()>("isIPv4", [](const ComboAddress& ca) { return ca.sin4.sin_family == AF_INET; });
  d_lw->registerFunction<bool(ComboAddress::*)()>("isIPv6", [](const ComboAddress& ca) { return ca.sin4.sin_family == AF_INET6; });
  d_lw->registerFunction<bool(ComboAddress::*)()>("isMappedIPv4", [](const ComboAddress& ca) { return ca.isMappedIPv4(); });
  d_lw->registerFunction<ComboAddress(ComboAddress::*)()>("mapToIPv4", [](const ComboAddress& ca) { return ca.mapToIPv4(); });
  d_lw->registerFunction<void(ComboAddress::*)(unsigned int)>("truncate", [](ComboAddress& ca, unsigned int bits) { ca.truncate(bits); });

  d_lw->writeFunction("newCA", [](const std::string& a) { return ComboAddress(a); });
  typedef std::unordered_set<ComboAddress,ComboAddress::addressOnlyHash,ComboAddress::addressOnlyEqual> cas_t;
  d_lw->writeFunction("newCAS", []{ return cas_t(); });


  d_lw->registerFunction<void(cas_t::*)(boost::variant<string,ComboAddress, vector<pair<unsigned int,string> > >)>(
    "add",
    [](cas_t& cas, const boost::variant<string,ComboAddress,vector<pair<unsigned int,string> > >& in)
    {
      try {
        if(auto s = boost::get<string>(&in)) {
          cas.insert(ComboAddress(*s));
        }
        else if(auto v = boost::get<vector<pair<unsigned int, string> > >(&in)) {
          for(const auto&entry : *v)
            cas.insert(ComboAddress(entry.second));
          }
        else {
          cas.insert(boost::get<ComboAddress>(in));
        }
      }
      catch(std::exception& e) { theL() <<Logger::Error<<e.what()<<endl; }
    });

  d_lw->registerFunction<bool(cas_t::*)(const ComboAddress&)>("check",[](const cas_t& cas, const ComboAddress&ca) {
      return (bool)cas.count(ca);
    });

  d_lw->registerFunction<bool(ComboAddress::*)(const ComboAddress&)>(
    "equal",
    [](const ComboAddress& lhs, const ComboAddress& rhs) {
      return ComboAddress::addressOnlyEqual()(lhs, rhs);
    }
  );
  
  d_lw->writeFunction("newNetmask", [](const string& s) { return Netmask(s); });
  d_lw->registerFunction<ComboAddress(Netmask::*)()>("getNetwork", [](const Netmask& nm) { return nm.getNetwork(); } ); // const reference makes this necessary
  d_lw->registerFunction<ComboAddress(Netmask::*)()>("getMaskedNetwork", [](const Netmask& nm) { return nm.getMaskedNetwork(); } );
  d_lw->registerFunction("isIpv4", &Netmask::isIpv4);
  d_lw->registerFunction("isIpv6", &Netmask::isIpv6);
  d_lw->registerFunction("getBits", &Netmask::getBits);
  d_lw->registerFunction("toString", &Netmask::toString);
  d_lw->registerFunction("empty", &Netmask::empty);
  d_lw->registerFunction("match", (bool (Netmask::*)(const string&) const)&Netmask::match);
  d_lw->registerFunction("__eq", &Netmask::operator==);

  d_lw->writeFunction("newNMG", []() { return NetmaskGroup(); });
  d_lw->registerFunction<void(NetmaskGroup::*)(const std::string&mask)>(
    "addMask", [](NetmaskGroup&nmg, const std::string& mask){
      nmg.addMask(mask);
    }
  );

  d_lw->registerFunction<void(NetmaskGroup::*)(const vector<pair<unsigned int, std::string>>&)>(
    "addMasks",
    [](NetmaskGroup&nmg, const vector<pair<unsigned int, std::string>>& masks){
      for(const auto& mask: masks)
        nmg.addMask(mask.second);
    }
  );


  d_lw->registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const)&NetmaskGroup::match);
  d_lw->registerFunction<string(DNSName::*)()>("toString", [](const DNSName&dn ) { return dn.toString(); });
  d_lw->registerFunction<string(DNSName::*)()>("toStringNoDot", [](const DNSName&dn ) { return dn.toStringNoDot(); });
  d_lw->registerFunction<bool(DNSName::*)()>("chopOff", [](DNSName&dn ) { return dn.chopOff(); });

  d_lw->registerMember<const DNSName (DNSQuestion::*)>("qname", [](const DNSQuestion& dq) -> const DNSName& { return dq.qname; }, [](DNSQuestion& dq, const DNSName& newName) { (void) newName; });
  d_lw->registerMember<uint16_t (DNSQuestion::*)>("qtype", [](const DNSQuestion& dq) -> uint16_t { return dq.qtype; }, [](DNSQuestion& dq, uint16_t newType) { (void) newType; });
  d_lw->registerMember<bool (DNSQuestion::*)>("isTcp", [](const DNSQuestion& dq) -> bool { return dq.isTcp; }, [](DNSQuestion& dq, bool newTcp) { (void) newTcp; });
  d_lw->registerMember<const ComboAddress (DNSQuestion::*)>("localaddr", [](const DNSQuestion& dq) -> const ComboAddress& { return dq.local; }, [](DNSQuestion& dq, const ComboAddress& newLocal) { (void) newLocal; });
  d_lw->registerMember<const ComboAddress (DNSQuestion::*)>("remoteaddr", [](const DNSQuestion& dq) -> const ComboAddress& { return dq.remote; }, [](DNSQuestion& dq, const ComboAddress& newRemote) { (void) newRemote; });
  d_lw->registerMember<vState (DNSQuestion::*)>("validationState", [](const DNSQuestion& dq) -> vState { return dq.validationState; }, [](DNSQuestion& dq, vState newState) { (void) newState; });

  d_lw->registerMember<bool (DNSQuestion::*)>("variable", [](const DNSQuestion& dq) -> bool { return dq.variable; }, [](DNSQuestion& dq, bool newVariable) { dq.variable = newVariable; });
  d_lw->registerMember<bool (DNSQuestion::*)>("wantsRPZ", [](const DNSQuestion& dq) -> bool { return dq.wantsRPZ; }, [](DNSQuestion& dq, bool newWantsRPZ) { dq.wantsRPZ = newWantsRPZ; });

  d_lw->registerMember("rcode", &DNSQuestion::rcode);
  d_lw->registerMember("tag", &DNSQuestion::tag);
  d_lw->registerMember("requestorId", &DNSQuestion::requestorId);
  d_lw->registerMember("followupFunction", &DNSQuestion::followupFunction);
  d_lw->registerMember("followupPrefix", &DNSQuestion::followupPrefix);
  d_lw->registerMember("followupName", &DNSQuestion::followupName);
  d_lw->registerMember("data", &DNSQuestion::data);
  d_lw->registerMember("udpQuery", &DNSQuestion::udpQuery);
  d_lw->registerMember("udpAnswer", &DNSQuestion::udpAnswer);
  d_lw->registerMember("udpQueryDest", &DNSQuestion::udpQueryDest);
  d_lw->registerMember("udpCallback", &DNSQuestion::udpCallback);
  d_lw->registerMember("appliedPolicy", &DNSQuestion::appliedPolicy);
  d_lw->registerMember<DNSFilterEngine::Policy, std::string>("policyName",
    [](const DNSFilterEngine::Policy& pol) -> std::string {
      if(pol.d_name)
        return *pol.d_name;
      return std::string();
    },
    [](DNSFilterEngine::Policy& pol, const std::string& name) {
      pol.d_name = std::make_shared<std::string>(name);
    });
  d_lw->registerMember("policyKind", &DNSFilterEngine::Policy::d_kind);
  d_lw->registerMember("policyTTL", &DNSFilterEngine::Policy::d_ttl);
  d_lw->registerMember<DNSFilterEngine::Policy, std::string>("policyCustom",
    [](const DNSFilterEngine::Policy& pol) -> std::string {
      if(pol.d_custom)
        return pol.d_custom->getZoneRepresentation();
      return std::string();
    },
    [](DNSFilterEngine::Policy& pol, const std::string& content) {
      // Only CNAMES for now, when we ever add a d_custom_type, there will be pain
      pol.d_custom = DNSRecordContent::mastermake(QType::CNAME, 1, content);
    }
  );
  d_lw->registerFunction("getDH", &DNSQuestion::getDH);
  d_lw->registerFunction("getEDNSOptions", &DNSQuestion::getEDNSOptions);
  d_lw->registerFunction("getEDNSOption", &DNSQuestion::getEDNSOption);
  d_lw->registerFunction("getEDNSSubnet", &DNSQuestion::getEDNSSubnet);
  d_lw->registerFunction("getEDNSFlags", &DNSQuestion::getEDNSFlags);
  d_lw->registerFunction("getEDNSFlag", &DNSQuestion::getEDNSFlag);
  d_lw->registerMember("name", &DNSRecord::d_name);
  d_lw->registerMember("type", &DNSRecord::d_type);
  d_lw->registerMember("ttl", &DNSRecord::d_ttl);
  d_lw->registerMember("place", &DNSRecord::d_place);

  d_lw->registerMember("size", &EDNSOptionView::size);
  d_lw->registerFunction<std::string(EDNSOptionView::*)()>("getContent", [](const EDNSOptionView& option) { return std::string(option.content, option.size); });

  d_lw->registerFunction<string(DNSRecord::*)()>("getContent", [](const DNSRecord& dr) { return dr.d_content->getZoneRepresentation(); });
  d_lw->registerFunction<boost::optional<ComboAddress>(DNSRecord::*)()>("getCA", [](const DNSRecord& dr) { 
      boost::optional<ComboAddress> ret;

      if(auto rec = std::dynamic_pointer_cast<ARecordContent>(dr.d_content))
        ret=rec->getCA(53);
      else if(auto aaaarec = std::dynamic_pointer_cast<AAAARecordContent>(dr.d_content))
        ret=aaaarec->getCA(53);
      return ret;
    });


  d_lw->registerFunction<void(DNSRecord::*)(const std::string&)>("changeContent", [](DNSRecord& dr, const std::string& newContent) { dr.d_content = DNSRecordContent::mastermake(dr.d_type, 1, newContent); });
  d_lw->registerFunction("addAnswer", &DNSQuestion::addAnswer);
  d_lw->registerFunction("addRecord", &DNSQuestion::addRecord);
  d_lw->registerFunction("getRecords", &DNSQuestion::getRecords);
  d_lw->registerFunction("setRecords", &DNSQuestion::setRecords);

  d_lw->registerFunction<void(DNSQuestion::*)(const std::string&)>("addPolicyTag", [](DNSQuestion& dq, const std::string& tag) { if (dq.policyTags) { dq.policyTags->push_back(tag); } });
  d_lw->registerFunction<void(DNSQuestion::*)(const std::vector<std::pair<int, std::string> >&)>("setPolicyTags", [](DNSQuestion& dq, const std::vector<std::pair<int, std::string> >& tags) {
      if (dq.policyTags) {
        dq.policyTags->clear();
        for (const auto& tag : tags) {
          dq.policyTags->push_back(tag.second);
        }
      }
    });
  d_lw->registerFunction<std::vector<std::pair<int, std::string> >(DNSQuestion::*)()>("getPolicyTags", [](const DNSQuestion& dq) {
      std::vector<std::pair<int, std::string> > ret;
      if (dq.policyTags) {
        int count = 1;
        for (const auto& tag : *dq.policyTags) {
          ret.push_back({count++, tag});
        }
      }
      return ret;
    });

  d_lw->registerFunction<void(DNSQuestion::*)(const std::string&)>("discardPolicy", [](DNSQuestion& dq, const std::string& policy) {
      if (dq.discardedPolicies) {
        (*dq.discardedPolicies)[policy] = true;
      }
    });

  d_lw->writeFunction("newDS", []() { return SuffixMatchNode(); });
  d_lw->registerFunction<void(SuffixMatchNode::*)(boost::variant<string,DNSName, vector<pair<unsigned int,string> > >)>(
    "add",
    [](SuffixMatchNode&smn, const boost::variant<string,DNSName,vector<pair<unsigned int,string> > >& in){
      try {
        if(auto s = boost::get<string>(&in)) {
          smn.add(DNSName(*s));
        }
        else if(auto v = boost::get<vector<pair<unsigned int, string> > >(&in)) {
          for(const auto& entry : *v)
            smn.add(DNSName(entry.second));
        }
        else {
          smn.add(boost::get<DNSName>(in));
        }
      }
      catch(std::exception& e) {
        theL() <<Logger::Error<<e.what()<<endl;
      }
    }
  );

  d_lw->registerFunction("check",(bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);
  d_lw->registerFunction("toString",(string (SuffixMatchNode::*)() const) &SuffixMatchNode::toString);


  d_lw->writeFunction("pdnslog", [](const std::string& msg, boost::optional<int> loglevel) {
      theL() << (Logger::Urgency)loglevel.get_value_or(Logger::Warning) << msg<<endl;
    });
  typedef vector<pair<string, int> > in_t;
  vector<pair<string, boost::variant<int, in_t, struct timeval* > > >  pd{
    {"DROP",  (int)PolicyDecision::DROP}
  };

  vector<pair<string, int> > rcodes = {{"NOERROR",  RCode::NoError  },
                                       {"FORMERR",  RCode::FormErr  },
                                       {"SERVFAIL", RCode::ServFail },
                                       {"NXDOMAIN", RCode::NXDomain },
                                       {"NOTIMP",   RCode::NotImp   },
                                       {"REFUSED",  RCode::Refused  },
                                       {"YXDOMAIN", RCode::YXDomain },
                                       {"YXRRSET",  RCode::YXRRSet  },
                                       {"NXRRSET",  RCode::NXRRSet  },
                                       {"NOTAUTH",  RCode::NotAuth  },
                                       {"NOTZONE",  RCode::NotZone  }};
  for(const auto& rcode : rcodes)
    pd.push_back({rcode.first, rcode.second});

  pd.push_back({"loglevels", in_t{
        {"Alert", LOG_ALERT},
	{"Critical", LOG_CRIT},
	{"Debug", LOG_DEBUG},
        {"Emergency", LOG_EMERG},
	{"Info", LOG_INFO},
	{"Notice", LOG_NOTICE},
	{"Warning", LOG_WARNING},
	{"Error", LOG_ERR}
	  }});

  pd.push_back({"policykinds", in_t {
    {"NoAction", (int)DNSFilterEngine::PolicyKind::NoAction},
    {"Drop",     (int)DNSFilterEngine::PolicyKind::Drop    },
    {"NXDOMAIN", (int)DNSFilterEngine::PolicyKind::NXDOMAIN},
    {"NODATA",   (int)DNSFilterEngine::PolicyKind::NODATA  },
    {"Truncate", (int)DNSFilterEngine::PolicyKind::Truncate},
    {"Custom",   (int)DNSFilterEngine::PolicyKind::Custom  }
    }});

  for(const auto& n : QType::names)
    pd.push_back({n.first, n.second});

  pd.push_back({"validationstates", in_t{
        {"Indeterminate", Indeterminate },
        {"Bogus", Bogus },
        {"Insecure", Insecure },
        {"Secure", Secure },
  }});

  pd.push_back({"now", &g_now});
  d_lw->registerMember("tv_sec", &timeval::tv_sec);
  d_lw->registerMember("tv_usec", &timeval::tv_usec);

  d_lw->writeVariable("pdns", pd);

  d_lw->writeFunction("getMetric", [](const std::string& str) {
      return DynMetric{getDynMetric(str)};
    });

  d_lw->registerFunction("inc", &DynMetric::inc);
  d_lw->registerFunction("incBy", &DynMetric::incBy);
  d_lw->registerFunction("set", &DynMetric::set);
  d_lw->registerFunction("get", &DynMetric::get);

  d_lw->writeFunction("getStat", [](const std::string& str) {
      uint64_t result = 0;
      optional<uint64_t> value = getStatByName(str);
      if (value) {
        result = *value;
      }
      return result;
    });

  d_lw->writeFunction("getRecursorThreadId", []() {
      return getRecursorThreadId();
    });

  d_lw->writeFunction("sendCustomSNMPTrap", [](const std::string& str) {
      if (g_snmpAgent) {
        g_snmpAgent->sendCustomTrap(str);
      }
    });

  d_lw->writeFunction("getregisteredname", [](const DNSName &dname) {
      return getRegisteredName(dname);
    });
  
  ifstream ifs(fname);
  if(!ifs) {
    throw std::runtime_error("Unable to read configuration file from '"+fname+"': "+strerror(errno));
  }  	
  d_lw->executeCode(ifs);

  d_prerpz = d_lw->readVariable<boost::optional<luacall_t>>("prerpz").get_value_or(0);
  d_preresolve = d_lw->readVariable<boost::optional<luacall_t>>("preresolve").get_value_or(0);
  d_nodata = d_lw->readVariable<boost::optional<luacall_t>>("nodata").get_value_or(0);
  d_nxdomain = d_lw->readVariable<boost::optional<luacall_t>>("nxdomain").get_value_or(0);
  d_postresolve = d_lw->readVariable<boost::optional<luacall_t>>("postresolve").get_value_or(0);
  d_preoutquery = d_lw->readVariable<boost::optional<luacall_t>>("preoutquery").get_value_or(0);

  d_ipfilter = d_lw->readVariable<boost::optional<ipfilter_t>>("ipfilter").get_value_or(0);
  d_gettag = d_lw->readVariable<boost::optional<gettag_t>>("gettag").get_value_or(0);
  d_gettag_ffi = d_lw->readVariable<boost::optional<gettag_ffi_t>>("gettag_ffi").get_value_or(0);
}

bool RecursorLua4::prerpz(DNSQuestion& dq, int& ret) const
{
  return genhook(d_prerpz, dq, ret);
}

bool RecursorLua4::preresolve(DNSQuestion& dq, int& ret) const
{
  return genhook(d_preresolve, dq, ret);
}

bool RecursorLua4::nxdomain(DNSQuestion& dq, int& ret) const
{
  return genhook(d_nxdomain, dq, ret);
}

bool RecursorLua4::nodata(DNSQuestion& dq, int& ret) const
{
  return genhook(d_nodata, dq, ret);
}

bool RecursorLua4::postresolve(DNSQuestion& dq, int& ret) const
{
  return genhook(d_postresolve, dq, ret);
}

bool RecursorLua4::preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret) const
{
  bool variableAnswer = false;
  bool wantsRPZ = false;
  RecursorLua4::DNSQuestion dq(ns, requestor, query, qtype.getCode(), isTcp, variableAnswer, wantsRPZ);
  dq.currentRecords = &res;

  return genhook(d_preoutquery, dq, ret);
}

bool RecursorLua4::ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader& dh) const
{
  if(d_ipfilter)
    return d_ipfilter(remote, local, dh);
  return false; // don't block
}

unsigned int RecursorLua4::gettag(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& qname, uint16_t qtype, std::vector<std::string>* policyTags, LuaContext::LuaObject& data, const std::map<uint16_t, EDNSOptionView>& ednsOptions, bool tcp, std::string& requestorId, std::string& deviceId) const
{
  if(d_gettag) {
    auto ret = d_gettag(remote, ednssubnet, local, qname, qtype, ednsOptions, tcp);

    if (policyTags) {
      const auto& tags = std::get<1>(ret);
      if (tags) {
        for (const auto& tag : *tags) {
          policyTags->push_back(tag.second);
        }
      }
    }
    const auto dataret = std::get<2>(ret);
    if (dataret) {
      data = *dataret;
    }
    const auto reqIdret = std::get<3>(ret);
    if (reqIdret) {
      requestorId = *reqIdret;
    }
    const auto deviceIdret = std::get<4>(ret);
    if (deviceIdret) {
      deviceId = *deviceIdret;
    }
    return std::get<0>(ret);
  }
  return 0;
}

struct pdns_ffi_param
{
public:
  pdns_ffi_param(const DNSName& qname_, uint16_t qtype_, const ComboAddress& local_, const ComboAddress& remote_, const Netmask& ednssubnet_, std::vector<std::string>& policyTags_, const std::map<uint16_t, EDNSOptionView>& ednsOptions_, std::string& requestorId_, std::string& deviceId_, uint32_t& ttlCap_, bool& variable_, bool tcp_): qname(qname_), local(local_), remote(remote_), ednssubnet(ednssubnet_), policyTags(policyTags_), ednsOptions(ednsOptions_), requestorId(requestorId_), deviceId(deviceId_), ttlCap(ttlCap_), variable(variable_), qtype(qtype_), tcp(tcp_)
  {
  }

  std::unique_ptr<std::string> qnameStr{nullptr};
  std::unique_ptr<std::string> localStr{nullptr};
  std::unique_ptr<std::string> remoteStr{nullptr};
  std::unique_ptr<std::string> ednssubnetStr{nullptr};
  std::vector<pdns_ednsoption_t> ednsOptionsVect;

  const DNSName& qname;
  const ComboAddress& local;
  const ComboAddress& remote;
  const Netmask& ednssubnet;
  std::vector<std::string>& policyTags;
  const std::map<uint16_t, EDNSOptionView>& ednsOptions;
  std::string& requestorId;
  std::string& deviceId;
  uint32_t& ttlCap;
  bool& variable;

  unsigned int tag{0};
  uint16_t qtype;
  bool tcp;
};

unsigned int RecursorLua4::gettag_ffi(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& qname, uint16_t qtype, std::vector<std::string>* policyTags, LuaContext::LuaObject& data, const std::map<uint16_t, EDNSOptionView>& ednsOptions, bool tcp, std::string& requestorId, std::string& deviceId, uint32_t& ttlCap, bool& variable) const
{
  if (d_gettag_ffi) {
    pdns_ffi_param_t param(qname, qtype, local, remote, ednssubnet, *policyTags, ednsOptions, requestorId, deviceId, ttlCap, variable, tcp);

    auto ret = d_gettag_ffi(&param);
    if (ret) {
      data = *ret;
    }

    return param.tag;
  }
  return 0;
}

bool RecursorLua4::genhook(const luacall_t& func, DNSQuestion& dq, int& ret) const
{
  if(!func)
    return false;

  if (dq.currentRecords) {
    dq.records = *dq.currentRecords;
  } else {
    dq.records.clear();
  }

  dq.followupFunction.clear();
  dq.followupPrefix.clear();
  dq.followupName.clear();
  dq.udpQuery.clear();
  dq.udpAnswer.clear();
  dq.udpCallback.clear();

  dq.rcode = ret;
  bool handled=func(&dq);

  if(handled) {
loop:;
    ret=dq.rcode;
    
    if(!dq.followupFunction.empty()) {
      if(dq.followupFunction=="followCNAMERecords") {
        ret = followCNAMERecords(dq.records, QType(dq.qtype));
      }
      else if(dq.followupFunction=="getFakeAAAARecords") {
        ret=getFakeAAAARecords(dq.followupName, dq.followupPrefix, dq.records);
      }
      else if(dq.followupFunction=="getFakePTRRecords") {
        ret=getFakePTRRecords(dq.followupName, dq.followupPrefix, dq.records);
      }
      else if(dq.followupFunction=="udpQueryResponse") {
        dq.udpAnswer = GenUDPQueryResponse(dq.udpQueryDest, dq.udpQuery);
        auto cbFunc = d_lw->readVariable<boost::optional<luacall_t>>(dq.udpCallback).get_value_or(0);
        if(!cbFunc) {
          theL()<<Logger::Error<<"Attempted callback for Lua UDP Query/Response which could not be found"<<endl;
          return false;
        }
        bool result=cbFunc(&dq);
        if(!result) {
          return false;
        }
        goto loop;
      }
    }
    if (dq.currentRecords) {
      *dq.currentRecords = dq.records;
    }
  }

  // see if they added followup work for us too
  return handled;
}

RecursorLua4::~RecursorLua4(){}

const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref)
{
  if (!ref->qnameStr) {
    ref->qnameStr = std::unique_ptr<std::string>(new std::string(ref->qname.toStringNoDot()));
  }

  return ref->qnameStr->c_str();
}

void pdns_ffi_param_get_qname_raw(pdns_ffi_param_t* ref, const char** qname, size_t* qnameSize)
{
  const auto& storage = ref->qname.getStorage();
  *qname = storage.data();
  *qnameSize = storage.size();
}

uint16_t pdns_ffi_param_get_qtype(const pdns_ffi_param_t* ref)
{
  return ref->qtype;
}

const char* pdns_ffi_param_get_remote(pdns_ffi_param_t* ref)
{
  if (!ref->remoteStr) {
    ref->remoteStr = std::unique_ptr<std::string>(new std::string(ref->remote.toString()));
  }

  return ref->remoteStr->c_str();
}

static void pdns_ffi_comboaddress_to_raw(const ComboAddress& ca, const void** addr, size_t* addrSize)
{
  if (ca.isIPv4()) {
    *addr = &ca.sin4.sin_addr.s_addr;
    *addrSize = sizeof(ca.sin4.sin_addr.s_addr);
  }
  else {
    *addr = &ca.sin6.sin6_addr.s6_addr;
    *addrSize = sizeof(ca.sin6.sin6_addr.s6_addr);
  }
}

void pdns_ffi_param_get_remote_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize)
{
  pdns_ffi_comboaddress_to_raw(ref->remote, addr, addrSize);
}

uint16_t pdns_ffi_param_get_remote_port(const pdns_ffi_param_t* ref)
{
  return ref->remote.getPort();
}

const char* pdns_ffi_param_get_local(pdns_ffi_param_t* ref)
{
  if (!ref->localStr) {
    ref->localStr = std::unique_ptr<std::string>(new std::string(ref->local.toString()));
  }

  return ref->localStr->c_str();
}

void pdns_ffi_param_get_local_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize)
{
  pdns_ffi_comboaddress_to_raw(ref->local, addr, addrSize);
}

uint16_t pdns_ffi_param_get_local_port(const pdns_ffi_param_t* ref)
{
  return ref->local.getPort();
}

const char* pdns_ffi_param_get_edns_cs(pdns_ffi_param_t* ref)
{
  if (ref->ednssubnet.empty()) {
    return nullptr;
  }

  if (!ref->ednssubnetStr) {
    ref->ednssubnetStr = std::unique_ptr<std::string>(new std::string(ref->ednssubnet.toStringNoMask()));
  }

  return ref->ednssubnetStr->c_str();
}

void pdns_ffi_param_get_edns_cs_raw(pdns_ffi_param_t* ref, const void** net, size_t* netSize)
{
  if (ref->ednssubnet.empty()) {
    *net = nullptr;
    *netSize = 0;
    return;
  }

  pdns_ffi_comboaddress_to_raw(ref->ednssubnet.getNetwork(), net, netSize);
}

uint8_t pdns_ffi_param_get_edns_cs_source_mask(const pdns_ffi_param_t* ref)
{
  return ref->ednssubnet.getBits();
}

static void fill_edns_option(const EDNSOptionView& view, pdns_ednsoption_t& option)
{
  option.len = view.size;
  option.data = nullptr;

  if (view.size > 0) {
    option.data = view.content;
  }
}

size_t pdns_ffi_param_get_edns_options(pdns_ffi_param_t* ref, const pdns_ednsoption_t** out)
{
  if (ref->ednsOptions.empty()) {
    return 0;
  }

  size_t count = ref->ednsOptions.size();
  ref->ednsOptionsVect.resize(count);

  size_t pos = 0;
  for (const auto& entry : ref->ednsOptions) {
    fill_edns_option(entry.second, ref->ednsOptionsVect.at(pos));
    ref->ednsOptionsVect.at(pos).optionCode = entry.first;
    pos++;
  }

  *out = ref->ednsOptionsVect.data();

  return count;
}

size_t pdns_ffi_param_get_edns_options_by_code(pdns_ffi_param_t* ref, uint16_t optionCode, const pdns_ednsoption_t** out)
{
  const auto& it = ref->ednsOptions.find(optionCode);
  if (it == ref->ednsOptions.cend()) {
    return 0;
  }

  /* the current code deals with only one entry per code, but we will fix that */
  ref->ednsOptionsVect.resize(1);
  fill_edns_option(it->second, ref->ednsOptionsVect.at(0));
  ref->ednsOptionsVect.at(0).optionCode = it->first;

  *out = ref->ednsOptionsVect.data();

  return 1;
}

void pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag)
{
  ref->tag = tag;
}

void pdns_ffi_param_add_policytag(pdns_ffi_param_t *ref, const char* name)
{
  ref->policyTags.push_back(std::string(name));
}

void pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name)
{
  ref->requestorId = std::string(name);
}

void pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name)
{
  ref->deviceId = std::string(name);
}

void pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name)
{
  ref->deviceId = std::string(reinterpret_cast<const char*>(name), len);
}

void pdns_ffi_param_set_variable(pdns_ffi_param_t* ref, bool variable)
{
  ref->variable = variable;
}

void pdns_ffi_param_set_ttl_cap(pdns_ffi_param_t* ref, uint32_t ttl)
{
  ref->ttlCap = ttl;
}
