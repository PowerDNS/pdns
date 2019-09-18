#include <fstream>
#include <unordered_set>
#include <unordered_map>
#include <typeinfo>
#include "logger.hh"
#include "iputils.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnspacket.hh"
#include "namespaces.hh"
#include "ednssubnet.hh"
#include "lua-base4.hh"
#include "dns_random.hh"

BaseLua4::BaseLua4() {
}

void BaseLua4::loadFile(const std::string &fname) {
  std::ifstream ifs(fname);
  if(!ifs) {
    g_log<<Logger::Error<<"Unable to read configuration file from '"<<fname<<"': "<<stringerror()<<endl;
    return;
  }
  loadStream(ifs);
};

void BaseLua4::loadString(const std::string &script) {
  std::istringstream iss(script);
  loadStream(iss);
};

//  By default no features
void BaseLua4::getFeatures(Features &) { }

#if !defined(HAVE_LUA)

void BaseLua4::prepareContext() { return; }
void BaseLua4::loadStream(std::istream &is) { return; }
BaseLua4::~BaseLua4() { }

#else

#include "ext/luawrapper/include/LuaContext.hpp"

void BaseLua4::prepareContext() {
  d_lw = std::unique_ptr<LuaContext>(new LuaContext);

  // lua features available
  Features features;
  getFeatures(features);
  d_lw->writeVariable("pdns_features", features);
  
  // dnsheader
  d_lw->registerFunction<int(dnsheader::*)()>("getID", [](dnsheader& dh) { return ntohs(dh.id); });
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

  // DNSName
  d_lw->writeFunction("newDN", [](const std::string& dom){ return DNSName(dom); });
  d_lw->registerFunction("__lt", &DNSName::operator<);
  d_lw->registerFunction("canonCompare", &DNSName::canonCompare);
  d_lw->registerFunction("makeRelative", &DNSName::makeRelative);
  d_lw->registerFunction("isPartOf", &DNSName::isPartOf);
  d_lw->registerFunction("getRawLabels", &DNSName::getRawLabels);
  d_lw->registerFunction<unsigned int(DNSName::*)()>("countLabels", [](const DNSName& name) { return name.countLabels(); });
  d_lw->registerFunction<size_t(DNSName::*)()>("wireLength", [](const DNSName& name) { return name.wirelength(); });
  d_lw->registerFunction<size_t(DNSName::*)()>("wirelength", [](const DNSName& name) { return name.wirelength(); });
  d_lw->registerFunction<bool(DNSName::*)(const std::string&)>("equal", [](const DNSName& lhs, const std::string& rhs) { return lhs==DNSName(rhs); });
  d_lw->registerEqFunction(&DNSName::operator==);
  d_lw->registerToStringFunction<string(DNSName::*)()>([](const DNSName&dn ) { return dn.toString(); });
  d_lw->registerFunction<string(DNSName::*)()>("toString", [](const DNSName&dn ) { return dn.toString(); });
  d_lw->registerFunction<string(DNSName::*)()>("toStringNoDot", [](const DNSName&dn ) { return dn.toStringNoDot(); });
  d_lw->registerFunction<bool(DNSName::*)()>("chopOff", [](DNSName&dn ) { return dn.chopOff(); });

  // DNSResourceRecord
  d_lw->writeFunction("newDRR", [](const DNSName& qname, const string& qtype, const unsigned int ttl, const string& content, boost::optional<int> domain_id, boost::optional<int> auth){
    auto drr = DNSResourceRecord();
    drr.qname = qname;
    drr.qtype = qtype;
    drr.ttl = ttl;
    drr.setContent(content);
    if (domain_id)
      drr.domain_id = *domain_id;
    if (auth)
      drr.auth = *auth;
     return drr;
  });
  d_lw->registerEqFunction(&DNSResourceRecord::operator==);
  d_lw->registerFunction("__lt", &DNSResourceRecord::operator<);
  d_lw->registerToStringFunction<string(DNSResourceRecord::*)()>([](const DNSResourceRecord& rec) { return rec.getZoneRepresentation(); });
  d_lw->registerFunction<string(DNSResourceRecord::*)()>("toString", [](const DNSResourceRecord& rec) { return rec.getZoneRepresentation();} );
  d_lw->registerFunction<DNSName(DNSResourceRecord::*)()>("qname", [](DNSResourceRecord& rec) { return rec.qname; });
  d_lw->registerFunction<DNSName(DNSResourceRecord::*)()>("wildcardName", [](DNSResourceRecord& rec) { return rec.wildcardname; });
  d_lw->registerFunction<string(DNSResourceRecord::*)()>("content", [](DNSResourceRecord& rec) { return rec.content; });
  d_lw->registerFunction<time_t(DNSResourceRecord::*)()>("lastModified", [](DNSResourceRecord& rec) { return rec.last_modified; });
  d_lw->registerFunction<uint32_t(DNSResourceRecord::*)()>("ttl", [](DNSResourceRecord& rec) { return rec.ttl; });
  d_lw->registerFunction<uint32_t(DNSResourceRecord::*)()>("signttl", [](DNSResourceRecord& rec) { return rec.signttl; });
  d_lw->registerFunction<int(DNSResourceRecord::*)()>("domainId", [](DNSResourceRecord& rec) { return rec.domain_id; });
  d_lw->registerFunction<uint16_t(DNSResourceRecord::*)()>("qtype", [](DNSResourceRecord& rec) { return rec.qtype.getCode(); });
  d_lw->registerFunction<uint16_t(DNSResourceRecord::*)()>("qclass", [](DNSResourceRecord& rec) { return rec.qclass; });
  d_lw->registerFunction<uint8_t(DNSResourceRecord::*)()>("scopeMask", [](DNSResourceRecord& rec) { return rec.scopeMask; });
  d_lw->registerFunction<bool(DNSResourceRecord::*)()>("auth", [](DNSResourceRecord& rec) { return rec.auth; });
  d_lw->registerFunction<bool(DNSResourceRecord::*)()>("disabled", [](DNSResourceRecord& rec) { return rec.disabled; });

  // ComboAddress
  d_lw->registerFunction<bool(ComboAddress::*)()>("isIPv4", [](const ComboAddress& ca) { return ca.sin4.sin_family == AF_INET; });
  d_lw->registerFunction<bool(ComboAddress::*)()>("isIPv6", [](const ComboAddress& ca) { return ca.sin4.sin_family == AF_INET6; });
  d_lw->registerFunction<uint16_t(ComboAddress::*)()>("getPort", [](const ComboAddress& ca) { return ntohs(ca.sin4.sin_port); } );
  d_lw->registerFunction<bool(ComboAddress::*)()>("isMappedIPv4", [](const ComboAddress& ca) { return ca.isMappedIPv4(); });
  d_lw->registerFunction<ComboAddress(ComboAddress::*)()>("mapToIPv4", [](const ComboAddress& ca) { return ca.mapToIPv4(); });
  d_lw->registerFunction<void(ComboAddress::*)(unsigned int)>("truncate", [](ComboAddress& ca, unsigned int bits) { ca.truncate(bits); });
  d_lw->registerFunction<string(ComboAddress::*)()>("toString", [](const ComboAddress& ca) { return ca.toString(); });
  d_lw->registerToStringFunction<string(ComboAddress::*)()>([](const ComboAddress& ca) { return ca.toString(); });
  d_lw->registerFunction<string(ComboAddress::*)()>("toStringWithPort", [](const ComboAddress& ca) { return ca.toStringWithPort(); });
  d_lw->registerFunction<string(ComboAddress::*)()>("getRaw", [](const ComboAddress& ca) {
      if(ca.sin4.sin_family == AF_INET) {
        auto t=ca.sin4.sin_addr.s_addr; return string((const char*)&t, 4);
      }
      else
        return string((const char*)&ca.sin6.sin6_addr.s6_addr, 16);
    } );

  d_lw->writeFunction("newCA", [](const std::string& a) { return ComboAddress(a); });
  typedef std::unordered_set<ComboAddress,ComboAddress::addressOnlyHash,ComboAddress::addressOnlyEqual> cas_t;
  d_lw->registerFunction<bool(ComboAddress::*)(const ComboAddress&)>("equal", [](const ComboAddress& lhs, const ComboAddress& rhs) { return ComboAddress::addressOnlyEqual()(lhs, rhs); });

  // cas_t
  d_lw->writeFunction("newCAS", []{ return cas_t(); });
  d_lw->registerFunction<void(cas_t::*)(boost::variant<string,ComboAddress, vector<pair<unsigned int,string> > >)>("add",
    [](cas_t& cas, const boost::variant<string,ComboAddress,vector<pair<unsigned int,string> > >& in)
    {
      try {
      if(auto s = boost::get<string>(&in)) {
        cas.insert(ComboAddress(*s));
      }
      else if(auto v = boost::get<vector<pair<unsigned int, string> > >(&in)) {
        for(const auto& str : *v)
          cas.insert(ComboAddress(str.second));
      }
      else
        cas.insert(boost::get<ComboAddress>(in));
      }
      catch(std::exception& e) { g_log <<Logger::Error<<e.what()<<endl; }
    });
  d_lw->registerFunction<bool(cas_t::*)(const ComboAddress&)>("check",[](const cas_t& cas, const ComboAddress&ca) { return cas.count(ca)>0; });

  // QType
  d_lw->writeFunction("newQType", [](const string& s) { QType q; q = s; return q; });
  d_lw->registerFunction("getCode", &QType::getCode);
  d_lw->registerFunction("getName", &QType::getName);
  d_lw->registerEqFunction<bool(QType::*)(const QType&)>([](const QType& a, const QType& b){ return a == b;}); // operator overloading confuses LuaContext
  d_lw->registerToStringFunction(&QType::getName);

  // Netmask
  d_lw->writeFunction("newNetmask", [](const string& s) { return Netmask(s); });
  d_lw->registerFunction<ComboAddress(Netmask::*)()>("getNetwork", [](const Netmask& nm) { return nm.getNetwork(); } ); // const reference makes this necessary
  d_lw->registerFunction<ComboAddress(Netmask::*)()>("getMaskedNetwork", [](const Netmask& nm) { return nm.getMaskedNetwork(); } );
  d_lw->registerFunction("isIpv4", &Netmask::isIpv4);
  d_lw->registerFunction("isIpv6", &Netmask::isIpv6);
  d_lw->registerFunction("getBits", &Netmask::getBits);
  d_lw->registerFunction("toString", &Netmask::toString);
  d_lw->registerFunction("empty", &Netmask::empty);
  d_lw->registerFunction("match", (bool (Netmask::*)(const string&) const)&Netmask::match);
  d_lw->registerEqFunction(&Netmask::operator==);
  d_lw->registerToStringFunction(&Netmask::toString);

  // NetmaskGroup
  d_lw->writeFunction("newNMG", []() { return NetmaskGroup(); });
  d_lw->registerFunction<void(NetmaskGroup::*)(const std::string&mask)>("addMask", [](NetmaskGroup&nmg, const std::string& mask) { nmg.addMask(mask); });
  d_lw->registerFunction<void(NetmaskGroup::*)(const vector<pair<unsigned int, std::string>>&)>("addMasks", [](NetmaskGroup&nmg, const vector<pair<unsigned int, std::string>>& masks) { for(const auto& mask: masks) { nmg.addMask(mask.second); } });
  d_lw->registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const)&NetmaskGroup::match);

  // DNSRecord
  d_lw->writeFunction("newDR", [](const DNSName &name, const std::string &type, unsigned int ttl, const std::string &content, int place){ QType qtype; qtype = type; auto dr = DNSRecord(); dr.d_name = name; dr.d_type = qtype.getCode(); dr.d_ttl = ttl; dr.d_content = shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(dr.d_type, 1, content)); dr.d_place = static_cast<DNSResourceRecord::Place>(place); return dr; });
  d_lw->registerMember("name", &DNSRecord::d_name);
  d_lw->registerMember("type", &DNSRecord::d_type);
  d_lw->registerMember("ttl", &DNSRecord::d_ttl);
  d_lw->registerMember("place", &DNSRecord::d_place);
  d_lw->registerFunction<string(DNSRecord::*)()>("getContent", [](const DNSRecord& dr) { return dr.d_content->getZoneRepresentation(); });
  d_lw->registerFunction<boost::optional<ComboAddress>(DNSRecord::*)()>("getCA", [](const DNSRecord& dr) {
      boost::optional<ComboAddress> ret;

      if(auto arec = std::dynamic_pointer_cast<ARecordContent>(dr.d_content))
        ret=arec->getCA(53);
      else if(auto aaaarec = std::dynamic_pointer_cast<AAAARecordContent>(dr.d_content))
        ret=aaaarec->getCA(53);
      return ret;
    });
  d_lw->registerFunction<void(DNSRecord::*)(const std::string&)>("changeContent", [](DNSRecord& dr, const std::string& newContent) { dr.d_content = shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(dr.d_type, 1, newContent)); });

  // pdnsload
  d_lw->writeFunction("pdnslog", [](const std::string& msg, boost::optional<int> loglevel) { g_log << (Logger::Urgency)loglevel.get_value_or(Logger::Warning) << msg<<endl; });
  d_lw->writeFunction("pdnsrandom", [](boost::optional<uint32_t> maximum) { return dns_random(maximum.get_value_or(0xffffffff)); });

  // certain constants
  d_pd.push_back({"PASS", (int)PolicyDecision::PASS});
  d_pd.push_back({"DROP", (int)PolicyDecision::DROP});
  d_pd.push_back({"TRUNCATE", (int)PolicyDecision::TRUNCATE});

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
    d_pd.push_back({rcode.first, rcode.second});

  d_pd.push_back({"place", in_t{
    {"QUESTION", 0},
    {"ANSWER", 1},
    {"AUTHORITY", 2},
    {"ADDITIONAL", 3}
  }});

  d_pd.push_back({"loglevels", in_t{
        {"Alert", LOG_ALERT},
        {"Critical", LOG_CRIT},
        {"Debug", LOG_DEBUG},
        {"Emergency", LOG_EMERG},
        {"Info", LOG_INFO},
        {"Notice", LOG_NOTICE},
        {"Warning", LOG_WARNING},
        {"Error", LOG_ERR}
          }});

  for(const auto& n : QType::names)
    d_pd.push_back({n.first, n.second});

  d_lw->registerMember("tv_sec", &timeval::tv_sec);
  d_lw->registerMember("tv_usec", &timeval::tv_usec);

  postPrepareContext();

  // so we can let postprepare do changes to this
  d_lw->writeVariable("pdns", d_pd);
}

void BaseLua4::loadStream(std::istream &is) {
  d_lw->executeCode(is);

  postLoad();
}

BaseLua4::~BaseLua4() { }

#endif
