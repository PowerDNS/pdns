#include "lua-auth4.hh"
#include "stubresolver.hh"
#include <fstream>
#include "logger.hh"
#include "dnsparser.hh"
#include "namespaces.hh"
#include "ednssubnet.hh"
#include <unordered_set>

#if !defined(HAVE_LUA)

AuthLua4::AuthLua4(const std::string& fname) { }
bool AuthLua4::updatePolicy(const DNSName &qname, QType qtype, const DNSName &zonename, DNSPacket *packet) { return false; }
bool AuthLua4::axfrfilter(const ComboAddress& remote, const DNSName& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out) { return false; }
AuthLua4::~AuthLua4() { }

#else

#undef L
#include "ext/luawrapper/include/LuaContext.hpp"

AuthLua4::AuthLua4(const std::string& fname) {
  d_lw = std::unique_ptr<LuaContext>(new LuaContext);
  stubParseResolveConf();
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

  d_lw->writeFunction("newDN", [](const std::string& dom){ return DNSName(dom); });
  d_lw->registerFunction("isPartOf", &DNSName::isPartOf);
  d_lw->registerFunction<bool(DNSName::*)(const std::string&)>("equal",
                                                              [](const DNSName& lhs, const std::string& rhs) { return lhs==DNSName(rhs); });
  d_lw->registerFunction("__eq", &DNSName::operator==);

  d_lw->registerFunction("__eq", &DNSResourceRecord::operator==);
  d_lw->registerFunction("__lt", &DNSResourceRecord::operator<);

  d_lw->registerFunction<string(DNSResourceRecord::*)()>("toString", [](const DNSResourceRecord& rec) { return rec.getZoneRepresentation();} );

  d_lw->registerFunction<DNSName(DNSResourceRecord::*)()>("qname", [](DNSResourceRecord& rec) { return rec.qname; });
  d_lw->registerFunction<DNSName(DNSResourceRecord::*)()>("wildcardname", [](DNSResourceRecord& rec) { return rec.wildcardname; });
  d_lw->registerFunction<string(DNSResourceRecord::*)()>("content", [](DNSResourceRecord& rec) { return rec.content; });
  d_lw->registerFunction<time_t(DNSResourceRecord::*)()>("last_modified", [](DNSResourceRecord& rec) { return rec.last_modified; });
  d_lw->registerFunction<uint32_t(DNSResourceRecord::*)()>("ttl", [](DNSResourceRecord& rec) { return rec.ttl; });
  d_lw->registerFunction<uint32_t(DNSResourceRecord::*)()>("signttl", [](DNSResourceRecord& rec) { return rec.signttl; });
  d_lw->registerFunction<int(DNSResourceRecord::*)()>("domain_id", [](DNSResourceRecord& rec) { return rec.domain_id; });
  d_lw->registerFunction<uint16_t(DNSResourceRecord::*)()>("qtype", [](DNSResourceRecord& rec) { return rec.qtype.getCode(); });
  d_lw->registerFunction<uint16_t(DNSResourceRecord::*)()>("qclass", [](DNSResourceRecord& rec) { return rec.qclass; });
  d_lw->registerFunction<uint8_t(DNSResourceRecord::*)()>("scopeMask", [](DNSResourceRecord& rec) { return rec.scopeMask; });
  d_lw->registerFunction<bool(DNSResourceRecord::*)()>("auth", [](DNSResourceRecord& rec) { return rec.auth; });
  d_lw->registerFunction<bool(DNSResourceRecord::*)()>("disabled", [](DNSResourceRecord& rec) { return rec.disabled; });

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

  d_lw->writeFunction("newCA", [](const std::string& a) { return ComboAddress(a); });
  typedef std::unordered_set<ComboAddress,ComboAddress::addressOnlyHash,ComboAddress::addressOnlyEqual> cas_t;
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
                                                                                     catch(std::exception& e) { theL() <<Logger::Error<<e.what()<<endl; }
                                                                                   });

  d_lw->registerFunction<bool(cas_t::*)(const ComboAddress&)>("check",[](const cas_t& cas, const ComboAddress&ca) {
      return (bool)cas.count(ca);
    });



  d_lw->registerFunction<bool(ComboAddress::*)(const ComboAddress&)>("equal", [](const ComboAddress& lhs, const ComboAddress& rhs) {
      return ComboAddress::addressOnlyEqual()(lhs, rhs);
    });


  d_lw->registerFunction<ComboAddress(Netmask::*)()>("getNetwork", [](const Netmask& nm) { return nm.getNetwork(); } ); // const reference makes this necessary
  d_lw->registerFunction("toString", &Netmask::toString);
  d_lw->registerFunction("empty", &Netmask::empty);

  d_lw->writeFunction("newNMG", []() { return NetmaskGroup(); });
  d_lw->registerFunction<void(NetmaskGroup::*)(const std::string&mask)>("addMask", [](NetmaskGroup&nmg, const std::string& mask)
                         {
                           nmg.addMask(mask);
                         });

  d_lw->registerFunction<void(NetmaskGroup::*)(const vector<pair<unsigned int, std::string>>&)>("addMasks", [](NetmaskGroup&nmg, const vector<pair<unsigned int, std::string>>& masks)
                         {
                           for(const auto& mask: masks)
                             nmg.addMask(mask.second);
                         });


  d_lw->registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const)&NetmaskGroup::match);
  d_lw->registerFunction<string(DNSName::*)()>("toString", [](const DNSName&dn ) { return dn.toString(); });
  d_lw->registerFunction<string(DNSName::*)()>("toStringNoDot", [](const DNSName&dn ) { return dn.toStringNoDot(); });
  d_lw->registerFunction<bool(DNSName::*)()>("chopOff", [](DNSName&dn ) { return dn.chopOff(); });
  d_lw->registerMember("name", &DNSRecord::d_name);
  d_lw->registerMember("type", &DNSRecord::d_type);
  d_lw->registerMember("ttl", &DNSRecord::d_ttl);


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

  d_lw->writeFunction("pdnslog", [](const std::string& msg, boost::optional<int> loglevel) {
      theL() << (Logger::Urgency)loglevel.get_value_or(Logger::Warning) << msg<<endl;
    });
  typedef vector<pair<string, int> > in_t;
  vector<pair<string, boost::variant<int, in_t, struct timeval* > > >  pd{
    {"PASS", (int)PolicyDecision::PASS}, {"DROP",  (int)PolicyDecision::DROP},
    {"TRUNCATE", (int)PolicyDecision::TRUNCATE}
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

  pd.push_back({"place", in_t{
    {"QUESTION", 0},
    {"ANSWER", 1},
    {"AUTHORITY", 2},
    {"ADDITIONAL", 3}
  }});

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

  for(const auto& n : QType::names)
    pd.push_back({n.first, n.second});
  d_lw->registerMember("tv_sec", &timeval::tv_sec);
  d_lw->registerMember("tv_usec", &timeval::tv_usec);

  d_lw->writeVariable("pdns", pd);

  d_lw->writeFunction("resolve", [](const std::string& qname, uint16_t qtype) {
      std::vector<DNSZoneRecord> ret;
      std::unordered_map<int, DNSResourceRecord> luaResult;
      stubDoResolve(DNSName(qname), qtype, ret);
      int i = 0;
      for(const auto &row: ret) {
        luaResult[++i] = DNSResourceRecord::fromWire(row.dr);
        luaResult[i].auth = row.auth;
      }
      return luaResult;
  });


/* update policy */
  d_lw->registerFunction<DNSName(UpdatePolicyQuery::*)()>("getQName", [](UpdatePolicyQuery& upq) { return upq.qname; });
  d_lw->registerFunction<DNSName(UpdatePolicyQuery::*)()>("getZoneName", [](UpdatePolicyQuery& upq) { return upq.zonename; });
  d_lw->registerFunction<uint16_t(UpdatePolicyQuery::*)()>("getQType", [](UpdatePolicyQuery& upq) { return upq.qtype; });
  d_lw->registerFunction<ComboAddress(UpdatePolicyQuery::*)()>("getLocal", [](UpdatePolicyQuery& upq) { return upq.local; });
  d_lw->registerFunction<ComboAddress(UpdatePolicyQuery::*)()>("getRemote", [](UpdatePolicyQuery& upq) { return upq.remote; });
  d_lw->registerFunction<Netmask(UpdatePolicyQuery::*)()>("getRealRemote", [](UpdatePolicyQuery& upq) { return upq.realRemote; });
  d_lw->registerFunction<DNSName(UpdatePolicyQuery::*)()>("getTsigName", [](UpdatePolicyQuery& upq) { return upq.tsigName; });
  d_lw->registerFunction<std::string(UpdatePolicyQuery::*)()>("getPeerPrincipal", [](UpdatePolicyQuery& upq) { return upq.peerPrincipal; });
/* end of update policy */

  ifstream ifs(fname);
  if(!ifs) {
    theL()<<Logger::Error<<"Unable to read configuration file from '"<<fname<<"': "<<strerror(errno)<<endl;
    return;
  }
  d_lw->executeCode(ifs);

  d_update_policy = d_lw->readVariable<boost::optional<luacall_update_policy_t>>("updatepolicy").get_value_or(0);
  d_axfr_filter = d_lw->readVariable<boost::optional<luacall_axfr_filter_t>>("axfrfilter").get_value_or(0);

}

bool AuthLua4::axfrfilter(const ComboAddress& remote, const DNSName& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out) {
  luacall_axfr_filter_t::result_type ret;
  int rcode;

  if (d_axfr_filter == NULL) return false;

  ret = d_axfr_filter(remote, zone, in);
  rcode = std::get<0>(ret);
  if (rcode < 0) {
    // no modification, handle normally
    return false;
  }
  else if (rcode == 0) {
    // replace the matching record by the filtered record(s)
  }
  else if (rcode == 1) {
    // append the filtered record(s) after the matching record
    out.push_back(in);
  }
  else
    throw PDNSException("Cannot understand return code "+std::to_string(rcode)+" in axfr filter response");

  const auto& rows = std::get<1>(ret);

  for(const auto& row: rows) {
    DNSResourceRecord rec;
    for(const auto& col: row.second) {
      if (col.first == "qtype")
        rec.qtype = QType(boost::get<unsigned int>(col.second));
      else if (col.first == "qname")
        rec.qname = DNSName(boost::get<std::string>(col.second)).makeLowerCase();
      else if (col.first == "ttl")
        rec.ttl = boost::get<unsigned int>(col.second);
      else if (col.first == "content")
        rec.setContent(boost::get<std::string>(col.second));
      else
        throw PDNSException("Cannot understand "+col.first+" in axfr filter response on row "+std::to_string(row.first));
    }
    out.push_back(rec);
  }

  return true;
}


bool AuthLua4::updatePolicy(const DNSName &qname, QType qtype, const DNSName &zonename, DNSPacket *packet) {
  UpdatePolicyQuery upq;
  upq.qname = qname;
  upq.qtype = qtype.getCode();
  upq.zonename = zonename;
  upq.local = packet->getLocal();
  upq.remote = packet->getRemote();
  upq.realRemote = packet->getRealRemote();
  upq.tsigName = packet->getTSIGKeyname();
  upq.peerPrincipal = packet->d_peer_principal;

  return d_update_policy(upq);
}

AuthLua4::~AuthLua4() { }

#endif
