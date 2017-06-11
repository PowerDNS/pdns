#include "lua-auth4.hh"
#include "stubresolver.hh"
#include <fstream>
#include "logger.hh"
#include "dnsparser.hh"
#include "namespaces.hh"
#include "ednssubnet.hh"
#include <unordered_set>

AuthLua4::AuthLua4() { prepareContext(); }

#if !defined(HAVE_LUA)

bool AuthLua4::updatePolicy(const DNSName &qname, QType qtype, const DNSName &zonename, DNSPacket *packet) { return false; }
bool AuthLua4::axfrfilter(const ComboAddress& remote, const DNSName& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out) { return false; }
AuthLua4::~AuthLua4() { }

#else

#undef L
#include "ext/luawrapper/include/LuaContext.hpp"

void AuthLua4::postPrepareContext() {
  stubParseResolveConf();

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
}

void AuthLua4::postLoad() {
  d_update_policy = d_lw->readVariable<boost::optional<luacall_update_policy_t>>("updatepolicy").get_value_or(0);
  d_axfr_filter = d_lw->readVariable<boost::optional<luacall_axfr_filter_t>>("axfrfilter").get_value_or(0);

}

bool AuthLua4::axfrfilter(const ComboAddress& remote, const DNSName& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out) {
  luacall_axfr_filter_t::result_type ret;
  int rcode;

  if (d_axfr_filter == NULL) return false;

  ret = d_axfr_filter(remote, zone, in);
  rcode = std::get<0>(ret);
  if (rcode < 0)
    return false;
  else if (rcode == 1)
    out.push_back(in);
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
