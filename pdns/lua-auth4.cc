#include "config.h"
#if defined(HAVE_LUA)
#include "ext/luawrapper/include/LuaContext.hpp"
#endif
#include "lua-auth4.hh"
#include "stubresolver.hh"
#include <fstream>
#include "logger.hh"
#include "dnsparser.hh"
#include "namespaces.hh"
#include "ednssubnet.hh"
#include <unordered_set>
#include "sstuff.hh"
#include <thread>
#include <mutex>

#include "ueberbackend.hh"

AuthLua4::AuthLua4() { prepareContext(); }

#if !defined(HAVE_LUA)

bool AuthLua4::updatePolicy(const DNSName &qname, QType qtype, const DNSName &zonename, const DNSPacket& packet) { return false; }
bool AuthLua4::axfrfilter(const ComboAddress& remote, const DNSName& zone, const DNSResourceRecord& in, vector<DNSResourceRecord>& out) { return false; }
LuaContext* AuthLua4::getLua() { return nullptr; }
std::unique_ptr<DNSPacket> AuthLua4::prequery(const DNSPacket& q) { return nullptr; }

AuthLua4::~AuthLua4() { }

void AuthLua4::postPrepareContext()
{
}

void AuthLua4::postLoad()
{
}

#else

LuaContext* AuthLua4::getLua()
{
  return d_lw.get();
}

void AuthLua4::postPrepareContext() {
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

/* DNSPacket */
  d_lw->writeFunction("newDNSPacket", [](bool isQuery) { return std::make_shared<DNSPacket>(isQuery); });
  d_lw->writeFunction("dupDNSPacket", [](const std::shared_ptr<DNSPacket> &orig) { return std::make_shared<DNSPacket>(*orig); });
  d_lw->registerFunction<DNSPacket, int(const char *, size_t)>("noparse", [](DNSPacket &p, const char *mesg, size_t len){ return p.noparse(mesg, len); });
  d_lw->registerFunction<DNSPacket, int(const char *, size_t)>("parse", [](DNSPacket &p, const char *mesg, size_t len){ return p.parse(mesg, len); });
  d_lw->registerFunction<DNSPacket, const std::string()>("getString", [](DNSPacket &p) { return p.getString(); });
  d_lw->registerFunction<DNSPacket, void(const ComboAddress&)>("setRemote", [](DNSPacket &p, const ComboAddress &ca) { p.setRemote(&ca); });
  d_lw->registerFunction<DNSPacket, ComboAddress()>("getRemote", [](DNSPacket &p) { return p.getRemote(); });
  d_lw->registerFunction<DNSPacket, Netmask()>("getRealRemote", [](DNSPacket &p) { return p.getRealRemote(); });
  d_lw->registerFunction<DNSPacket, ComboAddress()>("getLocal", [](DNSPacket &p) { return p.getLocal(); });
  d_lw->registerFunction<DNSPacket, unsigned int()>("getRemotePort", [](DNSPacket &p) { return p.getRemotePort(); });
  d_lw->registerFunction<DNSPacket, std::tuple<const std::string, unsigned int>()>("getQuestion", [](DNSPacket &p) { return std::make_tuple(p.qdomain.toString(), static_cast<unsigned int>(p.qtype.getCode())); });
  d_lw->registerFunction<DNSPacket, void(bool)>("setA", [](DNSPacket &p, bool a) { return p.setA(a); });
  d_lw->registerFunction<DNSPacket, void(unsigned int)>("setID", [](DNSPacket &p, unsigned int id) { return p.setID(static_cast<uint16_t>(id)); });
  d_lw->registerFunction<DNSPacket, void(bool)>("setRA", [](DNSPacket &p, bool ra) { return p.setRA(ra); });
  d_lw->registerFunction<DNSPacket, void(bool)>("setRD", [](DNSPacket &p, bool rd) { return p.setRD(rd); });
  d_lw->registerFunction<DNSPacket, void(bool)>("setAnswer", [](DNSPacket &p, bool answer) { return p.setAnswer(answer); });
  d_lw->registerFunction<DNSPacket, void(unsigned int)>("setOpCode", [](DNSPacket &p, unsigned int opcode) { return p.setOpcode(static_cast<uint16_t>(opcode)); });
  d_lw->registerFunction<DNSPacket, void(int)>("setRcode", [](DNSPacket &p, int rcode) { return p.setRcode(rcode); });
  d_lw->registerFunction<DNSPacket, void()>("clearRecords",[](DNSPacket &p){p.clearRecords();});
  d_lw->registerFunction<DNSPacket, void(DNSRecord&, bool)>("addRecord", [](DNSPacket &p, DNSRecord &dr, bool auth) { DNSZoneRecord dzr; dzr.dr = dr; dzr.auth = auth; p.addRecord(dzr); });
  d_lw->registerFunction<DNSPacket, void(const vector<pair<unsigned int, DNSRecord> >&)>("addRecords", [](DNSPacket &p, const vector<pair<unsigned int, DNSRecord> >& records){ for(const auto &dr: records){ DNSZoneRecord dzr; dzr.dr = std::get<1>(dr); dzr.auth = true; p.addRecord(dzr); }});
  d_lw->registerFunction<DNSPacket, void(unsigned int, const DNSName&, const std::string&)>("setQuestion", [](DNSPacket &p, unsigned int opcode, const DNSName &name, const string &type){ QType qtype; qtype = type; p.setQuestion(static_cast<int>(opcode), name, static_cast<int>(qtype.getCode())); });
  d_lw->registerFunction<DNSPacket, bool()>("isEmpty", [](DNSPacket &p){return p.isEmpty();});
  d_lw->registerFunction<DNSPacket, std::shared_ptr<DNSPacket>()>("replyPacket",[](DNSPacket& p){ return p.replyPacket();});
  d_lw->registerFunction<DNSPacket, bool()>("hasEDNSSubnet", [](DNSPacket &p){return p.hasEDNSSubnet();});
  d_lw->registerFunction<DNSPacket, bool()>("hasEDNS",[](DNSPacket &p){return p.hasEDNS();});
  d_lw->registerFunction<DNSPacket, unsigned int()>("getEDNSVersion",[](DNSPacket &p){return p.getEDNSVersion();});
  d_lw->registerFunction<DNSPacket, void(unsigned int)>("setEDNSRcode",[](DNSPacket &p, unsigned int extRCode){p.setEDNSRcode(static_cast<uint16_t>(extRCode));});
  d_lw->registerFunction<DNSPacket, unsigned int()>("getEDNSRcode",[](DNSPacket &p){return p.getEDNSRCode();});
  d_lw->registerFunction<DNSPacket, DNSName()>("getTSIGKeyname",[](DNSPacket &p){ return p.getTSIGKeyname();});
  d_lw->registerFunction<DNSPacket, std::unordered_map<unsigned int, DNSRecord>()>("getRRS", [](DNSPacket &p){ std::unordered_map<unsigned int, DNSRecord> ret; unsigned int i = 0; for(const auto &rec: p.getRRS()) { ret.insert({i++, rec.dr}); } return ret;});
  d_lw->registerMember<DNSPacket, DNSName>("qdomain", [](const DNSPacket &p) -> DNSName { return p.qdomain; }, [](DNSPacket &p, const DNSName& name) { p.qdomain = name; });
  d_lw->registerMember<DNSPacket, DNSName>("qdomainwild", [](const DNSPacket &p) -> DNSName { return p.qdomainwild; }, [](DNSPacket &p, const DNSName& name) { p.qdomainwild = name; });
  d_lw->registerMember<DNSPacket, DNSName>("qdomainzone", [](const DNSPacket &p) -> DNSName { return p.qdomainzone; }, [](DNSPacket &p, const DNSName& name) { p.qdomainzone = name; });

  d_lw->registerMember<DNSPacket, std::string>("d_peer_principal", [](const DNSPacket &p) -> std::string { return p.d_peer_principal; }, [](DNSPacket &p, const std::string &princ) { p.d_peer_principal = princ; });
  d_lw->registerMember<DNSPacket, const std::string>("qtype", [](const DNSPacket &p) ->  const std::string { return p.qtype.getName(); }, [](DNSPacket &p, const std::string &type) { p.qtype = type; });
/* End of DNSPacket */


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
  d_prequery = d_lw->readVariable<boost::optional<luacall_prequery_t>>("prequery").get_value_or(0);
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


bool AuthLua4::updatePolicy(const DNSName &qname, QType qtype, const DNSName &zonename, const DNSPacket& packet) {
  // default decision is all goes
  if (d_update_policy == nullptr) return true;

  UpdatePolicyQuery upq;
  upq.qname = qname;
  upq.qtype = qtype.getCode();
  upq.zonename = zonename;
  upq.local = packet.getLocal();
  upq.remote = packet.getRemote();
  upq.realRemote = packet.getRealRemote();
  upq.tsigName = packet.getTSIGKeyname();
  upq.peerPrincipal = packet.d_peer_principal;

  return d_update_policy(upq);
}

std::unique_ptr<DNSPacket> AuthLua4::prequery(const DNSPacket& q) {
  if (d_prequery == nullptr) return nullptr;

  auto r = q.replyPacket();
  if (d_prequery(r.get()))
    return r;

  return nullptr;
}

AuthLua4::~AuthLua4() { }


#endif
