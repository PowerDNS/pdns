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
#include "lua-recursor4.hh"
#include <fstream>
#include "logger.hh"
#include "dnsparser.hh"
#include "syncres.hh"
#include "resolver.hh"
#include "namespaces.hh"
#include "rec_channel.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "filterpo.hh"
#include "rec-snmp.hh"
#include <unordered_set>

RecursorLua4::RecursorLua4() { prepareContext(); }

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

std::vector<std::pair<int, ProxyProtocolValue>> RecursorLua4::DNSQuestion::getProxyProtocolValues() const
{
  std::vector<std::pair<int, ProxyProtocolValue>> result;
  if (proxyProtocolValues) {
    result.reserve(proxyProtocolValues->size());

    int idx = 1;
    for (const auto& value: *proxyProtocolValues) {
      result.push_back({ idx++, value });
    }
  }

  return result;
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
  dr.d_content = DNSRecordContent::mastermake(type, QClass::IN, content);
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

void RecursorLua4::postPrepareContext()
{
  d_lw->registerMember<const DNSName (DNSQuestion::*)>("qname", [](const DNSQuestion& dq) -> const DNSName& { return dq.qname; }, [](DNSQuestion& dq, const DNSName& newName) { (void) newName; });
  d_lw->registerMember<uint16_t (DNSQuestion::*)>("qtype", [](const DNSQuestion& dq) -> uint16_t { return dq.qtype; }, [](DNSQuestion& dq, uint16_t newType) { (void) newType; });
  d_lw->registerMember<bool (DNSQuestion::*)>("isTcp", [](const DNSQuestion& dq) -> bool { return dq.isTcp; }, [](DNSQuestion& dq, bool newTcp) { (void) newTcp; });
  d_lw->registerMember<const ComboAddress (DNSQuestion::*)>("localaddr", [](const DNSQuestion& dq) -> const ComboAddress& { return dq.local; }, [](DNSQuestion& dq, const ComboAddress& newLocal) { (void) newLocal; });
  d_lw->registerMember<const ComboAddress (DNSQuestion::*)>("remoteaddr", [](const DNSQuestion& dq) -> const ComboAddress& { return dq.remote; }, [](DNSQuestion& dq, const ComboAddress& newRemote) { (void) newRemote; });
  d_lw->registerMember<vState (DNSQuestion::*)>("validationState", [](const DNSQuestion& dq) -> vState { return dq.validationState; }, [](DNSQuestion& dq, vState newState) { (void) newState; });

  d_lw->registerMember<bool (DNSQuestion::*)>("variable", [](const DNSQuestion& dq) -> bool { return dq.variable; }, [](DNSQuestion& dq, bool newVariable) { dq.variable = newVariable; });
  d_lw->registerMember<bool (DNSQuestion::*)>("wantsRPZ", [](const DNSQuestion& dq) -> bool { return dq.wantsRPZ; }, [](DNSQuestion& dq, bool newWantsRPZ) { dq.wantsRPZ = newWantsRPZ; });
  d_lw->registerMember<bool (DNSQuestion::*)>("logResponse", [](const DNSQuestion& dq) -> bool { return dq.logResponse; }, [](DNSQuestion& dq, bool newLogResponse) { dq.logResponse = newLogResponse; });

  d_lw->registerMember("rcode", &DNSQuestion::rcode);
  d_lw->registerMember("tag", &DNSQuestion::tag);
  d_lw->registerMember("requestorId", &DNSQuestion::requestorId);
  d_lw->registerMember("deviceId", &DNSQuestion::deviceId);
  d_lw->registerMember("deviceName", &DNSQuestion::deviceName);
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
      return pol.getName();
    },
    [](DNSFilterEngine::Policy& pol, const std::string& name) {
      pol.setName(name);
    });
  d_lw->registerMember("policyKind", &DNSFilterEngine::Policy::d_kind);
  d_lw->registerMember("policyType", &DNSFilterEngine::Policy::d_type);
  d_lw->registerMember("policyTTL", &DNSFilterEngine::Policy::d_ttl);
  d_lw->registerMember("policyTrigger", &DNSFilterEngine::Policy::d_trigger);
  d_lw->registerMember("policyHit", &DNSFilterEngine::Policy::d_hit);
  d_lw->registerMember<DNSFilterEngine::Policy, std::string>("policyCustom",
    [](const DNSFilterEngine::Policy& pol) -> std::string {
      std::string result;
      if (pol.d_kind != DNSFilterEngine::PolicyKind::Custom) {
        return result;
      }

      for (const auto& dr : pol.d_custom) {
        if (!result.empty()) {
          result += "\n";
        }
        result += dr->getZoneRepresentation();
      }

      return result;
    },
    [](DNSFilterEngine::Policy& pol, const std::string& content) {
      // Only CNAMES for now, when we ever add a d_custom_type, there will be pain
      pol.d_custom.clear();
      pol.d_custom.push_back(DNSRecordContent::mastermake(QType::CNAME, QClass::IN, content));
    }
  );
  d_lw->registerFunction("getDH", &DNSQuestion::getDH);
  d_lw->registerFunction("getEDNSOptions", &DNSQuestion::getEDNSOptions);
  d_lw->registerFunction("getEDNSOption", &DNSQuestion::getEDNSOption);
  d_lw->registerFunction("getEDNSSubnet", &DNSQuestion::getEDNSSubnet);
  d_lw->registerFunction("getProxyProtocolValues", &DNSQuestion::getProxyProtocolValues);
  d_lw->registerFunction("getEDNSFlags", &DNSQuestion::getEDNSFlags);
  d_lw->registerFunction("getEDNSFlag", &DNSQuestion::getEDNSFlag);
  d_lw->registerMember("name", &DNSRecord::d_name);
  d_lw->registerMember("type", &DNSRecord::d_type);
  d_lw->registerMember("ttl", &DNSRecord::d_ttl);
  d_lw->registerMember("place", &DNSRecord::d_place);

  d_lw->registerMember("size", &EDNSOptionViewValue::size);
  d_lw->registerFunction<std::string(EDNSOptionViewValue::*)()>("getContent", [](const EDNSOptionViewValue& value) { return std::string(value.content, value.size); });
  d_lw->registerFunction<size_t(EDNSOptionView::*)()>("count", [](const EDNSOptionView& option) { return option.values.size(); });
  d_lw->registerFunction<std::vector<string>(EDNSOptionView::*)()>("getValues", [] (const EDNSOptionView& option) {
      std::vector<string> values;
      for (const auto& value : option.values) {
        values.push_back(std::string(value.content, value.size));
      }
      return values;
    });

  /* pre 4.2 API compatibility, when we had only one value for a given EDNS option */
  d_lw->registerMember<uint16_t(EDNSOptionView::*)>("size", [](const EDNSOptionView& option) -> uint16_t {
      uint16_t result = 0;

      if (!option.values.empty()) {
        result = option.values.at(0).size;
      }
      return result;
    },
    [](EDNSOptionView& option, uint16_t newSize) { (void) newSize; });
  d_lw->registerFunction<std::string(EDNSOptionView::*)()>("getContent", [](const EDNSOptionView& option) {
      if (option.values.empty()) {
        return std::string();
      }
      return std::string(option.values.at(0).content, option.values.at(0).size); });

  d_lw->registerFunction<string(DNSRecord::*)()>("getContent", [](const DNSRecord& dr) { return dr.d_content->getZoneRepresentation(); });
  d_lw->registerFunction<boost::optional<ComboAddress>(DNSRecord::*)()>("getCA", [](const DNSRecord& dr) { 
      boost::optional<ComboAddress> ret;

      if(auto rec = std::dynamic_pointer_cast<ARecordContent>(dr.d_content))
        ret=rec->getCA(53);
      else if(auto aaaarec = std::dynamic_pointer_cast<AAAARecordContent>(dr.d_content))
        ret=aaaarec->getCA(53);
      return ret;
    });

  d_lw->registerFunction<const ProxyProtocolValue, std::string()>("getContent", [](const ProxyProtocolValue& value) { return value.content; });
  d_lw->registerFunction<const ProxyProtocolValue, uint8_t()>("getType", [](const ProxyProtocolValue& value) { return value.type; });

  d_lw->registerFunction<void(DNSRecord::*)(const std::string&)>("changeContent", [](DNSRecord& dr, const std::string& newContent) { dr.d_content = DNSRecordContent::mastermake(dr.d_type, QClass::IN, newContent); });
  d_lw->registerFunction("addAnswer", &DNSQuestion::addAnswer);
  d_lw->registerFunction("addRecord", &DNSQuestion::addRecord);
  d_lw->registerFunction("getRecords", &DNSQuestion::getRecords);
  d_lw->registerFunction("setRecords", &DNSQuestion::setRecords);

  d_lw->registerFunction<void(DNSQuestion::*)(const std::string&)>("addPolicyTag", [](DNSQuestion& dq, const std::string& tag) { if (dq.policyTags) { dq.policyTags->insert(tag); } });
  d_lw->registerFunction<void(DNSQuestion::*)(const std::vector<std::pair<int, std::string> >&)>("setPolicyTags", [](DNSQuestion& dq, const std::vector<std::pair<int, std::string> >& tags) {
      if (dq.policyTags) {
        dq.policyTags->clear();
        dq.policyTags->reserve(tags.size());
        for (const auto& tag : tags) {
          dq.policyTags->insert(tag.second);
        }
      }
    });
  d_lw->registerFunction<std::vector<std::pair<int, std::string> >(DNSQuestion::*)()>("getPolicyTags", [](const DNSQuestion& dq) {
      std::vector<std::pair<int, std::string> > ret;
      if (dq.policyTags) {
        int count = 1;
        ret.reserve(dq.policyTags->size());
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
        g_log <<Logger::Error<<e.what()<<endl;
      }
    }
  );

  d_lw->registerFunction("check",(bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);
  d_lw->registerFunction("toString",(string (SuffixMatchNode::*)() const) &SuffixMatchNode::toString);

  d_pd.push_back({"policykinds", in_t {
    {"NoAction", (int)DNSFilterEngine::PolicyKind::NoAction},
    {"Drop",     (int)DNSFilterEngine::PolicyKind::Drop    },
    {"NXDOMAIN", (int)DNSFilterEngine::PolicyKind::NXDOMAIN},
    {"NODATA",   (int)DNSFilterEngine::PolicyKind::NODATA  },
    {"Truncate", (int)DNSFilterEngine::PolicyKind::Truncate},
    {"Custom",   (int)DNSFilterEngine::PolicyKind::Custom  }
    }});

  d_pd.push_back({"policytypes", in_t {
    {"None",       (int)DNSFilterEngine::PolicyType::None       },
    {"QName",      (int)DNSFilterEngine::PolicyType::QName      },
    {"ClientIP",   (int)DNSFilterEngine::PolicyType::ClientIP   },
    {"ResponseIP", (int)DNSFilterEngine::PolicyType::ResponseIP },
    {"NSDName",    (int)DNSFilterEngine::PolicyType::NSDName    },
    {"NSIP",       (int)DNSFilterEngine::PolicyType::NSIP       }
    }});

  for(const auto& n : QType::names)
    d_pd.push_back({n.first, n.second});

  d_pd.push_back({"validationstates", in_t{
        {"Indeterminate", static_cast<unsigned int>(vState::Indeterminate) },
        {"Bogus", static_cast<unsigned int>(vState::Bogus) },
        {"Insecure", static_cast<unsigned int>(vState::Insecure) },
        {"Secure", static_cast<unsigned int>(vState::Secure) },
  }});

  d_pd.push_back({"now", &g_now});

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

  d_lw->registerMember<const DNSName (PolicyEvent::*)>("qname", [](const PolicyEvent& event) -> const DNSName& { return event.qname; }, [](PolicyEvent& event, const DNSName& newName) { (void) newName; });
  d_lw->registerMember<uint16_t (PolicyEvent::*)>("qtype", [](const PolicyEvent& event) -> uint16_t { return event.qtype.getCode(); }, [](PolicyEvent& event, uint16_t newType) { (void) newType; });
  d_lw->registerMember<bool (PolicyEvent::*)>("isTcp", [](const PolicyEvent& event) -> bool { return event.isTcp; }, [](PolicyEvent& event, bool newTcp) { (void) newTcp; });
  d_lw->registerMember<const ComboAddress (PolicyEvent::*)>("remote", [](const PolicyEvent& event) -> const ComboAddress& { return event.remote; }, [](PolicyEvent& event, const ComboAddress& newRemote) { (void) newRemote; });
  d_lw->registerMember("appliedPolicy", &PolicyEvent::appliedPolicy);
  d_lw->registerFunction<void(PolicyEvent::*)(const std::string&)>("addPolicyTag", [](PolicyEvent& event, const std::string& tag) { if (event.policyTags) { event.policyTags->insert(tag); } });
  d_lw->registerFunction<void(PolicyEvent::*)(const std::vector<std::pair<int, std::string> >&)>("setPolicyTags", [](PolicyEvent& event, const std::vector<std::pair<int, std::string> >& tags) {
      if (event.policyTags) {
        event.policyTags->clear();
        event.policyTags->reserve(tags.size());
        for (const auto& tag : tags) {
          event.policyTags->insert(tag.second);
        }
      }
    });
  d_lw->registerFunction<std::vector<std::pair<int, std::string> >(PolicyEvent::*)()>("getPolicyTags", [](const PolicyEvent& event) {
      std::vector<std::pair<int, std::string> > ret;
      if (event.policyTags) {
        int count = 1;
        ret.reserve(event.policyTags->size());
        for (const auto& tag : *event.policyTags) {
          ret.push_back({count++, tag});
        }
      }
      return ret;
    });
  d_lw->registerFunction<void(PolicyEvent::*)(const std::string&)>("discardPolicy", [](PolicyEvent& event, const std::string& policy) {
    if (event.discardedPolicies) {
      (*event.discardedPolicies)[policy] = true;
    }
  });

  d_lw->writeFunction("cacheLookup", [](DNSName& qname, uint16_t qtype) {
    vector<DNSRecord> res;
    auto ret = g_recCache->get(g_now.tv_sec, qname, QType(qtype), true, &res, ComboAddress("127.0.0.1"));

    std::vector<std::pair<int, std::string> > out;
    int n = 0;
    for(const auto &i : res) {
      out.push_back({n++, i.d_content->getZoneRepresentation()});
    }
    cout<<"res.length()="<<res.size()<<endl;
    return out;
  });
}

void RecursorLua4::postLoad() {
  d_prerpz = d_lw->readVariable<boost::optional<luacall_t>>("prerpz").get_value_or(0);
  d_preresolve = d_lw->readVariable<boost::optional<luacall_t>>("preresolve").get_value_or(0);
  d_nodata = d_lw->readVariable<boost::optional<luacall_t>>("nodata").get_value_or(0);
  d_nxdomain = d_lw->readVariable<boost::optional<luacall_t>>("nxdomain").get_value_or(0);
  d_postresolve = d_lw->readVariable<boost::optional<luacall_t>>("postresolve").get_value_or(0);
  d_preoutquery = d_lw->readVariable<boost::optional<luacall_t>>("preoutquery").get_value_or(0);
  d_maintenance = d_lw->readVariable<boost::optional<luamaintenance_t>>("maintenance").get_value_or(0);

  d_ipfilter = d_lw->readVariable<boost::optional<ipfilter_t>>("ipfilter").get_value_or(0);
  d_gettag = d_lw->readVariable<boost::optional<gettag_t>>("gettag").get_value_or(0);
  d_gettag_ffi = d_lw->readVariable<boost::optional<gettag_ffi_t>>("gettag_ffi").get_value_or(0);

  d_policyHitEventFilter = d_lw->readVariable<boost::optional<policyEventFilter_t>>("policyEventFilter").get_value_or(0);
}

void RecursorLua4::getFeatures(Features & features) {
  // Add key-values pairs below.
  // Make sure you add string values explicitly converted to string.
  // e.g. features.push_back(make_pair("somekey", string("stringvalue"));
  // Both int and double end up as a lua number type.
   features.push_back(make_pair("PR8001_devicename", true));
}

void RecursorLua4::maintenance() const
{
  if (d_maintenance) {
    d_maintenance();
  }
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
  bool logQuery = false;
  RecursorLua4::DNSQuestion dq(ns, requestor, query, qtype.getCode(), isTcp, variableAnswer, wantsRPZ, logQuery);
  dq.currentRecords = &res;

  return genhook(d_preoutquery, dq, ret);
}

bool RecursorLua4::ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader& dh) const
{
  if(d_ipfilter)
    return d_ipfilter(remote, local, dh);
  return false; // don't block
}

bool RecursorLua4::policyHitEventFilter(const ComboAddress& remote, const DNSName& qname, const QType& qtype, bool tcp, DNSFilterEngine::Policy& policy, std::unordered_set<std::string>& tags, std::unordered_map<std::string, bool>& dicardedPolicies) const
{
  if (!d_policyHitEventFilter) {
    return false;
  }

  PolicyEvent event(remote, qname, qtype, tcp);
  event.appliedPolicy = &policy;
  event.policyTags = &tags;
  event.discardedPolicies = &dicardedPolicies;

  if (d_policyHitEventFilter(event)) {
    return true;
  }
  else {
    return false;
  }
}

unsigned int RecursorLua4::gettag(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& qname, uint16_t qtype, std::unordered_set<std::string>* policyTags, LuaContext::LuaObject& data, const EDNSOptionViewMap& ednsOptions, bool tcp, std::string& requestorId, std::string& deviceId, std::string& deviceName, std::string& routingTag, const std::vector<ProxyProtocolValue>& proxyProtocolValues) const
{
  if(d_gettag) {
    std::vector<std::pair<int, const ProxyProtocolValue*>> proxyProtocolValuesMap;
    proxyProtocolValuesMap.reserve(proxyProtocolValues.size());
    int num = 1;
    for (const auto& value : proxyProtocolValues) {
      proxyProtocolValuesMap.emplace_back(num++, &value);
    }

    auto ret = d_gettag(remote, ednssubnet, local, qname, qtype, ednsOptions, tcp, proxyProtocolValuesMap);

    if (policyTags) {
      const auto& tags = std::get<1>(ret);
      if (tags) {
        policyTags->reserve(policyTags->size() + tags->size());
        for (const auto& tag : *tags) {
          policyTags->insert(tag.second);
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

    const auto deviceNameret = std::get<5>(ret);
    if (deviceNameret) {
      deviceName = *deviceNameret;
    }

    const auto routingTarget = std::get<6>(ret);
    if (routingTarget) {
      routingTag = *routingTarget;
    }

    return std::get<0>(ret);
  }
  return 0;
}

struct pdns_ffi_param
{
public:
  pdns_ffi_param(const DNSName& qname_, uint16_t qtype_, const ComboAddress& local_, const ComboAddress& remote_, const Netmask& ednssubnet_, std::unordered_set<std::string>& policyTags_, std::vector<DNSRecord>& records_, const EDNSOptionViewMap& ednsOptions_, const std::vector<ProxyProtocolValue>& proxyProtocolValues_, std::string& requestorId_, std::string& deviceId_, std::string& deviceName_, std::string& routingTag_, boost::optional<int>& rcode_, uint32_t& ttlCap_, bool& variable_, bool tcp_, bool& logQuery_, bool& logResponse_, bool& followCNAMERecords_): qname(qname_), local(local_), remote(remote_), ednssubnet(ednssubnet_), policyTags(policyTags_), records(records_), ednsOptions(ednsOptions_), proxyProtocolValues(proxyProtocolValues_), requestorId(requestorId_), deviceId(deviceId_), deviceName(deviceName_), routingTag(routingTag_), rcode(rcode_), ttlCap(ttlCap_), variable(variable_), logQuery(logQuery_), logResponse(logResponse_), followCNAMERecords(followCNAMERecords_), qtype(qtype_), tcp(tcp_)
  {
  }

  std::unique_ptr<std::string> qnameStr{nullptr};
  std::unique_ptr<std::string> localStr{nullptr};
  std::unique_ptr<std::string> remoteStr{nullptr};
  std::unique_ptr<std::string> ednssubnetStr{nullptr};
  std::vector<pdns_ednsoption_t> ednsOptionsVect;
  std::vector<pdns_proxyprotocol_value_t> proxyProtocolValuesVect;

  const DNSName& qname;
  const ComboAddress& local;
  const ComboAddress& remote;
  const Netmask& ednssubnet;
  std::unordered_set<std::string>& policyTags;
  std::vector<DNSRecord>& records;
  const EDNSOptionViewMap& ednsOptions;
  const std::vector<ProxyProtocolValue>& proxyProtocolValues;
  std::string& requestorId;
  std::string& deviceId;
  std::string& deviceName;
  std::string& routingTag;
  boost::optional<int>& rcode;
  uint32_t& ttlCap;
  bool& variable;
  bool& logQuery;
  bool& logResponse;
  bool& followCNAMERecords;

  unsigned int tag{0};
  uint16_t qtype;
  bool tcp;
};

unsigned int RecursorLua4::gettag_ffi(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& qname, uint16_t qtype, std::unordered_set<std::string>* policyTags, std::vector<DNSRecord>& records, LuaContext::LuaObject& data, const EDNSOptionViewMap& ednsOptions, bool tcp, const std::vector<ProxyProtocolValue>& proxyProtocolValues, std::string& requestorId, std::string& deviceId, std::string& deviceName, std::string& routingTag, boost::optional<int>& rcode, uint32_t& ttlCap, bool& variable, bool& logQuery, bool& logResponse, bool& followCNAMERecords) const
{
  if (d_gettag_ffi) {
    pdns_ffi_param_t param(qname, qtype, local, remote, ednssubnet, *policyTags, records, ednsOptions, proxyProtocolValues, requestorId, deviceId, deviceName, routingTag, rcode, ttlCap, variable, tcp, logQuery, logResponse, followCNAMERecords);

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
        ret=getFakeAAAARecords(dq.followupName, ComboAddress(dq.followupPrefix), dq.records);
      }
      else if(dq.followupFunction=="getFakePTRRecords") {
        ret=getFakePTRRecords(dq.followupName, dq.records);
      }
      else if(dq.followupFunction=="udpQueryResponse") {
        dq.udpAnswer = GenUDPQueryResponse(dq.udpQueryDest, dq.udpQuery);
        auto cbFunc = d_lw->readVariable<boost::optional<luacall_t>>(dq.udpCallback).get_value_or(0);
        if(!cbFunc) {
          g_log<<Logger::Error<<"Attempted callback for Lua UDP Query/Response which could not be found"<<endl;
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

static void fill_edns_option(const EDNSOptionViewValue& value, pdns_ednsoption_t& option)
{
  option.len = value.size;
  option.data = nullptr;

  if (value.size > 0) {
    option.data = value.content;
  }
}

size_t pdns_ffi_param_get_edns_options(pdns_ffi_param_t* ref, const pdns_ednsoption_t** out)
{
  if (ref->ednsOptions.empty()) {
    return 0;
  }

  size_t totalCount = 0;
  for (const auto& option : ref->ednsOptions) {
    totalCount += option.second.values.size();
  }

  ref->ednsOptionsVect.resize(totalCount);

  size_t pos = 0;
  for (const auto& option : ref->ednsOptions) {
    for (const auto& entry : option.second.values) {
      fill_edns_option(entry, ref->ednsOptionsVect.at(pos));
      ref->ednsOptionsVect.at(pos).optionCode = option.first;
      pos++;
    }
  }

  *out = ref->ednsOptionsVect.data();

  return totalCount;
}

size_t pdns_ffi_param_get_edns_options_by_code(pdns_ffi_param_t* ref, uint16_t optionCode, const pdns_ednsoption_t** out)
{
  const auto& it = ref->ednsOptions.find(optionCode);
  if (it == ref->ednsOptions.cend() || it->second.values.empty()) {
    return 0;
  }

  ref->ednsOptionsVect.resize(it->second.values.size());

  size_t pos = 0;
  for (const auto& entry : it->second.values) {
    fill_edns_option(entry, ref->ednsOptionsVect.at(pos));
    ref->ednsOptionsVect.at(pos).optionCode = optionCode;
    pos++;
  }

  *out = ref->ednsOptionsVect.data();

  return pos;
}

size_t pdns_ffi_param_get_proxy_protocol_values(pdns_ffi_param_t* ref, const pdns_proxyprotocol_value_t** out)
{
  if (ref->proxyProtocolValues.empty()) {
    return 0;
  }

  ref->proxyProtocolValuesVect.resize(ref->proxyProtocolValues.size());

  size_t pos = 0;
  for (const auto& value : ref->proxyProtocolValues) {
    auto& dest = ref->proxyProtocolValuesVect.at(pos);
    dest.type = value.type;
    dest.len = value.content.size();
    if (dest.len > 0) {
      dest.data = value.content.data();
    }
    pos++;
  }

  *out = ref->proxyProtocolValuesVect.data();

  return ref->proxyProtocolValuesVect.size();
}

void pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag)
{
  ref->tag = tag;
}

void pdns_ffi_param_add_policytag(pdns_ffi_param_t *ref, const char* name)
{
  ref->policyTags.insert(std::string(name));
}

void pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name)
{
  ref->requestorId = std::string(name);
}

void pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name)
{
  ref->deviceName = std::string(name);
}

void pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name)
{
  ref->deviceId = std::string(reinterpret_cast<const char*>(name), len);
}

void pdns_ffi_param_set_routingtag(pdns_ffi_param_t* ref, const char* rtag)
{
  ref->routingTag = std::string(rtag);
}

void pdns_ffi_param_set_variable(pdns_ffi_param_t* ref, bool variable)
{
  ref->variable = variable;
}

void pdns_ffi_param_set_ttl_cap(pdns_ffi_param_t* ref, uint32_t ttl)
{
  ref->ttlCap = ttl;
}

void pdns_ffi_param_set_log_query(pdns_ffi_param_t* ref, bool logQuery)
{
  ref->logQuery = logQuery;
}

void pdns_ffi_param_set_log_response(pdns_ffi_param_t* ref, bool logResponse)
{
  ref->logResponse = logResponse;
}

void pdns_ffi_param_set_rcode(pdns_ffi_param_t* ref, int rcode)
{
  ref->rcode = rcode;
}

void pdns_ffi_param_set_follow_cname_records(pdns_ffi_param_t* ref, bool follow)
{
  ref->followCNAMERecords = follow;
}

bool pdns_ffi_param_add_record(pdns_ffi_param_t *ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentSize, pdns_record_place_t place)
{
  try {
    DNSRecord dr;
    dr.d_name = name != nullptr ? DNSName(name) : ref->qname;
    dr.d_ttl = ttl;
    dr.d_type = type;
    dr.d_class = QClass::IN;
    dr.d_place = DNSResourceRecord::Place(place);
    dr.d_content = DNSRecordContent::mastermake(type, QClass::IN, std::string(content, contentSize));
    ref->records.push_back(std::move(dr));

    return true;
  }
  catch (const std::exception& e) {
    g_log<<Logger::Error<<"Error attempting to add a record from Lua via pdns_ffi_param_add_record(): "<<e.what()<<endl;
    return false;
  }
}
