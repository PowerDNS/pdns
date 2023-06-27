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
#include "namespaces.hh"
#include "rec_channel.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "filterpo.hh"
#include "rec-snmp.hh"
#include <unordered_set>
#include <utility>
#include "rec-main.hh"

RecursorLua4::RecursorLua4() { prepareContext(); }

boost::optional<dnsheader> RecursorLua4::DNSQuestion::getDH() const
{
  if (dh != nullptr) {
    return *dh;
  }
  return {};
}

vector<string> RecursorLua4::DNSQuestion::getEDNSFlags() const
{
  vector<string> ret;
  if (ednsFlags != nullptr) {
    if ((*ednsFlags & EDNSOpts::DNSSECOK) != 0) {
      ret.emplace_back("DO");
    }
  }
  return ret;
}

bool RecursorLua4::DNSQuestion::getEDNSFlag(const string& flag) const
{
  if (ednsFlags != nullptr) {
    if (flag == "DO" && (*ednsFlags & EDNSOpts::DNSSECOK) != 0) {
      return true;
    }
  }
  return false;
}

vector<pair<uint16_t, string>> RecursorLua4::DNSQuestion::getEDNSOptions() const
{
  if (ednsOptions != nullptr) {
    return *ednsOptions;
  }
  return {};
}

boost::optional<string> RecursorLua4::DNSQuestion::getEDNSOption(uint16_t code) const
{
  if (ednsOptions != nullptr) {
    for (const auto& option : *ednsOptions) {
      if (option.first == code) {
        return option.second;
      }
    }
  }
  return {};
}

boost::optional<Netmask> RecursorLua4::DNSQuestion::getEDNSSubnet() const
{
  if (ednsOptions != nullptr) {
    for (const auto& option : *ednsOptions) {
      if (option.first == EDNSOptionCode::ECS) {
        EDNSSubnetOpts eso;
        if (getEDNSSubnetOptsFromString(option.second, &eso)) {
          return eso.source;
        }
        break;
      }
    }
  }
  return {};
}

std::vector<std::pair<int, ProxyProtocolValue>> RecursorLua4::DNSQuestion::getProxyProtocolValues() const
{
  std::vector<std::pair<int, ProxyProtocolValue>> result;
  if (proxyProtocolValues != nullptr) {
    result.reserve(proxyProtocolValues->size());

    int idx = 1;
    for (const auto& value : *proxyProtocolValues) {
      result.emplace_back(idx++, value);
    }
  }

  return result;
}

vector<pair<int, DNSRecord>> RecursorLua4::DNSQuestion::getRecords() const
{
  vector<pair<int, DNSRecord>> ret;
  int num = 1;
  ret.reserve(records.size());
  for (const auto& record : records) {
    ret.emplace_back(num++, record);
  }
  return ret;
}
void RecursorLua4::DNSQuestion::setRecords(const vector<pair<int, DNSRecord>>& recs)
{
  records.clear();
  for (const auto& record : recs) {
    records.push_back(record.second);
  }
}

void RecursorLua4::DNSQuestion::addRecord(uint16_t type, const std::string& content, DNSResourceRecord::Place place, boost::optional<int> ttl, boost::optional<string> name)
{
  DNSRecord dnsrec;
  dnsrec.d_name = name ? DNSName(*name) : qname;
  dnsrec.d_ttl = ttl.get_value_or(3600);
  dnsrec.d_type = type;
  dnsrec.d_place = place;
  dnsrec.setContent(DNSRecordContent::mastermake(type, QClass::IN, content));
  records.push_back(dnsrec);
}

void RecursorLua4::DNSQuestion::addAnswer(uint16_t type, const std::string& content, boost::optional<int> ttl, boost::optional<string> name)
{
  addRecord(type, content, DNSResourceRecord::ANSWER, ttl, std::move(name));
}

struct DynMetric
{
  std::atomic<unsigned long>* ptr;
  void inc() const { (*ptr)++; }
  void incBy(unsigned int inc) const { (*ptr) += inc; }
  [[nodiscard]] unsigned long get() const { return *ptr; }
  void set(unsigned long val) const { *ptr = val; }
};

// clang-format off

void RecursorLua4::postPrepareContext() // NOLINT(readability-function-cognitive-complexity)
{
  d_lw->registerMember<const DNSName (DNSQuestion::*)>("qname", [](const DNSQuestion& dnsq) -> const DNSName& { return dnsq.qname; }, [](DNSQuestion& /* dq */, const DNSName& newName) { (void) newName; });
  d_lw->registerMember<uint16_t (DNSQuestion::*)>("qtype", [](const DNSQuestion& dnsq) -> uint16_t { return dnsq.qtype; }, [](DNSQuestion& /* dq */, uint16_t newType) { (void) newType; });
  d_lw->registerMember<bool (DNSQuestion::*)>("isTcp", [](const DNSQuestion& dnsq) -> bool { return dnsq.isTcp; }, [](DNSQuestion& /* dq */, bool newTcp) { (void) newTcp; });
  d_lw->registerMember<const ComboAddress (DNSQuestion::*)>("localaddr", [](const DNSQuestion& dnsq) -> const ComboAddress& { return dnsq.local; }, [](DNSQuestion& /* dq */, const ComboAddress& newLocal) { (void) newLocal; });
  d_lw->registerMember<const ComboAddress (DNSQuestion::*)>("remoteaddr", [](const DNSQuestion& dnsq) -> const ComboAddress& { return dnsq.remote; }, [](DNSQuestion& /* dq */, const ComboAddress& newRemote) { (void) newRemote; });
  d_lw->registerMember<uint8_t (DNSQuestion::*)>("validationState", [](const DNSQuestion& dnsq) -> uint8_t { return (vStateIsBogus(dnsq.validationState) ? /* in order not to break older scripts */ static_cast<uint8_t>(255) : static_cast<uint8_t>(dnsq.validationState)); }, [](DNSQuestion& /* dq */, uint8_t newState) { (void) newState; });
  d_lw->registerMember<vState (DNSQuestion::*)>("detailedValidationState", [](const DNSQuestion& dnsq) -> vState { return dnsq.validationState; }, [](DNSQuestion& /* dq */, vState newState) { (void) newState; });

  d_lw->registerMember<bool (DNSQuestion::*)>("variable", [](const DNSQuestion& dnsq) -> bool { return dnsq.variable; }, [](DNSQuestion& dnsq, bool newVariable) { dnsq.variable = newVariable; });
  d_lw->registerMember<bool (DNSQuestion::*)>("wantsRPZ", [](const DNSQuestion& dnsq) -> bool { return dnsq.wantsRPZ; }, [](DNSQuestion& dnsq, bool newWantsRPZ) { dnsq.wantsRPZ = newWantsRPZ; });
  d_lw->registerMember<bool (DNSQuestion::*)>("logResponse", [](const DNSQuestion& dnsq) -> bool { return dnsq.logResponse; }, [](DNSQuestion& dnsq, bool newLogResponse) { dnsq.logResponse = newLogResponse; });
  d_lw->registerMember<bool (DNSQuestion::*)>("addPaddingToResponse", [](const DNSQuestion& dnsq) -> bool { return dnsq.addPaddingToResponse; }, [](DNSQuestion& dnsq, bool add) { dnsq.addPaddingToResponse = add; });

  d_lw->registerMember("rcode", &DNSQuestion::rcode);
  d_lw->registerMember("tag", &DNSQuestion::tag);
  d_lw->registerMember("requestorId", &DNSQuestion::requestorId);
  d_lw->registerMember("deviceId", &DNSQuestion::deviceId);
  d_lw->registerMember("deviceName", &DNSQuestion::deviceName);
  d_lw->registerMember("followupFunction", &DNSQuestion::followupFunction);
  d_lw->registerMember("followupPrefix", &DNSQuestion::followupPrefix);
  d_lw->registerMember("followupName", &DNSQuestion::followupName);
  d_lw->registerMember("data", &DNSQuestion::data);
  d_lw->registerMember<uint16_t (DNSQuestion::*)>("extendedErrorCode", [](const DNSQuestion& dnsq) -> uint16_t {
      if (dnsq.extendedErrorCode != nullptr && *dnsq.extendedErrorCode) {
        return *(*dnsq.extendedErrorCode);
      }
      return 0;
    },
    [](DNSQuestion& dnsq, uint16_t newCode) {
      if (dnsq.extendedErrorCode != nullptr) {
        *dnsq.extendedErrorCode = newCode;
      }
    });
  d_lw->registerMember<std::string (DNSQuestion::*)>("extendedErrorExtra", [](const DNSQuestion& dnsq) -> std::string {
      if (dnsq.extendedErrorExtra != nullptr) {
        return *dnsq.extendedErrorExtra;
      }
      return "";
    },
    [](DNSQuestion& dnsq, const std::string& newExtra) {
      if (dnsq.extendedErrorExtra != nullptr) {
        *dnsq.extendedErrorExtra = newExtra;
      }
    });
  d_lw->registerMember("udpQuery", &DNSQuestion::udpQuery);
  d_lw->registerMember("udpAnswer", &DNSQuestion::udpAnswer);
  d_lw->registerMember("udpQueryDest", &DNSQuestion::udpQueryDest);
  d_lw->registerMember("udpCallback", &DNSQuestion::udpCallback);
  d_lw->registerMember("appliedPolicy", &DNSQuestion::appliedPolicy);
  d_lw->registerMember("queryTime", &DNSQuestion::queryTime);

  d_lw->registerMember<DNSFilterEngine::AppliedPolicy, std::string>("policyName",
    [](const DNSFilterEngine::AppliedPolicy& pol) -> std::string {
      return pol.getName();
    },
    [](DNSFilterEngine::AppliedPolicy& pol, const std::string& name) {
      pol.setName(name);
    });
  d_lw->registerMember("policyKind", &DNSFilterEngine::AppliedPolicy::d_kind);
  d_lw->registerMember("policyType", &DNSFilterEngine::AppliedPolicy::d_type);
  d_lw->registerMember("policyTTL", &DNSFilterEngine::AppliedPolicy::d_ttl);
  d_lw->registerMember("policyTrigger", &DNSFilterEngine::AppliedPolicy::d_trigger);
  d_lw->registerMember("policyHit", &DNSFilterEngine::AppliedPolicy::d_hit);
  d_lw->registerMember<DNSFilterEngine::AppliedPolicy, std::string>("policyCustom",
    [](const DNSFilterEngine::AppliedPolicy& pol) -> std::string {
      std::string result;
      if (pol.d_kind != DNSFilterEngine::PolicyKind::Custom) {
        return result;
      }

      if (pol.customRecordsSize() > 0) {
        for (const auto& dnsrec : *pol.d_custom) {
          if (!result.empty()) {
            result += "\n";
          }
          result += dnsrec->getZoneRepresentation();
        }
      }

      return result;
    },
    [](DNSFilterEngine::AppliedPolicy& pol, const std::string& content) {
      // Only CNAMES for now, when we ever add a d_custom_type, there will be pain
      if (pol.d_custom != nullptr) {
        pol.d_custom->clear();
      }
      pol.allocateCustomRecords(1);
      pol.d_custom->push_back(DNSRecordContent::mastermake(QType::CNAME, QClass::IN, content));
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
      values.reserve(option.values.size());
      for (const auto& value : option.values) {
        values.emplace_back(value.content, value.size);
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
    [](EDNSOptionView& /* option */, uint16_t newSize) { (void) newSize; });
  d_lw->registerFunction<std::string(EDNSOptionView::*)()>("getContent", [](const EDNSOptionView& option) {
      if (option.values.empty()) {
        return std::string();
      }
      return std::string(option.values.at(0).content, option.values.at(0).size); });

  d_lw->registerFunction<string(DNSRecord::*)()>("getContent", [](const DNSRecord& dnsrec) { return dnsrec.getContent()->getZoneRepresentation(); });
  d_lw->registerFunction<boost::optional<ComboAddress>(DNSRecord::*)()>("getCA", [](const DNSRecord& dnsrec) { 
      boost::optional<ComboAddress> ret;

      if(auto rec = getRR<ARecordContent>(dnsrec)) {
        ret=rec->getCA(53);
      } else if(auto aaaarec = getRR<AAAARecordContent>(dnsrec)) {
        ret=aaaarec->getCA(53);
      }
      return ret;
    });

  d_lw->registerFunction<const ProxyProtocolValue, std::string()>("getContent", [](const ProxyProtocolValue& value) { return value.content; });
  d_lw->registerFunction<const ProxyProtocolValue, uint8_t()>("getType", [](const ProxyProtocolValue& value) { return value.type; });

  d_lw->registerFunction<void(DNSRecord::*)(const std::string&)>("changeContent", [](DNSRecord& dnsrec, const std::string& newContent) { dnsrec.setContent(DNSRecordContent::mastermake(dnsrec.d_type, QClass::IN, newContent)); });
  d_lw->registerFunction("addAnswer", &DNSQuestion::addAnswer);
  d_lw->registerFunction("addRecord", &DNSQuestion::addRecord);
  d_lw->registerFunction("getRecords", &DNSQuestion::getRecords);
  d_lw->registerFunction("setRecords", &DNSQuestion::setRecords);

  d_lw->registerFunction<void(DNSQuestion::*)(const std::string&)>("addPolicyTag", [](DNSQuestion& dnsq, const std::string& tag) { if (dnsq.policyTags != nullptr) { dnsq.policyTags->insert(tag); } });
  d_lw->registerFunction<void(DNSQuestion::*)(const std::vector<std::pair<int, std::string> >&)>("setPolicyTags", [](DNSQuestion& dnsq, const std::vector<std::pair<int, std::string> >& tags) {
      if (dnsq.policyTags != nullptr) {
        dnsq.policyTags->clear();
        dnsq.policyTags->reserve(tags.size());
        for (const auto& tag : tags) {
          dnsq.policyTags->insert(tag.second);
        }
      }
    });
  d_lw->registerFunction<std::vector<std::pair<int, std::string> >(DNSQuestion::*)()>("getPolicyTags", [](const DNSQuestion& dnsq) {
      std::vector<std::pair<int, std::string> > ret;
      if (dnsq.policyTags != nullptr) {
        int count = 1;
        ret.reserve(dnsq.policyTags->size());
        for (const auto& tag : *dnsq.policyTags) {
          ret.emplace_back(count++, tag);
        }
      }
      return ret;
    });

  d_lw->registerFunction<void(DNSQuestion::*)(const std::string&)>("discardPolicy", [](DNSQuestion& dnsq, const std::string& policy) {
      if (dnsq.discardedPolicies != nullptr) {
        (*dnsq.discardedPolicies)[policy] = true;
      }
    });

  d_lw->writeFunction("newDS", []() { return SuffixMatchNode(); });
  d_lw->registerFunction<void(SuffixMatchNode::*)(boost::variant<string,DNSName, vector<pair<unsigned int,string> > >)>(
    "add",
    [](SuffixMatchNode&smn, const boost::variant<string,DNSName,vector<pair<unsigned int,string> > >& arg){
      try {
        if (const auto *str = boost::get<string>(&arg)) {
          smn.add(DNSName(*str));
        }
        else if(const auto *vec = boost::get<vector<pair<unsigned int, string> > >(&arg)) {
          for(const auto& entry : *vec) {
            smn.add(DNSName(entry.second));
          }
        }
        else {
          smn.add(boost::get<DNSName>(arg));
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

  for(const auto& name : QType::names) {
    d_pd.emplace_back(name.first, name.second);
  }

  d_pd.push_back({"validationstates", in_t{
        {"Indeterminate", static_cast<unsigned int>(vState::Indeterminate) },
        {"BogusNoValidDNSKEY", static_cast<unsigned int>(vState::BogusNoValidDNSKEY) },
        {"BogusInvalidDenial", static_cast<unsigned int>(vState::BogusInvalidDenial) },
        {"BogusUnableToGetDSs", static_cast<unsigned int>(vState::BogusUnableToGetDSs) },
        {"BogusUnableToGetDNSKEYs", static_cast<unsigned int>(vState::BogusUnableToGetDNSKEYs) },
        {"BogusSelfSignedDS", static_cast<unsigned int>(vState::BogusSelfSignedDS) },
        {"BogusNoRRSIG", static_cast<unsigned int>(vState::BogusNoRRSIG) },
        {"BogusNoValidRRSIG", static_cast<unsigned int>(vState::BogusNoValidRRSIG) },
        {"BogusMissingNegativeIndication", static_cast<unsigned int>(vState::BogusMissingNegativeIndication) },
        {"BogusSignatureNotYetValid", static_cast<unsigned int>(vState::BogusSignatureNotYetValid)},
        {"BogusSignatureExpired", static_cast<unsigned int>(vState::BogusSignatureExpired)},
        {"BogusUnsupportedDNSKEYAlgo", static_cast<unsigned int>(vState::BogusUnsupportedDNSKEYAlgo)},
        {"BogusUnsupportedDSDigestType", static_cast<unsigned int>(vState::BogusUnsupportedDSDigestType)},
        {"BogusNoZoneKeyBitSet", static_cast<unsigned int>(vState::BogusNoZoneKeyBitSet)},
        {"BogusRevokedDNSKEY", static_cast<unsigned int>(vState::BogusRevokedDNSKEY)},
        {"BogusInvalidDNSKEYProtocol", static_cast<unsigned int>(vState::BogusInvalidDNSKEYProtocol)},
        {"Insecure", static_cast<unsigned int>(vState::Insecure) },
        {"Secure", static_cast<unsigned int>(vState::Secure) },
        /* in order not to break compatibility with older scripts: */
        {"Bogus", static_cast<unsigned int>(255) },
  }});

  d_lw->writeFunction("isValidationStateBogus", [](vState state) {
    return vStateIsBogus(state);
  });

  d_pd.emplace_back("now", &g_now);

  d_lw->writeFunction("getMetric", [](const std::string& str, boost::optional<std::string> prometheusName) {
    return DynMetric{getDynMetric(str, prometheusName ? *prometheusName : "")};
    });

  d_lw->registerFunction("inc", &DynMetric::inc);
  d_lw->registerFunction("incBy", &DynMetric::incBy);
  d_lw->registerFunction("set", &DynMetric::set);
  d_lw->registerFunction("get", &DynMetric::get);

  d_lw->writeFunction("getStat", [](const std::string& str) {
      uint64_t result = 0;
      auto value = getStatByName(str);
      if (value) {
        result = *value;
      }
      return result;
    });

  d_lw->writeFunction("getRecursorThreadId", []() {
    return RecThreadInfo::id();
  });

  d_lw->writeFunction("sendCustomSNMPTrap", [](const std::string& str) {
      if (g_snmpAgent) {
        g_snmpAgent->sendCustomTrap(str);
      }
    });

  d_lw->writeFunction("getregisteredname", [](const DNSName &dname) {
      return getRegisteredName(dname);
  });

  d_lw->registerMember<const DNSName (PolicyEvent::*)>("qname", [](const PolicyEvent& event) -> const DNSName& { return event.qname; }, [](PolicyEvent& /* event */, const DNSName& newName) { (void) newName; });
  d_lw->registerMember<uint16_t (PolicyEvent::*)>("qtype", [](const PolicyEvent& event) -> uint16_t { return event.qtype.getCode(); }, [](PolicyEvent& /* event */, uint16_t newType) { (void) newType; });
  d_lw->registerMember<bool (PolicyEvent::*)>("isTcp", [](const PolicyEvent& event) -> bool { return event.isTcp; }, [](PolicyEvent& /* event */, bool newTcp) { (void) newTcp; });
  d_lw->registerMember<const ComboAddress (PolicyEvent::*)>("remote", [](const PolicyEvent& event) -> const ComboAddress& { return event.remote; }, [](PolicyEvent& /* event */, const ComboAddress& newRemote) { (void) newRemote; });
  d_lw->registerMember("appliedPolicy", &PolicyEvent::appliedPolicy);
  d_lw->registerFunction<void(PolicyEvent::*)(const std::string&)>("addPolicyTag", [](PolicyEvent& event, const std::string& tag) { if (event.policyTags != nullptr) { event.policyTags->insert(tag); } });
  d_lw->registerFunction<void(PolicyEvent::*)(const std::vector<std::pair<int, std::string> >&)>("setPolicyTags", [](PolicyEvent& event, const std::vector<std::pair<int, std::string> >& tags) {
      if (event.policyTags != nullptr) {
        event.policyTags->clear();
        event.policyTags->reserve(tags.size());
        for (const auto& tag : tags) {
          event.policyTags->insert(tag.second);
        }
      }
    });
  d_lw->registerFunction<std::vector<std::pair<int, std::string> >(PolicyEvent::*)()>("getPolicyTags", [](const PolicyEvent& event) {
      std::vector<std::pair<int, std::string> > ret;
      if (event.policyTags != nullptr) {
        int count = 1;
        ret.reserve(event.policyTags->size());
        for (const auto& tag : *event.policyTags) {
          ret.emplace_back(count++, tag);
        }
      }
      return ret;
    });
  d_lw->registerFunction<void(PolicyEvent::*)(const std::string&)>("discardPolicy", [](PolicyEvent& event, const std::string& policy) {
    if (event.discardedPolicies != nullptr) {
      (*event.discardedPolicies)[policy] = true;
    }
  });
}

// clang-format on

void RecursorLua4::postLoad()
{
  d_prerpz = d_lw->readVariable<boost::optional<luacall_t>>("prerpz").get_value_or(nullptr);
  d_preresolve = d_lw->readVariable<boost::optional<luacall_t>>("preresolve").get_value_or(nullptr);
  d_nodata = d_lw->readVariable<boost::optional<luacall_t>>("nodata").get_value_or(nullptr);
  d_nxdomain = d_lw->readVariable<boost::optional<luacall_t>>("nxdomain").get_value_or(nullptr);
  d_postresolve = d_lw->readVariable<boost::optional<luacall_t>>("postresolve").get_value_or(nullptr);
  d_preoutquery = d_lw->readVariable<boost::optional<luacall_t>>("preoutquery").get_value_or(nullptr);
  d_maintenance = d_lw->readVariable<boost::optional<luamaintenance_t>>("maintenance").get_value_or(nullptr);

  d_ipfilter = d_lw->readVariable<boost::optional<ipfilter_t>>("ipfilter").get_value_or(nullptr);
  d_gettag = d_lw->readVariable<boost::optional<gettag_t>>("gettag").get_value_or(nullptr);
  d_gettag_ffi = d_lw->readVariable<boost::optional<gettag_ffi_t>>("gettag_ffi").get_value_or(nullptr);
  d_postresolve_ffi = d_lw->readVariable<boost::optional<postresolve_ffi_t>>("postresolve_ffi").get_value_or(nullptr);

  d_policyHitEventFilter = d_lw->readVariable<boost::optional<policyEventFilter_t>>("policyEventFilter").get_value_or(nullptr);
}

void RecursorLua4::getFeatures(Features& features)
{
  // Add key-values pairs below.
  // Make sure you add string values explicitly converted to string.
  // e.g. features.emplace_back("somekey", string("stringvalue");
  // Both int and double end up as a lua number type.
  features.emplace_back("PR8001_devicename", true);
}

static void warnDrop(const RecursorLua4::DNSQuestion& dnsquestion)
{
  if (dnsquestion.rcode == -2) {
    g_log << Logger::Error << "Returning -2 (pdns.DROP) is not supported anymore, see https://docs.powerdns.com/recursor/lua-scripting/hooks.html#hooksemantics" << endl;
    // We *could* set policy here, but that would also mean interfering with rcode and the return code of the hook.
    // So leave it at the error message.
  }
}

void RecursorLua4::maintenance() const
{
  if (d_maintenance) {
    d_maintenance();
  }
}

bool RecursorLua4::prerpz(DNSQuestion& dnsquestion, int& ret, RecEventTrace& eventtrace) const
{
  if (!d_prerpz) {
    return false;
  }
  eventtrace.add(RecEventTrace::LuaPreRPZ);
  bool isok = genhook(d_prerpz, dnsquestion, ret);
  eventtrace.add(RecEventTrace::LuaPreRPZ, isok, false);
  warnDrop(dnsquestion);
  return isok;
}

bool RecursorLua4::preresolve(DNSQuestion& dnsquestion, int& ret, RecEventTrace& eventtrace) const
{
  if (!d_preresolve) {
    return false;
  }
  eventtrace.add(RecEventTrace::LuaPreResolve);
  bool isok = genhook(d_preresolve, dnsquestion, ret);
  eventtrace.add(RecEventTrace::LuaPreResolve, isok, false);
  warnDrop(dnsquestion);
  return isok;
}

bool RecursorLua4::nxdomain(DNSQuestion& dnsquestion, int& ret, RecEventTrace& eventtrace) const
{
  if (!d_nxdomain) {
    return false;
  }
  eventtrace.add(RecEventTrace::LuaNXDomain);
  bool isok = genhook(d_nxdomain, dnsquestion, ret);
  eventtrace.add(RecEventTrace::LuaNXDomain, isok, false);
  warnDrop(dnsquestion);
  return isok;
}

bool RecursorLua4::nodata(DNSQuestion& dnsquestion, int& ret, RecEventTrace& eventtrace) const
{
  if (!d_nodata) {
    return false;
  }
  eventtrace.add(RecEventTrace::LuaNoData);
  bool isok = genhook(d_nodata, dnsquestion, ret);
  eventtrace.add(RecEventTrace::LuaNoData, isok, false);
  warnDrop(dnsquestion);
  return isok;
}

bool RecursorLua4::postresolve(DNSQuestion& dnsquestion, int& ret, RecEventTrace& eventtrace) const
{
  if (!d_postresolve) {
    return false;
  }
  eventtrace.add(RecEventTrace::LuaPostResolve);
  bool isok = genhook(d_postresolve, dnsquestion, ret);
  eventtrace.add(RecEventTrace::LuaPostResolve, isok, false);
  warnDrop(dnsquestion);
  return isok;
}

bool RecursorLua4::preoutquery(const ComboAddress& nsaddress, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret, RecEventTrace& eventtrace, const struct timeval& tval) const
{
  if (!d_preoutquery) {
    return false;
  }
  bool variableAnswer = false;
  bool wantsRPZ = false;
  bool logQuery = false;
  bool addPaddingToResponse = false;
  RecursorLua4::DNSQuestion dnsquestion(nsaddress, requestor, query, qtype.getCode(), isTcp, variableAnswer, wantsRPZ, logQuery, addPaddingToResponse, tval);
  dnsquestion.currentRecords = &res;
  eventtrace.add(RecEventTrace::LuaPreOutQuery);
  bool isok = genhook(d_preoutquery, dnsquestion, ret);
  eventtrace.add(RecEventTrace::LuaPreOutQuery, isok, false);
  warnDrop(dnsquestion);
  return isok;
}

bool RecursorLua4::ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader& header, RecEventTrace& eventtrace) const
{
  if (!d_ipfilter) {
    return false; // Do not block
  }
  eventtrace.add(RecEventTrace::LuaIPFilter);
  bool isok = d_ipfilter(remote, local, header);
  eventtrace.add(RecEventTrace::LuaIPFilter, isok, false);
  return isok;
}

bool RecursorLua4::policyHitEventFilter(const ComboAddress& remote, const DNSName& qname, const QType& qtype, bool tcp, DNSFilterEngine::AppliedPolicy& policy, std::unordered_set<std::string>& tags, std::unordered_map<std::string, bool>& discardedPolicies) const
{
  if (!d_policyHitEventFilter) {
    return false;
  }

  PolicyEvent event(remote, qname, qtype, tcp);
  event.appliedPolicy = &policy;
  event.policyTags = &tags;
  event.discardedPolicies = &discardedPolicies;

  return d_policyHitEventFilter(event);
}

unsigned int RecursorLua4::gettag(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& qname, uint16_t qtype, std::unordered_set<std::string>* policyTags, LuaContext::LuaObject& data, const EDNSOptionViewMap& ednsOptions, bool tcp, std::string& requestorId, std::string& deviceId, std::string& deviceName, std::string& routingTag, const std::vector<ProxyProtocolValue>& proxyProtocolValues) const // NOLINT(bugprone-easily-swappable-parameters)
{
  if (d_gettag) {
    std::vector<std::pair<int, const ProxyProtocolValue*>> proxyProtocolValuesMap;
    proxyProtocolValuesMap.reserve(proxyProtocolValues.size());
    int num = 1;
    for (const auto& value : proxyProtocolValues) {
      proxyProtocolValuesMap.emplace_back(num++, &value);
    }

    auto ret = d_gettag(remote, ednssubnet, local, qname, qtype, ednsOptions, tcp, proxyProtocolValuesMap);

    if (policyTags != nullptr) {
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
  pdns_ffi_param(RecursorLua4::FFIParams& params_) :
    params(params_)
  {
  }

  RecursorLua4::FFIParams& params;
  std::unique_ptr<std::string> qnameStr{nullptr};
  std::unique_ptr<std::string> localStr{nullptr};
  std::unique_ptr<std::string> remoteStr{nullptr};
  std::unique_ptr<std::string> ednssubnetStr{nullptr};
  std::vector<pdns_ednsoption_t> ednsOptionsVect;
  std::vector<pdns_proxyprotocol_value_t> proxyProtocolValuesVect;
};

unsigned int RecursorLua4::gettag_ffi(RecursorLua4::FFIParams& params) const
{
  if (d_gettag_ffi) {
    pdns_ffi_param_t param(params);

    auto ret = d_gettag_ffi(&param);
    if (ret) {
      params.data = *ret;
    }

    return param.params.tag;
  }
  return 0;
}

bool RecursorLua4::genhook(const luacall_t& func, DNSQuestion& dnsquestion, int& ret) const
{
  if (!func) {
    return false;
  }

  if (dnsquestion.currentRecords != nullptr) {
    dnsquestion.records = *dnsquestion.currentRecords;
  }
  else {
    dnsquestion.records.clear();
  }

  dnsquestion.followupFunction.clear();
  dnsquestion.followupPrefix.clear();
  dnsquestion.followupName.clear();
  dnsquestion.udpQuery.clear();
  dnsquestion.udpAnswer.clear();
  dnsquestion.udpCallback.clear();

  dnsquestion.rcode = ret;
  bool handled = func(&dnsquestion);

  if (handled) {
  loop:;
    ret = dnsquestion.rcode;

    if (!dnsquestion.followupFunction.empty()) {
      if (dnsquestion.followupFunction == "followCNAMERecords") {
        ret = followCNAMERecords(dnsquestion.records, QType(dnsquestion.qtype), ret);
      }
      else if (dnsquestion.followupFunction == "getFakeAAAARecords") {
        ret = getFakeAAAARecords(dnsquestion.followupName, ComboAddress(dnsquestion.followupPrefix), dnsquestion.records);
      }
      else if (dnsquestion.followupFunction == "getFakePTRRecords") {
        ret = getFakePTRRecords(dnsquestion.followupName, dnsquestion.records);
      }
      else if (dnsquestion.followupFunction == "udpQueryResponse") {
        PacketBuffer packetbuf = GenUDPQueryResponse(dnsquestion.udpQueryDest, dnsquestion.udpQuery);
        dnsquestion.udpAnswer = std::string(reinterpret_cast<const char*>(packetbuf.data()), packetbuf.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
        auto cbFunc = d_lw->readVariable<boost::optional<luacall_t>>(dnsquestion.udpCallback).get_value_or(nullptr);
        if (!cbFunc) {
          g_log << Logger::Error << "Attempted callback for Lua UDP Query/Response which could not be found" << endl;
          return false;
        }
        bool result = cbFunc(&dnsquestion);
        if (!result) {
          return false;
        }
        goto loop; // NOLINT(cppcoreguidelines-avoid-goto)
      }
    }
    if (dnsquestion.currentRecords != nullptr) {
      *dnsquestion.currentRecords = dnsquestion.records;
    }
  }

  // see if they added followup work for us too
  return handled;
}

RecursorLua4::~RecursorLua4() = default;

const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref)
{
  if (!ref->qnameStr) {
    ref->qnameStr = std::make_unique<std::string>(ref->params.qname.toStringNoDot());
  }

  return ref->qnameStr->c_str();
}

void pdns_ffi_param_get_qname_raw(pdns_ffi_param_t* ref, const char** qname, size_t* qnameSize)
{
  const auto& storage = ref->params.qname.getStorage();
  *qname = storage.data();
  *qnameSize = storage.size();
}

uint16_t pdns_ffi_param_get_qtype(const pdns_ffi_param_t* ref)
{
  return ref->params.qtype;
}

const char* pdns_ffi_param_get_remote(pdns_ffi_param_t* ref)
{
  if (!ref->remoteStr) {
    ref->remoteStr = std::make_unique<std::string>(ref->params.remote.toString());
  }

  return ref->remoteStr->c_str();
}

static void pdns_ffi_comboaddress_to_raw(const ComboAddress& address, const void** addr, size_t* addrSize)
{
  if (address.isIPv4()) {
    *addr = &address.sin4.sin_addr.s_addr;
    *addrSize = sizeof(address.sin4.sin_addr.s_addr);
  }
  else {
    *addr = &address.sin6.sin6_addr.s6_addr;
    *addrSize = sizeof(address.sin6.sin6_addr.s6_addr);
  }
}

void pdns_ffi_param_get_remote_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize)
{
  pdns_ffi_comboaddress_to_raw(ref->params.remote, addr, addrSize);
}

uint16_t pdns_ffi_param_get_remote_port(const pdns_ffi_param_t* ref)
{
  return ref->params.remote.getPort();
}

const char* pdns_ffi_param_get_local(pdns_ffi_param_t* ref)
{
  if (!ref->localStr) {
    ref->localStr = std::make_unique<std::string>(ref->params.local.toString());
  }

  return ref->localStr->c_str();
}

void pdns_ffi_param_get_local_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize)
{
  pdns_ffi_comboaddress_to_raw(ref->params.local, addr, addrSize);
}

uint16_t pdns_ffi_param_get_local_port(const pdns_ffi_param_t* ref)
{
  return ref->params.local.getPort();
}

const char* pdns_ffi_param_get_edns_cs(pdns_ffi_param_t* ref)
{
  if (ref->params.ednssubnet.empty()) {
    return nullptr;
  }

  if (!ref->ednssubnetStr) {
    ref->ednssubnetStr = std::make_unique<std::string>(ref->params.ednssubnet.toStringNoMask());
  }

  return ref->ednssubnetStr->c_str();
}

void pdns_ffi_param_get_edns_cs_raw(pdns_ffi_param_t* ref, const void** net, size_t* netSize)
{
  if (ref->params.ednssubnet.empty()) {
    *net = nullptr;
    *netSize = 0;
    return;
  }

  pdns_ffi_comboaddress_to_raw(ref->params.ednssubnet.getNetwork(), net, netSize);
}

uint8_t pdns_ffi_param_get_edns_cs_source_mask(const pdns_ffi_param_t* ref)
{
  return ref->params.ednssubnet.getBits();
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
  if (ref->params.ednsOptions.empty()) {
    return 0;
  }

  size_t totalCount = 0;
  for (const auto& option : ref->params.ednsOptions) {
    totalCount += option.second.values.size();
  }

  ref->ednsOptionsVect.resize(totalCount);

  size_t pos = 0;
  for (const auto& option : ref->params.ednsOptions) {
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
  const auto& iter = ref->params.ednsOptions.find(optionCode);
  if (iter == ref->params.ednsOptions.cend() || iter->second.values.empty()) {
    return 0;
  }

  ref->ednsOptionsVect.resize(iter->second.values.size());

  size_t pos = 0;
  for (const auto& entry : iter->second.values) {
    fill_edns_option(entry, ref->ednsOptionsVect.at(pos));
    ref->ednsOptionsVect.at(pos).optionCode = optionCode;
    pos++;
  }

  *out = ref->ednsOptionsVect.data();

  return pos;
}

size_t pdns_ffi_param_get_proxy_protocol_values(pdns_ffi_param_t* ref, const pdns_proxyprotocol_value_t** out)
{
  if (ref->params.proxyProtocolValues.empty()) {
    return 0;
  }

  ref->proxyProtocolValuesVect.resize(ref->params.proxyProtocolValues.size());

  size_t pos = 0;
  for (const auto& value : ref->params.proxyProtocolValues) {
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
  ref->params.tag = tag;
}

void pdns_ffi_param_add_policytag(pdns_ffi_param_t* ref, const char* name)
{
  ref->params.policyTags.insert(std::string(name));
}

void pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name)
{
  ref->params.requestorId = std::string(name);
}

void pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name)
{
  ref->params.deviceName = std::string(name);
}

void pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name)
{
  ref->params.deviceId = std::string(reinterpret_cast<const char*>(name), len); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
}

void pdns_ffi_param_set_routingtag(pdns_ffi_param_t* ref, const char* name)
{
  ref->params.routingTag = std::string(name);
}

void pdns_ffi_param_set_variable(pdns_ffi_param_t* ref, bool variable)
{
  ref->params.variable = variable;
}

void pdns_ffi_param_set_ttl_cap(pdns_ffi_param_t* ref, uint32_t ttl)
{
  ref->params.ttlCap = ttl;
}

void pdns_ffi_param_set_log_query(pdns_ffi_param_t* ref, bool logQuery)
{
  ref->params.logQuery = logQuery;
}

void pdns_ffi_param_set_log_response(pdns_ffi_param_t* ref, bool logResponse)
{
  ref->params.logResponse = logResponse;
}

void pdns_ffi_param_set_rcode(pdns_ffi_param_t* ref, int rcode)
{
  ref->params.rcode = rcode;
}

void pdns_ffi_param_set_follow_cname_records(pdns_ffi_param_t* ref, bool follow)
{
  ref->params.followCNAMERecords = follow;
}

void pdns_ffi_param_set_extended_error_code(pdns_ffi_param_t* ref, uint16_t code)
{
  ref->params.extendedErrorCode = code;
}

void pdns_ffi_param_set_extended_error_extra(pdns_ffi_param_t* ref, size_t len, const char* extra)
{
  ref->params.extendedErrorExtra = std::string(extra, len);
}

bool pdns_ffi_param_add_record(pdns_ffi_param_t* ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentSize, pdns_record_place_t place)
{
  try {
    DNSRecord dnsrecord;
    dnsrecord.d_name = name != nullptr ? DNSName(name) : ref->params.qname;
    dnsrecord.d_ttl = ttl;
    dnsrecord.d_type = type;
    dnsrecord.d_class = QClass::IN;
    dnsrecord.d_place = DNSResourceRecord::Place(place);
    dnsrecord.setContent(DNSRecordContent::mastermake(type, QClass::IN, std::string(content, contentSize)));
    ref->params.records.push_back(std::move(dnsrecord));

    return true;
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << "Error attempting to add a record from Lua via pdns_ffi_param_add_record(): " << e.what() << endl;
    return false;
  }
}

void pdns_ffi_param_set_padding_disabled(pdns_ffi_param_t* ref, bool disabled)
{
  ref->params.disablePadding = disabled;
}

void pdns_ffi_param_add_meta_single_string_kv(pdns_ffi_param_t* ref, const char* key, const char* val)
{
  ref->params.meta[std::string(key)].stringVal.insert(std::string(val));
}

void pdns_ffi_param_add_meta_single_int64_kv(pdns_ffi_param_t* ref, const char* key, int64_t val)
{
  ref->params.meta[std::string(key)].intVal.insert(val);
}

struct pdns_postresolve_ffi_handle
{
public:
  pdns_postresolve_ffi_handle(RecursorLua4::PostResolveFFIHandle& ffihandle) :
    handle(ffihandle)
  {
  }
  auto insert(std::string&& str)
  {
    const auto iter = pool.insert(std::move(str)).first;
    return iter;
  }
  [[nodiscard]] RecursorLua4::PostResolveFFIHandle& getHandle() const
  {
    return handle;
  }

private:
  std::unordered_set<std::string> pool;
  RecursorLua4::PostResolveFFIHandle& handle;
};

bool RecursorLua4::postresolve_ffi(RecursorLua4::PostResolveFFIHandle& ffihandle) const
{
  if (d_postresolve_ffi) {
    pdns_postresolve_ffi_handle_t handle(ffihandle);

    auto ret = d_postresolve_ffi(&handle);
    return ret;
  }
  return false;
}

const char* pdns_postresolve_ffi_handle_get_qname(pdns_postresolve_ffi_handle_t* ref)
{
  auto str = ref->insert(ref->getHandle().d_dq.qname.toStringNoDot());
  return str->c_str();
}

void pdns_postresolve_ffi_handle_get_qname_raw(pdns_postresolve_ffi_handle_t* ref, const char** qname, size_t* qnameSize)
{
  const auto& storage = ref->getHandle().d_dq.qname.getStorage();
  *qname = storage.data();
  *qnameSize = storage.size();
}

uint16_t pdns_postresolve_ffi_handle_get_qtype(const pdns_postresolve_ffi_handle_t* ref)
{
  return ref->getHandle().d_dq.qtype;
}

uint16_t pdns_postresolve_ffi_handle_get_rcode(const pdns_postresolve_ffi_handle_t* ref)
{
  return ref->getHandle().d_dq.rcode;
}

void pdns_postresolve_ffi_handle_set_rcode(const pdns_postresolve_ffi_handle_t* ref, uint16_t rcode)
{
  ref->getHandle().d_dq.rcode = rcode;
}

pdns_policy_kind_t pdns_postresolve_ffi_handle_get_appliedpolicy_kind(const pdns_postresolve_ffi_handle_t* ref)
{
  return static_cast<pdns_policy_kind_t>(ref->getHandle().d_dq.appliedPolicy->d_kind);
}

void pdns_postresolve_ffi_handle_set_appliedpolicy_kind(pdns_postresolve_ffi_handle_t* ref, pdns_policy_kind_t kind)
{
  ref->getHandle().d_dq.appliedPolicy->d_kind = static_cast<DNSFilterEngine::PolicyKind>(kind);
}

bool pdns_postresolve_ffi_handle_get_record(pdns_postresolve_ffi_handle_t* ref, unsigned int index, pdns_ffi_record_t* record, bool raw)
{
  if (index >= ref->getHandle().d_dq.currentRecords->size()) {
    return false;
  }
  try {
    DNSRecord& dnsrec = ref->getHandle().d_dq.currentRecords->at(index);
    if (raw) {
      const auto& storage = dnsrec.d_name.getStorage();
      record->name = storage.data();
      record->name_len = storage.size();
    }
    else {
      std::string name = dnsrec.d_name.toStringNoDot();
      record->name_len = name.size();
      record->name = ref->insert(std::move(name))->c_str();
    }
    if (raw) {
      auto content = ref->insert(dnsrec.getContent()->serialize(dnsrec.d_name, true));
      record->content = content->data();
      record->content_len = content->size();
    }
    else {
      auto content = ref->insert(dnsrec.getContent()->getZoneRepresentation());
      record->content = content->data();
      record->content_len = content->size();
    }
    record->ttl = dnsrec.d_ttl;
    record->place = static_cast<pdns_record_place_t>(dnsrec.d_place);
    record->type = dnsrec.d_type;
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << "Error attempting to get a record from Lua via pdns_postresolve_ffi_handle_get_record: " << e.what() << endl;
    return false;
  }

  return true;
}

bool pdns_postresolve_ffi_handle_set_record(pdns_postresolve_ffi_handle_t* ref, unsigned int index, const char* content, size_t contentLen, bool raw)
{
  if (index >= ref->getHandle().d_dq.currentRecords->size()) {
    return false;
  }
  try {
    DNSRecord& dnsrec = ref->getHandle().d_dq.currentRecords->at(index);
    if (raw) {
      dnsrec.setContent(DNSRecordContent::deserialize(dnsrec.d_name, dnsrec.d_type, string(content, contentLen)));
    }
    else {
      dnsrec.setContent(DNSRecordContent::mastermake(dnsrec.d_type, QClass::IN, string(content, contentLen)));
    }

    return true;
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << "Error attempting to set record content from Lua via pdns_postresolve_ffi_handle_set_record(): " << e.what() << endl;
    return false;
  }
}

void pdns_postresolve_ffi_handle_clear_records(pdns_postresolve_ffi_handle_t* ref)
{
  ref->getHandle().d_dq.currentRecords->clear();
}

bool pdns_postresolve_ffi_handle_add_record(pdns_postresolve_ffi_handle_t* ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentLen, pdns_record_place_t place, bool raw)
{
  try {
    DNSRecord dnsrec;
    dnsrec.d_name = name != nullptr ? DNSName(name) : ref->getHandle().d_dq.qname;
    dnsrec.d_ttl = ttl;
    dnsrec.d_type = type;
    dnsrec.d_class = QClass::IN;
    dnsrec.d_place = DNSResourceRecord::Place(place);
    if (raw) {
      dnsrec.setContent(DNSRecordContent::deserialize(dnsrec.d_name, dnsrec.d_type, string(content, contentLen)));
    }
    else {
      dnsrec.setContent(DNSRecordContent::mastermake(type, QClass::IN, string(content, contentLen)));
    }
    ref->getHandle().d_dq.currentRecords->push_back(std::move(dnsrec));

    return true;
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << "Error attempting to add a record from Lua via pdns_postresolve_ffi_handle_add_record(): " << e.what() << endl;
    return false;
  }
}

const char* pdns_postresolve_ffi_handle_get_authip(pdns_postresolve_ffi_handle_t* ref)
{
  return ref->insert(ref->getHandle().d_dq.fromAuthIP->toString())->c_str();
}

void pdns_postresolve_ffi_handle_get_authip_raw(pdns_postresolve_ffi_handle_t* ref, const void** addr, size_t* addrSize)
{
  return pdns_ffi_comboaddress_to_raw(*ref->getHandle().d_dq.fromAuthIP, addr, addrSize);
}
