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

#include <cinttypes>
#include <iostream>

#include "filterpo.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"

DNSFilterEngine::DNSFilterEngine()
{
}

bool DNSFilterEngine::Zone::findExactQNamePolicy(const DNSName& qname, DNSFilterEngine::Policy& pol) const
{
  return findExactNamedPolicy(d_qpolName, qname, pol);
}

bool DNSFilterEngine::Zone::findExactNSPolicy(const DNSName& qname, DNSFilterEngine::Policy& pol) const
{
  return findExactNamedPolicy(d_propolName, qname, pol);
}

bool DNSFilterEngine::Zone::findNSIPPolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const
{
  if (const auto fnd = d_propolNSAddr.lookup(addr)) {
    pol = fnd->second;
    return true;
  }
  return false;
}

bool DNSFilterEngine::Zone::findResponsePolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const
{
  if (const auto fnd = d_postpolAddr.lookup(addr)) {
    pol = fnd->second;
    return true;
  }
  return false;
}

bool DNSFilterEngine::Zone::findClientPolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const
{
  if (const auto fnd = d_qpolAddr.lookup(addr)) {
    pol = fnd->second;
    return true;
  }
  return false;
}

bool DNSFilterEngine::Zone::findNamedPolicy(const std::unordered_map<DNSName, DNSFilterEngine::Policy>& polmap, const DNSName& qname, DNSFilterEngine::Policy& pol)
{
  if (polmap.empty()) {
    return false;
  }

  /* for www.powerdns.com, we need to check:
     www.powerdns.com.
       *.powerdns.com.
                *.com.
                    *.
   */

  std::unordered_map<DNSName, DNSFilterEngine::Policy>::const_iterator iter;
  iter = polmap.find(qname);

  if(iter != polmap.end()) {
    pol=iter->second;
    return true;
  }

  DNSName s(qname);
  while(s.chopOff()){
    iter = polmap.find(g_wildcarddnsname+s);
    if(iter != polmap.end()) {
      pol=iter->second;
      return true;
    }
  }
  return false;
}

bool DNSFilterEngine::Zone::findExactNamedPolicy(const std::unordered_map<DNSName, DNSFilterEngine::Policy>& polmap, const DNSName& qname, DNSFilterEngine::Policy& pol)
{
  if (polmap.empty()) {
    return false;
  }

  const auto& it = polmap.find(qname);
  if (it != polmap.end()) {
    pol = it->second;
    return true;
  }

  return false;
}

bool DNSFilterEngine::getProcessingPolicy(const DNSName& qname, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& pol) const
{
  // cout<<"Got question for nameserver name "<<qname<<endl;
  std::vector<bool> zoneEnabled(d_zones.size());
  size_t count = 0;
  bool allEmpty = true;
  for (const auto& z : d_zones) {
    bool enabled = true;
    const auto& zoneName = z->getName();
    if (z->getPriority() >= pol.getPriority()) {
      enabled = false;
    }
    else if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
      enabled = false;
    }
    else {
      if (z->hasNSPolicies()) {
        allEmpty = false;
      }
      else {
        enabled = false;
      }
    }

    zoneEnabled[count] = enabled;
    ++count;
  }

  if (allEmpty) {
    return false;
  }

  /* prepare the wildcard-based names */
  std::vector<DNSName> wcNames;
  wcNames.reserve(qname.countLabels());
  DNSName s(qname);
  while (s.chopOff()){
    wcNames.emplace_back(g_wildcarddnsname+s);
  }

  count = 0;
  for(const auto& z : d_zones) {
    if (!zoneEnabled[count]) {
      ++count;
      continue;
    }
    if (z->findExactNSPolicy(qname, pol)) {
      // cerr<<"Had a hit on the nameserver ("<<qname<<") used to process the query"<<endl;
      return true;
    }

    for (const auto& wc : wcNames) {
      if (z->findExactNSPolicy(wc, pol)) {
        // cerr<<"Had a hit on the nameserver ("<<qname<<") used to process the query"<<endl;
        return true;
      }
    }
    ++count;
  }

  return false;
}

bool DNSFilterEngine::getProcessingPolicy(const ComboAddress& address, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& pol) const
{
  //  cout<<"Got question for nameserver IP "<<address.toString()<<endl;
  for(const auto& z : d_zones) {
    if (z->getPriority() >= pol.getPriority()) {
      break;
    }
    const auto& zoneName = z->getName();
    if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
      continue;
    }

    if(z->findNSIPPolicy(address, pol)) {
      //      cerr<<"Had a hit on the nameserver ("<<address.toString()<<") used to process the query"<<endl;
      return true;
    }
  }
  return false;
}

bool DNSFilterEngine::getClientPolicy(const ComboAddress& ca, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& pol) const
{
  // cout<<"Got question from "<<ca.toString()<<endl;
  for (const auto& z : d_zones) {
    if (z->getPriority() >= pol.getPriority()) {
      break;
    }
    const auto& zoneName = z->getName();
    if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
      continue;
    }

    if (z->findClientPolicy(ca, pol)) {
      // cerr<<"Had a hit on the IP address ("<<ca.toString()<<") of the client"<<endl;
      return true;
    }
  }
  return false;
}

bool DNSFilterEngine::getQueryPolicy(const DNSName& qname, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& pol, bool equalOK) const
{
  //cerr<<"Got question for "<<qname<<' '<< pol.getPriority()<< endl;
  std::vector<bool> zoneEnabled(d_zones.size());
  size_t count = 0;
  bool allEmpty = true;
  for (const auto& z : d_zones) {
    bool enabled = true;
    if (z->getPriority() > pol.getPriority() || (!equalOK && z->getPriority() == pol.getPriority())) {
      enabled = false;
    } else {
      const auto& zoneName = z->getName();
      if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
        enabled = false;
      }
      else {
        if (z->hasQNamePolicies()) {
          allEmpty = false;
        }
        else {
          enabled = false;
        }
      }
    }

    zoneEnabled[count] = enabled;
    ++count;
  }

  if (allEmpty) {
    return false;
  }

  /* prepare the wildcard-based names */
  std::vector<DNSName> wcNames;
  wcNames.reserve(qname.countLabels());
  DNSName s(qname);
  while (s.chopOff()){
    wcNames.emplace_back(g_wildcarddnsname+s);
  }

  count = 0;
  for (const auto& z : d_zones) {
    if (!zoneEnabled[count]) {
      ++count;
      continue;
    }

    if (z->findExactQNamePolicy(qname, pol)) {
      // cerr<<"Had a hit on the name of the query"<<endl;
      return true;
    }

    for (const auto& wc : wcNames) {
      if (z->findExactQNamePolicy(wc, pol)) {
        // cerr<<"Had a hit on the name of the query"<<endl;
        return true;
      }
    }

    ++count;
  }

  return false;
}

bool DNSFilterEngine::getPostPolicy(const vector<DNSRecord>& records, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& pol) const
{
  ComboAddress ca;
  for (const auto& r : records) {
    if (r.d_place != DNSResourceRecord::ANSWER)
      continue;
    if (r.d_type == QType::A) {
      if (auto rec = getRR<ARecordContent>(r)) {
        ca = rec->getCA();
      }
    }
    else if(r.d_type == QType::AAAA) {
      if (auto rec = getRR<AAAARecordContent>(r)) {
        ca = rec->getCA();
      }
    }
    else
      continue;

    for (const auto& z : d_zones) {
      if (z->getPriority() >= pol.getPriority()) {
        break;
      }
      const auto& zoneName = z->getName();
      if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
        continue;
      }

      if (z->findResponsePolicy(ca, pol)) {
	return true;
      }
    }
  }
  return false;
}

void DNSFilterEngine::assureZones(size_t zone)
{
  if(d_zones.size() <= zone)
    d_zones.resize(zone+1);
}

void DNSFilterEngine::Zone::addNameTrigger(std::unordered_map<DNSName,Policy>& map, const DNSName& n, Policy&& pol, bool ignoreDuplicate, PolicyType ptype)
{
  auto it = map.find(n);

  if (it != map.end()) {
    auto& existingPol = it->second;

    if (pol.d_kind != PolicyKind::Custom && !ignoreDuplicate) {
      throw std::runtime_error("Adding a " + getTypeToString(ptype) + "-based filter policy of kind " + getKindToString(pol.d_kind) + " but a policy of kind " + getKindToString(existingPol.d_kind) + " already exists for the following name: " + n.toLogString());
    }

    if (existingPol.d_kind != PolicyKind::Custom && ignoreDuplicate) {
      throw std::runtime_error("Adding a " + getTypeToString(ptype) + "-based filter policy of kind " + getKindToString(existingPol.d_kind) + " but there was already an existing policy for the following name: " + n.toLogString());
    }

    existingPol.d_custom.reserve(existingPol.d_custom.size() + pol.d_custom.size());

    std::move(pol.d_custom.begin(), pol.d_custom.end(), std::back_inserter(existingPol.d_custom));
  }
  else {
    auto& qpol = map.insert({n, std::move(pol)}).first->second;
    qpol.d_zoneData = d_zoneData;
    qpol.d_type = ptype;
  }
}

void DNSFilterEngine::Zone::addNetmaskTrigger(NetmaskTree<Policy>& nmt, const Netmask& nm, Policy&& pol, bool ignoreDuplicate, PolicyType ptype)
{
  bool exists = nmt.has_key(nm);

  if (exists) {
    // XXX NetMaskTree's node_type has a non-const second, but lookup() returns a const node_type *, so we cannot modify second
    // Should look into making lookup) return a non-const node_type *...
    auto& existingPol = const_cast<Policy&>(nmt.lookup(nm)->second);

    if (pol.d_kind != PolicyKind::Custom && !ignoreDuplicate) {
      throw std::runtime_error("Adding a " + getTypeToString(ptype) + "-based filter policy of kind " + getKindToString(pol.d_kind) + " but a policy of kind " + getKindToString(existingPol.d_kind) + " already exists for the following netmask: " + nm.toString());
    }

    if (existingPol.d_kind != PolicyKind::Custom && ignoreDuplicate) {
      throw std::runtime_error("Adding a " + getTypeToString(ptype) + "-based filter policy of kind " + getKindToString(existingPol.d_kind) + " but there was already an existing policy for the following netmask: " + nm.toString());
    }

    existingPol.d_custom.reserve(existingPol.d_custom.size() + pol.d_custom.size());

    std::move(pol.d_custom.begin(), pol.d_custom.end(), std::back_inserter(existingPol.d_custom));
  }
  else {
    pol.d_zoneData = d_zoneData;
    pol.d_type = ptype;
    nmt.insert(nm).second = std::move(pol);
  }
}

bool DNSFilterEngine::Zone::rmNameTrigger(std::unordered_map<DNSName,Policy>& map, const DNSName& n, const Policy& pol)
{
  auto found = map.find(n);
  if (found == map.end()) {
    return false;
  }

  auto& existing = found->second;
  if (existing.d_kind != DNSFilterEngine::PolicyKind::Custom) {
    map.erase(found);
    return true;
  }

  /* for custom types, we might have more than one type,
     and then we need to remove only the right ones. */
  bool result = false;
  for (auto& toRemove : pol.d_custom) {
    for (auto it = existing.d_custom.begin(); it != existing.d_custom.end(); ++it) {
      if (**it == *toRemove) {
        existing.d_custom.erase(it);
        result = true;
        break;
      }
    }
  }

  // No records left for this trigger?
  if (existing.d_custom.size() == 0) {
    map.erase(found);
    return true;
  }

  return result;
}

bool DNSFilterEngine::Zone::rmNetmaskTrigger(NetmaskTree<Policy>& nmt, const Netmask& nm, const Policy& pol)
{
  bool found = nmt.has_key(nm);
  if (!found) {
    return false;
  }

  // XXX NetMaskTree's node_type has a non-const second, but lookup() returns a const node_type *, so we cannot modify second
  // Should look into making lookup) return a non-const node_type *...
  auto& existing = const_cast<Policy&>(nmt.lookup(nm)->second);
  if (existing.d_kind != DNSFilterEngine::PolicyKind::Custom) {
    nmt.erase(nm);
    return true;
  }

  /* for custom types, we might have more than one type,
     and then we need to remove only the right ones. */

  bool result = false;
  for (auto& toRemove : pol.d_custom) {
    for (auto it = existing.d_custom.begin(); it != existing.d_custom.end(); ++it) {
      if (**it == *toRemove) {
        existing.d_custom.erase(it);
        result = true;
        break;
      }
    }
  }

  // No records left for this trigger?
  if (existing.d_custom.size() == 0) {
    nmt.erase(nm);
    return true;
  }

  return result;
}

void DNSFilterEngine::Zone::addClientTrigger(const Netmask& nm, Policy&& pol, bool ignoreDuplicate)
{
  addNetmaskTrigger(d_qpolAddr, nm, std::move(pol), ignoreDuplicate, PolicyType::ClientIP);
}

void DNSFilterEngine::Zone::addResponseTrigger(const Netmask& nm, Policy&& pol, bool ignoreDuplicate)
{
  addNetmaskTrigger(d_postpolAddr, nm, std::move(pol), ignoreDuplicate, PolicyType::ResponseIP);
}

void DNSFilterEngine::Zone::addQNameTrigger(const DNSName& n, Policy&& pol, bool ignoreDuplicate)
{
  addNameTrigger(d_qpolName, n, std::move(pol), ignoreDuplicate, PolicyType::QName);
}

void DNSFilterEngine::Zone::addNSTrigger(const DNSName& n, Policy&& pol, bool ignoreDuplicate)
{
  addNameTrigger(d_propolName, n, std::move(pol), ignoreDuplicate, PolicyType::NSDName);
}

void DNSFilterEngine::Zone::addNSIPTrigger(const Netmask& nm, Policy&& pol, bool ignoreDuplicate)
{
  addNetmaskTrigger(d_propolNSAddr, nm, std::move(pol), ignoreDuplicate, PolicyType::NSIP);
}

bool DNSFilterEngine::Zone::rmClientTrigger(const Netmask& nm, const Policy& pol)
{
  return rmNetmaskTrigger(d_qpolAddr, nm, pol);
}

bool DNSFilterEngine::Zone::rmResponseTrigger(const Netmask& nm, const Policy& pol)
{
  return rmNetmaskTrigger(d_postpolAddr, nm, pol);
}

bool DNSFilterEngine::Zone::rmQNameTrigger(const DNSName& n, const Policy& pol)
{
  return rmNameTrigger(d_qpolName, n, pol);
}

bool DNSFilterEngine::Zone::rmNSTrigger(const DNSName& n, const Policy& pol)
{
  return rmNameTrigger(d_propolName, n, pol);
}

bool DNSFilterEngine::Zone::rmNSIPTrigger(const Netmask& nm, const Policy& pol)
{
  return rmNetmaskTrigger(d_propolNSAddr, nm, pol);
}

DNSRecord DNSFilterEngine::Policy::getRecordFromCustom(const DNSName& qname, const std::shared_ptr<DNSRecordContent>& custom) const
{
  DNSRecord dr;
  dr.d_name = qname;
  dr.d_type = custom->getType();
  dr.d_ttl = d_ttl;
  dr.d_class = QClass::IN;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_content = custom;

  if (dr.d_type == QType::CNAME) {
    const auto content = std::dynamic_pointer_cast<CNAMERecordContent>(custom);
    if (content) {
      DNSName target = content->getTarget();
      if (target.isWildcard()) {
        target.chopOff();
        dr.d_content = std::make_shared<CNAMERecordContent>(qname + target);
      }
    }
  }

  return dr;
}

std::vector<DNSRecord> DNSFilterEngine::Policy::getCustomRecords(const DNSName& qname, uint16_t qtype) const
{
  if (d_kind != PolicyKind::Custom) {
    throw std::runtime_error("Asking for a custom record from a filtering policy of a non-custom type");
  }

  std::vector<DNSRecord> result;

  for (const auto& custom : d_custom) {
    if (qtype != QType::ANY && qtype != custom->getType() && custom->getType() != QType::CNAME) {
      continue;
    }

    DNSRecord dr;
    dr.d_name = qname;
    dr.d_type = custom->getType();
    dr.d_ttl = d_ttl;
    dr.d_class = QClass::IN;
    dr.d_place = DNSResourceRecord::ANSWER;
    dr.d_content = custom;

    if (dr.d_type == QType::CNAME) {
      const auto content = std::dynamic_pointer_cast<CNAMERecordContent>(custom);
      if (content) {
        DNSName target = content->getTarget();
        if (target.isWildcard()) {
          target.chopOff();
          dr.d_content = std::make_shared<CNAMERecordContent>(qname + target);
        }
      }
    }

    result.emplace_back(getRecordFromCustom(qname, custom));
  }

  return result;
}

std::string DNSFilterEngine::getKindToString(DNSFilterEngine::PolicyKind kind)
{
  static const DNSName drop("rpz-drop."), truncate("rpz-tcp-only."), noaction("rpz-passthru.");
  static const DNSName rpzClientIP("rpz-client-ip"), rpzIP("rpz-ip"),
    rpzNSDname("rpz-nsdname"), rpzNSIP("rpz-nsip.");
  static const std::string rpzPrefix("rpz-");

  switch(kind) {
  case DNSFilterEngine::PolicyKind::NoAction:
    return noaction.toString();
  case DNSFilterEngine::PolicyKind::Drop:
    return drop.toString();
  case DNSFilterEngine::PolicyKind::NXDOMAIN:
    return g_rootdnsname.toString();
  case PolicyKind::NODATA:
    return g_wildcarddnsname.toString();
  case DNSFilterEngine::PolicyKind::Truncate:
    return truncate.toString();
  default:
    throw std::runtime_error("Unexpected DNSFilterEngine::Policy kind");
  }
}

std::string DNSFilterEngine::getTypeToString(DNSFilterEngine::PolicyType type)
{
  switch(type) {
  case DNSFilterEngine::PolicyType::None:
    return "none";
  case DNSFilterEngine::PolicyType::QName:
    return "QName";
  case DNSFilterEngine::PolicyType::ClientIP:
    return "Client IP";
  case DNSFilterEngine::PolicyType::ResponseIP:
    return "Response IP";
  case DNSFilterEngine::PolicyType::NSDName:
    return "Name Server Name";
  case DNSFilterEngine::PolicyType::NSIP:
    return "Name Server IP";
  default:
    throw std::runtime_error("Unexpected DNSFilterEngine::Policy type");
  }
}

std::vector<DNSRecord> DNSFilterEngine::Policy::getRecords(const DNSName& qname) const
{
  std::vector<DNSRecord> result;

  if (d_kind == PolicyKind::Custom) {
    result = getCustomRecords(qname, QType::ANY);
  }
  else {
    DNSRecord dr;
    dr.d_name = qname;
    dr.d_ttl = static_cast<uint32_t>(d_ttl);
    dr.d_type = QType::CNAME;
    dr.d_class = QClass::IN;
    dr.d_content = DNSRecordContent::mastermake(QType::CNAME, QClass::IN, getKindToString(d_kind));
    result.push_back(std::move(dr));
  }

  return result;
}

void DNSFilterEngine::Zone::dumpNamedPolicy(FILE* fp, const DNSName& name, const Policy& pol)
{
  auto records = pol.getRecords(name);
  for (const auto& dr : records) {
    fprintf(fp, "%s %" PRIu32 " IN %s %s\n", dr.d_name.toString().c_str(), dr.d_ttl, QType(dr.d_type).getName().c_str(), dr.d_content->getZoneRepresentation().c_str());
  }
}

DNSName DNSFilterEngine::Zone::maskToRPZ(const Netmask& nm)
{
  int bits = nm.getBits();
  DNSName res(std::to_string(bits));
  const auto& addr = nm.getNetwork();

  if (addr.isIPv4()) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&addr.sin4.sin_addr.s_addr);
    res += DNSName(std::to_string(bytes[3]) + "." + std::to_string(bytes[2]) + "." + std::to_string(bytes[1]) + "." + std::to_string(bytes[0]));
  }
  else {
    DNSName temp;
    const auto str = addr.toString();
    const auto len = str.size();
    std::string::size_type begin = 0;

    while (begin < len) {
      std::string::size_type end = str.find(":", begin);
      std::string sub;
      if (end != string::npos) {
        sub = str.substr(begin, end - begin);
      }
      else {
        sub = str.substr(begin);
      }

      if (sub.empty()) {
        temp = DNSName("zz") + temp;
      }
      else {
        temp = DNSName(sub) + temp;
      }

      if (end == string::npos) {
        break;
      }
      begin = end + 1;
    }
    res += temp;
  }

  return res;
}


void DNSFilterEngine::Zone::dumpAddrPolicy(FILE* fp, const Netmask& nm, const DNSName& name, const Policy& pol)
{
  DNSName full = maskToRPZ(nm);
  full += name;

  auto records = pol.getRecords(full);
  for (const auto& dr : records) {
    fprintf(fp, "%s %" PRIu32 " IN %s %s\n", dr.d_name.toString().c_str(), dr.d_ttl, QType(dr.d_type).getName().c_str(), dr.d_content->getZoneRepresentation().c_str());
  }
}

void DNSFilterEngine::Zone::dump(FILE* fp) const
{
  /* fake the SOA record */
  auto soa = DNSRecordContent::mastermake(QType::SOA, QClass::IN, "fake.RPZ. hostmaster.fake.RPZ. " + std::to_string(d_serial) + " " + std::to_string(d_refresh) + " 600 3600000 604800");
  fprintf(fp, "%s IN SOA %s\n", d_domain.toString().c_str(), soa->getZoneRepresentation().c_str());

  for (const auto& pair : d_qpolName) {
    dumpNamedPolicy(fp, pair.first + d_domain, pair.second);
  }

  for (const auto& pair : d_propolName) {
    dumpNamedPolicy(fp, pair.first + DNSName("rpz-nsdname.") + d_domain, pair.second);
  }

  for (const auto& pair : d_qpolAddr) {
    dumpAddrPolicy(fp, pair.first, DNSName("rpz-client-ip.") + d_domain, pair.second);
  }

  for (const auto& pair : d_propolNSAddr) {
    dumpAddrPolicy(fp, pair.first, DNSName("rpz-nsip.") + d_domain, pair.second);
  }

  for (const auto& pair : d_postpolAddr) {
    dumpAddrPolicy(fp, pair.first, DNSName("rpz-ip.") + d_domain, pair.second);
  }
}

void mergePolicyTags(std::unordered_set<std::string>& tags, const std::unordered_set<std::string>& newTags)
{
  for (const auto& tag : newTags) {
    tags.insert(tag);
  }
}
