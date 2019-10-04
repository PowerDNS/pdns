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

DNSFilterEngine::Policy DNSFilterEngine::getProcessingPolicy(const DNSName& qname, const std::unordered_map<std::string,bool>& discardedPolicies) const
{
  // cout<<"Got question for nameserver name "<<qname<<endl;
  std::vector<bool> zoneEnabled(d_zones.size());
  size_t count = 0;
  bool allEmpty = true;
  for (const auto& z : d_zones) {
    bool enabled = true;
    const auto zoneName = z->getName();
    if (zoneName && discardedPolicies.find(*zoneName) != discardedPolicies.end()) {
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

  Policy pol;
  if (!allEmpty) {
    count = 0;
    for(const auto& z : d_zones) {
      if (zoneEnabled[count] && z->findExactNSPolicy(qname, pol)) {
        // cerr<<"Had a hit on the nameserver ("<<qname<<") used to process the query"<<endl;
        return pol;
      }
      ++count;
    }

    DNSName s(qname);
    while(s.chopOff()){
      count = 0;
      for(const auto& z : d_zones) {
        if (zoneEnabled[count] && z->findExactNSPolicy(g_wildcarddnsname+s, pol)) {
          // cerr<<"Had a hit on the nameserver ("<<qname<<") used to process the query"<<endl;
          return pol;
        }
        ++count;
      }
    }
  }

  return pol;
}

DNSFilterEngine::Policy DNSFilterEngine::getProcessingPolicy(const ComboAddress& address, const std::unordered_map<std::string,bool>& discardedPolicies) const
{
  Policy pol;
  //  cout<<"Got question for nameserver IP "<<address.toString()<<endl;
  for(const auto& z : d_zones) {
    const auto zoneName = z->getName();
    if(zoneName && discardedPolicies.find(*zoneName) != discardedPolicies.end()) {
      continue;
    }

    if(z->findNSIPPolicy(address, pol)) {
      //      cerr<<"Had a hit on the nameserver ("<<address.toString()<<") used to process the query"<<endl;
      return pol;
    }
  }
  return pol;
}

DNSFilterEngine::Policy DNSFilterEngine::getQueryPolicy(const DNSName& qname, const ComboAddress& ca, const std::unordered_map<std::string,bool>& discardedPolicies) const
{
  //  cout<<"Got question for "<<qname<<" from "<<ca.toString()<<endl;
  std::vector<bool> zoneEnabled(d_zones.size());
  size_t count = 0;
  bool allEmpty = true;
  for (const auto& z : d_zones) {
    bool enabled = true;
    const auto zoneName = z->getName();
    if (zoneName && discardedPolicies.find(*zoneName) != discardedPolicies.end()) {
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

    zoneEnabled[count] = enabled;
    ++count;
  }

  Policy pol;
  if (!allEmpty) {
    count = 0;
    for(const auto& z : d_zones) {
      if (zoneEnabled[count] && z->findExactQNamePolicy(qname, pol)) {
        //      cerr<<"Had a hit on the name of the query"<<endl;
        return pol;
      }
      ++count;
    }

    DNSName s(qname);
    while(s.chopOff()){
      count = 0;
      for(const auto& z : d_zones) {
        if (zoneEnabled[count] && z->findExactQNamePolicy(g_wildcarddnsname+s, pol)) {
          //      cerr<<"Had a hit on the name of the query"<<endl;
          return pol;
        }
        ++count;
      }
    }
  }

  count = 0;
  for(const auto& z : d_zones) {
    if (zoneEnabled[count] && z->findClientPolicy(ca, pol)) {
      //	cerr<<"Had a hit on the IP address ("<<ca.toString()<<") of the client"<<endl;
      return pol;
    }
    ++count;
  }

  return pol;
}

DNSFilterEngine::Policy DNSFilterEngine::getPostPolicy(const vector<DNSRecord>& records, const std::unordered_map<std::string,bool>& discardedPolicies) const
{
  Policy pol;
  ComboAddress ca;
  for(const auto& r : records) {
    if(r.d_place != DNSResourceRecord::ANSWER)
      continue;
    if(r.d_type == QType::A) {
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

    for(const auto& z : d_zones) {
      const auto zoneName = z->getName();
      if(zoneName && discardedPolicies.find(*zoneName) != discardedPolicies.end()) {
        continue;
      }

      if(z->findResponsePolicy(ca, pol)) {
	return pol;
      }
    }
  }
  return pol;
}

void DNSFilterEngine::assureZones(size_t zone)
{
  if(d_zones.size() <= zone)
    d_zones.resize(zone+1);
}

void DNSFilterEngine::Zone::addClientTrigger(const Netmask& nm, Policy&& pol)
{
  pol.d_name = d_name;
  pol.d_type = PolicyType::ClientIP;
  d_qpolAddr.insert(nm).second=std::move(pol);
}

void DNSFilterEngine::Zone::addResponseTrigger(const Netmask& nm, Policy&& pol)
{
  pol.d_name = d_name;
  pol.d_type = PolicyType::ResponseIP;
  d_postpolAddr.insert(nm).second=std::move(pol);
}

void DNSFilterEngine::Zone::addQNameTrigger(const DNSName& n, Policy&& pol, bool ignoreDuplicate)
{
  auto it = d_qpolName.find(n);

  if (it != d_qpolName.end()) {
    auto& existingPol = it->second;

    if (pol.d_kind != PolicyKind::Custom && !ignoreDuplicate) {
      throw std::runtime_error("Adding a QName-based filter policy of kind " + getKindToString(pol.d_kind) + " but a policy of kind " + getKindToString(existingPol.d_kind) + " already exists for the following QName: " + n.toLogString());
    }

    if (existingPol.d_kind != PolicyKind::Custom && ignoreDuplicate) {
      throw std::runtime_error("Adding a QName-based filter policy of kind " + getKindToString(existingPol.d_kind) + " but there was already an existing policy for the following QName: " + n.toLogString());
    }

    existingPol.d_custom.reserve(existingPol.d_custom.size() + pol.d_custom.size());

    std::move(pol.d_custom.begin(), pol.d_custom.end(), std::back_inserter(existingPol.d_custom));
  }
  else {
    auto& qpol = d_qpolName.insert({n, std::move(pol)}).first->second;
    qpol.d_name = d_name;
    qpol.d_type = PolicyType::QName;
  }
}

void DNSFilterEngine::Zone::addNSTrigger(const DNSName& n, Policy&& pol)
{
  pol.d_name = d_name;
  pol.d_type = PolicyType::NSDName;
  d_propolName.insert({n, std::move(pol)});
}

void DNSFilterEngine::Zone::addNSIPTrigger(const Netmask& nm, Policy&& pol)
{
  pol.d_name = d_name;
  pol.d_type = PolicyType::NSIP;
  d_propolNSAddr.insert(nm).second = std::move(pol);
}

bool DNSFilterEngine::Zone::rmClientTrigger(const Netmask& nm, const Policy& pol)
{
  d_qpolAddr.erase(nm);
  return true;
}

bool DNSFilterEngine::Zone::rmResponseTrigger(const Netmask& nm, const Policy& pol)
{
  d_postpolAddr.erase(nm);
  return true;
}

bool DNSFilterEngine::Zone::rmQNameTrigger(const DNSName& n, const Policy& pol)
{
  auto found = d_qpolName.find(n);
  if (found == d_qpolName.end()) {
    return false;
  }

  auto& existing = found->second;
  if (existing.d_kind != DNSFilterEngine::PolicyKind::Custom) {
    d_qpolName.erase(found);
    return true;
  }

  /* for custom types, we might have more than one type,
     and then we need to remove only the right ones. */
  if (existing.d_custom.size() <= 1) {
    d_qpolName.erase(found);
    return true;
  }

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

  return result;
}

bool DNSFilterEngine::Zone::rmNSTrigger(const DNSName& n, const Policy& pol)
{
  d_propolName.erase(n); // XXX verify policy matched? =pol;
  return true;
}

bool DNSFilterEngine::Zone::rmNSIPTrigger(const Netmask& nm, const Policy& pol)
{
  d_propolNSAddr.erase(nm);
  return true;
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

  for (const auto pair : d_qpolAddr) {
    dumpAddrPolicy(fp, pair->first, DNSName("rpz-client-ip.") + d_domain, pair->second);
  }

  for (const auto pair : d_propolNSAddr) {
    dumpAddrPolicy(fp, pair->first, DNSName("rpz-nsip.") + d_domain, pair->second);
  }

  for (const auto pair : d_postpolAddr) {
    dumpAddrPolicy(fp, pair->first, DNSName("rpz-ip.") + d_domain, pair->second);
  }
}
