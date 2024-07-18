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
#include <boost/format.hpp>

#include "filterpo.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"

// Names below are RPZ Actions and end with a dot (except "Local Data")
static const std::string rpzDropName("rpz-drop."),
  rpzTruncateName("rpz-tcp-only."),
  rpzNoActionName("rpz-passthru."),
  rpzCustomName("Local Data");

// Names below are (part) of RPZ Trigger names and do NOT end with a dot
static const std::string rpzClientIPName("rpz-client-ip"),
  rpzIPName("rpz-ip"),
  rpzNSDnameName("rpz-nsdname"),
  rpzNSIPName("rpz-nsip");

DNSFilterEngine::DNSFilterEngine() = default;

bool DNSFilterEngine::Zone::findExactQNamePolicy(const DNSName& qname, DNSFilterEngine::Policy& pol) const
{
  return findExactNamedPolicy(d_qpolName, qname, pol);
}

bool DNSFilterEngine::Zone::findExactNSPolicy(const DNSName& qname, DNSFilterEngine::Policy& pol) const
{
  if (findExactNamedPolicy(d_propolName, qname, pol)) {
    // hitdata set by findExactNamedPolicy
    pol.d_hitdata->d_trigger.appendRawLabel(rpzNSDnameName);
    return true;
  }
  return false;
}

bool DNSFilterEngine::Zone::findNSIPPolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const
{
  if (const auto* fnd = d_propolNSAddr.lookup(addr)) {
    pol = fnd->second;
    pol.setHitData(Zone::maskToRPZ(fnd->first), addr.toString());
    pol.d_hitdata->d_trigger.appendRawLabel(rpzNSIPName);
    return true;
  }
  return false;
}

bool DNSFilterEngine::Zone::findResponsePolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const
{
  if (const auto* fnd = d_postpolAddr.lookup(addr)) {
    pol = fnd->second;
    pol.setHitData(Zone::maskToRPZ(fnd->first), addr.toString());
    pol.d_hitdata->d_trigger.appendRawLabel(rpzIPName);
    return true;
  }
  return false;
}

bool DNSFilterEngine::Zone::findClientPolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const
{
  if (const auto* fnd = d_qpolAddr.lookup(addr)) {
    pol = fnd->second;
    pol.setHitData(Zone::maskToRPZ(fnd->first), addr.toString());
    pol.d_hitdata->d_trigger.appendRawLabel(rpzClientIPName);
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

  if (iter != polmap.end()) {
    pol = iter->second;
    return true;
  }

  DNSName sub(qname);
  while (sub.chopOff()) {
    iter = polmap.find(g_wildcarddnsname + sub);
    if (iter != polmap.end()) {
      pol = iter->second;
      pol.setHitData(iter->first, qname.toStringNoDot());
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

  const auto iter = polmap.find(qname);
  if (iter != polmap.end()) {
    pol = iter->second;
    pol.setHitData(qname, qname.toStringNoDot());
    return true;
  }

  return false;
}

bool DNSFilterEngine::getProcessingPolicy(const DNSName& qname, const std::unordered_map<std::string, bool>& discardedPolicies, Policy& pol) const
{
  // cout<<"Got question for nameserver name "<<qname<<endl;
  std::vector<bool> zoneEnabled(d_zones.size());
  size_t count = 0;
  bool allEmpty = true;
  for (const auto& zone : d_zones) {
    bool enabled = true;
    const auto& zoneName = zone->getName();
    if (zone->getPriority() >= pol.getPriority() || discardedPolicies.find(zoneName) != discardedPolicies.end()) {
      enabled = false;
    }
    else {
      if (zone->hasNSPolicies()) {
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
  DNSName sub(qname);
  while (sub.chopOff()) {
    wcNames.emplace_back(g_wildcarddnsname + sub);
  }

  count = 0;
  for (const auto& zone : d_zones) {
    if (!zoneEnabled[count]) {
      ++count;
      continue;
    }
    if (zone->findExactNSPolicy(qname, pol)) {
      // cerr<<"Had a hit on the nameserver ("<<qname<<") used to process the query"<<endl;
      return true;
    }

    for (const auto& wildcard : wcNames) {
      if (zone->findExactNSPolicy(wildcard, pol)) {
        // cerr<<"Had a hit on the nameserver ("<<qname<<") used to process the query"<<endl;
        // Hit is not the wildcard passed to findExactQNamePolicy but the actual qname!
        pol.d_hitdata->d_hit = qname.toStringNoDot();
        return true;
      }
    }
    ++count;
  }

  return false;
}

bool DNSFilterEngine::getProcessingPolicy(const ComboAddress& address, const std::unordered_map<std::string, bool>& discardedPolicies, Policy& pol) const
{
  //  cout<<"Got question for nameserver IP "<<address.toString()<<endl;
  for (const auto& zone : d_zones) {
    if (zone->getPriority() >= pol.getPriority()) {
      break;
    }
    const auto& zoneName = zone->getName();
    if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
      continue;
    }

    if (zone->findNSIPPolicy(address, pol)) {
      //      cerr<<"Had a hit on the nameserver ("<<address.toString()<<") used to process the query"<<endl;
      return true;
    }
  }
  return false;
}

bool DNSFilterEngine::getClientPolicy(const ComboAddress& address, const std::unordered_map<std::string, bool>& discardedPolicies, Policy& pol) const
{
  // cout<<"Got question from "<<ca.toString()<<endl;
  for (const auto& zone : d_zones) {
    if (zone->getPriority() >= pol.getPriority()) {
      break;
    }
    const auto& zoneName = zone->getName();
    if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
      continue;
    }

    if (zone->findClientPolicy(address, pol)) {
      // cerr<<"Had a hit on the IP address ("<<ca.toString()<<") of the client"<<endl;
      return true;
    }
  }
  return false;
}

bool DNSFilterEngine::getQueryPolicy(const DNSName& qname, const std::unordered_map<std::string, bool>& discardedPolicies, Policy& pol) const
{
  // cerr<<"Got question for "<<qname<<' '<< pol.getPriority()<< endl;
  std::vector<bool> zoneEnabled(d_zones.size());
  size_t count = 0;
  bool allEmpty = true;
  for (const auto& zone : d_zones) {
    bool enabled = true;
    if (zone->getPriority() >= pol.getPriority()) {
      enabled = false;
    }
    else {
      const auto& zoneName = zone->getName();
      if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
        enabled = false;
      }
      else {
        if (zone->hasQNamePolicies()) {
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
  DNSName sub(qname);
  while (sub.chopOff()) {
    wcNames.emplace_back(g_wildcarddnsname + sub);
  }

  count = 0;
  for (const auto& zone : d_zones) {
    if (!zoneEnabled[count]) {
      ++count;
      continue;
    }

    if (zone->findExactQNamePolicy(qname, pol)) {
      // cerr<<"Had a hit on the name of the query"<<endl;
      return true;
    }

    for (const auto& wildcard : wcNames) {
      if (zone->findExactQNamePolicy(wildcard, pol)) {
        // cerr<<"Had a hit on the name of the query"<<endl;
        // Hit is not the wildcard passed to findExactQNamePolicy but the actual qname!
        pol.d_hitdata->d_hit = qname.toStringNoDot();
        return true;
      }
    }

    ++count;
  }

  return false;
}

bool DNSFilterEngine::getPostPolicy(const vector<DNSRecord>& records, const std::unordered_map<std::string, bool>& discardedPolicies, Policy& pol) const
{
  for (const auto& record : records) {
    if (getPostPolicy(record, discardedPolicies, pol)) {
      return true;
    }
  }

  return false;
}

bool DNSFilterEngine::getPostPolicy(const DNSRecord& record, const std::unordered_map<std::string, bool>& discardedPolicies, Policy& pol) const
{
  ComboAddress address;
  if (record.d_place != DNSResourceRecord::ANSWER) {
    return false;
  }

  if (record.d_type == QType::A) {
    if (auto rec = getRR<ARecordContent>(record)) {
      address = rec->getCA();
    }
  }
  else if (record.d_type == QType::AAAA) {
    if (auto rec = getRR<AAAARecordContent>(record)) {
      address = rec->getCA();
    }
  }
  else {
    return false;
  }

  for (const auto& zone : d_zones) {
    if (zone->getPriority() >= pol.getPriority()) {
      break;
    }
    const auto& zoneName = zone->getName();
    if (discardedPolicies.find(zoneName) != discardedPolicies.end()) {
      return false;
    }

    if (zone->findResponsePolicy(address, pol)) {
      return true;
    }
  }

  return false;
}

void DNSFilterEngine::assureZones(size_t zone)
{
  if (d_zones.size() <= zone) {
    d_zones.resize(zone + 1);
  }
}

static void addCustom(DNSFilterEngine::Policy& existingPol, const DNSFilterEngine::Policy& pol)
{
  if (!existingPol.d_custom) {
    existingPol.d_custom = make_unique<DNSFilterEngine::Policy::CustomData>();
  }
  if (pol.d_custom) {
    existingPol.d_custom->reserve(existingPol.d_custom->size() + pol.d_custom->size());
    std::move(pol.d_custom->begin(), pol.d_custom->end(), std::back_inserter(*existingPol.d_custom));
  }
}

void DNSFilterEngine::Zone::addNameTrigger(std::unordered_map<DNSName, Policy>& map, const DNSName& n, Policy&& pol, bool ignoreDuplicate, PolicyType ptype)
{
  auto iter = map.find(n);

  if (iter != map.end()) {
    auto& existingPol = iter->second;

    if (pol.d_kind != PolicyKind::Custom && !ignoreDuplicate) {
      if (d_zoneData->d_ignoreDuplicates) {
        return;
      }
      throw std::runtime_error("Adding a " + getTypeToString(ptype) + "-based filter policy of kind " + getKindToString(pol.d_kind) + " but a policy of kind " + getKindToString(existingPol.d_kind) + " already exists for the following name: " + n.toLogString());
    }

    if (existingPol.d_kind != PolicyKind::Custom && !ignoreDuplicate) {
      if (d_zoneData->d_ignoreDuplicates) {
        return;
      }
      throw std::runtime_error("Adding a " + getTypeToString(ptype) + "-based filter policy of kind " + getKindToString(pol.d_kind) + " but a policy of kind " + getKindToString(existingPol.d_kind) + " already exists for for the following name: " + n.toLogString());
    }

    addCustom(existingPol, pol);
  }
  else {
    auto& qpol = map.insert({n, std::move(pol)}).first->second;
    qpol.d_zoneData = d_zoneData;
    qpol.d_type = ptype;
  }
}

void DNSFilterEngine::Zone::addNetmaskTrigger(NetmaskTree<Policy>& nmt, const Netmask& netmask, Policy&& pol, bool ignoreDuplicate, PolicyType ptype)
{
  bool exists = nmt.has_key(netmask);

  if (exists) {
    auto& existingPol = nmt.lookup(netmask)->second;

    if (pol.d_kind != PolicyKind::Custom && !ignoreDuplicate) {
      if (d_zoneData->d_ignoreDuplicates) {
        return;
      }
      throw std::runtime_error("Adding a " + getTypeToString(ptype) + "-based filter policy of kind " + getKindToString(pol.d_kind) + " but a policy of kind " + getKindToString(existingPol.d_kind) + " already exists for the following netmask: " + netmask.toString());
    }

    if (existingPol.d_kind != PolicyKind::Custom && !ignoreDuplicate) {
      if (d_zoneData->d_ignoreDuplicates) {
        return;
      }
      throw std::runtime_error("Adding a " + getTypeToString(ptype) + "-based filter policy of kind " + getKindToString(pol.d_kind) + " but a policy of kind " + getKindToString(existingPol.d_kind) + " already exists for the following netmask: " + netmask.toString());
    }

    addCustom(existingPol, pol);
  }
  else {
    pol.d_zoneData = d_zoneData;
    pol.d_type = ptype;
    nmt.insert(netmask).second = std::move(pol);
  }
}

bool DNSFilterEngine::Zone::rmNameTrigger(std::unordered_map<DNSName, Policy>& map, const DNSName& name, const Policy& pol)
{
  auto found = map.find(name);
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
  if (pol.d_custom && existing.d_custom) {
    for (const auto& toRemove : *pol.d_custom) {
      for (auto it = existing.d_custom->begin(); it != existing.d_custom->end(); ++it) {
        if (**it == *toRemove) {
          existing.d_custom->erase(it);
          result = true;
          break;
        }
      }
    }
  }

  // No records left for this trigger?
  if (existing.customRecordsSize() == 0) {
    map.erase(found);
    return true;
  }

  return result;
}

bool DNSFilterEngine::Zone::rmNetmaskTrigger(NetmaskTree<Policy>& nmt, const Netmask& netmask, const Policy& pol)
{
  bool found = nmt.has_key(netmask);
  if (!found) {
    return false;
  }

  auto& existing = nmt.lookup(netmask)->second;
  if (existing.d_kind != DNSFilterEngine::PolicyKind::Custom) {
    nmt.erase(netmask);
    return true;
  }

  /* for custom types, we might have more than one type,
     and then we need to remove only the right ones. */

  bool result = false;
  if (pol.d_custom && existing.d_custom) {
    for (const auto& toRemove : *pol.d_custom) {
      for (auto it = existing.d_custom->begin(); it != existing.d_custom->end(); ++it) {
        if (**it == *toRemove) {
          existing.d_custom->erase(it);
          result = true;
          break;
        }
      }
    }
  }

  // No records left for this trigger?
  if (existing.customRecordsSize() == 0) {
    nmt.erase(netmask);
    return true;
  }

  return result;
}

void DNSFilterEngine::Zone::addClientTrigger(const Netmask& netmask, Policy&& pol, bool ignoreDuplicate)
{
  addNetmaskTrigger(d_qpolAddr, netmask, std::move(pol), ignoreDuplicate, PolicyType::ClientIP);
}

void DNSFilterEngine::Zone::addResponseTrigger(const Netmask& netmask, Policy&& pol, bool ignoreDuplicate)
{
  addNetmaskTrigger(d_postpolAddr, netmask, std::move(pol), ignoreDuplicate, PolicyType::ResponseIP);
}

void DNSFilterEngine::Zone::addQNameTrigger(const DNSName& dnsname, Policy&& pol, bool ignoreDuplicate)
{
  addNameTrigger(d_qpolName, dnsname, std::move(pol), ignoreDuplicate, PolicyType::QName);
}

void DNSFilterEngine::Zone::addNSTrigger(const DNSName& dnsname, Policy&& pol, bool ignoreDuplicate)
{
  addNameTrigger(d_propolName, dnsname, std::move(pol), ignoreDuplicate, PolicyType::NSDName);
}

void DNSFilterEngine::Zone::addNSIPTrigger(const Netmask& netmask, Policy&& pol, bool ignoreDuplicate)
{
  addNetmaskTrigger(d_propolNSAddr, netmask, std::move(pol), ignoreDuplicate, PolicyType::NSIP);
}

bool DNSFilterEngine::Zone::rmClientTrigger(const Netmask& netmask, const Policy& pol)
{
  return rmNetmaskTrigger(d_qpolAddr, netmask, pol);
}

bool DNSFilterEngine::Zone::rmResponseTrigger(const Netmask& netmask, const Policy& pol)
{
  return rmNetmaskTrigger(d_postpolAddr, netmask, pol);
}

bool DNSFilterEngine::Zone::rmQNameTrigger(const DNSName& dnsname, const Policy& pol)
{
  return rmNameTrigger(d_qpolName, dnsname, pol);
}

bool DNSFilterEngine::Zone::rmNSTrigger(const DNSName& dnsname, const Policy& pol)
{
  return rmNameTrigger(d_propolName, dnsname, pol);
}

bool DNSFilterEngine::Zone::rmNSIPTrigger(const Netmask& netmask, const Policy& pol)
{
  return rmNetmaskTrigger(d_propolNSAddr, netmask, pol);
}

std::string DNSFilterEngine::Policy::getLogString() const
{
  return ": RPZ Hit; PolicyName=" + getName() + "; Trigger=" + getTrigger().toLogString() + "; Hit=" + getHit() + "; Type=" + getTypeToString(d_type) + "; Kind=" + getKindToString(d_kind);
}

void DNSFilterEngine::Policy::info(Logr::Priority prio, const std::shared_ptr<Logr::Logger>& log) const
{
  log->info(prio, "RPZ Hit", "policyName", Logging::Loggable(getName()), "trigger", Logging::Loggable(getTrigger()),
            "hit", Logging::Loggable(getHit()), "type", Logging::Loggable(getTypeToString(d_type)),
            "kind", Logging::Loggable(getKindToString(d_kind)));
}

DNSRecord DNSFilterEngine::Policy::getRecordFromCustom(const DNSName& qname, const std::shared_ptr<const DNSRecordContent>& custom) const
{
  DNSRecord dnsrecord;
  dnsrecord.d_name = qname;
  dnsrecord.d_type = custom->getType();
  dnsrecord.d_ttl = d_ttl;
  dnsrecord.d_class = QClass::IN;
  dnsrecord.d_place = DNSResourceRecord::ANSWER;
  dnsrecord.setContent(custom);

  if (dnsrecord.d_type == QType::CNAME) {
    const auto content = std::dynamic_pointer_cast<const CNAMERecordContent>(custom);
    if (content) {
      DNSName target = content->getTarget();
      if (target.isWildcard()) {
        target.chopOff();
        dnsrecord.setContent(std::make_shared<CNAMERecordContent>(qname + target));
      }
    }
  }

  return dnsrecord;
}

std::vector<DNSRecord> DNSFilterEngine::Policy::getCustomRecords(const DNSName& qname, uint16_t qtype) const
{
  if (d_kind != PolicyKind::Custom) {
    throw std::runtime_error("Asking for a custom record from a filtering policy of a non-custom type");
  }

  std::vector<DNSRecord> result;
  if (customRecordsSize() == 0) {
    return result;
  }

  for (const auto& custom : *d_custom) {
    if (qtype != QType::ANY && qtype != custom->getType() && custom->getType() != QType::CNAME) {
      continue;
    }

    DNSRecord dnsrecord;
    dnsrecord.d_name = qname;
    dnsrecord.d_type = custom->getType();
    dnsrecord.d_ttl = d_ttl;
    dnsrecord.d_class = QClass::IN;
    dnsrecord.d_place = DNSResourceRecord::ANSWER;
    dnsrecord.setContent(custom);

    if (dnsrecord.d_type == QType::CNAME) {
      const auto content = std::dynamic_pointer_cast<const CNAMERecordContent>(custom);
      if (content) {
        DNSName target = content->getTarget();
        if (target.isWildcard()) {
          target.chopOff();
          dnsrecord.setContent(std::make_shared<CNAMERecordContent>(qname + target));
        }
      }
    }

    result.emplace_back(getRecordFromCustom(qname, custom));
  }

  return result;
}

std::string DNSFilterEngine::getKindToString(DNSFilterEngine::PolicyKind kind)
{
  // static const std::string rpzPrefix("rpz-");

  switch (kind) {
  case DNSFilterEngine::PolicyKind::NoAction:
    return rpzNoActionName;
  case DNSFilterEngine::PolicyKind::Drop:
    return rpzDropName;
  case DNSFilterEngine::PolicyKind::NXDOMAIN:
    return g_rootdnsname.toString();
  case PolicyKind::NODATA:
    return g_wildcarddnsname.toString();
  case DNSFilterEngine::PolicyKind::Truncate:
    return rpzTruncateName;
  case DNSFilterEngine::PolicyKind::Custom:
    return rpzCustomName;
  default:
    throw std::runtime_error("Unexpected DNSFilterEngine::Policy kind");
  }
}

std::string DNSFilterEngine::getTypeToString(DNSFilterEngine::PolicyType type)
{
  switch (type) {
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
    DNSRecord dnsrecord;
    dnsrecord.d_name = qname;
    dnsrecord.d_ttl = static_cast<uint32_t>(d_ttl);
    dnsrecord.d_type = QType::CNAME;
    dnsrecord.d_class = QClass::IN;
    dnsrecord.setContent(DNSRecordContent::make(QType::CNAME, QClass::IN, getKindToString(d_kind)));
    result.push_back(std::move(dnsrecord));
  }

  return result;
}

void DNSFilterEngine::Zone::dumpNamedPolicy(FILE* filePtr, const DNSName& name, const Policy& pol)
{
  auto records = pol.getRecords(name);
  for (const auto& record : records) {
    fprintf(filePtr, "%s %" PRIu32 " IN %s %s\n", record.d_name.toString().c_str(), record.d_ttl, QType(record.d_type).toString().c_str(), record.getContent()->getZoneRepresentation().c_str());
  }
}

DNSName DNSFilterEngine::Zone::maskToRPZ(const Netmask& netmask)
{
  int bits = netmask.getBits();
  DNSName res(std::to_string(bits));
  const auto& addr = netmask.getNetwork();

  if (addr.isIPv4()) {
    const auto* bytes = reinterpret_cast<const uint8_t*>(&addr.sin4.sin_addr.s_addr); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    res += DNSName(std::to_string(bytes[3]) + "." + std::to_string(bytes[2]) + "." + std::to_string(bytes[1]) + "." + std::to_string(bytes[0])); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  }
  else {
    DNSName temp;
    static_assert(sizeof(addr.sin6.sin6_addr.s6_addr) == sizeof(uint16_t) * 8);
    const auto* src = reinterpret_cast<const uint16_t*>(&addr.sin6.sin6_addr.s6_addr); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
    std::array<uint16_t, 8> elems{};

    // this routine was adopted from libc's inet_ntop6, written by Paul Vixie
    // because the RPZ spec (https://datatracker.ietf.org/doc/html/draft-vixie-dnsop-dns-rpz-00#section-4.1.1) says:
    //
    //    If there exists more than one sequence of zero-valued fields of
    //    identical length, then only the last such sequence is compressed.
    //    Note that [RFC5952] specifies compressing the first such sequence,
    //    but our notation here reverses the order of fields, and so must also
    //    reverse the selection of which zero sequence to compress.
    //
    // 'cur.len > best.len' from the original code is replaced by 'cur.len >= best.len', so the last-longest wins.

    struct
    {
      int base, len;
    } best = {-1, 0}, cur = {-1, 0};

    const int size = elems.size();
    for (int i = 0; i < size; i++) {
      elems.at(i) = ntohs(src[i]); // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      if (elems.at(i) == 0) {
        if (cur.base == -1) { // start of a run of zeroes
          cur = {i, 1};
        }
        else {
          cur.len++; // continuation of a run of zeroes
        }
      }
      else { // not a zero
        if (cur.base != -1) { // end of a run of zeroes
          if (best.base == -1 || cur.len >= best.len) { // first run of zeroes, or a better one than we found before
            best = cur;
          }
          cur.base = -1;
        }
      }
    }

    if (cur.base != -1) { // address ended with a zero
      if (best.base == -1 || cur.len >= best.len) { // first run of zeroes, or a better one than we found before
        best = cur;
      }
    }

    if (best.base != -1 && best.len < 2) { // if our best run is only one zero long, we do not replace it
      best.base = -1;
    }
    for (int i = 0; i < (int)elems.size(); i++) {
      if (i == best.base) {
        temp = DNSName("zz") + temp;
        i = i + best.len - 1;
      }
      else {
        temp = DNSName((boost::format("%x") % elems.at(i)).str()) + temp;
      }
    }
    res += temp;
  }

  return res;
}

void DNSFilterEngine::Zone::dumpAddrPolicy(FILE* filePtr, const Netmask& netmask, const DNSName& name, const Policy& pol)
{
  DNSName full = maskToRPZ(netmask);
  full += name;

  auto records = pol.getRecords(full);
  for (const auto& record : records) {
    fprintf(filePtr, "%s %" PRIu32 " IN %s %s\n", record.d_name.toString().c_str(), record.d_ttl, QType(record.d_type).toString().c_str(), record.getContent()->getZoneRepresentation().c_str());
  }
}

void DNSFilterEngine::Zone::dump(FILE* filePtr) const
{
  if (DNSRecord soa = d_zoneData->d_soa; !soa.d_name.empty()) {
    fprintf(filePtr, "%s IN SOA %s\n", soa.d_name.toString().c_str(), soa.getContent()->getZoneRepresentation().c_str());
  }
  else {
    /* fake the SOA record */
    auto soarr = DNSRecordContent::make(QType::SOA, QClass::IN, "fake.RPZ. hostmaster.fake.RPZ. " + std::to_string(d_serial) + " " + std::to_string(d_refresh) + " 600 3600000 604800");
    fprintf(filePtr, "%s IN SOA %s\n", d_domain.toString().c_str(), soarr->getZoneRepresentation().c_str());
  }

  for (const auto& pair : d_qpolName) {
    dumpNamedPolicy(filePtr, pair.first + d_domain, pair.second);
  }

  for (const auto& pair : d_propolName) {
    dumpNamedPolicy(filePtr, pair.first + DNSName(rpzNSDnameName) + d_domain, pair.second);
  }

  for (const auto& pair : d_qpolAddr) {
    dumpAddrPolicy(filePtr, pair.first, DNSName(rpzClientIPName) + d_domain, pair.second);
  }

  for (const auto& pair : d_propolNSAddr) {
    dumpAddrPolicy(filePtr, pair.first, DNSName(rpzNSIPName) + d_domain, pair.second);
  }

  for (const auto& pair : d_postpolAddr) {
    dumpAddrPolicy(filePtr, pair.first, DNSName(rpzIPName) + d_domain, pair.second);
  }
}

void mergePolicyTags(std::unordered_set<std::string>& tags, const std::unordered_set<std::string>& newTags)
{
  for (const auto& tag : newTags) {
    tags.insert(tag);
  }
}
