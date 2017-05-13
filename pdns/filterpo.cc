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
#include "filterpo.hh"
#include <iostream>
#include "namespaces.hh"
#include "dnsrecords.hh"

DNSFilterEngine::DNSFilterEngine()
{
}

static bool findNamedPolicy(const std::unordered_map<DNSName, DNSFilterEngine::Policy>& polmap, const DNSName& qname, DNSFilterEngine::Policy& pol)
{
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

DNSFilterEngine::Policy DNSFilterEngine::getProcessingPolicy(const DNSName& qname, const std::unordered_map<std::string,bool>& discardedPolicies) const
{
  //  cout<<"Got question for nameserver name "<<qname<<endl;
  Policy pol;
  for(const auto& z : d_zones) {
    const auto zoneName = z->getName();
    if(zoneName && discardedPolicies.find(*zoneName) != discardedPolicies.end()) {
      continue;
    }

    if(findNamedPolicy(z->d_propolName, qname, pol)) {
      //      cerr<<"Had a hit on the nameserver ("<<qname<<") used to process the query"<<endl;
      return pol;
    }
  }
  return pol;
}

DNSFilterEngine::Policy DNSFilterEngine::getProcessingPolicy(const ComboAddress& address, const std::unordered_map<std::string,bool>& discardedPolicies) const
{
  //  cout<<"Got question for nameserver IP "<<address.toString()<<endl;
  for(const auto& z : d_zones) {
    const auto zoneName = z->getName();
    if(zoneName && discardedPolicies.find(*zoneName) != discardedPolicies.end()) {
      continue;
    }

    if(auto fnd=z->d_propolNSAddr.lookup(address)) {
      //      cerr<<"Had a hit on the nameserver ("<<address.toString()<<") used to process the query"<<endl;
      return fnd->second;;
    }
  }
  return Policy();
}

DNSFilterEngine::Policy DNSFilterEngine::getQueryPolicy(const DNSName& qname, const ComboAddress& ca, const std::unordered_map<std::string,bool>& discardedPolicies) const
{
  //  cout<<"Got question for "<<qname<<" from "<<ca.toString()<<endl;
  Policy pol;
  for(const auto& z : d_zones) {
    const auto zoneName = z->getName();
    if(zoneName && discardedPolicies.find(*zoneName) != discardedPolicies.end()) {
      continue;
    }

    if(findNamedPolicy(z->d_qpolName, qname, pol)) {
      //      cerr<<"Had a hit on the name of the query"<<endl;
      return pol;
    }
    
    if(auto fnd=z->d_qpolAddr.lookup(ca)) {
      //	cerr<<"Had a hit on the IP address ("<<ca.toString()<<") of the client"<<endl;
      return fnd->second;
    }
  }

  return pol;
}

DNSFilterEngine::Policy DNSFilterEngine::getPostPolicy(const vector<DNSRecord>& records, const std::unordered_map<std::string,bool>& discardedPolicies) const
{
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

      if(auto fnd=z->d_postpolAddr.lookup(ca))
	return fnd->second;
    }
  }
  return Policy();
}

void DNSFilterEngine::assureZones(size_t zone)
{
  if(d_zones.size() <= zone)
    d_zones.resize(zone+1);
}

void DNSFilterEngine::Zone::addClientTrigger(const Netmask& nm, Policy pol)
{
  pol.d_name = d_name;
  d_qpolAddr.insert(nm).second=pol;
}

void DNSFilterEngine::Zone::addResponseTrigger(const Netmask& nm, Policy pol)
{
  pol.d_name = d_name;
  d_postpolAddr.insert(nm).second=pol;
}

void DNSFilterEngine::Zone::addQNameTrigger(const DNSName& n, Policy pol)
{
  pol.d_name = d_name;
  d_qpolName[n]=pol;
}

void DNSFilterEngine::Zone::addNSTrigger(const DNSName& n, Policy pol)
{
  pol.d_name = d_name;
  d_propolName[n]=pol;
}

void DNSFilterEngine::Zone::addNSIPTrigger(const Netmask& nm, Policy pol)
{
  pol.d_name = d_name;
  d_propolNSAddr.insert(nm).second = pol;
}

bool DNSFilterEngine::Zone::rmClientTrigger(const Netmask& nm, Policy pol)
{
  d_qpolAddr.erase(nm);
  return true;
}

bool DNSFilterEngine::Zone::rmResponseTrigger(const Netmask& nm, Policy pol)
{
  d_postpolAddr.erase(nm);
  return true;
}

bool DNSFilterEngine::Zone::rmQNameTrigger(const DNSName& n, Policy pol)
{
  d_qpolName.erase(n); // XXX verify we had identical policy?
  return true;
}

bool DNSFilterEngine::Zone::rmNSTrigger(const DNSName& n, Policy pol)
{
  d_propolName.erase(n); // XXX verify policy matched? =pol;
  return true;
}

bool DNSFilterEngine::Zone::rmNSIPTrigger(const Netmask& nm, Policy pol)
{
  d_propolNSAddr.erase(nm);
  return true;
}

DNSRecord DNSFilterEngine::Policy::getCustomRecord(const DNSName& qname) const
{
  if (d_kind != PolicyKind::Custom) {
    throw std::runtime_error("Asking for a custom record from a filtering policy of a non-custom type");
  }

  DNSRecord result;
  result.d_name = qname;
  result.d_type = d_custom->getType();
  result.d_ttl = d_ttl;
  result.d_class = QClass::IN;
  result.d_place = DNSResourceRecord::ANSWER;
  result.d_content = d_custom;

  if (result.d_type == QType::CNAME) {
    const auto content = std::dynamic_pointer_cast<CNAMERecordContent>(d_custom);
    if (content) {
      DNSName target = content->getTarget();
      if (target.isWildcard()) {
        target.chopOff();
        result.d_content = std::make_shared<CNAMERecordContent>(qname + target);
      }
    }
  }

  return result;
}
