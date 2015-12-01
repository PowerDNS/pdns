#include "filterpo.hh"
#include <iostream>
#include "namespaces.hh"
#include "dnsrecords.hh"

DNSFilterEngine::DNSFilterEngine()
{
}

bool findNamedPolicy(const map<DNSName, DNSFilterEngine::Policy>& polmap, const DNSName& qname, DNSFilterEngine::Policy& pol)
{
  DNSName s(qname);

    /* for www.powerdns.com, we need to check:
         www.powerdns.com.
           *.powerdns.com.
             powerdns.com.
	            *.com.
                      com.
	 	        *.
  			 .       */
 
  bool first=true;
  do {
    auto iter = polmap.find(s);
    if(iter != polmap.end()) {
      pol=iter->second;
      return true;
    }
    if(!first) {
      iter = polmap.find(DNSName("*")+s);
      if(iter != polmap.end()) {
	pol=iter->second;
	return true;
      }
    }
    first=false;
  } while(s.chopOff());
  return false;
}

DNSFilterEngine::Policy DNSFilterEngine::getProcessingPolicy(const DNSName& qname) const
{
  //  cout<<"Got question for nameserver name "<<qname<<endl;
  Policy pol{PolicyKind::NoAction};
  for(const auto& z : d_zones) {
    if(findNamedPolicy(z.propolName, qname, pol)) {
      //      cerr<<"Had a hit on the nameserver ("<<qname<<") used to process the query"<<endl;
      return pol;
    }
  }
  return pol;
}  


DNSFilterEngine::Policy DNSFilterEngine::getQueryPolicy(const DNSName& qname, const ComboAddress& ca) const
{
  //  cout<<"Got question for "<<qname<<" from "<<ca.toString()<<endl;

  Policy pol{PolicyKind::NoAction};
  for(const auto& z : d_zones) {
    if(findNamedPolicy(z.qpolName, qname, pol)) {
      //      cerr<<"Had a hit on the name of the query"<<endl;
      return pol;
    }
    
    if(auto fnd=z.qpolAddr.lookup(ca)) {
      //	cerr<<"Had a hit on the IP address ("<<ca.toString()<<") of the client"<<endl;
      return fnd->second;
    }
  }

  return pol;
}

DNSFilterEngine::Policy DNSFilterEngine::getPostPolicy(const vector<DNSRecord>& records) const
{
  ComboAddress ca;

  for(const auto& r : records) {
    if(r.d_place != DNSResourceRecord::ANSWER) 
      continue;
    if(r.d_type == QType::A) 
      ca = std::dynamic_pointer_cast<ARecordContent>(r.d_content)->getCA();
    else if(r.d_type == QType::AAAA) 
      ca = std::dynamic_pointer_cast<AAAARecordContent>(r.d_content)->getCA();
    else
      continue;

    for(const auto& z : d_zones) {
      if(auto fnd=z.postpolAddr.lookup(ca))
	return fnd->second;
    }
  }
  return Policy{PolicyKind::NoAction};
}

void DNSFilterEngine::assureZones(int zone)
{
  if((int)d_zones.size() <= zone)
    d_zones.resize(zone+1);
}

void DNSFilterEngine::addClientTrigger(const Netmask& nm, Policy pol, int zone)
{
  assureZones(zone);
  d_zones[zone].qpolAddr.insert(nm).second=pol;
}

void DNSFilterEngine::addResponseTrigger(const Netmask& nm, Policy pol, int zone)
{
  assureZones(zone);
  d_zones[zone].postpolAddr.insert(nm).second=pol;
}

void DNSFilterEngine::addQNameTrigger(const DNSName& n, Policy pol, int zone)
{
  assureZones(zone);
  d_zones[zone].qpolName[n]=pol;
}

void DNSFilterEngine::addNSTrigger(const DNSName& n, Policy pol, int zone)
{
  assureZones(zone);
  d_zones[zone].propolName[n]=pol;
}

bool DNSFilterEngine::rmClientTrigger(const Netmask& nm, Policy pol, int zone)
{
  assureZones(zone);

  auto& qpols = d_zones[zone].qpolAddr;
  qpols.erase(nm);
  return true;
}

bool DNSFilterEngine::rmResponseTrigger(const Netmask& nm, Policy pol, int zone)
{
  assureZones(zone);
  auto& postpols = d_zones[zone].postpolAddr;
  postpols.erase(nm);  
  return true;
}

bool DNSFilterEngine::rmQNameTrigger(const DNSName& n, Policy pol, int zone)
{
  assureZones(zone);
  d_zones[zone].qpolName.erase(n); // XXX verify we had identical policy?
  return true;
}

bool DNSFilterEngine::rmNSTrigger(const DNSName& n, Policy pol, int zone)
{
  assureZones(zone);
  d_zones[zone].propolName.erase(n); // XXX verify policy matched? =pol;
  return true;
}
