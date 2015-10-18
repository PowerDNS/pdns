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
  cout<<"Got question for nameserver name "<<qname<<endl;
  Policy pol = Policy::NoAction;
  for(const auto& z : d_zones) {
    if(findNamedPolicy(z.propolName, qname, pol)) {
      cerr<<"Had a hit on the nameserver used to process the query"<<endl;
      return pol;
    }
  }
  return pol;
}  


DNSFilterEngine::Policy DNSFilterEngine::getQueryPolicy(const DNSName& qname, const ComboAddress& ca) const
{
  cout<<"Got question for "<<qname<<" from "<<ca.toString()<<endl;

  Policy pol = Policy::NoAction;
  for(const auto& z : d_zones) {
    if(findNamedPolicy(z.qpolName, qname, pol)) {
      cerr<<"Had a hit on the name of the query"<<endl;
      return pol;
    }
    
    for(const auto& qa : z.qpolAddr) {
      if(qa.first.match(ca)) {
	cerr<<"Had a hit on the IP address of the client"<<endl;
	return qa.second;
      }
    }
  }

  return Policy::NoAction;
}

DNSFilterEngine::Policy DNSFilterEngine::getPostPolicy(const vector<DNSRecord>& records) const
{
  ComboAddress ca;

  for(const auto& r : records) {
    if(r.d_place != DNSRecord::Answer) 
      continue;
    if(r.d_type == QType::A) 
      ca = std::dynamic_pointer_cast<ARecordContent>(r.d_content)->getCA();
    else if(r.d_type == QType::AAAA) 
      ca = std::dynamic_pointer_cast<AAAARecordContent>(r.d_content)->getCA();
    else
      continue;

    for(const auto& z : d_zones) {
      for(const auto& qa : z.postpolAddr) {
	if(qa.first.match(ca)) {
	  cerr<<"Had a hit on IP address in answer"<<endl;
	  return qa.second;
	}
      }
    }
  }
  return Policy::NoAction;
}

void DNSFilterEngine::assureZones(int zone)
{
  if((int)d_zones.size() <= zone)
    d_zones.resize(zone+1);

}

void DNSFilterEngine::addClientTrigger(const Netmask& nm, Policy pol, int zone)
{
  assureZones(zone);
  d_zones[zone].qpolAddr.push_back({nm,pol});
}

void DNSFilterEngine::addResponseTrigger(const Netmask& nm, Policy pol, int zone)
{
  assureZones(zone);
  d_zones[zone].postpolAddr.push_back({nm,pol});
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
