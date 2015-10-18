#include "rpzloader.hh"
#include "zoneparser-tng.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "syncres.hh"

static Netmask makeNetmaskFromRPZ(const DNSName& name)
{
  auto parts = name.getRawLabels();
  if(parts.size() < 5) 
    throw PDNSException("Invalid IP address in RPZ: "+name.toString());
  return Netmask(parts[4]+"."+parts[3]+"."+parts[2]+"."+parts[1]+"/"+parts[0]);
}

int loadRPZFromFile(const std::string& fname, DNSFilterEngine& target, int place)
{
  ZoneParserTNG zpt(fname);
  DNSResourceRecord drr;

  static const DNSName drop("rpz-drop."), truncate("rpz-tcp-only."), noaction("rpz-passthru.");

  static const DNSName rpzClientIP("rpz-client-ip"), rpzIP("rpz-ip"),
    rpzNSDname("rpz-nsdname"), rpzNSIP("rpz-nsip.");
    
							   
  
  DNSName domain;
  while(zpt.get(drr)) {
    DNSFilterEngine::Policy pol=DNSFilterEngine::Policy::NoAction;

    try {
      if(drr.qtype.getCode() == QType::CNAME && drr.content.empty())
	drr.content=".";
      DNSRecord dr(drr);
      if(dr.d_type == QType::SOA) {
	domain = dr.d_name;
	cerr<<"Origin is "<<domain<<endl;
      }
      if(dr.d_type == QType::CNAME) {
	dr.d_name=dr.d_name.makeRelative(domain);
	auto target=std::dynamic_pointer_cast<CNAMERecordContent>(dr.d_content)->getTarget();
	if(target.isRoot()) {
	  cerr<<"Wants NXDOMAIN for "<<dr.d_name<<": ";
	  pol = DNSFilterEngine::Policy::NXDOMAIN;
	} else if(target==DNSName("*")) {
	  cerr<<"Wants NODATA for "<<dr.d_name<<": ";
	  pol = DNSFilterEngine::Policy::NODATA;
	}
	else if(target==drop) {
	  cerr<<"Wants DROP for "<<dr.d_name<<": ";
	  pol = DNSFilterEngine::Policy::Drop;
	}
	else if(target==truncate) {
	  cerr<<"Wants TRUNCATE for "<<dr.d_name<<": ";
	  pol = DNSFilterEngine::Policy::Truncate;
	}
	else if(target==noaction) {
	  cerr<<"Wants NOACTION for "<<dr.d_name<<": ";
	  pol = DNSFilterEngine::Policy::NoAction;
	}
	else
	  cerr<<"Wants custom "<<target<<" for "<<dr.d_name<<": ";

	if(dr.d_name.isPartOf(rpzNSDname)) {
	  DNSName filt=dr.d_name.makeRelative(rpzNSDname);
	  cerr<<"Should apply '"<<filt<<"' to nameserver policy"<<endl;
	  g_dfe.addNSTrigger(filt, pol);
	} else 	if(dr.d_name.isPartOf(rpzClientIP)) {
	  cerr<<"Should apply to client IP policy"<<endl;
	  auto nm=makeNetmaskFromRPZ(dr.d_name);
	  cout<<"Parsed as "<<nm.toString()<<endl;
	  g_dfe.addClientTrigger(nm, pol);

	} else 	if(dr.d_name.isPartOf(rpzIP)) {
	  cerr<<"Should apply answer content IP policy: "<<dr.d_name<<endl;
	  auto nm=makeNetmaskFromRPZ(dr.d_name);
	  cout<<"Parsed as "<<nm.toString()<<endl;
	  g_dfe.addResponseTrigger(nm, pol);
	} else 	if(dr.d_name.isPartOf(rpzNSIP)) {
	  cerr<<"Should apply to nameserver IP address policy"<<endl;
	} else {
	  cerr<<"Should apply to query names"<<endl;
	  g_dfe.addQNameTrigger(dr.d_name, pol);
	}

      }
    }
    catch(PDNSException& pe) {
      cerr<<"Issue parsing '"<<drr.qname<<"' '"<<drr.content<<"' at "<<zpt.getLineOfFile()<<endl;
      cerr<<pe.reason<<endl;
    }
  }
  
  return place;
}
