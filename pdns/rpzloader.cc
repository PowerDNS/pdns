#include "rpzloader.hh"
#include "zoneparser-tng.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "syncres.hh"
#include "resolver.hh"
#include "logger.hh"

static Netmask makeNetmaskFromRPZ(const DNSName& name)
{
  auto parts = name.getRawLabels();
  if(parts.size() < 5) 
    throw PDNSException("Invalid IP address in RPZ: "+name.toString());
  return Netmask(parts[4]+"."+parts[3]+"."+parts[2]+"."+parts[1]+"/"+parts[0]);
}

void RPZRecordToPolicy(const DNSRecord& dr, DNSFilterEngine& target, bool addOrRemove, int place)
{
  static const DNSName drop("rpz-drop."), truncate("rpz-tcp-only."), noaction("rpz-passthru.");
  static const DNSName rpzClientIP("rpz-client-ip"), rpzIP("rpz-ip"),
    rpzNSDname("rpz-nsdname"), rpzNSIP("rpz-nsip.");

  DNSFilterEngine::Policy pol{DNSFilterEngine::PolicyKind::NoAction};

  if(dr.d_type == QType::CNAME) {
    auto target=std::dynamic_pointer_cast<CNAMERecordContent>(dr.d_content)->getTarget();
    if(target.isRoot()) {
      // cerr<<"Wants NXDOMAIN for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::NXDOMAIN;
    } else if(target==DNSName("*")) {
      // cerr<<"Wants NODATA for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::NODATA;
    }
    else if(target==drop) {
      // cerr<<"Wants DROP for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
    }
    else if(target==truncate) {
      // cerr<<"Wants TRUNCATE for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::Truncate;
    }
    else if(target==noaction) {
      // cerr<<"Wants NOACTION for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::NoAction;
    }
    else {
      pol.d_kind = DNSFilterEngine::PolicyKind::Custom;
      pol.d_custom = dr.d_content;
      // cerr<<"Wants custom "<<target<<" for "<<dr.d_name<<": ";
    }
  }
  else {
    pol.d_kind = DNSFilterEngine::PolicyKind::Custom;
    pol.d_custom = dr.d_content;
    // cerr<<"Wants custom "<<dr.d_content->getZoneRepresentation()<<" for "<<dr.d_name<<": ";
  }

  // now to DO something with that
  
  if(dr.d_name.isPartOf(rpzNSDname)) {
    DNSName filt=dr.d_name.makeRelative(rpzNSDname);
    if(addOrRemove)
      g_dfe.addNSTrigger(filt, pol);
    else
      g_dfe.rmNSTrigger(filt, pol);
  } else 	if(dr.d_name.isPartOf(rpzClientIP)) {

    auto nm=makeNetmaskFromRPZ(dr.d_name);

    if(addOrRemove)
      g_dfe.addClientTrigger(nm, pol);
    else
      g_dfe.rmClientTrigger(nm, pol);
    
  } else 	if(dr.d_name.isPartOf(rpzIP)) {
    // cerr<<"Should apply answer content IP policy: "<<dr.d_name<<endl;
    auto nm=makeNetmaskFromRPZ(dr.d_name);
    if(addOrRemove)
      g_dfe.addResponseTrigger(nm, pol);
    else
      g_dfe.rmResponseTrigger(nm, pol);
  } else if(dr.d_name.isPartOf(rpzNSIP)) {
    cerr<<"Should apply to nameserver IP address policy HAVE NOTHING HERE"<<endl;

  } else {
    if(addOrRemove)
      g_dfe.addQNameTrigger(dr.d_name, pol);
    else
      g_dfe.rmQNameTrigger(dr.d_name, pol);
  }
}

shared_ptr<SOARecordContent> loadRPZFromServer(const ComboAddress& master, const DNSName& zone, DNSFilterEngine& target, int place)
{
  L<<Logger::Warning<<"Loading RPZ zone '"<<zone<<"' from "<<master.toStringWithPort()<<endl;
  ComboAddress local("0.0.0.0");
  AXFRRetriever axfr(master, zone, DNSName(), DNSName(), "", &local);
  unsigned int nrecords=0;
  Resolver::res_t nop;
  vector<DNSRecord> chunk;
  time_t last=0;
  shared_ptr<SOARecordContent> sr;
  while(axfr.getChunk(nop, &chunk)) {
    for(auto& dr : chunk) {
      dr.d_name.makeUsRelative(zone);
      if(dr.d_type==QType::SOA) {
	sr = std::dynamic_pointer_cast<SOARecordContent>(dr.d_content);
	continue;
      }
      if(dr.d_type==QType::NS) {
	continue;
      }

      RPZRecordToPolicy(dr, target, true, place);
      nrecords++;
    } 
    if(last != time(0)) {
      L<<Logger::Info<<"Loaded & indexed "<<nrecords<<" policy records so far"<<endl;
      last=time(0);
    }
  }
  L<<Logger::Info<<"Done: "<<nrecords<<" policy records active, SOA: "<<sr->getZoneRepresentation()<<endl;
  return sr;
}

int loadRPZFromFile(const std::string& fname, DNSFilterEngine& target, int place)
{
  ZoneParserTNG zpt(fname);
  DNSResourceRecord drr;
  DNSName domain;
  while(zpt.get(drr)) {
    try {
      if(drr.qtype.getCode() == QType::CNAME && drr.content.empty())
	drr.content=".";
      DNSRecord dr(drr);
      if(dr.d_type == QType::SOA) {
	domain = dr.d_name;
	cerr<<"Origin is "<<domain<<endl;
      }
      else if(dr.d_type == QType::NS) {
	continue;
      }
      else {
	dr.d_name=dr.d_name.makeRelative(domain);
	RPZRecordToPolicy(dr, target, true, place);
      }
    }
    catch(PDNSException& pe) {
      cerr<<"Issue parsing '"<<drr.qname<<"' '"<<drr.content<<"' at "<<zpt.getLineOfFile()<<endl;
      cerr<<pe.reason<<endl;
    }
  }
  
  return place;
}
