#include "rpzloader.hh"
#include "zoneparser-tng.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "syncres.hh"
#include "resolver.hh"
#include "logger.hh"
#include "rec-lua-conf.hh"

static Netmask makeNetmaskFromRPZ(const DNSName& name)
{
  auto parts = name.getRawLabels();
  if(parts.size() < 5) 
    throw PDNSException("Invalid IP address in RPZ: "+name.toString());
  return Netmask(parts[4]+"."+parts[3]+"."+parts[2]+"."+parts[1]+"/"+parts[0]);
}

void RPZRecordToPolicy(const DNSRecord& dr, DNSFilterEngine& target, std::shared_ptr<const std::string> polName, bool addOrRemove, boost::optional<DNSFilterEngine::Policy> defpol, int place)
{
  static const DNSName drop("rpz-drop."), truncate("rpz-tcp-only."), noaction("rpz-passthru.");
  static const DNSName rpzClientIP("rpz-client-ip"), rpzIP("rpz-ip"),
    rpzNSDname("rpz-nsdname"), rpzNSIP("rpz-nsip.");

  DNSFilterEngine::Policy pol{DNSFilterEngine::PolicyKind::NoAction, nullptr, polName, 0};

  if(dr.d_class != QClass::IN) {
    return;
  }

  if(dr.d_type == QType::CNAME) {
    auto crc = getRR<CNAMERecordContent>(dr);
    if (!crc) {
      return;
    }
    auto target=crc->getTarget();
    if(defpol) {
      pol=*defpol;
    }
    else if(target.isRoot()) {
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
    if (defpol) {
      pol=*defpol;
    }
    else {
      pol.d_kind = DNSFilterEngine::PolicyKind::Custom;
      pol.d_custom = dr.d_content;
      // cerr<<"Wants custom "<<dr.d_content->getZoneRepresentation()<<" for "<<dr.d_name<<": ";
    }
  }

  if(pol.d_ttl < 0)
    pol.d_ttl = dr.d_ttl;

  // now to DO something with that
  
  if(dr.d_name.isPartOf(rpzNSDname)) {
    DNSName filt=dr.d_name.makeRelative(rpzNSDname);
    if(addOrRemove)
      target.addNSTrigger(filt, pol);
    else
      target.rmNSTrigger(filt, pol);
  } else 	if(dr.d_name.isPartOf(rpzClientIP)) {

    auto nm=makeNetmaskFromRPZ(dr.d_name);

    if(addOrRemove)
      target.addClientTrigger(nm, pol);
    else
      target.rmClientTrigger(nm, pol);
    
  } else 	if(dr.d_name.isPartOf(rpzIP)) {
    // cerr<<"Should apply answer content IP policy: "<<dr.d_name<<endl;
    auto nm=makeNetmaskFromRPZ(dr.d_name);
    if(addOrRemove)
      target.addResponseTrigger(nm, pol);
    else
      target.rmResponseTrigger(nm, pol);
  } else if(dr.d_name.isPartOf(rpzNSIP)) {
    cerr<<"Should apply to nameserver IP address policy HAVE NOTHING HERE"<<endl;

  } else {
    if(addOrRemove)
      target.addQNameTrigger(dr.d_name, pol);
    else
      target.rmQNameTrigger(dr.d_name, pol);
  }
}

shared_ptr<SOARecordContent> loadRPZFromServer(const ComboAddress& master, const DNSName& zone, DNSFilterEngine& target, std::shared_ptr<const std::string> polName, boost::optional<DNSFilterEngine::Policy> defpol, int place,  const TSIGTriplet& tt, size_t maxReceivedBytes)
{
  L<<Logger::Warning<<"Loading RPZ zone '"<<zone<<"' from "<<master.toStringWithPort()<<endl;
  if(!tt.name.empty())
    L<<Logger::Warning<<"With TSIG key '"<<tt.name<<"' of algorithm '"<<tt.algo<<"'"<<endl;

  ComboAddress local= master.sin4.sin_family == AF_INET ? ComboAddress("0.0.0.0") : ComboAddress("::"); // should be configurable
  AXFRRetriever axfr(master, zone, tt, &local, maxReceivedBytes);
  unsigned int nrecords=0;
  Resolver::res_t nop;
  vector<DNSRecord> chunk;
  time_t last=0;
  shared_ptr<SOARecordContent> sr;
  while(axfr.getChunk(nop, &chunk)) {
    for(auto& dr : chunk) {
      if(dr.d_type==QType::NS || dr.d_type==QType::TSIG) {
	continue;
      }

      dr.d_name.makeUsRelative(zone);
      if(dr.d_type==QType::SOA) {
	sr = getRR<SOARecordContent>(dr);
	continue;
      }

      RPZRecordToPolicy(dr, target, polName, true, defpol, place);
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

// this function is silent - you do the logging
int loadRPZFromFile(const std::string& fname, DNSFilterEngine& target, std::shared_ptr<const std::string> polName, boost::optional<DNSFilterEngine::Policy> defpol, int place)
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
      }
      else if(dr.d_type == QType::NS) {
	continue;
      }
      else {
	dr.d_name=dr.d_name.makeRelative(domain);
	RPZRecordToPolicy(dr, target, polName, true, defpol, place);
      }
    }
    catch(PDNSException& pe) {
      throw PDNSException("Issue parsing '"+drr.qname.toString()+"' '"+drr.content+"' at "+zpt.getLineOfFile()+": "+pe.reason);
    }
  }
  
  return place;
}
