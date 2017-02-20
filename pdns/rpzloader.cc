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
  /*
   * why 2?, the minimally valid IPv6 address that can be encoded in an RPZ is
   * $NETMASK.zz (::/$NETMASK)
   * Terrible right?
   */
  if(parts.size() < 2 || parts.size() > 9)
    throw PDNSException("Invalid IP address in RPZ: "+name.toString());

  bool isV6 = (stoi(parts[0]) > 32);
  bool hadZZ = false;

  for (auto &part : parts) {
    // Check if we have an IPv4 octet
    for (auto c : part)
      if (!isdigit(c))
        isV6 = true;

    if (pdns_iequals(part,"zz")) {
      if (hadZZ)
        throw PDNSException("more than one 'zz' label found in RPZ name"+name.toString());
      part = "";
      isV6 = true;
      hadZZ = true;
    }
  }

  if (isV6 && parts.size() < 9 && !hadZZ)
    throw PDNSException("No 'zz' label found in an IPv6 RPZ name shorter than 9 elements: "+name.toString());

  if (parts.size() == 5 && !isV6)
    return Netmask(parts[4]+"."+parts[3]+"."+parts[2]+"."+parts[1]+"/"+parts[0]);

  string v6;

  for (uint8_t i = parts.size()-1 ; i > 0; i--) {
    v6 += parts[i];
    if (parts[i] == "" && i == 1 && i == parts.size()-1)
        v6+= "::";
    if (parts[i] == "" && i != parts.size()-1)
        v6+= ":";
    if (parts[i] != "" && i != 1)
      v6 += ":";
  }
  v6 += "/" + parts[0];

  return Netmask(v6);
}

void RPZRecordToPolicy(const DNSRecord& dr, DNSFilterEngine& target, bool addOrRemove, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL, size_t place)
{
  static const DNSName drop("rpz-drop."), truncate("rpz-tcp-only."), noaction("rpz-passthru.");
  static const DNSName rpzClientIP("rpz-client-ip"), rpzIP("rpz-ip"),
    rpzNSDname("rpz-nsdname"), rpzNSIP("rpz-nsip.");

  DNSFilterEngine::Policy pol;

  if(dr.d_class != QClass::IN) {
    return;
  }

  if(dr.d_type == QType::CNAME) {
    auto crc = getRR<CNAMERecordContent>(dr);
    if (!crc) {
      return;
    }
    auto crcTarget=crc->getTarget();
    if(defpol) {
      pol=*defpol;
    }
    else if(crcTarget.isRoot()) {
      // cerr<<"Wants NXDOMAIN for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::NXDOMAIN;
    } else if(crcTarget==g_wildcarddnsname) {
      // cerr<<"Wants NODATA for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::NODATA;
    }
    else if(crcTarget==drop) {
      // cerr<<"Wants DROP for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
    }
    else if(crcTarget==truncate) {
      // cerr<<"Wants TRUNCATE for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::Truncate;
    }
    else if(crcTarget==noaction) {
      // cerr<<"Wants NOACTION for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::NoAction;
    }
    else {
      pol.d_kind = DNSFilterEngine::PolicyKind::Custom;
      pol.d_custom = dr.d_content;
      // cerr<<"Wants custom "<<crcTarget<<" for "<<dr.d_name<<": ";
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

  if (!defpol || defpol->d_ttl < 0) {
    pol.d_ttl = static_cast<int32_t>(std::min(maxTTL, dr.d_ttl));
  } else {
    pol.d_ttl = static_cast<int32_t>(std::min(maxTTL, static_cast<uint32_t>(pol.d_ttl)));
  }

  // now to DO something with that
  
  if(dr.d_name.isPartOf(rpzNSDname)) {
    DNSName filt=dr.d_name.makeRelative(rpzNSDname);
    if(addOrRemove)
      target.addNSTrigger(filt, pol, place);
    else
      target.rmNSTrigger(filt, pol, place);
  } else 	if(dr.d_name.isPartOf(rpzClientIP)) {
    DNSName filt=dr.d_name.makeRelative(rpzClientIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      target.addClientTrigger(nm, pol, place);
    else
      target.rmClientTrigger(nm, pol, place);
    
  } else 	if(dr.d_name.isPartOf(rpzIP)) {
    // cerr<<"Should apply answer content IP policy: "<<dr.d_name<<endl;
    DNSName filt=dr.d_name.makeRelative(rpzIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      target.addResponseTrigger(nm, pol, place);
    else
      target.rmResponseTrigger(nm, pol, place);
  } else if(dr.d_name.isPartOf(rpzNSIP)) {
    DNSName filt=dr.d_name.makeRelative(rpzNSIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      target.addNSIPTrigger(nm, pol, place);
    else
      target.rmNSIPTrigger(nm, pol, place);
  } else {
    if(addOrRemove)
      target.addQNameTrigger(dr.d_name, pol, place);
    else
      target.rmQNameTrigger(dr.d_name, pol, place);
  }
}

shared_ptr<SOARecordContent> loadRPZFromServer(const ComboAddress& master, const DNSName& zone, DNSFilterEngine& target, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL, size_t place, const TSIGTriplet& tt, size_t maxReceivedBytes, const ComboAddress& localAddress)
{
  L<<Logger::Warning<<"Loading RPZ zone '"<<zone<<"' from "<<master.toStringWithPort()<<endl;
  if(!tt.name.empty())
    L<<Logger::Warning<<"With TSIG key '"<<tt.name<<"' of algorithm '"<<tt.algo<<"'"<<endl;

  ComboAddress local(localAddress);
  if (local == ComboAddress())
    local = getQueryLocalAddress(master.sin4.sin_family, 0);

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

      RPZRecordToPolicy(dr, target, true, defpol, maxTTL, place);
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
int loadRPZFromFile(const std::string& fname, DNSFilterEngine& target, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL, size_t place)
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
	RPZRecordToPolicy(dr, target, true, defpol, maxTTL, place);
      }
    }
    catch(PDNSException& pe) {
      throw PDNSException("Issue parsing '"+drr.qname.toString()+"' '"+drr.content+"' at "+zpt.getLineOfFile()+": "+pe.reason);
    }
  }
  
  return place;
}
