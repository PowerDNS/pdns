#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "ixfr.hh"
#include "syncres.hh"
#include "resolver.hh"
#include "logger.hh"
#include "rec-lua-conf.hh"
#include "rpzloader.hh"
#include "zoneparser-tng.hh"

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

void RPZRecordToPolicy(const DNSRecord& dr, std::shared_ptr<DNSFilterEngine::Zone> zone, bool addOrRemove, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL)
{
  static const DNSName drop("rpz-drop."), truncate("rpz-tcp-only."), noaction("rpz-passthru.");
  static const DNSName rpzClientIP("rpz-client-ip"), rpzIP("rpz-ip"),
    rpzNSDname("rpz-nsdname"), rpzNSIP("rpz-nsip.");
  static const std::string rpzPrefix("rpz-");

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
    /* "The special RPZ encodings which are not to be taken as Local Data are
       CNAMEs with targets that are:
       +  "."  (NXDOMAIN action),
       +  "*." (NODATA action),
       +  a top level domain starting with "rpz-",
       +  a child of a top level domain starting with "rpz-".
    */
    else if(!crcTarget.empty() && !crcTarget.isRoot() && crcTarget.getRawLabel(crcTarget.countLabels() - 1).compare(0, rpzPrefix.length(), rpzPrefix) == 0) {
      /* this is very likely an higher format number or a configuration error,
         let's just ignore it. */
      g_log<<Logger::Info<<"Discarding unsupported RPZ entry "<<crcTarget.toString()<<" for "<<dr.d_name<<endl;
      return;
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
      zone->addNSTrigger(filt, pol);
    else
      zone->rmNSTrigger(filt, pol);
  } else if(dr.d_name.isPartOf(rpzClientIP)) {
    DNSName filt=dr.d_name.makeRelative(rpzClientIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      zone->addClientTrigger(nm, pol);
    else
      zone->rmClientTrigger(nm, pol);
    
  } else if(dr.d_name.isPartOf(rpzIP)) {
    // cerr<<"Should apply answer content IP policy: "<<dr.d_name<<endl;
    DNSName filt=dr.d_name.makeRelative(rpzIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      zone->addResponseTrigger(nm, pol);
    else
      zone->rmResponseTrigger(nm, pol);
  } else if(dr.d_name.isPartOf(rpzNSIP)) {
    DNSName filt=dr.d_name.makeRelative(rpzNSIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      zone->addNSIPTrigger(nm, pol);
    else
      zone->rmNSIPTrigger(nm, pol);
  } else {
    if(addOrRemove)
      zone->addQNameTrigger(dr.d_name, pol);
    else
      zone->rmQNameTrigger(dr.d_name, pol);
  }
}

shared_ptr<SOARecordContent> loadRPZFromServer(const ComboAddress& master, const DNSName& zoneName, std::shared_ptr<DNSFilterEngine::Zone> zone, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL, const TSIGTriplet& tt, size_t maxReceivedBytes, const ComboAddress& localAddress, uint16_t axfrTimeout)
{
  g_log<<Logger::Warning<<"Loading RPZ zone '"<<zoneName<<"' from "<<master.toStringWithPort()<<endl;
  if(!tt.name.empty())
    g_log<<Logger::Warning<<"With TSIG key '"<<tt.name<<"' of algorithm '"<<tt.algo<<"'"<<endl;

  ComboAddress local(localAddress);
  if (local == ComboAddress())
    local = getQueryLocalAddress(master.sin4.sin_family, 0);

  AXFRRetriever axfr(master, zoneName, tt, &local, maxReceivedBytes);
  unsigned int nrecords=0;
  Resolver::res_t nop;
  vector<DNSRecord> chunk;
  time_t last=0;
  time_t axfrStart = time(nullptr);
  time_t axfrNow = time(nullptr);
  shared_ptr<SOARecordContent> sr;
  while(axfr.getChunk(nop, &chunk, (axfrStart + axfrTimeout - axfrNow))) {
    for(auto& dr : chunk) {
      if(dr.d_type==QType::NS || dr.d_type==QType::TSIG) {
	continue;
      }

      dr.d_name.makeUsRelative(zoneName);
      if(dr.d_type==QType::SOA) {
	sr = getRR<SOARecordContent>(dr);
	continue;
      }

      RPZRecordToPolicy(dr, zone, true, defpol, maxTTL);
      nrecords++;
    } 
    axfrNow = time(nullptr);
    if (axfrNow < axfrStart || axfrNow - axfrStart > axfrTimeout) {
      throw PDNSException("Total AXFR time exceeded!");
    }
    if(last != time(0)) {
      g_log<<Logger::Info<<"Loaded & indexed "<<nrecords<<" policy records so far"<<endl;
      last=time(0);
    }
  }
  g_log<<Logger::Info<<"Done: "<<nrecords<<" policy records active, SOA: "<<sr->getZoneRepresentation()<<endl;
  return sr;
}

// this function is silent - you do the logging
void loadRPZFromFile(const std::string& fname, std::shared_ptr<DNSFilterEngine::Zone> zone, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL)
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
        zone->setDomain(domain);
      }
      else if(dr.d_type == QType::NS) {
	continue;
      }
      else {
	dr.d_name=dr.d_name.makeRelative(domain);
	RPZRecordToPolicy(dr, zone, true, defpol, maxTTL);
      }
    }
    catch(const PDNSException& pe) {
      throw PDNSException("Issue parsing '"+drr.qname.toString()+"' '"+drr.content+"' at "+zpt.getLineOfFile()+": "+pe.reason);
    }
  }
}

static std::unordered_map<std::string, shared_ptr<rpzStats> > s_rpzStats;
static std::mutex s_rpzStatsMutex;

shared_ptr<rpzStats> getRPZZoneStats(const std::string& zone)
{
  std::lock_guard<std::mutex> l(s_rpzStatsMutex);
  if (s_rpzStats.find(zone) == s_rpzStats.end()) {
    s_rpzStats[zone] = std::make_shared<rpzStats>();
  }
  return s_rpzStats[zone];
}

static void incRPZFailedTransfers(const std::string& zone)
{
  auto stats = getRPZZoneStats(zone);
  if (stats != nullptr)
    stats->d_failedTransfers++;
}

static void setRPZZoneNewState(const std::string& zone, uint32_t serial, uint64_t numberOfRecords, bool wasAXFR)
{
  auto stats = getRPZZoneStats(zone);
  if (stats == nullptr)
    return;
  stats->d_successfulTransfers++;
  if (wasAXFR) {
    stats->d_fullTransfers++;
  }
  stats->d_lastUpdate = time(nullptr);
  stats->d_serial = serial;
  stats->d_numberOfRecords = numberOfRecords;
}

void RPZIXFRTracker(const ComboAddress& master, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL, size_t zoneIdx, const TSIGTriplet& tt, size_t maxReceivedBytes, const ComboAddress& localAddress, std::shared_ptr<DNSFilterEngine::Zone> zone, const uint16_t axfrTimeout)
{
  uint32_t refresh = zone->getRefresh();
  DNSName zoneName = zone->getDomain();
  std::string polName = zone->getName() ? *(zone->getName()) : zoneName.toString();
  shared_ptr<SOARecordContent> sr;

  while (!sr) {
    try {
      sr=loadRPZFromServer(master, zoneName, zone, defpol, maxTTL, tt, maxReceivedBytes, localAddress, axfrTimeout);
      if(refresh == 0) {
        refresh = sr->d_st.refresh;
      }
      zone->setSerial(sr->d_st.serial);
      setRPZZoneNewState(polName, sr->d_st.serial, zone->size(), true);
    }
    catch(const std::exception& e) {
      g_log<<Logger::Warning<<"Unable to load RPZ zone '"<<zoneName<<"' from '"<<master<<"': '"<<e.what()<<"'. (Will try again in "<<refresh<<" seconds...)"<<endl;
      incRPZFailedTransfers(polName);
    }
    catch(const PDNSException& e) {
      g_log<<Logger::Warning<<"Unable to load RPZ zone '"<<zoneName<<"' from '"<<master<<"': '"<<e.reason<<"'. (Will try again in "<<refresh<<" seconds...)"<<endl;
      incRPZFailedTransfers(polName);
    }

    if (!sr) {
      if (refresh == 0) {
        sleep(10);
      } else {
        sleep(refresh);
      }
    }
  }

  for(;;) {
    DNSRecord dr;
    dr.d_content=sr;

    sleep(refresh);

    g_log<<Logger::Info<<"Getting IXFR deltas for "<<zoneName<<" from "<<master.toStringWithPort()<<", our serial: "<<getRR<SOARecordContent>(dr)->d_st.serial<<endl;
    vector<pair<vector<DNSRecord>, vector<DNSRecord> > > deltas;

    ComboAddress local(localAddress);
    if (local == ComboAddress())
      local = getQueryLocalAddress(master.sin4.sin_family, 0);

    try {
      deltas = getIXFRDeltas(master, zoneName, dr, tt, &local, maxReceivedBytes);
    } catch(std::runtime_error& e ){
      g_log<<Logger::Warning<<e.what()<<endl;
      incRPZFailedTransfers(polName);
      continue;
    }
    if(deltas.empty())
      continue;
    g_log<<Logger::Info<<"Processing "<<deltas.size()<<" delta"<<addS(deltas)<<" for RPZ "<<zoneName<<endl;

    auto luaconfsLocal = g_luaconfs.getLocal();
    const std::shared_ptr<DNSFilterEngine::Zone> oldZone = luaconfsLocal->dfe.getZone(zoneIdx);
    /* we need to make a _full copy_ of the zone we are going to work on */
    std::shared_ptr<DNSFilterEngine::Zone> newZone = std::make_shared<DNSFilterEngine::Zone>(*oldZone);

    int totremove=0, totadd=0;
    bool fullUpdate = false;
    for(const auto& delta : deltas) {
      const auto& remove = delta.first;
      const auto& add = delta.second;
      if(remove.empty()) {
        g_log<<Logger::Warning<<"IXFR update is a whole new zone"<<endl;
        newZone->clear();
        fullUpdate = true;
      }
      for(const auto& rr : remove) { // should always contain the SOA
        if(rr.d_type == QType::NS)
          continue;
	if(rr.d_type == QType::SOA) {
	  auto oldsr = getRR<SOARecordContent>(rr);
	  if(oldsr && oldsr->d_st.serial == sr->d_st.serial) {
	    //	    cout<<"Got good removal of SOA serial "<<oldsr->d_st.serial<<endl;
	  }
	  else
	    g_log<<Logger::Error<<"GOT WRONG SOA SERIAL REMOVAL, SHOULD TRIGGER WHOLE RELOAD"<<endl;
	}
	else {
          totremove++;
	  g_log<<(g_logRPZChanges ? Logger::Info : Logger::Debug)<<"Had removal of "<<rr.d_name<<" from RPZ zone "<<zoneName<<endl;
	  RPZRecordToPolicy(rr, newZone, false, defpol, maxTTL);
	}
      }

      for(const auto& rr : add) { // should always contain the new SOA
        if(rr.d_type == QType::NS)
          continue;
	if(rr.d_type == QType::SOA) {
	  auto newsr = getRR<SOARecordContent>(rr);
	  //	  g_log<<Logger::Info<<"New SOA serial for "<<zoneName<<": "<<newsr->d_st.serial<<endl;
	  if (newsr) {
	    sr = newsr;
	  }
	}
	else {
          totadd++;
	  g_log<<(g_logRPZChanges ? Logger::Info : Logger::Debug)<<"Had addition of "<<rr.d_name<<" to RPZ zone "<<zoneName<<endl;
	  RPZRecordToPolicy(rr, newZone, true, defpol, maxTTL);
	}
      }
    }
    g_log<<Logger::Info<<"Had "<<totremove<<" RPZ removal"<<addS(totremove)<<", "<<totadd<<" addition"<<addS(totadd)<<" for "<<zoneName<<" New serial: "<<sr->d_st.serial<<endl;
    newZone->setSerial(sr->d_st.serial);
    setRPZZoneNewState(polName, sr->d_st.serial, newZone->size(), fullUpdate);

    /* we need to replace the existing zone with the new one,
       but we don't want to touch anything else, especially other zones,
       since they might have been updated by another RPZ IXFR tracker thread.
    */
    g_luaconfs.modify([zoneIdx, &newZone](LuaConfigItems& lci) {
                        lci.dfe.setZone(zoneIdx, newZone);
                      });
  }
}
