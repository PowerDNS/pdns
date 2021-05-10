#include "arguments.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "ixfr.hh"
#include "syncres.hh"
#include "axfr-retriever.hh"
#include "lock.hh"
#include "logger.hh"
#include "logging.hh"
#include "rec-lua-conf.hh"
#include "rpzloader.hh"
#include "zoneparser-tng.hh"
#include "threadname.hh"
#include "query-local-address.hh"

Netmask makeNetmaskFromRPZ(const DNSName& name)
{
  auto parts = name.getRawLabels();
  /*
   * why 2?, the minimally valid IPv6 address that can be encoded in an RPZ is
   * $NETMASK.zz (::/$NETMASK)
   * Terrible right?
   */
  if(parts.size() < 2 || parts.size() > 9)
    throw PDNSException("Invalid IP address in RPZ: "+name.toLogString());

  bool isV6 = (stoi(parts[0]) > 32);
  bool hadZZ = false;

  for (auto &part : parts) {
    // Check if we have an IPv4 octet
    for (auto c : part)
      if (!isdigit(c))
        isV6 = true;

    if (pdns_iequals(part,"zz")) {
      if (hadZZ)
        throw PDNSException("more than one 'zz' label found in RPZ name"+name.toLogString());
      part = "";
      isV6 = true;
      hadZZ = true;
    }
  }

  if (isV6 && parts.size() < 9 && !hadZZ)
    throw PDNSException("No 'zz' label found in an IPv6 RPZ name shorter than 9 elements: "+name.toLogString());

  if (parts.size() == 5 && !isV6)
    return Netmask(parts[4]+"."+parts[3]+"."+parts[2]+"."+parts[1]+"/"+parts[0]);

  string v6;

  if (parts[parts.size()-1] == "") {
    v6 += ":";
  }
  for (uint8_t i = parts.size()-1 ; i > 0; i--) {
    v6 += parts[i];
    if (i > 1 || (i == 1 && parts[i] == "")) {
      v6 += ":";
    }
  }
  v6 += "/" + parts[0];

  return Netmask(v6);
}

static void RPZRecordToPolicy(const DNSRecord& dr, std::shared_ptr<DNSFilterEngine::Zone> zone, bool addOrRemove, boost::optional<DNSFilterEngine::Policy> defpol, bool defpolOverrideLocal, uint32_t maxTTL)
{
  static const DNSName drop("rpz-drop."), truncate("rpz-tcp-only."), noaction("rpz-passthru.");
  static const DNSName rpzClientIP("rpz-client-ip"), rpzIP("rpz-ip"),
    rpzNSDname("rpz-nsdname"), rpzNSIP("rpz-nsip.");
  static const std::string rpzPrefix("rpz-");

  DNSFilterEngine::Policy pol;
  bool defpolApplied = false;

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
      defpolApplied = true;
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
      g_log<<Logger::Info<<"Discarding unsupported RPZ entry "<<crcTarget<<" for "<<dr.d_name<<endl;
      return;
    }
    else {
      pol.d_kind = DNSFilterEngine::PolicyKind::Custom;
      pol.d_custom.emplace_back(dr.d_content);
      // cerr<<"Wants custom "<<crcTarget<<" for "<<dr.d_name<<": ";
    }
  }
  else {
    if (defpol && defpolOverrideLocal) {
      pol=*defpol;
      defpolApplied = true;
    }
    else {
      pol.d_kind = DNSFilterEngine::PolicyKind::Custom;
      pol.d_custom.emplace_back(dr.d_content);
      // cerr<<"Wants custom "<<dr.d_content->getZoneRepresentation()<<" for "<<dr.d_name<<": ";
    }
  }

  if (!defpolApplied || defpol->d_ttl < 0) {
    pol.d_ttl = static_cast<int32_t>(std::min(maxTTL, dr.d_ttl));
  } else {
    pol.d_ttl = static_cast<int32_t>(std::min(maxTTL, static_cast<uint32_t>(pol.d_ttl)));
  }

  // now to DO something with that

  if(dr.d_name.isPartOf(rpzNSDname)) {
    DNSName filt=dr.d_name.makeRelative(rpzNSDname);
    if(addOrRemove)
      zone->addNSTrigger(filt, std::move(pol), defpolApplied);
    else
      zone->rmNSTrigger(filt, std::move(pol));
  } else if(dr.d_name.isPartOf(rpzClientIP)) {
    DNSName filt=dr.d_name.makeRelative(rpzClientIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      zone->addClientTrigger(nm, std::move(pol), defpolApplied);
    else
      zone->rmClientTrigger(nm, std::move(pol));
    
  } else if(dr.d_name.isPartOf(rpzIP)) {
    // cerr<<"Should apply answer content IP policy: "<<dr.d_name<<endl;
    DNSName filt=dr.d_name.makeRelative(rpzIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      zone->addResponseTrigger(nm, std::move(pol), defpolApplied);
    else
      zone->rmResponseTrigger(nm, std::move(pol));
  } else if(dr.d_name.isPartOf(rpzNSIP)) {
    DNSName filt=dr.d_name.makeRelative(rpzNSIP);
    auto nm=makeNetmaskFromRPZ(filt);
    if(addOrRemove)
      zone->addNSIPTrigger(nm, std::move(pol), defpolApplied);
    else
      zone->rmNSIPTrigger(nm, std::move(pol));
  } else {
    if(addOrRemove) {
      /* if we did override the existing policy with the default policy,
         we might turn two A or AAAA into a CNAME, which would trigger
         an exception. Let's just ignore it. */
      zone->addQNameTrigger(dr.d_name, std::move(pol), defpolApplied);
    }
    else {
      zone->rmQNameTrigger(dr.d_name, std::move(pol));
    }
  }
}

static shared_ptr<SOARecordContent> loadRPZFromServer(const shared_ptr<Logr::Logger>& plogger, const ComboAddress& primary, const DNSName& zoneName, std::shared_ptr<DNSFilterEngine::Zone> zone, boost::optional<DNSFilterEngine::Policy> defpol, bool defpolOverrideLocal, uint32_t maxTTL, const TSIGTriplet& tt, size_t maxReceivedBytes, const ComboAddress& localAddress, uint16_t axfrTimeout)
{

  auto logger = plogger->withValues("primary", Logging::Loggable(primary));
  logger->info(Logr::Info, "Loading RPZ from nameserver");
  logger = logger->v(1);
  if(!tt.name.empty()) {
    logger->info(Logr::Info, "Using TSIG key for authentication", "tsig_key_name", Logging::Loggable(tt.name), "tsig_key_algorithm", Logging::Loggable(tt.algo));
  }

  ComboAddress local(localAddress);
  if (local == ComboAddress())
    local = pdns::getQueryLocalAddress(primary.sin4.sin_family, 0);

  AXFRRetriever axfr(primary, zoneName, tt, &local, maxReceivedBytes, axfrTimeout);
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

      RPZRecordToPolicy(dr, zone, true, defpol, defpolOverrideLocal, maxTTL);
      nrecords++;
    } 
    axfrNow = time(nullptr);
    if (axfrNow < axfrStart || axfrNow - axfrStart > axfrTimeout) {
      throw PDNSException("Total AXFR time exceeded!");
    }
    if(last != time(0)) {
      logger->info(Logr::Info, "RPZ load in progress", "nrecords", Logging::Loggable(nrecords));
      last=time(0);
    }
  }
  logger->info(Logr::Info, "RPZ load completed", "nrecords", Logging::Loggable(nrecords), "soa", Logging::Loggable(sr->getZoneRepresentation()));
  return sr;
}

// this function is silent - you do the logging
std::shared_ptr<SOARecordContent> loadRPZFromFile(const std::string& fname, std::shared_ptr<DNSFilterEngine::Zone> zone, boost::optional<DNSFilterEngine::Policy> defpol, bool defpolOverrideLocal, uint32_t maxTTL)
{
  shared_ptr<SOARecordContent> sr = nullptr;
  ZoneParserTNG zpt(fname);
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
  DNSResourceRecord drr;
  DNSName domain;
  while(zpt.get(drr)) {
    try {
      if(drr.qtype.getCode() == QType::CNAME && drr.content.empty())
	drr.content=".";
      DNSRecord dr(drr);
      if(dr.d_type == QType::SOA) {
        sr = getRR<SOARecordContent>(dr);
        domain = dr.d_name;
        zone->setDomain(domain);
      }
      else if(dr.d_type == QType::NS) {
	continue;
      }
      else {
	dr.d_name=dr.d_name.makeRelative(domain);
	RPZRecordToPolicy(dr, zone, true, defpol, defpolOverrideLocal, maxTTL);
      }
    }
    catch(const PDNSException& pe) {
      throw PDNSException("Issue parsing '"+drr.qname.toLogString()+"' '"+drr.content+"' at "+zpt.getLineOfFile()+": "+pe.reason);
    }
  }

  if (sr != nullptr) {
    zone->setRefresh(sr->d_st.refresh);
  }
  return sr;
}

static LockGuarded<std::unordered_map<std::string, shared_ptr<rpzStats> > > s_rpzStats;

shared_ptr<rpzStats> getRPZZoneStats(const std::string& zone)
{
  auto stats = s_rpzStats.lock();
  auto it = stats->find(zone);
  if (it == stats->end()) {
    auto stat = std::make_shared<rpzStats>();
    (*stats)[zone] = stat;
    return stat;
  }
  return it->second;
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

static bool dumpZoneToDisk(const shared_ptr<Logr::Logger>& plogger, const DNSName& zoneName, const std::shared_ptr<DNSFilterEngine::Zone>& newZone, const std::string& dumpZoneFileName)
{
  auto logger = plogger->v(1);
  logger->info("Dumping zone to disk", "destination_file", Logging::Loggable(dumpZoneFileName));
  std::string temp = dumpZoneFileName + "XXXXXX";
  int fd = mkstemp(&temp.at(0));
  if (fd < 0) {
    logger->error(Logr::Warning, errno, "Unable to create temporary file");
    return false;
  }

  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(fd, "w+"), fclose);
  if (!fp) {
    int err = errno;
    close(fd);
    logger->error(Logr::Warning, err, "Unable to open file pointer");
    return false;
  }
  fd = -1;

  try {
    newZone->dump(fp.get());
  }
  catch(const std::exception& e) {
    logger->error(Logr::Warning, e.what(), "Error while dumping the content of the RPZ");
    return false;
  }

  if (fflush(fp.get()) != 0) {
    logger->error(Logr::Warning, errno, "Error while flushing the content of the RPZ");
    return false;
  }

  if (fsync(fileno(fp.get())) != 0) {
    logger->error(Logr::Warning, errno, "Error while syncing the content of the RPZ");
    return false;
  }

  if (fclose(fp.release()) != 0) {
    logger->error(Logr::Warning, errno, "Error while writing the content of the RPZ");
    return false;
  }

  if (rename(temp.c_str(), dumpZoneFileName.c_str()) != 0) {
    logger->error(Logr::Warning, errno, "Error while moving the content of the RPZ", "destination_file", Logging::Loggable(dumpZoneFileName));
    return false;
  }

  return true;
}

void RPZIXFRTracker(const std::vector<ComboAddress>& primaries, boost::optional<DNSFilterEngine::Policy> defpol, bool defpolOverrideLocal, uint32_t maxTTL, size_t zoneIdx, const TSIGTriplet& tt, size_t maxReceivedBytes, const ComboAddress& localAddress, const uint16_t axfrTimeout, const uint32_t refreshFromConf, std::shared_ptr<SOARecordContent> sr, std::string dumpZoneFileName, uint64_t configGeneration)
{
  setThreadName("pdns-r/RPZIXFR");
  bool isPreloaded = sr != nullptr;
  auto luaconfsLocal = g_luaconfs.getLocal();

  auto logger = g_slog->withName("rpz")->v(1);

  /* we can _never_ modify this zone directly, we need to do a full copy then replace the existing zone */
  std::shared_ptr<DNSFilterEngine::Zone> oldZone = luaconfsLocal->dfe.getZone(zoneIdx);
  if (!oldZone) {
    logger->error(Logr::Error, "Unable to retrieve RPZ zone from configuration", "index", Logging::Loggable(zoneIdx));
    return;
  }

  // If oldZone failed to load its getRefresh() returns 0, protect against that
  uint32_t refresh = std::max(refreshFromConf ? refreshFromConf : oldZone->getRefresh(), 10U);
  DNSName zoneName = oldZone->getDomain();
  std::string polName = oldZone->getName().empty() ? oldZone->getName() : zoneName.toString();

  // Now that we know the name, set it in the logger
  logger = logger->withValues("zone", Logging::Loggable(zoneName));

  while (!sr) {
    /* if we received an empty sr, the zone was not really preloaded */

    /* full copy, as promised */
    std::shared_ptr<DNSFilterEngine::Zone> newZone = std::make_shared<DNSFilterEngine::Zone>(*oldZone);
    for (const auto& primary : primaries) {
      try {
        sr = loadRPZFromServer(logger, primary, zoneName, newZone, defpol, defpolOverrideLocal, maxTTL, tt, maxReceivedBytes, localAddress, axfrTimeout);
        newZone->setSerial(sr->d_st.serial);
        newZone->setRefresh(sr->d_st.refresh);
        refresh = std::max(refreshFromConf ? refreshFromConf : newZone->getRefresh(), 1U);
        setRPZZoneNewState(polName, sr->d_st.serial, newZone->size(), true);

        g_luaconfs.modify([zoneIdx, &newZone](LuaConfigItems& lci) {
            lci.dfe.setZone(zoneIdx, newZone);
          });

        if (!dumpZoneFileName.empty()) {
          dumpZoneToDisk(logger, zoneName, newZone, dumpZoneFileName);
        }

        /* no need to try another primary */
        break;
      }
      catch(const std::exception& e) {
        logger->info(Logr::Warning, "Unable to load RPZ zone, will retry", "from", Logging::Loggable(primary), "exception", Logging::Loggable(e.what()), "refresh", Logging::Loggable(refresh));
        incRPZFailedTransfers(polName);
      }
      catch(const PDNSException& e) {
        logger->info(Logr::Warning, "Unable to load RPZ zone, will retry", "from", Logging::Loggable(primary), "exception", Logging::Loggable(e.reason), "refresh", Logging::Loggable(refresh));
        incRPZFailedTransfers(polName);
      }
    }

    if (!sr) {
      sleep(refresh);
    }
  }

  bool skipRefreshDelay = isPreloaded;

  for(;;) {
    DNSRecord dr;
    dr.d_content=sr;

    if (skipRefreshDelay) {
      skipRefreshDelay = false;
    }
    else {
      sleep(refresh);
    }

    if (luaconfsLocal->generation != configGeneration) {
      /* the configuration has been reloaded, meaning that a new thread
         has been started to handle that zone and we are now obsolete.
      */
      g_log<<Logger::Info<<"A more recent configuration has been found, stopping the existing RPZ update thread for "<<zoneName<<endl;
      return;
    }

    vector<pair<vector<DNSRecord>, vector<DNSRecord> > > deltas;
    for (const auto& primary : primaries) {
      g_log<<Logger::Info<<"Getting IXFR deltas for "<<zoneName<<" from "<<primary.toStringWithPort()<<", our serial: "<<getRR<SOARecordContent>(dr)->d_st.serial<<endl;

      ComboAddress local(localAddress);
      if (local == ComboAddress()) {
        local = pdns::getQueryLocalAddress(primary.sin4.sin_family, 0);
      }

      try {
        deltas = getIXFRDeltas(primary, zoneName, dr, tt, &local, maxReceivedBytes);

        /* no need to try another primary */
        break;
      } catch(const std::runtime_error& e ){
        g_log<<Logger::Warning<<e.what()<<endl;
        incRPZFailedTransfers(polName);
        continue;
      }
    }

    if(deltas.empty()) {
      continue;
    }

    try {
      g_log<<Logger::Info<<"Processing "<<deltas.size()<<" delta"<<addS(deltas)<<" for RPZ "<<zoneName<<endl;

      if (luaconfsLocal->generation != configGeneration) {
        g_log<<Logger::Info<<"A more recent configuration has been found, stopping the existing RPZ update thread for "<<zoneName<<endl;
        return;
      }
      oldZone = luaconfsLocal->dfe.getZone(zoneIdx);
      if (!oldZone || oldZone->getDomain() != zoneName) {
        g_log<<Logger::Info<<"This policy is no more, stopping the existing RPZ update thread for "<<zoneName << endl;
        return;
      }
      /* we need to make a _full copy_ of the zone we are going to work on */
      std::shared_ptr<DNSFilterEngine::Zone> newZone = std::make_shared<DNSFilterEngine::Zone>(*oldZone);
      /* initialize the current serial to the last one */
      std::shared_ptr<SOARecordContent> currentSR = sr;

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
            if (oldsr && oldsr->d_st.serial == currentSR->d_st.serial) {
              //	    cout<<"Got good removal of SOA serial "<<oldsr->d_st.serial<<endl;
            }
            else {
              if (!oldsr) {
                throw std::runtime_error("Unable to extract serial from SOA record while processing the removal part of an update");
              }
              else {
                throw std::runtime_error("Received an unexpected serial (" + std::to_string(oldsr->d_st.serial) + ", expecting " + std::to_string(currentSR->d_st.serial) + ") from SOA record while processing the removal part of an update");
              }
            }
          }
          else {
            totremove++;
            g_log<<(g_logRPZChanges ? Logger::Info : Logger::Debug)<<"Had removal of "<<rr.d_name<<" from RPZ zone "<<zoneName<<endl;
            RPZRecordToPolicy(rr, newZone, false, defpol, defpolOverrideLocal, maxTTL);
          }
        }

        for(const auto& rr : add) { // should always contain the new SOA
          if(rr.d_type == QType::NS)
            continue;
          if(rr.d_type == QType::SOA) {
            auto tempSR = getRR<SOARecordContent>(rr);
            //	  g_log<<Logger::Info<<"New SOA serial for "<<zoneName<<": "<<currentSR->d_st.serial<<endl;
            if (tempSR) {
              currentSR = tempSR;
            }
          }
          else {
            totadd++;
            g_log<<(g_logRPZChanges ? Logger::Info : Logger::Debug)<<"Had addition of "<<rr.d_name<<" to RPZ zone "<<zoneName<<endl;
            RPZRecordToPolicy(rr, newZone, true, defpol, defpolOverrideLocal, maxTTL);
          }
        }
      }

      /* only update sr now that all changes have been converted */
      if (currentSR) {
        sr = currentSR;
      }
      g_log<<Logger::Info<<"Had "<<totremove<<" RPZ removal"<<addS(totremove)<<", "<<totadd<<" addition"<<addS(totadd)<<" for "<<zoneName<<" New serial: "<<sr->d_st.serial<<endl;
      newZone->setSerial(sr->d_st.serial);
      newZone->setRefresh(sr->d_st.refresh);
      setRPZZoneNewState(polName, sr->d_st.serial, newZone->size(), fullUpdate);

      /* we need to replace the existing zone with the new one,
         but we don't want to touch anything else, especially other zones,
         since they might have been updated by another RPZ IXFR tracker thread.
      */
      if (luaconfsLocal->generation != configGeneration) {
        g_log<<Logger::Info<<"A more recent configuration has been found, stopping the existing RPZ update thread for "<<zoneName<<endl;
        return;
      }
      g_luaconfs.modify([zoneIdx, &newZone](LuaConfigItems& lci) {
                          lci.dfe.setZone(zoneIdx, newZone);
                        });

      if (!dumpZoneFileName.empty()) {
        dumpZoneToDisk(logger, zoneName, newZone, dumpZoneFileName);
      }
      refresh = std::max(refreshFromConf ? refreshFromConf : newZone->getRefresh(), 1U);
    }
    catch (const std::exception& e) {
      g_log << Logger::Error << "Error while applying the update received over XFR for "<<zoneName<<", skipping the update: "<< e.what() <<endl;
    }
  }
}
