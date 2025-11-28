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
#include <condition_variable>
#include "arguments.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "ixfr.hh"
#include "axfr-retriever.hh"
#include "lock.hh"
#include "logging.hh"
#include "rec-lua-conf.hh"
#include "rpzloader.hh"
#include "zoneparser-tng.hh"
#include "threadname.hh"
#include "query-local-address.hh"
#include "rec-system-resolve.hh"

Netmask makeNetmaskFromRPZ(const DNSName& name)
{
  auto parts = name.getRawLabels();
  /*
   * why 2?, the minimally valid IPv6 address that can be encoded in an RPZ is
   * $NETMASK.zz (::/$NETMASK)
   * Terrible right?
   */
  if (parts.size() < 2 || parts.size() > 9) {
    throw PDNSException("Invalid IP address in RPZ: " + name.toLogString());
  }

  bool isV6 = (stoi(parts[0]) > 32);
  bool hadZZ = false;

  for (auto& part : parts) {
    // Check if we have an IPv4 octet
    for (auto labelLetter : part) {
      if (isdigit(labelLetter) == 0) {
        isV6 = true;
      }
    }
    if (pdns_iequals(part, "zz")) {
      if (hadZZ) {
        throw PDNSException("more than one 'zz' label found in RPZ name" + name.toLogString());
      }
      part = "";
      isV6 = true;
      hadZZ = true;
    }
  }

  if (isV6 && parts.size() < 9 && !hadZZ) {
    throw PDNSException("No 'zz' label found in an IPv6 RPZ name shorter than 9 elements: " + name.toLogString());
  }

  if (parts.size() == 5 && !isV6) {
    return parts[4] + "." + parts[3] + "." + parts[2] + "." + parts[1] + "/" + parts[0];
  }
  string v6Address;

  if (parts[parts.size() - 1].empty()) {
    v6Address += ":";
  }
  for (uint8_t i = parts.size() - 1; i > 0; i--) {
    v6Address += parts[i];
    if (i > 1 || (i == 1 && parts[i].empty())) {
      v6Address += ":";
    }
  }
  v6Address += "/" + parts[0];

  return v6Address;
}

static void RPZRecordToPolicy(const DNSRecord& dnsRecord, const std::shared_ptr<DNSFilterEngine::Zone>& zone, bool addOrRemove, const std::optional<DNSFilterEngine::Policy>& defpol, bool defpolOverrideLocal, uint32_t maxTTL, Logr::log_t log)
{
  static const DNSName drop("rpz-drop.");
  static const DNSName truncate("rpz-tcp-only.");
  static const DNSName noaction("rpz-passthru.");
  static const DNSName rpzClientIP("rpz-client-ip");
  static const DNSName rpzIP("rpz-ip");
  static const DNSName rpzNSDname("rpz-nsdname");
  static const DNSName rpzNSIP("rpz-nsip.");
  static const std::string rpzPrefix("rpz-");

  DNSFilterEngine::Policy pol;
  bool defpolApplied = false;

  if (dnsRecord.d_class != QClass::IN) {
    return;
  }

  if (dnsRecord.d_type == QType::CNAME) {
    auto crc = getRR<CNAMERecordContent>(dnsRecord);
    if (!crc) {
      return;
    }
    auto crcTarget = crc->getTarget();
    if (defpol) {
      pol = *defpol;
      defpolApplied = true;
    }
    else if (crcTarget.isRoot()) {
      // cerr<<"Wants NXDOMAIN for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::NXDOMAIN;
    }
    else if (crcTarget == g_wildcarddnsname) {
      // cerr<<"Wants NODATA for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::NODATA;
    }
    else if (crcTarget == drop) {
      // cerr<<"Wants DROP for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::Drop;
    }
    else if (crcTarget == truncate) {
      // cerr<<"Wants TRUNCATE for "<<dr.d_name<<": ";
      pol.d_kind = DNSFilterEngine::PolicyKind::Truncate;
    }
    else if (crcTarget == noaction) {
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
    else if (!crcTarget.empty() && !crcTarget.isRoot() && crcTarget.getRawLabel(crcTarget.countLabels() - 1).compare(0, rpzPrefix.length(), rpzPrefix) == 0) {
      /* this is very likely a higher format number or a configuration error,
         let's just ignore it. */
      log->info(Logr::Info, "Discarding unsupported RPZ entry", "target", Logging::Loggable(crcTarget), "name", Logging::Loggable(dnsRecord.d_name));
      return;
    }
    else {
      pol.d_kind = DNSFilterEngine::PolicyKind::Custom;
      if (!pol.d_custom) {
        pol.d_custom = make_unique<DNSFilterEngine::Policy::CustomData>();
      }
      pol.d_custom->emplace_back(dnsRecord.getContent());
      // cerr<<"Wants custom "<<crcTarget<<" for "<<dr.d_name<<": ";
    }
  }
  else {
    if (defpol && defpolOverrideLocal) {
      pol = *defpol;
      defpolApplied = true;
    }
    else {
      pol.d_kind = DNSFilterEngine::PolicyKind::Custom;
      if (!pol.d_custom) {
        pol.d_custom = make_unique<DNSFilterEngine::Policy::CustomData>();
      }
      pol.d_custom->emplace_back(dnsRecord.getContent());
      // cerr<<"Wants custom "<<dr.d_content->getZoneRepresentation()<<" for "<<dr.d_name<<": ";
    }
  }

  if (!defpolApplied || defpol->d_ttl < 0) {
    pol.d_ttl = static_cast<int32_t>(std::min(maxTTL, dnsRecord.d_ttl));
  }
  else {
    pol.d_ttl = static_cast<int32_t>(std::min(maxTTL, static_cast<uint32_t>(pol.d_ttl)));
  }

  // now to DO something with that

  if (dnsRecord.d_name.isPartOf(rpzNSDname)) {
    DNSName filt = dnsRecord.d_name.makeRelative(rpzNSDname);
    if (addOrRemove) {
      zone->addNSTrigger(filt, std::move(pol), defpolApplied);
    }
    else {
      zone->rmNSTrigger(filt, pol);
    }
  }
  else if (dnsRecord.d_name.isPartOf(rpzClientIP)) {
    DNSName filt = dnsRecord.d_name.makeRelative(rpzClientIP);
    auto netmask = makeNetmaskFromRPZ(filt);
    if (addOrRemove) {
      zone->addClientTrigger(netmask, std::move(pol), defpolApplied);
    }
    else {
      zone->rmClientTrigger(netmask, pol);
    }
  }
  else if (dnsRecord.d_name.isPartOf(rpzIP)) {
    // cerr<<"Should apply answer content IP policy: "<<dr.d_name<<endl;
    DNSName filt = dnsRecord.d_name.makeRelative(rpzIP);
    auto netmask = makeNetmaskFromRPZ(filt);
    if (addOrRemove) {
      zone->addResponseTrigger(netmask, std::move(pol), defpolApplied);
    }
    else {
      zone->rmResponseTrigger(netmask, pol);
    }
  }
  else if (dnsRecord.d_name.isPartOf(rpzNSIP)) {
    DNSName filt = dnsRecord.d_name.makeRelative(rpzNSIP);
    auto netmask = makeNetmaskFromRPZ(filt);
    if (addOrRemove) {
      zone->addNSIPTrigger(netmask, std::move(pol), defpolApplied);
    }
    else {
      zone->rmNSIPTrigger(netmask, pol);
    }
  }
  else {
    if (addOrRemove) {
      /* if we did override the existing policy with the default policy,
         we might turn two A or AAAA into a CNAME, which would trigger
         an exception. Let's just ignore it. */
      zone->addQNameTrigger(dnsRecord.d_name, std::move(pol), defpolApplied);
    }
    else {
      zone->rmQNameTrigger(dnsRecord.d_name, pol);
    }
  }
}

static shared_ptr<const SOARecordContent> loadRPZFromServer(Logr::log_t plogger, const ComboAddress& primary, const DNSName& zoneName, const std::shared_ptr<DNSFilterEngine::Zone>& zone, const std::optional<DNSFilterEngine::Policy>& defpol, bool defpolOverrideLocal, uint32_t maxTTL, const TSIGTriplet& tsigTriplet, size_t maxReceivedBytes, const ComboAddress& localAddress, uint16_t axfrTimeout)
{

  auto logger = plogger->withValues("primary", Logging::Loggable(primary));
  logger->info(Logr::Info, "Loading RPZ from nameserver");
  if (!tsigTriplet.name.empty()) {
    logger->info(Logr::Info, "Using TSIG key for authentication", "tsig_key_name", Logging::Loggable(tsigTriplet.name), "tsig_key_algorithm", Logging::Loggable(tsigTriplet.algo));
  }

  ComboAddress local(localAddress);
  if (local == ComboAddress()) {
    local = pdns::getQueryLocalAddress(primary.sin4.sin_family, 0);
  }

  AXFRRetriever axfr(primary, zoneName, tsigTriplet, &local, maxReceivedBytes, axfrTimeout);
  unsigned int nrecords = 0;
  Resolver::res_t nop;
  vector<DNSRecord> chunk;
  time_t last = 0;
  time_t axfrStart = time(nullptr);
  time_t axfrNow = time(nullptr);
  shared_ptr<const SOARecordContent> soaRecordContent;
  // coverity[store_truncates_time_t]
  while (axfr.getChunk(nop, &chunk, (axfrStart + axfrTimeout - axfrNow)) != 0) {
    for (auto& dnsRecord : chunk) {
      if (dnsRecord.d_type == QType::NS || dnsRecord.d_type == QType::TSIG) {
        continue;
      }

      // We want the full name in the SOA record
      if (dnsRecord.d_type == QType::SOA) {
        zone->setSOA(dnsRecord);
      }
      dnsRecord.d_name.makeUsRelative(zoneName);
      if (dnsRecord.d_type == QType::SOA) {
        soaRecordContent = getRR<SOARecordContent>(dnsRecord);
        continue;
      }

      RPZRecordToPolicy(dnsRecord, zone, true, defpol, defpolOverrideLocal, maxTTL, logger);
      nrecords++;
    }
    axfrNow = time(nullptr);
    if (axfrNow < axfrStart || axfrNow - axfrStart > axfrTimeout) {
      throw PDNSException("Total AXFR time exceeded!");
    }
    if (last != time(nullptr)) {
      logger->info(Logr::Info, "RPZ load in progress", "nrecords", Logging::Loggable(nrecords));
      last = time(nullptr);
    }
  }
  logger->info(Logr::Info, "RPZ load completed", "nrecords", Logging::Loggable(nrecords), "soa", Logging::Loggable(soaRecordContent->getZoneRepresentation()));
  return soaRecordContent;
}

static LockGuarded<std::unordered_map<std::string, shared_ptr<rpzStats>>> s_rpzStats;

shared_ptr<rpzStats> getRPZZoneStats(const std::string& zone)
{
  auto stats = s_rpzStats.lock();
  auto statsIt = stats->find(zone);
  if (statsIt == stats->end()) {
    auto stat = std::make_shared<rpzStats>();
    (*stats)[zone] = stat;
    return stat;
  }
  return statsIt->second;
}

static void incRPZFailedTransfers(const std::string& zone)
{
  auto stats = getRPZZoneStats(zone);
  if (stats != nullptr) {
    stats->d_failedTransfers++;
  }
}

static void setRPZZoneNewState(const std::string& zone, uint32_t serial, uint64_t numberOfRecords, bool fromFile, bool wasAXFR)
{
  auto stats = getRPZZoneStats(zone);
  if (stats == nullptr) {
    return;
  }
  if (!fromFile) {
    stats->d_successfulTransfers++;
    if (wasAXFR) {
      stats->d_fullTransfers++;
    }
  }
  stats->d_lastUpdate = time(nullptr);
  stats->d_serial = serial;
  stats->d_numberOfRecords = numberOfRecords;
}

// this function is silent - you do the logging
std::shared_ptr<const SOARecordContent> loadRPZFromFile(const std::string& fname, const std::shared_ptr<DNSFilterEngine::Zone>& zone, const std::optional<DNSFilterEngine::Policy>& defpol, bool defpolOverrideLocal, uint32_t maxTTL)
{
  shared_ptr<const SOARecordContent> soaRecordContent = nullptr;
  ZoneParserTNG zpt(fname);
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
  zpt.setMaxIncludes(::arg().asNum("max-include-depth"));
  DNSResourceRecord drr;
  DNSRecord soaRecord;
  DNSName domain;
  auto log = g_slog->withName("rpz")->withValues("file", Logging::Loggable(fname), "zone", Logging::Loggable(zone->getName()));
  while (zpt.get(drr)) {
    try {
      if (drr.qtype.getCode() == QType::CNAME && drr.content.empty()) {
        drr.content = ".";
      }
      DNSRecord dnsRecord(drr);
      if (dnsRecord.d_type == QType::SOA) {
        soaRecordContent = getRR<SOARecordContent>(dnsRecord);
        domain = dnsRecord.d_name;
        zone->setDomain(domain);
        soaRecord = std::move(dnsRecord);
      }
      else if (dnsRecord.d_type == QType::NS) {
        continue;
      }
      else {
        dnsRecord.d_name = dnsRecord.d_name.makeRelative(domain);
        RPZRecordToPolicy(dnsRecord, zone, true, defpol, defpolOverrideLocal, maxTTL, log);
      }
    }
    catch (const PDNSException& pe) {
      throw PDNSException("Issue parsing '" + drr.qname.toLogString() + "' '" + drr.content + "' at " + zpt.getLineOfFile() + ": " + pe.reason);
    }
  }

  if (soaRecordContent != nullptr) {
    zone->setRefresh(soaRecordContent->d_st.refresh);
    zone->setSOA(std::move(soaRecord));
    setRPZZoneNewState(zone->getName(), soaRecordContent->d_st.serial, zone->size(), true, false);
  }
  return soaRecordContent;
}

struct FilenameDeleter
{
  void operator()(const string* name) const noexcept
  {
    if (name != nullptr) {
      if (!name->empty()) {
        unlink(name->c_str());
      }
      delete name; // NOLINT(cppcoreguidelines-owning-memory)
    }
  }
};

using UniqueFilenameDeleterPtr = std::unique_ptr<std::string, FilenameDeleter>;

static bool dumpZoneToDisk(Logr::log_t logger, const std::shared_ptr<DNSFilterEngine::Zone>& newZone, const std::string& dumpZoneFileName)
{
  logger->info(Logr::Debug, "Dumping zone to disk", "destination_file", Logging::Loggable(dumpZoneFileName));
  DNSRecord soa = newZone->getSOA();
  uint32_t serial = 0;
  DNSName zone;
  if (auto soaContent = getRR<SOARecordContent>(soa)) {
    serial = soaContent->d_st.serial;
  }
  if (newZone->getSerial() != serial) {
    logger->info(Logr::Error, "Inconsistency of internal serial and SOA serial", "serial", Logging::Loggable(newZone->getSerial()), "soaserial", Logging::Loggable(serial));
  }

  if (newZone->getDomain() != soa.d_name) {
    logger->info(Logr::Error, "Inconsistency of internal name and SOA name", "zone", Logging::Loggable(newZone->getDomain()), "soaname", Logging::Loggable(soa.d_name));
  }
  auto tempFile = UniqueFilenameDeleterPtr(new string(dumpZoneFileName + "XXXXXX"));
  int fileDesc = mkstemp(tempFile->data());
  if (fileDesc < 0) {
    logger->error(Logr::Error, errno, "Unable to create temporary file");
    tempFile->clear(); // file has not been created, no need to unlink
    return false;
  }

  auto filePtr = pdns::UniqueFilePtr(fdopen(fileDesc, "w+"));
  if (!filePtr) {
    int err = errno;
    close(fileDesc);
    logger->error(Logr::Error, err, "Unable to open file pointer");
    return false;
  }

  try {
    newZone->dump(filePtr.get());
  }
  catch (const std::exception& e) {
    logger->error(Logr::Error, e.what(), "Error while dumping the content of the RPZ");
    return false;
  }

  if (fflush(filePtr.get()) != 0) {
    logger->error(Logr::Warning, errno, "Error while flushing the content of the RPZ");
    return false;
  }

  if (fsync(fileno(filePtr.get())) != 0) {
    logger->error(Logr::Error, errno, "Error while syncing the content of the RPZ");
    return false;
  }

  if (fclose(filePtr.release()) != 0) {
    logger->error(Logr::Error, errno, "Error while writing the content of the RPZ");
    return false;
  }

  if (rename(tempFile->c_str(), dumpZoneFileName.c_str()) != 0) {
    logger->error(Logr::Error, errno, "Error while moving the content of the RPZ", "destination_file", Logging::Loggable(dumpZoneFileName));
    return false;
  }
  tempFile->clear(); // file has been renamed, no need to unlink
  return true;
}

static void preloadRPZFIle(RPZTrackerParams& params, const DNSName& zoneName, std::shared_ptr<DNSFilterEngine::Zone>& oldZone, uint32_t& refresh, const string& polName, uint64_t configGeneration, ZoneXFR::ZoneWaiter& rpzwaiter, Logr::log_t logger)
{
  while (!params.zoneXFRParams.soaRecordContent) {
    /* if we received an empty sr, the zone was not really preloaded */

    /* full copy, as promised */
    std::shared_ptr<DNSFilterEngine::Zone> newZone = std::make_shared<DNSFilterEngine::Zone>(*oldZone);
    for (const auto& primary : params.zoneXFRParams.primaries) {
      try {
        auto combo = pdns::fromNameOrIP(primary, 53, logger);
        params.zoneXFRParams.soaRecordContent = loadRPZFromServer(logger, combo, zoneName, newZone, params.defpol, params.defpolOverrideLocal, params.maxTTL, params.zoneXFRParams.tsigtriplet, params.zoneXFRParams.maxReceivedMBytes, params.zoneXFRParams.localAddress, params.zoneXFRParams.xfrTimeout);
        newZone->setSerial(params.zoneXFRParams.soaRecordContent->d_st.serial);
        newZone->setRefresh(params.zoneXFRParams.soaRecordContent->d_st.refresh);
        refresh = std::max(params.zoneXFRParams.refreshFromConf != 0 ? params.zoneXFRParams.refreshFromConf : newZone->getRefresh(), 1U);
        setRPZZoneNewState(polName, params.zoneXFRParams.soaRecordContent->d_st.serial, newZone->size(), false, true);

        g_luaconfs.modify([zoneIdx = params.zoneXFRParams.zoneIdx, &newZone](LuaConfigItems& lci) {
          lci.dfe.setZone(zoneIdx, newZone);
        });

        if (!params.dumpZoneFileName.empty()) {
          dumpZoneToDisk(logger, newZone, params.dumpZoneFileName);
        }

        /* no need to try another primary */
        break;
      }
      catch (const std::exception& e) {
        logger->error(Logr::Warning, e.what(), "Unable to load RPZ zone, will retry", "from", Logging::Loggable(primary), "exception", Logging::Loggable("std::exception"), "refresh", Logging::Loggable(refresh));
        incRPZFailedTransfers(polName);
      }
      catch (const PDNSException& e) {
        logger->error(Logr::Warning, e.reason, "Unable to load RPZ zone, will retry", "from", Logging::Loggable(primary), "exception", Logging::Loggable("PDNSException"), "refresh", Logging::Loggable(refresh));
        incRPZFailedTransfers(polName);
      }
    }
    // Release newZone before (long) sleep to reduce memory usage
    newZone = nullptr;
    if (!params.zoneXFRParams.soaRecordContent) {
      std::unique_lock lock(rpzwaiter.mutex);
      rpzwaiter.condVar.wait_for(lock, std::chrono::seconds(refresh),
                                 [&stop = rpzwaiter.stop] { return stop.load(); });
    }
    rpzwaiter.stop = false;
    auto luaconfsLocal = g_luaconfs.getLocal();

    if (luaconfsLocal->generation != configGeneration) {
      /* the configuration has been reloaded, meaning that a new thread
         has been started to handle that zone and we are now obsolete.
      */
      return;
    }
  }
}

static bool RPZTrackerIteration(RPZTrackerParams& params, const DNSName& zoneName, std::shared_ptr<DNSFilterEngine::Zone>& oldZone, uint32_t& refresh, const string& polName, bool& skipRefreshDelay, uint64_t configGeneration, ZoneXFR::ZoneWaiter& rpzwaiter, Logr::log_t logger)
{
  // Don't hold on to oldZone, it well be re-assigned after sleep in the try block
  oldZone = nullptr;
  DNSRecord dnsRecord;
  dnsRecord.setContent(params.zoneXFRParams.soaRecordContent);

  if (skipRefreshDelay) {
    skipRefreshDelay = false;
  }
  else {
    const time_t minimumTimeBetweenRefreshes = std::min(refresh, 5U);
    const time_t startTime = time(nullptr);
    time_t wakeTime = startTime;
    while (wakeTime - startTime < minimumTimeBetweenRefreshes) {
      std::unique_lock lock(rpzwaiter.mutex);
      time_t remaining = refresh - (wakeTime - startTime);
      if (remaining <= 0) {
        break;
      }
      rpzwaiter.condVar.wait_for(lock, std::chrono::seconds(remaining),
                                 [&stop = rpzwaiter.stop] { return stop.load(); });
      rpzwaiter.stop = false;
      wakeTime = time(nullptr);
    }
  }
  auto luaconfsLocal = g_luaconfs.getLocal();

  if (luaconfsLocal->generation != configGeneration) {
    /* the configuration has been reloaded, meaning that a new thread
       has been started to handle that zone and we are now obsolete.
    */
    logger->info(Logr::Info, "A more recent configuration has been found, stopping the existing RPZ update thread");
    return false;
  }

  vector<pair<vector<DNSRecord>, vector<DNSRecord>>> deltas;
  for (const auto& ipOrName : params.zoneXFRParams.primaries) {
    auto primary = pdns::fromNameOrIP(ipOrName, 53, logger);
    auto soa = getRR<SOARecordContent>(dnsRecord);
    auto serial = soa ? soa->d_st.serial : 0;
    logger->info(Logr::Info, "Getting IXFR deltas", "address", Logging::Loggable(primary), "ourserial", Logging::Loggable(serial));

    ComboAddress local(params.zoneXFRParams.localAddress);
    if (local == ComboAddress()) {
      local = pdns::getQueryLocalAddress(primary.sin4.sin_family, 0);
    }

    try {
      deltas = getIXFRDeltas(primary, zoneName, dnsRecord, params.zoneXFRParams.xfrTimeout, true, params.zoneXFRParams.tsigtriplet, &local, params.zoneXFRParams.maxReceivedMBytes);

      /* no need to try another primary */
      break;
    }
    catch (const std::runtime_error& e) {
      logger->error(Logr::Warning, e.what(), "Exception during retrieval of delta", "exception", Logging::Loggable("std::runtime_error"));
      incRPZFailedTransfers(polName);
      continue;
    }
  }

  if (deltas.empty()) {
    return true;
  }

  try {
    logger->info(Logr::Info, "Processing deltas", "size", Logging::Loggable(deltas.size()));

    if (luaconfsLocal->generation != configGeneration) {
      logger->info(Logr::Info, "A more recent configuration has been found, stopping the existing RPZ update thread");
      return false;
    }
    oldZone = luaconfsLocal->dfe.getZone(params.zoneXFRParams.zoneIdx);
    if (!oldZone || oldZone->getDomain() != zoneName) {
      logger->info(Logr::Info, "This policy is no more, stopping the existing RPZ update thread");
      return false;
    }
    /* we need to make a _full copy_ of the zone we are going to work on */
    std::shared_ptr<DNSFilterEngine::Zone> newZone = std::make_shared<DNSFilterEngine::Zone>(*oldZone);
    /* initialize the current serial to the last one */
    std::shared_ptr<const SOARecordContent> currentSR = params.zoneXFRParams.soaRecordContent;

    int totremove = 0;
    int totadd = 0;
    bool fullUpdate = false;
    for (const auto& delta : deltas) {
      const auto& remove = delta.first;
      const auto& add = delta.second;
      if (remove.empty()) {
        logger->info(Logr::Warning, "IXFR update is a whole new zone");
        newZone->clear();
        fullUpdate = true;
      }
      for (const auto& resourceRecord : remove) { // should always contain the SOA
        if (resourceRecord.d_type == QType::NS) {
          continue;
        }
        if (resourceRecord.d_type == QType::SOA) {
          auto oldsr = getRR<SOARecordContent>(resourceRecord);
          if (oldsr && oldsr->d_st.serial == currentSR->d_st.serial) {
            //	Got good removal of SOA serial, no work to be done
          }
          else {
            if (!oldsr) {
              throw std::runtime_error("Unable to extract serial from SOA record while processing the removal part of an update");
            }
            throw std::runtime_error("Received an unexpected serial (" + std::to_string(oldsr->d_st.serial) + ", expecting " + std::to_string(currentSR->d_st.serial) + ") from SOA record while processing the removal part of an update");
          }
        }
        else {
          totremove++;
          logger->info(g_logRPZChanges ? Logr::Info : Logr::Debug, "Remove from RPZ zone", "name", Logging::Loggable(resourceRecord.d_name));
          RPZRecordToPolicy(resourceRecord, newZone, false, params.defpol, params.defpolOverrideLocal, params.maxTTL, logger);
        }
      }

      for (const auto& resourceRecord : add) { // should always contain the new SOA
        if (resourceRecord.d_type == QType::NS) {
          continue;
        }
        if (resourceRecord.d_type == QType::SOA) {
          if (auto tempSR = getRR<SOARecordContent>(resourceRecord)) {
            dnsRecord = resourceRecord;
            // IXFR leaves us a relative name, fix that
            dnsRecord.d_name = newZone->getDomain();
            currentSR = std::move(tempSR);
          }
        }
        else {
          totadd++;
          logger->info(g_logRPZChanges ? Logr::Info : Logr::Debug, "Addition to RPZ zone", "name", Logging::Loggable(resourceRecord.d_name));
          RPZRecordToPolicy(resourceRecord, newZone, true, params.defpol, params.defpolOverrideLocal, params.maxTTL, logger);
        }
      }
    }

    /* only update sr now that all changes have been converted */
    if (currentSR) {
      newZone->setSOA(std::move(dnsRecord));
      params.zoneXFRParams.soaRecordContent = std::move(currentSR);
    }
    logger->info(Logr::Info, "RPZ mutations", "removals", Logging::Loggable(totremove), "additions", Logging::Loggable(totadd), "newserial", Logging::Loggable(params.zoneXFRParams.soaRecordContent->d_st.serial));
    newZone->setSerial(params.zoneXFRParams.soaRecordContent->d_st.serial);
    newZone->setRefresh(params.zoneXFRParams.soaRecordContent->d_st.refresh);
    setRPZZoneNewState(polName, params.zoneXFRParams.soaRecordContent->d_st.serial, newZone->size(), false, fullUpdate);

    /* we need to replace the existing zone with the new one,
       but we don't want to touch anything else, especially other zones,
       since they might have been updated by another RPZ IXFR tracker thread.
    */
    if (luaconfsLocal->generation != configGeneration) {
      logger->info(Logr::Info, "A more recent configuration has been found, stopping the existing RPZ update thread");
      return false;
    }
    g_luaconfs.modify([zoneIdx = params.zoneXFRParams.zoneIdx, &newZone](LuaConfigItems& lci) {
      lci.dfe.setZone(zoneIdx, newZone);
    });

    if (!params.dumpZoneFileName.empty()) {
      dumpZoneToDisk(logger, newZone, params.dumpZoneFileName);
    }
    refresh = std::max(params.zoneXFRParams.refreshFromConf != 0 ? params.zoneXFRParams.refreshFromConf : newZone->getRefresh(), 1U);
  }
  catch (const std::exception& e) {
    logger->error(Logr::Error, e.what(), "Exception while applying the update received over XFR, skipping", "exception", Logging::Loggable("std::exception"));
  }
  catch (const PDNSException& e) {
    logger->error(Logr::Error, e.reason, "Exception while applying the update received over XFR, skipping", "exception", Logging::Loggable("PDNSException"));
  }
  return true;
}

// coverity[pass_by_value] params is intended to be a copy, as this is the main function of a thread
void RPZIXFRTracker(RPZTrackerParams params, uint64_t configGeneration)
{
  setThreadName("rec/rpzixfr");
  bool isPreloaded = params.zoneXFRParams.soaRecordContent != nullptr;
  auto logger = g_slog->withName("rpz");
  ZoneXFR::ZoneWaiter waiter(std::this_thread::get_id());

  /* we can _never_ modify this zone directly, we need to do a full copy then replace the existing zone */
  std::shared_ptr<DNSFilterEngine::Zone> oldZone = g_luaconfs.getLocal()->dfe.getZone(params.zoneXFRParams.zoneIdx);
  if (!oldZone) {
    logger->error(Logr::Error, "Unable to retrieve RPZ zone from configuration", "index", Logging::Loggable(params.zoneXFRParams.zoneIdx));
    return;
  }

  // If oldZone failed to load its getRefresh() returns 0, protect against that
  uint32_t refresh = std::max(params.zoneXFRParams.refreshFromConf != 0 ? params.zoneXFRParams.refreshFromConf : oldZone->getRefresh(), 10U);
  DNSName zoneName = oldZone->getDomain();
  std::string polName = !oldZone->getName().empty() ? oldZone->getName() : zoneName.toStringNoDot();

  // Now that we know the name, set it in the logger
  logger = logger->withValues("zone", Logging::Loggable(zoneName));

  ZoneXFR::insertZoneTracker(zoneName, waiter);

  preloadRPZFIle(params, zoneName, oldZone, refresh, polName, configGeneration, waiter, logger);

  bool skipRefreshDelay = isPreloaded;

  while (RPZTrackerIteration(params, zoneName, oldZone, refresh, polName, skipRefreshDelay, configGeneration, waiter, logger)) {
    // empty
  }

  ZoneXFR::clearZoneTracker(zoneName);
}
