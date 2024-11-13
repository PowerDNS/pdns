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

#include "rec-xfr.hh"
#include "arguments.hh"
#include "logging.hh"
#include "threadname.hh"
#include "rec-lua-conf.hh"
#include "query-local-address.hh"
#include "axfr-retriever.hh"
#include "ixfr.hh"
#include "dnsrecords.hh"
#include "rec-system-resolve.hh"

static const DNSName cZones("zones");
static const DNSName cVersion("version");

// TODO: cleanup files if not in catalogzones?

static bool validate(const DNSRecord& record, Logr::log_t logger)
{
  if (record.d_name.empty()) {
    logger->info(Logr::Warning, "Record is not part of zone, skipping", "name", Logging::Loggable(record.d_name));
    return false;
  }
  if (record.d_class != QClass::IN) {
    logger->info(Logr::Warning, "Record class is not IN, skipping", "name", Logging::Loggable(record.d_name));
    return false;
  }

  if (record.d_name.getLastLabel() != cZones && record.d_name != cVersion) {
    logger->info(Logr::Warning, "Record is not a catalog zone entry, skipping", "name", Logging::Loggable(record.d_name));
    return false;
  }
  return true;
}

void CatalogZone::add(const DNSRecord& record, Logr::log_t logger)
{
  if (!validate(record, logger)) {
    return;
  }
  const auto& key = record.d_name;
  logger->info(Logr::Debug, "Adding cat zone entry", "name", Logging::Loggable(key), "qtype", Logging::Loggable(QType(record.d_type)));
  d_records.emplace(std::make_pair(key, record.d_type), record);
}

void CatalogZone::remove(const DNSRecord& record, Logr::log_t logger)
{
  if (!validate(record, logger)) {
    return;
  }
  const auto& key = record.d_name;
  logger->info(Logr::Debug, "Removing cat zone entry", "name", Logging::Loggable(key), "qtype", Logging::Loggable(QType(record.d_type)));
  d_records.erase(std::make_pair(key, record.d_type));
}

void CatalogZone::registerForwarders(const FWCatalogZone& params, Logr::log_t logger) const
{
  const string zonesFile = ::arg()["api-config-dir"] + "/catzone." + d_name.toString();
  ::rust::Vec<::pdns::rust::settings::rec::ForwardZone> forwards;

  for (const auto& record : d_records) {
    if (record.first.second != QType::PTR) {
      continue;
    }
    if (const auto ptr = getRR<PTRRecordContent>(record.second)) {
      auto defsIter = params.d_defaults.find("");
      const auto& name = record.first.first;
      const auto& target = ptr->getContent();
      auto groupKey = name;
      groupKey.prependRawLabel("group");
      // Look for group records matching the member
      auto range = d_records.equal_range(std::make_pair(groupKey, QType::TXT));
      for (auto groupIter = range.first; groupIter != range.second; ++groupIter) {
        if (const auto txt = getRR<TXTRecordContent>(groupIter->second); txt != nullptr) {
          auto groupName = txt->d_text;
          groupName = unquotify(groupName);
          auto iter = params.d_defaults.find(groupName);
          if (iter == params.d_defaults.end()) {
            logger->info(Logr::Error, "No match for group in YAML config", "name", Logging::Loggable(name), "groupName", Logging::Loggable(groupName), "target", Logging::Loggable(target));
            continue;
          }
          logger->info(Logr::Debug, "Match for group in YAML config", "name", Logging::Loggable(name), "groupName", Logging::Loggable(groupName), "target", Logging::Loggable(target));
          defsIter = iter;
          break;
        }
      }
      if (defsIter == params.d_defaults.end()) {
        logger->info(Logr::Error, "No match for default group in YAML config", "name", Logging::Loggable(name), "target", Logging::Loggable(target));
        continue;
      }
      pdns::rust::settings::rec::ForwardZone forward;
      forward.zone = target.toString();
      forward.recurse = defsIter->second.recurse;
      forward.notify_allowed = defsIter->second.notify_allowed;
      for (const auto& value : defsIter->second.forwarders) {
        forward.forwarders.emplace_back(value);
      }
      forward.validate("catz");
      forwards.emplace_back(std::move(forward));
    }
  }

  // Simple approach: just replace everything. Keeping track of changes to members is a bit involved as the
  // members themselves can change, be added ot deleted, but also the group records.
  pdns::rust::settings::rec::api_delete_zones(zonesFile);
  pdns::rust::settings::rec::api_add_forward_zones(zonesFile, forwards);
  reloadZoneConfiguration(true);
}

bool CatalogZone::versionCheck() const
{
  auto records = d_records.equal_range(std::make_pair(cVersion, QType::TXT));
  bool invalid = false;
  size_t count = 0;
  for (auto record = records.first; record != records.second; ++record) {
    const auto txt = getRR<TXTRecordContent>(record->second);
    if (txt == nullptr) {
      invalid = true;
      continue;
    }
    if (txt->d_text != "\"2\"") {
      invalid = true;
      continue;
    }
    ++count;
  }
  return !invalid && count == 1;
}

bool CatalogZone::dupsCheck() const
{
  std::unordered_set<DNSName> values;
  bool invalid = false;
  for (const auto& [key, record] : d_records) {
    if (key.second != QType::PTR) {
      continue;
    }
    const auto ptr = getRR<PTRRecordContent>(record);
    if (ptr == nullptr) {
      invalid = true;
      continue;
    }
    if (!values.emplace(ptr->getContent()).second) {
      invalid = true;
      break;
    }
  }
  return !invalid;
}

static shared_ptr<const SOARecordContent> loadZoneFromServer(Logr::log_t plogger, const ComboAddress& primary, const DNSName& zoneName, shared_ptr<CatalogZone>& zone, const TSIGTriplet& tsigTriplet, size_t maxReceivedBytes, const ComboAddress& localAddress, uint16_t axfrTimeout)
{

  auto logger = plogger->withValues("primary", Logging::Loggable(primary));
  logger->info(Logr::Info, "Loading zone from nameserver");
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
  const time_t axfrStart = time(nullptr);
  time_t axfrNow = axfrStart;
  shared_ptr<const SOARecordContent> soaRecordContent;
  // coverity[store_truncates_time_t]
  while (axfr.getChunk(nop, &chunk, (axfrStart + axfrTimeout - axfrNow)) != 0) {
    for (auto& dnsRecord : chunk) {
      if (dnsRecord.d_type == QType::NS || dnsRecord.d_type == QType::TSIG) {
        continue;
      }

      dnsRecord.d_name.makeUsRelative(zoneName);
      if (dnsRecord.d_type == QType::SOA) {
        soaRecordContent = getRR<SOARecordContent>(dnsRecord);
        continue;
      }

      zone->add(dnsRecord, logger);
      nrecords++;
    }
    axfrNow = time(nullptr);
    if (axfrNow < axfrStart || axfrNow - axfrStart > axfrTimeout) {
      throw PDNSException("Total AXFR time exceeded!");
    }
    if (last != time(nullptr)) {
      logger->info(Logr::Info, "Zone load in progress", "nrecords", Logging::Loggable(nrecords));
      last = time(nullptr);
    }
  }

  if (!zone->versionCheck()) {
    zone->clear();
    throw PDNSException("no valid version record in catalog zone");
  }
  if (!zone->dupsCheck()) {
    zone->clear();
    throw PDNSException("duplicate PTR values in catalog zone");
  }
  logger->info(Logr::Info, "Zone load completed", "nrecords", Logging::Loggable(nrecords), "soa", Logging::Loggable(soaRecordContent->getZoneRepresentation()));
  return soaRecordContent;
}

void FWCatZoneXFR::preloadZoneFile(const DNSName& zoneName, const std::shared_ptr<const CatalogZone>& oldZone, uint32_t& refresh, uint64_t configGeneration, ZoneWaiter& waiter, Logr::log_t logger)
{
  while (!d_params.soaRecordContent) {
    /* if we received an empty sr, the zone was not really preloaded */

    /* full copy, as promised */
    auto newZone = std::make_shared<CatalogZone>(*oldZone);
    for (const auto& nameOrIp : d_params.primaries) {
      try {
        auto primary = pdns::fromNameOrIP(nameOrIp, 53, logger);
        d_params.soaRecordContent = loadZoneFromServer(logger, primary, zoneName, newZone, d_params.tsigtriplet, d_params.maxReceivedMBytes, d_params.localAddress, d_params.xfrTimeout);
        newZone->setSerial(d_params.soaRecordContent->d_st.serial);
        newZone->setRefresh(d_params.soaRecordContent->d_st.refresh);
        refresh = std::max(d_params.refreshFromConf != 0 ? d_params.refreshFromConf : newZone->getRefresh(), 1U);
        // XXX Stats

        g_luaconfs.modify([zoneIdx = d_params.zoneIdx, &newZone](LuaConfigItems& lci) {
          lci.catalogzones.at(zoneIdx).d_catz = newZone;
        });

        auto lci = g_luaconfs.getLocal();
        newZone->registerForwarders(lci->catalogzones.at(d_params.zoneIdx), logger);
        /* no need to try another primary */
        break;
      }
      catch (const std::exception& e) {
        logger->error(Logr::Warning, e.what(), "Unable to load zone, will retry", "from", Logging::Loggable(nameOrIp), "exception", Logging::Loggable("std::exception"), "refresh", Logging::Loggable(refresh));
        // XXX Stats
      }
      catch (const PDNSException& e) {
        logger->error(Logr::Warning, e.reason, "Unable to load zone, will retry", "from", Logging::Loggable(nameOrIp), "exception", Logging::Loggable("PDNSException"), "refresh", Logging::Loggable(refresh));
        // XXX Stats
      }
    }
    // Release newZone before (long) sleep to reduce memory usage
    newZone = nullptr;
    if (!d_params.soaRecordContent) {
      std::unique_lock lock(waiter.mutex);
      waiter.condVar.wait_for(lock, std::chrono::seconds(refresh),
                              [&stop = waiter.stop] { return stop.load(); });
    }
    waiter.stop = false;
    auto luaconfsLocal = g_luaconfs.getLocal();

    if (luaconfsLocal->generation != configGeneration) {
      /* the configuration has been reloaded, meaning that a new thread
         has been started to handle that zone and we are now obsolete.
      */
      return;
    }
  }
}

bool FWCatZoneXFR::zoneTrackerIteration(const DNSName& zoneName, std::shared_ptr<const CatalogZone>& oldZone, uint32_t& refresh, bool& skipRefreshDelay, uint64_t configGeneration, ZoneWaiter& waiter, Logr::log_t logger)
{
  // Don't hold on to oldZone, it well be re-assigned after sleep in the try block
  oldZone = nullptr;
  DNSRecord soaRecord;
  soaRecord.setContent(d_params.soaRecordContent);

  if (skipRefreshDelay) {
    skipRefreshDelay = false;
  }
  else {
    const time_t minimumTimeBetweenRefreshes = std::min(refresh, 5U);
    const time_t startTime = time(nullptr);
    time_t wakeTime = startTime;
    while (wakeTime - startTime < minimumTimeBetweenRefreshes) {
      std::unique_lock lock(waiter.mutex);
      time_t remaining = refresh - (wakeTime - startTime);
      if (remaining <= 0) {
        break;
      }
      waiter.condVar.wait_for(lock, std::chrono::seconds(remaining),
                              [&stop = waiter.stop] { return stop.load(); });
      waiter.stop = false;
      wakeTime = time(nullptr);
    }
  }
  auto luaconfsLocal = g_luaconfs.getLocal();

  if (luaconfsLocal->generation != configGeneration) {
    /* the configuration has been reloaded, meaning that a new thread
       has been started to handle that zone and we are now obsolete.
    */
    logger->info(Logr::Info, "A more recent configuration has been found, stopping the existing zone update thread");
    return false;
  }

  vector<pair<vector<DNSRecord>, vector<DNSRecord>>> deltas;
  for (const auto& nameOrIp : d_params.primaries) {
    auto primary = pdns::fromNameOrIP(nameOrIp, 53, logger);
    auto soa = getRR<SOARecordContent>(soaRecord);
    auto serial = soa ? soa->d_st.serial : 0;
    logger->info(Logr::Info, "Getting IXFR deltas", "address", Logging::Loggable(primary), "ourserial", Logging::Loggable(serial));

    ComboAddress local(d_params.localAddress);
    if (local == ComboAddress()) {
      local = pdns::getQueryLocalAddress(primary.sin4.sin_family, 0);
    }

    try {
      deltas = getIXFRDeltas(primary, zoneName, soaRecord, d_params.xfrTimeout, true, d_params.tsigtriplet, &local, d_params.maxReceivedMBytes);

      /* no need to try another primary */
      break;
    }
    catch (const std::runtime_error& e) {
      logger->error(Logr::Warning, e.what(), "Exception during retrieval of delta", "exception", Logging::Loggable("std::runtime_error"));
      if (oldZone) {
        // XXX Stats
      }
      continue;
    }
  }

  if (deltas.empty()) {
    return true;
  }

  try {
    logger->info(Logr::Info, "Processing deltas", "size", Logging::Loggable(deltas.size()));

    if (luaconfsLocal->generation != configGeneration) {
      logger->info(Logr::Info, "A more recent configuration has been found, stopping the existing zone update thread");
      return false;
    }
    oldZone = luaconfsLocal->catalogzones.at(d_params.zoneIdx).d_catz;
    if (!oldZone || oldZone->getName() != zoneName) {
      logger->info(Logr::Info, "This policy is no more, stopping the existing zone update thread");
      return false;
    }
    /* we need to make a _full copy_ of the zone we are going to work on */
    auto newZone = std::make_shared<CatalogZone>(*oldZone);
    /* initialize the current serial to the last one */
    std::shared_ptr<const SOARecordContent> currentSR = d_params.soaRecordContent;

    int removed = 0;
    int added = 0;

    for (const auto& delta : deltas) {
      const auto& remove = delta.first;
      const auto& add = delta.second;
      if (remove.empty()) {
        logger->info(Logr::Warning, "IXFR update is a whole new zone");
        newZone->clear();
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
          removed++;
          logger->info(Logr::Debug, "Remove from zone", "name", Logging::Loggable(resourceRecord.d_name));
          newZone->remove(resourceRecord, logger);
        }
      }

      for (const auto& resourceRecord : add) { // should always contain the new SOA
        if (resourceRecord.d_type == QType::NS) {
          continue;
        }
        if (resourceRecord.d_type == QType::SOA) {
          auto tempSR = getRR<SOARecordContent>(resourceRecord);
          if (tempSR) {
            currentSR = std::move(tempSR);
          }
        }
        else {
          added++;
          logger->info(Logr::Debug, "Addition to zone", "name", Logging::Loggable(resourceRecord.d_name));
          newZone->add(resourceRecord, logger);
        }
      }
    }
    if (!newZone->versionCheck()) {
      throw PDNSException("no valid version record in catalog zone");
    }
    if (!newZone->dupsCheck()) {
      throw PDNSException("duplicate PTR values in catalog zone");
    }

    /* only update sr now that all changes have been converted */
    if (currentSR) {
      d_params.soaRecordContent = std::move(currentSR);
    }
    logger->info(Logr::Info, "Zone mutations", "removals", Logging::Loggable(removed), "additions", Logging::Loggable(added), "newserial", Logging::Loggable(d_params.soaRecordContent->d_st.serial));
    newZone->setSerial(d_params.soaRecordContent->d_st.serial);
    newZone->setRefresh(d_params.soaRecordContent->d_st.refresh);
    // XXX Stats

    /* we need to replace the existing zone with the new one,
       but we don't want to touch anything else, especially other zones,
       since they might have been updated by another Zone IXFR tracker thread.
    */
    if (luaconfsLocal->generation != configGeneration) {
      logger->info(Logr::Info, "A more recent configuration has been found, stopping the existing zone update thread");
      return false;
    }
    g_luaconfs.modify([zoneIdx = d_params.zoneIdx, &newZone](LuaConfigItems& lci) {
      lci.catalogzones.at(zoneIdx).d_catz = newZone;
    });

    auto lci = g_luaconfs.getLocal();
    newZone->registerForwarders(lci->catalogzones.at(d_params.zoneIdx), logger);
    refresh = std::max(d_params.refreshFromConf != 0 ? d_params.refreshFromConf : newZone->getRefresh(), 1U);
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
void FWCatZoneXFR::zoneXFRTracker(ZoneXFRParams params, uint64_t configGeneration) // NOLINT(performance-unnecessary-value-param)
{
  setThreadName("rec/fwcatzixfr");
  bool isPreloaded = params.soaRecordContent != nullptr;
  auto logger = g_slog->withName("fwcatzixfr");
  ZoneWaiter waiter(std::this_thread::get_id());

  /* we can _never_ modify this zone directly, we need to do a full copy then replace the existing zone */
  std::shared_ptr<const CatalogZone> oldZone;
  if (params.zoneIdx < g_luaconfs.getLocal()->catalogzones.size()) {
    oldZone = g_luaconfs.getLocal()->catalogzones.at(params.zoneIdx).d_catz;
  }
  if (!oldZone) {
    logger->error(Logr::Error, "Unable to retrieve catalog zone from configuration", "index", Logging::Loggable(params.zoneIdx));
    return;
  }

  // If oldZone failed to load its getRefresh() returns 0, protect against that
  uint32_t refresh = std::max(params.refreshFromConf != 0 ? params.refreshFromConf : oldZone->getRefresh(), 10U);
  DNSName zoneName = oldZone->getName();

  // Now that we know the name, set it in the logger
  logger = logger->withValues("zone", Logging::Loggable(zoneName));

  insertZoneTracker(zoneName, waiter);

  FWCatZoneXFR xfrObject(std::move(params));
  xfrObject.preloadZoneFile(zoneName, oldZone, refresh, configGeneration, waiter, logger);
  bool skipRefreshDelay = isPreloaded;
  while (xfrObject.zoneTrackerIteration(zoneName, oldZone, refresh, skipRefreshDelay, configGeneration, waiter, logger)) {
    // empty
  }

  clearZoneTracker(zoneName);
}
