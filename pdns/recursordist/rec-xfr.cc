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
#include "lock.hh"
#include "logging.hh"
#include "threadname.hh"
#include "rec-lua-conf.hh"
#include "query-local-address.hh"
#include "ixfr.hh"

// As there can be multiple threads doing updates (due to config reloads), we use a multimap.
// The value contains the actual thread id that owns the struct.

static LockGuarded<std::multimap<DNSName, ZoneWaiter&>> condVars;

// Notify all threads tracking the zone name
bool notifyZoneTracker(const DNSName& name)
{
  auto lock = condVars.lock();
  auto [start, end] = lock->equal_range(name);
  if (start == end) {
    // Did not find any thread tracking that name
    return false;
  }
  while (start != end) {
    start->second.stop = true;
    start->second.condVar.notify_one();
    ++start;
  }
  return true;
}

void insertZoneTracker(const DNSName& zoneName, ZoneWaiter& waiter)
{
  auto lock = condVars.lock();
  lock->emplace(zoneName, waiter);
}

void clearZoneTracker(const DNSName& zoneName)
{
  // Zap our (and only our) ZoneWaiter struct out of the multimap
  auto lock = condVars.lock();
  auto [start, end] = lock->equal_range(zoneName);
  while (start != end) {
    if (start->second.id == std::this_thread::get_id()) {
      lock->erase(start);
      break;
    }
    ++start;
  }
}

static bool zoneTrackerIteration(ZoneXFRParams& params, const DNSName& zoneName, std::shared_ptr<Zone>& oldZone, uint32_t& refresh, bool& skipRefreshDelay, uint64_t configGeneration, ZoneWaiter& waiter, Logr::log_t logger)
{
  // Don't hold on to oldZone, it well be re-assigned after sleep in the try block
  oldZone = nullptr;
  DNSRecord soaRecord;
  soaRecord.setContent(params.soaRecordContent);

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
  for (const auto& primary : params.primaries) {
    auto soa = getRR<SOARecordContent>(soaRecord);
    auto serial = soa ? soa->d_st.serial : 0;
    logger->info(Logr::Info, "Getting IXFR deltas", "address", Logging::Loggable(primary), "ourserial", Logging::Loggable(serial));

    ComboAddress local(params.localAddress);
    if (local == ComboAddress()) {
      local = pdns::getQueryLocalAddress(primary.sin4.sin_family, 0);
    }

    try {
      deltas = getIXFRDeltas(primary, zoneName, soaRecord, params.xfrTimeout, true, params.tsigtriplet, &local, params.maxReceivedMBytes);

      /* no need to try another primary */
      break;
    }
    catch (const std::runtime_error& e) {
      logger->error(Logr::Warning, e.what(), "Exception during retrieval of delta", "exception", Logging::Loggable("std::runtime_error"));
      // XXX stats
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
    oldZone = luaconfsLocal->catalogzones.at(params.zoneIdx).second;
    if (!oldZone || oldZone->name != zoneName) {
      logger->info(Logr::Info, "This policy is no more, stopping the existing zone update thread");
      return false;
    }
    /* we need to make a _full copy_ of the zone we are going to work on */
    std::shared_ptr<Zone> newZone = std::make_shared<Zone>(*oldZone);
    /* initialize the current serial to the last one */
    std::shared_ptr<const SOARecordContent> currentSR = params.soaRecordContent;

    int totremove = 0;
    int totadd = 0;

    for (const auto& delta : deltas) {
      const auto& remove = delta.first;
      const auto& add = delta.second;
      if (remove.empty()) {
        logger->info(Logr::Warning, "IXFR update is a whole new zone");
        newZone->d_records.clear();
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
          logger->info(Logr::Debug, "Remove from zone", "name", Logging::Loggable(resourceRecord.d_name));
        //RPZRecordToPolicy(resourceRecord, newZone, false, params.defpol, params.defpolOverrideLocal, params.maxTTL, logger);
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
          totadd++;
          logger->info(Logr::Debug, "Addition to zone", "name", Logging::Loggable(resourceRecord.d_name));
        //RPZRecordToPolicy(resourceRecord, newZone, true, params.defpol, params.defpolOverrideLocal, params.maxTTL, logger);
        }
      }
    }

    /* only update sr now that all changes have been converted */
    if (currentSR) {
      params.soaRecordContent = std::move(currentSR);
    }
    logger->info(Logr::Info, "Zone mutations", "removals", Logging::Loggable(totremove), "additions", Logging::Loggable(totadd), "newserial", Logging::Loggable(params.soaRecordContent->d_st.serial));
    newZone->serial = params.soaRecordContent->d_st.serial;
    newZone->refresh = params.soaRecordContent->d_st.refresh;
    //setRPZZoneNewState(polName, params.zoneXFRParams.soaRecordContent->d_st.serial, newZone->size(), false, fullUpdate);

    /* we need to replace the existing zone with the new one,
       but we don't want to touch anything else, especially other zones,
       since they might have been updated by another Zone IXFR tracker thread.
    */
    if (luaconfsLocal->generation != configGeneration) {
      logger->info(Logr::Info, "A more recent configuration has been found, stopping the existing zone update thread");
      return false;
    }
    g_luaconfs.modify([zoneIdx = params.zoneIdx, &newZone](LuaConfigItems& lci) {
      lci.catalogzones.at(zoneIdx).second = newZone;
    });

    refresh = std::max(params.refreshFromConf != 0 ? params.refreshFromConf : newZone->refresh, 1U);
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
void zoneXFRTracker(ZoneXFRParams params, uint64_t configGeneration) // NOLINT(performance-unnecessary-value-param)
{
  setThreadName("rec/catixfr");
  bool isPreloaded = params.soaRecordContent != nullptr;
  auto logger = g_slog->withName("catixfr");
  ZoneWaiter waiter(std::this_thread::get_id());

  /* we can _never_ modify this zone directly, we need to do a full copy then replace the existing zone */
  std::shared_ptr<Zone> oldZone;
  if (params.zoneIdx < g_luaconfs.getLocal()->catalogzones.size()) {
    oldZone = g_luaconfs.getLocal()->catalogzones.at(params.zoneIdx).second;
  }
  if (!oldZone) {
    logger->error(Logr::Error, "Unable to retrieve catalog zone from configuration", "index", Logging::Loggable(params.zoneIdx));
    return;
  }

  // If oldZone failed to load its getRefresh() returns 0, protect against that
  uint32_t refresh = std::max(params.refreshFromConf != 0 ? params.refreshFromConf : oldZone->refresh, 10U);
  DNSName zoneName = oldZone->name;

  // Now that we know the name, set it in the logger
  logger = logger->withValues("zone", Logging::Loggable(zoneName));

  insertZoneTracker(zoneName, waiter);

  while (zoneTrackerIteration(params, zoneName, oldZone, refresh, skipRefreshDelay, configGeneration, waiter, logger)) {
    // empty
  }

  clearZoneTracker(zoneName);
}
