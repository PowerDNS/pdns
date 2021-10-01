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

#include "rec-zonetocache.hh"

#include "syncres.hh"
#include "zoneparser-tng.hh"
#include "query-local-address.hh"
#include "axfr-retriever.hh"
#include "validate-recursor.hh"
#include "logging.hh"
#include "threadname.hh"
#include "rec-lua-conf.hh"

#ifdef HAVE_LIBCURL
#include "minicurl.hh"
#endif

#include <fstream>

struct ZoneData
{
  ZoneData(shared_ptr<Logr::Logger>& log) :
    d_log(log) {}

  std::map<pair<DNSName, QType>, vector<DNSRecord>> d_all;
  std::map<pair<DNSName, QType>, vector<shared_ptr<RRSIGRecordContent>>> d_sigs;
  std::set<DNSName> d_delegations;
  time_t d_now;
  DNSName d_zone;
  shared_ptr<Logr::Logger>& d_log;

  bool isRRSetAuth(const DNSName& qname, QType qtype);
  void parseDRForCache(DNSRecord& dr);
  void getByAXFR(const RecZoneToCache::Config&);
  void ZoneToCache(const RecZoneToCache::Config& config);
};

bool ZoneData::isRRSetAuth(const DNSName& qname, QType qtype)
{
  DNSName delegatedZone(qname);
  if (qtype == QType::DS) {
    delegatedZone.chopOff();
  }
  bool isDelegated = false;
  for (;;) {
    if (d_delegations.count(delegatedZone) > 0) {
      isDelegated = true;
      break;
    }
    delegatedZone.chopOff();
    if (delegatedZone == g_rootdnsname || delegatedZone == d_zone)
      break;
  }
  return !isDelegated;
}

void ZoneData::parseDRForCache(DNSRecord& dr)
{
  const auto key = make_pair(dr.d_name, dr.d_type);

  dr.d_ttl += d_now;

  switch (dr.d_type) {
  case QType::NSEC:
  case QType::NSEC3:
    break;
  case QType::RRSIG: {
    const auto& rr = getRR<RRSIGRecordContent>(dr);
    const auto sigkey = make_pair(key.first, rr->d_type);
    auto found = d_sigs.find(sigkey);
    if (found != d_sigs.end()) {
      found->second.push_back(rr);
    }
    else {
      vector<shared_ptr<RRSIGRecordContent>> sigsrr;
      sigsrr.push_back(rr);
      d_sigs.insert({sigkey, sigsrr});
    }
    break;
  }
  case QType::NS:
    if (dr.d_name != d_zone) {
      d_delegations.insert(dr.d_name);
    }
    break;
  default:
    break;
  }

  auto found = d_all.find(key);
  if (found != d_all.end()) {
    found->second.push_back(dr);
  }
  else {
    vector<DNSRecord> v;
    v.push_back(dr);
    d_all.insert({key, v});
  }
}

void ZoneData::getByAXFR(const RecZoneToCache::Config& config)
{
  ComboAddress primary = ComboAddress(config.d_sources.at(0), 53);
  uint16_t axfrTimeout = config.d_timeout;
  size_t maxReceivedBytes = config.d_maxReceivedBytes;
  const TSIGTriplet tt = config.d_tt;
  ComboAddress local = config.d_local;
  if (local == ComboAddress()) {
    local = pdns::getQueryLocalAddress(primary.sin4.sin_family, 0);
  }

  AXFRRetriever axfr(primary, d_zone, tt, &local, maxReceivedBytes, axfrTimeout);
  Resolver::res_t nop;
  vector<DNSRecord> chunk;
  time_t axfrStart = time(nullptr);
  time_t axfrNow = time(nullptr);

  while (axfr.getChunk(nop, &chunk, (axfrStart + axfrTimeout - axfrNow))) {
    for (auto& dr : chunk) {
      parseDRForCache(dr);
    }
    axfrNow = time(nullptr);
    if (axfrNow < axfrStart || axfrNow - axfrStart > axfrTimeout) {
      throw PDNSException("Total AXFR time for zoneToCache exceeded!");
    }
  }
}

static std::vector<std::string> getLinesFromFile(const RecZoneToCache::Config& config)
{

  std::vector<std::string> lines;
  std::ifstream stream(config.d_sources.at(0));
  if (!stream) {
    throw PDNSException("Cannot read file: " + config.d_sources.at(0));
  }
  std::string line;
  while (std::getline(stream, line)) {
    lines.push_back(line);
  }
  return lines;
}

static std::vector<std::string> getURL(const RecZoneToCache::Config& config)
{
  std::vector<std::string> lines;
#ifdef HAVE_LIBCURL
  MiniCurl mc;
  ComboAddress local = config.d_local;
  std::string reply = mc.getURL(config.d_sources.at(0), nullptr, local == ComboAddress() ? nullptr : &local, config.d_timeout, false, true);
  if (config.d_maxReceivedBytes > 0 && reply.size() > config.d_maxReceivedBytes) {
    // We should actually detect this *during* the GET
    throw PDNSException("Retrieved data exceeds maxReceivedBytes");
  }
  std::istringstream stream(reply);
  string line;
  while (std::getline(stream, line)) {
    lines.push_back(line);
  }
#endif
  return lines;
}

void ZoneData::ZoneToCache(const RecZoneToCache::Config& config)
{
  if (config.d_sources.size() > 1) {
    d_log->info("Multiple sources not yet supported, using first");
  }
  d_zone = DNSName(config.d_zone);
  d_now = time(nullptr);

  // We do not do validation, it will happen on-demand if an Indeterminate record is encountered when the caches are queried
  // First scan all records collecting info about delegations ans sigs
  // A this moment, we ignore NSEC and NSEC3 records. It is not clear to me yet under which conditions
  // they could be entered in into the (neg)cache.

  if (config.d_method == "axfr") {
    d_log->info("Getting zone by AXFR");
    getByAXFR(config);
  }
  else {
    vector<string> lines;
    if (config.d_method == "url") {
      d_log->info("Getting zone by URL");
      lines = getURL(config);
    }
    else if (config.d_method == "file") {
      d_log->info("Getting zone from file");
      lines = getLinesFromFile(config);
    }
    DNSResourceRecord drr;
    ZoneParserTNG zpt(lines, d_zone);
    zpt.setMaxGenerateSteps(0);

    while (zpt.get(drr)) {
      DNSRecord dr(drr);
      parseDRForCache(dr);
    }
  }

  // Rerun, now inserting the rrsets into the cache with associated sigs
  d_now = time(nullptr);
  for (const auto& [key, v] : d_all) {
    const auto& [qname, qtype] = key;
    switch (qtype) {
    case QType::NSEC:
    case QType::NSEC3:
      break;
    case QType::RRSIG:
      break;
    default: {
      vector<shared_ptr<RRSIGRecordContent>> sigsrr;
      auto it = d_sigs.find(key);
      if (it != d_sigs.end()) {
        for (const auto& sig : it->second) {
          sigsrr.push_back(sig);
        }
      }
      bool auth = isRRSetAuth(qname, qtype);
      // Same decision as updateCacheFromRecords() (we do not test for NSEC since we skip those completely)
      if (auth || (qtype == QType::NS || qtype == QType::A || qtype == QType::AAAA || qtype == QType::DS)) {
        g_recCache->replace(d_now, qname, qtype, v, sigsrr,
                            std::vector<std::shared_ptr<DNSRecord>>(), auth, d_zone);
      }
      break;
    }
    }
  }
}

// Config must be a copy, so call by value!
void RecZoneToCache::ZoneToCache(RecZoneToCache::Config config, uint64_t configGeneration)
{
  setThreadName("pdns-r/ztc/" + config.d_zone);
  auto luaconfsLocal = g_luaconfs.getLocal();
  auto log = g_slog->withName("ztc")->withValues("zone", Logging::Loggable(config.d_zone));

  while (true) {
    if (luaconfsLocal->generation != configGeneration) {
      /* the configuration has been reloaded, meaning that a new thread
         has been started to handle that zone and we are now obsolete.
      */
      log->info("A more recent configuration has been found, stopping the old update thread");
      return;
    }

    time_t refresh = config.d_retryOnError;
    try {
      ZoneData data(log);
      data.ZoneToCache(config);
      refresh = config.d_refreshPeriod;
      log->info("Loaded zone into cache", "refresh", Logging::Loggable(refresh));
    }
    catch (const PDNSException& e) {
      log->info("Unable to load zone into cache, will retry", "exception", Logging::Loggable(e.reason), "refresh", Logging::Loggable(refresh));
    }
    catch (const std::runtime_error& e) {
      log->info("Unable to load zone into cache, will retry", "exception", Logging::Loggable(e.what()), "refresh", Logging::Loggable(refresh));
    }
    catch (...) {
      log->info("Unable to load zone into cache, will retry", "exception", Logging::Loggable("unknown"), "refresh", Logging::Loggable(refresh));
    }
    if (refresh == 0) {
      return; // single shot
    }
    sleep(refresh);
  }
}
