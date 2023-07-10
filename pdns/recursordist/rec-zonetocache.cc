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
#include "rec-lua-conf.hh"
#include "zonemd.hh"
#include "validate.hh"

#ifdef HAVE_LIBCURL
#include "minicurl.hh"
#endif

#include <fstream>

struct ZoneData
{
  ZoneData(Logr::log_t log, const std::string& zone) :
    d_log(log),
    d_zone(zone),
    d_now(time(nullptr)) {}

  // Potentially the two fields below could be merged into a single map. ATM it is not clear to me
  // if that would make the code easier to read.
  std::map<pair<DNSName, QType>, vector<DNSRecord>> d_all;
  std::map<pair<DNSName, QType>, vector<shared_ptr<const RRSIGRecordContent>>> d_sigs;

  // Maybe use a SuffixMatchTree?
  std::set<DNSName> d_delegations;

  Logr::log_t d_log;
  DNSName d_zone;
  time_t d_now;

  bool isRRSetAuth(const DNSName& qname, QType qtype) const;
  void parseDRForCache(DNSRecord& dr);
  pdns::ZoneMD::Result getByAXFR(const RecZoneToCache::Config&, pdns::ZoneMD&);
  pdns::ZoneMD::Result processLines(const std::vector<std::string>& lines, const RecZoneToCache::Config& config, pdns::ZoneMD&);
  void ZoneToCache(const RecZoneToCache::Config& config);
  vState dnssecValidate(pdns::ZoneMD&, size_t& zonemdCount) const;
};

bool ZoneData::isRRSetAuth(const DNSName& qname, QType qtype) const
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
  if (dr.d_class != QClass::IN) {
    return;
  }
  const auto key = pair(dr.d_name, dr.d_type);

  dr.d_ttl += d_now;

  switch (dr.d_type) {
  case QType::NSEC:
  case QType::NSEC3:
    break;
  case QType::RRSIG: {
    const auto& rr = getRR<RRSIGRecordContent>(dr);
    const auto sigkey = pair(key.first, rr->d_type);
    auto found = d_sigs.find(sigkey);
    if (found != d_sigs.end()) {
      found->second.push_back(rr);
    }
    else {
      vector<shared_ptr<const RRSIGRecordContent>> sigsrr;
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

pdns::ZoneMD::Result ZoneData::getByAXFR(const RecZoneToCache::Config& config, pdns::ZoneMD& zonemd)
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
      if (config.d_zonemd != pdns::ZoneMD::Config::Ignore) {
        zonemd.readRecord(dr);
      }
      parseDRForCache(dr);
    }
    axfrNow = time(nullptr);
    if (axfrNow < axfrStart || axfrNow - axfrStart > axfrTimeout) {
      throw std::runtime_error("Total AXFR time for zoneToCache exceeded!");
    }
  }
  if (config.d_zonemd != pdns::ZoneMD::Config::Ignore) {
    bool validationDone, validationSuccess;
    zonemd.verify(validationDone, validationSuccess);
    d_log->info("ZONEMD digest validation", "validationDone", Logging::Loggable(validationDone),
                "validationSuccess", Logging::Loggable(validationSuccess));
    if (!validationDone) {
      return pdns::ZoneMD::Result::NoValidationDone;
    }
    if (!validationSuccess) {
      return pdns::ZoneMD::Result::ValidationFailure;
    }
  }
  return pdns::ZoneMD::Result::OK;
}

static std::vector<std::string> getLinesFromFile(const std::string& file)
{

  std::vector<std::string> lines;
  std::ifstream stream(file);
  if (!stream) {
    throw std::runtime_error("Cannot read file: " + file);
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
    throw std::runtime_error("Retrieved data exceeds maxReceivedBytes");
  }
  std::istringstream stream(reply);
  string line;
  while (std::getline(stream, line)) {
    lines.push_back(line);
  }
#else
  throw std::runtime_error("url method configured but libcurl not compiled in");
#endif
  return lines;
}

pdns::ZoneMD::Result ZoneData::processLines(const vector<string>& lines, const RecZoneToCache::Config& config, pdns::ZoneMD& zonemd)
{
  DNSResourceRecord drr;
  ZoneParserTNG zpt(lines, d_zone, true);
  zpt.setMaxGenerateSteps(1);
  zpt.setMaxIncludes(0);

  while (zpt.get(drr)) {
    DNSRecord dr(drr);
    if (config.d_zonemd != pdns::ZoneMD::Config::Ignore) {
      zonemd.readRecord(dr);
    }
    parseDRForCache(dr);
  }
  if (config.d_zonemd != pdns::ZoneMD::Config::Ignore) {
    bool validationDone, validationSuccess;
    zonemd.verify(validationDone, validationSuccess);
    d_log->info("ZONEMD digest validation", "validationDone", Logging::Loggable(validationDone),
                "validationSuccess", Logging::Loggable(validationSuccess));
    if (!validationDone) {
      return pdns::ZoneMD::Result::NoValidationDone;
    }
    if (!validationSuccess) {
      return pdns::ZoneMD::Result::ValidationFailure;
    }
  }
  return pdns::ZoneMD::Result::OK;
}

vState ZoneData::dnssecValidate(pdns::ZoneMD& zonemd, size_t& zonemdCount) const
{
  zonemdCount = 0;

  SyncRes sr({d_now, 0});
  sr.setDoDNSSEC(true);
  sr.setDNSSECValidationRequested(true);

  dsmap_t dsmap; // Actually a set
  vState dsState = sr.getDSRecords(d_zone, dsmap, false, 0, "");
  if (dsState != vState::Secure) {
    return dsState;
  }

  skeyset_t dnsKeys;
  sortedRecords_t records;
  if (zonemd.getDNSKEYs().size() == 0) {
    return vState::BogusUnableToGetDNSKEYs;
  }
  for (const auto& key : zonemd.getDNSKEYs()) {
    dnsKeys.emplace(key);
    records.emplace(key);
  }

  skeyset_t validKeys;
  vState dnsKeyState = validateDNSKeysAgainstDS(d_now, d_zone, dsmap, dnsKeys, records, zonemd.getRRSIGs(), validKeys, std::nullopt);
  if (dnsKeyState != vState::Secure) {
    return dnsKeyState;
  }

  if (validKeys.size() == 0) {
    return vState::BogusNoValidDNSKEY;
  }

  auto zonemdRecords = zonemd.getZONEMDs();
  zonemdCount = zonemdRecords.size();

  // De we need to do a denial validation?
  if (zonemdCount == 0) {
    const auto& nsecs = zonemd.getNSECs();
    const auto& nsec3s = zonemd.getNSEC3s();
    cspmap_t csp;

    vState nsecValidationStatus;

    if (nsecs.records.size() > 0 && nsecs.signatures.size() > 0) {
      // Valdidate the NSEC
      nsecValidationStatus = validateWithKeySet(d_now, d_zone, nsecs.records, nsecs.signatures, validKeys, std::nullopt);
      csp.emplace(std::make_pair(d_zone, QType::NSEC), nsecs);
    }
    else if (nsec3s.records.size() > 0 && nsec3s.signatures.size() > 0) {
      // Validate NSEC3PARAMS
      records.clear();
      for (const auto& rec : zonemd.getNSEC3Params()) {
        records.emplace(rec);
      }
      nsecValidationStatus = validateWithKeySet(d_now, d_zone, records, zonemd.getRRSIGs(), validKeys, std::nullopt);
      if (nsecValidationStatus != vState::Secure) {
        d_log->info("NSEC3PARAMS records did not validate");
        return nsecValidationStatus;
      }
      // Valdidate the NSEC3
      nsecValidationStatus = validateWithKeySet(d_now, zonemd.getNSEC3Label(), nsec3s.records, nsec3s.signatures, validKeys, std::nullopt);
      csp.emplace(std::make_pair(zonemd.getNSEC3Label(), QType::NSEC3), nsec3s);
    }
    else {
      d_log->info("No NSEC(3) records and/or RRSIGS found to deny ZONEMD");
      return vState::BogusInvalidDenial;
    }

    if (nsecValidationStatus != vState::Secure) {
      d_log->info("zone NSEC(3) record does not validate");
      return nsecValidationStatus;
    }

    auto denial = getDenial(csp, d_zone, QType::ZONEMD, false, false, std::nullopt, true);
    if (denial == dState::NXQTYPE) {
      d_log->info("Validated denial of absence of ZONEMD record");
      return vState::Secure;
    }
    d_log->info("No ZONEMD record, but NSEC(3) record does not deny it");
    return vState::BogusInvalidDenial;
  }

  // Collect the ZONEMD records and validate them using the validated DNSSKEYs
  records.clear();
  for (const auto& rec : zonemdRecords) {
    records.emplace(rec);
  }
  return validateWithKeySet(d_now, d_zone, records, zonemd.getRRSIGs(), validKeys, std::nullopt);
}

void ZoneData::ZoneToCache(const RecZoneToCache::Config& config)
{
  if (config.d_sources.size() > 1) {
    d_log->info("Multiple sources not yet supported, using first");
  }

  if (config.d_dnssec == pdns::ZoneMD::Config::Require && (g_dnssecmode == DNSSECMode::Off || g_dnssecmode == DNSSECMode::ProcessNoValidate)) {
    throw PDNSException("ZONEMD DNSSEC validation failure: DNSSEC validation is switched off but required by ZoneToCache");
  }

  // First scan all records collecting info about delegations and sigs
  // A this moment, we ignore NSEC and NSEC3 records. It is not clear to me yet under which conditions
  // they could be entered in into the (neg)cache.

  auto zonemd = pdns::ZoneMD(DNSName(config.d_zone));
  pdns::ZoneMD::Result result = pdns::ZoneMD::Result::OK;
  if (config.d_method == "axfr") {
    d_log->info("Getting zone by AXFR");
    result = getByAXFR(config, zonemd);
  }
  else {
    vector<string> lines;
    if (config.d_method == "url") {
      d_log->info("Getting zone by URL");
      lines = getURL(config);
    }
    else if (config.d_method == "file") {
      d_log->info("Getting zone from file");
      lines = getLinesFromFile(config.d_sources.at(0));
    }
    result = processLines(lines, config, zonemd);
  }

  // Validate DNSKEYs and ZONEMD, rest of records are validated on-demand by SyncRes
  if (config.d_dnssec == pdns::ZoneMD::Config::Require || (g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate && config.d_dnssec != pdns::ZoneMD::Config::Ignore)) {
    size_t zonemdCount;
    auto validationStatus = dnssecValidate(zonemd, zonemdCount);
    d_log->info("ZONEMD record related DNSSEC validation", "validationStatus", Logging::Loggable(validationStatus),
                "zonemdCount", Logging::Loggable(zonemdCount));
    if (config.d_dnssec == pdns::ZoneMD::Config::Require && validationStatus != vState::Secure) {
      throw PDNSException("ZONEMD required DNSSEC validation failed");
    }
    if (validationStatus != vState::Secure && validationStatus != vState::Insecure) {
      throw PDNSException("ZONEMD record DNSSEC validation failed");
    }
  }

  if (config.d_zonemd == pdns::ZoneMD::Config::Require && result != pdns::ZoneMD::Result::OK) {
    // We do not accept NoValidationDone in this case
    throw PDNSException("ZONEMD digest validation failure");
    return;
  }
  if (config.d_zonemd == pdns::ZoneMD::Config::Validate && result == pdns::ZoneMD::Result::ValidationFailure) {
    throw PDNSException("ZONEMD digest validation failure");
    return;
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
      vector<shared_ptr<const RRSIGRecordContent>> sigsrr;
      auto it = d_sigs.find(key);
      if (it != d_sigs.end()) {
        sigsrr = it->second;
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

void RecZoneToCache::maintainStates(const map<DNSName, Config>& configs, map<DNSName, State>& states, uint64_t mygeneration)
{
  // Delete states that have no config
  for (auto it = states.begin(); it != states.end();) {
    if (configs.find(it->first) == configs.end()) {
      it = states.erase(it);
    }
    else {
      it = ++it;
    }
  }
  // Reset states for which the config generation changed and create new states for new configs
  for (const auto& config : configs) {
    auto state = states.find(config.first);
    if (state != states.end()) {
      if (state->second.d_generation != mygeneration) {
        state->second = {0, 0, mygeneration};
      }
    }
    else {
      states.emplace(std::make_pair(config.first, State{0, 0, mygeneration}));
    }
  }
}

void RecZoneToCache::ZoneToCache(const RecZoneToCache::Config& config, RecZoneToCache::State& state)
{
  if (state.d_waittime == 0 && state.d_lastrun > 0) {
    // single shot
    return;
  }
  if (state.d_lastrun > 0 && state.d_lastrun + state.d_waittime > time(nullptr)) {
    return;
  }
  auto log = g_slog->withName("ztc")->withValues("zone", Logging::Loggable(config.d_zone));

  state.d_waittime = config.d_retryOnError;
  try {
    ZoneData data(log, config.d_zone);
    data.ZoneToCache(config);
    state.d_waittime = config.d_refreshPeriod;
    log->info("Loaded zone into cache", "refresh", Logging::Loggable(state.d_waittime));
  }
  catch (const PDNSException& e) {
    log->error(Logr::Error, e.reason, "Unable to load zone into cache, will retry", "exception", Logging::Loggable("PDNSException"), "refresh", Logging::Loggable(state.d_waittime));
  }
  catch (const std::runtime_error& e) {
    log->error(Logr::Error, e.what(), "Unable to load zone into cache, will retry", "exception", Logging::Loggable("std::runtime_error"), "refresh", Logging::Loggable(state.d_waittime));
  }
  catch (...) {
    log->info("Unable to load zone into cache, will retry", "refresh", Logging::Loggable(state.d_waittime));
  }
  state.d_lastrun = time(nullptr);
  return;
}
