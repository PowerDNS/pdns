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
#include "minicurl.hh"
#include "zoneparser-tng.hh"
#include "query-local-address.hh"
#include "axfr-retriever.hh"
#include "validate-recursor.hh"

time_t RecZoneToCache::ZonesToCache(const std::map<std::string, std::string>& map)
{
  // By default and max once per 24 hours
  time_t refresh = 24 * 3600;

  struct timeval now;
  gettimeofday(&now, nullptr);
  SyncRes sr(now);
  bool dnssec = g_dnssecmode != DNSSECMode::Off;
  sr.setDoDNSSEC(dnssec);
  sr.setDNSSECValidationRequested(g_dnssecmode != DNSSECMode::Off && g_dnssecmode != DNSSECMode::ProcessNoValidate);

  for (const auto& [zone, url] : map) {
    const string msg = "zones-to-cache error while loading " + zone + " from " + url + ": ";
    try {
      refresh = min(refresh, ZoneToCache(zone, url, dnssec));
    }
    catch (const PDNSException& e) {
      g_log << Logger::Error << msg << e.reason << endl;
    }
    catch (const std::runtime_error& e) {
      g_log << Logger::Error << msg << e.what() << endl;
    }
    catch (...) {
      g_log << Logger::Error << msg << "unexpected exception" << endl;
    }

    // We do not want to refresh more than once per hour
    refresh = max(refresh, 3600LL);
  }

  return refresh;
}

struct ZoneData
{
  std::map<pair<DNSName, QType>, vector<DNSRecord>> d_all;
  std::map<pair<DNSName, QType>, vector<shared_ptr<RRSIGRecordContent>>> d_sigs;
  std::set<DNSName> d_delegations;
  time_t d_refresh;
  time_t d_now;
  DNSName d_zone;

  bool isRRSetAuth(const DNSName& qname, QType qtype);
  void parseDRForCache(DNSRecord& dr);
  void getByAXFR(const std::string& url);
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

  d_refresh = min(d_refresh, static_cast<time_t>(dr.d_ttl));
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

void ZoneData::getByAXFR(const std::string& url)
{
  ComboAddress primary = ComboAddress(url.substr(7), 53);
  uint16_t axfrTimeout = 20;
  size_t maxReceivedBytes = 0;
  const TSIGTriplet tt;
  ComboAddress local; //(localAddress);
  if (local == ComboAddress()) {
    local = pdns::getQueryLocalAddress(primary.sin4.sin_family, 0);
  }
  AXFRRetriever axfr(primary, d_zone, tt, &local, maxReceivedBytes, axfrTimeout);
  Resolver::res_t nop;
  vector<DNSRecord> chunk;
  time_t axfrStart = time(nullptr);
  time_t axfrNow = time(nullptr);
  shared_ptr<SOARecordContent> sr;
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

static std::vector<std::string> getLinesFromFile(const std::string& url)
{
  std::vector<std::string> lines;
  std::ifstream stream(url);
  std::string line;
  while (std::getline(stream, line)) {
    lines.push_back(line);
  }
  return lines;
}

static std::vector<std::string> getURL(const std::string& url)
{
  std::vector<std::string> lines;
#ifdef HAVE_LIBCURL
  MiniCurl mc;
  std::string reply = mc.getURL(url, nullptr, nullptr, 10, false, true);
  std::istringstream stream(reply);
  string line;
  while (std::getline(stream, line)) {
    lines.push_back(line);
  }
#endif
  return lines;
}

time_t RecZoneToCache::ZoneToCache(const string& name, const string& url, bool dnssec)
{
  ZoneData data;
  data.d_refresh = std::numeric_limits<time_t>::max();
  data.d_zone = DNSName(name);
  data.d_now = time(nullptr);

  // We do not do validation, it will happen on-demand if an Indeterminate record is encountered when the caches are queried
  // First scan all records collecting info about delegations ans sigs
  // A this moment, we ignore NSEC and NSEC3 records. It is not clear to me yet under which conditions
  // they could be entered in into the (neg)cache.

  if (url.substr(0, 7) == "axfr://") {
    data.getByAXFR(url);
  }
  else {
    vector<string> lines;
    if (url.substr(0, 8) != "https://" && url.substr(0, 7) != "http://") {
      lines = getLinesFromFile(url);
    }
    else {
      lines = getURL(url);
    }
    DNSResourceRecord drr;
    ZoneParserTNG zpt(lines, data.d_zone);
    zpt.setMaxGenerateSteps(0);

    while (zpt.get(drr)) {
      DNSRecord dr(drr);
      data.parseDRForCache(dr);
    }
  }

  // Rerun, now inserting the rrsets into the cache with associated sigs
  data.d_now = time(nullptr);
  for (const auto& [key, v] : data.d_all) {
    const auto& [qname, qtype] = key;
    switch (qtype) {
    case QType::NSEC:
    case QType::NSEC3:
      break;
    case QType::RRSIG:
      break;
    default: {
      vector<shared_ptr<RRSIGRecordContent>> sigsrr;
      auto it = data.d_sigs.find(key);
      if (it != data.d_sigs.end()) {
        for (const auto& sig : it->second) {
          sigsrr.push_back(sig);
        }
      }
      bool auth = data.isRRSetAuth(qname, qtype);
      // Same decision as updateCacheFromRecords() (we do not test for NSEC since we skip those completely)
      if (auth || (qtype == QType::NS || qtype == QType::A || qtype == QType::AAAA || qtype == QType::DS)) {
        g_recCache->replace(data.d_now, qname, qtype, v, sigsrr,
                            std::vector<std::shared_ptr<DNSRecord>>(), auth, data.d_zone);
      }
      break;
    }
    }
  }

  return data.d_refresh;
}
