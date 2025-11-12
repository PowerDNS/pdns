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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "tinydnsbackend.hh"
#include "pdns/misc.hh"
#include "pdns/dnsrecords.hh"
#include <utility>

static string backendname = "[TinyDNSBackend] ";
domainid_t TinyDNSBackend::s_lastId;
LockGuarded<TinyDNSBackend::TDI_suffix_t> TinyDNSBackend::s_domainInfo;

vector<string> TinyDNSBackend::getLocations()
{
  vector<string> ret;

  if (!d_dnspacket) {
    return ret;
  }

  //TODO: We do not have IPv6 support.
  Netmask remote = d_dnspacket->getRealRemote();
  if (remote.getBits() != 32) {
    return ret;
  }

  unsigned long addr = remote.getNetwork().sin4.sin_addr.s_addr;

  char key[6];
  key[0] = '\000';
  key[1] = '\045';
  key[2] = (addr) & 0xff;
  key[3] = (addr >> 8) & 0xff;
  key[4] = (addr >> 16) & 0xff;
  key[5] = (addr >> 24) & 0xff;

  for (int i = 4; i >= 0; i--) {
    string searchkey(key, i + 2);
    try {
      auto reader = std::make_unique<CDB>(getArg("dbfile"));
      ret = reader->findall(searchkey);
    }
    catch (const std::exception& e) {
      g_log << Logger::Error << e.what() << endl;
      throw PDNSException(e.what());
    }

    //Biggest item wins, so when we find something, we can jump out.
    if (ret.size() > 0) {
      break;
    }
  }

  return ret;
}

TinyDNSBackend::TinyDNSBackend(const string& suffix)
{
  setArgPrefix("tinydns" + suffix);
  d_suffix = suffix;
  d_locations = mustDo("locations");
  d_ignorebogus = mustDo("ignore-bogus-records");
  d_taiepoch = 4611686018427387904ULL + getArgAsNum("tai-adjust");
  d_dnspacket = NULL;
  d_cdbReader = NULL;
  d_isAxfr = false;
  d_isWildcardQuery = false;
}

TinyDNSBackend::TDI_t::iterator TinyDNSBackend::updateState(DomainInfo& domain, TDI_t* state)
{
  TDIByZone_t& zone_index = state->get<tag_zone>();
  TDIByZone_t::iterator itByZone = zone_index.find(domain.zone);
  if (itByZone != zone_index.end()) {
    return itByZone;
  }

  TinyDomainInfo tmp;
  s_lastId++;
  tmp.zone = domain.zone;
  tmp.id = s_lastId;
  tmp.notified_serial = domain.serial;
  return state->insert(tmp).first;
}

void TinyDNSBackend::getUpdatedPrimaries(vector<DomainInfo>& retDomains, std::unordered_set<DNSName>& /* catalogs */, CatalogHashMap& /* catalogHashes */)
{
  bool alwaysNotify{false};
  auto domainInfo = s_domainInfo.lock(); //TODO: We could actually lock less if we do it per suffix.
  if (domainInfo->count(d_suffix) == 0) {
    // If we don't have any state yet, this is startup, check whether we need
    // to always notify.
    alwaysNotify = mustDo("notify-on-startup");
    TDI_t tmp;
    domainInfo->emplace(d_suffix, tmp);
  }

  TDI_t* state = &(*domainInfo)[d_suffix];

  vector<DomainInfo> allDomains;
  getAllDomains_locked(&allDomains, true);

  for (auto& domain : allDomains) {
    auto iter = updateState(domain, state);
    // Keep domain id in sync with our current state.
    domain.id = iter->id;
    if (alwaysNotify || iter->notified_serial < domain.serial) {
      retDomains.push_back(domain);
    }
  }
}

// NOLINTNEXTLINE(readability-identifier-length)
void TinyDNSBackend::setNotified(domainid_t id, uint32_t serial)
{
  auto domainInfo = s_domainInfo.lock();
  if (!domainInfo->count(d_suffix)) {
    throw PDNSException("Can't get list of domains to set the serial.");
  }
  TDI_t* state = &(*domainInfo)[d_suffix];
  TDIById_t& domain_index = state->get<tag_domainid>();
  TDIById_t::iterator itById = domain_index.find(id);
  if (itById == domain_index.end()) {
    g_log << Logger::Error << backendname << "Received updated serial(" << serial << "), but domain ID (" << id << ") is not known in this backend." << endl;
  }
  else {
    DLOG(g_log << Logger::Debug << backendname << "Setting serial for " << itById->zone << " to " << serial << endl);
    domain_index.modify(itById, TDI_SerialModifier(serial));
  }
  (*domainInfo)[d_suffix] = *state;
}

void TinyDNSBackend::getAllDomains_locked(vector<DomainInfo>* domains, bool getSerial)
{
  d_isAxfr = true;
  d_isGetDomains = true;
  d_dnspacket = NULL;

  try {
    d_cdbReader = std::make_unique<CDB>(getArg("dbfile"));
    d_currentDomain = UnknownDomainID;
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << e.what() << endl;
    throw PDNSException(e.what());
  }

  d_cdbReader->searchAll();
  DNSResourceRecord rr;
  std::unordered_set<DNSName> dupcheck;

  while (get(rr)) {
    if (rr.qtype.getCode() == QType::SOA && dupcheck.insert(rr.qname).second) {
      DomainInfo di;
      di.id = d_currentDomain; // Will be overridden by caller
      di.backend = this;
      di.zone = ZoneName(rr.qname);
      di.kind = DomainInfo::Primary;
      di.last_check = time(0);

      if (getSerial) {
        SOAData sd;
        try {
          fillSOAData(rr.content, sd);
          di.serial = sd.serial;
        }
        catch (...) {
          di.serial = 0;
        }
      }

      di.notified_serial = di.serial;
      domains->push_back(di);
    }
  }
}

void TinyDNSBackend::getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool /* include_disabled */)
{
  auto domainInfo = s_domainInfo.lock(); //TODO: We could actually lock less if we do it per suffix.
  if (domainInfo->count(d_suffix) == 0) {
    TDI_t tmp;
    domainInfo->emplace(d_suffix, tmp);
  }

  TDI_t* state = &(*domainInfo)[d_suffix];

  getAllDomains_locked(domains, getSerial);

  for (auto& domain : *domains) {
    auto iter = updateState(domain, state);
    // Keep domain id in sync with our current state.
    domain.id = iter->id;
  }
}

//NOLINTNEXTLINE(readability-identifier-length)
bool TinyDNSBackend::getDomainInfo(const ZoneName& domain, DomainInfo& di, bool getSerial)
{
  auto domainInfo = s_domainInfo.lock(); //TODO: We could actually lock less if we do it per suffix.
  if (domainInfo->count(d_suffix) == 0) {
    TDI_t tmp;
    domainInfo->emplace(d_suffix, tmp);
  }

  TDI_t* state = &(*domainInfo)[d_suffix];

  vector<DomainInfo> allDomains;
  getAllDomains_locked(&allDomains, getSerial);

  bool found{false};
  for (auto& oneDomain : allDomains) {
    auto iter = updateState(oneDomain, state);
    if (oneDomain.zone == domain) {
      // Keep domain id in sync with our current state.
      oneDomain.id = iter->id;
      di = oneDomain;
      found = true;
    }
  }
  return found;
}

bool TinyDNSBackend::list(const ZoneName& target, domainid_t domain_id, bool /* include_disabled */)
{
  d_isAxfr = true;
  d_isGetDomains = false;
  string key = target.operator const DNSName&().toDNSStringLC();
  try {
    d_cdbReader = std::make_unique<CDB>(getArg("dbfile"));
    d_currentDomain = domain_id;
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << e.what() << endl;
    throw PDNSException(e.what());
  }

  return d_cdbReader->searchSuffix(key);
}

void TinyDNSBackend::lookup(const QType& qtype, const DNSName& qdomain, domainid_t zoneId, DNSPacket* pkt_p)
{
  d_isAxfr = false;
  d_isGetDomains = false;
  string queryDomain = toLowerCanonic(qdomain.toString());

  string key = simpleCompress(queryDomain);

  DLOG(g_log << Logger::Debug << backendname << "[lookup] query for qtype [" << qtype.toString() << "] qdomain [" << qdomain << "]" << endl);
  DLOG(g_log << Logger::Debug << "[lookup] key [" << makeHexDump(key) << "]" << endl);

  d_isWildcardQuery = false;
  if (key[0] == '\001' && key[1] == '\052') {
    d_isWildcardQuery = true;
    key.erase(0, 2);
  }

  d_qtype = qtype;

  try {
    d_cdbReader = std::make_unique<CDB>(getArg("dbfile"));
    d_currentDomain = zoneId;
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << e.what() << endl;
    throw PDNSException(e.what());
  }

  d_cdbReader->searchKey(key);
  d_dnspacket = pkt_p;
}

bool TinyDNSBackend::get(DNSResourceRecord& rr)
{
  pair<string, string> record;

  while (d_cdbReader->readNext(record)) {
    string val = record.second;
    string key = record.first;

#if 0
    DLOG(g_log<<Logger::Debug<<"[GET] Key: "<<makeHexDump(key)<<endl);
    DLOG(g_log<<Logger::Debug<<"[GET] Val: "<<makeHexDump(val)<<endl);
#endif
    if (key[0] == '\000' && key[1] == '\045') { // skip locations
      continue;
    }

    if (!d_isAxfr) {
      // If we have a wildcard query, but the record we got is not a wildcard, we skip.
      if (d_isWildcardQuery && val[2] != '\052' && val[2] != '\053') {
        continue;
      }

      // If it is NOT a wildcard query, but we do find a wildcard record, we skip it.
      if (!d_isWildcardQuery && (val[2] == '\052' || val[2] == '\053')) {
        continue;
      }
    }

    PacketReader pr(val, 0);
    rr.qtype = QType(pr.get16BitInt());

    if (d_isGetDomains && rr.qtype != QType::SOA) {
      continue;
    }

    if (d_isAxfr || d_qtype.getCode() == QType::ANY || rr.qtype == d_qtype) {
      char locwild = pr.get8BitInt();
      if (locwild != '\075' && (locwild == '\076' || locwild == '\053')) {
        if (d_isAxfr && d_locations) { // We skip records with a location in AXFR, unless we disable locations.
          continue;
        }
        char recloc[2];
        recloc[0] = pr.get8BitInt();
        recloc[1] = pr.get8BitInt();

        if (d_locations) {
          bool foundLocation = false;
          vector<string> locations = getLocations();
          while (locations.size() > 0) {
            string locId = locations.back();
            locations.pop_back();

            if (recloc[0] == locId[0] && recloc[1] == locId[1]) {
              foundLocation = true;
              break;
            }
          }
          if (!foundLocation) {
            continue;
          }
        }
      }

      if (d_isAxfr && (val[2] == '\052' || val[2] == '\053')) { // Keys are not stored with wildcard character, with AXFR we need to add that.
        key.insert(0, 1, '\052');
        key.insert(0, 1, '\001');
      }
      // rr.qname.clear();
      rr.qname = DNSName(key.c_str(), key.size(), 0, false);
      rr.domain_id = d_currentDomain;
      // 11:13.21 <@ahu> IT IS ALWAYS AUTH --- well not really because we are just a backend :-)
      // We could actually do NSEC3-NARROW DNSSEC according to Habbie, if we do, we need to change something here.
      rr.auth = true;

      rr.ttl = pr.get32BitInt();
      uint64_t timestamp = pr.get32BitInt();
      timestamp <<= 32;
      timestamp += pr.get32BitInt();
      if (timestamp) {
        uint64_t now = d_taiepoch + time(NULL);
        if (rr.ttl == 0) {
          if (timestamp < now) {
            continue;
          }
          rr.ttl = timestamp - now;
          if (rr.ttl <= 2)
            rr.ttl = 2;
          if (rr.ttl >= 3600)
            rr.ttl = 3600;
        }
        else if (now <= timestamp) {
          continue;
        }
      }
      try {
        DNSRecord dr;
        dr.d_class = 1;
        dr.d_type = rr.qtype.getCode();
        dr.d_clen = val.size() - pr.getPosition();

        auto drc = DNSRecordContent::make(dr, pr);
        rr.content = drc->getZoneRepresentation();
        DLOG(cerr << "CONTENT: " << rr.content << endl);
      }
      catch (...) {
        g_log << Logger::Error << backendname << "Failed to parse record content for " << rr.qname << " with type " << rr.qtype.toString();
        if (d_ignorebogus || d_isGetDomains) {
          g_log << ". Ignoring!" << endl;
          continue;
        }
        else {
          g_log << ". Erroring out!" << endl;
          throw;
        }
      }
#if 0
      DLOG(g_log<<Logger::Debug<<backendname<<"Returning ["<<rr.content<<"] for ["<<rr.qname<<"] of RecordType ["<<rr.qtype.toString()<<"]"<<endl;);
#endif
      return true;
    }
  } // end of while
  DLOG(g_log << Logger::Debug << backendname << "No more records to return." << endl);

  d_cdbReader = nullptr;
  d_currentDomain = UnknownDomainID;
  return false;
}

// boilerplate
class TinyDNSFactory : public BackendFactory
{
public:
  TinyDNSFactory() :
    BackendFactory("tinydns") {}

  void declareArguments(const string& suffix = "") override
  {
    declare(suffix, "notify-on-startup", "Tell the TinyDNSBackend to notify all the secondary nameservers on startup. Default is no.", "no");
    declare(suffix, "dbfile", "Location of the cdb data file", "data.cdb");
    declare(suffix, "tai-adjust", "This adjusts the TAI value if timestamps are used. These seconds will be added to the start point (1970) and will allow you to adjust for leap seconds. The default is 11.", "11");
    declare(suffix, "locations", "Enable or Disable location support in the backend. Changing the value to 'no' will make the backend ignore the locations. This then returns all records!", "yes");
    declare(suffix, "ignore-bogus-records", "The data.cdb file might have some incorrect record data, this causes PowerDNS to fail, where tinydns would send out truncated data. This option makes powerdns ignore that data!", "no");
  }

  DNSBackend* make(const string& suffix = "") override
  {
    return new TinyDNSBackend(suffix);
  }
};

// boilerplate
class TinyDNSLoader
{
public:
  TinyDNSLoader()
  {
    BackendMakers().report(std::make_unique<TinyDNSFactory>());
    g_log << Logger::Info << "[tinydnsbackend] This is the tinydns backend version " VERSION
#ifndef REPRODUCIBLE
          << " (" __DATE__ " " __TIME__ ")"
#endif
          << " reporting" << endl;
  }
};

static TinyDNSLoader tinydnsloader;
