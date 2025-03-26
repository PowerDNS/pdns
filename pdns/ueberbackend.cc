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
#include <memory>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>

#include "auth-querycache.hh"
#include "auth-zonecache.hh"

#include <dlfcn.h>
#include <map>
#include <string>
#include <sys/types.h>

#include "dns.hh"
#include "arguments.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "logger.hh"
#include "statbag.hh"

extern StatBag S;

LockGuarded<vector<UeberBackend*>> UeberBackend::d_instances;

// initially we are blocked
bool UeberBackend::d_go = false;
bool UeberBackend::s_doANYLookupsOnly = false;
std::mutex UeberBackend::d_mut;
std::condition_variable UeberBackend::d_cond;
AtomicCounter* UeberBackend::s_backendQueries = nullptr;

//! Loads a module and reports it to all UeberBackend threads
bool UeberBackend::loadmodule(const string& name)
{
  g_log << Logger::Warning << "Loading '" << name << "'" << endl;

  void* dlib = dlopen(name.c_str(), RTLD_NOW);

  if (dlib == nullptr) {
    // NOLINTNEXTLINE(concurrency-mt-unsafe): There's no thread-safe alternative to dlerror().
    g_log << Logger::Error << "Unable to load module '" << name << "': " << dlerror() << endl;
    return false;
  }

  return true;
}

bool UeberBackend::loadModules(const vector<string>& modules, const string& path)
{
  g_log << Logger::Debug << "UeberBackend: path = " << path << endl;

  for (const auto& module : modules) {
    bool res = false;

    g_log << Logger::Debug << "UeberBackend: Attempting to load module '" << module << "'" << endl;

    if (module.find('.') == string::npos) {
      auto fullPath = path;
      fullPath += "/lib";
      fullPath += module;
      fullPath += "backend.so";
      g_log << Logger::Debug << "UeberBackend: Loading '" << fullPath << "'" << endl;
      res = UeberBackend::loadmodule(fullPath);
    }
    else if (module[0] == '/' || (module[0] == '.' && module[1] == '/') || (module[0] == '.' && module[1] == '.')) {
      // Absolute path, Current path or Parent path
      g_log << Logger::Debug << "UeberBackend: Loading '" << module << "'" << endl;
      res = UeberBackend::loadmodule(module);
    }
    else {
      auto fullPath = path;
      fullPath += "/";
      fullPath += module;
      g_log << Logger::Debug << "UeberBackend: Loading '" << fullPath << "'" << endl;
      res = UeberBackend::loadmodule(fullPath);
    }

    if (!res) {
      return false;
    }
  }
  return true;
}

void UeberBackend::go()
{
  if (::arg().mustDo("consistent-backends")) {
    s_doANYLookupsOnly = true;
  }

  S.declare("backend-queries", "Number of queries sent to the backend(s)");
  s_backendQueries = S.getPointer("backend-queries");

  {
    std::unique_lock<std::mutex> lock(d_mut);
    d_go = true;
  }
  d_cond.notify_all();
}

bool UeberBackend::getDomainInfo(const DNSName& domain, DomainInfo& domainInfo, bool getSerial)
{
  return firstCapableBackend(&DNSBackend::getDomainInfo, domain, domainInfo, getSerial);
}

bool UeberBackend::createDomain(const DNSName& domain, const DomainInfo::DomainKind kind, const vector<ComboAddress>& primaries, const string& account)
{
  return firstCapableBackend(&DNSBackend::createDomain, domain, kind, primaries, account);
}

bool UeberBackend::doesDNSSEC()
{
  return firstCapableBackend(&DNSBackend::doesDNSSEC);
}

bool UeberBackend::addDomainKey(const DNSName& name, const DNSBackend::KeyData& key, int64_t& keyID)
{
  keyID = -1;
  return firstCapableBackend(&DNSBackend::addDomainKey, name, key, keyID);
}
bool UeberBackend::getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys)
{
  return firstCapableBackend(&DNSBackend::getDomainKeys, name, keys);
}

bool UeberBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string>>& meta)
{
  return firstCapableBackend(&DNSBackend::getAllDomainMetadata, name, meta);
}

bool UeberBackend::getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta)
{
  return firstCapableBackend(&DNSBackend::getDomainMetadata, name, kind, meta);
}

bool UeberBackend::getDomainMetadata(const DNSName& name, const std::string& kind, std::string& meta)
{
  meta.clear();
  std::vector<string> tmp;
  const bool ret = getDomainMetadata(name, kind, tmp);
  if (ret && !tmp.empty()) {
    meta = *tmp.begin();
  }
  return ret;
}

bool UeberBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  return firstCapableBackend(&DNSBackend::setDomainMetadata, name, kind, meta);
}

bool UeberBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::string& meta)
{
  std::vector<string> tmp;
  if (!meta.empty()) {
    tmp.push_back(meta);
  }
  return setDomainMetadata(name, kind, tmp);
}

bool UeberBackend::activateDomainKey(const DNSName& name, unsigned int keyID)
{
  return firstCapableBackend(&DNSBackend::activateDomainKey, name, keyID);
}

bool UeberBackend::deactivateDomainKey(const DNSName& name, unsigned int keyID)
{
  return firstCapableBackend(&DNSBackend::deactivateDomainKey, name, keyID);
}

bool UeberBackend::publishDomainKey(const DNSName& name, unsigned int keyID)
{
  return firstCapableBackend(&DNSBackend::publishDomainKey, name, keyID);
}

bool UeberBackend::unpublishDomainKey(const DNSName& name, unsigned int keyID)
{
  return firstCapableBackend(&DNSBackend::unpublishDomainKey, name, keyID);
}

bool UeberBackend::removeDomainKey(const DNSName& name, unsigned int keyID)
{
  return firstCapableBackend(&DNSBackend::removeDomainKey, name, keyID);
}

void UeberBackend::reload()
{
  backendIterator(&DNSBackend::reload);
}

void UeberBackend::updateZoneCache()
{
  if (!g_zoneCache.isEnabled()) {
    return;
  }

  vector<std::tuple<DNSName, int>> zone_indices;
  g_zoneCache.setReplacePending();

  for (auto& backend : backends) {
    vector<DomainInfo> zones;
    backend->getAllDomains(&zones, false, true);
    for (auto& domainInfo : zones) {
      zone_indices.emplace_back(std::move(domainInfo.zone), (int)domainInfo.id); // this cast should not be necessary
    }
  }
  g_zoneCache.replace(zone_indices);
}

void UeberBackend::rediscover(string* status)
{
  for (auto backend = backends.begin(); backend != backends.end(); ++backend) {
    string tmpstr;
    (*backend)->rediscover(&tmpstr);
    if (status != nullptr) {
      *status += tmpstr + (backend != backends.begin() ? "\n" : "");
    }
  }

  updateZoneCache();
}

void UeberBackend::getUnfreshSecondaryInfos(vector<DomainInfo>* domains)
{
  backendIterator(&DNSBackend::getUnfreshSecondaryInfos, domains);
}

void UeberBackend::getUpdatedPrimaries(vector<DomainInfo>& domains, std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes)
{
  backendIterator(&DNSBackend::getUpdatedPrimaries, domains, catalogs, catalogHashes);
}

bool UeberBackend::inTransaction()
{
  return firstCapableBackend(&DNSBackend::inTransaction);
}

bool UeberBackend::fillSOAFromZoneRecord(DNSName& shorter, const int zoneId, SOAData* const soaData)
{
  // Zone exists in zone cache, directly look up SOA.
  lookup(QType(QType::SOA), shorter, zoneId, nullptr);

  DNSZoneRecord zoneRecord;
  if (!get(zoneRecord)) {
    DLOG(g_log << Logger::Info << "Backend returned no SOA for zone '" << shorter.toLogString() << "', which it reported as existing " << endl);
    return false;
  }

  if (zoneRecord.dr.d_name != shorter) {
    throw PDNSException("getAuth() returned an SOA for the wrong zone. Zone '" + zoneRecord.dr.d_name.toLogString() + "' is not equal to looked up zone '" + shorter.toLogString() + "'");
  }

  // Fill soaData.
  soaData->qname = zoneRecord.dr.d_name;

  try {
    fillSOAData(zoneRecord, *soaData);
  }
  catch (...) {
    g_log << Logger::Warning << "Backend returned a broken SOA for zone '" << shorter.toLogString() << "'" << endl;

    while (get(zoneRecord)) {
      ;
    }

    return false;
  }

  soaData->db = backends.size() == 1 ? backends.begin()->get() : nullptr;

  // Leave database handle in a consistent state.
  while (get(zoneRecord)) {
    ;
  }

  return true;
}

UeberBackend::CacheResult UeberBackend::fillSOAFromCache(SOAData* soaData, DNSName& shorter)
{
  auto cacheResult = cacheHas(d_question, d_answers);

  if (cacheResult == CacheResult::Hit && !d_answers.empty() && d_cache_ttl != 0U) {
    DLOG(g_log << Logger::Error << "has pos cache entry: " << shorter << endl);
    fillSOAData(d_answers[0], *soaData);

    soaData->db = backends.size() == 1 ? backends.begin()->get() : nullptr;
    soaData->qname = shorter;
  }
  else if (cacheResult == CacheResult::NegativeMatch && d_negcache_ttl != 0U) {
    DLOG(g_log << Logger::Error << "has neg cache entry: " << shorter << endl);
  }

  return cacheResult;
}

static std::vector<std::unique_ptr<DNSBackend>>::iterator findBestMatchingBackend(std::vector<std::unique_ptr<DNSBackend>>& backends, std::vector<std::pair<std::size_t, SOAData>>& bestMatches, const DNSName& shorter, SOAData* soaData)
{
  auto backend = backends.begin();
  for (auto bestMatch = bestMatches.begin(); backend != backends.end() && bestMatch != bestMatches.end(); ++backend, ++bestMatch) {

    DLOG(g_log << Logger::Error << "backend: " << backend - backends.begin() << ", qname: " << shorter << endl);

    if (bestMatch->first < shorter.wirelength()) {
      DLOG(g_log << Logger::Error << "skipped, we already found a shorter best match in this backend: " << bestMatch->second.qname << endl);
      continue;
    }

    if (bestMatch->first == shorter.wirelength()) {
      DLOG(g_log << Logger::Error << "use shorter best match: " << bestMatch->second.qname << endl);
      *soaData = bestMatch->second;
      break;
    }

    DLOG(g_log << Logger::Error << "lookup: " << shorter << endl);

    if ((*backend)->getAuth(shorter, soaData)) {
      DLOG(g_log << Logger::Error << "got: " << soaData->qname << endl);

      if (!soaData->qname.empty() && !shorter.isPartOf(soaData->qname)) {
        throw PDNSException("getAuth() returned an SOA for the wrong zone. Zone '" + soaData->qname.toLogString() + "' is not part of '" + shorter.toLogString() + "'");
      }

      bestMatch->first = soaData->qname.wirelength();
      bestMatch->second = *soaData;

      if (soaData->qname == shorter) {
        break;
      }
    }
    else {
      DLOG(g_log << Logger::Error << "no match for: " << shorter << endl);
    }
  }

  return backend;
}

static bool foundTarget(const DNSName& target, const DNSName& shorter, const QType& qtype, [[maybe_unused]] SOAData* soaData, const bool found)
{
  if (found == (qtype == QType::DS) || target != shorter) {
    DLOG(g_log << Logger::Error << "found: " << soaData->qname << endl);
    return true;
  }

  DLOG(g_log << Logger::Error << "chasing next: " << soaData->qname << endl);
  return false;
}

bool UeberBackend::getAuth(const DNSName& target, const QType& qtype, SOAData* soaData, bool cachedOk)
{
  // A backend can respond to our authority request with the 'best' match it
  // has. For example, when asked for a.b.c.example.com. it might respond with
  // com. We then store that and keep querying the other backends in case one
  // of them has a more specific zone but don't bother asking this specific
  // backend again for b.c.example.com., c.example.com. and example.com.
  // If a backend has no match it may respond with an empty qname.

  bool found = false;
  DNSName shorter(target);
  vector<pair<size_t, SOAData>> bestMatches(backends.size(), pair(target.wirelength() + 1, SOAData()));

  bool first = true;
  while (first || shorter.chopOff()) {
    first = false;

    int zoneId{-1};

    if (cachedOk && g_zoneCache.isEnabled()) {
      if (g_zoneCache.getEntry(shorter, zoneId)) {
        if (fillSOAFromZoneRecord(shorter, zoneId, soaData)) {
          if (foundTarget(target, shorter, qtype, soaData, found)) {
            return true;
          }

          found = true;
        }

        continue;
      }

      // Zone does not exist, try again with a shorter name.
      continue;
    }

    d_question.qtype = QType::SOA;
    d_question.qname = shorter;
    d_question.zoneId = zoneId;

    // Check cache.
    if (cachedOk && (d_cache_ttl != 0 || d_negcache_ttl != 0)) {
      auto cacheResult = fillSOAFromCache(soaData, shorter);
      if (cacheResult == CacheResult::Hit) {
        if (foundTarget(target, shorter, qtype, soaData, found)) {
          return true;
        }

        found = true;
        continue;
      }

      if (cacheResult == CacheResult::NegativeMatch) {
        continue;
      }
    }

    // Check backends.
    {
      auto backend = findBestMatchingBackend(backends, bestMatches, shorter, soaData);

      // Add to cache
      if (backend == backends.end()) {
        if (d_negcache_ttl != 0U) {
          DLOG(g_log << Logger::Error << "add neg cache entry:" << shorter << endl);
          d_question.qname = shorter;
          addNegCache(d_question);
        }

        continue;
      }

      if (d_cache_ttl != 0) {
        DLOG(g_log << Logger::Error << "add pos cache entry: " << soaData->qname << endl);

        d_question.qtype = QType::SOA;
        d_question.qname = soaData->qname;
        d_question.zoneId = zoneId;

        DNSZoneRecord resourceRecord;
        resourceRecord.dr.d_name = soaData->qname;
        resourceRecord.dr.d_type = QType::SOA;
        resourceRecord.dr.setContent(makeSOAContent(*soaData));
        resourceRecord.dr.d_ttl = soaData->ttl;
        resourceRecord.domain_id = soaData->domain_id;

        addCache(d_question, {std::move(resourceRecord)});
      }
    }

    if (foundTarget(target, shorter, qtype, soaData, found)) {
      return true;
    }

    found = true;
  }

  return found;
}

bool UeberBackend::getSOAUncached(const DNSName& domain, SOAData& soaData)
{
  d_question.qtype = QType::SOA;
  d_question.qname = domain;
  d_question.zoneId = -1;

  for (auto& backend : backends) {
    if (backend->getSOA(domain, soaData)) {
      if (domain != soaData.qname) {
        throw PDNSException("getSOA() returned an SOA for the wrong zone. Question: '" + domain.toLogString() + "', answer: '" + soaData.qname.toLogString() + "'");
      }
      if (d_cache_ttl != 0U) {
        DNSZoneRecord zoneRecord;
        zoneRecord.dr.d_name = soaData.qname;
        zoneRecord.dr.d_type = QType::SOA;
        zoneRecord.dr.setContent(makeSOAContent(soaData));
        zoneRecord.dr.d_ttl = soaData.ttl;
        zoneRecord.domain_id = soaData.domain_id;

        addCache(d_question, {std::move(zoneRecord)});
      }
      return true;
    }
  }

  if (d_negcache_ttl != 0U) {
    addNegCache(d_question);
  }
  return false;
}

bool UeberBackend::autoPrimaryAdd(const AutoPrimary& primary)
{
  return firstCapableBackend(&DNSBackend::autoPrimaryAdd, primary);
}

bool UeberBackend::autoPrimaryRemove(const AutoPrimary& primary)
{
  return firstCapableBackend(&DNSBackend::autoPrimaryRemove, primary);
}

bool UeberBackend::autoPrimariesList(std::vector<AutoPrimary>& primaries)
{
  return firstCapableBackend(&DNSBackend::autoPrimariesList, primaries);
}

bool UeberBackend::autoPrimaryBackend(const string& ipAddr, const DNSName& domain, const vector<DNSResourceRecord>& nsset, string* nameserver, string* account, DNSBackend** dnsBackend)
{
  return firstCapableBackend(&DNSBackend::autoPrimaryBackend, ipAddr, domain, nsset, nameserver, account, dnsBackend);
}

UeberBackend::UeberBackend(const string& pname)
{
  {
    d_instances.lock()->push_back(this); // report to the static list of ourself
  }

  d_cache_ttl = ::arg().asNum("query-cache-ttl");
  d_negcache_ttl = ::arg().asNum("negquery-cache-ttl");

  backends = BackendMakers().all(pname == "key-only");
}

// returns -1 for miss, 0 for negative match, 1 for hit
enum UeberBackend::CacheResult UeberBackend::cacheHas(const Question& question, vector<DNSZoneRecord>& resourceRecords) const
{
  extern AuthQueryCache QC;

  if (d_cache_ttl == 0 && d_negcache_ttl == 0) {
    return CacheResult::Miss;
  }

  resourceRecords.clear();
  //  g_log<<Logger::Warning<<"looking up: '"<<q.qname+"'|N|"+q.qtype.getName()+"|"+itoa(q.zoneId)<<endl;

  bool ret = QC.getEntry(question.qname, question.qtype, resourceRecords, question.zoneId); // think about lowercasing here
  if (!ret) {
    return CacheResult::Miss;
  }
  if (resourceRecords.empty()) { // negatively cached
    return CacheResult::NegativeMatch;
  }

  return CacheResult::Hit;
}

void UeberBackend::addNegCache(const Question& question) const
{
  extern AuthQueryCache QC;

  if (d_negcache_ttl == 0) {
    return;
  }
  // we should also not be storing negative answers if a pipebackend does scopeMask, but we can't pass a negative scopeMask in an empty set!
  QC.insert(question.qname, question.qtype, vector<DNSZoneRecord>(), d_negcache_ttl, question.zoneId);
}

void UeberBackend::addCache(const Question& question, vector<DNSZoneRecord>&& rrs) const
{
  extern AuthQueryCache QC;

  if (d_cache_ttl == 0) {
    return;
  }

  for (const auto& resourceRecord : rrs) {
    if (resourceRecord.scopeMask != 0) {
      return;
    }
  }

  QC.insert(question.qname, question.qtype, std::move(rrs), d_cache_ttl, question.zoneId);
}

void UeberBackend::alsoNotifies(const DNSName& domain, set<string>* ips)
{
  backendIterator(&DNSBackend::alsoNotifies, domain, ips);
}

UeberBackend::~UeberBackend()
{
  DLOG(g_log << Logger::Error << "UeberBackend destructor called, removing ourselves from instances, and deleting our backends" << endl);

  {
    auto instances = d_instances.lock();
    [[maybe_unused]] auto end = remove(instances->begin(), instances->end(), this);
    instances->resize(instances->size() - 1);
  }

  backends.clear();
}

// this handle is more magic than most
void UeberBackend::lookup(const QType& qtype, const DNSName& qname, int zoneId, DNSPacket* pkt_p)
{
  if (d_stale) {
    g_log << Logger::Error << "Stale ueberbackend received question, signalling that we want to be recycled" << endl;
    throw PDNSException("We are stale, please recycle");
  }

  DLOG(g_log << "UeberBackend received question for " << qtype << " of " << qname << endl);
  if (!d_go) {
    g_log << Logger::Error << "UeberBackend is blocked, waiting for 'go'" << endl;
    std::unique_lock<std::mutex> lock(d_mut);
    d_cond.wait(lock, [] { return d_go; });
    g_log << Logger::Error << "Broadcast received, unblocked" << endl;
  }

  d_qtype = qtype.getCode();

  d_handle.i = 0;
  d_handle.qtype = s_doANYLookupsOnly ? QType::ANY : qtype;
  d_handle.qname = qname;
  d_handle.zoneId = zoneId;
  d_handle.pkt_p = pkt_p;

  if (backends.empty()) {
    g_log << Logger::Error << "No database backends available - unable to answer questions." << endl;
    d_stale = true; // please recycle us!
    throw PDNSException("We are stale, please recycle");
  }

  d_question.qtype = d_handle.qtype;
  d_question.qname = qname;
  d_question.zoneId = d_handle.zoneId;

  auto cacheResult = cacheHas(d_question, d_answers);
  if (cacheResult == CacheResult::Miss) { // nothing
    //      cout<<"UeberBackend::lookup("<<qname<<"|"<<DNSRecordContent::NumberToType(qtype.getCode())<<"): uncached"<<endl;
    d_negcached = d_cached = false;
    d_answers.clear();
    (d_handle.d_hinterBackend = backends[d_handle.i++].get())->lookup(d_handle.qtype, d_handle.qname, d_handle.zoneId, d_handle.pkt_p);
    ++(*s_backendQueries);
  }
  else if (cacheResult == CacheResult::NegativeMatch) {
    //      cout<<"UeberBackend::lookup("<<qname<<"|"<<DNSRecordContent::NumberToType(qtype.getCode())<<"): NEGcached"<<endl;
    d_negcached = true;
    d_cached = false;
    d_answers.clear();
  }
  else {
    // cout<<"UeberBackend::lookup("<<qname<<"|"<<DNSRecordContent::NumberToType(qtype.getCode())<<"): CACHED"<<endl;
    d_negcached = false;
    d_cached = true;
    d_cachehandleiter = d_answers.begin();
  }

  d_handle.parent = this;
}

void UeberBackend::getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled)
{
  backendIterator(&DNSBackend::getAllDomains, domains, getSerial, include_disabled);
}

bool UeberBackend::get(DNSZoneRecord& resourceRecord)
{
  // cout<<"UeberBackend::get(DNSZoneRecord) called"<<endl;
  if (d_negcached) {
    return false;
  }

  if (d_cached) {
    while (d_cachehandleiter != d_answers.end()) {
      resourceRecord = *d_cachehandleiter++;
      if ((d_qtype == QType::ANY || resourceRecord.dr.d_type == d_qtype)) {
        return true;
      }
    }
    return false;
  }

  while (d_handle.get(resourceRecord)) {
    resourceRecord.dr.d_place = DNSResourceRecord::ANSWER;
    d_answers.push_back(resourceRecord);
    if ((d_qtype == QType::ANY || resourceRecord.dr.d_type == d_qtype)) {
      return true;
    }
  }

  // cout<<"end of ueberbackend get, seeing if we should cache"<<endl;
  if (d_answers.empty()) {
    // cout<<"adding negcache"<<endl;
    addNegCache(d_question);
  }
  else {
    // cout<<"adding query cache"<<endl;
    addCache(d_question, std::move(d_answers));
  }
  d_answers.clear();
  return false;
}

void UeberBackend::lookupEnd()
{
  if (!d_negcached && !d_cached) {
    DNSZoneRecord zoneRecord;
    while (d_handle.get(zoneRecord)) {
      // Read all answers so the backends will close any database handles they might have allocated.
      // One day this could be optimized.
    }
  }

  d_answers.clear();
  d_cached = d_negcached = false;
}

// TSIG
//
bool UeberBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content)
{
  return firstCapableBackend(&DNSBackend::setTSIGKey, name, algorithm, content);
}

bool UeberBackend::getTSIGKey(const DNSName& name, DNSName& algorithm, string& content)
{
  algorithm.clear();
  content.clear();

  if (!firstCapableBackend(&DNSBackend::getTSIGKey, name, algorithm, content)) {
    return false;
  }
  return (!algorithm.empty() && !content.empty());
}

bool UeberBackend::getTSIGKeys(std::vector<struct TSIGKey>& keys)
{
  keys.clear();
  return firstCapableBackend(&DNSBackend::getTSIGKeys, keys);
}

bool UeberBackend::deleteTSIGKey(const DNSName& name)
{
  return firstCapableBackend(&DNSBackend::deleteTSIGKey, name);
}

// API Search
//
bool UeberBackend::searchRecords(const string& pattern, size_t maxResults, vector<DNSResourceRecord>& result)
{
  bool ret = false;
  for (auto backend = backends.begin(); result.size() < maxResults && backend != backends.end(); ++backend) {
    if ((*backend)->searchRecords(pattern, maxResults - result.size(), result)) {
      ret = true;
    }
  }
  return ret;
}

bool UeberBackend::searchComments(const string& pattern, size_t maxResults, vector<Comment>& result)
{
  bool ret = false;
  for (auto backend = backends.begin(); result.size() < maxResults && backend != backends.end(); ++backend) {
    if ((*backend)->searchComments(pattern, maxResults - result.size(), result)) {
      ret = true;
    }
  }
  return ret;
}

bool UeberBackend::hasCreatedLocalFiles()
{
  return std::any_of(backends.begin(), backends.end(), [](std::unique_ptr<DNSBackend>& backend) { return backend->hasCreatedLocalFiles(); });
}

AtomicCounter UeberBackend::handle::instances(0);

UeberBackend::handle::handle()
{
  //  g_log<<Logger::Warning<<"Handle instances: "<<instances<<endl;
  ++instances;
}

UeberBackend::handle::~handle()
{
  --instances;
}

bool UeberBackend::handle::get(DNSZoneRecord& record)
{
  DLOG(g_log << "Ueber get() was called for a " << qtype << " record" << endl);
  bool isMore = false;
  while (d_hinterBackend != nullptr && !(isMore = d_hinterBackend->get(record))) { // this backend out of answers
    if (i < parent->backends.size()) {
      DLOG(g_log << "Backend #" << i << " of " << parent->backends.size()
                 << " out of answers, taking next" << endl);

      d_hinterBackend = parent->backends[i++].get();
      d_hinterBackend->lookup(qtype, qname, zoneId, pkt_p);
      ++(*s_backendQueries);
    }
    else {
      break;
    }

    DLOG(g_log << "Now asking backend #" << i << endl);
  }

  if (!isMore && i == parent->backends.size()) {
    DLOG(g_log << "UeberBackend reached end of backends" << endl);
    return false;
  }

  DLOG(g_log << "Found an answering backend - will not try another one" << endl);
  i = parent->backends.size(); // don't go on to the next backend
  return true;
}
