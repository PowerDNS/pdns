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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include "dnsbackend.hh"
#include "arguments.hh"
#include "ueberbackend.hh"
#include "logger.hh"

#include <sys/types.h>
#include "packetcache.hh"
#include "auth-zonecache.hh"
#include "dnspacket.hh"
#include "dns.hh"
#include "statbag.hh"

extern StatBag S;

// this has to be somewhere central, and not in a file that requires Lua
// this is so the geoipbackend can set this pointer if loaded for lua-record.cc
std::function<std::string(const std::string&, int)> g_getGeo;

bool DNSBackend::getAuth(const ZoneName& target, SOAData* soaData)
{
  return this->getSOA(target, UnknownDomainID, *soaData);
}

void DNSBackend::setArgPrefix(const string& prefix)
{
  d_prefix = prefix;
}

bool DNSBackend::mustDo(const string& key)
{
  return arg().mustDo(d_prefix + "-" + key);
}

const string& DNSBackend::getArg(const string& key)
{
  return arg()[d_prefix + "-" + key];
}

int DNSBackend::getArgAsNum(const string& key)
{
  return arg().asNum(d_prefix + "-" + key);
}

// Default API lookup has no support for disabled records and simply wraps lookup()
void DNSBackend::APILookup(const QType& qtype, const DNSName& qdomain, domainid_t zoneId, bool /* include_disabled */)
{
  lookup(qtype, qdomain, zoneId, nullptr);
}

void BackendFactory::declare(const string& suffix, const string& param, const string& explanation, const string& value)
{
  string fullname = d_name + suffix + "-" + param;
  arg().set(fullname, explanation) = value;
  arg().setDefault(fullname, value);
}

const string& BackendFactory::getName() const
{
  return d_name;
}

BackendMakerClass& BackendMakers()
{
  static BackendMakerClass bmc;
  return bmc;
}

void BackendMakerClass::report(std::unique_ptr<BackendFactory>&& backendFactory)
{
  d_repository[backendFactory->getName()] = std::move(backendFactory);
}

void BackendMakerClass::clear()
{
  d_instances.clear();
  d_repository.clear();
}

vector<string> BackendMakerClass::getModules()
{
  load_all();
  vector<string> ret;
  //  copy(d_repository.begin(), d_repository.end(),back_inserter(ret));
  for (auto& repo : d_repository) {
    ret.push_back(repo.first);
  }
  return ret;
}

void BackendMakerClass::load_all()
{
  auto directoryError = pdns::visit_directory(arg()["module-dir"], []([[maybe_unused]] ino_t inodeNumber, const std::string_view& name) {
    if (boost::starts_with(name, "lib") && name.size() > 13 && boost::ends_with(name, "backend.so")) {
      load(std::string(name));
    }
    return true;
  });
  if (directoryError) {
    g_log << Logger::Error << "Unable to open module directory '" << arg()["module-dir"] << "': " << *directoryError << endl;
  }
}

void BackendMakerClass::load(const string& module)
{
  bool res = false;

  g_log << Logger::Debug << "BackendMakerClass: module = " << module << endl;
  g_log << Logger::Debug << "BackendMakerClass: module-dir = " << arg()["module-dir"] << endl;
  if (module.find('.') == string::npos) {
    auto modulePath = arg()["module-dir"] + "/lib" + module + "backend.so";
    g_log << Logger::Debug << "BackendMakerClass: Loading '" << modulePath << "'" << endl;
    res = UeberBackend::loadmodule(modulePath);
  }
  else if (module[0] == '/' || (module[0] == '.' && module[1] == '/') || (module[0] == '.' && module[1] == '.')) {
    // Absolute path, Current path or Parent path
    g_log << Logger::Debug << "BackendMakerClass: Loading '" << module << "'" << endl;
    res = UeberBackend::loadmodule(module);
  }
  else {
    auto modulePath = arg()["module-dir"] + "/" + module;
    g_log << Logger::Debug << "BackendMakerClass: Loading '" << modulePath << "'" << endl;
    res = UeberBackend::loadmodule(modulePath);
  }

  if (!res) {
    g_log << Logger::Error << "DNSBackend unable to load module in " << module << endl;
    exit(1);
  }
}

void BackendMakerClass::launch(const string& instr)
{
  //    if(instr.empty())
  // throw ArgException("Not launching any backends - nameserver won't function");

  vector<string> parts;
  stringtok(parts, instr, ", ");

  for (const auto& part : parts) {
    if (count(parts.begin(), parts.end(), part) > 1) {
      throw ArgException("Refusing to launch multiple backends with the same name '" + part + "', verify all 'launch' statements in your configuration");
    }
  }

  for (const auto& part : parts) {
    string module;
    string name;
    vector<string> pparts;
    stringtok(pparts, part, ": ");
    module = pparts[0];
    if (pparts.size() > 1) {
      name = "-" + pparts[1];
    }

    if (d_repository.find(module) == d_repository.end()) {
      // this is *so* userfriendly
      load(module);
      if (d_repository.find(module) == d_repository.end()) {
        throw ArgException("Trying to launch unknown backend '" + module + "'");
      }
    }
    d_repository[module]->declareArguments(name);
    d_instances.emplace_back(module, name);
  }
}

size_t BackendMakerClass::numLauncheable() const
{
  return d_instances.size();
}

vector<std::unique_ptr<DNSBackend>> BackendMakerClass::all(bool metadataOnly)
{
  if (d_instances.empty()) {
    throw PDNSException("No database backends configured for launch, unable to function");
  }

  vector<unique_ptr<DNSBackend>> ret;
  ret.reserve(d_instances.size());

  std::string current; // to make the exception text more useful

  try {
    for (const auto& instance : d_instances) {
      current = instance.first + instance.second;
      const auto& repo = d_repository[instance.first];
      std::unique_ptr<DNSBackend> made{metadataOnly ? repo->makeMetadataOnly(instance.second) : repo->make(instance.second)};
      if (made == nullptr) {
        throw PDNSException("Unable to launch backend '" + instance.first + "'");
      }
      ret.push_back(std::move(made));
    }
  }
  catch (const PDNSException& ae) {
    g_log << Logger::Error << "Caught an exception instantiating a backend (" << current << "): " << ae.reason << endl;
    g_log << Logger::Error << "Cleaning up" << endl;
    ret.clear();
    throw;
  }
  catch (...) {
    // and cleanup
    g_log << Logger::Error << "Caught an exception instantiating a backend (" << current << "), cleaning up" << endl;
    ret.clear();
    throw;
  }

  return ret;
}

/** getSOA() is a function that is called to get the SOA of a domain. Callers should ONLY
    use getSOA() and not perform a lookup() themselves as backends may decide to special case
    the SOA record.

    Returns false if there is definitely no SOA for the domain. May throw a DBException
    to indicate that the backend is currently unable to supply an answer.

    WARNING: This function *may* fill out the db attribute of the SOAData, but then again,
    it may not! If you find a zero in there, you may have been handed a non-live and cached
    answer, in which case you need to perform a getDomainInfo call!

    \param domain Domain we want to get the SOA details of
    \param zoneId Domain id, if known
    \param soaData SOAData which is filled with the SOA details
    \param unmodifiedSerial bool if set, serial will be returned as stored in the backend (maybe 0)
*/
bool DNSBackend::getSOA(const ZoneName& domain, domainid_t zoneId, SOAData& soaData)
{
  soaData.db = nullptr;

  if (domain.hasVariant() && zoneId == UnknownDomainID) {
    DomainInfo domaininfo;
    if (!this->getDomainInfo(domain, domaininfo, false)) {
      return false;
    }
    zoneId = domaininfo.id;
  }
  // Safe for zoneId to be -1 here - it won't be the case for variants, see above
  this->lookup(QType(QType::SOA), domain.operator const DNSName&(), zoneId);
  S.inc("backend-queries");

  DNSResourceRecord resourceRecord;
  int hits = 0;

  try {
    while (this->get(resourceRecord)) {
      if (resourceRecord.qtype != QType::SOA) {
        throw PDNSException("Got non-SOA record when asking for SOA, zone: '" + domain.toLogString() + "'");
      }
      hits++;
      soaData.qname = domain.operator const DNSName&();
      soaData.ttl = resourceRecord.ttl;
      soaData.db = this;
      soaData.domain_id = resourceRecord.domain_id;
      fillSOAData(resourceRecord.content, soaData);
    }
  }
  catch (...) {
    while (this->get(resourceRecord)) {
      ;
    }
    throw;
  }

  return hits != 0;
}

bool DNSBackend::get(DNSZoneRecord& zoneRecord)
{
  //  cout<<"DNSBackend::get(DNSZoneRecord&) called - translating into DNSResourceRecord query"<<endl;
  DNSResourceRecord resourceRecord;
  if (!this->get(resourceRecord)) {
    return false;
  }
  zoneRecord.auth = resourceRecord.auth;
  zoneRecord.domain_id = resourceRecord.domain_id;
  zoneRecord.scopeMask = resourceRecord.scopeMask;
  if (resourceRecord.qtype.getCode() == QType::TXT && !resourceRecord.content.empty() && resourceRecord.content[0] != '"') {
    resourceRecord.content = "\"" + resourceRecord.content + "\"";
  }
  try {
    zoneRecord.dr = DNSRecord(resourceRecord);
  }
  catch (...) {
    while (this->get(resourceRecord)) {
      ;
    }
    throw;
  }
  return true;
}

bool DNSBackend::getBeforeAndAfterNames(domainid_t domainId, const ZoneName& zonename, const DNSName& qname, DNSName& before, DNSName& after)
{
  DNSName unhashed;
  bool ret = this->getBeforeAndAfterNamesAbsolute(domainId, qname.makeRelative(zonename).makeLowerCase(), unhashed, before, after);
  DNSName lczonename = zonename.makeLowerCase().operator const DNSName&();
  before += lczonename;
  after += lczonename;
  return ret;
}

void DNSBackend::getAllDomains(vector<DomainInfo>* /* domains */, bool /* getSerial */, bool /* include_disabled */)
{
  if (g_zoneCache.isEnabled()) {
    g_log << Logger::Error << "One of the backends does not support zone caching. Put zone-cache-refresh-interval=0 in the config file to disable this cache." << endl;
    exit(1);
  }
}

void fillSOAData(const DNSZoneRecord& inZoneRecord, SOAData& soaData)
{
  soaData.domain_id = inZoneRecord.domain_id;
  soaData.ttl = inZoneRecord.dr.d_ttl;

  auto src = getRR<SOARecordContent>(inZoneRecord.dr);
  soaData.nameserver = src->d_mname;
  soaData.rname = src->d_rname;
  soaData.serial = src->d_st.serial;
  soaData.refresh = src->d_st.refresh;
  soaData.retry = src->d_st.retry;
  soaData.expire = src->d_st.expire;
  soaData.minimum = src->d_st.minimum;
}

std::shared_ptr<DNSRecordContent> makeSOAContent(const SOAData& soaData)
{
  struct soatimes soaTimes{
    .serial = soaData.serial,
    .refresh = soaData.refresh,
    .retry = soaData.retry,
    .expire = soaData.expire,
    .minimum = soaData.minimum,
  };
  return std::make_shared<SOARecordContent>(soaData.nameserver, soaData.rname, soaTimes);
}

void fillSOAData(const string& content, SOAData& soaData)
{
  vector<string> parts;
  parts.reserve(7);
  stringtok(parts, content);

  try {
    soaData.nameserver = DNSName(parts.at(0));
    soaData.rname = DNSName(parts.at(1));
    pdns::checked_stoi_into(soaData.serial, parts.at(2));
    pdns::checked_stoi_into(soaData.refresh, parts.at(3));
    pdns::checked_stoi_into(soaData.retry, parts.at(4));
    pdns::checked_stoi_into(soaData.expire, parts.at(5));
    pdns::checked_stoi_into(soaData.minimum, parts.at(6));
  }
  catch (const std::out_of_range& oor) {
    throw PDNSException("Out of range exception parsing '" + content + "'");
  }
}
