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
#include <cerrno>
#include <string>
#include <set>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <fcntl.h>
#include <sstream>
#include <boost/algorithm/string.hpp>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

#include "pdns/dnsseckeeper.hh"
#include "pdns/dnssecinfra.hh"
#include "pdns/base32.hh"
#include "pdns/namespaces.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "bindbackend2.hh"
#include "pdns/dnspacket.hh"
#include "pdns/zoneparser-tng.hh"
#include "pdns/bindparserclasses.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/qtype.hh"
#include "pdns/misc.hh"
#include "pdns/dynlistener.hh"
#include "pdns/lock.hh"
#include "pdns/auth-zonecache.hh"
#include "pdns/auth-caches.hh"

/*
   All instances of this backend share one s_state, which is indexed by zone name and zone id.
   The s_state is protected by a read/write lock, and the goal it to only interact with it briefly.
   When a query comes in, we take a read lock and COPY the best zone to answer from s_state (BB2DomainInfo object)
   All answers are served from this copy.

   To interact with s_state, use safeGetBBDomainInfo (search on name or id), safePutBBDomainInfo (to update)
   or safeRemoveBBDomainInfo. These all lock as they should.

   Several functions need to traverse s_state to get data for the rest of PowerDNS. When doing so,
   you need to manually take the lock (read).

   Parsing zones happens with parseZone(), which fills a BB2DomainInfo object. This can then be stored with safePutBBDomainInfo.

   Finally, the BB2DomainInfo contains all records as a LookButDontTouch object. This makes sure you only look, but don't touch, since
   the records might be in use in other places.
*/

SharedLockGuarded<Bind2Backend::state_t> Bind2Backend::s_state;
int Bind2Backend::s_first = 1;
bool Bind2Backend::s_ignore_broken_records = false;

std::mutex Bind2Backend::s_autosecondary_config_lock; // protects writes to config file
std::mutex Bind2Backend::s_startup_lock;
string Bind2Backend::s_binddirectory;

BB2DomainInfo::BB2DomainInfo()
{
  d_loaded = false;
  d_lastcheck = 0;
  d_checknow = false;
  d_status = "Unknown";
}

void BB2DomainInfo::setCheckInterval(time_t seconds)
{
  d_checkinterval = seconds;
}

bool BB2DomainInfo::current()
{
  if (d_checknow) {
    return false;
  }

  if (!d_checkinterval)
    return true;

  if (time(nullptr) - d_lastcheck < d_checkinterval)
    return true;

  if (d_filename.empty())
    return true;

  return (getCtime() == d_ctime);
}

time_t BB2DomainInfo::getCtime()
{
  struct stat buf;

  if (d_filename.empty() || stat(d_filename.c_str(), &buf) < 0)
    return 0;
  d_lastcheck = time(nullptr);
  return buf.st_ctime;
}

void BB2DomainInfo::setCtime()
{
  struct stat buf;
  if (stat(d_filename.c_str(), &buf) < 0)
    return;
  d_ctime = buf.st_ctime;
}

// NOLINTNEXTLINE(readability-identifier-length)
bool Bind2Backend::safeGetBBDomainInfo(domainid_t id, BB2DomainInfo* bbd)
{
  auto state = s_state.read_lock();
  state_t::const_iterator iter = state->find(id);
  if (iter == state->end()) {
    return false;
  }
  *bbd = *iter;
  return true;
}

bool Bind2Backend::safeGetBBDomainInfo(const ZoneName& name, BB2DomainInfo* bbd)
{
  auto state = s_state.read_lock();
  const auto& nameindex = boost::multi_index::get<NameTag>(*state);
  auto iter = nameindex.find(name);
  if (iter == nameindex.end()) {
    return false;
  }
  *bbd = *iter;
  return true;
}

bool Bind2Backend::safeRemoveBBDomainInfo(const ZoneName& name)
{
  auto state = s_state.write_lock();
  using nameindex_t = state_t::index<NameTag>::type;
  nameindex_t& nameindex = boost::multi_index::get<NameTag>(*state);

  nameindex_t::iterator iter = nameindex.find(name);
  if (iter == nameindex.end()) {
    return false;
  }
  nameindex.erase(iter);
  return true;
}

void Bind2Backend::safePutBBDomainInfo(const BB2DomainInfo& bbd)
{
  auto state = s_state.write_lock();
  replacing_insert(*state, bbd);
}

// NOLINTNEXTLINE(readability-identifier-length)
void Bind2Backend::setNotified(domainid_t id, uint32_t serial)
{
  BB2DomainInfo bbd;
  if (!safeGetBBDomainInfo(id, &bbd))
    return;
  bbd.d_lastnotified = serial;
  safePutBBDomainInfo(bbd);
}

// NOLINTNEXTLINE(readability-identifier-length)
void Bind2Backend::setLastCheck(domainid_t domain_id, time_t lastcheck)
{
  BB2DomainInfo bbd;
  if (safeGetBBDomainInfo(domain_id, &bbd)) {
    bbd.d_lastcheck = lastcheck;
    safePutBBDomainInfo(bbd);
  }
}

void Bind2Backend::setStale(domainid_t domain_id)
{
  Bind2Backend::setLastCheck(domain_id, 0);
}

void Bind2Backend::setFresh(domainid_t domain_id)
{
  Bind2Backend::setLastCheck(domain_id, time(nullptr));
}

bool Bind2Backend::startTransaction(const ZoneName& qname, domainid_t domainId)
{
  if (domainId == UnknownDomainID) {
    d_transaction_tmpname.clear();
    d_transaction_id = UnknownDomainID;
    // No support for domain contents deletion
    return false;
  }
  if (domainId == 0) {
    throw DBException("domain_id 0 is invalid for this backend.");
  }

  d_transaction_id = domainId;
  d_transaction_qname = qname;
  BB2DomainInfo bbd;
  if (safeGetBBDomainInfo(domainId, &bbd)) {
    d_transaction_tmpname = bbd.d_filename + "XXXXXX";
    int fd = mkstemp(&d_transaction_tmpname.at(0));
    if (fd == -1) {
      throw DBException("Unable to create a unique temporary zonefile '" + d_transaction_tmpname + "': " + stringerror());
    }

    d_of = std::make_unique<ofstream>(d_transaction_tmpname);
    if (!*d_of) {
      unlink(d_transaction_tmpname.c_str());
      close(fd);
      fd = -1;
      d_of.reset();
      throw DBException("Unable to open temporary zonefile '" + d_transaction_tmpname + "': " + stringerror());
    }
    close(fd);
    fd = -1;

    *d_of << "; Written by PowerDNS, don't edit!" << endl;
    *d_of << "; Zone '" << bbd.d_name << "' retrieved from primary " << endl
          << "; at " << nowTime() << endl; // insert primary info here again

    return true;
  }
  return false;
}

bool Bind2Backend::commitTransaction()
{
  // d_transaction_id is only set to a valid domain id if we are actually
  // setting up a replacement zone file with the updated data.
  if (d_transaction_id == UnknownDomainID) {
    return false;
  }
  d_of.reset();

  BB2DomainInfo bbd;
  if (safeGetBBDomainInfo(d_transaction_id, &bbd)) {
    if (rename(d_transaction_tmpname.c_str(), bbd.d_filename.c_str()) < 0)
      throw DBException("Unable to commit (rename to: '" + bbd.d_filename + "') AXFRed zone: " + stringerror());
    queueReloadAndStore(bbd.d_id);
  }

  d_transaction_id = UnknownDomainID;

  return true;
}

bool Bind2Backend::abortTransaction()
{
  // d_transaction_id is only set to a valid domain id if we are actually
  // setting up a replacement zone file with the updated data.
  if (d_transaction_id != UnknownDomainID) {
    unlink(d_transaction_tmpname.c_str());
    d_of.reset();
    d_transaction_id = UnknownDomainID;
  }

  return true;
}

static bool ciEqual(const string& lhs, const string& rhs)
{
  if (lhs.size() != rhs.size()) {
    return false;
  }

  string::size_type pos = 0;
  const string::size_type epos = lhs.size();
  for (; pos < epos; ++pos) {
    if (dns_tolower(lhs[pos]) != dns_tolower(rhs[pos])) {
      return false;
    }
  }
  return true;
}

/** does domain end on suffix? Is smart about "wwwds9a.nl" "ds9a.nl" not matching */
static bool endsOn(const string& domain, const string& suffix)
{
  if (suffix.empty() || ciEqual(domain, suffix)) {
    return true;
  }

  if (domain.size() <= suffix.size()) {
    return false;
  }

  string::size_type dpos = domain.size() - suffix.size() - 1;
  string::size_type spos = 0;

  if (domain[dpos++] != '.') {
    return false;
  }

  for (; dpos < domain.size(); ++dpos, ++spos) {
    if (dns_tolower(domain[dpos]) != dns_tolower(suffix[spos])) {
      return false;
    }
  }

  return true;
}

/** strips a domain suffix from a domain, returns true if it stripped */
static bool stripDomainSuffix(string* qname, const string& domain)
{
  if (!endsOn(*qname, domain)) {
    return false;
  }

  if (toLower(*qname) == toLower(domain)) {
    *qname = "@";
  }
  else {
    if ((*qname)[qname->size() - domain.size() - 1] != '.') {
      return false;
    }

    qname->resize(qname->size() - domain.size() - 1);
  }
  return true;
}

bool Bind2Backend::feedRecord(const DNSResourceRecord& rr, const DNSName& /* ordername */, bool /* ordernameIsNSEC3 */)
{
  if (d_transaction_id == UnknownDomainID) {
    throw DBException("Bind2Backend::feedRecord() called outside of transaction");
  }

  string qname;
  if (d_transaction_qname.empty()) {
    qname = rr.qname.toString();
  }
  else if (rr.qname.isPartOf(d_transaction_qname)) {
    if (rr.qname == d_transaction_qname.operator const DNSName&()) {
      qname = "@";
    }
    else {
      DNSName relName = rr.qname.makeRelative(d_transaction_qname);
      qname = relName.toStringNoDot();
    }
  }
  else {
    throw DBException("out-of-zone data '" + rr.qname.toLogString() + "' during AXFR of zone '" + d_transaction_qname.toLogString() + "'");
  }

  shared_ptr<DNSRecordContent> drc(DNSRecordContent::make(rr.qtype.getCode(), QClass::IN, rr.content));
  string content = drc->getZoneRepresentation();

  // SOA needs stripping too! XXX FIXME - also, this should not be here I think
  switch (rr.qtype.getCode()) {
  case QType::MX:
  case QType::SRV:
  case QType::CNAME:
  case QType::DNAME:
  case QType::NS:
    stripDomainSuffix(&content, d_transaction_qname.toString());
    // fallthrough
  default:
    if (d_of && *d_of) {
      *d_of << qname << "\t" << rr.ttl << "\t" << rr.qtype.toString() << "\t" << content << endl;
    }
  }
  return true;
}

void Bind2Backend::getUpdatedPrimaries(vector<DomainInfo>& changedDomains, std::unordered_set<DNSName>& /* catalogs */, CatalogHashMap& /* catalogHashes */)
{
  vector<DomainInfo> consider;
  {
    auto state = s_state.read_lock();

    for (const auto& i : *state) {
      if (i.d_kind != DomainInfo::Primary && this->alsoNotify.empty() && i.d_also_notify.empty())
        continue;

      DomainInfo di;
      di.id = i.d_id;
      di.zone = i.d_name;
      di.last_check = i.d_lastcheck;
      di.notified_serial = i.d_lastnotified;
      di.backend = this;
      di.kind = DomainInfo::Primary;
      consider.push_back(std::move(di));
    }
  }

  SOAData soadata;
  for (DomainInfo& di : consider) {
    soadata.serial = 0;
    try {
      this->getSOA(di.zone, di.id, soadata); // we might not *have* a SOA yet, but this might trigger a load of it
    }
    catch (...) {
      continue;
    }
    if (di.notified_serial != soadata.serial) {
      BB2DomainInfo bbd;
      if (safeGetBBDomainInfo(di.id, &bbd)) {
        bbd.d_lastnotified = soadata.serial;
        safePutBBDomainInfo(bbd);
      }
      if (di.notified_serial) { // don't do notification storm on startup
        di.serial = soadata.serial;
        changedDomains.push_back(std::move(di));
      }
    }
  }
}

void Bind2Backend::getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool /* include_disabled */)
{
  SOAData soadata;

  // prevent deadlock by using getSOA() later on
  {
    auto state = s_state.read_lock();
    domains->reserve(state->size());

    for (const auto& i : *state) {
      DomainInfo di;
      di.id = i.d_id;
      di.zone = i.d_name;
      di.last_check = i.d_lastcheck;
      di.kind = i.d_kind;
      di.primaries = i.d_primaries;
      di.backend = this;
      domains->push_back(std::move(di));
    };
  }

  if (getSerial) {
    for (DomainInfo& di : *domains) {
      // do not corrupt di if domain supplied by another backend.
      if (di.backend != this)
        continue;
      try {
        this->getSOA(di.zone, di.id, soadata);
      }
      catch (...) {
        continue;
      }
      di.serial = soadata.serial;
    }
  }
}

void Bind2Backend::getUnfreshSecondaryInfos(vector<DomainInfo>* unfreshDomains)
{
  vector<DomainInfo> domains;
  {
    auto state = s_state.read_lock();
    domains.reserve(state->size());
    for (const auto& i : *state) {
      if (i.d_kind != DomainInfo::Secondary)
        continue;
      DomainInfo sd;
      sd.id = i.d_id;
      sd.zone = i.d_name;
      sd.primaries = i.d_primaries;
      sd.last_check = i.d_lastcheck;
      sd.backend = this;
      sd.kind = DomainInfo::Secondary;
      domains.push_back(std::move(sd));
    }
  }
  unfreshDomains->reserve(domains.size());

  for (DomainInfo& sd : domains) {
    SOAData soadata;
    soadata.refresh = 0;
    soadata.serial = 0;
    try {
      getSOA(sd.zone, sd.id, soadata); // we might not *have* a SOA yet
    }
    catch (...) {
    }
    sd.serial = soadata.serial;
    // coverity[store_truncates_time_t]
    if (sd.last_check + soadata.refresh < (unsigned int)time(nullptr))
      unfreshDomains->push_back(std::move(sd));
  }
}

bool Bind2Backend::getDomainInfo(const ZoneName& domain, DomainInfo& info, bool getSerial)
{
  BB2DomainInfo bbd;
  if (!safeGetBBDomainInfo(domain, &bbd))
    return false;

  info.id = bbd.d_id;
  info.zone = domain;
  info.primaries = bbd.d_primaries;
  info.last_check = bbd.d_lastcheck;
  info.backend = this;
  info.kind = bbd.d_kind;
  info.serial = 0;
  if (getSerial) {
    try {
      SOAData sd;
      sd.serial = 0;

      getSOA(bbd.d_name, bbd.d_id, sd); // we might not *have* a SOA yet
      info.serial = sd.serial;
    }
    catch (...) {
    }
  }

  return true;
}

void Bind2Backend::alsoNotifies(const ZoneName& domain, set<string>* ips)
{
  // combine global list with local list
  for (const auto& i : this->alsoNotify) {
    (*ips).insert(i);
  }
  // check metadata too if available
  vector<string> meta;
  if (getDomainMetadata(domain, "ALSO-NOTIFY", meta)) {
    for (const auto& str : meta) {
      (*ips).insert(str);
    }
  }
  auto state = s_state.read_lock();
  for (const auto& i : *state) {
    if (i.d_name == domain) {
      for (const auto& it : i.d_also_notify) {
        (*ips).insert(it);
      }
      return;
    }
  }
}

// only parses, does NOT add to s_state!
void Bind2Backend::parseZoneFile(BB2DomainInfo* bbd)
{
  NSEC3PARAMRecordContent ns3pr;
  bool nsec3zone = false;
  if (d_hybrid) {
    DNSSECKeeper dk;
    nsec3zone = dk.getNSEC3PARAM(bbd->d_name, &ns3pr);
  }
  else
    nsec3zone = getNSEC3PARAMuncached(bbd->d_name, &ns3pr);

  auto records = std::make_shared<recordstorage_t>();
  ZoneParserTNG zpt(bbd->d_filename, bbd->d_name, s_binddirectory, d_upgradeContent);
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
  zpt.setMaxIncludes(::arg().asNum("max-include-depth"));
  DNSResourceRecord rr;
  string hashed;
  while (zpt.get(rr)) {
    if (rr.qtype.getCode() == QType::NSEC || rr.qtype.getCode() == QType::NSEC3 || rr.qtype.getCode() == QType::NSEC3PARAM)
      continue; // we synthesise NSECs on demand

    insertRecord(records, bbd->d_name, rr.qname, rr.qtype, rr.content, rr.ttl, "");
  }
  fixupOrderAndAuth(records, bbd->d_name, nsec3zone, ns3pr);
  doEmptyNonTerminals(records, bbd->d_name, nsec3zone, ns3pr);
  bbd->setCtime();
  bbd->d_loaded = true;
  bbd->d_checknow = false;
  bbd->d_status = "parsed into memory at " + nowTime();
  bbd->d_records = LookButDontTouch<recordstorage_t>(std::move(records));
  bbd->d_nsec3zone = nsec3zone;
  bbd->d_nsec3param = std::move(ns3pr);
}

/** THIS IS AN INTERNAL FUNCTION! It does moadnsparser prio impedance matching
    Much of the complication is due to the efforts to benefit from std::string reference counting copy on write semantics */
void Bind2Backend::insertRecord(std::shared_ptr<recordstorage_t>& records, const ZoneName& zoneName, const DNSName& qname, const QType& qtype, const string& content, int ttl, const std::string& hashed, const bool* auth)
{
  Bind2DNSRecord bdr;
  bdr.qname = qname;

  if (zoneName.empty())
    ;
  else if (bdr.qname.isPartOf(zoneName))
    bdr.qname.makeUsRelative(zoneName);
  else {
    string msg = "Trying to insert non-zone data, name='" + bdr.qname.toLogString() + "', qtype=" + qtype.toString() + ", zone='" + zoneName.toLogString() + "'";
    if (s_ignore_broken_records) {
      g_log << Logger::Warning << msg << " ignored" << endl;
      return;
    }
    throw PDNSException(std::move(msg));
  }

  //  bdr.qname.swap(bdr.qname);

  if (!records->empty() && bdr.qname == boost::prior(records->end())->qname)
    bdr.qname = boost::prior(records->end())->qname;

  bdr.qname = bdr.qname;
  bdr.qtype = qtype.getCode();
  bdr.content = content;
  bdr.nsec3hash = hashed;

  if (auth != nullptr) // Set auth on empty non-terminals
    bdr.auth = *auth;
  else
    bdr.auth = true;

  bdr.ttl = ttl;
  records->insert(std::move(bdr));
}

string Bind2Backend::DLReloadNowHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  ostringstream ret;

  for (auto i = parts.begin() + 1; i < parts.end(); ++i) {
    BB2DomainInfo bbd;
    ZoneName zone(*i);
    if (safeGetBBDomainInfo(zone, &bbd)) {
      Bind2Backend bb2;
      bb2.queueReloadAndStore(bbd.d_id);
      if (!safeGetBBDomainInfo(zone, &bbd)) // Read the *new* domain status
        ret << *i << ": [missing]\n";
      else
        ret << *i << ": " << (bbd.d_wasRejectedLastReload ? "[rejected]" : "") << "\t" << bbd.d_status << "\n";
      purgeAuthCaches(zone.toString() + "$");
      DNSSECKeeper::clearMetaCache(zone);
    }
    else
      ret << *i << " no such domain\n";
  }
  if (ret.str().empty())
    ret << "no domains reloaded";
  return ret.str();
}

string Bind2Backend::DLDomStatusHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  ostringstream ret;

  if (parts.size() > 1) {
    for (auto i = parts.begin() + 1; i < parts.end(); ++i) {
      BB2DomainInfo bbd;
      if (safeGetBBDomainInfo(ZoneName(*i), &bbd)) {
        ret << *i << ": " << (bbd.d_loaded ? "" : "[rejected]") << "\t" << bbd.d_status << "\n";
      }
      else {
        ret << *i << " no such domain\n";
      }
    }
  }
  else {
    auto state = s_state.read_lock();
    for (const auto& i : *state) {
      ret << i.d_name << ": " << (i.d_loaded ? "" : "[rejected]") << "\t" << i.d_status << "\n";
    }
  }

  if (ret.str().empty())
    ret << "no domains passed";

  return ret.str();
}

static void printDomainExtendedStatus(ostringstream& ret, const BB2DomainInfo& info)
{
  ret << info.d_name << ": " << std::endl;
  ret << "\t Status: " << info.d_status << std::endl;
  ret << "\t Internal ID: " << info.d_id << std::endl;
  ret << "\t On-disk file: " << info.d_filename << " (" << info.d_ctime << ")" << std::endl;
  ret << "\t Kind: ";
  switch (info.d_kind) {
  case DomainInfo::Primary:
    ret << "Primary";
    break;
  case DomainInfo::Secondary:
    ret << "Secondary";
    break;
  default:
    ret << "Native";
  }
  ret << std::endl;
  ret << "\t Primaries: " << std::endl;
  for (const auto& primary : info.d_primaries) {
    ret << "\t\t - " << primary.toStringWithPort() << std::endl;
  }
  ret << "\t Also Notify: " << std::endl;
  for (const auto& also : info.d_also_notify) {
    ret << "\t\t - " << also << std::endl;
  }
  ret << "\t Number of records: " << info.d_records.getEntriesCount() << std::endl;
  ret << "\t Loaded: " << info.d_loaded << std::endl;
  ret << "\t Check now: " << info.d_checknow << std::endl;
  ret << "\t Check interval: " << info.getCheckInterval() << std::endl;
  ret << "\t Last check: " << info.d_lastcheck << std::endl;
  ret << "\t Last notified: " << info.d_lastnotified << std::endl;
}

string Bind2Backend::DLDomExtendedStatusHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  ostringstream ret;

  if (parts.size() > 1) {
    for (auto i = parts.begin() + 1; i < parts.end(); ++i) {
      BB2DomainInfo bbd;
      if (safeGetBBDomainInfo(ZoneName(*i), &bbd)) {
        printDomainExtendedStatus(ret, bbd);
      }
      else {
        ret << *i << " no such domain" << std::endl;
      }
    }
  }
  else {
    auto rstate = s_state.read_lock();
    for (const auto& state : *rstate) {
      printDomainExtendedStatus(ret, state);
    }
  }

  if (ret.str().empty()) {
    ret << "no domains passed" << std::endl;
  }

  return ret.str();
}

string Bind2Backend::DLListRejectsHandler(const vector<string>& /* parts */, Utility::pid_t /* ppid */)
{
  ostringstream ret;
  auto rstate = s_state.read_lock();
  for (const auto& i : *rstate) {
    if (!i.d_loaded)
      ret << i.d_name << "\t" << i.d_status << endl;
  }
  return ret.str();
}

string Bind2Backend::DLAddDomainHandler(const vector<string>& parts, Utility::pid_t /* ppid */)
{
  if (parts.size() < 3)
    return "ERROR: Domain name and zone filename are required";

  ZoneName domainname(parts[1]);
  const string& filename = parts[2];
  BB2DomainInfo bbd;
  if (safeGetBBDomainInfo(domainname, &bbd))
    return "Already loaded";

  if (!boost::starts_with(filename, "/") && ::arg()["chroot"].empty())
    return "Unable to load zone " + domainname.toLogString() + " from " + filename + " as the filename is not absolute.";

  struct stat buf;
  if (stat(filename.c_str(), &buf) != 0)
    return "Unable to load zone " + domainname.toLogString() + " from " + filename + ": " + strerror(errno);

  Bind2Backend bb2; // createdomainentry needs access to our configuration
  bbd = bb2.createDomainEntry(domainname, filename);
  bbd.d_filename = filename;
  bbd.d_checknow = true;
  bbd.d_loaded = true;
  bbd.d_lastcheck = 0;
  bbd.d_status = "parsing into memory";
  bbd.setCtime();

  safePutBBDomainInfo(bbd);

  g_zoneCache.add(domainname, bbd.d_id); // make new zone visible

  g_log << Logger::Warning << "Zone " << domainname << " loaded" << endl;
  return "Loaded zone " + domainname.toLogString() + " from " + filename;
}

Bind2Backend::Bind2Backend(const string& suffix, bool loadZones)
{
  d_getAllDomainMetadataQuery_stmt = nullptr;
  d_getDomainMetadataQuery_stmt = nullptr;
  d_deleteDomainMetadataQuery_stmt = nullptr;
  d_insertDomainMetadataQuery_stmt = nullptr;
  d_getDomainKeysQuery_stmt = nullptr;
  d_deleteDomainKeyQuery_stmt = nullptr;
  d_insertDomainKeyQuery_stmt = nullptr;
  d_GetLastInsertedKeyIdQuery_stmt = nullptr;
  d_activateDomainKeyQuery_stmt = nullptr;
  d_deactivateDomainKeyQuery_stmt = nullptr;
  d_getTSIGKeyQuery_stmt = nullptr;
  d_setTSIGKeyQuery_stmt = nullptr;
  d_deleteTSIGKeyQuery_stmt = nullptr;
  d_getTSIGKeysQuery_stmt = nullptr;

  setArgPrefix("bind" + suffix);
  d_logprefix = "[bind" + suffix + "backend]";
  d_hybrid = mustDo("hybrid");
  if (d_hybrid && g_zoneCache.isEnabled()) {
    throw PDNSException("bind-hybrid and the zone cache currently interoperate badly. Please disable the zone cache or stop using bind-hybrid");
  }

  d_transaction_id = UnknownDomainID;
  s_ignore_broken_records = mustDo("ignore-broken-records");
  d_upgradeContent = ::arg().mustDo("upgrade-unknown-types");

  if (!loadZones && d_hybrid)
    return;

  std::lock_guard<std::mutex> l(s_startup_lock);

  setupDNSSEC();
  if (s_first == 0) {
    return;
  }

  if (loadZones) {
    loadConfig();
    s_first = 0;
  }

  DynListener::registerFunc("BIND-RELOAD-NOW", &DLReloadNowHandler, "bindbackend: reload domains", "<domains>");
  DynListener::registerFunc("BIND-DOMAIN-STATUS", &DLDomStatusHandler, "bindbackend: list status of all domains", "[domains]");
  DynListener::registerFunc("BIND-DOMAIN-EXTENDED-STATUS", &DLDomExtendedStatusHandler, "bindbackend: list the extended status of all domains", "[domains]");
  DynListener::registerFunc("BIND-LIST-REJECTS", &DLListRejectsHandler, "bindbackend: list rejected domains");
  DynListener::registerFunc("BIND-ADD-ZONE", &DLAddDomainHandler, "bindbackend: add zone", "<domain> <filename>");
}

Bind2Backend::~Bind2Backend()
{
  freeStatements();
} // deallocate statements

void Bind2Backend::rediscover(string* status)
{
  loadConfig(status);
}

void Bind2Backend::reload()
{
  auto state = s_state.write_lock();
  for (const auto& i : *state) {
    i.d_checknow = true; // being a bit cheeky here, don't index state_t on this (mutable)
  }
}

void Bind2Backend::fixupOrderAndAuth(std::shared_ptr<recordstorage_t>& records, const ZoneName& zoneName, bool nsec3zone, const NSEC3PARAMRecordContent& ns3pr)
{
  bool skip;
  DNSName shorter;
  set<DNSName> nssets, dssets;

  for (const auto& bdr : *records) {
    if (!bdr.qname.isRoot() && bdr.qtype == QType::NS)
      nssets.insert(bdr.qname);
    else if (bdr.qtype == QType::DS)
      dssets.insert(bdr.qname);
  }

  for (auto iter = records->begin(); iter != records->end(); iter++) {
    skip = false;
    shorter = iter->qname;

    if (!iter->qname.isRoot() && shorter.chopOff() && !iter->qname.isRoot()) {
      do {
        if (nssets.count(shorter) != 0u) {
          skip = true;
          break;
        }
      } while (shorter.chopOff() && !iter->qname.isRoot());
    }

    iter->auth = (!skip && (iter->qtype == QType::DS || iter->qtype == QType::RRSIG || (nssets.count(iter->qname) == 0u)));

    if (!skip && nsec3zone && iter->qtype != QType::RRSIG && (iter->auth || (iter->qtype == QType::NS && (ns3pr.d_flags == 0u)) || (dssets.count(iter->qname) != 0u))) {
      Bind2DNSRecord bdr = *iter;
      bdr.nsec3hash = toBase32Hex(hashQNameWithSalt(ns3pr, bdr.qname + zoneName.operator const DNSName&()));
      records->replace(iter, bdr);
    }

    // cerr<<iter->qname<<"\t"<<QType(iter->qtype).toString()<<"\t"<<iter->nsec3hash<<"\t"<<iter->auth<<endl;
  }
}

void Bind2Backend::doEmptyNonTerminals(std::shared_ptr<recordstorage_t>& records, const ZoneName& zoneName, bool nsec3zone, const NSEC3PARAMRecordContent& ns3pr)
{
  bool auth = false;
  DNSName shorter;
  std::unordered_set<DNSName> qnames;
  std::unordered_map<DNSName, bool> nonterm;

  uint32_t maxent = ::arg().asNum("max-ent-entries");

  for (const auto& bdr : *records)
    qnames.insert(bdr.qname);

  for (const auto& bdr : *records) {

    if (!bdr.auth && bdr.qtype == QType::NS)
      auth = (!nsec3zone || (ns3pr.d_flags == 0u));
    else
      auth = bdr.auth;

    shorter = bdr.qname;
    while (shorter.chopOff()) {
      if (qnames.count(shorter) == 0u) {
        if (!(maxent)) {
          g_log << Logger::Error << "Zone '" << zoneName << "' has too many empty non terminals." << endl;
          return;
        }

        if (nonterm.count(shorter) == 0u) {
          nonterm.emplace(shorter, auth);
          --maxent;
        }
        else if (auth)
          nonterm[shorter] = true;
      }
    }
  }

  DNSResourceRecord rr;
  rr.qtype = "#0";
  rr.content = "";
  rr.ttl = 0;
  for (auto& nt : nonterm) {
    string hashed;
    rr.qname = nt.first + zoneName.operator const DNSName&();
    if (nsec3zone && nt.second)
      hashed = toBase32Hex(hashQNameWithSalt(ns3pr, rr.qname));
    insertRecord(records, zoneName, rr.qname, rr.qtype, rr.content, rr.ttl, hashed, &nt.second);

    // cerr<<rr.qname<<"\t"<<rr.qtype.toString()<<"\t"<<hashed<<"\t"<<nt.second<<endl;
  }
}

void Bind2Backend::loadConfig(string* status) // NOLINT(readability-function-cognitive-complexity) 13379 https://github.com/PowerDNS/pdns/issues/13379 Habbie: zone2sql.cc, bindbackend2.cc: reduce complexity
{
  static domainid_t domain_id = 1;

  if (!getArg("config").empty()) {
    BindParser BP;
    try {
      BP.parse(getArg("config"));
    }
    catch (PDNSException& ae) {
      g_log << Logger::Error << "Error parsing bind configuration: " << ae.reason << endl;
      throw;
    }

    vector<BindDomainInfo> domains = BP.getDomains();
    this->alsoNotify = BP.getAlsoNotify();

    s_binddirectory = BP.getDirectory();
    //    ZP.setDirectory(d_binddirectory);

    g_log << Logger::Warning << d_logprefix << " Parsing " << domains.size() << " domain(s), will report when done" << endl;

    set<ZoneName> oldnames;
    set<ZoneName> newnames;
    {
      auto state = s_state.read_lock();
      for (const BB2DomainInfo& bbd : *state) {
        oldnames.insert(bbd.d_name);
      }
    }
    int rejected = 0;
    int newdomains = 0;

    struct stat st;

    for (auto& domain : domains) {
      if (stat(domain.filename.c_str(), &st) == 0) {
        domain.d_dev = st.st_dev;
        domain.d_ino = st.st_ino;
      }
    }

    sort(domains.begin(), domains.end()); // put stuff in inode order
    for (const auto& domain : domains) {
      if (!(domain.hadFileDirective)) {
        g_log << Logger::Warning << d_logprefix << " Zone '" << domain.name << "' has no 'file' directive set in " << getArg("config") << endl;
        rejected++;
        continue;
      }

      if (domain.type.empty()) {
        g_log << Logger::Notice << d_logprefix << " Zone '" << domain.name << "' has no type specified, assuming 'native'" << endl;
      }
      if (domain.type != "primary" && domain.type != "secondary" && domain.type != "native" && !domain.type.empty() && domain.type != "master" && domain.type != "slave") {
        g_log << Logger::Warning << d_logprefix << " Warning! Skipping zone '" << domain.name << "' because type '" << domain.type << "' is invalid" << endl;
        rejected++;
        continue;
      }

      BB2DomainInfo bbd;
      bool isNew = false;

      if (!safeGetBBDomainInfo(domain.name, &bbd)) {
        isNew = true;
        bbd.d_id = domain_id++;
        bbd.setCheckInterval(getArgAsNum("check-interval"));
        bbd.d_lastnotified = 0;
        bbd.d_loaded = false;
      }

      // overwrite what we knew about the domain
      bbd.d_name = domain.name;
      bool filenameChanged = (bbd.d_filename != domain.filename);
      bool addressesChanged = (bbd.d_primaries != domain.primaries || bbd.d_also_notify != domain.alsoNotify);
      bbd.d_filename = domain.filename;
      bbd.d_primaries = domain.primaries;
      bbd.d_also_notify = domain.alsoNotify;

      DomainInfo::DomainKind kind = DomainInfo::Native;
      if (domain.type == "primary" || domain.type == "master") {
        kind = DomainInfo::Primary;
      }
      if (domain.type == "secondary" || domain.type == "slave") {
        kind = DomainInfo::Secondary;
      }

      bool kindChanged = (bbd.d_kind != kind);
      bbd.d_kind = kind;

      newnames.insert(bbd.d_name);
      if (filenameChanged || !bbd.d_loaded || !bbd.current()) {
        g_log << Logger::Info << d_logprefix << " parsing '" << domain.name << "' from file '" << domain.filename << "'" << endl;

        try {
          parseZoneFile(&bbd);
        }
        catch (PDNSException& ae) {
          ostringstream msg;
          msg << " error at " + nowTime() + " parsing '" << domain.name << "' from file '" << domain.filename << "': " << ae.reason;

          if (status != nullptr)
            *status += msg.str();
          bbd.d_status = msg.str();

          g_log << Logger::Warning << d_logprefix << msg.str() << endl;
          rejected++;
        }
        catch (std::system_error& ae) {
          ostringstream msg;
          if (ae.code().value() == ENOENT && isNew && domain.type == "slave")
            msg << " error at " + nowTime() << " no file found for new secondary domain '" << domain.name << "'. Has not been AXFR'd yet";
          else
            msg << " error at " + nowTime() + " parsing '" << domain.name << "' from file '" << domain.filename << "': " << ae.what();

          if (status != nullptr)
            *status += msg.str();
          bbd.d_status = msg.str();
          g_log << Logger::Warning << d_logprefix << msg.str() << endl;
          rejected++;
        }
        catch (std::exception& ae) {
          ostringstream msg;
          msg << " error at " + nowTime() + " parsing '" << domain.name << "' from file '" << domain.filename << "': " << ae.what();

          if (status != nullptr)
            *status += msg.str();
          bbd.d_status = msg.str();

          g_log << Logger::Warning << d_logprefix << msg.str() << endl;
          rejected++;
        }
        safePutBBDomainInfo(bbd);
      }
      else if (addressesChanged || kindChanged) {
        safePutBBDomainInfo(bbd);
      }
    }
    vector<ZoneName> diff;

    set_difference(oldnames.begin(), oldnames.end(), newnames.begin(), newnames.end(), back_inserter(diff));
    unsigned int remdomains = diff.size();

    for (const ZoneName& name : diff) {
      safeRemoveBBDomainInfo(name);
    }

    // count number of entirely new domains
    diff.clear();
    set_difference(newnames.begin(), newnames.end(), oldnames.begin(), oldnames.end(), back_inserter(diff));
    newdomains = diff.size();

    ostringstream msg;
    msg << " Done parsing domains, " << rejected << " rejected, " << newdomains << " new, " << remdomains << " removed";
    if (status != nullptr)
      *status = msg.str();

    g_log << Logger::Error << d_logprefix << msg.str() << endl;
  }
}

// NOLINTNEXTLINE(readability-identifier-length)
void Bind2Backend::queueReloadAndStore(domainid_t id)
{
  BB2DomainInfo bbold;
  try {
    if (!safeGetBBDomainInfo(id, &bbold))
      return;
    bbold.d_checknow = false;
    BB2DomainInfo bbnew(bbold);
    /* make sure that nothing will be able to alter the existing records,
       we will load them from the zone file instead */
    bbnew.d_records = LookButDontTouch<recordstorage_t>();
    parseZoneFile(&bbnew);
    bbnew.d_wasRejectedLastReload = false;
    safePutBBDomainInfo(bbnew);
    g_log << Logger::Warning << "Zone '" << bbnew.d_name << "' (" << bbnew.d_filename << ") reloaded" << endl;
  }
  catch (PDNSException& ae) {
    ostringstream msg;
    msg << " error at " + nowTime() + " parsing '" << bbold.d_name << "' from file '" << bbold.d_filename << "': " << ae.reason;
    g_log << Logger::Warning << "Error parsing '" << bbold.d_name << "' from file '" << bbold.d_filename << "': " << ae.reason << endl;
    bbold.d_status = msg.str();
    bbold.d_lastcheck = time(nullptr);
    bbold.d_wasRejectedLastReload = true;
    safePutBBDomainInfo(bbold);
  }
  catch (std::exception& ae) {
    ostringstream msg;
    msg << " error at " + nowTime() + " parsing '" << bbold.d_name << "' from file '" << bbold.d_filename << "': " << ae.what();
    g_log << Logger::Warning << "Error parsing '" << bbold.d_name << "' from file '" << bbold.d_filename << "': " << ae.what() << endl;
    bbold.d_status = msg.str();
    bbold.d_lastcheck = time(nullptr);
    bbold.d_wasRejectedLastReload = true;
    safePutBBDomainInfo(bbold);
  }
}

bool Bind2Backend::findBeforeAndAfterUnhashed(std::shared_ptr<const recordstorage_t>& records, const DNSName& qname, DNSName& /* unhashed */, DNSName& before, DNSName& after)
{
  // for(const auto& record: *records)
  //   cerr<<record.qname<<"\t"<<makeHexDump(record.qname.toDNSString())<<endl;

  recordstorage_t::const_iterator iterBefore, iterAfter;

  iterBefore = iterAfter = records->upper_bound(qname.makeLowerCase());

  if (iterBefore != records->begin())
    --iterBefore;
  while ((!iterBefore->auth && iterBefore->qtype != QType::NS) || !iterBefore->qtype)
    --iterBefore;
  before = iterBefore->qname;

  if (iterAfter == records->end()) {
    iterAfter = records->begin();
  }
  else {
    while ((!iterAfter->auth && iterAfter->qtype != QType::NS) || !iterAfter->qtype) {
      ++iterAfter;
      if (iterAfter == records->end()) {
        iterAfter = records->begin();
        break;
      }
    }
  }
  after = iterAfter->qname;

  return true;
}

// NOLINTNEXTLINE(readability-identifier-length)
bool Bind2Backend::getBeforeAndAfterNamesAbsolute(domainid_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
  BB2DomainInfo bbd;
  if (!safeGetBBDomainInfo(id, &bbd))
    return false;

  shared_ptr<const recordstorage_t> records = bbd.d_records.get();
  if (!bbd.d_nsec3zone) {
    return findBeforeAndAfterUnhashed(records, qname, unhashed, before, after);
  }
  else {
    const auto& hashindex = boost::multi_index::get<NSEC3Tag>(*records);

    // for(auto iter = first; iter != hashindex.end(); iter++)
    //  cerr<<iter->nsec3hash<<endl;

    auto first = hashindex.upper_bound("");
    auto iter = hashindex.upper_bound(qname.toStringNoDot());

    if (iter == hashindex.end()) {
      --iter;
      before = DNSName(iter->nsec3hash);
      after = DNSName(first->nsec3hash);
    }
    else {
      after = DNSName(iter->nsec3hash);
      if (iter != first)
        --iter;
      else
        iter = --hashindex.end();
      before = DNSName(iter->nsec3hash);
    }
    unhashed = iter->qname + bbd.d_name.operator const DNSName&();

    return true;
  }
}

void Bind2Backend::lookup(const QType& qtype, const DNSName& qname, domainid_t zoneId, DNSPacket* /* pkt_p */)
{
  d_handle.reset();

  static bool mustlog = ::arg().mustDo("query-logging");

  bool found = false;
  ZoneName domain;
  BB2DomainInfo bbd;

  if (mustlog)
    g_log << Logger::Warning << "Lookup for '" << qtype.toString() << "' of '" << qname << "' within zoneID " << zoneId << endl;

  if (zoneId != UnknownDomainID) {
    if ((found = (safeGetBBDomainInfo(zoneId, &bbd) && qname.isPartOf(bbd.d_name)))) {
      domain = std::move(bbd.d_name);
    }
  }
  else {
    domain = ZoneName(qname);
    do {
      found = safeGetBBDomainInfo(domain, &bbd);
    } while (!found && qtype != QType::SOA && domain.chopOff());
  }

  if (!found) {
    if (mustlog)
      g_log << Logger::Warning << "Found no authoritative zone for '" << qname << "' and/or id " << zoneId << endl;
    d_handle.d_list = false;
    return;
  }

  if (mustlog)
    g_log << Logger::Warning << "Found a zone '" << domain << "' (with id " << bbd.d_id << ") that might contain data " << endl;

  d_handle.id = bbd.d_id;
  d_handle.qname = qname.makeRelative(domain); // strip domain name
  d_handle.qtype = qtype;
  d_handle.domain = std::move(domain);

  if (!bbd.current()) {
    g_log << Logger::Warning << "Zone '" << d_handle.domain << "' (" << bbd.d_filename << ") needs reloading" << endl;
    queueReloadAndStore(bbd.d_id);
    if (!safeGetBBDomainInfo(d_handle.domain, &bbd))
      throw DBException("Zone '" + bbd.d_name.toLogString() + "' (" + bbd.d_filename + ") gone after reload"); // if we don't throw here, we crash for some reason
  }

  if (!bbd.d_loaded) {
    d_handle.reset();
    throw DBException("Zone for '" + d_handle.domain.toLogString() + "' in '" + bbd.d_filename + "' not loaded (file missing, corrupt or primary dead)"); // fsck
  }

  d_handle.d_records = bbd.d_records.get();

  if (d_handle.d_records->empty())
    DLOG(g_log << "Query with no results" << endl);

  d_handle.mustlog = mustlog;

  const auto& hashedidx = boost::multi_index::get<UnorderedNameTag>(*d_handle.d_records);
  auto range = hashedidx.equal_range(d_handle.qname);

  d_handle.d_list = false;
  d_handle.d_iter = range.first;
  d_handle.d_end_iter = range.second;
}

Bind2Backend::handle::handle()
{
  mustlog = false;
}

bool Bind2Backend::get(DNSResourceRecord& r)
{
  if (!d_handle.d_records) {
    if (d_handle.mustlog)
      g_log << Logger::Warning << "There were no answers" << endl;
    return false;
  }

  if (!d_handle.get(r)) {
    if (d_handle.mustlog)
      g_log << Logger::Warning << "End of answers" << endl;

    d_handle.reset();

    return false;
  }
  if (d_handle.mustlog)
    g_log << Logger::Warning << "Returning: '" << r.qtype.toString() << "' of '" << r.qname << "', content: '" << r.content << "'" << endl;
  return true;
}

bool Bind2Backend::handle::get(DNSResourceRecord& r)
{
  if (d_list)
    return get_list(r);
  else
    return get_normal(r);
}

void Bind2Backend::handle::reset()
{
  d_records.reset();
  qname.clear();
  mustlog = false;
}

//#define DLOG(x) x
bool Bind2Backend::handle::get_normal(DNSResourceRecord& r)
{
  DLOG(g_log << "Bind2Backend get() was called for " << qtype.toString() << " record for '" << qname << "' - " << d_records->size() << " available in total!" << endl);

  if (d_iter == d_end_iter) {
    return false;
  }

  while (d_iter != d_end_iter && !(qtype.getCode() == QType::ANY || (d_iter)->qtype == qtype.getCode())) {
    DLOG(g_log << Logger::Warning << "Skipped " << qname << "/" << QType(d_iter->qtype).toString() << ": '" << d_iter->content << "'" << endl);
    d_iter++;
  }
  if (d_iter == d_end_iter) {
    return false;
  }
  DLOG(g_log << "Bind2Backend get() returning a rr with a " << QType(d_iter->qtype).getCode() << endl);

  const DNSName& domainName(domain);
  r.qname = qname.empty() ? domainName : (qname + domainName);
  r.domain_id = id;
  r.content = (d_iter)->content;
  //  r.domain_id=(d_iter)->domain_id;
  r.qtype = (d_iter)->qtype;
  r.ttl = (d_iter)->ttl;

  //if(!d_iter->auth && r.qtype.getCode() != QType::A && r.qtype.getCode()!=QType::AAAA && r.qtype.getCode() != QType::NS)
  //  cerr<<"Warning! Unauth response for qtype "<< r.qtype.toString() << " for '"<<r.qname<<"'"<<endl;
  r.auth = d_iter->auth;

  d_iter++;

  return true;
}

bool Bind2Backend::list(const ZoneName& /* target */, domainid_t domainId, bool /* include_disabled */)
{
  BB2DomainInfo bbd;

  if (!safeGetBBDomainInfo(domainId, &bbd)) {
    return false;
  }

  d_handle.reset();
  DLOG(g_log << "Bind2Backend constructing handle for list of " << domainId << endl);

  if (!bbd.d_loaded) {
    throw PDNSException("zone was not loaded, perhaps because of: " + bbd.d_status);
  }

  d_handle.d_records = bbd.d_records.get(); // give it a copy, which will stay around
  d_handle.d_qname_iter = d_handle.d_records->begin();
  d_handle.d_qname_end = d_handle.d_records->end(); // iter now points to a vector of pointers to vector<BBResourceRecords>

  d_handle.id = domainId;
  d_handle.domain = bbd.d_name;
  d_handle.d_list = true;
  return true;
}

bool Bind2Backend::handle::get_list(DNSResourceRecord& r)
{
  if (d_qname_iter != d_qname_end) {
    const DNSName& domainName(domain);
    r.qname = d_qname_iter->qname.empty() ? domainName : (d_qname_iter->qname + domainName);
    r.domain_id = id;
    r.content = (d_qname_iter)->content;
    r.qtype = (d_qname_iter)->qtype;
    r.ttl = (d_qname_iter)->ttl;
    r.auth = d_qname_iter->auth;
    d_qname_iter++;
    return true;
  }
  return false;
}

bool Bind2Backend::autoPrimariesList(std::vector<AutoPrimary>& primaries)
{
  if (getArg("autoprimary-config").empty())
    return false;

  ifstream c_if(getArg("autoprimaries"), std::ios::in);
  if (!c_if) {
    g_log << Logger::Error << "Unable to open autoprimaries file for read: " << stringerror() << endl;
    return false;
  }

  string line, sip, saccount;
  while (getline(c_if, line)) {
    std::istringstream ii(line);
    ii >> sip;
    if (!sip.empty()) {
      ii >> saccount;
      primaries.emplace_back(sip, "", saccount);
    }
  }

  c_if.close();
  return true;
}

bool Bind2Backend::autoPrimaryBackend(const string& ipAddress, const ZoneName& /* domain */, const vector<DNSResourceRecord>& /* nsset */, string* /* nameserver */, string* account, DNSBackend** backend)
{
  // Check whether we have a configfile available.
  if (getArg("autoprimary-config").empty())
    return false;

  ifstream c_if(getArg("autoprimaries").c_str(), std::ios::in); // this was nocreate?
  if (!c_if) {
    g_log << Logger::Error << "Unable to open autoprimaries file for read: " << stringerror() << endl;
    return false;
  }

  // Format:
  // <ip> <accountname>
  string line, sip, saccount;
  while (getline(c_if, line)) {
    std::istringstream ii(line);
    ii >> sip;
    if (sip == ipAddress) {
      ii >> saccount;
      break;
    }
  }
  c_if.close();

  if (sip != ipAddress) { // ip not found in authorization list - reject
    return false;
  }

  // ip authorized as autoprimary - accept
  *backend = this;
  if (saccount.length() > 0)
    *account = saccount.c_str();

  return true;
}

BB2DomainInfo Bind2Backend::createDomainEntry(const ZoneName& domain, const string& filename)
{
  domainid_t newid = 1;
  { // Find a free zone id nr.
    auto state = s_state.read_lock();
    if (!state->empty()) {
      // older (1.53) versions of boost have an expression for s_state.rbegin()
      // that is ambiguous in C++17. So construct it explicitly
      newid = boost::make_reverse_iterator(state->end())->d_id + 1;
    }
  }

  BB2DomainInfo bbd;
  bbd.d_kind = DomainInfo::Native;
  bbd.d_id = newid;
  bbd.d_records = std::make_shared<recordstorage_t>();
  bbd.d_name = domain;
  bbd.setCheckInterval(getArgAsNum("check-interval"));
  bbd.d_filename = filename;

  return bbd;
}

bool Bind2Backend::createSecondaryDomain(const string& ipAddress, const ZoneName& domain, const string& /* nameserver */, const string& account)
{
  string filename = getArg("autoprimary-destdir") + '/' + domain.toStringNoDot();

  g_log << Logger::Warning << d_logprefix
        << " Writing bind config zone statement for superslave zone '" << domain
        << "' from autoprimary " << ipAddress << endl;

  {
    std::lock_guard<std::mutex> l2(s_autosecondary_config_lock);

    ofstream c_of(getArg("autoprimary-config").c_str(), std::ios::app);
    if (!c_of) {
      g_log << Logger::Error << "Unable to open autoprimary configfile for append: " << stringerror() << endl;
      throw DBException("Unable to open autoprimary configfile for append: " + stringerror());
    }

    c_of << endl;
    c_of << "# AutoSecondary zone '" << domain.toString() << "' (added: " << nowTime() << ") (account: " << account << ')' << endl;
    c_of << "zone \"" << domain.toStringNoDot() << "\" {" << endl;
    c_of << "\ttype secondary;" << endl;
    c_of << "\tfile \"" << filename << "\";" << endl;
    c_of << "\tprimaries { " << ipAddress << "; };" << endl;
    c_of << "};" << endl;
    c_of.close();
  }

  BB2DomainInfo bbd = createDomainEntry(domain, filename);
  bbd.d_kind = DomainInfo::Secondary;
  bbd.d_primaries.emplace_back(ComboAddress(ipAddress, 53));
  bbd.setCtime();
  safePutBBDomainInfo(bbd);

  return true;
}

bool Bind2Backend::searchRecords(const string& pattern, size_t maxResults, vector<DNSResourceRecord>& result)
{
  SimpleMatch sm(pattern, true);
  static bool mustlog = ::arg().mustDo("query-logging");
  if (mustlog)
    g_log << Logger::Warning << "Search for pattern '" << pattern << "'" << endl;

  {
    auto state = s_state.read_lock();

    for (const auto& i : *state) {
      BB2DomainInfo h;
      if (!safeGetBBDomainInfo(i.d_id, &h)) {
        continue;
      }

      if (!h.d_loaded) {
        continue;
      }

      shared_ptr<const recordstorage_t> rhandle = h.d_records.get();

      for (recordstorage_t::const_iterator ri = rhandle->begin(); result.size() < maxResults && ri != rhandle->end(); ri++) {
        const DNSName& domainName(i.d_name);
        DNSName name = ri->qname.empty() ? domainName : (ri->qname + domainName);
        if (sm.match(name) || sm.match(ri->content)) {
          DNSResourceRecord r;
          r.qname = std::move(name);
          r.domain_id = i.d_id;
          r.content = ri->content;
          r.qtype = ri->qtype;
          r.ttl = ri->ttl;
          r.auth = ri->auth;
          result.push_back(std::move(r));
        }
      }
    }
  }

  return true;
}

class Bind2Factory : public BackendFactory
{
public:
  Bind2Factory() :
    BackendFactory("bind") {}

  void declareArguments(const string& suffix = "") override
  {
    declare(suffix, "ignore-broken-records", "Ignore records that are out-of-bound for the zone.", "no");
    declare(suffix, "config", "Location of named.conf", "");
    declare(suffix, "check-interval", "Interval for zonefile changes", "0");
    declare(suffix, "autoprimary-config", "Location of (part of) named.conf where pdns can write zone-statements to", "");
    declare(suffix, "autoprimaries", "List of IP-addresses of autoprimaries", "");
    declare(suffix, "autoprimary-destdir", "Destination directory for newly added secondary zones", ::arg()["config-dir"]);
    declare(suffix, "dnssec-db", "Filename to store & access our DNSSEC metadatabase, empty for none", "");
    declare(suffix, "dnssec-db-journal-mode", "SQLite3 journal mode", "WAL");
    declare(suffix, "hybrid", "Store DNSSEC metadata in other backend", "no");
  }

  DNSBackend* make(const string& suffix = "") override
  {
    assertEmptySuffix(suffix);
    return new Bind2Backend(suffix);
  }

  DNSBackend* makeMetadataOnly(const string& suffix = "") override
  {
    assertEmptySuffix(suffix);
    return new Bind2Backend(suffix, false);
  }

private:
  void assertEmptySuffix(const string& suffix)
  {
    if (!suffix.empty())
      throw PDNSException("launch= suffixes are not supported on the bindbackend");
  }
};

//! Magic class that is activated when the dynamic library is loaded
class Bind2Loader
{
public:
  Bind2Loader()
  {
    BackendMakers().report(std::make_unique<Bind2Factory>());
    g_log << Logger::Info << "[bind2backend] This is the bind backend version " << VERSION
#ifndef REPRODUCIBLE
          << " (" __DATE__ " " __TIME__ ")"
#endif
#ifdef HAVE_SQLITE3
          << " (with bind-dnssec-db support)"
#endif
          << " reporting" << endl;
  }
};
static Bind2Loader bind2loader;
