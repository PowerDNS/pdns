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

#include "utility.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "base32.hh"
#include <cerrno>
#include "communicator.hh"
#include <set>
#include <boost/utility.hpp>
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "packethandler.hh"
#include "axfr-retriever.hh"
#include "logger.hh"
#include "dns.hh"
#include "arguments.hh"
#include "auth-caches.hh"

#include "base64.hh"
#include "inflighter.cc"
#include "namespaces.hh"
#include "auth-main.hh"
#include "query-local-address.hh"

#include "ixfr.hh"

static std::string humanTime(time_t time)
{
  std::array<char, 80> buf{};
  struct tm tm0{};
  strftime(buf.data(), buf.size() - 1, "%F %H:%M:%S", localtime_r(&time, &tm0));
  return {buf.data(), strlen(buf.data())};
}

void CommunicatorClass::addSuckRequest(const ZoneName& domain, const ComboAddress& primary, SuckRequest::RequestPriority priority, bool force)
{
  auto data = d_data.lock();
  SuckRequest sr;
  sr.domain = domain;
  sr.primary = primary;
  sr.force = force;
  sr.priorityAndOrder.first = priority;
  sr.priorityAndOrder.second = data->d_sorthelper++;
  pair<UniQueue::iterator, bool> res;

  res = data->d_suckdomains.insert(sr);
  if (res.second) {
    d_suck_sem.post();
  }
  else {
    data->d_suckdomains.modify(res.first, [priorityAndOrder = sr.priorityAndOrder](SuckRequest& so) {
      if (priorityAndOrder.first < so.priorityAndOrder.first) {
        so.priorityAndOrder = priorityAndOrder;
      }
    });
  }
}

struct ZoneStatus
{
  bool isDnssecZone{false};
  bool isPresigned{false};
  bool isNSEC3{false};
  bool optOutFlag{false};
  NSEC3PARAMRecordContent ns3pr;

  bool isNarrow{false};
  unsigned int soa_serial{0};
  set<DNSName> nsset, qnames, secured;
  uint32_t domain_id;
  size_t numDeltas{0};
};

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static bool catalogDiff(const DomainInfo& di, vector<CatalogInfo>& fromXFR, vector<CatalogInfo>& fromDB, const string& logPrefix)
{
  extern CommunicatorClass Communicator;

  bool doTransaction{true};
  bool inTransaction{false};
  CatalogInfo ciCreate, ciRemove;
  std::unordered_map<ZoneName, bool> clearCache;
  vector<CatalogInfo> retrieve;

  try {
    sort(fromXFR.begin(), fromXFR.end());
    sort(fromDB.begin(), fromDB.end());

    auto xfr = fromXFR.cbegin();
    auto db = fromDB.cbegin();

    while (xfr != fromXFR.end() || db != fromDB.end()) {
      bool create{false};
      bool remove{false};

      if (xfr != fromXFR.end() && (db == fromDB.end() || *xfr < *db)) { // create
        ciCreate = *xfr;
        create = true;
        ++xfr;
      }
      else if (db != fromDB.end() && (xfr == fromXFR.end() || *db < *xfr)) { // remove
        ciRemove = *db;
        remove = true;
        ++db;
      }
      else {
        CatalogInfo ciXFR = *xfr;
        CatalogInfo ciDB = *db;
        if (ciDB.d_unique.empty() || ciXFR.d_unique == ciDB.d_unique) { // update
          bool doOptions{false};

          if (ciDB.d_unique.empty()) { // set unique
            g_log << Logger::Warning << logPrefix << "set unique, zone '" << ciXFR.d_zone << "' is now a member" << endl;
            ciDB.d_unique = ciXFR.d_unique;
            doOptions = true;
          }

          if (ciXFR.d_coo != ciDB.d_coo) { // update coo
            g_log << Logger::Warning << logPrefix << "update coo for zone '" << ciXFR.d_zone << "' to '" << ciXFR.d_coo << "'" << endl;
            ciDB.d_coo = ciXFR.d_coo;
            doOptions = true;
          }

          if (ciXFR.d_group != ciDB.d_group) { // update group
            g_log << Logger::Warning << logPrefix << "update group for zone '" << ciXFR.d_zone << "' to '" << boost::join(ciXFR.d_group, ", ") << "'" << endl;
            ciDB.d_group = ciXFR.d_group;
            doOptions = true;
          }

          if (doOptions) { // update zone options
            if (doTransaction && (inTransaction = di.backend->startTransaction(di.zone))) {
              g_log << Logger::Warning << logPrefix << "backend transaction started" << endl;
              doTransaction = false;
            }

            g_log << Logger::Warning << logPrefix << "update options for zone '" << ciXFR.d_zone << "'" << endl;
            di.backend->setOptions(ciXFR.d_zone, ciDB.toJson());
          }

          if (di.primaries != ciDB.d_primaries) { // update primaries
            if (doTransaction && (inTransaction = di.backend->startTransaction(di.zone))) {
              g_log << Logger::Warning << logPrefix << "backend transaction started" << endl;
              doTransaction = false;
            }

            vector<string> primaries;
            for (const auto& primary : di.primaries) {
              primaries.push_back(primary.toStringWithPortExcept(53));
            }
            g_log << Logger::Warning << logPrefix << "update primaries for zone '" << ciXFR.d_zone << "' to '" << boost::join(primaries, ", ") << "'" << endl;
            di.backend->setPrimaries(ciXFR.d_zone, di.primaries);

            retrieve.emplace_back(ciXFR);
          }
        }
        else { // reset
          ciCreate = *xfr;
          ciRemove = *db;
          create = true;
          remove = true;
        }
        ++xfr;
        ++db;
      }

      DomainInfo d;
      if (create && remove) {
        g_log << Logger::Warning << logPrefix << "zone '" << ciCreate.d_zone << "' state reset" << endl;
      }
      else if (create && di.backend->getDomainInfo(ciCreate.d_zone, d)) { // detect clash
        CatalogInfo ci;
        ci.fromJson(d.options, CatalogInfo::CatalogType::Consumer);

        if (di.zone != d.catalog && di.zone.operator const DNSName&() == ci.d_coo) {
          if (ciCreate.d_unique == ci.d_unique) {
            g_log << Logger::Warning << logPrefix << "zone '" << d.zone << "' owner change without state reset, old catalog '" << d.catalog << "', new catalog '" << di.zone << "'" << endl;

            if (doTransaction && (inTransaction = di.backend->startTransaction(di.zone))) {
              g_log << Logger::Warning << logPrefix << "backend transaction started" << endl;
              doTransaction = false;
            }

            di.backend->setPrimaries(ciCreate.d_zone, di.primaries);
            di.backend->setOptions(ciCreate.d_zone, ciCreate.toJson());
            di.backend->setCatalog(ciCreate.d_zone, di.zone);

            retrieve.emplace_back(ciCreate);
            continue;
          }
          g_log << Logger::Warning << logPrefix << "zone '" << d.zone << "' owner change with state reset, old catalog '" << d.catalog << "', new catalog '" << di.zone << "'" << endl;

          ciRemove.d_zone = d.zone;
          remove = true;
        }
        else {
          g_log << Logger::Warning << logPrefix << "zone '" << d.zone << "' already exists";
          if (!d.catalog.empty()) {
            g_log << " in catalog '" << d.catalog;
          }
          g_log << "', create skipped" << endl;
          continue;
        }
      }

      if (remove) { // delete zone
        if (doTransaction && (inTransaction = di.backend->startTransaction(di.zone))) {
          g_log << Logger::Warning << logPrefix << "backend transaction started" << endl;
          doTransaction = false;
        }

        g_log << Logger::Warning << logPrefix << "delete zone '" << ciRemove.d_zone << "'" << endl;
        di.backend->deleteDomain(ciRemove.d_zone);

        if (!create) {
          clearCache[ciRemove.d_zone] = false;
        }
      }

      if (create) { // create zone
        if (doTransaction && (inTransaction = di.backend->startTransaction(di.zone))) {
          g_log << Logger::Warning << logPrefix << "backend transaction started" << endl;
          doTransaction = false;
        }

        g_log << Logger::Warning << logPrefix << "create zone '" << ciCreate.d_zone << "'" << endl;
        di.backend->createDomain(ciCreate.d_zone, DomainInfo::Secondary, ciCreate.d_primaries, "");

        di.backend->setPrimaries(ciCreate.d_zone, di.primaries);
        di.backend->setOptions(ciCreate.d_zone, ciCreate.toJson());
        di.backend->setCatalog(ciCreate.d_zone, di.zone);

        clearCache[ciCreate.d_zone] = true;
        retrieve.emplace_back(ciCreate);
      }
    }

    if (inTransaction && di.backend->commitTransaction()) {
      g_log << Logger::Warning << logPrefix << "backend transaction committed" << endl;
    }

    // Update zonecache and clear all caches
    DomainInfo d;
    for (const auto& zone : clearCache) {
      if (g_zoneCache.isEnabled()) {
        if (zone.second) {
          if (di.backend->getDomainInfo(zone.first, d)) {
            g_zoneCache.add(zone.first, d.id);
          }
          else {
            g_log << Logger::Error << logPrefix << "new zone '" << zone.first << "' does not exists and was not inserted in the zone-cache" << endl;
          }
        }
        else {
          g_zoneCache.remove(zone.first);
        }
      }

      DNSSECKeeper::clearCaches(zone.first);
      purgeAuthCaches(zone.first.operator const DNSName&().toString() + "$");
    }

    // retrieve new and updated zones with new primaries
    auto primaries = di.primaries;
    if (!primaries.empty()) {
      for (auto& ret : retrieve) {
        shuffle(primaries.begin(), primaries.end(), pdns::dns_random_engine());
        const auto& primary = primaries.front();
        Communicator.addSuckRequest(ret.d_zone, primary, SuckRequest::Notify);
      }
    }

    return true;
  }
  catch (DBException& re) {
    g_log << Logger::Error << logPrefix << "DBException " << re.reason << endl;
  }
  catch (PDNSException& pe) {
    g_log << Logger::Error << logPrefix << "PDNSException " << pe.reason << endl;
  }
  catch (std::exception& re) {
    g_log << Logger::Error << logPrefix << "std::exception " << re.what() << endl;
  }

  if (di.backend && inTransaction) {
    g_log << Logger::Info << logPrefix << "aborting possible open transaction" << endl;
    di.backend->abortTransaction();
  }

  return false;
}

static bool catalogProcess(const DomainInfo& di, vector<DNSResourceRecord>& rrs, string logPrefix)
{
  logPrefix += "Catalog-Zone ";

  vector<CatalogInfo> fromXFR, fromDB;
  std::unordered_set<ZoneName> dupcheck;

  // From XFR
  bool hasSOA{false};
  bool zoneInvalid{false};
  int hasVersion{0};

  CatalogInfo ci;

  vector<DNSResourceRecord> ret;

  const auto compare = [](const DNSResourceRecord& a, const DNSResourceRecord& b) { return a.qname == b.qname ? a.qtype < b.qtype : a.qname.canonCompare(b.qname); };
  sort(rrs.begin(), rrs.end(), compare);

  DNSName rel;
  DNSName unique;
  for (auto& rr : rrs) {
    if (di.zone.operator const DNSName&() == rr.qname) {
      if (rr.qtype == QType::SOA) {
        hasSOA = true;
        continue;
      }
      if (rr.qtype == QType::NS) {
        continue;
      }
    }

    else if (rr.qname == g_versiondnsname + di.zone.operator const DNSName&() && rr.qtype == QType::TXT) {
      if (hasVersion) {
        g_log << Logger::Warning << logPrefix << "zone '" << di.zone << "', multiple version records found, aborting" << endl;
        return false;
      }

      if (rr.content == "\"1\"") {
        hasVersion = 1;
      }
      else if (rr.content == "\"2\"") {
        hasVersion = 2;
      }
      else {
        g_log << Logger::Warning << logPrefix << "zone '" << di.zone << "', unsupported catalog zone schema version " << rr.content << ", aborting" << endl;
        return false;
      }
    }

    else if (rr.qname.isPartOf(g_zonesdnsname + di.zone.operator const DNSName&())) {
      if (rel.empty() && !hasVersion) {
        g_log << Logger::Warning << logPrefix << "zone '" << di.zone << "', catalog zone schema version missing, aborting" << endl;
        return false;
      }

      rel = rr.qname.makeRelative(g_zonesdnsname + di.zone.operator const DNSName&());

      if (rel.countLabels() == 1 && rr.qtype == QType::PTR) {
        if (!unique.empty()) {
          if (rel != unique) {
            fromXFR.emplace_back(ci);
          }
          else {
            g_log << Logger::Warning << logPrefix << "zone '" << di.zone << "', duplicate unique '" << unique << "'" << endl;
            zoneInvalid = true;
          }
        }

        unique = rel;

        ci = {};
        ci.setType(CatalogInfo::CatalogType::Consumer);
        ci.d_zone = ZoneName(rr.content);
        ci.d_unique = unique;

        if (!dupcheck.insert(ci.d_zone).second) {
          g_log << Logger::Warning << logPrefix << "zone '" << di.zone << "', duplicate member zone'" << ci.d_zone << "'" << endl;
          zoneInvalid = true;
        }
      }

      else if (hasVersion == 2) {
        if (rel == (g_coodnsname + unique) && rr.qtype == QType::PTR) {
          if (!ci.d_coo.empty()) {
            g_log << Logger::Warning << logPrefix << "zone '" << di.zone << "', duplicate COO for unique '" << unique << "'" << endl;
            zoneInvalid = true;
          }
          else {
            ci.d_coo = DNSName(rr.content);
          }
        }
        else if (rel == (g_groupdnsname + unique) && rr.qtype == QType::TXT) {
          std::string content = rr.content;
          if (content.length() >= 2 && content.at(0) == '\"' && content.at(content.length() - 1) == '\"') { // TXT pain
            content = content.substr(1, content.length() - 2);
          }
          ci.d_group.insert(content);
        }
      }
    }
    rr.disabled = true;
  }
  if (!ci.d_zone.empty()) {
    fromXFR.emplace_back(ci);
  }

  if (!hasSOA || !hasVersion || zoneInvalid) {
    g_log << Logger::Warning << logPrefix << "zone '" << di.zone << "' is invalid, skip updates" << endl;
    return false;
  }

  // Get catalog ifo from db
  if (!di.backend->getCatalogMembers(di.zone, fromDB, CatalogInfo::CatalogType::Consumer)) {
    return false;
  }

  // Process
  return catalogDiff(di, fromXFR, fromDB, logPrefix);
}

void CommunicatorClass::ixfrSuck(const ZoneName& domain, const TSIGTriplet& tsig, const ComboAddress& laddr, const ComboAddress& remote, ZoneStatus& status, vector<DNSRecord>* axfr)
{
  string logPrefix = "IXFR-in zone '" + domain.toLogString() + "', primary '" + remote.toString() + "', ";

  UeberBackend B; // fresh UeberBackend

  DomainInfo di;
  di.backend = nullptr;
  //  bool transaction=false;
  try {
    DNSSECKeeper dk(&B); // reuse our UeberBackend copy for DNSSECKeeper

    bool wrongDomainKind = false;
    // this checks three error conditions, and sets wrongDomainKind if we hit the third & had an error
    if (!B.getDomainInfo(domain, di) || !di.backend || (wrongDomainKind = true, di.kind != DomainInfo::Secondary)) { // di.backend and B are mostly identical
      if (wrongDomainKind)
        g_log << Logger::Warning << logPrefix << "can't determine backend, not configured as secondary" << endl;
      else
        g_log << Logger::Warning << logPrefix << "can't determine backend" << endl;
      return;
    }

    uint16_t xfrTimeout = ::arg().asNum("axfr-fetch-timeout");
    soatimes drsoa_soatimes = {di.serial, 0, 0, 0, 0};
    DNSRecord drsoa;
    drsoa.setContent(std::make_shared<SOARecordContent>(g_rootdnsname, g_rootdnsname, drsoa_soatimes));
    auto deltas = getIXFRDeltas(remote, domain.operator const DNSName&(), drsoa, xfrTimeout, false, tsig, laddr.sin4.sin_family != 0 ? &laddr : nullptr, ((size_t)::arg().asNum("xfr-max-received-mbytes")) * 1024 * 1024);
    status.numDeltas = deltas.size();
    //    cout<<"Got "<<deltas.size()<<" deltas from serial "<<di.serial<<", applying.."<<endl;

    for (const auto& d : deltas) {
      const auto& remove = d.first;
      const auto& add = d.second;
      //      cout<<"Delta sizes: "<<remove.size()<<", "<<add.size()<<endl;

      if (remove.empty()) { // we got passed an AXFR!
        *axfr = add;
        return;
      }

      // our hammer is 'replaceRRSet(domain_id, qname, qt, vector<DNSResourceRecord>& rrset)
      // which thinks in terms of RRSETs
      // however, IXFR does not, and removes and adds *records* (bummer)
      // this means that we must group updates by {qname,qtype}, retrieve the RRSET, apply
      // the add/remove updates, and replaceRRSet the whole thing.

      map<pair<ZoneName, uint16_t>, pair<vector<DNSRecord>, vector<DNSRecord>>> grouped;

      for (const auto& x : remove)
        grouped[{ZoneName(x.d_name), x.d_type}].first.push_back(x);
      for (const auto& x : add)
        grouped[{ZoneName(x.d_name), x.d_type}].second.push_back(x);

      di.backend->startTransaction(domain, UnknownDomainID);
      for (const auto& g : grouped) {
        vector<DNSRecord> rrset;
        {
          DNSZoneRecord zrr;
          di.backend->lookup(QType(g.first.second), g.first.first.operator const DNSName&() + domain.operator const DNSName&(), di.id);
          while (di.backend->get(zrr)) {
            zrr.dr.d_name.makeUsRelative(domain);
            rrset.push_back(zrr.dr);
          }
        }
        // O(N^2)!
        rrset.erase(remove_if(rrset.begin(), rrset.end(),
                              [&g](const DNSRecord& dr) {
                                return count(g.second.first.cbegin(),
                                             g.second.first.cend(), dr);
                              }),
                    rrset.end());
        // the DNSRecord== operator compares on name, type, class and lowercase content representation

        for (const auto& x : g.second.second) {
          rrset.push_back(x);
        }

        vector<DNSResourceRecord> replacement;
        for (const auto& dr : rrset) {
          auto rr = DNSResourceRecord::fromWire(dr);
          rr.qname += domain.operator const DNSName&();
          rr.domain_id = di.id;
          if (dr.d_type == QType::SOA) {
            //            cout<<"New SOA: "<<x.d_content->getZoneRepresentation()<<endl;
            auto sr = getRR<SOARecordContent>(dr);
            status.soa_serial = sr->d_st.serial;
          }

          replacement.emplace_back(std::move(rr));
        }

        di.backend->replaceRRSet(di.id, g.first.first.operator const DNSName&() + domain.operator const DNSName&(), QType(g.first.second), replacement);
      }
      di.backend->commitTransaction();
    }
  }
  catch (std::exception& p) {
    g_log << Logger::Error << logPrefix << "got exception (std::exception): " << p.what() << endl;
    throw;
  }
  catch (PDNSException& p) {
    g_log << Logger::Error << logPrefix << "got exception (PDNSException): " << p.reason << endl;
    throw;
  }
}

static bool processRecordForZS(const DNSName& domain, bool& firstNSEC3, DNSResourceRecord& rr, ZoneStatus& zs)
{
  switch (rr.qtype.getCode()) {
  case QType::NSEC3PARAM:
    zs.ns3pr = NSEC3PARAMRecordContent(rr.content);
    zs.isDnssecZone = zs.isNSEC3 = true;
    zs.isNarrow = false;
    return false;
  case QType::NSEC3: {
    NSEC3RecordContent ns3rc(rr.content);
    if (firstNSEC3) {
      zs.isDnssecZone = zs.isPresigned = true;
      firstNSEC3 = false;
    }
    else if (zs.optOutFlag != (ns3rc.d_flags & 1))
      throw PDNSException("Zones with a mixture of Opt-Out NSEC3 RRs and non-Opt-Out NSEC3 RRs are not supported.");
    zs.optOutFlag = ns3rc.d_flags & 1;
    if (ns3rc.isSet(QType::NS) && !(rr.qname == domain)) {
      DNSName hashPart = rr.qname.makeRelative(domain);
      zs.secured.insert(hashPart);
    }
    return false;
  }

  case QType::NSEC:
    zs.isDnssecZone = zs.isPresigned = true;
    return false;

  case QType::NS:
    if (rr.qname != domain)
      zs.nsset.insert(rr.qname);
    break;
  }

  zs.qnames.insert(rr.qname);

  rr.domain_id = zs.domain_id;
  return true;
}

/* So this code does a number of things.
   1) It will AXFR a domain from a primary
      The code can retrieve the current serial number in the database itself.
      It may attempt an IXFR
   2) It will filter the zone through a lua *filter* script
   3) The code walks through the zone records do determine DNSSEC status (secured, nsec/nsec3, optout)
   4) It inserts the zone into the database
      With the right 'ordername' fields
   5) It updates the Empty Non Terminals
*/

static vector<DNSResourceRecord> doAxfr(const ComboAddress& raddr, const DNSName& domain, const TSIGTriplet& tt, const ComboAddress& laddr, unique_ptr<AuthLua4>& pdl, ZoneStatus& zs)
{
  uint16_t axfr_timeout = ::arg().asNum("axfr-fetch-timeout");
  vector<DNSResourceRecord> rrs;
  AXFRRetriever retriever(raddr, ZoneName(domain), tt, (laddr.sin4.sin_family == 0) ? nullptr : &laddr, ((size_t)::arg().asNum("xfr-max-received-mbytes")) * 1024 * 1024, axfr_timeout);
  Resolver::res_t recs;
  bool first = true;
  bool firstNSEC3{true};
  bool soa_received{false};
  string logPrefix = "AXFR-in zone '" + domain.toLogString() + "', primary '" + raddr.toString() + "', ";
  while (retriever.getChunk(recs, nullptr, axfr_timeout)) {
    if (first) {
      g_log << Logger::Notice << logPrefix << "retrieval started" << endl;
      first = false;
    }

    for (auto& rec : recs) {
      rec.qname.makeUsLowerCase();
      if (rec.qtype.getCode() == QType::OPT || rec.qtype.getCode() == QType::TSIG) // ignore EDNS0 & TSIG
        continue;

      if (!rec.qname.isPartOf(domain)) {
        g_log << Logger::Warning << logPrefix << "primary tried to sneak in out-of-zone data '" << rec.qname << "'|" << rec.qtype.toString() << ", ignoring" << endl;
        continue;
      }

      vector<DNSResourceRecord> out;
      if (!pdl || !pdl->axfrfilter(raddr, domain, rec, out)) {
        out.push_back(rec); // if axfrfilter didn't do anything, we put our record in 'out' ourselves
      }

      for (auto& rr : out) {
        if (!rr.qname.isPartOf(domain)) {
          g_log << Logger::Error << logPrefix << "axfrfilter() filter tried to sneak in out-of-zone data '" << rr.qname << "'|" << rr.qtype.toString() << ", ignoring" << endl;
          continue;
        }
        if (!processRecordForZS(domain, firstNSEC3, rr, zs))
          continue;
        if (rr.qtype.getCode() == QType::SOA) {
          if (soa_received)
            continue; // skip the last SOA
          SOAData sd;
          fillSOAData(rr.content, sd);
          zs.soa_serial = sd.serial;
          soa_received = true;
        }

        rrs.push_back(rr);
      }
    }
  }
  return rrs;
}

void CommunicatorClass::suck(const ZoneName& domain, const ComboAddress& remote, bool force) // NOLINT(readability-function-cognitive-complexity)
{
  {
    auto data = d_data.lock();
    if (data->d_inprogress.count(domain)) {
      return;
    }
    data->d_inprogress.insert(domain);
  }
  RemoveSentinel rs(domain, this); // this removes us from d_inprogress when we go out of scope

  string logPrefix = "XFR-in zone: '" + domain.toLogString() + "', primary: '" + remote.toString() + "', ";

  g_log << Logger::Notice << logPrefix << "initiating transfer" << endl;
  UeberBackend B; // fresh UeberBackend

  DomainInfo di;
  di.backend = nullptr;
  bool transaction = false;
  try {
    DNSSECKeeper dk(&B); // reuse our UeberBackend copy for DNSSECKeeper
    bool wrongDomainKind = false;
    // this checks three error conditions & sets wrongDomainKind if we hit the third
    if (!B.getDomainInfo(domain, di) || !di.backend || (wrongDomainKind = true, !force && !di.isSecondaryType())) { // di.backend and B are mostly identical
      if (wrongDomainKind)
        g_log << Logger::Warning << logPrefix << "can't determine backend, not configured as secondary" << endl;
      else
        g_log << Logger::Warning << logPrefix << "can't determine backend" << endl;
      return;
    }
    ZoneStatus zs;
    zs.domain_id = di.id;

    TSIGTriplet tt;
    if (dk.getTSIGForAccess(domain, remote, &tt.name)) {
      string tsigsecret64;
      if (B.getTSIGKey(tt.name, tt.algo, tsigsecret64)) {
        if (B64Decode(tsigsecret64, tt.secret)) {
          g_log << Logger::Error << logPrefix << "unable to Base-64 decode TSIG key '" << tt.name << "' or zone not found" << endl;
          return;
        }
      }
      else {
        g_log << Logger::Warning << logPrefix << "TSIG key '" << tt.name << "' for zone not found" << endl;
        return;
      }
    }

    unique_ptr<AuthLua4> pdl{nullptr};
    vector<string> scripts;
    string script = ::arg()["lua-axfr-script"];
    if (B.getDomainMetadata(domain, "LUA-AXFR-SCRIPT", scripts) && !scripts.empty()) {
      if (pdns_iequals(scripts[0], "NONE")) {
        script.clear();
      }
      else {
        script = scripts[0];
      }
    }
    if (!script.empty()) {
      try {
        pdl = make_unique<AuthLua4>(::arg()["lua-global-include-dir"]);
        pdl->loadFile(script);
        g_log << Logger::Info << logPrefix << "loaded Lua script '" << script << "'" << endl;
      }
      catch (std::exception& e) {
        g_log << Logger::Error << logPrefix << "failed to load Lua script '" << script << "': " << e.what() << endl;
        return;
      }
    }

    vector<string> localaddr;
    ComboAddress laddr;

    if (B.getDomainMetadata(domain, "AXFR-SOURCE", localaddr) && !localaddr.empty()) {
      try {
        laddr = ComboAddress(localaddr[0]);
        g_log << Logger::Info << logPrefix << "xfr source set to " << localaddr[0] << endl;
      }
      catch (std::exception& e) {
        g_log << Logger::Error << logPrefix << "failed to set xfr source '" << localaddr[0] << "': " << e.what() << endl;
        return;
      }
    }
    else {
      if (!pdns::isQueryLocalAddressFamilyEnabled(remote.sin4.sin_family)) {
        bool isV6 = remote.sin4.sin_family == AF_INET6;
        g_log << Logger::Warning << logPrefix << "unable to xfr, address family (IPv" << (isV6 ? "6" : "4") << " is not enabled for outgoing traffic (query-local-address)" << endl;
        return;
      }
      laddr = pdns::getQueryLocalAddress(remote.sin4.sin_family, 0);
    }

    bool hadDnssecZone = false;
    bool hadPresigned = false;
    bool hadNSEC3 = false;
    NSEC3PARAMRecordContent hadNs3pr;
    bool hadNarrow = false;

    vector<DNSResourceRecord> rrs;
    if (dk.isSecuredZone(domain, false)) {
      hadDnssecZone = true;
      hadPresigned = dk.isPresigned(domain, false);
      if (dk.getNSEC3PARAM(domain, &zs.ns3pr, &zs.isNarrow, false)) {
        hadNSEC3 = true;
        hadNs3pr = zs.ns3pr;
        hadNarrow = zs.isNarrow;
      }
    }
    else if (di.serial) {
      vector<string> meta;
      B.getDomainMetadata(domain, "IXFR", meta);
      if (!meta.empty() && meta[0] == "1") {
        logPrefix = "I" + logPrefix; // XFR -> IXFR
        vector<DNSRecord> axfr;
        g_log << Logger::Notice << logPrefix << "starting IXFR" << endl;
        CommunicatorClass::ixfrSuck(domain, tt, laddr, remote, zs, &axfr);
        if (!axfr.empty()) {
          g_log << Logger::Notice << logPrefix << "IXFR turned into an AXFR" << endl;
          logPrefix[0] = 'A'; // IXFR -> AXFR
          bool firstNSEC3 = true;
          rrs.reserve(axfr.size());
          for (const auto& dr : axfr) {
            auto rr = DNSResourceRecord::fromWire(dr);
            rr.qname += domain.operator const DNSName&();
            rr.qname.makeUsLowerCase();
            rr.domain_id = zs.domain_id;
            if (!processRecordForZS(domain.operator const DNSName&(), firstNSEC3, rr, zs)) {
              continue;
            }
            if (dr.d_type == QType::SOA) {
              auto sd = getRR<SOARecordContent>(dr);
              zs.soa_serial = sd->d_st.serial;
            }
            rrs.emplace_back(std::move(rr));
          }
        }
        else {
          g_log << Logger::Warning << logPrefix << "got " << zs.numDeltas << " delta" << addS(zs.numDeltas) << ", zone committed with serial " << zs.soa_serial << endl;
          purgeAuthCaches(domain.operator const DNSName&().toString() + "$");
          return;
        }
      }
    }

    if (rrs.empty()) {
      g_log << Logger::Notice << logPrefix << "starting AXFR" << endl;
      rrs = doAxfr(remote, domain.operator const DNSName&(), tt, laddr, pdl, zs);
      logPrefix = "A" + logPrefix; // XFR -> AXFR
      g_log << Logger::Notice << logPrefix << "retrieval finished" << endl;
    }

    if (di.kind == DomainInfo::Consumer) {
      if (!catalogProcess(di, rrs, logPrefix)) {
        g_log << Logger::Warning << logPrefix << "Catalog-Zone update failed, only import records" << endl;
      }
    }

    if (zs.isNSEC3) {
      zs.ns3pr.d_flags = zs.optOutFlag ? 1 : 0;
    }

    if (!zs.isPresigned) {
      DNSSECKeeper::keyset_t keys = dk.getKeys(domain, false);
      if (!keys.empty()) {
        zs.isDnssecZone = true;
        zs.isNSEC3 = hadNSEC3;
        zs.ns3pr = hadNs3pr;
        zs.optOutFlag = (hadNs3pr.d_flags & 1);
        zs.isNarrow = hadNarrow;
      }
    }

    if (zs.isDnssecZone) {
      if (!zs.isNSEC3)
        g_log << Logger::Debug << logPrefix << "adding NSEC ordering information" << endl;
      else if (!zs.isNarrow)
        g_log << Logger::Debug << logPrefix << "adding NSEC3 hashed ordering information" << endl;
      else
        g_log << Logger::Debug << logPrefix << "zone is narrow, only setting 'auth' fields" << endl;
    }

    transaction = di.backend->startTransaction(domain, zs.domain_id);
    g_log << Logger::Info << logPrefix << "storage transaction started" << endl;

    // update the presigned flag and NSEC3PARAM
    if (zs.isDnssecZone) {
      // update presigned if there was a change
      if (zs.isPresigned && !hadPresigned) {
        // zone is now presigned
        dk.setPresigned(domain);
      }
      else if (hadPresigned && !zs.isPresigned) {
        // zone is no longer presigned
        dk.unsetPresigned(domain);
      }
      // update NSEC3PARAM
      if (zs.isNSEC3) {
        // zone is NSEC3, only update if there was a change
        if (!hadNSEC3 || (hadNarrow != zs.isNarrow) || (zs.ns3pr.d_algorithm != hadNs3pr.d_algorithm) || (zs.ns3pr.d_flags != hadNs3pr.d_flags) || (zs.ns3pr.d_iterations != hadNs3pr.d_iterations) || (zs.ns3pr.d_salt != hadNs3pr.d_salt)) {
          dk.setNSEC3PARAM(domain, zs.ns3pr, zs.isNarrow);
        }
      }
      else if (hadNSEC3) {
        // zone is no longer NSEC3
        dk.unsetNSEC3PARAM(domain);
      }
    }
    else if (hadDnssecZone) {
      // zone is no longer signed
      if (hadPresigned) {
        // remove presigned
        dk.unsetPresigned(domain);
      }
      if (hadNSEC3) {
        // unset NSEC3PARAM
        dk.unsetNSEC3PARAM(domain);
      }
    }

    bool doent = true;
    uint32_t maxent = ::arg().asNum("max-ent-entries");
    DNSName shorter, ordername;
    set<DNSName> rrterm;
    map<DNSName, bool> nonterm;

    for (DNSResourceRecord& rr : rrs) {
      if (!zs.isPresigned) {
        if (rr.qtype.getCode() == QType::RRSIG)
          continue;
        if (zs.isDnssecZone && rr.qtype.getCode() == QType::DNSKEY && !::arg().mustDo("direct-dnskey"))
          continue;
      }

      // Figure out auth and ents
      rr.auth = true;
      shorter = rr.qname;
      rrterm.clear();
      do {
        if (doent) {
          if (!zs.qnames.count(shorter))
            rrterm.insert(shorter);
        }
        if (zs.nsset.count(shorter) && rr.qtype.getCode() != QType::DS)
          rr.auth = false;

        if (shorter == domain.operator const DNSName&()) { // stop at apex
          break;
        }
      } while (shorter.chopOff());

      // Insert ents
      if (doent && !rrterm.empty()) {
        bool auth;
        if (!rr.auth && rr.qtype.getCode() == QType::NS) {
          if (zs.isNSEC3)
            ordername = DNSName(toBase32Hex(hashQNameWithSalt(zs.ns3pr, rr.qname)));
          auth = (!zs.isNSEC3 || !zs.optOutFlag || zs.secured.count(ordername));
        }
        else
          auth = rr.auth;

        for (const auto& nt : rrterm) {
          if (!nonterm.count(nt))
            nonterm.insert(pair<DNSName, bool>(nt, auth));
          else if (auth)
            nonterm[nt] = true;
        }

        if (nonterm.size() > maxent) {
          g_log << Logger::Warning << logPrefix << "zone has too many empty non terminals" << endl;
          nonterm.clear();
          doent = false;
        }
      }

      // RRSIG is always auth, even inside a delegation
      if (rr.qtype.getCode() == QType::RRSIG)
        rr.auth = true;

      // Add ordername and insert record
      if (zs.isDnssecZone && rr.qtype.getCode() != QType::RRSIG) {
        if (zs.isNSEC3) {
          // NSEC3
          ordername = DNSName(toBase32Hex(hashQNameWithSalt(zs.ns3pr, rr.qname)));
          if (!zs.isNarrow && (rr.auth || (rr.qtype.getCode() == QType::NS && (!zs.optOutFlag || zs.secured.count(ordername))))) {
            di.backend->feedRecord(rr, ordername, true);
          }
          else
            di.backend->feedRecord(rr, DNSName());
        }
        else {
          // NSEC
          if (rr.auth || rr.qtype.getCode() == QType::NS) {
            ordername = rr.qname.makeRelative(domain);
            di.backend->feedRecord(rr, ordername);
          }
          else
            di.backend->feedRecord(rr, DNSName());
        }
      }
      else
        di.backend->feedRecord(rr, DNSName());
    }

    // Insert empty non-terminals
    if (doent && !nonterm.empty()) {
      if (zs.isNSEC3) {
        di.backend->feedEnts3(zs.domain_id, domain.operator const DNSName&(), nonterm, zs.ns3pr, zs.isNarrow);
      }
      else
        di.backend->feedEnts(zs.domain_id, nonterm);
    }

    di.backend->commitTransaction();
    transaction = false;
    di.backend->setFresh(zs.domain_id);
    purgeAuthCaches(domain.operator const DNSName&().toString() + "$");

    g_log << Logger::Warning << logPrefix << "zone committed with serial " << zs.soa_serial << endl;

    // Send secondary re-notifications
    bool doNotify;
    vector<string> meta;
    if (B.getDomainMetadata(domain, "SLAVE-RENOTIFY", meta) && !meta.empty()) {
      doNotify = (meta.front() == "1");
    }
    else {
      doNotify = (::arg().mustDo("secondary-do-renotify"));
    }
    if (doNotify) {
      notifyDomain(domain, &B);
    }
  }
  catch (DBException& re) {
    g_log << Logger::Error << logPrefix << "unable to feed record: " << re.reason << endl;
    if (di.backend && transaction) {
      g_log << Logger::Info << logPrefix << "aborting possible open transaction" << endl;
      di.backend->abortTransaction();
    }
  }
  catch (const MOADNSException& mde) {
    g_log << Logger::Error << logPrefix << "unable to parse record (MOADNSException): " << mde.what() << endl;
    if (di.backend && transaction) {
      g_log << Logger::Info << logPrefix << "aborting possible open transaction" << endl;
      di.backend->abortTransaction();
    }
  }
  catch (std::exception& re) {
    g_log << Logger::Error << logPrefix << "unable to xfr zone (std::exception): " << re.what() << endl;
    if (di.backend && transaction) {
      g_log << Logger::Info << logPrefix << "aborting possible open transaction" << endl;
      di.backend->abortTransaction();
    }
  }
  catch (ResolverException& re) {
    {
      auto data = d_data.lock();
      // The AXFR probably failed due to a problem on the primary server. If SOA-checks against this primary
      // still succeed, we would constantly try to AXFR the zone. To avoid this, we add the zone to the list of
      // failed secondary-checks. This will suspend secondary-checks (and subsequent AXFR) for this zone for some time.
      uint64_t newCount = 1;
      time_t now = time(nullptr);
      const auto failedEntry = data->d_failedSecondaryRefresh.find(domain);
      if (failedEntry != data->d_failedSecondaryRefresh.end()) {
        newCount = data->d_failedSecondaryRefresh[domain].first + 1;
      }
      time_t nextCheck = now + std::min(newCount * d_tickinterval, (uint64_t)::arg().asNum("default-ttl"));
      data->d_failedSecondaryRefresh[domain] = {newCount, nextCheck};
      g_log << Logger::Warning << logPrefix << "unable to xfr zone (ResolverException): " << re.reason << " (This was attempt number " << newCount << ". Excluding zone from secondary-checks until " << humanTime(nextCheck) << ")" << endl;
    }
    if (di.backend && transaction) {
      g_log << Logger::Info << "aborting possible open transaction" << endl;
      di.backend->abortTransaction();
    }
  }
  catch (PDNSException& ae) {
    g_log << Logger::Error << logPrefix << "unable to xfr zone (PDNSException): " << ae.reason << endl;
    if (di.backend && transaction) {
      g_log << Logger::Info << logPrefix << "aborting possible open transaction" << endl;
      di.backend->abortTransaction();
    }
  }
}
namespace
{
struct DomainNotificationInfo
{
  DomainInfo di;
  bool dnssecOk;
  ComboAddress localaddr;
  DNSName tsigkeyname, tsigalgname;
  string tsigsecret;
};
}

struct SecondarySenderReceiver
{
  typedef std::tuple<DNSName, ComboAddress, uint16_t> Identifier;

  struct Answer
  {
    uint32_t theirSerial;
    uint32_t theirInception;
    uint32_t theirExpire;
  };

  map<uint32_t, Answer> d_freshness;

  void deliverTimeout(const Identifier& /* i */)
  {
  }

  Identifier send(DomainNotificationInfo& dni)
  {
    shuffle(dni.di.primaries.begin(), dni.di.primaries.end(), pdns::dns_random_engine());
    try {
      return {dni.di.zone.operator const DNSName&(),
              *dni.di.primaries.begin(),
              d_resolver.sendResolve(*dni.di.primaries.begin(),
                                     dni.localaddr,
                                     dni.di.zone.operator const DNSName&(),
                                     QType::SOA,
                                     nullptr,
                                     dni.dnssecOk, dni.tsigkeyname, dni.tsigalgname, dni.tsigsecret)};
    }
    catch (PDNSException& e) {
      throw runtime_error("While attempting to query freshness of '" + dni.di.zone.toLogString() + "': " + e.reason);
    }
  }

  bool receive(Identifier& id, Answer& a)
  {
    return d_resolver.tryGetSOASerial(&(std::get<0>(id)), &(std::get<1>(id)), &a.theirSerial, &a.theirInception, &a.theirExpire, &(std::get<2>(id)));
  }

  void deliverAnswer(const DomainNotificationInfo& dni, const Answer& a, unsigned int /* usec */)
  {
    d_freshness[dni.di.id] = a;
  }

  Resolver d_resolver;
};

void CommunicatorClass::addSecondaryCheckRequest(const DomainInfo& di, const ComboAddress& remote)
{
  auto data = d_data.lock();
  DomainInfo ours = di;
  ours.backend = nullptr;

  // When adding a check, if the remote addr from which notification was
  // received is a primary, clear all other primaries so we can be sure the
  // query goes to that one.
  for (const auto& primary : di.primaries) {
    if (ComboAddress::addressOnlyEqual()(remote, primary)) {
      ours.primaries.clear();
      ours.primaries.push_back(primary);
      break;
    }
  }
  data->d_tocheck.erase(di);
  data->d_tocheck.insert(ours);
  d_any_sem.post(); // kick the loop!
}

void CommunicatorClass::addTryAutoPrimaryRequest(const DNSPacket& p)
{
  const DNSPacket& ours = p;
  auto data = d_data.lock();
  if (data->d_potentialautoprimaries.insert(ours).second) {
    d_any_sem.post(); // kick the loop!
  }
}

void CommunicatorClass::secondaryRefresh(PacketHandler* P)
{
  // not unless we are secondary
  if (!::arg().mustDo("secondary"))
    return;

  UeberBackend* B = P->getBackend();
  vector<DomainInfo> rdomains;
  vector<DomainNotificationInfo> sdomains;
  set<DNSPacket, Data::cmp> trysuperdomains;
  {
    auto data = d_data.lock();
    set<DomainInfo> requeue;
    rdomains.reserve(data->d_tocheck.size());
    for (const auto& di : data->d_tocheck) {
      if (data->d_inprogress.count(di.zone)) {
        g_log << Logger::Debug << "Got NOTIFY for " << di.zone << " while AXFR in progress, requeueing SOA check" << endl;
        requeue.insert(di);
      }
      else {
        // We received a NOTIFY for a zone. This means at least one of the zone's primary server is working.
        // Therefore we delete the zone from the list of failed secondary-checks to allow immediate checking.
        const auto wasFailedDomain = data->d_failedSecondaryRefresh.find(di.zone);
        if (wasFailedDomain != data->d_failedSecondaryRefresh.end()) {
          g_log << Logger::Debug << "Got NOTIFY for " << di.zone << ", removing zone from list of failed secondary-checks and going to check SOA serial" << endl;
          data->d_failedSecondaryRefresh.erase(di.zone);
        }
        else {
          g_log << Logger::Debug << "Got NOTIFY for " << di.zone << ", going to check SOA serial" << endl;
        }
        rdomains.push_back(di);
      }
    }
    data->d_tocheck.swap(requeue);

    trysuperdomains = std::move(data->d_potentialautoprimaries);
    data->d_potentialautoprimaries.clear();
  }

  for (const DNSPacket& dp : trysuperdomains) {
    // get the TSIG key name
    TSIGRecordContent trc;
    DNSName tsigkeyname;
    dp.getTSIGDetails(&trc, &tsigkeyname);
    P->tryAutoPrimarySynchronous(dp, tsigkeyname); // FIXME could use some error logging
  }
  if (rdomains.empty()) { // if we have priority domains, check them first
    B->getUnfreshSecondaryInfos(&rdomains);
  }
  sdomains.reserve(rdomains.size());
  DNSSECKeeper dk(B); // NOW HEAR THIS! This DK uses our B backend, so no interleaved access!
  bool checkSignatures = ::arg().mustDo("secondary-check-signature-freshness") && dk.doesDNSSEC();
  {
    auto data = d_data.lock();
    domains_by_name_t& nameindex = boost::multi_index::get<IDTag>(data->d_suckdomains);
    time_t now = time(nullptr);

    for (DomainInfo& di : rdomains) {
      const auto failed = data->d_failedSecondaryRefresh.find(di.zone);
      if (failed != data->d_failedSecondaryRefresh.end() && now < failed->second.second) {
        // If the domain has failed before and the time before the next check has not expired, skip this domain
        g_log << Logger::Debug << "Zone '" << di.zone << "' is on the list of failed SOA checks. Skipping SOA checks until " << humanTime(failed->second.second) << endl;
        continue;
      }
      std::vector<std::string> localaddr;
      SuckRequest sr;
      sr.domain = di.zone;
      if (di.primaries.empty()) // secondary domains w/o primaries are ignored
        continue;
      // remove unfresh domains already queued for AXFR, no sense polling them again
      sr.primary = *di.primaries.begin();
      if (nameindex.count(sr)) { // this does NOT however protect us against AXFRs already in progress!
        continue;
      }
      if (data->d_inprogress.count(sr.domain)) { // this does
        continue;
      }

      DomainNotificationInfo dni;
      dni.di = di;
      dni.dnssecOk = checkSignatures;

      if (dk.getTSIGForAccess(di.zone, sr.primary, &dni.tsigkeyname)) {
        string secret64;
        if (!B->getTSIGKey(dni.tsigkeyname, dni.tsigalgname, secret64)) {
          g_log << Logger::Warning << "TSIG key '" << dni.tsigkeyname << "' for domain '" << di.zone << "' not found, can not AXFR." << endl;
          continue;
        }
        if (B64Decode(secret64, dni.tsigsecret) == -1) {
          g_log << Logger::Error << "Unable to Base-64 decode TSIG key '" << dni.tsigkeyname << "' for domain '" << di.zone << "', can not AXFR." << endl;
          continue;
        }
      }

      localaddr.clear();
      // check for AXFR-SOURCE
      if (B->getDomainMetadata(di.zone, "AXFR-SOURCE", localaddr) && !localaddr.empty()) {
        try {
          dni.localaddr = ComboAddress(localaddr[0]);
          g_log << Logger::Info << "Freshness check source (AXFR-SOURCE) for domain '" << di.zone << "' set to " << localaddr[0] << endl;
        }
        catch (std::exception& e) {
          g_log << Logger::Error << "Failed to load freshness check source '" << localaddr[0] << "' for '" << di.zone << "': " << e.what() << endl;
          return;
        }
      }
      else {
        dni.localaddr.sin4.sin_family = 0;
      }

      sdomains.push_back(std::move(dni));
    }
  }
  if (sdomains.empty()) {
    if (d_secondarieschanged) {
      auto data = d_data.lock();
      g_log << Logger::Info << "No new unfresh secondary domains, " << data->d_suckdomains.size() << " queued for AXFR already, " << data->d_inprogress.size() << " in progress" << endl;
    }
    d_secondarieschanged = !rdomains.empty();
    return;
  }
  else {
    auto data = d_data.lock();
    g_log << Logger::Info << sdomains.size() << " secondary domain" << (sdomains.size() > 1 ? "s" : "") << " need" << (sdomains.size() > 1 ? "" : "s") << " checking, " << data->d_suckdomains.size() << " queued for AXFR" << endl;
  }

  SecondarySenderReceiver ssr;

  Inflighter<vector<DomainNotificationInfo>, SecondarySenderReceiver> ifl(sdomains, ssr);

  ifl.d_maxInFlight = 200;

  for (;;) {
    try {
      ifl.run();
      break;
    }
    catch (std::exception& e) {
      g_log << Logger::Error << "While checking domain freshness: " << e.what() << endl;
    }
    catch (PDNSException& re) {
      g_log << Logger::Error << "While checking domain freshness: " << re.reason << endl;
    }
  }

  if (ifl.getTimeouts()) {
    g_log << Logger::Warning << "Received serial number updates for " << ssr.d_freshness.size() << " zone" << addS(ssr.d_freshness.size()) << ", had " << ifl.getTimeouts() << " timeout" << addS(ifl.getTimeouts()) << endl;
  }
  else {
    g_log << Logger::Info << "Received serial number updates for " << ssr.d_freshness.size() << " zone" << addS(ssr.d_freshness.size()) << endl;
  }

  time_t now = time(nullptr);
  for (auto& val : sdomains) {
    DomainInfo& di(val.di);
    // If our di comes from packethandler (caused by incoming NOTIFY), di.backend will not be filled out,
    // and di.serial will not either.
    // Conversely, if our di came from getUnfreshSecondaryInfos, di.backend and di.serial are valid.
    if (!di.backend) {
      // Do not overwrite received DI just to make sure it exists in backend:
      // di.primaries should contain the picked primary (as first entry)!
      DomainInfo tempdi;
      if (!B->getDomainInfo(di.zone, tempdi, false)) {
        g_log << Logger::Info << "Ignore domain " << di.zone << " since it has been removed from our backend" << endl;
        continue;
      }
      // Backend for di still doesn't exist and this might cause us to
      // SEGFAULT on the setFresh command later on
      di.backend = tempdi.backend;
    }

    if (!ssr.d_freshness.count(di.id)) { // If we don't have an answer for the domain
      uint64_t newCount = 1;
      auto data = d_data.lock();
      const auto failedEntry = data->d_failedSecondaryRefresh.find(di.zone);
      if (failedEntry != data->d_failedSecondaryRefresh.end())
        newCount = data->d_failedSecondaryRefresh[di.zone].first + 1;
      time_t nextCheck = now + std::min(newCount * d_tickinterval, (uint64_t)::arg().asNum("default-ttl"));
      data->d_failedSecondaryRefresh[di.zone] = {newCount, nextCheck};
      if (newCount == 1) {
        g_log << Logger::Warning << "Unable to retrieve SOA for " << di.zone << ", this was the first time. NOTE: For every subsequent failed SOA check the domain will be suspended from freshness checks for 'num-errors x " << d_tickinterval << " seconds', with a maximum of " << (uint64_t)::arg().asNum("default-ttl") << " seconds. Skipping SOA checks until " << humanTime(nextCheck) << endl;
      }
      else if (newCount % 10 == 0) {
        g_log << Logger::Notice << "Unable to retrieve SOA for " << di.zone << ", this was the " << std::to_string(newCount) << "th time. Skipping SOA checks until " << humanTime(nextCheck) << endl;
      }
      // Make sure we recheck SOA for notifies
      if (di.receivedNotify) {
        di.backend->setStale(di.id);
      }
      continue;
    }

    {
      auto data = d_data.lock();
      const auto wasFailedDomain = data->d_failedSecondaryRefresh.find(di.zone);
      if (wasFailedDomain != data->d_failedSecondaryRefresh.end())
        data->d_failedSecondaryRefresh.erase(di.zone);
    }

    bool hasSOA = false;
    SOAData sd;
    try {
      // Use UeberBackend cache for SOA. Cache gets cleared after AXFR/IXFR.
      B->lookup(QType(QType::SOA), di.zone.operator const DNSName&(), di.id, nullptr);
      DNSZoneRecord zr;
      hasSOA = B->get(zr);
      if (hasSOA) {
        fillSOAData(zr, sd);
        B->lookupEnd();
      }
    }
    catch (...) {
    }

    uint32_t theirserial = ssr.d_freshness[di.id].theirSerial;
    uint32_t ourserial = sd.serial;
    const ComboAddress remote = *di.primaries.begin();

    if (hasSOA && rfc1982LessThan(theirserial, ourserial) && !::arg().mustDo("axfr-lower-serial")) {
      g_log << Logger::Warning << "Domain '" << di.zone << "' more recent than primary " << remote.toStringWithPortExcept(53) << ", our serial " << ourserial << " > their serial " << theirserial << endl;
      di.backend->setFresh(di.id);
    }
    else if (hasSOA && theirserial == ourserial) {
      uint32_t maxExpire = 0, maxInception = 0;
      if (checkSignatures && dk.isPresigned(di.zone)) {
        B->lookup(QType(QType::RRSIG), di.zone.operator const DNSName&(), di.id); // can't use DK before we are done with this lookup!
        DNSZoneRecord zr;
        while (B->get(zr)) {
          auto rrsig = getRR<RRSIGRecordContent>(zr.dr);
          if (rrsig->d_type == QType::SOA) {
            maxInception = std::max(maxInception, rrsig->d_siginception);
            maxExpire = std::max(maxExpire, rrsig->d_sigexpire);
          }
        }
      }

      SuckRequest::RequestPriority prio = SuckRequest::SignaturesRefresh;
      if (di.receivedNotify) {
        prio = SuckRequest::Notify;
      }

      if (!maxInception && !ssr.d_freshness[di.id].theirInception) {
        g_log << Logger::Info << "Domain '" << di.zone << "' is fresh (no DNSSEC), serial is " << ourserial << " (checked primary " << remote.toStringWithPortExcept(53) << ")" << endl;
        di.backend->setFresh(di.id);
      }
      else if (maxInception == ssr.d_freshness[di.id].theirInception && maxExpire == ssr.d_freshness[di.id].theirExpire) {
        g_log << Logger::Info << "Domain '" << di.zone << "' is fresh and SOA RRSIGs match, serial is " << ourserial << " (checked primary " << remote.toStringWithPortExcept(53) << ")" << endl;
        di.backend->setFresh(di.id);
      }
      else if (maxExpire >= now && !ssr.d_freshness[di.id].theirInception) {
        g_log << Logger::Info << "Domain '" << di.zone << "' is fresh, primary " << remote.toStringWithPortExcept(53) << " is no longer signed but (some) signatures are still valid, serial is " << ourserial << endl;
        di.backend->setFresh(di.id);
      }
      else if (maxInception && !ssr.d_freshness[di.id].theirInception) {
        g_log << Logger::Notice << "Domain '" << di.zone << "' is stale, primary " << remote.toStringWithPortExcept(53) << " is no longer signed and all signatures have expired, serial is " << ourserial << endl;
        addSuckRequest(di.zone, remote, prio);
      }
      else if (dk.doesDNSSEC() && !maxInception && ssr.d_freshness[di.id].theirInception) {
        g_log << Logger::Notice << "Domain '" << di.zone << "' is stale, primary " << remote.toStringWithPortExcept(53) << " has signed, serial is " << ourserial << endl;
        addSuckRequest(di.zone, remote, prio);
      }
      else {
        g_log << Logger::Notice << "Domain '" << di.zone << "' is fresh, but RRSIGs differ on primary " << remote.toStringWithPortExcept(53) << ", so DNSSEC is stale, serial is " << ourserial << endl;
        addSuckRequest(di.zone, remote, prio);
      }
    }
    else {
      SuckRequest::RequestPriority prio = SuckRequest::SerialRefresh;
      if (di.receivedNotify) {
        prio = SuckRequest::Notify;
      }

      if (hasSOA) {
        g_log << Logger::Notice << "Domain '" << di.zone << "' is stale, primary " << remote.toStringWithPortExcept(53) << " serial " << theirserial << ", our serial " << ourserial << endl;
      }
      else {
        g_log << Logger::Notice << "Domain '" << di.zone << "' is empty, primary " << remote.toStringWithPortExcept(53) << " serial " << theirserial << endl;
      }
      addSuckRequest(di.zone, remote, prio);
    }
  }
}

vector<pair<ZoneName, ComboAddress>> CommunicatorClass::getSuckRequests()
{
  vector<pair<ZoneName, ComboAddress>> ret;
  auto data = d_data.lock();
  ret.reserve(data->d_suckdomains.size());
  for (auto const& d : data->d_suckdomains) {
    ret.emplace_back(d.domain, d.primary);
  }
  return ret;
}

size_t CommunicatorClass::getSuckRequestsWaiting()
{
  return d_data.lock()->d_suckdomains.size();
}
