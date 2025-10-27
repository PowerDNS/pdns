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

#include "arguments.hh"
#include "syncres.hh"
#include "reczones-helpers.hh"
#include "root-addresses.hh"
#include "zoneparser-tng.hh"

static void putIntoCache(time_t now, QType qtype, vState state, const ComboAddress& from, const set<DNSName>& seen, const std::multimap<DNSName, DNSRecord>& allRecords)
{
  for (const auto& name : seen) {
    auto records = allRecords.equal_range(name);
    vector<DNSRecord> aset;
    for (auto elem = records.first; elem != records.second; ++elem) {
      aset.emplace_back(elem->second);
    }
    // Put non-default root hints into cache as authoritative.  As argued below in
    // putDefaultHintsIntoCache, this is actually wrong, but people might depend on it by having
    // root-hints that refer to servers that aren't actually capable or willing to serve root data.
    g_recCache->replace(now, name, qtype, aset, {}, {}, true, g_rootdnsname, boost::none, boost::none, state, MemRecursorCache::Extra{from, false});
  }
}

static void parseHintFile(time_t now, const std::string& hintfile, set<DNSName>& seenA, set<DNSName>& seenAAAA, set<DNSName>& seenNS, std::multimap<DNSName, DNSRecord>& aRecords, std::multimap<DNSName, DNSRecord>& aaaaRecords, vector<DNSRecord>& nsvec)
{
  ZoneParserTNG zpt(hintfile);
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
  zpt.setMaxIncludes(::arg().asNum("max-include-depth"));
  DNSResourceRecord rrecord;

  while (zpt.get(rrecord)) {
    rrecord.ttl += now;
    switch (rrecord.qtype) {
    case QType::A:
      seenA.insert(rrecord.qname);
      aRecords.emplace(rrecord.qname, DNSRecord(rrecord));
      break;
    case QType::AAAA:
      seenAAAA.insert(rrecord.qname);
      aaaaRecords.emplace(rrecord.qname, DNSRecord(rrecord));
      break;
    case QType::NS:
      seenNS.emplace(rrecord.content);
      rrecord.content = toLower(rrecord.content);
      nsvec.emplace_back(rrecord);
      break;
    }
  }
}

static bool determineReachable(const set<DNSName>& names, const set<DNSName>& nameservers)
{
  bool reachable = false;
  for (auto const& record : names) {
    if (nameservers.count(record) != 0) {
      reachable = true;
      break;
    }
  }
  return reachable;
}

bool readHintsIntoCache(time_t now, const std::string& hintfile, std::vector<DNSRecord>& nsvec)
{
  const ComboAddress from("255.255.255.255");
  set<DNSName> seenNS;
  set<DNSName> seenA;
  set<DNSName> seenAAAA;

  std::multimap<DNSName, DNSRecord> aRecords;
  std::multimap<DNSName, DNSRecord> aaaaRecords;

  parseHintFile(now, hintfile, seenA, seenAAAA, seenNS, aRecords, aaaaRecords, nsvec);

  putIntoCache(now, QType::A, vState::Insecure, from, seenA, aRecords);
  putIntoCache(now, QType::AAAA, vState::Insecure, from, seenAAAA, aaaaRecords);

  bool reachableA = determineReachable(seenA, seenNS);
  bool reachableAAAA = determineReachable(seenAAAA, seenNS);

  auto log = g_slog->withName("config");
  if (SyncRes::s_doIPv4 && !SyncRes::s_doIPv6 && !reachableA) {
    log->info(Logr::Error, "Running IPv4 only but no IPv4 root hints");
    return false;
  }
  if (!SyncRes::s_doIPv4 && SyncRes::s_doIPv6 && !reachableAAAA) {
    log->info(Logr::Error, "Running IPv6 only but no IPv6 root hints");
    return false;
  }
  if (SyncRes::s_doIPv4 && SyncRes::s_doIPv6 && !reachableA && !reachableAAAA) {
    log->info(Logr::Error, "No valid root hints");
    return false;
  }
  return true;
}

void putDefaultHintsIntoCache(time_t now, std::vector<DNSRecord>& nsvec)
{
  const ComboAddress from("255.255.255.255");

  DNSRecord arr;
  DNSRecord aaaarr;
  DNSRecord nsrr;

  nsrr.d_name = g_rootdnsname;
  arr.d_type = QType::A;
  aaaarr.d_type = QType::AAAA;
  nsrr.d_type = QType::NS;
  // coverity[store_truncates_time_t]
  arr.d_ttl = aaaarr.d_ttl = nsrr.d_ttl = now + 3600000;

  string templ = "a.root-servers.net.";

  static_assert(rootIps4.size() == rootIps6.size());

  for (size_t letter = 0; letter < rootIps4.size(); ++letter) {
    templ.at(0) = static_cast<char>(letter + 'a');
    aaaarr.d_name = arr.d_name = DNSName(templ);
    nsrr.setContent(std::make_shared<NSRecordContent>(DNSName(templ)));
    nsvec.push_back(nsrr);

    if (!rootIps4.at(letter).empty()) {
      arr.setContent(std::make_shared<ARecordContent>(ComboAddress(rootIps4.at(letter))));
      /*
       * Originally the hint records were inserted with the auth flag set, with the consequence that
       * data from AUTHORITY and ADDITIONAL sections (as seen in a . NS response) were not used. This
       * (together with the long ttl) caused outdated hint to be kept in cache. So insert as non-auth,
       * and the extra sections in the . NS refreshing cause the cached records to be updated with
       * up-to-date information received from a real root server.
       *
       * Note that if a user query is done for one of the root-server.net names, it will be inserted
       * into the cache with the auth bit set. Further NS refreshes will not update that entry. If all
       * root names are queried at the same time by a user, all root-server.net names will be marked
       * auth and will expire at the same time. A re-prime is then triggered, as before, when the
       * records were inserted with the auth bit set and the TTD comes.
       */
      g_recCache->replace(now, DNSName(templ), QType::A, {arr}, {}, {}, false, g_rootdnsname, boost::none, boost::none, vState::Insecure, MemRecursorCache::Extra{from, false});
    }
    if (!rootIps6.at(letter).empty()) {
      aaaarr.setContent(std::make_shared<AAAARecordContent>(ComboAddress(rootIps6.at(letter))));
      g_recCache->replace(now, DNSName(templ), QType::AAAA, {aaaarr}, {}, {}, false, g_rootdnsname, boost::none, boost::none, vState::Insecure, MemRecursorCache::Extra{from, false});
    }
  }
}

template <typename T>
static SyncRes::AuthDomain makeSOAAndNSNodes(DNSRecord& dr, T content)
{
  dr.d_class = 1;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_ttl = 86400;
  dr.d_type = QType::SOA;
  dr.setContent(DNSRecordContent::make(QType::SOA, 1, "localhost. root 1 604800 86400 2419200 604800"));

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;
  ad.d_records.insert(dr);

  dr.d_type = QType::NS;
  dr.setContent(std::make_shared<NSRecordContent>(content));
  ad.d_records.insert(dr);

  return ad;
}

static void addToDomainMap(SyncRes::domainmap_t& newMap,
                           SyncRes::AuthDomain ad,
                           const DNSName& name,
                           Logr::log_t log,
                           const bool partial = false,
                           const bool reverse = false)
{
  if (newMap.count(name) != 0) {
    log->info(Logr::Warning, "Will not overwrite already loaded zone", "zone",
              Logging::Loggable(name));
  }
  else {
    if (!partial) {
      const auto direction = reverse ? std::string{"reverse"} : std::string{"forward"};
      log->info(Logr::Notice, "Inserting " + direction + " zone based on hosts file", "zone", Logging::Loggable(name));
    }
    ad.d_name = name;
    newMap[ad.d_name] = ad;
  }
}

static void makeNameToIPZone(SyncRes::domainmap_t& newMap,
                             const DNSName& hostname,
                             const ComboAddress& address)
{
  DNSRecord dr;
  dr.d_name = hostname;

  auto entry = newMap.find(hostname);
  if (entry == newMap.end()) {
    auto ad = makeSOAAndNSNodes(dr, "localhost.");
    ad.d_name = dr.d_name;
    entry = newMap.insert({dr.d_name, ad}).first;
  }

  auto recType = address.isIPv6() ? QType::AAAA : QType::A;
  dr.d_type = recType;
  dr.d_ttl = 86400;
  dr.setContent(DNSRecordContent::make(recType, QClass::IN, address.toStringNoInterface()));
  entry->second.d_records.insert(dr);
}

static void makeIPToNamesZone(SyncRes::domainmap_t& newMap,
                              const ComboAddress& address,
                              const std::string& canonicalHostname,
                              Logr::log_t log)
{
  DNSRecord dr;
  dr.d_name = DNSName(address.toStringReversed());
  dr.d_name.appendRawLabel(address.isIPv4() ? "in-addr" : "ip6");
  dr.d_name.appendRawLabel("arpa");

  SyncRes::AuthDomain ad = makeSOAAndNSNodes(dr, DNSName("localhost."));

  // Add a PTR entry for the primary name for reverse lookups.
  dr.d_type = QType::PTR;
  dr.setContent(DNSRecordContent::make(QType::PTR, 1, DNSName(canonicalHostname).toString()));
  ad.d_records.insert(dr);

  addToDomainMap(newMap, std::move(ad), dr.d_name, log, false, true);
}

void makePartialIPZone(SyncRes::domainmap_t& newMap,
                       std::initializer_list<const char*> labels,
                       Logr::log_t log)
{
  DNSRecord dr;
  for (auto label = std::rbegin(labels); label != std::rend(labels); ++label) {
    dr.d_name.appendRawLabel(*label);
  }
  dr.d_name.appendRawLabel("in-addr");
  dr.d_name.appendRawLabel("arpa");

  SyncRes::AuthDomain ad = makeSOAAndNSNodes(dr, DNSName("localhost."));

  addToDomainMap(newMap, std::move(ad), dr.d_name, log, true, true);
}

void makePartialIP6Zone(SyncRes::domainmap_t& newMap,
                        const std::string& name,
                        Logr::log_t log)
{
  DNSRecord dnsRecord;
  dnsRecord.d_name = DNSName(name);
  SyncRes::AuthDomain authDomain = makeSOAAndNSNodes(dnsRecord, DNSName("localhost."));

  addToDomainMap(newMap, std::move(authDomain), dnsRecord.d_name, log, true, true);
}

void addForwardAndReverseLookupEntries(SyncRes::domainmap_t& newMap,
                                       const std::string& searchSuffix,
                                       const std::vector<std::string>& parts,
                                       Logr::log_t log)
{
  const ComboAddress address{parts[0]};

  // Go over the hostname and aliases (parts[1], parts[2], etc...) and add entries
  // for forward lookups.
  for (auto name = parts.cbegin() + 1; name != parts.cend(); ++name) {
    if (searchSuffix.empty() || name->find('.') != string::npos) {
      makeNameToIPZone(newMap, DNSName(*name), address);
    }
    else {
      DNSName canonical = toCanonic(DNSName(searchSuffix), *name);
      if (canonical != DNSName(*name)) {
        makeNameToIPZone(newMap, canonical, address);
      }
    }
  }

  // Add entries for the primary name for reverse lookups.
  if (searchSuffix.empty() || parts[1].find('.') != string::npos) {
    makeIPToNamesZone(newMap, address, parts[1], log);
  }
  else {
    DNSName canonical = toCanonic(DNSName(searchSuffix), parts[1]);
    makeIPToNamesZone(newMap, address, canonical.toString(), log);
  }
}

bool parseEtcHostsLine(std::vector<std::string>& parts, std::string& line)
{
  const string::size_type pos = line.find('#');
  if (pos != string::npos) {
    line.resize(pos);
  }
  boost::trim(line);
  if (line.empty()) {
    return false;
  }
  parts.clear();
  stringtok(parts, line, "\t\r\n ");
  return parts.size() >= 2;
}
