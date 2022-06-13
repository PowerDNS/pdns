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

#include "syncres.hh"
#include "reczones-helpers.hh"

template <typename T>
static SyncRes::AuthDomain makeSOAAndNSNodes(DNSRecord& dr, T content)
{
  dr.d_class = 1;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_ttl = 86400;
  dr.d_type = QType::SOA;
  dr.d_content = DNSRecordContent::mastermake(QType::SOA, 1, "localhost. root 1 604800 86400 2419200 604800");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;
  ad.d_records.insert(dr);

  dr.d_type = QType::NS;
  dr.d_content = std::make_shared<NSRecordContent>(content);
  ad.d_records.insert(dr);

  return ad;
}

static void addToDomainMap(SyncRes::domainmap_t& newMap,
                           SyncRes::AuthDomain ad,
                           DNSName& name,
                           Logr::log_t log,
                           const bool partial = false,
                           const bool reverse = false)
{
  if (newMap.count(name) != 0) {
    SLOG(g_log << Logger::Warning << "Will not overwrite zone '" << name << "' already loaded" << endl,
         log->info(Logr::Warning, "Will not overwrite already loaded zone", "zone",
                   Logging::Loggable(name)));
  }
  else {
    if (!partial) {
      const auto direction = reverse ? std::string{"reverse"} : std::string{"forward"};
      SLOG(g_log << Logger::Warning << "Inserting " << direction << " zone '" << name << "' based on hosts file" << endl,
           log->info(Logr::Notice, "Inserting " + direction + " zone based on hosts file", "zone", Logging::Loggable(name)));
    }
    ad.d_name = name;
    newMap[ad.d_name] = ad;
  }
}

static void makeNameToIPZone(SyncRes::domainmap_t& newMap,
                             const DNSName& hostname,
                             const ComboAddress& address,
                             Logr::log_t log)
{
  DNSRecord dr;
  dr.d_name = hostname;

  SyncRes::AuthDomain ad = makeSOAAndNSNodes(dr, "localhost.");

  auto recType = address.isIPv6() ? QType::AAAA : QType::A;
  dr.d_type = recType;
  dr.d_content = DNSRecordContent::mastermake(recType, 1, address.toStringNoInterface());
  ad.d_records.insert(dr);

  addToDomainMap(newMap, ad, dr.d_name, log);
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
  dr.d_content = DNSRecordContent::mastermake(QType::PTR, 1, DNSName(canonicalHostname).toString());
  ad.d_records.insert(dr);

  addToDomainMap(newMap, ad, dr.d_name, log, false, true);
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

  addToDomainMap(newMap, ad, dr.d_name, log, true, true);
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
      makeNameToIPZone(newMap, DNSName(*name), address, log);
    }
    else {
      DNSName canonical = toCanonic(DNSName(searchSuffix), *name);
      if (canonical != DNSName(*name)) {
        makeNameToIPZone(newMap, canonical, address, log);
      }
    }
  }

  // Add entries for the primary name for reverse lookups.
  makeIPToNamesZone(newMap, address, parts[1], log);
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
