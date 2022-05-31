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

static void makeNameToIPZone(const std::shared_ptr<SyncRes::domainmap_t>& newMap,
                             const DNSName& hostname,
                             const string& ip,
                             Logr::log_t log)
{
  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;

  DNSRecord dr;
  dr.d_name = hostname;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_ttl = 86400;
  dr.d_type = QType::SOA;
  dr.d_class = 1;
  dr.d_content = DNSRecordContent::mastermake(QType::SOA, 1, "localhost. root 1 604800 86400 2419200 604800");

  ad.d_records.insert(dr);

  dr.d_type = QType::NS;
  dr.d_content = std::make_shared<NSRecordContent>("localhost.");

  ad.d_records.insert(dr);

  dr.d_type = QType::A;
  dr.d_content = DNSRecordContent::mastermake(QType::A, 1, ip);
  ad.d_records.insert(dr);

  if (newMap->count(dr.d_name) != 0) {
    SLOG(g_log << Logger::Warning << "Hosts file will not overwrite zone '" << dr.d_name << "' already loaded" << endl,
         log->info(Logr::Warning, "Hosts file will not overwrite already loaded zone", "zone", Logging::Loggable(dr.d_name)));
  }
  else {
    SLOG(g_log << Logger::Warning << "Inserting forward zone '" << dr.d_name << "' based on hosts file" << endl,
         log->info(Logr::Notice, "Inserting forward zone based on hosts file", "zone", Logging::Loggable(dr.d_name)));
    ad.d_name = dr.d_name;
    (*newMap)[ad.d_name] = ad;
  }
}

//! parts[0] must be an IP address, the rest must be host names
void makeIPToNamesZone(const std::shared_ptr<SyncRes::domainmap_t>& newMap,
                       const vector<string>& parts,
                       Logr::log_t log)
{
  string address = parts[0];
  vector<string> ipParts;
  stringtok(ipParts, address, ".");

  SyncRes::AuthDomain ad;
  ad.d_rdForward = false;

  DNSRecord dr;
  for (auto part = ipParts.rbegin(); part != ipParts.rend(); ++part) {
    dr.d_name.appendRawLabel(*part);
  }
  dr.d_name.appendRawLabel("in-addr");
  dr.d_name.appendRawLabel("arpa");
  dr.d_class = 1;
  dr.d_place = DNSResourceRecord::ANSWER;
  dr.d_ttl = 86400;
  dr.d_type = QType::SOA;
  dr.d_content = DNSRecordContent::mastermake(QType::SOA, 1, "localhost. root 1 604800 86400 2419200 604800");

  ad.d_records.insert(dr);

  dr.d_type = QType::NS;
  dr.d_content = std::make_shared<NSRecordContent>(DNSName("localhost."));

  ad.d_records.insert(dr);
  dr.d_type = QType::PTR;

  if (ipParts.size() == 4) { // otherwise this is a partial zone
    for (unsigned int n = 1; n < parts.size(); ++n) {
      dr.d_content = DNSRecordContent::mastermake(QType::PTR, 1, DNSName(parts[n]).toString()); // XXX FIXME DNSNAME PAIN CAN THIS BE RIGHT?
      ad.d_records.insert(dr);
    }
  }

  if (newMap->count(dr.d_name) != 0) {
    SLOG(g_log << Logger::Warning << "Will not overwrite zone '" << dr.d_name << "' already loaded" << endl,
         log->info(Logr::Warning, "Will not overwrite already loaded zone", "zone", Logging::Loggable(dr.d_name)));
  }
  else {
    if (ipParts.size() == 4) {
      SLOG(g_log << Logger::Warning << "Inserting reverse zone '" << dr.d_name << "' based on hosts file" << endl,
           log->info(Logr::Notice, "Inserting reverse zone based on hosts file", "zone", Logging::Loggable(dr.d_name)));
    }
    ad.d_name = dr.d_name;
    (*newMap)[ad.d_name] = ad;
  }
}

void addForwardAndReverseLookupEntries(const std::shared_ptr<SyncRes::domainmap_t>& newMap,
                                       const std::string& searchSuffix,
                                       const std::vector<std::string>& parts,
                                       Logr::log_t log)
{
  for (unsigned int n = 1; n < parts.size(); ++n) {
    if (searchSuffix.empty() || parts[n].find('.') != string::npos) {
      makeNameToIPZone(newMap, DNSName(parts[n]), parts[0], log);
    }
    else {
      DNSName canonic = toCanonic(DNSName(searchSuffix), parts[n]); /// XXXX DNSName pain
      if (canonic != DNSName(parts[n])) { // XXX further DNSName pain
        makeNameToIPZone(newMap, canonic, parts[0], log);
      }
    }
  }
  makeIPToNamesZone(newMap, parts, log);
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
  if (parts[0].find(':') != string::npos) {
    return false;
  }
  return parts.size() >= 2;
}
