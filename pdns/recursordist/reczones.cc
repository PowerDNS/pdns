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

#include <sys/stat.h>

#include "reczones-helpers.hh"
#include "arguments.hh"
#include "dnsrecords.hh"
#include "logger.hh"
#include "syncres.hh"
#include "zoneparser-tng.hh"
#include "rec-rust-lib/cxxsettings.hh"
#include "rec-system-resolve.hh"
#include "rec-main.hh"

bool primeHints(time_t now)
{
  const string hintfile = ::arg()["hint-file"];
  vector<DNSRecord> nsvec;
  bool ret = true;

  if (hintfile == "no" || hintfile == "no-refresh") {
    auto log = g_slog->withName("config");
    SLOG(g_log << Logger::Debug << "Priming root disabled by hint-file setting" << endl,
         log->info(Logr::Debug, "Priming root disabled by hint-file setting"));
    return ret;
  }

  if (hintfile.empty()) {
    putDefaultHintsIntoCache(now, nsvec);
  }
  else {
    ret = readHintsIntoCache(now, hintfile, nsvec);
  }

  g_recCache->doWipeCache(g_rootdnsname, false, QType::NS);
  g_recCache->replace(now, g_rootdnsname, QType::NS, nsvec, {}, {}, false, g_rootdnsname, boost::none, boost::none, vState::Insecure, ComboAddress("255.255.255.255")); // and stuff in the cache
  return ret;
}

static void convertServersForAD(const std::string& zone, const std::string& input, SyncRes::AuthDomain& authDomain, const char* sepa, Logr::log_t log, bool verbose = true)
{
  vector<string> servers;
  stringtok(servers, input, sepa);
  authDomain.d_servers.clear();

  vector<string> addresses;
  for (auto& server : servers) {
    ComboAddress addr = pdns::fromNameOrIP(server, 53, log);
    authDomain.d_servers.push_back(addr);
    if (verbose) {
      addresses.push_back(addr.toStringWithPort());
    }
  }
  if (verbose) {
    if (!g_slogStructured) {
      g_log << Logger::Info << "Redirecting queries for zone '" << zone << "' ";
      if (authDomain.d_rdForward) {
        g_log << "with recursion ";
      }
      g_log << "to: ";
      bool first = true;
      for (const auto& address : addresses) {
        if (!first) {
          g_log << ", ";
        }
        else {
          first = false;
        }
        g_log << address;
      }
      g_log << endl;
    }
    else {
      log->info(Logr::Info, "Redirecting queries", "zone", Logging::Loggable(zone), "recursion", Logging::Loggable(authDomain.d_rdForward), "addresses", Logging::IterLoggable(addresses.begin(), addresses.end()));
    }
  }
}

static void* pleaseUseNewSDomainsMap(std::shared_ptr<SyncRes::domainmap_t> newmap)
{
  SyncRes::setDomainMap(std::move(newmap));
  return nullptr;
}

string reloadZoneConfiguration(bool yaml)
{
  auto log = g_slog->withName("config");

  string configname = ::arg()["config-dir"] + "/recursor";
  if (!::arg()["config-name"].empty()) {
    configname = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"];
  }
  cleanSlashes(configname);

  try {
    SLOG(g_log << Logger::Warning << "Reloading zones, purging data from cache" << endl,
         log->info(Logr::Notice, "Reloading zones, purging data from cache"));

    if (yaml) {
      configname += g_yamlSettingsSuffix;
      string msg;
      pdns::rust::settings::rec::Recursorsettings settings;
      // XXX Does ::arg()["include-dir"] have the right value, i.e. potentially overriden by command line?
      auto yamlstatus = pdns::settings::rec::readYamlSettings(configname, ::arg()["include-dir"], settings, msg, log);

      switch (yamlstatus) {
      case pdns::settings::rec::YamlSettingsStatus::CannotOpen:
        throw runtime_error("Unable to open '" + configname + "': " + msg);
        break;
      case pdns::settings::rec::YamlSettingsStatus::PresentButFailed:
        throw runtime_error("Error processing '" + configname + "': " + msg);
        break;
      case pdns::settings::rec::YamlSettingsStatus::OK:
        // Does *not* set include-dir
        pdns::settings::rec::setArgsForZoneRelatedSettings(settings);
        break;
      }
    }
    else {
      configname += ".conf";

      if (!::arg().preParseFile(configname, "forward-zones")) {
        throw runtime_error("Unable to re-parse configuration file '" + configname + "'");
      }
      ::arg().preParseFile(configname, "forward-zones-file");
      ::arg().preParseFile(configname, "forward-zones-recurse");
      ::arg().preParseFile(configname, "auth-zones");
      ::arg().preParseFile(configname, "allow-notify-for");
      ::arg().preParseFile(configname, "allow-notify-for-file");
      ::arg().preParseFile(configname, "export-etc-hosts", "off");
      ::arg().preParseFile(configname, "serve-rfc1918");
      ::arg().preParseFile(configname, "serve-rfc6303");
      ::arg().preParseFile(configname, "include-dir");
      ::arg().preParse(g_argc, g_argv, "include-dir");

      // then process includes
      std::vector<std::string> extraConfigs;
      ::arg().gatherIncludes(::arg()["include-dir"], ".conf", extraConfigs);

      for (const std::string& filename : extraConfigs) {
        if (!::arg().preParseFile(filename, "forward-zones", ::arg()["forward-zones"])) {
          throw runtime_error("Unable to re-parse configuration file include '" + filename + "'");
        }
        ::arg().preParseFile(filename, "forward-zones-file", ::arg()["forward-zones-file"]);
        ::arg().preParseFile(filename, "forward-zones-recurse", ::arg()["forward-zones-recurse"]);
        ::arg().preParseFile(filename, "auth-zones", ::arg()["auth-zones"]);
        ::arg().preParseFile(filename, "allow-notify-for", ::arg()["allow-notify-for"]);
        ::arg().preParseFile(filename, "allow-notify-for-file", ::arg()["allow-notify-for-file"]);
        ::arg().preParseFile(filename, "export-etc-hosts", ::arg()["export-etc-hosts"]);
        ::arg().preParseFile(filename, "serve-rfc1918", ::arg()["serve-rfc1918"]);
        ::arg().preParseFile(filename, "serve-rfc6303", ::arg()["serve-rfc6303"]);
      }
    }
    // Process command line args potentially overriding what we read from config files
    ::arg().preParse(g_argc, g_argv, "forward-zones");
    ::arg().preParse(g_argc, g_argv, "forward-zones-file");
    ::arg().preParse(g_argc, g_argv, "forward-zones-recurse");
    ::arg().preParse(g_argc, g_argv, "auth-zones");
    ::arg().preParse(g_argc, g_argv, "allow-notify-for");
    ::arg().preParse(g_argc, g_argv, "allow-notify-for-file");
    ::arg().preParse(g_argc, g_argv, "export-etc-hosts");
    ::arg().preParse(g_argc, g_argv, "serve-rfc1918");
    ::arg().preParse(g_argc, g_argv, "serve-rfc6303");

    auto [newDomainMap, newNotifySet] = parseZoneConfiguration(yaml);

    // purge both original and new names
    std::set<DNSName> oldAndNewDomains;
    for (const auto& entry : *newDomainMap) {
      oldAndNewDomains.insert(entry.first);
    }

    {
      auto lock = g_initialDomainMap.lock();
      if (*lock) {
        for (const auto& entry : **lock) {
          oldAndNewDomains.insert(entry.first);
        }
      }
    }

    // these explicitly-named captures should not be necessary, as lambda
    // capture of tuple-like structured bindings is permitted, but some
    // compilers still don't allow it
    broadcastFunction([dmap = newDomainMap] { return pleaseUseNewSDomainsMap(dmap); });
    broadcastFunction([nsset = newNotifySet] { return pleaseSupplantAllowNotifyFor(nsset); });

    // Wipe the caches *after* the new auth domain info has been set
    // up, as a query during setting up might fill the caches
    // again. Old code did the clear before, exposing a race.
    for (const auto& entry : oldAndNewDomains) {
      wipeCaches(entry, true, 0xffff);
    }
    *g_initialDomainMap.lock() = std::move(newDomainMap);
    *g_initialAllowNotifyFor.lock() = std::move(newNotifySet);
    return "ok\n";
  }
  catch (const std::exception& e) {
    SLOG(g_log << Logger::Error << "Encountered error reloading zones, keeping original data: " << e.what() << endl,
         log->error(Logr::Error, e.what(), "Encountered error reloading zones, keeping original data"));
  }
  catch (const PDNSException& ae) {
    SLOG(g_log << Logger::Error << "Encountered error reloading zones, keeping original data: " << ae.reason << endl,
         log->error(Logr::Error, ae.reason, "Encountered error reloading zones, keeping original data"));
  }
  catch (...) {
    SLOG(g_log << Logger::Error << "Encountered unknown error reloading zones, keeping original data" << endl,
         log->error(Logr::Error, "Exception", "Encountered error reloading zones, keeping original data"));
  }
  return "reloading failed, see log\n";
}

static void readAuthZoneData(SyncRes::AuthDomain& authDomain, const pair<string, string>& headers, Logr::log_t log)
{
  SLOG(g_log << Logger::Notice << "Parsing authoritative data for zone '" << headers.first << "' from file '" << headers.second << "'" << endl,
       log->info(Logr::Notice, "Parsing authoritative data from file", "zone", Logging::Loggable(headers.first), "file", Logging::Loggable(headers.second)));
  ZoneParserTNG zpt(headers.second, DNSName(headers.first));
  zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
  zpt.setMaxIncludes(::arg().asNum("max-include-depth"));
  DNSResourceRecord resourceRecord;
  DNSRecord dnsrecord;
  while (zpt.get(resourceRecord)) {
    try {
      dnsrecord = DNSRecord(resourceRecord);
      dnsrecord.d_place = DNSResourceRecord::ANSWER;
    }
    catch (std::exception& e) {
      throw PDNSException("Error parsing record '" + resourceRecord.qname.toLogString() + "' of type " + resourceRecord.qtype.toString() + " in zone '" + headers.first + "' from file '" + headers.second + "': " + e.what());
    }
    catch (...) {
      throw PDNSException("Error parsing record '" + resourceRecord.qname.toLogString() + "' of type " + resourceRecord.qtype.toString() + " in zone '" + headers.first + "' from file '" + headers.second + "'");
    }

    authDomain.d_records.insert(dnsrecord);
  }
}

static void processForwardZones(shared_ptr<SyncRes::domainmap_t>& newMap, Logr::log_t log)
{
  const std::array<string, 3> option_names = {"auth-zones", "forward-zones", "forward-zones-recurse"};

  for (size_t option = 0; option < option_names.size(); ++option) {
    vector<string> parts;
    stringtok(parts, ::arg()[option_names.at(option)], " ,\t\n\r");
    for (const auto& part : parts) {
      SyncRes::AuthDomain authDomain;
      if (part.find('=') == string::npos) {
        throw PDNSException("Error parsing '" + part + "', missing =");
      }
      pair<string, string> headers = splitField(part, '=');
      boost::trim(headers.first);
      boost::trim(headers.second);

      if (option == 0) {
        authDomain.d_rdForward = false;
        readAuthZoneData(authDomain, headers, log);
      }
      else {
        authDomain.d_rdForward = (option == 2);
        convertServersForAD(headers.first, headers.second, authDomain, ";", log);
      }

      authDomain.d_name = DNSName(headers.first);
      (*newMap)[authDomain.d_name] = authDomain;
    }
  }
}

static void processApiZonesFile(const string& file, shared_ptr<SyncRes::domainmap_t>& newMap, shared_ptr<notifyset_t>& newSet, Logr::log_t log)
{
  if (::arg()["api-config-dir"].empty()) {
    return;
  }
  const auto filename = ::arg()["api-config-dir"] + "/" + file;
  struct stat statStruct{};
  // It's a TOCTU, but a harmless one
  if (stat(filename.c_str(), &statStruct) != 0) {
    return;
  }

  SLOG(g_log << Logger::Notice << "Processing ApiZones YAML settings from " << filename << endl,
       log->info(Logr::Notice, "Processing ApiZones YAML settings", "path", Logging::Loggable(filename)));

  const uint64_t before = newMap->size();

  std::unique_ptr<pdns::rust::settings::rec::ApiZones> zones = pdns::rust::settings::rec::api_read_zones(filename);
  zones->validate("apizones");

  for (const auto& forward : zones->forward_zones) {
    SyncRes::AuthDomain authDomain;
    authDomain.d_name = DNSName(string(forward.zone));
    authDomain.d_rdForward = forward.recurse;
    for (const auto& forwarder : forward.forwarders) {
      ComboAddress addr = pdns::fromNameOrIP(string(forwarder), 53, log);
      authDomain.d_servers.emplace_back(addr);
    }
    (*newMap)[authDomain.d_name] = authDomain;
    if (forward.notify_allowed) {
      newSet->insert(authDomain.d_name);
    }
  }
  for (const auto& auth : zones->auth_zones) {
    SyncRes::AuthDomain authDomain;
    authDomain.d_name = DNSName(string(auth.zone));
    readAuthZoneData(authDomain, {string(auth.zone), string(auth.file)}, log);
    (*newMap)[authDomain.d_name] = authDomain;
  }
  SLOG(g_log << Logger::Warning << "Done parsing " << newMap->size() - before
             << " ApiZones YAML settings from file '"
             << filename << "'" << endl,
       log->info(Logr::Notice, "Done parsing ApiZones YAML from file", "file",
                 Logging::Loggable(filename), "count",
                 Logging::Loggable(newMap->size() - before)));
}

static void processForwardZonesFile(shared_ptr<SyncRes::domainmap_t>& newMap, shared_ptr<notifyset_t>& newSet, Logr::log_t log)
{
  const auto& filename = ::arg()["forward-zones-file"];
  if (filename.empty()) {
    return;
  }
  const uint64_t before = newMap->size();

  if (boost::ends_with(filename, ".yml")) {
    ::rust::Vec<pdns::rust::settings::rec::ForwardZone> vec;
    pdns::settings::rec::readYamlForwardZonesFile(filename, vec, log);
    for (const auto& forward : vec) {
      SyncRes::AuthDomain authDomain;
      authDomain.d_name = DNSName(string(forward.zone));
      authDomain.d_rdForward = forward.recurse;
      for (const auto& forwarder : forward.forwarders) {
        ComboAddress addr = pdns::fromNameOrIP(string(forwarder), 53, log);
        authDomain.d_servers.emplace_back(addr);
      }
      (*newMap)[authDomain.d_name] = authDomain;
      if (forward.notify_allowed) {
        newSet->insert(authDomain.d_name);
      }
    }
  }
  else {
    SLOG(g_log << Logger::Warning << "Reading zone forwarding information from '" << filename << "'" << endl,
         log->info(Logr::Notice, "Reading zone forwarding information", "file", Logging::Loggable(filename)));
    auto filePtr = pdns::UniqueFilePtr(fopen(filename.c_str(), "r"));
    if (!filePtr) {
      int err = errno;
      throw PDNSException("Error opening forward-zones-file '" + filename + "': " + stringerror(err));
    }

    string line;
    int linenum = 0;
    while (linenum++, stringfgets(filePtr.get(), line)) {
      SyncRes::AuthDomain authDomain;
      boost::trim(line);
      if (line[0] == '#') { // Comment line, skip to the next line
        continue;
      }
      string domain;
      string instructions;
      std::tie(domain, instructions) = splitField(line, '=');
      instructions = splitField(instructions, '#').first; // Remove EOL comments
      boost::trim(domain);
      boost::trim(instructions);
      if (domain.empty()) {
        if (instructions.empty()) { // empty line
          continue;
        }
        throw PDNSException("Error parsing line " + std::to_string(linenum) + " of " + filename);
      }

      bool allowNotifyFor = false;

      for (; !domain.empty(); domain.erase(0, 1)) {
        switch (domain[0]) {
        case '+':
          authDomain.d_rdForward = true;
          continue;
        case '^':
          allowNotifyFor = true;
          continue;
        }
        break;
      }

      if (domain.empty()) {
        throw PDNSException("Error parsing line " + std::to_string(linenum) + " of " + filename);
      }

      try {
        convertServersForAD(domain, instructions, authDomain, ",; ", log, false);
      }
      catch (...) {
        throw PDNSException("Conversion error parsing line " + std::to_string(linenum) + " of " + filename);
      }

      authDomain.d_name = DNSName(domain);
      (*newMap)[authDomain.d_name] = authDomain;
      if (allowNotifyFor) {
        newSet->insert(authDomain.d_name);
      }
    }
  }
  SLOG(g_log << Logger::Warning << "Done parsing " << newMap->size() - before
             << " forwarding instructions from file '"
             << filename << "'" << endl,
       log->info(Logr::Notice, "Done parsing forwarding instructions from file", "file",
                 Logging::Loggable(filename), "count",
                 Logging::Loggable(newMap->size() - before)));
}

static void processExportEtcHosts(std::shared_ptr<SyncRes::domainmap_t>& newMap, Logr::log_t log)
{
  if (!::arg().mustDo("export-etc-hosts")) {
    return;
  }
  string fname = ::arg()["etc-hosts-file"];
  ifstream ifs(fname);
  if (!ifs) {
    SLOG(g_log << Logger::Warning << "Could not open " << fname << " for reading" << endl,
         log->error(Logr::Warning, "Could not open file for reading", "file", Logging::Loggable(fname)));
    return;
  }
  vector<string> parts;
  std::string line{};
  while (getline(ifs, line)) {
    if (!parseEtcHostsLine(parts, line)) {
      continue;
    }

    try {
      string searchSuffix = ::arg()["export-etc-hosts-search-suffix"];
      addForwardAndReverseLookupEntries(*newMap, searchSuffix, parts, log);
    }
    catch (const PDNSException& ex) {
      SLOG(g_log << Logger::Warning
                 << "The line `" << line << "` "
                 << "in the provided etc-hosts file `" << fname << "` "
                 << "could not be added: " << ex.reason << ". Going to skip it."
                 << endl,
           log->info(Logr::Notice, "Skipping line in etc-hosts file",
                     "line", Logging::Loggable(line),
                     "hosts-file", Logging::Loggable(fname),
                     "reason", Logging::Loggable(ex.reason)));
    }
  }
}

static void processServeRFC1918(std::shared_ptr<SyncRes::domainmap_t>& newMap, Logr::log_t log)
{
  if (!::arg().mustDo("serve-rfc1918")) {
    return;
  }
  SLOG(g_log << Logger::Warning << "Inserting rfc 1918 private space zones" << endl,
       log->info(Logr::Notice, "Inserting rfc 1918 private space zones"));

  makePartialIPZone(*newMap, {"127"}, log);
  makePartialIPZone(*newMap, {"10"}, log);
  makePartialIPZone(*newMap, {"192", "168"}, log);

  for (int count = 16; count < 32; count++) {
    makePartialIPZone(*newMap, {"172", std::to_string(count).c_str()}, log);
  }
}

static void processServeRFC6303(std::shared_ptr<SyncRes::domainmap_t>& newMap, Logr::log_t log)
{
  if (!::arg().mustDo("serve-rfc6303")) {
    return;
  }
  if (!::arg().mustDo("serve-rfc1918")) {
    return;
  }
  SLOG(g_log << Logger::Warning << "Inserting rfc 6303 private space zones" << endl,
       log->info(Logr::Notice, "Inserting rfc 6303 private space zones"));
  // Section 4.2
  makePartialIPZone(*newMap, {"0"}, log);
  // makePartialIPZone(*newMap, { "127" }, log) already done in processServeRFC1918
  makePartialIPZone(*newMap, {"169", "254"}, log);
  makePartialIPZone(*newMap, {"192", "0", "2"}, log);
  makePartialIPZone(*newMap, {"198", "51", "100"}, log);
  makePartialIPZone(*newMap, {"203", "0", "113"}, log);
  makePartialIPZone(*newMap, {"255", "255", "255", "255"}, log); // actually produces NODATA instead of the RFC's NXDOMAIN

  // Note v6 names are not reversed
  // Section 4.3
  // makePartialIP6Zone(*newMap, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", log) already handled by SyncRes::doSpecialNamesResolve, in accordance with section 4.2
  makePartialIP6Zone(*newMap, "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", log); // actually produces NODATA instead of the RFC's NXDOMAIN
  // Section 4.4
  makePartialIP6Zone(*newMap, "d.f.ip6.arpa", log);
  // Section 4.5
  makePartialIP6Zone(*newMap, "8.e.f.ip6.arpa", log);
  makePartialIP6Zone(*newMap, "9.e.f.ip6.arpa", log);
  makePartialIP6Zone(*newMap, "a.e.f.ip6.arpa", log);
  makePartialIP6Zone(*newMap, "b.e.f.ip6.arpa", log);
  // Section 4.6
  makePartialIP6Zone(*newMap, "8.b.d.0.1.0.0.2.ip6.arpa", log);
}

static void processAllowNotifyFor(shared_ptr<notifyset_t>& newSet)
{
  vector<string> parts;
  stringtok(parts, ::arg()["allow-notify-for"], " ,\t\n\r");
  for (auto& part : parts) {
    newSet->insert(DNSName(part));
  }
}

static void processAllowNotifyForFile(shared_ptr<notifyset_t>& newSet, Logr::log_t log)
{
  const auto& filename = ::arg()["allow-notify-for-file"];
  if (filename.empty()) {
    return;
  }
  const uint64_t before = newSet->size();
  if (boost::ends_with(filename, ".yml")) {
    ::rust::Vec<::rust::String> vec;
    pdns::settings::rec::readYamlAllowNotifyForFile(filename, vec, log);
    for (const auto& name : vec) {
      newSet->insert(DNSName(string(name)));
    }
  }
  else {
    SLOG(g_log << Logger::Warning << "Reading NOTIFY-allowed zones from '" << filename << "'" << endl,
         log->info(Logr::Notice, "Reading NOTIFY-allowed zones from file", "file", Logging::Loggable(filename)));
    auto filePtr = pdns::UniqueFilePtr(fopen(filename.c_str(), "r"));
    if (!filePtr) {
      throw PDNSException("Error opening allow-notify-for-file '" + filename + "': " + stringerror());
    }

    string line;
    while (stringfgets(filePtr.get(), line)) {
      boost::trim(line);
      if (line[0] == '#') { // Comment line, skip to the next line
        continue;
      }
      newSet->insert(DNSName(line));
    }
  }
  SLOG(g_log << Logger::Warning << "Done parsing " << newSet->size() - before << " NOTIFY-allowed zones from file '" << filename << "'" << endl,
       log->info(Logr::Notice, "Done parsing NOTIFY-allowed zones from file", "file", Logging::Loggable(filename), "count", Logging::Loggable(newSet->size() - before)));
}

std::tuple<std::shared_ptr<SyncRes::domainmap_t>, std::shared_ptr<notifyset_t>> parseZoneConfiguration(bool yaml)
{
  auto log = g_slog->withName("config");

  auto newMap = std::make_shared<SyncRes::domainmap_t>();
  auto newSet = std::make_shared<notifyset_t>();

  processForwardZones(newMap, log);
  processForwardZonesFile(newMap, newSet, log);
  if (yaml) {
    auto lci = g_luaconfs.getLocal();
    processApiZonesFile("apizones", newMap, newSet, log);
    for (const auto& catz : lci->catalogzones) {
      processApiZonesFile("catzone." + catz.d_catz->getName().toString(), newMap, newSet, log);
    }
  }
  processExportEtcHosts(newMap, log);
  processServeRFC1918(newMap, log);
  processServeRFC6303(newMap, log);
  processAllowNotifyFor(newSet);
  processAllowNotifyForFile(newSet, log);

  return {newMap, newSet};
}
