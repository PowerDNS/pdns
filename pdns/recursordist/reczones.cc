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

#include "reczones-helpers.hh"
#include "arguments.hh"
#include "dnsrecords.hh"
#include "logger.hh"
#include "syncres.hh"
#include "zoneparser-tng.hh"

extern int g_argc;
extern char** g_argv;

bool primeHints(time_t now)
{
  const string hintfile = ::arg()["hint-file"];
  vector<DNSRecord> nsvec;
  bool ret = true;

  if (hintfile == "no") {
    auto log = g_slog->withName("config");
    SLOG(g_log << Logger::Debug << "Priming root disabled by hint-file=no" << endl,
         log->info(Logr::Debug, "Priming root disabled by hint-file=no"));
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

static void convertServersForAD(const std::string& zone, const std::string& input, SyncRes::AuthDomain& ad, const char* sepa, Logr::log_t log, bool verbose = true)
{
  vector<string> servers;
  stringtok(servers, input, sepa);
  ad.d_servers.clear();

  vector<string> addresses;
  for (auto server = servers.begin(); server != servers.end(); ++server) {
    ComboAddress addr = parseIPAndPort(*server, 53);
    ad.d_servers.push_back(addr);
    if (verbose) {
      addresses.push_back(addr.toStringWithPort());
    }
  }
  if (verbose) {
    if (!g_slogStructured) {
      g_log << Logger::Info << "Redirecting queries for zone '" << zone << "' ";
      if (ad.d_rdForward) {
        g_log << "with recursion ";
      }
      g_log << "to: ";
      bool first = true;
      for (const auto& a : addresses) {
        if (!first) {
          g_log << ", ";
        }
        else {
          first = false;
        }
        g_log << a;
      }
      g_log << endl;
    }
    else {
      log->info(Logr::Info, "Redirecting queries", "zone", Logging::Loggable(zone), "recursion", Logging::Loggable(ad.d_rdForward), "addresses", Logging::IterLoggable(addresses.begin(), addresses.end()));
    }
  }
}

static void* pleaseUseNewSDomainsMap(std::shared_ptr<SyncRes::domainmap_t> newmap)
{
  SyncRes::setDomainMap(newmap);
  return 0;
}

string reloadZoneConfiguration()
{
  std::shared_ptr<SyncRes::domainmap_t> original = SyncRes::getDomainMap();
  auto log = g_slog->withName("config");

  try {
    SLOG(g_log << Logger::Warning << "Reloading zones, purging data from cache" << endl,
         log->info(Logr::Notice, "Reloading zones, purging data from cache"));

    string configname = ::arg()["config-dir"] + "/recursor.conf";
    if (::arg()["config-name"] != "") {
      configname = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"] + ".conf";
    }
    cleanSlashes(configname);

    if (!::arg().preParseFile(configname.c_str(), "forward-zones"))
      throw runtime_error("Unable to re-parse configuration file '" + configname + "'");
    ::arg().preParseFile(configname.c_str(), "forward-zones-file");
    ::arg().preParseFile(configname.c_str(), "forward-zones-recurse");
    ::arg().preParseFile(configname.c_str(), "auth-zones");
    ::arg().preParseFile(configname.c_str(), "allow-notify-for");
    ::arg().preParseFile(configname.c_str(), "allow-notify-for-file");
    ::arg().preParseFile(configname.c_str(), "export-etc-hosts", "off");
    ::arg().preParseFile(configname.c_str(), "serve-rfc1918");
    ::arg().preParseFile(configname.c_str(), "include-dir");
    ::arg().preParse(g_argc, g_argv, "include-dir");

    // then process includes
    std::vector<std::string> extraConfigs;
    ::arg().gatherIncludes(extraConfigs);

    for (const std::string& fn : extraConfigs) {
      if (!::arg().preParseFile(fn.c_str(), "forward-zones", ::arg()["forward-zones"]))
        throw runtime_error("Unable to re-parse configuration file include '" + fn + "'");
      ::arg().preParseFile(fn.c_str(), "forward-zones-file", ::arg()["forward-zones-file"]);
      ::arg().preParseFile(fn.c_str(), "forward-zones-recurse", ::arg()["forward-zones-recurse"]);
      ::arg().preParseFile(fn.c_str(), "auth-zones", ::arg()["auth-zones"]);
      ::arg().preParseFile(fn.c_str(), "allow-notify-for", ::arg()["allow-notify-for"]);
      ::arg().preParseFile(fn.c_str(), "allow-notify-for-file", ::arg()["allow-notify-for-file"]);
      ::arg().preParseFile(fn.c_str(), "export-etc-hosts", ::arg()["export-etc-hosts"]);
      ::arg().preParseFile(fn.c_str(), "serve-rfc1918", ::arg()["serve-rfc1918"]);
    }

    ::arg().preParse(g_argc, g_argv, "forward-zones");
    ::arg().preParse(g_argc, g_argv, "forward-zones-file");
    ::arg().preParse(g_argc, g_argv, "forward-zones-recurse");
    ::arg().preParse(g_argc, g_argv, "auth-zones");
    ::arg().preParse(g_argc, g_argv, "allow-notify-for");
    ::arg().preParse(g_argc, g_argv, "allow-notify-for-file");
    ::arg().preParse(g_argc, g_argv, "export-etc-hosts");
    ::arg().preParse(g_argc, g_argv, "serve-rfc1918");

    auto [newDomainMap, newNotifySet] = parseZoneConfiguration();

    // purge both original and new names
    std::set<DNSName> oldAndNewDomains;
    for (const auto& i : *newDomainMap) {
      oldAndNewDomains.insert(i.first);
    }

    if (original) {
      for (const auto& i : *original) {
        oldAndNewDomains.insert(i.first);
      }
    }

    // these explicitly-named captures should not be necessary, as lambda
    // capture of tuple-like structured bindings is permitted, but some
    // compilers still don't allow it
    broadcastFunction([dm = newDomainMap] { return pleaseUseNewSDomainsMap(dm); });
    broadcastFunction([ns = newNotifySet] { return pleaseSupplantAllowNotifyFor(ns); });

    // Wipe the caches *after* the new auth domain info has been set
    // up, as a query during setting up might fill the caches
    // again. Old code did the clear before, exposing a race.
    for (const auto& i : oldAndNewDomains) {
      wipeCaches(i, true, 0xffff);
    }
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

std::tuple<std::shared_ptr<SyncRes::domainmap_t>, std::shared_ptr<notifyset_t>> parseZoneConfiguration()
{
  auto log = g_slog->withName("config");

  TXTRecordContent::report();
  OPTRecordContent::report();

  auto newMap = std::make_shared<SyncRes::domainmap_t>();
  auto newSet = std::make_shared<notifyset_t>();

  typedef vector<string> parts_t;
  parts_t parts;
  const char* option_names[3] = {"auth-zones", "forward-zones", "forward-zones-recurse"};
  for (int n = 0; n < 3; ++n) {
    parts.clear();
    stringtok(parts, ::arg()[option_names[n]], " ,\t\n\r");
    for (parts_t::const_iterator iter = parts.begin(); iter != parts.end(); ++iter) {
      SyncRes::AuthDomain ad;
      if ((*iter).find('=') == string::npos)
        throw PDNSException("Error parsing '" + *iter + "', missing =");
      pair<string, string> headers = splitField(*iter, '=');
      boost::trim(headers.first);
      boost::trim(headers.second);
      // headers.first=toCanonic("", headers.first);
      if (n == 0) {
        ad.d_rdForward = false;
        SLOG(g_log << Logger::Notice << "Parsing authoritative data for zone '" << headers.first << "' from file '" << headers.second << "'" << endl,
             log->info(Logr::Notice, "Parsing authoritative data from file", "zone", Logging::Loggable(headers.first), "file", Logging::Loggable(headers.second)));
        ZoneParserTNG zpt(headers.second, DNSName(headers.first));
        zpt.setMaxGenerateSteps(::arg().asNum("max-generate-steps"));
        zpt.setMaxIncludes(::arg().asNum("max-include-depth"));
        DNSResourceRecord rr;
        DNSRecord dr;
        while (zpt.get(rr)) {
          try {
            dr = DNSRecord(rr);
            dr.d_place = DNSResourceRecord::ANSWER;
          }
          catch (std::exception& e) {
            throw PDNSException("Error parsing record '" + rr.qname.toLogString() + "' of type " + rr.qtype.toString() + " in zone '" + headers.first + "' from file '" + headers.second + "': " + e.what());
          }
          catch (...) {
            throw PDNSException("Error parsing record '" + rr.qname.toLogString() + "' of type " + rr.qtype.toString() + " in zone '" + headers.first + "' from file '" + headers.second + "'");
          }

          ad.d_records.insert(dr);
        }
      }
      else {
        ad.d_rdForward = (n == 2);
        convertServersForAD(headers.first, headers.second, ad, ";", log);
      }

      ad.d_name = DNSName(headers.first);
      (*newMap)[ad.d_name] = ad;
    }
  }

  if (!::arg()["forward-zones-file"].empty()) {
    SLOG(g_log << Logger::Warning << "Reading zone forwarding information from '" << ::arg()["forward-zones-file"] << "'" << endl,
         log->info(Logr::Notice, "Reading zone forwarding information", "file", Logging::Loggable(::arg()["forward-zones-file"])));
    auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fopen(::arg()["forward-zones-file"].c_str(), "r"), fclose);
    if (!fp) {
      throw PDNSException("Error opening forward-zones-file '" + ::arg()["forward-zones-file"] + "': " + stringerror());
    }

    string line;
    int linenum = 0;
    uint64_t before = newMap->size();
    while (linenum++, stringfgets(fp.get(), line)) {
      SyncRes::AuthDomain ad;
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
        throw PDNSException("Error parsing line " + std::to_string(linenum) + " of " + ::arg()["forward-zones-file"]);
      }

      bool allowNotifyFor = false;

      for (; !domain.empty(); domain.erase(0, 1)) {
        switch (domain[0]) {
        case '+':
          ad.d_rdForward = true;
          continue;
        case '^':
          allowNotifyFor = true;
          continue;
        }
        break;
      }

      if (domain.empty()) {
        throw PDNSException("Error parsing line " + std::to_string(linenum) + " of " + ::arg()["forward-zones-file"]);
      }

      try {
        convertServersForAD(domain, instructions, ad, ",; ", log, false);
      }
      catch (...) {
        throw PDNSException("Conversion error parsing line " + std::to_string(linenum) + " of " + ::arg()["forward-zones-file"]);
      }

      ad.d_name = DNSName(domain);
      (*newMap)[ad.d_name] = ad;
      if (allowNotifyFor) {
        newSet->insert(ad.d_name);
      }
    }
    SLOG(g_log << Logger::Warning << "Done parsing " << newMap->size() - before
               << " forwarding instructions from file '"
               << ::arg()["forward-zones-file"] << "'" << endl,
         log->info(Logr::Notice, "Done parsing forwarding instructions from file", "file",
                   Logging::Loggable(::arg()["forward-zones-file"]), "count",
                   Logging::Loggable(newMap->size() - before)));
  }

  if (::arg().mustDo("export-etc-hosts")) {
    string fname = ::arg()["etc-hosts-file"];
    ifstream ifs(fname.c_str());
    if (!ifs) {
      SLOG(g_log << Logger::Warning << "Could not open " << fname << " for reading" << endl,
           log->error(Logr::Warning, "Could not open file for reading", "file", Logging::Loggable(fname)));
    }
    else {
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
  }

  if (::arg().mustDo("serve-rfc1918")) {
    SLOG(g_log << Logger::Warning << "Inserting rfc 1918 private space zones" << endl,
         log->info(Logr::Notice, "Inserting rfc 1918 private space zones"));

    makePartialIPZone(*newMap, {"127"}, log);
    makePartialIPZone(*newMap, {"10"}, log);
    makePartialIPZone(*newMap, {"192", "168"}, log);

    for (int n = 16; n < 32; n++) {
      makePartialIPZone(*newMap, {"172", std::to_string(n).c_str()}, log);
    }
  }

  parts.clear();
  stringtok(parts, ::arg()["allow-notify-for"], " ,\t\n\r");
  for (auto& part : parts) {
    newSet->insert(DNSName(part));
  }

  if (auto anff = ::arg()["allow-notify-for-file"]; !anff.empty()) {
    SLOG(g_log << Logger::Warning << "Reading NOTIFY-allowed zones from '" << anff << "'" << endl,
         log->info(Logr::Notice, "Reading NOTIFY-allowed zones from file", "file", Logging::Loggable(anff)));
    auto fp = std::unique_ptr<FILE, int (*)(FILE*)>(fopen(anff.c_str(), "r"), fclose);
    if (!fp) {
      throw PDNSException("Error opening allow-notify-for-file '" + anff + "': " + stringerror());
    }

    string line;
    uint64_t before = newSet->size();
    while (stringfgets(fp.get(), line)) {
      boost::trim(line);
      if (line[0] == '#') // Comment line, skip to the next line
        continue;
      newSet->insert(DNSName(line));
    }
    SLOG(g_log << Logger::Warning << "Done parsing " << newSet->size() - before << " NOTIFY-allowed zones from file '" << anff << "'" << endl,
         log->info(Logr::Notice, "Done parsing NOTIFY-allowed zones from file", "file", Logging::Loggable(anff), "count", Logging::Loggable(newSet->size() - before)));
  }

  return {newMap, newSet};
}
