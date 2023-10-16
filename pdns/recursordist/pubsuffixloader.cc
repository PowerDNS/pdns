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

#include <fstream>
#include <stdexcept>

#include "dnsname.hh"
#include "logger.hh"
#include "logging.hh"
#include "misc.hh"
#include "pubsuffix.hh"

extern const char* g_pubsuffix[];
std::vector<std::vector<std::string>> g_pubs;

void initPublicSuffixList(const std::string& file)
{
  std::vector<std::vector<std::string>> pbList;

  bool loaded = false;
  if (!file.empty()) {
    try {
      Regex reg("^[.0-9a-z-]*$");
      std::ifstream suffixFile(file);
      if (!suffixFile.is_open()) {
        throw std::runtime_error("Error opening the public suffix list file");
      }

      std::string line;
      while (std::getline(suffixFile, line)) {
        if (line.empty() || (line.rfind("//", 0) == 0)) {
          /* skip empty and commented lines */
          continue;
        }
        try {
          line = toLower(line);
          if (!reg.match(line)) {
            continue;
          }
          DNSName name(toLower(line));
          if (name.countLabels() < 2) {
            continue;
          }
          pbList.push_back(name.labelReverse().getRawLabels());
        }
        catch (...) {
          /* not a DNS name, ignoring */
        }
      }

      SLOG(g_log << Logger::Info << "Loaded the Public Suffix List from '" << file << "'" << endl,
           g_slog->withName("runtime")->info(Logr::Info, "Loaded the Public Suffix List", "file", Logging::Loggable(file)));
      loaded = true;
    }
    catch (const std::exception& e) {
      SLOG(g_log << Logger::Warning << "Error while loading the Public Suffix List from '" << file << "', falling back to the built-in list: " << e.what() << endl,
           g_slog->withName("runtime")->error(Logr::Error, e.what(), "Error while loading the Public Suffix List", "file", Logging::Loggable(file)));
    }
  }

  if (!loaded) {
    pbList.clear();

    for (const char** p = g_pubsuffix; *p; ++p) {
      string low = toLower(*p);

      vector<string> parts;
      stringtok(parts, low, ".");
      reverse(parts.begin(), parts.end());
      pbList.push_back(parts);
    }
  }

  sort(pbList.begin(), pbList.end());
  g_pubs = std::move(pbList);
}
