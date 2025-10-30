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
#include "logging.hh"
#include "misc.hh"
#include "pubsuffix.hh"

std::vector<std::vector<std::string>> g_pubs;

static bool initPublicSuffixList(const std::string& file, std::istream& stream, std::vector<std::vector<std::string>>& pbList)
{

  try {
    Regex reg("^[.0-9a-z-]*$");

    std::string line;
    while (std::getline(stream, line)) {
      if (line.empty() || (line.rfind("//", 0) == 0)) {
        /* skip empty and commented lines */
        continue;
      }
      try {
        line = toLower(line);
        if (!reg.match(line)) {
          continue;
        }
        DNSName name(line);
        if (name.countLabels() < 2) {
          continue;
        }
        pbList.emplace_back(name.labelReverse().getRawLabels());
      }
      catch (...) {
        /* not a DNS name, ignoring */
        continue;
      }
    }

    if (file != "internal") {
      g_slog->withName("runtime")->info(Logr::Info, "Loaded the Public Suffix List", "file", Logging::Loggable(file));
    }
    return true;
  }
  catch (const std::exception& e) {
    g_slog->withName("runtime")->error(Logr::Error, e.what(), "Error while loading the Public Suffix List", "file", Logging::Loggable(file));
  }
  return false;
}

void initPublicSuffixList(const std::string& file)
{
  bool loaded = false;
  std::vector<std::vector<std::string>> pbList;

  if (!file.empty()) {
    try {
      std::ifstream suffixFile(file);
      if (!suffixFile.is_open()) {
        throw std::runtime_error("Error opening the public suffix list file");
      }
      loaded = initPublicSuffixList(file, suffixFile, pbList);
    }
    catch (const std::exception& e) {
      g_slog->withName("runtime")->error(Logr::Error, e.what(), "Error while loading the Public Suffix List", "file", Logging::Loggable(file));
    }
  }

  if (!loaded) {
    pbList.clear();
    std::istringstream stream(g_pubsuffix);
    initPublicSuffixList("internal", stream, pbList);
  }
  std::sort(pbList.begin(), pbList.end());
  g_pubs = std::move(pbList);
}
