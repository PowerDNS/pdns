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
          DNSName name(toLower(line));
          pbList.push_back(name.labelReverse().getRawLabels());
        }
        catch(...) {
          /* not a DNS name, ignoring */
        }
      }

      g_log<<Logger::Info<<"Loaded the Public Suffix List from '"<<file<<"'"<<endl;
      loaded = true;
    }
    catch (const std::exception& e) {
      g_log<<Logger::Warning<<"Error while loading the Public Suffix List from '"<<file<<"', falling back to the built-in list: "<<e.what()<<endl;
    }
  }

  if (!loaded) {
    pbList.clear();

    for(const char** p = g_pubsuffix; *p; ++p) {
      string low=toLower(*p);

      vector<string> parts;
      stringtok(parts, low, ".");
      reverse(parts.begin(), parts.end());
      pbList.push_back(parts);
    }
  }

  sort(pbList.begin(), pbList.end());
  g_pubs = std::move(pbList);
}
