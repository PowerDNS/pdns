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
#include "geoipbackend.hh"
#include "geoipinterface.hh"

unique_ptr<GeoIPInterface> GeoIPInterface::makeInterface(const string& dbStr) {
  /* parse dbStr */
  map<string, string> opts;
  vector<string> parts1, parts2;
  string driver;
  string filename;
  stringtok(parts1, dbStr, ":");

  if (parts1.size() == 1) {
    stringtok(parts2, parts1[0], ";");
    /* try extension */
    filename = parts2[0];
    size_t pos = filename.find_last_of(".");
    if (pos != string::npos)
      driver = filename.substr(pos+1);
    else
      driver = "unknown";
  } else {
    driver = parts1[0];
    stringtok(parts2, parts1[1], ";");
    filename = parts2[0];
  }

  if (parts2.size() > 1) {
     parts2.erase(parts2.begin(), parts2.begin()+1);
     for(const auto &opt: parts2) {
       vector<string> kv;
       stringtok(kv, opt, "=");
       opts[kv[0]] = kv[1];
     }
  }

  if (driver == "dat") {
     return makeDATInterface(filename, opts);
  } else if (driver == "mmdb") {
     return makeMMDBInterface(filename, opts);
  } else {
     throw PDNSException(string("Unsupported file type '") + driver + string("' (use type: prefix to force type)"));
  }
}
