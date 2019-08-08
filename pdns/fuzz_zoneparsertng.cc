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

#include "dnsname.hh"
#include "dnsparser.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "zoneparser-tng.hh"

StatBag S;

static void init()
{
  reportAllTypes();
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static bool initialized = false;

  if (!initialized) {
    init();
    initialized = true;
  }

  try {
    std::vector<std::string> lines;
    std::string tmp(reinterpret_cast<const char*>(data), size);
    boost::split(lines, tmp, boost::is_any_of("\n"));

    ZoneParserTNG zpt(lines, g_rootdnsname);
    DNSResourceRecord drr;
    while (zpt.get(drr)) {
    }
  }
  catch(const std::exception& e) {
  }
  catch(const PDNSException& e) {
  }

  return 0;
}
