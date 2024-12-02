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
#include "ednszoneversion.hh"
#include "dns.hh"

namespace
{
struct EDNSZoneVersionWire
{
  uint8_t labelcount;
  uint8_t type;
  char version[256]; // FIXME they can be bigger
} GCCPACKATTRIBUTE; // BRRRRR

}

bool getEDNSZoneVersionFromString(const string& options, EDNSZoneVersion& zoneversion)
{
  // cerr<<"options.size:"<<options.size()<<endl;
  return getEDNSZoneVersionFromString(options.c_str(), options.length(), zoneversion);
}

bool getEDNSZoneVersionFromString(const char* options, unsigned int len, EDNSZoneVersion& zoneversion)
{
  EDNSZoneVersionWire zoneversionw{};
  // static_assert(sizeof(zoneversionw) == 4, "sizeof(EDNSSubnetOptsWire) must be 4 bytes");
  if (len > sizeof(zoneversionw)) {
    return false; // FIXME this silently breaks on >256 bytes of version
  }
  if (len < (1 + 1 + 4)) {
    return false; // does not contain labelcount + type + uint32_t version
  }
  memcpy(&zoneversionw, options, len);
  zoneversion.labelcount = zoneversionw.labelcount;
  zoneversion.type = zoneversionw.type;

  memcpy(&zoneversion.version, zoneversionw.version, sizeof(zoneversion.version));
  zoneversion.version = ntohl(zoneversion.version);

  return true;
}

string makeEDNSZoneVersionString(const EDNSZoneVersion& zoneversion)
{
  string ret;
  EDNSZoneVersionWire zoneversionw{};
  zoneversionw.labelcount = zoneversion.labelcount;
  zoneversionw.type = zoneversion.type;

  uint32_t version = htonl(zoneversion.version);
  memcpy(&zoneversionw.version, &version, sizeof(zoneversion.version));

  ret.assign((const char*)&zoneversionw, 1 + 1 + 4);

  return ret;
}
