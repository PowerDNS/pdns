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
#pragma once
#include "namespaces.hh"
#include "iputils.hh"
#include "dnsname.hh"

struct EDNSZoneVersion
{
  static const size_t EDNSZoneVersionOptSize = 1 + 1 + 4; // used for upper bound size calculation in dnspacket, assumes versions are 4 bytes

  uint8_t labelcount;
  uint8_t type;
  uint32_t version; // this assumes all versions fit in uint32_t. RFC9660 does not promise that.
};

bool getEDNSZoneVersionFromString(const string& options, EDNSZoneVersion& zoneversion);
bool getEDNSZoneVersionFromString(const char* options, unsigned int len, EDNSZoneVersion& zoneversion);
string makeEDNSZoneVersionString(const EDNSZoneVersion& zoneversion);
