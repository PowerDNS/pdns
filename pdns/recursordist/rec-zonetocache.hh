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
#include "dns.hh"
#include "iputils.hh"

class RecZoneToCache
{
public:
  struct Config
  {
    std::string d_zone; // Zone name
    std::string d_method; // axfr, http, https, file
    vector<std::string> d_sources; // IPs or URLs
    ComboAddress d_local; // local address
    TSIGTriplet d_tt; // Authentication data
    size_t d_maxReceivedBytes{0}; // Maximum size
    time_t d_retryOnError{60}; // Retry on error
    time_t d_refreshPeriod{0}; // Take from SOA by default
    uint32_t d_timeout{20}; // timeout in seconds
  };
  static void ZoneToCache(Config config, uint64_t gen);
};
