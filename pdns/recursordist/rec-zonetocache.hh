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
#include "zonemd.hh"

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
    time_t d_refreshPeriod{static_cast<time_t>(24 * 3600)}; // Time between refetch
    uint32_t d_timeout{20}; // timeout in seconds
    pdns::ZoneMD::Config d_zonemd{pdns::ZoneMD::Config::Validate};
    pdns::ZoneMD::Config d_dnssec{pdns::ZoneMD::Config::Validate};
  };

  struct State
  {
    time_t d_lastrun{0};
    time_t d_waittime{0};
    uint64_t d_generation{0};
  };

  static void maintainStates(const map<DNSName, Config>&, map<DNSName, State>&, uint64_t mygeneration);
  static void ZoneToCache(const Config& config, State& state);
};
