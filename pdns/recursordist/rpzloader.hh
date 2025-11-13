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
#include "rec-xfr.hh"
#include "filterpo.hh"
#include <string>
#include "dnsrecords.hh"

extern bool g_logRPZChanges;

// Please make sure that the struct below only contains value types since they are used as parameters in a thread ct
struct RPZTrackerParams
{
  ZoneXFRParams zoneXFRParams;
  std::optional<DNSFilterEngine::Policy> defpol;
  std::string defcontent;
  bool defpolOverrideLocal{true};
  uint32_t maxTTL = std::numeric_limits<uint32_t>::max();
  std::string seedFileName;
  std::string dumpZoneFileName;
  std::string polName;
  std::set<std::string> tags;
  uint32_t extendedErrorCode{std::numeric_limits<uint32_t>::max()};
  std::string extendedErrorExtra;
  bool includeSOA{false};
  bool ignoreDuplicates{false};
};

std::shared_ptr<const SOARecordContent> loadRPZFromFile(const std::string& fname, const std::shared_ptr<DNSFilterEngine::Zone>& zone, const std::optional<DNSFilterEngine::Policy>& defpol, bool defpolOverrideLocal, uint32_t maxTTL);
void RPZIXFRTracker(RPZTrackerParams params, uint64_t configGeneration);

struct rpzStats
{
  std::atomic<uint64_t> d_failedTransfers;
  std::atomic<uint64_t> d_successfulTransfers;
  std::atomic<uint64_t> d_fullTransfers;
  std::atomic<uint64_t> d_numberOfRecords;
  std::atomic<time_t> d_lastUpdate;
  std::atomic<uint32_t> d_serial;
};

Netmask makeNetmaskFromRPZ(const DNSName& name);
shared_ptr<rpzStats> getRPZZoneStats(const std::string& zone);
