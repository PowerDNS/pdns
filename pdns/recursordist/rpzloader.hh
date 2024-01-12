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
#include "filterpo.hh"
#include <string>
#include "dnsrecords.hh"

extern bool g_logRPZChanges;

// Please make sure that the struct below only contains value types since they are used as parameters in a thread ct
struct RPZTrackerParams
{
  std::vector<ComboAddress> primaries;
  boost::optional<DNSFilterEngine::Policy> defpol;
  bool defpolOverrideLocal;
  uint32_t maxTTL;
  size_t zoneIdx;
  TSIGTriplet tsigtriplet;
  size_t maxReceivedBytes;
  ComboAddress localAddress;
  uint16_t xfrTimeout;
  uint32_t refreshFromConf;
  std::shared_ptr<const SOARecordContent> soaRecordContent;
  std::string dumpZoneFileName;
};

std::shared_ptr<const SOARecordContent> loadRPZFromFile(const std::string& fname, std::shared_ptr<DNSFilterEngine::Zone> zone, const boost::optional<DNSFilterEngine::Policy>& defpol, bool defpolOverrideLocal, uint32_t maxTTL);
void RPZIXFRTracker(RPZTrackerParams params, uint64_t configGeneration);
bool notifyRPZTracker(const DNSName& name);

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
