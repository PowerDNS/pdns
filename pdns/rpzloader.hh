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

std::shared_ptr<SOARecordContent> loadRPZFromFile(const std::string& fname, std::shared_ptr<DNSFilterEngine::Zone> zone, boost::optional<DNSFilterEngine::Policy> defpol, bool defpolOverrideLocal, uint32_t maxTTL);
void RPZIXFRTracker(const std::vector<ComboAddress>& masters, boost::optional<DNSFilterEngine::Policy> defpol, bool defpolOverrideLocal, uint32_t maxTTL, size_t zoneIdx, const TSIGTriplet& tt, size_t maxReceivedBytes, const ComboAddress& localAddress, const uint16_t axfrTimeout, shared_ptr<SOARecordContent> sr, std::string dumpZoneFileName, uint64_t configGeneration);

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
