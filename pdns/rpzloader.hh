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

void loadRPZFromFile(const std::string& fname, std::shared_ptr<DNSFilterEngine::Zone> zone, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL);
std::shared_ptr<SOARecordContent> loadRPZFromServer(const ComboAddress& master, const DNSName& zoneName, std::shared_ptr<DNSFilterEngine::Zone> zone, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL, const TSIGTriplet& tt, size_t maxReceivedBytes, const ComboAddress& localAddress);
void RPZRecordToPolicy(const DNSRecord& dr, std::shared_ptr<DNSFilterEngine::Zone> zone, bool addOrRemove, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL);
void RPZIXFRTracker(const ComboAddress& master, const DNSName& zoneName, boost::optional<DNSFilterEngine::Policy> defpol, uint32_t maxTTL, size_t polZone, const TSIGTriplet &tt, shared_ptr<SOARecordContent> oursr, size_t maxReceivedBytes, const ComboAddress& localAddress);
