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
#include <atomic>
#include <map>
#include <string>

#include "dnsname.hh"
#include "pdnsexception.hh"

class ixfrdistStats {
  public:
    ixfrdistStats() {
      progStats.startTime = time(nullptr);
    }

    std::string getStats();

    void setSOASerial(const DNSName& d, const uint32_t serial) {
      auto stat = getRegisteredDomain(d);
      stat->second.currentSOA = serial;
      stat->second.haveZone = true;
    }
    void incrementSOAChecks(const DNSName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numSOAChecks += amount;
    }
    void incrementSOAChecksFailed(const DNSName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numSOAChecksFailed += amount;
    }
    void incrementSOAinQueries(const DNSName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numSOAinQueries += amount;
    }
    void incrementAXFRinQueries(const DNSName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numAXFRinQueries += amount;
    }
    void incrementIXFRinQueries(const DNSName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numIXFRinQueries += amount;
    }
    void incrementAXFRFailures(const DNSName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numAXFRFailures += amount;
    }
    void incrementIXFRFailures(const DNSName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numIXFRFailures += amount;
    }
    void registerDomain(const DNSName& d) {
      domainStats[d].haveZone = false;
    }
  private:
    class perDomainStat {
      public:
        bool                  haveZone;
        std::atomic<uint32_t> currentSOA; // NOTE: this will wrongly be zero for unavailable zones

        std::atomic<uint32_t> numSOAChecks;
        std::atomic<uint32_t> numSOAChecksFailed;

        std::atomic<uint64_t> numSOAinQueries;
        std::atomic<uint64_t> numAXFRinQueries;
        std::atomic<uint64_t> numIXFRinQueries;

        std::atomic<uint64_t> numAXFRFailures;
        std::atomic<uint64_t> numIXFRFailures;
    };
    class programStats {
      public:
        time_t startTime;
    };

    std::map<DNSName, perDomainStat> domainStats;
    programStats progStats;

    std::map<DNSName, perDomainStat>::iterator getRegisteredDomain(const DNSName& d) {
      auto ret = domainStats.find(d);
      if (ret == domainStats.end()) {
        throw PDNSException("Domain '" + d.toLogString() + "' not defined in the statistics map");
      }
      return ret;
    };
};
