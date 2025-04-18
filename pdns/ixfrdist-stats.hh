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

#include "dns.hh"
#include "dnsname.hh"
#include "pdnsexception.hh"

class ixfrdistStats {
  public:
    ixfrdistStats() {
      progStats.startTime = time(nullptr);
    }

    std::string getStats();

    void setSOASerial(const ZoneName& d, const uint32_t serial) {
      auto stat = getRegisteredDomain(d);
      stat->second.currentSOA = serial;
      stat->second.haveZone = true;
    }
    void incrementSOAChecks(const ZoneName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numSOAChecks += amount;
    }
    void incrementSOAChecksFailed(const ZoneName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numSOAChecksFailed += amount;
    }
    void incrementSOAinQueries(const ZoneName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numSOAinQueries += amount;
    }
    void incrementAXFRinQueries(const ZoneName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numAXFRinQueries += amount;
    }
    void incrementIXFRinQueries(const ZoneName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numIXFRinQueries += amount;
    }
    void incrementAXFRFailures(const ZoneName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numAXFRFailures += amount;
    }
    void incrementIXFRFailures(const ZoneName& d, const uint64_t amount = 1) {
      getRegisteredDomain(d)->second.numIXFRFailures += amount;
    }
    void registerDomain(const ZoneName& d) {
      domainStats[d].haveZone = false;
    }

    void incrementUnknownDomainInQueries(const ZoneName& /* d */)
    { // the name is ignored. It would be great to report it, but we don't want to blow up Prometheus
      progStats.unknownDomainInQueries += 1;
    }

    void incrementNotImplemented(uint8_t opcode)
    {
      notimpStats.at(opcode) ++;
    }

  private:
    class perDomainStat {
      public:
        bool                  haveZone;
        std::atomic<uint32_t> currentSOA{0}; // NOTE: this will wrongly be zero for unavailable zones

        std::atomic<uint32_t> numSOAChecks{0};
        std::atomic<uint32_t> numSOAChecksFailed{0};

        std::atomic<uint64_t> numSOAinQueries{0};
        std::atomic<uint64_t> numAXFRinQueries{0};
        std::atomic<uint64_t> numIXFRinQueries{0};

        std::atomic<uint64_t> numAXFRFailures{0};
        std::atomic<uint64_t> numIXFRFailures{0};
    };
    class programStats {
      public:
        time_t startTime;
        std::atomic<uint32_t> unknownDomainInQueries{0};
    };

    std::map<ZoneName, perDomainStat> domainStats;
    std::array<std::atomic<uint64_t>, 16> notimpStats{};
    programStats progStats;

    std::map<ZoneName, perDomainStat>::iterator getRegisteredDomain(const ZoneName& d) {
      auto ret = domainStats.find(d);
      if (ret == domainStats.end()) {
        throw PDNSException("Domain '" + d.toLogString() + "' not defined in the statistics map");
      }
      return ret;
    };
};

extern string doGetStats();
