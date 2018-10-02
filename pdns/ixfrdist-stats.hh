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

class ixfrdistStats {
  public:
    ixfrdistStats() {
      progStats.startTime = time(nullptr);
    }

    std::string getStats() {
      std::stringstream stats;
      const std::string prefix = "ixfrdist_";

      stats<<"# TYPE "<<prefix<<"uptime_seconds gauge"<<std::endl;
      stats<<prefix<<"uptime_seconds "<<time(nullptr) - progStats.startTime<<std::endl;
      stats<<"# TYPE "<<prefix<<"domains gauge"<<std::endl;
      stats<<prefix<<"domains "<<domainStats.size()<<std::endl;

      uint64_t numSOAChecks{0}, numSOAChecksFailed{0}, numSOAinQueries{0}, numIXFRinQueries{0}, numAXFRinQueries{0}, numAXFRFailures{0}, numIXFRFailures{0};
      for (auto const &d : domainStats) {
        if(d.second.haveZone)
          stats<<prefix<<"soa_serial{domain="<<d.first<<"} "<<d.second.currentSOA<<std::endl;
        else
          stats<<prefix<<"soa_serial{domain="<<d.first<<"} NaN"<<std::endl;

        stats<<prefix<<"soa_checks{domain="<<d.first<<"} "<<d.second.numSOAChecks<<std::endl;
        numSOAChecks += d.second.numSOAChecks;

        stats<<prefix<<"soa_checks_failed{domain="<<d.first<<"} "<<d.second.numSOAChecksFailed<<std::endl;
        numSOAChecksFailed += d.second.numSOAChecksFailed;

        stats<<prefix<<"soa_inqueries{domain="<<d.first<<"} "<<d.second.numSOAinQueries<<std::endl;
        numSOAinQueries += d.second.numSOAinQueries;

        stats<<prefix<<"axfr_inqueries{domain="<<d.first<<"} "<<d.second.numAXFRinQueries<<std::endl;
        numAXFRinQueries += d.second.numAXFRinQueries;

        stats<<prefix<<"ixfr_inqueries{domain="<<d.first<<"} "<<d.second.numIXFRinQueries<<std::endl;
        numIXFRinQueries += d.second.numIXFRinQueries;

        stats<<prefix<<"axfr_failures{domain="<<d.first<<"} "<<d.second.numAXFRFailures<<std::endl;
        numAXFRFailures += d.second.numAXFRFailures;

        stats<<prefix<<"ixfr_failures{domain="<<d.first<<"} "<<d.second.numIXFRFailures<<std::endl;
        numIXFRFailures += d.second.numIXFRFailures;
      }

      stats<<prefix<<"soa_checks "<<numSOAChecks<<std::endl;
      stats<<prefix<<"soa_checks_failed "<<numSOAChecksFailed<<std::endl;
      stats<<prefix<<"soa_inqueries "<<numSOAinQueries<<std::endl;
      stats<<prefix<<"axfr_inqueries "<<numAXFRinQueries<<std::endl;
      stats<<prefix<<"ixfr_inqueries "<<numIXFRinQueries<<std::endl;
      stats<<prefix<<"axfr_failures "<<numAXFRFailures<<std::endl;
      stats<<prefix<<"ixfr_failures "<<numIXFRFailures<<std::endl;
      return stats.str();
    }

    void setSOASerial(const DNSName& d, const uint32_t serial) {
      domainStats[d].currentSOA = serial;
      domainStats[d].haveZone = true;
    }
    void incrementSOAChecks(const DNSName& d, const uint64_t amount = 1) {
      domainStats[d].numSOAChecks += amount;
    }
    void incrementSOAChecksFailed(const DNSName& d, const uint64_t amount = 1) {
      domainStats[d].numSOAChecksFailed += amount;
    }
    void incrementSOAinQueries(const DNSName& d, const uint64_t amount = 1) {
      domainStats[d].numSOAinQueries += amount;
    }
    void incrementAXFRinQueries(const DNSName& d, const uint64_t amount = 1) {
      domainStats[d].numAXFRinQueries += amount;
    }
    void incrementIXFRinQueries(const DNSName& d, const uint64_t amount = 1) {
      domainStats[d].numIXFRinQueries += amount;
    }
    void incrementAXFRFailures(const DNSName& d, const uint64_t amount = 1) {
      domainStats[d].numAXFRFailures += amount;
    }
    void incrementIXFRFailures(const DNSName& d, const uint64_t amount = 1) {
      domainStats[d].numIXFRFailures += amount;
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
};
