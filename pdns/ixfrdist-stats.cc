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

#include "ixfrdist-stats.hh"
#include "misc.hh"

std::string ixfrdistStats::getStats() {
  std::stringstream stats;
  const std::string prefix = "ixfrdist_";

  stats<<"# HELP "<<prefix<<"uptime_seconds The uptime of the process (in seconds)"<<std::endl;
  stats<<"# TYPE "<<prefix<<"uptime_seconds counter"<<std::endl;
  stats<<prefix<<"uptime_seconds "<<time(nullptr) - progStats.startTime<<std::endl;

  stats<<"# HELP "<<prefix<<"sys_msec Number of msec spent in system time"<<std::endl;
  stats<<"# TYPE "<<prefix<<"sys_msec counter"<<std::endl;
  stats<<prefix<<"sys_msec "<<getCPUTimeSystem("")<<std::endl;

  stats<<"# HELP "<<prefix<<"user_msec Number of msec spent in user time"<<std::endl;
  stats<<"# TYPE "<<prefix<<"user_msec counter"<<std::endl;
  stats<<prefix<<"user_msec "<<getCPUTimeUser("")<<std::endl;

  stats<<"# HELP "<<prefix<<"fd_usage Number of open file descriptors"<<std::endl;
  stats<<"# TYPE "<<prefix<<"fd_usage gauge"<<std::endl;
  stats<<prefix<<"fd_usage "<<getOpenFileDescriptors("")<<std::endl;

  stats<<"# HELP "<<prefix<<"real_memory_usage Actual unique use of memory in bytes (approx)"<<std::endl;
  stats<<"# TYPE "<<prefix<<"real_memory_usage gauge"<<std::endl;
  stats<<prefix<<"real_memory_usage "<<getRealMemoryUsage("")<<std::endl;

  stats<<"# HELP "<<prefix<<"domains The amount of configured domains"<<std::endl;
  stats<<"# TYPE "<<prefix<<"domains gauge"<<std::endl;
  stats<<prefix<<"domains "<<domainStats.size()<<std::endl;

  if (!domainStats.empty()) {
    stats<<"# HELP "<<prefix<<"soa_serial The SOA serial number of a domain"<<std::endl;
    stats<<"# TYPE "<<prefix<<"soa_serial gauge"<<std::endl;
    stats << "# HELP " << prefix << "soa_checks_total Number of times a SOA check at the primary was attempted" << std::endl;
    stats<<"# TYPE "<<prefix<<"soa_checks_total counter"<<std::endl;
    stats << "# HELP " << prefix << "soa_checks_failed_total Number of times a SOA check at the primary failed" << std::endl;
    stats<<"# TYPE "<<prefix<<"soa_checks_failed_total counter"<<std::endl;
    stats<<"# HELP "<<prefix<<"soa_inqueries_total Number of times a SOA query was received"<<std::endl;
    stats<<"# TYPE "<<prefix<<"soa_inqueries_total counter"<<std::endl;
    stats<<"# HELP "<<prefix<<"axfr_inqueries_total Number of times an AXFR query was received"<<std::endl;
    stats<<"# TYPE "<<prefix<<"axfr_inqueries_total counter"<<std::endl;
    stats<<"# HELP "<<prefix<<"axfr_failures_total Number of times an AXFR query was not properly answered"<<std::endl;
    stats<<"# TYPE "<<prefix<<"axfr_failures_total counter"<<std::endl;
    stats<<"# HELP "<<prefix<<"ixfr_inqueries_total Number of times an IXFR query was received"<<std::endl;
    stats<<"# TYPE "<<prefix<<"ixfr_inqueries_total counter"<<std::endl;
    stats<<"# HELP "<<prefix<<"ixfr_failures_total Number of times an IXFR query was not properly answered"<<std::endl;
    stats<<"# TYPE "<<prefix<<"ixfr_failures_total counter"<<std::endl;
  }

  for (auto const &d : domainStats) {
    if(d.second.haveZone)
      stats<<prefix<<"soa_serial{domain=\""<<d.first<<"\"} "<<d.second.currentSOA<<std::endl;
    else
      stats<<prefix<<"soa_serial{domain=\""<<d.first<<"\"} NaN"<<std::endl;

    stats<<prefix<<"soa_checks_total{domain=\""<<d.first<<"\"} "<<d.second.numSOAChecks<<std::endl;
    stats<<prefix<<"soa_checks_failed_total{domain=\""<<d.first<<"\"} "<<d.second.numSOAChecksFailed<<std::endl;
    stats<<prefix<<"soa_inqueries_total{domain=\""<<d.first<<"\"} "<<d.second.numSOAinQueries<<std::endl;
    stats<<prefix<<"axfr_inqueries_total{domain=\""<<d.first<<"\"} "<<d.second.numAXFRinQueries<<std::endl;
    stats<<prefix<<"axfr_failures_total{domain=\""<<d.first<<"\"} "<<d.second.numAXFRFailures<<std::endl;
    stats<<prefix<<"ixfr_inqueries_total{domain=\""<<d.first<<"\"} "<<d.second.numIXFRinQueries<<std::endl;
    stats<<prefix<<"ixfr_failures_total{domain=\""<<d.first<<"\"} "<<d.second.numIXFRFailures<<std::endl;
  }

  if (!notimpStats.empty()) {
    stats<<"# HELP "<<prefix<<"notimp An unimplemented opcode"<<std::endl;
    stats<<"# TYPE "<<prefix<<"notimp counter"<<std::endl;
  }

  for (std::size_t i = 0; i < notimpStats.size() ; i++) {
    auto val = notimpStats.at(i).load();

    if (val > 0) {
      stats<<prefix<<"notimp{opcode=\""<<Opcode::to_s(i)<<"\"} "<<val<<std::endl;
    }
  }

  stats<<"# HELP "<<prefix<<"unknown_domain_inqueries_total Number of queries received for domains unknown to us"<<std::endl;
  stats<<"# TYPE "<<prefix<<"unknown_domain_inqueries_total counter"<<std::endl;
  stats<<prefix<<"unknown_domain_inqueries_total "<<progStats.unknownDomainInQueries<<std::endl;

  return stats.str();
}
