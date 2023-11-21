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

#include <cinttypes>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "lock.hh"
#include "stat_t.hh"

namespace dnsdist::metrics
{
using Error = std::string;

[[nodiscard]] std::optional<Error> declareCustomMetric(const std::string& name, const std::string& type, const std::string& description, std::optional<std::string> customName);
[[nodiscard]] std::variant<uint64_t, Error> incrementCustomCounter(const std::string_view& name, uint64_t step);
[[nodiscard]] std::variant<uint64_t, Error> decrementCustomCounter(const std::string_view& name, uint64_t step);
[[nodiscard]] std::variant<double, Error> setCustomGauge(const std::string_view& name, const double value);
[[nodiscard]] std::variant<double, Error> getCustomMetric(const std::string_view& name);

using pdns::stat_t;

struct Stats
{
  Stats();

  stat_t responses{0};
  stat_t servfailResponses{0};
  stat_t queries{0};
  stat_t frontendNXDomain{0};
  stat_t frontendServFail{0};
  stat_t frontendNoError{0};
  stat_t nonCompliantQueries{0};
  stat_t nonCompliantResponses{0};
  stat_t rdQueries{0};
  stat_t emptyQueries{0};
  stat_t aclDrops{0};
  stat_t dynBlocked{0};
  stat_t ruleDrop{0};
  stat_t ruleNXDomain{0};
  stat_t ruleRefused{0};
  stat_t ruleServFail{0};
  stat_t ruleTruncated{0};
  stat_t selfAnswered{0};
  stat_t downstreamTimeouts{0};
  stat_t downstreamSendErrors{0};
  stat_t truncFail{0};
  stat_t noPolicy{0};
  stat_t cacheHits{0};
  stat_t cacheMisses{0};
  stat_t latency0_1{0}, latency1_10{0}, latency10_50{0}, latency50_100{0}, latency100_1000{0}, latencySlow{0}, latencySum{0}, latencyCount{0};
  stat_t securityStatus{0};
  stat_t dohQueryPipeFull{0};
  stat_t dohResponsePipeFull{0};
  stat_t doqResponsePipeFull{0};
  stat_t doh3ResponsePipeFull{0};
  stat_t outgoingDoHQueryPipeFull{0};
  stat_t proxyProtocolInvalid{0};
  stat_t tcpQueryPipeFull{0};
  stat_t tcpCrossProtocolQueryPipeFull{0};
  stat_t tcpCrossProtocolResponsePipeFull{0};
  double latencyAvg100{0}, latencyAvg1000{0}, latencyAvg10000{0}, latencyAvg1000000{0};
  double latencyTCPAvg100{0}, latencyTCPAvg1000{0}, latencyTCPAvg10000{0}, latencyTCPAvg1000000{0};
  double latencyDoTAvg100{0}, latencyDoTAvg1000{0}, latencyDoTAvg10000{0}, latencyDoTAvg1000000{0};
  double latencyDoHAvg100{0}, latencyDoHAvg1000{0}, latencyDoHAvg10000{0}, latencyDoHAvg1000000{0};
  double latencyDoQAvg100{0}, latencyDoQAvg1000{0}, latencyDoQAvg10000{0}, latencyDoQAvg1000000{0};
  double latencyDoH3Avg100{0}, latencyDoH3Avg1000{0}, latencyDoH3Avg10000{0}, latencyDoH3Avg1000000{0};
  using statfunction_t = std::function<uint64_t(const std::string&)>;
  using entry_t = std::variant<stat_t*, pdns::stat_t_trait<double>*, double*, statfunction_t>;
  struct EntryPair
  {
    std::string d_name;
    entry_t d_value;
  };

  SharedLockGuarded<std::vector<EntryPair>> entries;
};

extern struct Stats g_stats;
}
