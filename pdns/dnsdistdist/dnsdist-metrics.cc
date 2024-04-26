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
#include <regex>

#include "dnsdist-metrics.hh"
#include "dnsdist.hh"
#include "dnsdist-web.hh"

namespace dnsdist::metrics
{

struct MutableCounter
{
  MutableCounter() = default;
  MutableCounter(const MutableCounter&) = delete;
  MutableCounter(MutableCounter&& rhs) noexcept :
    d_value(rhs.d_value.load())
  {
  }
  MutableCounter& operator=(const MutableCounter&) = delete;
  MutableCounter& operator=(MutableCounter&& rhs) noexcept
  {
    d_value = rhs.d_value.load();
    return *this;
  }
  ~MutableCounter() = default;

  mutable stat_t d_value{0};
};

struct MutableGauge
{
  MutableGauge() = default;
  MutableGauge(const MutableGauge&) = delete;
  MutableGauge(MutableGauge&& rhs) noexcept :
    d_value(rhs.d_value.load())
  {
  }
  MutableGauge& operator=(const MutableGauge&) = delete;
  MutableGauge& operator=(MutableGauge&& rhs) noexcept
  {
    d_value = rhs.d_value.load();
    return *this;
  }
  ~MutableGauge() = default;

  mutable pdns::stat_t_trait<double> d_value{0};
};

static SharedLockGuarded<std::map<std::string, MutableCounter, std::less<>>> s_customCounters;
static SharedLockGuarded<std::map<std::string, MutableGauge, std::less<>>> s_customGauges;

Stats::Stats() :
  entries{std::vector<EntryPair>{
    {"responses", &responses},
    {"servfail-responses", &servfailResponses},
    {"queries", &queries},
    {"frontend-nxdomain", &frontendNXDomain},
    {"frontend-servfail", &frontendServFail},
    {"frontend-noerror", &frontendNoError},
    {"acl-drops", &aclDrops},
    {"rule-drop", &ruleDrop},
    {"rule-nxdomain", &ruleNXDomain},
    {"rule-refused", &ruleRefused},
    {"rule-servfail", &ruleServFail},
    {"rule-truncated", &ruleTruncated},
    {"self-answered", &selfAnswered},
    {"downstream-timeouts", &downstreamTimeouts},
    {"downstream-send-errors", &downstreamSendErrors},
    {"trunc-failures", &truncFail},
    {"no-policy", &noPolicy},
    {"latency0-1", &latency0_1},
    {"latency1-10", &latency1_10},
    {"latency10-50", &latency10_50},
    {"latency50-100", &latency50_100},
    {"latency100-1000", &latency100_1000},
    {"latency-slow", &latencySlow},
    {"latency-avg100", &latencyAvg100},
    {"latency-avg1000", &latencyAvg1000},
    {"latency-avg10000", &latencyAvg10000},
    {"latency-avg1000000", &latencyAvg1000000},
    {"latency-tcp-avg100", &latencyTCPAvg100},
    {"latency-tcp-avg1000", &latencyTCPAvg1000},
    {"latency-tcp-avg10000", &latencyTCPAvg10000},
    {"latency-tcp-avg1000000", &latencyTCPAvg1000000},
    {"latency-dot-avg100", &latencyDoTAvg100},
    {"latency-dot-avg1000", &latencyDoTAvg1000},
    {"latency-dot-avg10000", &latencyDoTAvg10000},
    {"latency-dot-avg1000000", &latencyDoTAvg1000000},
    {"latency-doh-avg100", &latencyDoHAvg100},
    {"latency-doh-avg1000", &latencyDoHAvg1000},
    {"latency-doh-avg10000", &latencyDoHAvg10000},
    {"latency-doh-avg1000000", &latencyDoHAvg1000000},
    {"latency-doq-avg100", &latencyDoQAvg100},
    {"latency-doq-avg1000", &latencyDoQAvg1000},
    {"latency-doq-avg10000", &latencyDoQAvg10000},
    {"latency-doq-avg1000000", &latencyDoQAvg1000000},
    {"latency-doh3-avg100", &latencyDoH3Avg100},
    {"latency-doh3-avg1000", &latencyDoH3Avg1000},
    {"latency-doh3-avg10000", &latencyDoH3Avg10000},
    {"latency-doh3-avg1000000", &latencyDoH3Avg1000000},
    {"uptime", uptimeOfProcess},
    {"real-memory-usage", getRealMemoryUsage},
    {"special-memory-usage", getSpecialMemoryUsage},
    {"udp-in-errors", [](const std::string&) { return udpErrorStats("udp-in-errors"); }},
    {"udp-noport-errors", [](const std::string&) { return udpErrorStats("udp-noport-errors"); }},
    {"udp-recvbuf-errors", [](const std::string&) { return udpErrorStats("udp-recvbuf-errors"); }},
    {"udp-sndbuf-errors", [](const std::string&) { return udpErrorStats("udp-sndbuf-errors"); }},
    {"udp-in-csum-errors", [](const std::string&) { return udpErrorStats("udp-in-csum-errors"); }},
    {"udp6-in-errors", [](const std::string&) { return udp6ErrorStats("udp6-in-errors"); }},
    {"udp6-recvbuf-errors", [](const std::string&) { return udp6ErrorStats("udp6-recvbuf-errors"); }},
    {"udp6-sndbuf-errors", [](const std::string&) { return udp6ErrorStats("udp6-sndbuf-errors"); }},
    {"udp6-noport-errors", [](const std::string&) { return udp6ErrorStats("udp6-noport-errors"); }},
    {"udp6-in-csum-errors", [](const std::string&) { return udp6ErrorStats("udp6-in-csum-errors"); }},
    {"tcp-listen-overflows", [](const std::string&) { return tcpErrorStats("ListenOverflows"); }},
    {"noncompliant-queries", &nonCompliantQueries},
    {"noncompliant-responses", &nonCompliantResponses},
    {"proxy-protocol-invalid", &proxyProtocolInvalid},
    {"rdqueries", &rdQueries},
    {"empty-queries", &emptyQueries},
    {"cache-hits", &cacheHits},
    {"cache-misses", &cacheMisses},
    {"cpu-iowait", getCPUIOWait},
    {"cpu-steal", getCPUSteal},
    {"cpu-sys-msec", getCPUTimeSystem},
    {"cpu-user-msec", getCPUTimeUser},
    {"fd-usage", getOpenFileDescriptors},
    {"dyn-blocked", &dynBlocked},
    {"dyn-block-nmg-size", [](const std::string&) { return g_dynblockNMG.getLocal()->size(); }},
    {"security-status", &securityStatus},
    {"doh-query-pipe-full", &dohQueryPipeFull},
    {"doh-response-pipe-full", &dohResponsePipeFull},
    {"doq-response-pipe-full", &doqResponsePipeFull},
    {"doh3-response-pipe-full", &doh3ResponsePipeFull},
    {"outgoing-doh-query-pipe-full", &outgoingDoHQueryPipeFull},
    {"tcp-query-pipe-full", &tcpQueryPipeFull},
    {"tcp-cross-protocol-query-pipe-full", &tcpCrossProtocolQueryPipeFull},
    {"tcp-cross-protocol-response-pipe-full", &tcpCrossProtocolResponsePipeFull},
    // Latency histogram
    {"latency-sum", &latencySum},
    {"latency-count", &latencyCount},
  }}
{
}

struct Stats g_stats;

std::optional<std::string> declareCustomMetric(const std::string& name, const std::string& type, const std::string& description, std::optional<std::string> customName)
{
  if (!std::regex_match(name, std::regex("^[a-z0-9-]+$"))) {
    return std::string("Unable to declare metric '") + std::string(name) + std::string("': invalid name\n");
  }

  const std::string finalCustomName(customName ? *customName : "");
  if (type == "counter") {
    auto customCounters = s_customCounters.write_lock();
    auto itp = customCounters->insert({name, MutableCounter()});
    if (itp.second) {
      g_stats.entries.write_lock()->emplace_back(Stats::EntryPair{name, &(*customCounters)[name].d_value});
      dnsdist::prometheus::PrometheusMetricDefinition def{name, type, description, finalCustomName};
      addMetricDefinition(def);
    }
  }
  else if (type == "gauge") {
    auto customGauges = s_customGauges.write_lock();
    auto itp = customGauges->insert({name, MutableGauge()});
    if (itp.second) {
      g_stats.entries.write_lock()->emplace_back(Stats::EntryPair{name, &(*customGauges)[name].d_value});
      dnsdist::prometheus::PrometheusMetricDefinition def{name, type, description, finalCustomName};
      addMetricDefinition(def);
    }
  }
  else {
    return std::string("Unable to declare metric: unknown type '") + type + "'";
  }
  return std::nullopt;
}

std::variant<uint64_t, Error> incrementCustomCounter(const std::string_view& name, uint64_t step)
{
  auto customCounters = s_customCounters.read_lock();
  auto metric = customCounters->find(name);
  if (metric != customCounters->end()) {
    metric->second.d_value += step;
    return metric->second.d_value.load();
  }
  return std::string("Unable to increment custom metric '") + std::string(name) + "': no such metric";
}

std::variant<uint64_t, Error> decrementCustomCounter(const std::string_view& name, uint64_t step)
{
  auto customCounters = s_customCounters.read_lock();
  auto metric = customCounters->find(name);
  if (metric != customCounters->end()) {
    metric->second.d_value -= step;
    return metric->second.d_value.load();
  }
  return std::string("Unable to decrement custom metric '") + std::string(name) + "': no such metric";
}

std::variant<double, Error> setCustomGauge(const std::string_view& name, const double value)
{
  auto customGauges = s_customGauges.read_lock();
  auto metric = customGauges->find(name);
  if (metric != customGauges->end()) {
    metric->second.d_value = value;
    return value;
  }

  return std::string("Unable to set metric '") + std::string(name) + "': no such metric";
}

std::variant<double, Error> getCustomMetric(const std::string_view& name)
{
  {
    auto customCounters = s_customCounters.read_lock();
    auto counter = customCounters->find(name);
    if (counter != customCounters->end()) {
      return static_cast<double>(counter->second.d_value.load());
    }
  }
  {
    auto customGauges = s_customGauges.read_lock();
    auto gauge = customGauges->find(name);
    if (gauge != customGauges->end()) {
      return gauge->second.d_value.load();
    }
  }
  return std::string("Unable to get metric '") + std::string(name) + "': no such metric";
}

}
