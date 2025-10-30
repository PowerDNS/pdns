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
#include <boost/algorithm/string/join.hpp>
#include <numeric>
#include <regex>
#include <utility>

#include "dnsdist-metrics.hh"
#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"
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

  mutable pdns::stat_double_t d_value{0};
};

/* map of metric name -> map of labels -> metric value */
template <class MetricType>
using LabelsToMetricMap = std::map<std::string, MetricType>;
static SharedLockGuarded<std::map<std::string, LabelsToMetricMap<MutableCounter>, std::less<>>> s_customCounters;
static SharedLockGuarded<std::map<std::string, LabelsToMetricMap<MutableGauge>, std::less<>>> s_customGauges;

Stats::Stats() :
  entries{std::vector<EntryTriple>{
    {"responses", "", &responses},
    {"servfail-responses", "", &servfailResponses},
    {"queries", "", &queries},
    {"frontend-nxdomain", "", &frontendNXDomain},
    {"frontend-servfail", "", &frontendServFail},
    {"frontend-noerror", "", &frontendNoError},
    {"acl-drops", "", &aclDrops},
    {"rule-drop", "", &ruleDrop},
    {"rule-nxdomain", "", &ruleNXDomain},
    {"rule-refused", "", &ruleRefused},
    {"rule-servfail", "", &ruleServFail},
    {"rule-truncated", "", &ruleTruncated},
    {"self-answered", "", &selfAnswered},
    {"downstream-timeouts", "", &downstreamTimeouts},
    {"downstream-send-errors", "", &downstreamSendErrors},
    {"trunc-failures", "", &truncFail},
    {"no-policy", "", &noPolicy},
    {"latency0-1", "", &latency0_1},
    {"latency1-10", "", &latency1_10},
    {"latency10-50", "", &latency10_50},
    {"latency50-100", "", &latency50_100},
    {"latency100-1000", "", &latency100_1000},
    {"latency-slow", "", &latencySlow},
    {"latency-avg100", "", &latencyAvg100},
    {"latency-avg1000", "", &latencyAvg1000},
    {"latency-avg10000", "", &latencyAvg10000},
    {"latency-avg1000000", "", &latencyAvg1000000},
    {"latency-tcp-avg100", "", &latencyTCPAvg100},
    {"latency-tcp-avg1000", "", &latencyTCPAvg1000},
    {"latency-tcp-avg10000", "", &latencyTCPAvg10000},
    {"latency-tcp-avg1000000", "", &latencyTCPAvg1000000},
    {"latency-dot-avg100", "", &latencyDoTAvg100},
    {"latency-dot-avg1000", "", &latencyDoTAvg1000},
    {"latency-dot-avg10000", "", &latencyDoTAvg10000},
    {"latency-dot-avg1000000", "", &latencyDoTAvg1000000},
    {"latency-doh-avg100", "", &latencyDoHAvg100},
    {"latency-doh-avg1000", "", &latencyDoHAvg1000},
    {"latency-doh-avg10000", "", &latencyDoHAvg10000},
    {"latency-doh-avg1000000", "", &latencyDoHAvg1000000},
    {"latency-doq-avg100", "", &latencyDoQAvg100},
    {"latency-doq-avg1000", "", &latencyDoQAvg1000},
    {"latency-doq-avg10000", "", &latencyDoQAvg10000},
    {"latency-doq-avg1000000", "", &latencyDoQAvg1000000},
    {"latency-doh3-avg100", "", &latencyDoH3Avg100},
    {"latency-doh3-avg1000", "", &latencyDoH3Avg1000},
    {"latency-doh3-avg10000", "", &latencyDoH3Avg10000},
    {"latency-doh3-avg1000000", "", &latencyDoH3Avg1000000},
    {"uptime", "", uptimeOfProcess},
    {"real-memory-usage", "", getRealMemoryUsage},
    {"special-memory-usage", "", getSpecialMemoryUsage},
    {"udp-in-errors", "", [](const std::string&) { return udpErrorStats("udp-in-errors"); }},
    {"udp-noport-errors", "", [](const std::string&) { return udpErrorStats("udp-noport-errors"); }},
    {"udp-recvbuf-errors", "", [](const std::string&) { return udpErrorStats("udp-recvbuf-errors"); }},
    {"udp-sndbuf-errors", "", [](const std::string&) { return udpErrorStats("udp-sndbuf-errors"); }},
    {"udp-in-csum-errors", "", [](const std::string&) { return udpErrorStats("udp-in-csum-errors"); }},
    {"udp6-in-errors", "", [](const std::string&) { return udp6ErrorStats("udp6-in-errors"); }},
    {"udp6-recvbuf-errors", "", [](const std::string&) { return udp6ErrorStats("udp6-recvbuf-errors"); }},
    {"udp6-sndbuf-errors", "", [](const std::string&) { return udp6ErrorStats("udp6-sndbuf-errors"); }},
    {"udp6-noport-errors", "", [](const std::string&) { return udp6ErrorStats("udp6-noport-errors"); }},
    {"udp6-in-csum-errors", "", [](const std::string&) { return udp6ErrorStats("udp6-in-csum-errors"); }},
    {"tcp-listen-overflows", "", [](const std::string&) { return tcpErrorStats("ListenOverflows"); }},
    {"noncompliant-queries", "", &nonCompliantQueries},
    {"noncompliant-responses", "", &nonCompliantResponses},
    {"proxy-protocol-invalid", "", &proxyProtocolInvalid},
    {"rdqueries", "", &rdQueries},
    {"empty-queries", "", &emptyQueries},
    {"cache-hits", "", &cacheHits},
    {"cache-misses", "", &cacheMisses},
    {"cpu-iowait", "", getCPUIOWait},
    {"cpu-steal", "", getCPUSteal},
    {"cpu-sys-msec", "", getCPUTimeSystem},
    {"cpu-user-msec", "", getCPUTimeUser},
    {"fd-usage", "", getOpenFileDescriptors},
    {"dyn-blocked", "", &dynBlocked},
#ifndef DISABLE_DYNBLOCKS
    {"dyn-block-nmg-size", "", [](const std::string&) { return dnsdist::DynamicBlocks::getClientAddressDynamicRules().size(); }},
#endif /* DISABLE_DYNBLOCKS */
    {"security-status", "", &securityStatus},
    {"doh-query-pipe-full", "", &dohQueryPipeFull},
    {"doh-response-pipe-full", "", &dohResponsePipeFull},
    {"doq-response-pipe-full", "", &doqResponsePipeFull},
    {"doh3-response-pipe-full", "", &doh3ResponsePipeFull},
    {"outgoing-doh-query-pipe-full", "", &outgoingDoHQueryPipeFull},
    {"tcp-query-pipe-full", "", &tcpQueryPipeFull},
    {"tcp-cross-protocol-query-pipe-full", "", &tcpCrossProtocolQueryPipeFull},
    {"tcp-cross-protocol-response-pipe-full", "", &tcpCrossProtocolResponsePipeFull},
    // Latency histogram
    {"latency-sum", "", &latencySum},
    {"latency-count", "", &latencyCount},
  }}
{
}

struct Stats g_stats;

std::optional<std::string> declareCustomMetric(const std::string& name, const std::string& type, const std::string& description, std::optional<std::string> customName, bool withLabels)
{
  if (!std::regex_match(name, std::regex("^[a-z0-9-]+$"))) {
    return std::string("Unable to declare metric '") + std::string(name) + std::string("': invalid name\n");
  }

  const std::string finalCustomName(customName ? *customName : "");
  if (type == "counter") {
    auto customCounters = s_customCounters.write_lock();
    auto itp = customCounters->emplace(name, std::map<std::string, MutableCounter>());
    if (itp.second) {
      if (!withLabels) {
        auto counter = itp.first->second.emplace("", MutableCounter());
        g_stats.entries.write_lock()->emplace_back(Stats::EntryTriple{name, "", &counter.first->second.d_value});
      }
      dnsdist::prometheus::PrometheusMetricDefinition def{name, type, description, finalCustomName};
      dnsdist::webserver::addMetricDefinition(def);
    }
  }
  else if (type == "gauge") {
    auto customGauges = s_customGauges.write_lock();
    auto itp = customGauges->emplace(name, std::map<std::string, MutableGauge>());
    if (itp.second) {
      if (!withLabels) {
        auto gauge = itp.first->second.emplace("", MutableGauge());
        g_stats.entries.write_lock()->emplace_back(Stats::EntryTriple{name, "", &gauge.first->second.d_value});
      }
      dnsdist::prometheus::PrometheusMetricDefinition def{name, type, description, finalCustomName};
      dnsdist::webserver::addMetricDefinition(def);
    }
  }
  else {
    return std::string("Unable to declare metric: unknown type '") + type + "'";
  }
  return std::nullopt;
}

static string prometheusLabelValueEscape(const string& value)
{
  string ret;

  for (char lblchar : value) {
    if (lblchar == '"' || lblchar == '\\') {
      ret += '\\';
      ret += lblchar;
    }
    else if (lblchar == '\n') {
      ret += '\\';
      ret += 'n';
    }
    else {
      ret += lblchar;
    }
  }
  return ret;
}

static std::string generateCombinationOfLabels(const Labels& optLabels)
{
  if (!optLabels || optLabels->get().empty()) {
    return {};
  }
  const auto& labels = optLabels->get();
  auto ordered = std::map(labels.begin(), labels.end());
  return std::accumulate(ordered.begin(), ordered.end(), std::string(), [](const std::string& acc, const std::pair<std::string, std::string>& label) {
    return acc + (acc.empty() ? std::string() : ",") + label.first + "=" + "\"" + prometheusLabelValueEscape(label.second) + "\"";
  });
}

template <typename MetricType, typename MetricValueType>
static std::variant<MetricValueType, Error> updateMetric(const std::string_view& name, SharedLockGuarded<std::map<std::string, LabelsToMetricMap<MetricType>, std::less<>>>& metricMap, const Labels& labels, const std::function<void(const MetricType&)>& callback)
{
  auto combinationOfLabels = generateCombinationOfLabels(labels);
  /* be optimistic first, and see if the metric and labels exist */
  {
    auto readLockedMap = metricMap.read_lock();
    auto labelsMapIt = readLockedMap->find(name);
    if (labelsMapIt == readLockedMap->end()) {
      if constexpr (std::is_same_v<MetricType, MutableCounter>) {
        return std::string("Unable to update custom metric '") + std::string(name) + "': no such counter";
      }
      else {
        return std::string("Unable to update custom metric '") + std::string(name) + "': no such gauge";
      }
    }

    auto& metricEntries = labelsMapIt->second;
    auto metricEntry = metricEntries.find(combinationOfLabels);
    if (metricEntry != metricEntries.end()) {
      callback(metricEntry->second);
      return metricEntry->second.d_value.load();
    }
  }

  /* OK, so we the metric exists (otherwise we would have returned an Error) but the label doesn't yet */
  {
    // too bad Coverity claims to understand C++ yet does not understand RAII
    // coverity[double_lock]
    auto writeLockedMap = metricMap.write_lock();
    auto labelsMapIt = writeLockedMap->find(name);
    if (labelsMapIt == writeLockedMap->end()) {
      if constexpr (std::is_same_v<MetricType, MutableCounter>) {
        return std::string("Unable to update custom metric '") + std::string(name) + "': no such counter";
      }
      else {
        return std::string("Unable to update custom metric '") + std::string(name) + "': no such gauge";
      }
    }
    /* we need to check again, it might have been inserted in the meantime */
    auto& metricEntries = labelsMapIt->second;
    auto metricEntry = metricEntries.find(combinationOfLabels);
    if (metricEntry != metricEntries.end()) {
      callback(metricEntry->second);
      return metricEntry->second.d_value.load();
    }
    metricEntry = metricEntries.emplace(std::piecewise_construct, std::forward_as_tuple(combinationOfLabels), std::forward_as_tuple()).first;
    g_stats.entries.write_lock()->emplace_back(Stats::EntryTriple{std::string(name), std::move(combinationOfLabels), &metricEntry->second.d_value});
    callback(metricEntry->second);
    return metricEntry->second.d_value.load();
  }
}

std::variant<uint64_t, Error> incrementCustomCounter(const std::string_view& name, uint64_t step, const Labels& labels)
{
  return updateMetric<MutableCounter, uint64_t>(name, s_customCounters, labels, [step](const MutableCounter& counter) -> void {
    counter.d_value += step;
  });
}

std::variant<uint64_t, Error> decrementCustomCounter(const std::string_view& name, uint64_t step, const Labels& labels)
{
  return updateMetric<MutableCounter, uint64_t>(name, s_customCounters, labels, [step](const MutableCounter& counter) {
    counter.d_value -= step;
  });
}

std::variant<double, Error> setCustomGauge(const std::string_view& name, const double value, const Labels& labels)
{
  return updateMetric<MutableGauge, double>(name, s_customGauges, labels, [value](const MutableGauge& gauge) {
    gauge.d_value = value;
  });
}

std::variant<double, Error> getCustomMetric(const std::string_view& name, const Labels& labels)
{
  {
    auto customCounters = s_customCounters.read_lock();
    auto counter = customCounters->find(name);
    if (counter != customCounters->end()) {
      auto combinationOfLabels = generateCombinationOfLabels(labels);
      auto metricEntry = counter->second.find(combinationOfLabels);
      if (metricEntry != counter->second.end()) {
        return static_cast<double>(metricEntry->second.d_value.load());
      }
    }
  }
  {
    auto customGauges = s_customGauges.read_lock();
    auto gauge = customGauges->find(name);
    if (gauge != customGauges->end()) {
      auto combinationOfLabels = generateCombinationOfLabels(labels);
      auto metricEntry = gauge->second.find(combinationOfLabels);
      if (metricEntry != gauge->second.end()) {
        return metricEntry->second.d_value.load();
      }
    }
  }
  return std::string("Unable to get metric '") + std::string(name) + "': no such metric";
}

void doLatencyStats(dnsdist::Protocol protocol, double udiff)
{
  constexpr auto doAvg = [](pdns::stat_double_t& var, double n, double weight) {
    var.store((weight - 1) * var.load() / weight + n / weight);
  };

  if (protocol == dnsdist::Protocol::DoUDP || protocol == dnsdist::Protocol::DNSCryptUDP) {
    if (udiff < 1000) {
      ++dnsdist::metrics::g_stats.latency0_1;
    }
    else if (udiff < 10000) {
      ++dnsdist::metrics::g_stats.latency1_10;
    }
    else if (udiff < 50000) {
      ++dnsdist::metrics::g_stats.latency10_50;
    }
    else if (udiff < 100000) {
      ++dnsdist::metrics::g_stats.latency50_100;
    }
    else if (udiff < 1000000) {
      ++dnsdist::metrics::g_stats.latency100_1000;
    }
    else {
      ++dnsdist::metrics::g_stats.latencySlow;
    }

    dnsdist::metrics::g_stats.latencySum += static_cast<unsigned long>(udiff) / 1000;
    ++dnsdist::metrics::g_stats.latencyCount;

    doAvg(dnsdist::metrics::g_stats.latencyAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoTCP || protocol == dnsdist::Protocol::DNSCryptTCP) {
    doAvg(dnsdist::metrics::g_stats.latencyTCPAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyTCPAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyTCPAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyTCPAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoT) {
    doAvg(dnsdist::metrics::g_stats.latencyDoTAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyDoTAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyDoTAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyDoTAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoH) {
    doAvg(dnsdist::metrics::g_stats.latencyDoHAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyDoHAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyDoHAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyDoHAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoQ) {
    doAvg(dnsdist::metrics::g_stats.latencyDoQAvg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyDoQAvg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyDoQAvg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyDoQAvg1000000, udiff, 1000000);
  }
  else if (protocol == dnsdist::Protocol::DoH3) {
    doAvg(dnsdist::metrics::g_stats.latencyDoH3Avg100, udiff, 100);
    doAvg(dnsdist::metrics::g_stats.latencyDoH3Avg1000, udiff, 1000);
    doAvg(dnsdist::metrics::g_stats.latencyDoH3Avg10000, udiff, 10000);
    doAvg(dnsdist::metrics::g_stats.latencyDoH3Avg1000000, udiff, 1000000);
  }
}
}
