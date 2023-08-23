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

std::optional<std::string> declareCustomMetric(const std::string& name, const std::string& type, const std::string& description, std::optional<std::string> customName)
{
  if (!std::regex_match(name, std::regex("^[a-z0-9-]+$"))) {
    return std::string("Unable to declare metric '") + std::string(name) + std::string("': invalid name\n");
  }

  if (type == "counter") {
    auto customCounters = g_stats.customCounters.write_lock();
    auto itp = customCounters->insert({name, DNSDistStats::MutableCounter()});
    if (itp.second) {
      g_stats.entries.write_lock()->emplace_back(DNSDistStats::EntryPair{name, &(*customCounters)[name].d_value});
      addMetricDefinition(name, "counter", description, customName ? *customName : "");
    }
  }
  else if (type == "gauge") {
    auto customGauges = g_stats.customGauges.write_lock();
    auto itp = customGauges->insert({name, DNSDistStats::MutableGauge()});
    if (itp.second) {
      g_stats.entries.write_lock()->emplace_back(DNSDistStats::EntryPair{name, &(*customGauges)[name].d_value});
      addMetricDefinition(name, "gauge", description, customName ? *customName : "");
    }
  }
  else {
    return std::string("Unable to declare metric: unknown type '") + type + "'";
  }
  return std::nullopt;
}

std::variant<uint64_t, Error> incrementCustomCounter(const std::string_view& name, uint64_t step)
{
  auto customCounters = g_stats.customCounters.read_lock();
  auto metric = customCounters->find(name);
  if (metric != customCounters->end()) {
    if (step) {
      metric->second.d_value += step;
      return metric->second.d_value.load();
    }
    return ++(metric->second.d_value);
  }
  return std::string("Unable to increment custom metric '") + std::string(name) + "': no such metric";
}

std::variant<uint64_t, Error> decrementCustomCounter(const std::string_view& name, uint64_t step)
{
  auto customCounters = g_stats.customCounters.read_lock();
  auto metric = customCounters->find(name);
  if (metric != customCounters->end()) {
    if (step) {
      metric->second.d_value -= step;
      return metric->second.d_value.load();
    }
    return --(metric->second.d_value);
  }
  return std::string("Unable to decrement custom metric '") + std::string(name) + "': no such metric";
}

std::variant<double, Error> setCustomGauge(const std::string_view& name, const double value)
{
  auto customGauges = g_stats.customGauges.read_lock();
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
    auto customCounters = g_stats.customCounters.read_lock();
    auto counter = customCounters->find(name);
    if (counter != customCounters->end()) {
      return static_cast<double>(counter->second.d_value.load());
    }
  }
  {
    auto customGauges = g_stats.customGauges.read_lock();
    auto gauge = customGauges->find(name);
    if (gauge != customGauges->end()) {
      return gauge->second.d_value.load();
    }
  }
  return std::string("Unable to get metric '") + std::string(name) + "': no such metric";
}
}
