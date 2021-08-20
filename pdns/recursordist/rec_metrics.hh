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

#include <string>
#include <map>

// Metric types for Prometheus
enum class PrometheusMetricType : uint8_t
{
  counter,
  gauge,
  histogram,
  multicounter
};

// Keeps additional information about metrics
struct MetricDefinition
{
  MetricDefinition(const PrometheusMetricType prometheusType, const std::string& description) :
    d_description(description), d_prometheusType(prometheusType)
  {
  }

  MetricDefinition() = default;

  // Metric description
  std::string d_description;
  // Metric type for Prometheus
  PrometheusMetricType d_prometheusType;
};

class MetricDefinitionStorage
{
public:
  // Return metric definition by name
  bool getMetricDetails(const std::string& metricName, MetricDefinition& metric)
  {
    auto metricDetailsIter = d_metrics.find(metricName);

    if (metricDetailsIter == d_metrics.end()) {
      return false;
    }

    metric = metricDetailsIter->second;
    return true;
  };

  // Return string representation of Prometheus metric type
  static std::string getPrometheusStringMetricType(const PrometheusMetricType metricType)
  {
    switch (metricType) {
    case PrometheusMetricType::counter:
      return "counter";
      break;
    case PrometheusMetricType::gauge:
      return "gauge";
      break;
    case PrometheusMetricType::histogram:
      return "histogram";
      break;
    case PrometheusMetricType::multicounter:
      // A multicounter produces multiple values of type "counter"
      return "counter";
      break;
    default:
      return "";
      break;
    }
  };

private:
  // Description and types for prometheus output of stats
  static const std::map<std::string, MetricDefinition> d_metrics;
};
