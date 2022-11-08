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

#include "tcounters.hh"

#include <string>

#include "histogram.hh"

namespace rec
{

// Simple counters
enum class Counter : uint8_t
{
  syncresqueries,
  outgoingtimeouts,
  outgoing4timeouts,
  outgoing6timeouts,
  throttledqueries,
  dontqueries,
  qnameminfallbacksuccess,
  authzonequeries,
  outqueries,
  tcpoutqueries,
  dotoutqueries,
  unreachables,
  servFails,
  nxDomains,
  noErrors,
  qcounter,
  ipv6qcounter,
  tcpqcounter,
  unauthorizedUDP, // when this is increased, qcounter isn't
  unauthorizedTCP, // when this is increased, qcounter isn't
  sourceDisallowedNotify, // when this is increased, qcounter is also
  zoneDisallowedNotify, // when this is increased, qcounter is also
  policyDrops,
  tcpClientOverflow,
  clientParseError,
  serverParseError,
  tooOldDrops,
  truncatedDrops,
  queryPipeFullDrops,
  unexpectedCount,
  caseMismatchCount,
  spoofCount,
  resourceLimits,
  overCapacityDrops,
  ipv6queries,
  chainResends,
  nsSetInvalidations,
  ednsPingMatches,
  ednsPingMismatches,
  noPingOutQueries,
  noEdnsOutQueries,
  packetCacheHits,
  noPacketError,
  ignoredCount,
  emptyQueriesCount,
  dnssecQueries,
  dnssecAuthenticDataQueries,
  dnssecCheckDisabledQueries,
  variableResponses,
  maxMThreadStackUsage,
  dnssecValidations, // should be the sum of all dnssecResult* stats
  rebalancedQueries,
  proxyProtocolInvalidCount,
  nodLookupsDroppedOversize,
  dns64prefixanswers,
  maintenanceUsec,
  maintenanceCalls,

  numberOfCounters
};

// double avegares times, weighted according to how many packets they processed
enum class DoubleWAvgCounter : uint8_t
{
  avgLatencyUsec,
  avgLatencyOursUsec,
  numberOfCounters
};

// An RCode histogram
enum class RCode : uint8_t
{
  auth,
  numberOfCounters
};

// A few other histograms
enum class Histogram : uint8_t
{
  answers,
  auth4Answers,
  auth6Answers,
  ourtime,
  cumulativeAnswers,
  cumulativeAuth4Answers,
  cumulativeAuth6Answers,

  numberOfCounters
};

struct Counters
{
  // An aray of simple counters
  std::array<uint64_t, static_cast<size_t>(Counter::numberOfCounters)> uint64Count{};

  struct WeightedAverage
  {
    double avg{};
    uint64_t weight{};

    void add(double value)
    {
      avg = value;
      ++weight;
    }

    void addToRollingAvg(double value, uint64_t rollsize)
    {
      add((1.0 - 1.0 / static_cast<double>(rollsize)) * avg + value / static_cast<double>(rollsize));
    }
  };
  // And an array of weighted averaged values
  std::array<WeightedAverage, static_cast<size_t>(DoubleWAvgCounter::numberOfCounters)> doubleWAvg{};

  struct RCodeCounters
  {
    RCodeCounters& operator+=(const RCodeCounters& rhs)
    {
      for (size_t i = 0; i < rcodeCounters.size(); i++) {
        rcodeCounters.at(i) += rhs.rcodeCounters.at(i);
      }
      return *this;
    }
    static const size_t numberoOfRCodes = 16;
    std::array<uint64_t, numberoOfRCodes> rcodeCounters;
  };
  // An RCodes histogram
  RCodeCounters auth{};

  std::array<pdns::Histogram, static_cast<size_t>(Histogram::numberOfCounters)> histograms = {
    pdns::Histogram{"answers", {1000, 10000, 100000, 1000000}},
    pdns::Histogram{"auth4answers", {1000, 10000, 100000, 1000000}},
    pdns::Histogram{"auth6answers", {1000, 10000, 100000, 1000000}},
    pdns::Histogram{"ourtime", {1000, 2000, 4000, 8000, 16000, 32000}},
    pdns::Histogram{"cumul-clientanswers-", 10, 19},
    pdns::Histogram{"cumul-authanswers-", 1000, 13},
    pdns::Histogram{"cumul-authanswers-", 1000, 13}};

  Counters()
  {
    for (auto& elem : uint64Count) {
      elem = 0;
    }
    // doubleWAvg has a default ct that initializes
    for (auto& elem : auth.rcodeCounters) {
      elem = 0;
    }
  }

  // Merge a set of counters into an existing set of counters. For simple counters, that will be additions
  // for averages, we should take the weights into account. Histograms need to sum all individual counts.
  Counters& merge(const Counters& data);

  // The following accessors select the rightcounter type based on the index type
  uint64_t& at(Counter index)
  {
    return uint64Count.at(static_cast<size_t>(index));
  }

  WeightedAverage& at(DoubleWAvgCounter index)
  {
    return doubleWAvg.at(static_cast<size_t>(index));
  }

  RCodeCounters& at(RCode index)
  {
    // We only have a single RCode indexed Histogram, so no need to select a specific one
    return auth;
  }

  pdns::Histogram& at(Histogram index)
  {
    return histograms.at(static_cast<size_t>(index));
  }

  // Mainly for debugging purposes
  [[nodiscard]] std::string toString() const;
};

// The application specific types, one for thread local, one for the aggregator
using TCounters = pdns::TLocalCounters<Counters>;
using GlobalCounters = pdns::GlobalCounters<Counters>;
}
