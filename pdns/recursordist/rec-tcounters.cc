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

#include "rec-tcounters.hh"

#include <sstream>

namespace rec
{

Counters& Counters::merge(const Counters& data)
{
  // Counters are simply added
  for (size_t i = 0; i < uint64Count.size(); i++) {
    uint64Count.at(i) += data.uint64Count.at(i);
  }
  // Averages: take weight into account
  for (size_t i = 0; i < doubleWAvg.size(); i++) {
    auto& lhs = doubleWAvg.at(i);
    const auto& rhs = data.doubleWAvg.at(i);
    auto weight = lhs.weight + rhs.weight;
    auto avg = (lhs.avg * static_cast<double>(lhs.weight)) + (rhs.avg * static_cast<double>(rhs.weight));
    avg = weight == 0 ? 0 : avg / static_cast<double>(weight);
    lhs.avg = avg;
    lhs.weight = weight;
  }

  // Rcode Counters are simply added
  for (size_t i = 0; i < auth.rcodeCounters.size(); i++) {
    auth.rcodeCounters.at(i) += data.auth.rcodeCounters.at(i);
  }

  // Histograms counts are added by += operator on Histograms
  for (size_t i = 0; i < histograms.size(); i++) {
    histograms.at(i) += data.histograms.at(i);
  }

  // ResponseStats knows how to add
  responseStats += data.responseStats;

  // DNSSEC histograms: add individual entries
  for (size_t i = 0; i < dnssecCounters.size(); i++) {
    auto& lhs = dnssecCounters.at(i);
    const auto& rhs = data.dnssecCounters.at(i);
    for (size_t j = 0; j < lhs.counts.size(); j++) {
      lhs.counts.at(j) += rhs.counts.at(j);
    }
  }

  // policy kind counters: add individual entries
  for (size_t i = 0; i < policyCounters.counts.size(); i++) {
    policyCounters.counts.at(i) += data.policyCounters.counts.at(i);
  }

  // Policy name counts knows how to add
  policyNameHits += data.policyNameHits;

  return *this;
}

std::string Counters::toString() const
{
  std::ostringstream stream;

  for (auto element : uint64Count) {
    stream << element << ' ';
  }
  stream << std::endl;
  for (auto element : doubleWAvg) {
    stream << '(' << element.avg << ' ' << element.weight << ')';
  }
  stream << " RCodes: ";
  for (auto element : auth.rcodeCounters) {
    stream << element << ' ';
  }
  stream << "Histograms: ";
  for (const auto& element : histograms) {
    stream << element.getName() << ": NYI ";
  }
  stream << "DNSSEC Histograms: ";
  stream << "NYI ";
  stream << "Policy Counters: ";
  stream << "NYI ";
  stream << "Policy Name Counters: ";
  stream << "NYI ";

  stream << std::endl;
  return stream.str();
}

}

// Compile with:
// c++ -DTEST_TCOUNTER_TIMING -Wall -std=c++17 -O2 rec-tcounters.cc -pthread

#if TEST_TCOUNTER_TIMING

#include <iostream>
#include <vector>
#include <atomic>
#include <thread>
#include <ctime>

rec::GlobalCounters g_counters;
thread_local rec::TCounters t_counters(g_counters);

std::atomic<uint64_t> atomicCounter;

size_t iterations;

void atomicThread()
{
  for (size_t i = 0; i < iterations; i++) {
    ++atomicCounter;
  }
}

void tcounterThread()
{
  for (size_t i = 0; i < iterations; i++) {
    ++t_counters.at(rec::Counter::qcounter);
    if (i % 100 == 0) {
      t_counters.updateSnap();
    }
  }
}

int main(int argc, char* argv[])
{
  size_t threads = std::atoi(argv[1]);
  iterations = std::atoi(argv[2]);

  std::cout << "Starting " << threads << " threads doing " << iterations << " iterations using atomics" << std::endl;
  std::vector<std::thread> thr;
  thr.resize(threads);

  timeval start;
  gettimeofday(&start, nullptr);
  for (size_t i = 0; i < threads; i++) {
    thr[i] = std::thread(atomicThread);
  }
  for (size_t i = 0; i < threads; i++) {
    thr[i].join();
  }
  timeval stop;
  gettimeofday(&stop, nullptr);
  timeval diff;
  timersub(&stop, &start, &diff);
  auto elapsed = (diff.tv_sec + diff.tv_usec / 1e6);
  std::cout << "Sum is " << atomicCounter << " elapsed is " << elapsed << std::endl;

  std::cout << "Now doing the same with tcounters" << std::endl;
  gettimeofday(&start, nullptr);
  for (size_t i = 0; i < threads; i++) {
    thr[i] = std::thread(tcounterThread);
  }
  for (size_t i = 0; i < threads; i++) {
    thr[i].join();
  }
  gettimeofday(&stop, nullptr);
  timersub(&stop, &start, &diff);
  elapsed = (diff.tv_sec + diff.tv_usec / 1e6);
  std::cout << "Sum is " << g_counters.sum(rec::Counter::qcounter) << " elapsed is " << elapsed << std::endl;
}

#endif
