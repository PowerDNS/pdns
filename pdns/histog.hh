#pragma once
#ifdef L
#error "Include this file BEFORE including logger.hh"
#endif

#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics.hpp>

#include <vector>
#include <fstream>
#include <deque>


struct LogHistogramBin
{
  double percentile;
  double latLimit;
  double latAverage;
  double latMedian;
  double latStddev;
  uint64_t count;
};

template<typename T>
std::vector<LogHistogramBin> createLogHistogram(const T& bins,
                        std::deque<double> percentiles={0.001, 0.01, 0.1, 0.2, 0.5, 1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 60, 70, 80, 90, 94, 95, 96, 97, 97.5, 98, 98.5, 99, 99.5, 99.6, 99.9, 99.99, 99.999, 99.9999})
{
  uint64_t totcumul=0, sum=0;

  for(const auto& c: bins) {
    totcumul += c.second;
  }

  namespace ba=boost::accumulators;
  ba::accumulator_set<double, ba::features<ba::tag::mean, ba::tag::median, ba::tag::variance>, double> acc;
  
  uint64_t bincount=0;
  std::vector<LogHistogramBin> ret;
  for(const auto& c: bins) {
    if(percentiles.empty())
      break;
    sum += c.second;
    bincount += c.second;
      
    acc(c.first, ba::weight=c.second);
      
    if(sum > percentiles.front() * totcumul / 100.0) {
      ret.push_back({100.0-percentiles.front(), (double)c.first, ba::mean(acc), ba::median(acc), sqrt(ba::variance(acc)), bincount});
      
      percentiles.pop_front();
      acc=decltype(acc)();
      bincount=0;
    }
  }
  std::sort(ret.begin(), ret.end(), [](const LogHistogramBin& a, const LogHistogramBin& b) {
      return a.percentile < b.percentile;
    });
  return ret;
}
template<typename T>
void writeLogHistogramFile(const T& bins, std::ofstream& out, std::deque<double> percentiles={0.001, 0.01, 0.1, 0.2, 0.5, 1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 60, 70, 80, 90, 94, 95, 96, 97, 97.5, 98, 98.5, 99, 99.5, 99.6, 99.9, 99.99, 99.999, 99.9999} )
{

  auto vec = createLogHistogram(bins, percentiles);
  out<<"# slow-percentile usec-latency-max usec-latency-mean usec-latency-median usec-latency-stddev num-queries\n";
  
  
  for(const auto& e : vec) {
    out<<e.percentile<<" "<<e.latLimit<<" "<<e.latAverage<<" "<<e.latMedian<<" "<<e.latStddev<<" "<<e.count<<"\n";
  }
  out.flush();
}
