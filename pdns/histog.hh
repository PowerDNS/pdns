#pragma once
#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics.hpp>

#include <vector>
#include <fstream>
#include <deque>
#include <map>

struct LogHistogramBin
{
  double percentile;
  double latLimit;
  double latAverage;
  double latMedian;
  double latStddev;
  uint64_t count;
  double cumulLatAverage;
  double cumulLatMedian;
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
  ba::accumulator_set<double, ba::features<ba::tag::mean, ba::tag::median, ba::tag::variance>, unsigned> acc;

  ba::accumulator_set<double, ba::features<ba::tag::mean, ba::tag::median, ba::tag::variance>, unsigned int> cumulstats;

  uint64_t bincount=0;
  std::vector<LogHistogramBin> ret;
  for(const auto& c: bins) {
    if(percentiles.empty())
      break;
    sum += c.second;
    bincount += c.second;
      
    acc(c.first/1000.0, ba::weight=c.second);
    for(unsigned int i=0; i < c.second; ++i)
      cumulstats(c.first/1000.0, ba::weight=1); // "weighted" does not work for median
    if(sum > percentiles.front() * totcumul / 100.0) {
      ret.push_back({100.0-percentiles.front(), (double)c.first/1000.0, ba::mean(acc), ba::median(acc), sqrt(ba::variance(acc)), bincount, ba::mean(cumulstats), ba::median(cumulstats)});
      
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
void writeLogHistogramFile(const T& bins, std::ostream& out, std::deque<double> percentiles={0.001, 0.01, 0.1, 0.2, 0.5, 1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 60, 70, 80, 90, 94, 95, 96, 97, 97.5, 98, 98.5, 99, 99.5, 99.6, 99.9, 99.99, 99.999, 99.9999} )
{

  auto vec = createLogHistogram(bins, percentiles);
  out<< R"(# set logscale xy
# set mxtics 10
# set mytics 10
# set grid xtics
# set grid ytics
# set xlabel "Slowest percentile"
# set ylabel "Millisecond response time"
# set terminal svg
# set output 'log-histogram.svg'
# plot 'log-histogram' using 1:2 with linespoints title 'Average latency per percentile', \
#	'log-histogram' using 1:6 with linespoints title 'Cumulative average latency', \
#	'log-histogram' using 1:7 with linespoints title 'Cumulative median latency')"<<"\n";

  out<<"# slow-percentile usec-latency-mean usec-latency-max usec-latency-median usec-latency-stddev usec-latency-cumul usec-latency-median-cumul num-queries\n";
  
  
  for(const auto& e : vec) {
    out<<e.percentile<<" "<<e.latAverage<<" "<<e.latLimit<<" "<<e.latMedian<<" "<<e.latStddev<<" "<<e.cumulLatAverage<<" "<<e.cumulLatMedian<<" "<<e.count<<"\n";
  }
  out.flush();
}

template<typename T>
void writeFullHistogramFile(const T& bins, double binMsec, std::ofstream& out)
{
  std::map<unsigned int, uint64_t> reducedBins;
  for(const auto& b : bins) {
    reducedBins[b.first/(1000.0*binMsec)]+=b.second;
  }
  out<<"# msec-bin-low count\n";
  for(const auto& rb : reducedBins) {
    out<<rb.first*binMsec<<" "<<rb.second<<"\n";
  }
  out.flush();
}
