#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "rec-responsestats.hh"

#include <limits>

#include "namespaces.hh"
#include "logger.hh"

#include "dnsparser.hh"

static auto sizeBounds()
{
  std::vector<uint64_t> bounds;

  bounds.push_back(20);
  bounds.push_back(40);
  bounds.push_back(60);
  bounds.push_back(80);
  bounds.push_back(100);
  bounds.push_back(150);
  for (uint64_t n = 200; n < 65000; n += 200) {
    bounds.push_back(n);
  }
  return bounds;
}

RecResponseStats::RecResponseStats() :
  d_sizecounters("SizeCounters", sizeBounds())
{
  for (auto& entry : d_qtypecounters) {
    entry = 0;
  }
  for (auto& entry : d_rcodecounters) {
    entry = 0;
  }
}

RecResponseStats& RecResponseStats::operator+=(const RecResponseStats& rhs)
{
  for (size_t i = 0; i < d_qtypecounters.size(); i++) {
    d_qtypecounters.at(i) += rhs.d_qtypecounters.at(i);
  }
  for (size_t i = 0; i < d_rcodecounters.size(); i++) {
    d_rcodecounters.at(i) += rhs.d_rcodecounters.at(i);
  }
  d_sizecounters += rhs.d_sizecounters;
  return *this;
}

map<uint16_t, uint64_t> RecResponseStats::getQTypeResponseCounts() const
{
  map<uint16_t, uint64_t> ret;
  for (size_t i = 0; i < d_qtypecounters.size(); ++i) {
    auto count = d_qtypecounters.at(i);
    if (count != 0) {
      ret[i] = count;
    }
  }
  return ret;
}

map<uint16_t, uint64_t> RecResponseStats::getSizeResponseCounts() const
{
  map<uint16_t, uint64_t> ret;
  for (const auto& sizecounter : d_sizecounters.getRawData()) {
    if (sizecounter.d_count > 0) {
      ret[sizecounter.d_boundary] = sizecounter.d_count;
    }
  }
  return ret;
}

map<uint8_t, uint64_t> RecResponseStats::getRCodeResponseCounts() const
{
  map<uint8_t, uint64_t> ret;
  for (size_t i = 0; i < d_rcodecounters.size(); ++i) {
    auto count = d_rcodecounters.at(i);
    if (count != 0) {
      ret[i] = count;
    }
  }
  return ret;
}

string RecResponseStats::getQTypeReport() const
{
  auto qtypenums = getQTypeResponseCounts();
  ostringstream ostr;
  for (const auto& val : qtypenums) {
    ostr << DNSRecordContent::NumberToType(val.first) << '\t' << std::to_string(val.second) << endl;
  }
  return ostr.str();
}
