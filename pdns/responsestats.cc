#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "responsestats.hh"

#include <limits>
#include <boost/format.hpp>

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

ResponseStats::ResponseStats() :
  d_sizecounters("SizeCounters", sizeBounds())
{
  for (auto& entry : d_qtypecounters) {
    entry.value = 0;
  }
  for (auto& entry : d_rcodecounters) {
    entry.value = 0;
  }
}

ResponseStats g_rs;

void ResponseStats::submitResponse(uint16_t qtype, uint16_t respsize, uint8_t rcode, bool udpOrTCP) const
{
  d_rcodecounters.at(rcode).value++;
  submitResponse(qtype, respsize, udpOrTCP);
}

void ResponseStats::submitResponse(uint16_t qtype, uint16_t respsize, bool /* udpOrTCP */) const
{
  d_qtypecounters.at(qtype).value++;
  d_sizecounters(respsize);
}

map<uint16_t, uint64_t> ResponseStats::getQTypeResponseCounts() const
{
  map<uint16_t, uint64_t> ret;
  uint64_t count;
  for (unsigned int i = 0; i < d_qtypecounters.size(); ++i) {
    count = d_qtypecounters.at(i).value;
    if (count) {
      ret[i] = count;
    }
  }
  return ret;
}

map<uint16_t, uint64_t> ResponseStats::getSizeResponseCounts() const
{
  map<uint16_t, uint64_t> ret;
  for (const auto& sizecounter : d_sizecounters.getRawData()) {
    if (sizecounter.d_count) {
      ret[sizecounter.d_boundary] = sizecounter.d_count;
    }
  }
  return ret;
}

map<uint8_t, uint64_t> ResponseStats::getRCodeResponseCounts() const
{
  map<uint8_t, uint64_t> ret;
  uint64_t count;
  for (unsigned int i = 0; i < d_rcodecounters.size(); ++i) {
    count = d_rcodecounters.at(i).value;
    if (count) {
      ret[i] = count;
    }
  }
  return ret;
}

string ResponseStats::getQTypeReport() const
{
  auto qtypenums = getQTypeResponseCounts();
  ostringstream os;
  boost::format fmt("%s\t%d\n");
  for (const auto& val : qtypenums) {
    os << (fmt % DNSRecordContent::NumberToType(val.first) % val.second).str();
  }
  return os.str();
}
