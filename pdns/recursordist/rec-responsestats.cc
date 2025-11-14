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

#include "rec-responsestats.hh"

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
  for (uint64_t count = 200; count < 65000; count += 200) {
    bounds.push_back(count);
  }
  return bounds;
}

RecResponseStats::RecResponseStats() :
  d_sizecounters("SizeCounters", sizeBounds())
{
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

std::map<uint16_t, uint64_t> RecResponseStats::getQTypeResponseCounts() const
{
  std::map<uint16_t, uint64_t> ret;
  for (size_t i = 0; i < d_qtypecounters.size(); ++i) {
    auto count = d_qtypecounters.at(i);
    if (count != 0) {
      ret[i] = count;
    }
  }
  return ret;
}

std::map<uint16_t, uint64_t> RecResponseStats::getSizeResponseCounts() const
{
  std::map<uint16_t, uint64_t> ret;
  for (const auto& sizecounter : d_sizecounters.getRawData()) {
    if (sizecounter.d_count > 0) {
      ret[sizecounter.d_boundary] = sizecounter.d_count;
    }
  }
  return ret;
}

std::map<uint8_t, uint64_t> RecResponseStats::getRCodeResponseCounts() const
{
  std::map<uint8_t, uint64_t> ret;
  for (size_t i = 0; i < d_rcodecounters.size(); ++i) {
    auto count = d_rcodecounters.at(i);
    if (count != 0) {
      ret[i] = count;
    }
  }
  return ret;
}

std::string RecResponseStats::getQTypeReport() const
{
  auto qtypenums = getQTypeResponseCounts();
  std::ostringstream ostr;
  for (const auto& val : qtypenums) {
    ostr << DNSRecordContent::NumberToType(val.first) << '\t' << std::to_string(val.second) << endl;
  }
  return ostr.str();
}
