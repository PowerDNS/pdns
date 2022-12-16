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

#include <array>

#include "histogram.hh"
#include "dnspacket.hh"

class RecResponseStats
{
public:
  RecResponseStats();

  RecResponseStats& operator+=(const RecResponseStats&);

  // To limit the size of this object, we cap the rcodes and qtypes,
  // in line with
  // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

  // This is to reduce the memory used and the amount of work to be
  // done by TCounters. As this class is part of the TCounter object,
  // growing it too much would cause large objects on the stack. A
  // full QType array would take 64k * sizeof(uint64_t) = 512k.
  // Having such an object on a thread stack does not work well on
  // e.g. macOS or OpenBSD, where the default thread stack size is
  // limited. Additionally, C++ has no platform independent way to
  // enlarge the thread stack size.

  // We could allocate parts of this on the heap, but this would still
  // mean having to manipulate large amounts of data by the TCounter
  // classes

  static const uint16_t maxRCode = 23; // BADCOOKIE
  static const uint16_t maxQType = 260; // AMTRELAY

  void submitResponse(uint16_t qtype, uint16_t respsize, uint8_t rcode)
  {
    if (rcode <= maxRCode) {
      d_rcodecounters.at(rcode)++;
    }
    if (qtype <= maxQType) {
      d_qtypecounters.at(qtype)++;
    }
    d_sizecounters(respsize);
  }
  map<uint16_t, uint64_t> getQTypeResponseCounts() const;
  map<uint16_t, uint64_t> getSizeResponseCounts() const;
  map<uint8_t, uint64_t> getRCodeResponseCounts() const;
  string getQTypeReport() const;

private:
  std::array<uint64_t, maxQType + 1> d_qtypecounters{};
  std::array<uint64_t, maxRCode + 1> d_rcodecounters{};
  pdns::Histogram d_sizecounters;
};
