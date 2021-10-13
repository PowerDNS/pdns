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
#include "stat_t.hh"

#include "dnspacket.hh"

class ResponseStats
{
public:
  ResponseStats();

  void submitResponse(DNSPacket& p, bool udpOrTCP, bool last = true) const;
  void submitResponse(uint16_t qtype, uint16_t respsize, bool udpOrTCP) const;
  void submitResponse(uint16_t qtype, uint16_t respsize, uint8_t rcode, bool udpOrTCP) const;
  map<uint16_t, uint64_t> getQTypeResponseCounts() const;
  map<uint16_t, uint64_t> getSizeResponseCounts() const;
  map<uint8_t, uint64_t> getRCodeResponseCounts() const;
  string getQTypeReport() const;

private:
  struct Counter
  {
    mutable pdns::stat_t value;
  };

  std::array<Counter, 65536> d_qtypecounters;
  std::array<Counter, 256> d_rcodecounters;
  pdns::AtomicHistogram d_sizecounters;
};

extern ResponseStats g_rs;
