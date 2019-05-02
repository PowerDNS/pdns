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
#include "misc.hh"
#include "dnspacket.hh"

class ResponseStats
{
public:
  ResponseStats();

  void submitResponse(DNSPacket &p, bool udpOrTCP);
  void submitResponse(uint16_t qtype, uint16_t respsize, bool udpOrTCP);
  void submitResponse(uint16_t qtype, uint16_t respsize, uint8_t rcode, bool udpOrTCP);
  map<uint16_t, uint64_t> getQTypeResponseCounts();
  map<uint16_t, uint64_t> getSizeResponseCounts();
  map<uint8_t, uint64_t> getRCodeResponseCounts();
  string getQTypeReport();

private:
  boost::scoped_array<std::atomic<unsigned long>> d_qtypecounters;
  boost::scoped_array<std::atomic<unsigned long>> d_rcodecounters;
  typedef vector<pair<uint16_t, uint64_t> > sizecounters_t;
  sizecounters_t d_sizecounters;
};

extern ResponseStats g_rs;
