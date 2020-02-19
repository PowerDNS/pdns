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
#include "config.h"

#include <mutex>

#include "iputils.hh"

#ifdef HAVE_EBPF

class BPFFilter
{
public:
  BPFFilter(uint32_t maxV4Addresses, uint32_t maxV6Addresses, uint32_t maxQNames);
  void addSocket(int sock);
  void removeSocket(int sock);
  void block(const ComboAddress& addr);
  void block(const DNSName& qname, uint16_t qtype = 255);
  void unblock(const ComboAddress& addr);
  void unblock(const DNSName& qname, uint16_t qtype = 255);
  std::vector<std::pair<ComboAddress, uint64_t>> getAddrStats();
  std::vector<std::tuple<DNSName, uint16_t, uint64_t>> getQNameStats();

private:
  struct FDWrapper
  {
    ~FDWrapper()
    {
      if (fd != -1) {
        close(fd);
      }
    }
    int fd{-1};
  };
  std::mutex d_mutex;
  uint32_t d_maxV4;
  uint32_t d_maxV6;
  uint32_t d_maxQNames;
  uint32_t d_v4Count{0};
  uint32_t d_v6Count{0};
  uint32_t d_qNamesCount{0};
  FDWrapper d_v4map;
  FDWrapper d_v6map;
  FDWrapper d_qnamemap;
  FDWrapper d_filtermap;
  FDWrapper d_mainfilter;
  FDWrapper d_qnamefilter;
};

#endif /* HAVE_EBPF */
