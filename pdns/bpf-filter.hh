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

#include "iputils.hh"
#include "lock.hh"

class BPFFilter
{
public:
  enum class MapType : uint8_t {
    IPv4,
    IPv6,
    QNames,
    Filters
  };

  struct MapConfiguration
  {
    std::string d_pinnedPath;
    uint32_t d_maxItems{0};
    MapType d_type;
  };

  BPFFilter(const BPFFilter::MapConfiguration& v4, const BPFFilter::MapConfiguration& v6, const BPFFilter::MapConfiguration& qnames);
  BPFFilter(const BPFFilter&) = delete;
  BPFFilter(BPFFilter&&) = delete;
  BPFFilter& operator=(const BPFFilter&) = delete;
  BPFFilter& operator=(BPFFilter&&) = delete;

  void addSocket(int sock);
  void removeSocket(int sock);
  void block(const ComboAddress& addr);
  void block(const DNSName& qname, uint16_t qtype=255);
  void unblock(const ComboAddress& addr);
  void unblock(const DNSName& qname, uint16_t qtype=255);

  std::vector<std::pair<ComboAddress, uint64_t> > getAddrStats();
  std::vector<std::tuple<DNSName, uint16_t, uint64_t> > getQNameStats();

  uint64_t getHits(const ComboAddress& requestor);

private:
#ifdef HAVE_EBPF
  struct Map
  {
    Map()
    {
    }
    Map(const MapConfiguration&);
    MapConfiguration d_config;
    uint32_t d_count{0};
    FDWrapper d_fd;
  };

  struct Maps
  {
    Map d_v4;
    Map d_v6;
    Map d_qnames;
    /* The qname filter program held in d_qnamefilter is
       stored in an eBPF map, so we can call it from the
       main filter. This is the only entry in that map. */
    Map d_filters;
  };

  LockGuarded<Maps> d_maps;

  /* main eBPF program */
  FDWrapper d_mainfilter;
  /* qname filtering program */
  FDWrapper d_qnamefilter;
#endif /* HAVE_EBPF */
};
