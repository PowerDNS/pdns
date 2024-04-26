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

#include "bpf-filter.hh"
#include "iputils.hh"

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/member.hpp>

class DynBPFFilter
{
public:
  DynBPFFilter(std::shared_ptr<BPFFilter>& bpf)
  {
    d_data.lock()->d_bpf = bpf;
  }
  ~DynBPFFilter()
  {
  }
  void excludeRange(const Netmask& range)
  {
    d_data.lock()->d_excludedSubnets.addMask(range);
  }
  void includeRange(const Netmask& range)
  {
    d_data.lock()->d_excludedSubnets.addMask(range, false);
  }
  /* returns true if the addr wasn't already blocked, false otherwise */
  bool block(const ComboAddress& addr, const struct timespec& until);
  void purgeExpired(const struct timespec& now);
  std::vector<std::tuple<ComboAddress, uint64_t, struct timespec>> getAddrStats();

private:
  struct BlockEntry
  {
    BlockEntry(const ComboAddress& addr, const struct timespec until) :
      d_addr(addr), d_until(until)
    {
    }
    ComboAddress d_addr;
    struct timespec d_until;
  };
  typedef boost::multi_index_container<BlockEntry,
                                       boost::multi_index::indexed_by<
                                         boost::multi_index::ordered_unique<boost::multi_index::member<BlockEntry, ComboAddress, &BlockEntry::d_addr>, ComboAddress::addressOnlyLessThan>,
                                         boost::multi_index::ordered_non_unique<boost::multi_index::member<BlockEntry, struct timespec, &BlockEntry::d_until>>>>
    container_t;
  struct Data
  {
    container_t d_entries;
    std::shared_ptr<BPFFilter> d_bpf{nullptr};
    NetmaskGroup d_excludedSubnets;
  };
  LockGuarded<Data> d_data;
};
