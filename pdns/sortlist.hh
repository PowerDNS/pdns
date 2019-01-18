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
#include "iputils.hh"
#include "dnsrecords.hh"

struct SortListOrder
{
  NetmaskTree<int> d_orders;
};


struct SortListOrderCmp
{
  SortListOrderCmp(const SortListOrder& slo) : d_slo(slo) {}
  bool operator()(const DNSRecord& a, const DNSRecord& b) const;
  const SortListOrder d_slo;
};

class SortList {
public:
  void clear();
  void addEntry(const Netmask& covers, const Netmask& answermask, int order=-1);
  int getMaxOrder(const Netmask& formask) const;
  std::unique_ptr<SortListOrderCmp> getOrderCmp(const ComboAddress& who) const;
private:
  
  NetmaskTree<SortListOrder> d_sortlist;
};
