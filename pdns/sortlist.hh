#pragma once
#include "iputils.hh"
#include "dnsrecords.hh"

struct SortListOrder
{
  NetmaskTree<int> d_orders;
};


struct SortListOrderCmp
{
  SortListOrderCmp(SortListOrder slo) : d_slo(slo) {}
  bool operator()(const ComboAddress& a, const ComboAddress& b) const;
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
