#include "sortlist.hh"
#include "dnsrecords.hh"

void SortList::clear()
{
  d_sortlist.clear();
}

int SortList::getMaxOrder(const Netmask& formask) const
{
  int order = 0;

  const auto* place = d_sortlist.lookup(formask);
  if (place != nullptr && place->first == formask) {
    for (const auto& node_order : place->second.d_orders) {
      order = std::max(order, node_order.second);
    }
  }

  return order;
}

void SortList::addEntry(const Netmask& covers, const Netmask& answermask, int order)
{
  if (order < 0) {
    order = getMaxOrder(covers);
    ++order;
  }
  //  cout<<"Adding for netmask "<<formask.toString()<<" the order instruction that "<<valmask.toString()<<" is order "<<order<<endl;
  d_sortlist.insert(covers).second.d_orders.insert(answermask).second = order;
}

std::unique_ptr<SortListOrderCmp> SortList::getOrderCmp(const ComboAddress& who) const
{
  if (!d_sortlist.match(who)) {
    return {};
  }
  const auto* fnd = d_sortlist.lookup(who);
  //  cerr<<"Returning sort order for "<<who.toString()<<", have "<<fnd->second.d_orders.size()<<" entries"<<endl;
  return make_unique<SortListOrderCmp>(fnd->second);
}

// call this with **stable_sort**
bool SortListOrderCmp::operator()(const DNSRecord& lhs, const DNSRecord& rhs) const
{
  bool aAddr = (lhs.d_type == QType::A || lhs.d_type == QType::AAAA);
  bool bAddr = (rhs.d_type == QType::A || rhs.d_type == QType::AAAA);

  // anything address related is always 'larger', rest is equal
  if (aAddr && !bAddr) {
    return false;
  }
  if (!aAddr && bAddr) {
    return true;
  }
  if (!aAddr && !bAddr) {
    return false;
  }

  int aOrder = std::numeric_limits<int>::max();
  int bOrder = aOrder;

  ComboAddress laddr = getAddr(lhs);
  ComboAddress raddr = getAddr(rhs);

  if (d_slo.d_orders.match(laddr)) {
    aOrder = d_slo.d_orders.lookup(laddr)->second;
  }
  if (d_slo.d_orders.match(raddr)) {
    bOrder = d_slo.d_orders.lookup(raddr)->second;
  }
  return aOrder < bOrder;
}
