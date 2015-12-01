#include "sortlist.hh"
#include "dnsrecords.hh"

void SortList::clear()
{
  d_sortlist.clear();
}

int SortList::getMaxOrder(const Netmask& formask) const
{
  int order=0;
  
  auto place = d_sortlist.lookup(formask);
  if(place && place->first == formask) {
    for(const auto& o : place->second.d_orders) 
      order = std::max(order, o->second); // aki, shouldn't this be o.second?
  }
  
  return order;
}

void SortList::addEntry(const Netmask& formask, const Netmask& valmask, int order)
{
  if(order < 0) {
    order=getMaxOrder(formask);
    ++order;
  }
  //  cout<<"Adding for netmask "<<formask.toString()<<" the order instruction that "<<valmask.toString()<<" is order "<<order<<endl;
  d_sortlist.insert(formask).second.d_orders.insert(valmask).second=order;
}

std::unique_ptr<SortListOrderCmp> SortList::getOrderCmp(const ComboAddress& who) const
{
  if(!d_sortlist.match(who)) {
    return std::unique_ptr<SortListOrderCmp>();
  }
  auto fnd = d_sortlist.lookup(who);
  //  cerr<<"Returning sort order for "<<who.toString()<<", have "<<fnd->second.d_orders.size()<<" entries"<<endl;
  return make_unique<SortListOrderCmp>(fnd->second);
}

bool SortListOrderCmp::operator()(const ComboAddress& a, const ComboAddress& b) const
{
  int aOrder=std::numeric_limits<int>::max();
  int bOrder=aOrder;

  if(d_slo.d_orders.match(a))
    aOrder = d_slo.d_orders.lookup(a)->second;
  if(d_slo.d_orders.match(b))
    bOrder = d_slo.d_orders.lookup(b)->second;

  return aOrder < bOrder;
}

static ComboAddress getAddr(const DNSRecord& dr)
{
  if(auto addr=getRR<ARecordContent>(dr)) {
    return addr->getCA();
  }
  else
    return getRR<AAAARecordContent>(dr)->getCA();
}
bool SortListOrderCmp::operator()(const DNSRecord& ar, const DNSRecord& br) const
{
  if(ar.d_type < br.d_type)
    return true;
  if(ar.d_type > br.d_type)
    return false;

  if(ar.d_type != QType::A && ar.d_type != QType::AAAA) 
    return false;  // all other types are equal among themselves

  int aOrder=std::numeric_limits<int>::max();
  int bOrder=aOrder;

  ComboAddress a=getAddr(ar), b=getAddr(br);
  
  if(d_slo.d_orders.match(a))
    aOrder = d_slo.d_orders.lookup(a)->second;
  else {
    //    cout<<"Could not find anything for "<<a.toString()<<" in our orders!"<<endl;
  }
  if(d_slo.d_orders.match(b))
    bOrder = d_slo.d_orders.lookup(b)->second;
  else {
    //    cout<<"Could not find anything for "<<b.toString()<<" in our orders!"<<endl;
  }
  return aOrder < bOrder;
}
