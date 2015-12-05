#include "dnsdist.hh"
#include "lock.hh"

unsigned int Rings::numDistinctRequestors()
{
  std::set<ComboAddress, ComboAddress::addressOnlyLessThan> s;
  WriteLock wl(&queryLock);
  for(const auto& q : queryRing)
    s.insert(q.requestor);
  return s.size();
}

vector<pair<unsigned int,ComboAddress> > Rings::getTopBandwidth(unsigned int numentries)
{
  map<ComboAddress, unsigned int, ComboAddress::addressOnlyLessThan> counts;
  {
    WriteLock wl(&queryLock);
    for(const auto& q : queryRing)
      counts[q.requestor]+=q.size;
  }

  {
    std::lock_guard<std::mutex> lock(respMutex);
    for(const auto& r : respRing)
      counts[r.requestor]+=r.size;
  }

  typedef vector<pair<unsigned int, ComboAddress>> ret_t;
  ret_t ret;
  for(const auto& p : counts)
    ret.push_back({p.second, p.first});
  numentries = ret.size() < numentries ? ret.size() : numentries;
  partial_sort(ret.begin(), ret.begin()+numentries, ret.end(), [](const ret_t::value_type&a, const ret_t::value_type&b)
	       {
		 return(b.second < a.second);
	       });
  ret.resize(numentries);
  return ret;
}
