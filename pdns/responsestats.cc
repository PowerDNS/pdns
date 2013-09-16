#include "responsestats.hh"
#include <limits>
#include "namespaces.hh"

ResponseStats::ResponseStats()
{
  d_qtypecounters.resize(std::numeric_limits<uint16_t>::max()+1);
  d_sizecounters.push_back(make_pair(20,0));
  d_sizecounters.push_back(make_pair(40,0));
  d_sizecounters.push_back(make_pair(60,0));
  d_sizecounters.push_back(make_pair(80,0));
  d_sizecounters.push_back(make_pair(100,0));
  d_sizecounters.push_back(make_pair(150,0));
  for(int n=200; n < 65000 ; n+=200)
    d_sizecounters.push_back(make_pair(n,0));
  d_sizecounters.push_back(make_pair(std::numeric_limits<uint16_t>::max(),0));
}

static bool pcomp(const pair<uint16_t, uint64_t>&a , const pair<uint16_t, uint64_t>&b)
{
  return a.first < b.first;
} 

void ResponseStats::submitResponse(uint16_t qtype, uint16_t respsize, bool udpOrTCP) 
{
  d_qtypecounters[qtype]++;
  pair<uint16_t, uint64_t> s(respsize, 0);
  sizecounters_t::iterator iter = std::upper_bound(d_sizecounters.begin(), d_sizecounters.end(), s, pcomp);
  if(iter!= d_sizecounters.begin())
    --iter;
  iter->second++;
}

map<uint16_t, uint64_t> ResponseStats::getQTypeResponseCounts()
{
  map<uint16_t, uint64_t> ret;
  uint64_t count;
  for(int i = 0 ; i < d_qtypecounters.size() ; ++i) {
    count= d_qtypecounters[i];
    if(count)
      ret[i]=count;
  }
  return ret;
}

map<uint16_t, uint64_t> ResponseStats::getSizeResponseCounts()
{
  map<uint16_t, uint64_t> ret;
  for(sizecounters_t::const_iterator iter = d_sizecounters.begin();
      iter != d_sizecounters.end();
      ++iter) {
    ret[iter->first]=iter->second;
  }
  return ret;
}
