#include "dnsdist.hh"
#include "dnsrulactions.hh"
#include <thread>
#include "dolog.hh"
#include "sodcrypto.hh"
#include "base64.hh"
#include <map>
#include <fstream>


static double DiffTime(const struct timespec& first, const struct timespec& second)
{
  int seconds=second.tv_sec - first.tv_sec;
  int nseconds=second.tv_nsec - first.tv_nsec;
  
  if(nseconds < 0) {
    seconds-=1;
    nseconds+=1000000000;
  }
  return seconds + nseconds/1000000000.0;
}

map<ComboAddress,int> filterScore(const map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan >& counts, 
				  struct timespec& mintime,
				  struct timespec& maxtime, int rate)
{
  std::multimap<unsigned int,ComboAddress> score;
  for(const auto& e : counts) 
    score.insert({e.second, e.first});

  map<ComboAddress,int> ret;
  
  double delta=DiffTime(mintime, maxtime);
  double lim = delta*rate;
  
  for(auto s = score.crbegin(); s != score.crend() && s->first > lim; ++s) {
    ret[s->second]=s->first;
  }
  return ret;
}


typedef   map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan > counts_t;
map<ComboAddress,int> exceedRespGen(int rate, int seconds, std::function<void(counts_t&, const Rings::Response&)> T) 
{
  counts_t counts;
  struct timespec mintime, maxtime, cutoff;
  clock_gettime(CLOCK_MONOTONIC, &maxtime);
  mintime=cutoff=maxtime;
  cutoff.tv_sec -= seconds;
  
  for(const auto& c : g_rings.respRing) {
    if(seconds && c.when < cutoff)
      continue;

    T(counts, c);
    if(c.when < mintime)
      mintime = c.when;
  }
  
  return filterScore(counts, mintime, maxtime, rate);
}


map<ComboAddress,int> exceedRCode(int rate, int seconds, int rcode) 
{
  return exceedRespGen(rate, seconds, [rcode](counts_t& counts, const Rings::Response& r) 
		   {
		     if(r.rcode == rcode)
		       counts[r.requestor]++;
		   });
}

map<ComboAddress,int> exceedRespByterate(int rate, int seconds) 
{
  return exceedRespGen(rate, seconds, [](counts_t& counts, const Rings::Response& r) 
		   {
		     counts[r.requestor]+=r.size;
		   });
}


void moreLua()
{
  g_lua.writeFunction("newCA", [](const std::string& name) { return ComboAddress(name); });
  g_lua.writeFunction("newNMG", []() { return std::make_shared<NetmaskGroup>(); });
  g_lua.registerFunction<void(NetmaskGroup::*)(const ComboAddress&)>("add", 
								     [](NetmaskGroup& s, const ComboAddress& ca) { s.addMask(Netmask(ca)); });

  g_lua.registerFunction<void(NetmaskGroup::*)(const map<ComboAddress,int>&)>("add", 
									      [](NetmaskGroup& s, const map<ComboAddress,int>& m) { 
										for(const auto& capair : m)
										  s.addMask(Netmask(capair.first)); 
									      });


  g_lua.registerFunction<bool(NetmaskGroup::*)(const ComboAddress&)>("match", 
								     [](NetmaskGroup& s, const ComboAddress& ca) { return s.match(ca); });


  g_lua.writeFunction("exceedServfails", [](unsigned int rate, int seconds) {
      return exceedRCode(rate, seconds, RCode::ServFail);
    });
  g_lua.writeFunction("exceedNXDOMAINs", [](unsigned int rate, int seconds) {
      return exceedRCode(rate, seconds, RCode::NXDomain);
    });

  g_lua.writeFunction("exceedRespByterate", [](unsigned int rate, int seconds) {
      return exceedRespByterate(rate, seconds);
    });


}
