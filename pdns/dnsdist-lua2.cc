#include "dnsdist.hh"
#include "dnsrulactions.hh"
#include <thread>
#include "dolog.hh"
#include "sodcrypto.hh"
#include "base64.hh"
#include "lock.hh"
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

map<ComboAddress,int> exceedQueryGen(int rate, int seconds, std::function<void(counts_t&, const Rings::Query&)> T) 
{
  counts_t counts;
  struct timespec mintime, maxtime, cutoff;
  clock_gettime(CLOCK_MONOTONIC, &maxtime);
  mintime=cutoff=maxtime;
  cutoff.tv_sec -= seconds;
  
  ReadLock rl(&g_rings.queryLock);
  for(const auto& c : g_rings.queryRing) {
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
  typedef NetmaskTree<string> nmts_t;
  g_lua.writeFunction("newCA", [](const std::string& name) { return ComboAddress(name); });
  g_lua.writeFunction("newNMG", []() { return nmts_t(); });
  g_lua.registerFunction<void(nmts_t::*)(const ComboAddress&, const std::string&)>("add", 
							       [](nmts_t& s, const ComboAddress& ca, const std::string& msg) 
							       { 
								 s.insert(Netmask(ca)).second=msg; 
							       });

  g_lua.writeFunction("setDynBlockNMG", [](const nmts_t& nmg) {
      g_dynblockNMG.setState(nmg);
    });

  g_lua.writeFunction("showDynBlocks", []() {
      auto slow = g_dynblockNMG.getCopy();
      for(const auto& e: slow) {
	g_outputBuffer+=e->first.toString()+"\t"+e->second+"\n";
      }
    });

  g_lua.registerFunction<void(nmts_t::*)(const map<ComboAddress,int>&, const std::string&)>("add", 
									[](nmts_t& s, const map<ComboAddress,int>& m, const std::string& msg) { 
										for(const auto& capair : m)
										  s.insert(Netmask(capair.first)).second=msg;
									      });


  g_lua.registerFunction<bool(nmts_t::*)(const ComboAddress&)>("match", 
								     [](nmts_t& s, const ComboAddress& ca) { return s.match(ca); });

  g_lua.writeFunction("exceedServfails", [](unsigned int rate, int seconds) {
      return exceedRCode(rate, seconds, RCode::ServFail);
    });
  g_lua.writeFunction("exceedNXDOMAINs", [](unsigned int rate, int seconds) {
      return exceedRCode(rate, seconds, RCode::NXDomain);
    });



  g_lua.writeFunction("exceedRespByterate", [](unsigned int rate, int seconds) {
      return exceedRespByterate(rate, seconds);
    });

  g_lua.writeFunction("exceedQTypeRate", [](uint16_t type, unsigned int rate, int seconds) {
      return exceedQueryGen(rate, seconds, [type](counts_t& counts, const Rings::Query& q) {
	  if(q.qtype==type)
	    counts[q.requestor]++;
	});


    });


}
