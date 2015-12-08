#include "dnsdist.hh"
#include "dnsrulactions.hh"
#include <thread>
#include "dolog.hh"
#include "sodcrypto.hh"
#include "base64.hh"
#include "lock.hh"
#include <map>
#include <fstream>

map<ComboAddress,int> filterScore(const map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan >& counts, 
				  double delta, int rate)
{
  std::multimap<unsigned int,ComboAddress> score;
  for(const auto& e : counts) 
    score.insert({e.second, e.first});

  map<ComboAddress,int> ret;
  
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
  struct timespec cutoff, mintime, now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  cutoff = mintime = now;
  cutoff.tv_sec -= seconds;
  
  for(const auto& c : g_rings.respRing) {
    if(seconds && c.when < cutoff)
      continue;
    if(now < c.when)
      continue;

    T(counts, c);
    if(c.when < mintime)
      mintime = c.when;
  }
  double delta = seconds ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}

map<ComboAddress,int> exceedQueryGen(int rate, int seconds, std::function<void(counts_t&, const Rings::Query&)> T) 
{
  counts_t counts;
  struct timespec cutoff, mintime, now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  cutoff = mintime = now;
  cutoff.tv_sec -= seconds;

  ReadLock rl(&g_rings.queryLock);
  for(const auto& c : g_rings.queryRing) {
    if(seconds && c.when < cutoff)
      continue;
    if(now < c.when)
      continue;
    T(counts, c);
    if(c.when < mintime)
      mintime = c.when;
  }
  double delta = seconds ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}


map<ComboAddress,int> exceedRCode(int rate, int seconds, int rcode) 
{
  return exceedRespGen(rate, seconds, [rcode](counts_t& counts, const Rings::Response& r) 
		   {
		     if(r.dh.rcode == rcode)
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
  typedef NetmaskTree<DynBlock> nmts_t;
  g_lua.writeFunction("newCA", [](const std::string& name) { return ComboAddress(name); });
  g_lua.writeFunction("newNMG", []() { return nmts_t(); });
  g_lua.registerFunction<void(nmts_t::*)(const ComboAddress&, const std::string&, boost::optional<int> seconds)>("add", 
														 [](nmts_t& s, const ComboAddress& ca, const std::string& msg, boost::optional<int> seconds) 
							       { 
								 struct timespec until;
								 clock_gettime(CLOCK_MONOTONIC, &until);
								 until.tv_sec += seconds ? *seconds : 10;
								 
								 s.insert(Netmask(ca)).second={msg, until};
							       });

  g_lua.writeFunction("setDynBlockNMG", [](const nmts_t& nmg) {
      g_dynblockNMG.setState(nmg);
    });

  g_lua.writeFunction("showDynBlocks", []() {
      auto slow = g_dynblockNMG.getCopy();
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      boost::format fmt("%-24s %8d %8d %s\n");
      g_outputBuffer = (fmt % "Netmask" % "Seconds" % "Blocks" % "Reason").str();
      for(const auto& e: slow) {
	if(now < e->second.until)
	  g_outputBuffer+= (fmt % e->first.toString() % (e->second.until.tv_sec - now.tv_sec) % e->second.blocks % e->second.reason).str();
      }
    });

  g_lua.writeFunction("clearDynBlocks", []() {
      nmts_t nmg;
      g_dynblockNMG.setState(nmg);
    });

  g_lua.writeFunction("addDynBlocks", 
			  [](const map<ComboAddress,int>& m, const std::string& msg, boost::optional<int> seconds) { 
			   auto slow = g_dynblockNMG.getCopy();
			   struct timespec until, now;
			   clock_gettime(CLOCK_MONOTONIC, &now);
			   until=now;
                           int actualSeconds = seconds ? *seconds : 10;
			   until.tv_sec += actualSeconds; 
			   for(const auto& capair : m) {
			     unsigned int count;
			     if(auto got = slow.lookup(Netmask(capair.first))) {
			       if(until < got->second.until) // had a longer policy
				 continue;
			       if(now < got->second.until) // don't inherit count on expired entry
				 count=got->second.blocks;
			     }
			     DynBlock db{msg,until};
			     db.blocks=count;
                             warnlog("Inserting dynamic block for %s for %d seconds: %s", capair.first.toString(), actualSeconds, msg);
			     slow.insert(Netmask(capair.first)).second=db;
			   }
			   g_dynblockNMG.setState(slow);
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

  g_lua.writeFunction("topBandwidth", [](unsigned int top) {
      auto res = g_rings.getTopBandwidth(top);
      boost::format fmt("%7d  %s\n");
      for(const auto& l : res) {
	g_outputBuffer += (fmt % l.first % l.second.toString()).str();
      }
    });

  g_lua.writeFunction("grepq", [](const std::string& s, boost::optional<unsigned int> limit) {
      boost::optional<Netmask>  nm;
      boost::optional<DNSName> dn;
      try 
      {
        nm = Netmask(s);
      }
      catch(...) {
        try { dn=DNSName(s); }
        catch(...) 
          {
            g_outputBuffer = "Could not parse '"+s+"' as domain name or netmask";
            return;
          }
      }

      decltype(g_rings.queryRing) qr;
      decltype(g_rings.respRing) rr;
      {
        ReadLock rl(&g_rings.queryLock);
        qr=g_rings.queryRing;
      }
      sort(qr.begin(), qr.end(), [](const decltype(qr)::value_type& a, const decltype(qr)::value_type& b) {
        return b.when < a.when;
      });
      {
	std::lock_guard<std::mutex> lock(g_rings.respMutex);
        rr=g_rings.respRing;
      }

      sort(rr.begin(), rr.end(), [](const decltype(rr)::value_type& a, const decltype(rr)::value_type& b) {
        return b.when < a.when;
      });
      
      unsigned int num=0;
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
            
      std::multimap<struct timespec, string> out;

      boost::format      fmt("%-7.1f %-47s %-5d %-25s %-5s %-4.1f %-2s %-2s %-2s %s\n");
      g_outputBuffer+= (fmt % "Time" % "Client" % "ID" % "Name" % "Type" % "Lat." % "TC" % "RD" % "AA" % "Rcode").str();

      for(const auto& c : qr) {
        if((nm && nm->match(c.requestor)) || (dn && c.name.isPartOf(*dn)))  {
          QType qt(c.qtype);
          out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % htons(c.dh.id) % c.name.toString() % qt.getName()  % "" % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") %  "Question").str()  )) ;

          if(limit && *limit==++num)
            break;
        }
      }
      num=0;



      for(const auto& c : rr) {
        if((nm && nm->match(c.requestor)) || (dn && c.name.isPartOf(*dn)))  {
          QType qt(c.qtype);
          out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % htons(c.dh.id) % c.name.toString()  % qt.getName()  % (c.usec/1000.0) % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") % RCode::to_s(c.dh.rcode)).str()  )) ;

          if(limit && *limit==++num)
            break;
        }
      }

      for(const auto& p : out) {
        g_outputBuffer+=p.second;
      }
    });
}
