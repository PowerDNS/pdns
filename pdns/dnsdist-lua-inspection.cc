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
#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-rings.hh"

#include "statnode.hh"

static std::unordered_map<unsigned int, vector<boost::variant<string,double>>> getGenResponses(unsigned int top, boost::optional<int> labels, std::function<bool(const Rings::Response&)> pred)
{
  setLuaNoSideEffect();
  map<DNSName, unsigned int> counts;
  unsigned int total=0;
  {
    for (const auto& shard : g_rings.d_shards) {
      std::lock_guard<std::mutex> rl(shard->respLock);
      if(!labels) {
        for(const auto& a : shard->respRing) {
          if(!pred(a))
            continue;
          counts[a.name]++;
          total++;
        }
      }
      else {
        unsigned int lab = *labels;
        for(const auto& a : shard->respRing) {
          if(!pred(a))
            continue;

          DNSName temp(a.name);
          temp.trimToLabels(lab);
          counts[temp]++;
          total++;
        }
      }
    }
  }
  //      cout<<"Looked at "<<total<<" responses, "<<counts.size()<<" different ones"<<endl;
  vector<pair<unsigned int, DNSName>> rcounts;
  rcounts.reserve(counts.size());
  for(const auto& c : counts)
    rcounts.push_back(make_pair(c.second, c.first.makeLowerCase()));

  sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a,
                                          const decltype(rcounts)::value_type& b) {
         return b.first < a.first;
       });

  std::unordered_map<unsigned int, vector<boost::variant<string,double>>> ret;
  unsigned int count=1, rest=0;
  for(const auto& rc : rcounts) {
    if(count==top+1)
      rest+=rc.first;
    else
      ret.insert({count++, {rc.second.toString(), rc.first, 100.0*rc.first/total}});
  }
  ret.insert({count, {"Rest", rest, total > 0 ? 100.0*rest/total : 100.0}});
  return ret;
}

typedef std::unordered_map<ComboAddress, unsigned int, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual> counts_t;

static counts_t filterScore(const counts_t& counts,
                        double delta, unsigned int rate)
{
  counts_t ret;

  double lim = delta*rate;
  for(const auto& c : counts) {
    if (c.second > lim) {
      ret[c.first] = c.second;
    }
  }

  return ret;
}


typedef std::function<void(const StatNode&, const StatNode::Stat&, const StatNode::Stat&)> statvisitor_t;

static void statNodeRespRing(statvisitor_t visitor, unsigned int seconds)
{
  struct timespec cutoff, now;
  gettime(&now);
  cutoff = now;
  cutoff.tv_sec -= seconds;

  StatNode root;
  for (const auto& shard : g_rings.d_shards) {
    std::lock_guard<std::mutex> rl(shard->respLock);

    for(const auto& c : shard->respRing) {
      if (now < c.when)
        continue;

      if (seconds && c.when < cutoff)
        continue;

      root.submit(c.name, c.dh.rcode, boost::none);
    }
  }

  StatNode::Stat node;
  root.visit([visitor](const StatNode* node_, const StatNode::Stat& self, const StatNode::Stat& children) {
      visitor(*node_, self, children);},  node);
}

static vector<pair<unsigned int, std::unordered_map<string,string> > > getRespRing(boost::optional<int> rcode)
{
  typedef std::unordered_map<string,string>  entry_t;
  vector<pair<unsigned int, entry_t > > ret;

  for (const auto& shard : g_rings.d_shards) {
    std::lock_guard<std::mutex> rl(shard->respLock);

    entry_t e;
    unsigned int count=1;
    for(const auto& c : shard->respRing) {
      if(rcode && (rcode.get() != c.dh.rcode))
        continue;
      e["qname"]=c.name.toString();
      e["rcode"]=std::to_string(c.dh.rcode);
      ret.push_back(std::make_pair(count,e));
      count++;
    }
  }

  return ret;
}

static counts_t exceedRespGen(unsigned int rate, int seconds, std::function<void(counts_t&, const Rings::Response&)> T)
{
  counts_t counts;
  struct timespec cutoff, mintime, now;
  gettime(&now);
  cutoff = mintime = now;
  cutoff.tv_sec -= seconds;

  counts.reserve(g_rings.getNumberOfResponseEntries());

  for (const auto& shard : g_rings.d_shards) {
    std::lock_guard<std::mutex> rl(shard->respLock);
    for(const auto& c : shard->respRing) {

      if(seconds && c.when < cutoff)
        continue;
      if(now < c.when)
        continue;

      T(counts, c);
      if(c.when < mintime)
        mintime = c.when;
    }
  }

  double delta = seconds ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}

static counts_t exceedQueryGen(unsigned int rate, int seconds, std::function<void(counts_t&, const Rings::Query&)> T)
{
  counts_t counts;
  struct timespec cutoff, mintime, now;
  gettime(&now);
  cutoff = mintime = now;
  cutoff.tv_sec -= seconds;

  counts.reserve(g_rings.getNumberOfQueryEntries());

  for (const auto& shard : g_rings.d_shards) {
    std::lock_guard<std::mutex> rl(shard->queryLock);
    for(const auto& c : shard->queryRing) {
      if(seconds && c.when < cutoff)
        continue;
      if(now < c.when)
        continue;
      T(counts, c);
      if(c.when < mintime)
        mintime = c.when;
    }
  }

  double delta = seconds ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}


static counts_t exceedRCode(unsigned int rate, int seconds, int rcode)
{
  return exceedRespGen(rate, seconds, [rcode](counts_t& counts, const Rings::Response& r)
		   {
		     if(r.dh.rcode == rcode)
		       counts[r.requestor]++;
		   });
}

static counts_t exceedRespByterate(unsigned int rate, int seconds)
{
  return exceedRespGen(rate, seconds, [](counts_t& counts, const Rings::Response& r)
		   {
		     counts[r.requestor]+=r.size;
		   });
}

void setupLuaInspection()
{
  g_lua.writeFunction("topClients", [](boost::optional<unsigned int> top_) {
      setLuaNoSideEffect();
      auto top = top_.get_value_or(10);
      map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan > counts;
      unsigned int total=0;
      {
        for (const auto& shard : g_rings.d_shards) {
          std::lock_guard<std::mutex> rl(shard->queryLock);
          for(const auto& c : shard->queryRing) {
            counts[c.requestor]++;
            total++;
          }
        }
      }
      vector<pair<unsigned int, ComboAddress>> rcounts;
      rcounts.reserve(counts.size());
      for(const auto& c : counts)
	rcounts.push_back(make_pair(c.second, c.first));

      sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a,
					      const decltype(rcounts)::value_type& b) {
	     return b.first < a.first;
	   });
      unsigned int count=1, rest=0;
      boost::format fmt("%4d  %-40s %4d %4.1f%%\n");
      for(const auto& rc : rcounts) {
	if(count==top+1)
	  rest+=rc.first;
	else
	  g_outputBuffer += (fmt % (count++) % rc.second.toString() % rc.first % (100.0*rc.first/total)).str();
      }
      g_outputBuffer += (fmt % (count) % "Rest" % rest % (total > 0 ? 100.0*rest/total : 100.0)).str();
    });

  g_lua.writeFunction("getTopQueries", [](unsigned int top, boost::optional<int> labels) {
      setLuaNoSideEffect();
      map<DNSName, unsigned int> counts;
      unsigned int total=0;
      if(!labels) {
        for (const auto& shard : g_rings.d_shards) {
          std::lock_guard<std::mutex> rl(shard->queryLock);
          for(const auto& a : shard->queryRing) {
            counts[a.name]++;
            total++;
          }
        }
      }
      else {
	unsigned int lab = *labels;
        for (const auto& shard : g_rings.d_shards) {
          std::lock_guard<std::mutex> rl(shard->queryLock);
          for(auto a : shard->queryRing) {
            a.name.trimToLabels(lab);
            counts[a.name]++;
            total++;
          }
        }
      }
      // cout<<"Looked at "<<total<<" queries, "<<counts.size()<<" different ones"<<endl;
      vector<pair<unsigned int, DNSName>> rcounts;
      rcounts.reserve(counts.size());
      for(const auto& c : counts)
	rcounts.push_back(make_pair(c.second, c.first.makeLowerCase()));

      sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a,
					      const decltype(rcounts)::value_type& b) {
	     return b.first < a.first;
	   });

      std::unordered_map<unsigned int, vector<boost::variant<string,double>>> ret;
      unsigned int count=1, rest=0;
      for(const auto& rc : rcounts) {
	if(count==top+1)
	  rest+=rc.first;
	else
	  ret.insert({count++, {rc.second.toString(), rc.first, 100.0*rc.first/total}});
      }
      ret.insert({count, {"Rest", rest, total > 0 ? 100.0*rest/total : 100.0}});
      return ret;

    });

  g_lua.executeCode(R"(function topQueries(top, labels) top = top or 10; for k,v in ipairs(getTopQueries(top,labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2], v[3])) end end)");

  g_lua.writeFunction("getResponseRing", []() {
      setLuaNoSideEffect();
      size_t totalEntries = 0;
      std::vector<boost::circular_buffer<Rings::Response>> rings;
      rings.reserve(g_rings.getNumberOfShards());
      for (const auto& shard : g_rings.d_shards) {
        {
          std::lock_guard<std::mutex> rl(shard->respLock);
          rings.push_back(shard->respRing);
        }
        totalEntries += rings.back().size();
      }
      vector<std::unordered_map<string, boost::variant<string, unsigned int> > > ret;
      ret.reserve(totalEntries);
      decltype(ret)::value_type item;
      for (size_t idx = 0; idx < rings.size(); idx++) {
        for(const auto& r : rings[idx]) {
          item["name"]=r.name.toString();
          item["qtype"]=r.qtype;
          item["rcode"]=r.dh.rcode;
          item["usec"]=r.usec;
          ret.push_back(item);
        }
      }
      return ret;
    });

  g_lua.writeFunction("getTopResponses", [](unsigned int top, unsigned int kind, boost::optional<int> labels) {
      return getGenResponses(top, labels, [kind](const Rings::Response& r) { return r.dh.rcode == kind; });
    });

  g_lua.executeCode(R"(function topResponses(top, kind, labels) top = top or 10; kind = kind or 0; for k,v in ipairs(getTopResponses(top, kind, labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");


  g_lua.writeFunction("getSlowResponses", [](unsigned int top, unsigned int msec, boost::optional<int> labels) {
      return getGenResponses(top, labels, [msec](const Rings::Response& r) { return r.usec > msec*1000; });
    });


  g_lua.executeCode(R"(function topSlow(top, msec, labels) top = top or 10; msec = msec or 500; for k,v in ipairs(getSlowResponses(top, msec, labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");

  g_lua.writeFunction("getTopBandwidth", [](unsigned int top) {
      setLuaNoSideEffect();
      return g_rings.getTopBandwidth(top);
    });

  g_lua.executeCode(R"(function topBandwidth(top) top = top or 10; for k,v in ipairs(getTopBandwidth(top)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");

  g_lua.writeFunction("delta", []() {
      setLuaNoSideEffect();
      // we hold the lua lock already!
      for(const auto& d : g_confDelta) {
        struct tm tm;
        localtime_r(&d.first.tv_sec, &tm);
        char date[80];
        strftime(date, sizeof(date)-1, "-- %a %b %d %Y %H:%M:%S %Z\n", &tm);
        g_outputBuffer += date;
        g_outputBuffer += d.second + "\n";
      }
    });

  g_lua.writeFunction("grepq", [](boost::variant<string, vector<pair<int,string> > > inp, boost::optional<unsigned int> limit) {
      setLuaNoSideEffect();
      boost::optional<Netmask>  nm;
      boost::optional<DNSName> dn;
      int msec=-1;

      vector<string> vec;
      auto str=boost::get<string>(&inp);
      if(str)
        vec.push_back(*str);
      else {
        auto v = boost::get<vector<pair<int, string> > >(inp);
        for(const auto& a: v)
          vec.push_back(a.second);
      }

      for(const auto& s : vec) {
        try
          {
            nm = Netmask(s);
          }
        catch(...) {
          if(boost::ends_with(s,"ms") && sscanf(s.c_str(), "%ums", &msec)) {
            ;
          }
          else {
            try { dn=DNSName(s); }
            catch(...)
              {
                g_outputBuffer = "Could not parse '"+s+"' as domain name or netmask";
                return;
              }
          }
        }
      }

      std::vector<Rings::Query> qr;
      std::vector<Rings::Response> rr;
      qr.reserve(g_rings.getNumberOfQueryEntries());
      rr.reserve(g_rings.getNumberOfResponseEntries());
      for (const auto& shard : g_rings.d_shards) {
        {
          std::lock_guard<std::mutex> rl(shard->queryLock);
          for (const auto& entry : shard->queryRing) {
            qr.push_back(entry);
          }
        }
        {
          std::lock_guard<std::mutex> rl(shard->respLock);
          for (const auto& entry : shard->respRing) {
            rr.push_back(entry);
          }
        }
      }

      sort(qr.begin(), qr.end(), [](const decltype(qr)::value_type& a, const decltype(qr)::value_type& b) {
        return b.when < a.when;
      });

      sort(rr.begin(), rr.end(), [](const decltype(rr)::value_type& a, const decltype(rr)::value_type& b) {
        return b.when < a.when;
      });

      unsigned int num=0;
      struct timespec now;
      gettime(&now);

      std::multimap<struct timespec, string> out;

      boost::format      fmt("%-7.1f %-47s %-12s %-5d %-25s %-5s %-6.1f %-2s %-2s %-2s %-s\n");
      g_outputBuffer+= (fmt % "Time" % "Client" % "Server" % "ID" % "Name" % "Type" % "Lat." % "TC" % "RD" % "AA" % "Rcode").str();

      if(msec==-1) {
        for(const auto& c : qr) {
          bool nmmatch=true, dnmatch=true;
          if(nm)
            nmmatch = nm->match(c.requestor);
          if(dn)
            dnmatch = c.name.isPartOf(*dn);
          if(nmmatch && dnmatch) {
            QType qt(c.qtype);
            std::string extra;
            if (c.dh.opcode != 0) {
              extra = " (" + Opcode::to_s(c.dh.opcode) + ")";
            }
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % "" % htons(c.dh.id) % c.name.toString() % qt.getName()  % "" % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") % ("Question" + extra)).str() )) ;

            if(limit && *limit==++num)
              break;
          }
        }
      }
      num=0;


      string extra;
      for(const auto& c : rr) {
        bool nmmatch=true, dnmatch=true, msecmatch=true;
        if(nm)
          nmmatch = nm->match(c.requestor);
        if(dn)
          dnmatch = c.name.isPartOf(*dn);
        if(msec != -1)
          msecmatch=(c.usec/1000 > (unsigned int)msec);

        if(nmmatch && dnmatch && msecmatch) {
          QType qt(c.qtype);
	  if(!c.dh.rcode)
	    extra=". " +std::to_string(htons(c.dh.ancount))+ " answers";
	  else
	    extra.clear();
          if(c.usec != std::numeric_limits<decltype(c.usec)>::max())
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % c.ds.toStringWithPort() % htons(c.dh.id) % c.name.toString()  % qt.getName()  % (c.usec/1000.0) % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") % (RCode::to_s(c.dh.rcode) + extra)).str()  )) ;
          else
            out.insert(make_pair(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % c.ds.toStringWithPort() % htons(c.dh.id) % c.name.toString()  % qt.getName()  % "T.O" % (c.dh.tc ? "TC" : "") % (c.dh.rd? "RD" : "") % (c.dh.aa? "AA" : "") % (RCode::to_s(c.dh.rcode) + extra)).str()  )) ;

          if(limit && *limit==++num)
            break;
        }
      }

      for(const auto& p : out) {
        g_outputBuffer+=p.second;
      }
    });

  g_lua.writeFunction("showResponseLatency", []() {
      setLuaNoSideEffect();
      map<double, unsigned int> histo;
      double bin=100;
      for(int i=0; i < 15; ++i) {
	histo[bin];
	bin*=2;
      }

      double totlat=0;
      unsigned int size=0;
      {
        for (const auto& shard : g_rings.d_shards) {
          std::lock_guard<std::mutex> rl(shard->respLock);
          for(const auto& r : shard->respRing) {
            /* skip actively discovered timeouts */
            if (r.usec == std::numeric_limits<unsigned int>::max())
              continue;

            ++size;
            auto iter = histo.lower_bound(r.usec);
            if(iter != histo.end())
              iter->second++;
            else
              histo.rbegin()++;
            totlat+=r.usec;
          }
        }
      }

      if (size == 0) {
        g_outputBuffer = "No traffic yet.\n";
        return;
      }

      g_outputBuffer = (boost::format("Average response latency: %.02f msec\n") % (0.001*totlat/size)).str();
      double highest=0;

      for(auto iter = histo.cbegin(); iter != histo.cend(); ++iter) {
	highest=std::max(highest, iter->second*1.0);
      }
      boost::format fmt("%7.2f\t%s\n");
      g_outputBuffer += (fmt % "msec" % "").str();

      for(auto iter = histo.cbegin(); iter != histo.cend(); ++iter) {
	int stars = (70.0 * iter->second/highest);
	char c='*';
	if(!stars && iter->second) {
	  stars=1; // you get 1 . to show something is there..
	  if(70.0*iter->second/highest > 0.5)
	    c=':';
	  else
	    c='.';
	}
	g_outputBuffer += (fmt % (iter->first/1000.0) % string(stars, c)).str();
      }
    });

  g_lua.writeFunction("showTCPStats", [] {
      setLuaNoSideEffect();
      ostringstream ret;
      boost::format fmt("%-12d %-12d %-12d %-12d");
      ret << (fmt % "Workers" % "Max Workers" % "Queued" % "Max Queued") << endl;
      ret << (fmt % g_tcpclientthreads->getThreadsCount() % g_maxTCPClientThreads % g_tcpclientthreads->getQueuedCount() % g_maxTCPQueuedConnections) << endl;
      ret << endl;

      ret << "Query distribution mode is: " << std::string(g_useTCPSinglePipe ? "single queue" : "per-thread queues") << endl;
      ret << endl;

      ret << "Frontends:" << endl;
      fmt = boost::format("%-3d %-20.20s %-20d %-20d %-25d %-20d %-20d %-20d %-20f %-20f %-20d %-20d %-25d %-25d %-15d %-15d %-15d %-15d %-15d");
      ret << (fmt % "#" % "Address" % "Connections" % "Died reading query" % "Died sending response" % "Gave up" % "Client timeouts" % "Downstream timeouts" % "Avg queries/conn" % "Avg duration" % "TLS new sessions" % "TLS Resumptions" % "TLS unknown ticket keys" % "TLS inactive ticket keys" % "TLS 1.0" % "TLS 1.1" % "TLS 1.2" % "TLS 1.3" % "TLS other") << endl;

      size_t counter = 0;
      for(const auto& f : g_frontends) {
        ret << (fmt % counter % f->local.toStringWithPort() % f->tcpCurrentConnections % f->tcpDiedReadingQuery % f->tcpDiedSendingResponse % f->tcpGaveUp % f->tcpClientTimeouts % f->tcpDownstreamTimeouts % f->tcpAvgQueriesPerConnection % f->tcpAvgConnectionDuration % f->tlsNewSessions % f->tlsResumptions % f->tlsUnknownTicketKey % f->tlsInactiveTicketKey % f->tls10queries % f->tls11queries % f->tls12queries % f->tls13queries % f->tlsUnknownqueries) << endl;
        ++counter;
      }
      ret << endl;

      ret << "Backends:" << endl;
      fmt = boost::format("%-3d %-20.20s %-20.20s %-20d %-20d %-25d %-20d %-20d %-20d %-20f %-20f");
      ret << (fmt % "#" % "Name" % "Address" % "Connections" % "Died sending query" % "Died reading response" % "Gave up" % "Read timeouts" % "Write timeouts" % "Avg queries/conn" % "Avg duration") << endl;

      auto states = g_dstates.getLocal();
      counter = 0;
      for(const auto& s : *states) {
        ret << (fmt % counter % s->name % s->remote.toStringWithPort() % s->tcpCurrentConnections % s->tcpDiedSendingQuery % s->tcpDiedReadingResponse % s->tcpGaveUp % s->tcpReadTimeouts % s->tcpWriteTimeouts % s->tcpAvgQueriesPerConnection % s->tcpAvgConnectionDuration) << endl;
        ++counter;
      }

      g_outputBuffer=ret.str();
    });

  g_lua.writeFunction("showTLSErrorCounters", [] {
      setLuaNoSideEffect();
      ostringstream ret;
      boost::format fmt("%-3d %-20.20s %-23d %-23d %-23d %-23d %-23d %-23d %-23d %-23d");

      ret << (fmt % "#" % "Address" % "DH key too small" % "Inappropriate fallback" % "No shared cipher" % "Unknown cipher type" % "Unknown exchange type" % "Unknown protocol" % "Unsupported EC" % "Unsupported protocol") << endl;

      size_t counter = 0;
      for(const auto& f : g_frontends) {
        if (!f->hasTLS()) {
          continue;
        }
        const TLSErrorCounters* errorCounters = nullptr;
        if (f->tlsFrontend != nullptr) {
          errorCounters = &f->tlsFrontend->d_tlsCounters;
        }
        else if (f->dohFrontend != nullptr) {
          errorCounters = &f->dohFrontend->d_tlsCounters;
        }
        if (errorCounters == nullptr) {
          continue;
        }

        ret << (fmt % counter % f->local.toStringWithPort() % errorCounters->d_dhKeyTooSmall % errorCounters->d_inappropriateFallBack % errorCounters->d_noSharedCipher % errorCounters->d_unknownCipherType % errorCounters->d_unknownKeyExchangeType % errorCounters->d_unknownProtocol % errorCounters->d_unsupportedEC % errorCounters->d_unsupportedProtocol) << endl;
        ++counter;
      }
      ret << endl;

      g_outputBuffer=ret.str();
    });

  g_lua.writeFunction("dumpStats", [] {
      setLuaNoSideEffect();
      vector<string> leftcolumn, rightcolumn;

      boost::format fmt("%-23s\t%+11s");
      g_outputBuffer.clear();
      auto entries = g_stats.entries;
      sort(entries.begin(), entries.end(),
	   [](const decltype(entries)::value_type& a, const decltype(entries)::value_type& b) {
	     return a.first < b.first;
	   });
      boost::format flt("    %9.1f");
      for(const auto& e : entries) {
	string second;
	if(const auto& val = boost::get<DNSDistStats::stat_t*>(&e.second))
	  second=std::to_string((*val)->load());
	else if (const auto& dval = boost::get<double*>(&e.second))
	  second=(flt % (**dval)).str();
	else
	  second=std::to_string((*boost::get<DNSDistStats::statfunction_t>(&e.second))(e.first));

	if(leftcolumn.size() < g_stats.entries.size()/2)
	  leftcolumn.push_back((fmt % e.first % second).str());
	else
	  rightcolumn.push_back((fmt % e.first % second).str());
      }

      auto leftiter=leftcolumn.begin(), rightiter=rightcolumn.begin();
      boost::format clmn("%|0t|%1% %|39t|%2%\n");

      for(;leftiter != leftcolumn.end() || rightiter != rightcolumn.end();) {
	string lentry, rentry;
	if(leftiter!= leftcolumn.end()) {
	  lentry = *leftiter;
	  leftiter++;
	}
	if(rightiter!= rightcolumn.end()) {
	  rentry = *rightiter;
	  rightiter++;
	}
	g_outputBuffer += (clmn % lentry % rentry).str();
      }
    });

  g_lua.writeFunction("exceedServFails", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRCode(rate, seconds, RCode::ServFail);
    });
  g_lua.writeFunction("exceedNXDOMAINs", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRCode(rate, seconds, RCode::NXDomain);
    });

  g_lua.writeFunction("exceedRespByterate", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRespByterate(rate, seconds);
    });

  g_lua.writeFunction("exceedQTypeRate", [](uint16_t type, unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedQueryGen(rate, seconds, [type](counts_t& counts, const Rings::Query& q) {
	  if(q.qtype==type)
	    counts[q.requestor]++;
	});
    });

  g_lua.writeFunction("exceedQRate", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedQueryGen(rate, seconds, [](counts_t& counts, const Rings::Query& q) {
          counts[q.requestor]++;
	});
    });

  g_lua.writeFunction("getRespRing", getRespRing);

  /* StatNode */
  g_lua.registerFunction<StatNode, unsigned int()>("numChildren",
                                                   [](StatNode& sn) -> unsigned int {
                                                     return sn.children.size();
                                                   } );
  g_lua.registerMember("fullname", &StatNode::fullname);
  g_lua.registerMember("labelsCount", &StatNode::labelsCount);
  g_lua.registerMember("servfails", &StatNode::Stat::servfails);
  g_lua.registerMember("nxdomains", &StatNode::Stat::nxdomains);
  g_lua.registerMember("queries", &StatNode::Stat::queries);

  g_lua.writeFunction("statNodeRespRing", [](statvisitor_t visitor, boost::optional<unsigned int> seconds) {
      statNodeRespRing(visitor, seconds ? *seconds : 0);
    });

  /* DynBlockRulesGroup */
  g_lua.writeFunction("dynBlockRulesGroup", []() { return std::make_shared<DynBlockRulesGroup>(); });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>)>("setQueryRate", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate) {
      if (group) {
        group->setQueryRate(rate, warningRate ? *warningRate : 0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None);
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>)>("setResponseByteRate", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate) {
      if (group) {
        group->setResponseByteRate(rate, warningRate ? *warningRate : 0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None);
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, DynBlockRulesGroup::smtVisitor_t)>("setSuffixMatchRule", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, DynBlockRulesGroup::smtVisitor_t visitor) {
      if (group) {
        group->setSuffixMatchRule(seconds, reason, blockDuration, action ? *action : DNSAction::Action::None, visitor);
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, dnsdist_ffi_stat_node_visitor_t)>("setSuffixMatchRuleFFI", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, dnsdist_ffi_stat_node_visitor_t visitor) {
      if (group) {
        group->setSuffixMatchRuleFFI(seconds, reason, blockDuration, action ? *action : DNSAction::Action::None, visitor);
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(uint8_t, unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>)>("setRCodeRate", [](std::shared_ptr<DynBlockRulesGroup>& group, uint8_t rcode, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate) {
      if (group) {
        group->setRCodeRate(rcode, rate, warningRate ? *warningRate : 0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None);
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(uint16_t, unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>)>("setQTypeRate", [](std::shared_ptr<DynBlockRulesGroup>& group, uint16_t qtype, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate) {
      if (group) {
        group->setQTypeRate(qtype, rate, warningRate ? *warningRate : 0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None);
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(boost::variant<std::string, std::vector<std::pair<int, std::string>>>)>("excludeRange", [](std::shared_ptr<DynBlockRulesGroup>& group, boost::variant<std::string, std::vector<std::pair<int, std::string>>> ranges) {
      if (ranges.type() == typeid(std::vector<std::pair<int, std::string>>)) {
        for (const auto& range : *boost::get<std::vector<std::pair<int, std::string>>>(&ranges)) {
          group->excludeRange(Netmask(range.second));
        }
      }
      else {
        group->excludeRange(Netmask(*boost::get<std::string>(&ranges)));
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(boost::variant<std::string, std::vector<std::pair<int, std::string>>>)>("includeRange", [](std::shared_ptr<DynBlockRulesGroup>& group, boost::variant<std::string, std::vector<std::pair<int, std::string>>> ranges) {
      if (ranges.type() == typeid(std::vector<std::pair<int, std::string>>)) {
        for (const auto& range : *boost::get<std::vector<std::pair<int, std::string>>>(&ranges)) {
          group->includeRange(Netmask(range.second));
        }
      }
      else {
        group->includeRange(Netmask(*boost::get<std::string>(&ranges)));
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(boost::variant<std::string, std::vector<std::pair<int, std::string>>>)>("excludeDomains", [](std::shared_ptr<DynBlockRulesGroup>& group, boost::variant<std::string, std::vector<std::pair<int, std::string>>> domains) {
      if (domains.type() == typeid(std::vector<std::pair<int, std::string>>)) {
        for (const auto& range : *boost::get<std::vector<std::pair<int, std::string>>>(&domains)) {
          group->excludeDomain(DNSName(range.second));
        }
      }
      else {
        group->excludeDomain(DNSName(*boost::get<std::string>(&domains)));
      }
    });
  g_lua.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)()>("apply", [](std::shared_ptr<DynBlockRulesGroup>& group) {
    group->apply();
  });
  g_lua.registerFunction("setQuiet", &DynBlockRulesGroup::setQuiet);
  g_lua.registerFunction("toString", &DynBlockRulesGroup::toString);
}
