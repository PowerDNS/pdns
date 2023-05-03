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
#include <fcntl.h>

#include "dnsdist.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-tcp.hh"

#include "statnode.hh"

#ifndef DISABLE_TOP_N_BINDINGS
static LuaArray<std::vector<boost::variant<string,double>>> getGenResponses(uint64_t top, boost::optional<int> labels, std::function<bool(const Rings::Response&)> pred)
{
  setLuaNoSideEffect();
  map<DNSName, unsigned int> counts;
  unsigned int total=0;
  {
    for (const auto& shard : g_rings.d_shards) {
      auto rl = shard->respRing.lock();
      if (!labels) {
        for(const auto& a : *rl) {
          if(!pred(a))
            continue;
          counts[a.name]++;
          total++;
        }
      }
      else {
        unsigned int lab = *labels;
        for(const auto& a : *rl) {
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
  for (const auto& c : counts)
    rcounts.emplace_back(c.second, c.first.makeLowerCase());

  sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& a,
                                          const decltype(rcounts)::value_type& b) {
         return b.first < a.first;
       });

  LuaArray<vector<boost::variant<string,double>>> ret;
  ret.reserve(std::min(rcounts.size(), static_cast<size_t>(top + 1U)));
  int count = 1;
  unsigned int rest = 0;
  for (const auto& rc : rcounts) {
    if (count == static_cast<int>(top + 1)) {
      rest+=rc.first;
    }
    else {
      ret.push_back({count++, {rc.second.toString(), rc.first, 100.0*rc.first/total}});
    }
  }

  if (total > 0) {
    ret.push_back({count, {"Rest", rest, 100.0*rest/total}});
  }
  else {
    ret.push_back({count, {"Rest", rest, 100.0 }});
  }

  return ret;
}
#endif /* DISABLE_TOP_N_BINDINGS */

#ifndef DISABLE_DYNBLOCKS
#ifndef DISABLE_DEPRECATED_DYNBLOCK

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

using statvisitor_t = std::function<void(const StatNode&, const StatNode::Stat&, const StatNode::Stat&)>;

static void statNodeRespRing(statvisitor_t visitor, uint64_t seconds)
{
  struct timespec cutoff, now;
  gettime(&now);
  cutoff = now;
  cutoff.tv_sec -= seconds;

  StatNode root;
  for (const auto& shard : g_rings.d_shards) {
    auto rl = shard->respRing.lock();

    for(const auto& c : *rl) {
      if (now < c.when){
        continue;
      }

      if (seconds && c.when < cutoff) {
        continue;
      }

      bool hit = c.ds.sin4.sin_family == 0;
      if (!hit && c.ds.isIPv4() && c.ds.sin4.sin_addr.s_addr == 0 && c.ds.sin4.sin_port == 0) {
        hit = true;
      }

      root.submit(c.name, ((c.dh.rcode == 0 && c.usec == std::numeric_limits<unsigned int>::max()) ? -1 : c.dh.rcode), c.size, hit, boost::none);
    }
  }

  StatNode::Stat node;
  root.visit([visitor](const StatNode* node_, const StatNode::Stat& self, const StatNode::Stat& children) {
      visitor(*node_, self, children);},  node);
}

static LuaArray<LuaAssociativeTable<std::string>> getRespRing(boost::optional<int> rcode)
{
  typedef LuaAssociativeTable<std::string> entry_t;
  LuaArray<entry_t> ret;

  for (const auto& shard : g_rings.d_shards) {
    auto rl = shard->respRing.lock();

    int count = 1;
    for (const auto& c : *rl) {
      if (rcode && (rcode.get() != c.dh.rcode)) {
        continue;
      }
      entry_t e;
      e["qname"] = c.name.toString();
      e["rcode"] = std::to_string(c.dh.rcode);
      ret.emplace_back(count, std::move(e));
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
    auto rl = shard->respRing.lock();
    for(const auto& c : *rl) {

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
    auto rl = shard->queryRing.lock();
    for(const auto& c : *rl) {
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

#endif /* DISABLE_DEPRECATED_DYNBLOCK */
#endif /* DISABLE_DYNBLOCKS */

void setupLuaInspection(LuaContext& luaCtx)
{
#ifndef DISABLE_TOP_N_BINDINGS
  luaCtx.writeFunction("topClients", [](boost::optional<uint64_t> top_) {
      setLuaNoSideEffect();
      uint64_t top = top_ ? *top_ : 10U;
      map<ComboAddress, unsigned int,ComboAddress::addressOnlyLessThan > counts;
      unsigned int total=0;
      {
        for (const auto& shard : g_rings.d_shards) {
          auto rl = shard->queryRing.lock();
          for(const auto& c : *rl) {
            counts[c.requestor]++;
            total++;
          }
        }
      }
      vector<pair<unsigned int, ComboAddress>> rcounts;
      rcounts.reserve(counts.size());
      for(const auto& c : counts)
        rcounts.emplace_back(c.second, c.first);

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

  luaCtx.writeFunction("getTopQueries", [](uint64_t top, boost::optional<int> labels) {
      setLuaNoSideEffect();
      map<DNSName, unsigned int> counts;
      unsigned int total=0;
      if(!labels) {
        for (const auto& shard : g_rings.d_shards) {
          auto rl = shard->queryRing.lock();
          for(const auto& a : *rl) {
            counts[a.name]++;
            total++;
          }
        }
      }
      else {
	unsigned int lab = *labels;
        for (const auto& shard : g_rings.d_shards) {
          auto rl = shard->queryRing.lock();
          // coverity[auto_causes_copy]
          for (auto a : *rl) {
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
        rcounts.emplace_back(c.second, c.first.makeLowerCase());

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

      if (total > 0) {
        ret.insert({count, {"Rest", rest, 100.0*rest/total}});
      }
      else {
        ret.insert({count, {"Rest", rest, 100.0}});
      }

      return ret;

    });

  luaCtx.executeCode(R"(function topQueries(top, labels) top = top or 10; for k,v in ipairs(getTopQueries(top,labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2], v[3])) end end)");

  luaCtx.writeFunction("getResponseRing", []() {
      setLuaNoSideEffect();
      size_t totalEntries = 0;
      std::vector<boost::circular_buffer<Rings::Response>> rings;
      rings.reserve(g_rings.getNumberOfShards());
      for (const auto& shard : g_rings.d_shards) {
        {
          auto rl = shard->respRing.lock();
          rings.push_back(*rl);
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

  luaCtx.writeFunction("getTopResponses", [](uint64_t top, uint64_t kind, boost::optional<int> labels) {
      return getGenResponses(top, labels, [kind](const Rings::Response& r) { return r.dh.rcode == kind; });
    });

  luaCtx.executeCode(R"(function topResponses(top, kind, labels) top = top or 10; kind = kind or 0; for k,v in ipairs(getTopResponses(top, kind, labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");


  luaCtx.writeFunction("getSlowResponses", [](uint64_t top, uint64_t msec, boost::optional<int> labels) {
      return getGenResponses(top, labels, [msec](const Rings::Response& r) { return r.usec > msec*1000; });
    });


  luaCtx.executeCode(R"(function topSlow(top, msec, labels) top = top or 10; msec = msec or 500; for k,v in ipairs(getSlowResponses(top, msec, labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");

  luaCtx.writeFunction("getTopBandwidth", [](uint64_t top) {
      setLuaNoSideEffect();
      return g_rings.getTopBandwidth(top);
    });

  luaCtx.executeCode(R"(function topBandwidth(top) top = top or 10; for k,v in ipairs(getTopBandwidth(top)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");
#endif /* DISABLE_TOP_N_BINDINGS */

  luaCtx.writeFunction("delta", []() {
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

  luaCtx.writeFunction("grepq", [](LuaTypeOrArrayOf<std::string> inp, boost::optional<unsigned int> limit, boost::optional<LuaAssociativeTable<std::string>> options) {
      setLuaNoSideEffect();
      boost::optional<Netmask>  nm;
      boost::optional<DNSName> dn;
      int msec = -1;
      std::unique_ptr<FILE, decltype(&fclose)> outputFile{nullptr, fclose};

      if (options) {
        std::string outputFileName;
        if (getOptionalValue<std::string>(options, "outputFile", outputFileName) > 0) {
          int fd = open(outputFileName.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
          if (fd < 0) {
            g_outputBuffer = "Error opening dump file for writing: " + stringerror() + "\n";
            return;
          }
          outputFile = std::unique_ptr<FILE, decltype(&fclose)>(fdopen(fd, "w"), fclose);
          if (outputFile == nullptr) {
            g_outputBuffer = "Error opening dump file for writing: " + stringerror() + "\n";
            close(fd);
            return;
          }
        }
        checkAllParametersConsumed("grepq", options);
      }

      vector<string> vec;
      auto str = boost::get<string>(&inp);
      if (str) {
        vec.push_back(*str);
      }
      else {
        auto v = boost::get<LuaArray<std::string>>(inp);
        for (const auto& a: v) {
          vec.push_back(a.second);
        }
      }

      for (const auto& s : vec) {
        try {
            nm = Netmask(s);
        }
        catch (...) {
          if (boost::ends_with(s,"ms") && sscanf(s.c_str(), "%ums", &msec)) {
            ;
          }
          else {
            try {
              dn = DNSName(s);
            }
            catch (...) {
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
          auto rl = shard->queryRing.lock();
          for (const auto& entry : *rl) {
            qr.push_back(entry);
          }
        }
        {
          auto rl = shard->respRing.lock();
          for (const auto& entry : *rl) {
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

      boost::format        fmt("%-7.1f %-47s %-12s %-12s %-5d %-25s %-5s %-6.1f %-2s %-2s %-2s %-s\n");
      const auto headLine = (fmt % "Time" % "Client" % "Protocol" % "Server" % "ID" % "Name" % "Type" % "Lat." % "TC" % "RD" % "AA" % "Rcode").str();
      if (!outputFile) {
        g_outputBuffer += headLine;
      }
      else {
        fprintf(outputFile.get(), "%s", headLine.c_str());
      }

      if (msec == -1) {
        for (const auto& c : qr) {
          bool nmmatch = true;
          bool dnmatch = true;
          if (nm) {
            nmmatch = nm->match(c.requestor);
          }
          if (dn) {
            if (c.name.empty()) {
              dnmatch = false;
            }
            else {
              dnmatch = c.name.isPartOf(*dn);
            }
          }
          if (nmmatch && dnmatch) {
            QType qt(c.qtype);
            std::string extra;
            if (c.dh.opcode != 0) {
              extra = " (" + Opcode::to_s(c.dh.opcode) + ")";
            }
            out.emplace(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % dnsdist::Protocol(c.protocol).toString() % "" % htons(c.dh.id) % c.name.toString() % qt.toString() % "" % (c.dh.tc ? "TC" : "") % (c.dh.rd ? "RD" : "") % (c.dh.aa ? "AA" : "") % ("Question" + extra)).str());

            if (limit && *limit == ++num) {
              break;
            }
          }
        }
      }
      num = 0;

      string extra;
      for (const auto& c : rr) {
        bool nmmatch = true;
        bool dnmatch = true;
        bool msecmatch = true;
        if (nm) {
          nmmatch = nm->match(c.requestor);
        }
        if (dn) {
          if (c.name.empty()) {
            dnmatch = false;
          }
          else {
            dnmatch = c.name.isPartOf(*dn);
          }
        }
        if (msec != -1) {
          msecmatch = (c.usec/1000 > (unsigned int)msec);
        }

        if (nmmatch && dnmatch && msecmatch) {
          QType qt(c.qtype);
	  if (!c.dh.rcode) {
	    extra = ". " +std::to_string(htons(c.dh.ancount)) + " answers";
          }
	  else {
	    extra.clear();
          }

          std::string server = c.ds.toStringWithPort();
          std::string protocol = dnsdist::Protocol(c.protocol).toString();
          if (server == "0.0.0.0:0") {
            server = "Cache";
            protocol = "-";
          }
          if (c.usec != std::numeric_limits<decltype(c.usec)>::max()) {
            out.emplace(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % protocol % server % htons(c.dh.id) % c.name.toString() % qt.toString() % (c.usec / 1000.0) % (c.dh.tc ? "TC" : "") % (c.dh.rd ? "RD" : "") % (c.dh.aa ? "AA" : "") % (RCode::to_s(c.dh.rcode) + extra)).str());
          }
          else {
            out.emplace(c.when, (fmt % DiffTime(now, c.when) % c.requestor.toStringWithPort() % protocol % server % htons(c.dh.id) % c.name.toString() % qt.toString() % "T.O" % (c.dh.tc ? "TC" : "") % (c.dh.rd ? "RD" : "") % (c.dh.aa ? "AA" : "") % (RCode::to_s(c.dh.rcode) + extra)).str());
          }

          if (limit && *limit == ++num) {
            break;
          }
        }
      }

      for (const auto& p : out) {
        if (!outputFile) {
          g_outputBuffer += p.second;
        }
        else {
          fprintf(outputFile.get(), "%s", p.second.c_str());
        }
      }
    });

  luaCtx.writeFunction("showResponseLatency", []() {
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
          auto rl = shard->respRing.lock();
          for(const auto& r : *rl) {
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

      g_outputBuffer = (boost::format("Average response latency: %.02f ms\n") % (0.001*totlat/size)).str();
      double highest=0;

      for(auto iter = histo.cbegin(); iter != histo.cend(); ++iter) {
	highest=std::max(highest, iter->second*1.0);
      }
      boost::format fmt("%7.2f\t%s\n");
      g_outputBuffer += (fmt % "ms" % "").str();

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

  luaCtx.writeFunction("showTCPStats", [] {
      setLuaNoSideEffect();
      ostringstream ret;
      boost::format fmt("%-12d %-12d %-12d %-12d");
      ret << (fmt % "Workers" % "Max Workers" % "Queued" % "Max Queued") << endl;
      ret << (fmt % g_tcpclientthreads->getThreadsCount() % (g_maxTCPClientThreads ? *g_maxTCPClientThreads : 0) % g_tcpclientthreads->getQueuedCount() % g_maxTCPQueuedConnections) << endl;
      ret << endl;

      ret << "Frontends:" << endl;
      fmt = boost::format("%-3d %-20.20s %-20d %-20d %-20d %-25d %-20d %-20d %-20d %-20f %-20f %-20d %-20d %-25d %-25d %-15d %-15d %-15d %-15d %-15d");
      ret << (fmt % "#" % "Address" % "Connections" % "Max concurrent conn" % "Died reading query" % "Died sending response" % "Gave up" % "Client timeouts" % "Downstream timeouts" % "Avg queries/conn" % "Avg duration" % "TLS new sessions" % "TLS Resumptions" % "TLS unknown ticket keys" % "TLS inactive ticket keys" % "TLS 1.0" % "TLS 1.1" % "TLS 1.2" % "TLS 1.3" % "TLS other") << endl;

      size_t counter = 0;
      for(const auto& f : g_frontends) {
        ret << (fmt % counter % f->local.toStringWithPort() % f->tcpCurrentConnections % f->tcpMaxConcurrentConnections % f->tcpDiedReadingQuery % f->tcpDiedSendingResponse % f->tcpGaveUp % f->tcpClientTimeouts % f->tcpDownstreamTimeouts % f->tcpAvgQueriesPerConnection % f->tcpAvgConnectionDuration % f->tlsNewSessions % f->tlsResumptions % f->tlsUnknownTicketKey % f->tlsInactiveTicketKey % f->tls10queries % f->tls11queries % f->tls12queries % f->tls13queries % f->tlsUnknownqueries) << endl;
        ++counter;
      }
      ret << endl;

      ret << "Backends:" << endl;
      fmt = boost::format("%-3d %-20.20s %-20.20s %-20d %-20d %-25d %-25d %-20d %-20d %-20d %-20d %-20d %-20d %-20d %-20d %-20f %-20f");
      ret << (fmt % "#" % "Name" % "Address" % "Connections" % "Max concurrent conn" % "Died sending query" % "Died reading response" % "Gave up" % "Read timeouts" % "Write timeouts" % "Connect timeouts" % "Too many conn" % "Total connections" % "Reused connections" % "TLS resumptions" % "Avg queries/conn" % "Avg duration") << endl;

      auto states = g_dstates.getLocal();
      counter = 0;
      for(const auto& s : *states) {
        ret << (fmt % counter % s->getName() % s->d_config.remote.toStringWithPort() % s->tcpCurrentConnections % s->tcpMaxConcurrentConnections % s->tcpDiedSendingQuery % s->tcpDiedReadingResponse % s->tcpGaveUp % s->tcpReadTimeouts % s->tcpWriteTimeouts % s->tcpConnectTimeouts % s->tcpTooManyConcurrentConnections % s->tcpNewConnections % s->tcpReusedConnections % s->tlsResumptions % s->tcpAvgQueriesPerConnection % s->tcpAvgConnectionDuration) << endl;
        ++counter;
      }

      g_outputBuffer=ret.str();
    });

  luaCtx.writeFunction("showTLSErrorCounters", [] {
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

  luaCtx.writeFunction("requestTCPStatesDump", [] {
    setLuaNoSideEffect();
    extern std::atomic<uint64_t> g_tcpStatesDumpRequested;
    g_tcpStatesDumpRequested += g_tcpclientthreads->getThreadsCount();
  });

  luaCtx.writeFunction("requestDoHStatesDump", [] {
    setLuaNoSideEffect();
    g_dohStatesDumpRequested += g_dohClientThreads->getThreadsCount();
  });

  luaCtx.writeFunction("dumpStats", [] {
      setLuaNoSideEffect();
      vector<string> leftcolumn, rightcolumn;

      boost::format fmt("%-35s\t%+11s");
      g_outputBuffer.clear();
      auto entries = g_stats.entries;
      sort(entries.begin(), entries.end(),
	   [](const decltype(entries)::value_type& a, const decltype(entries)::value_type& b) {
	     return a.first < b.first;
	   });
      boost::format flt("    %9.1f");
      for (const auto& e : entries) {
        string second;
        if (const auto& val = boost::get<pdns::stat_t*>(&e.second)) {
          second = std::to_string((*val)->load());
        }
        else if (const auto& adval = boost::get<pdns::stat_t_trait<double>*>(&e.second)) {
          second = (flt % (*adval)->load()).str();
        }
        else if (const auto& dval = boost::get<double*>(&e.second)) {
          second = (flt % (**dval)).str();
        }
        else if (const auto& func = boost::get<DNSDistStats::statfunction_t>(&e.second)) {
          second = std::to_string((*func)(e.first));
        }

        if (leftcolumn.size() < g_stats.entries.size()/2) {
          leftcolumn.push_back((fmt % e.first % second).str());
        }
        else {
          rightcolumn.push_back((fmt % e.first % second).str());
        }
      }

      auto leftiter=leftcolumn.begin(), rightiter=rightcolumn.begin();
      boost::format clmn("%|0t|%1% %|51t|%2%\n");

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

#ifndef DISABLE_DYNBLOCKS
#ifndef DISABLE_DEPRECATED_DYNBLOCK
  luaCtx.writeFunction("exceedServFails", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRCode(rate, seconds, RCode::ServFail);
    });
  luaCtx.writeFunction("exceedNXDOMAINs", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRCode(rate, seconds, RCode::NXDomain);
    });

  luaCtx.writeFunction("exceedRespByterate", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedRespByterate(rate, seconds);
    });

  luaCtx.writeFunction("exceedQTypeRate", [](uint16_t type, unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedQueryGen(rate, seconds, [type](counts_t& counts, const Rings::Query& q) {
	  if(q.qtype==type)
	    counts[q.requestor]++;
	});
    });

  luaCtx.writeFunction("exceedQRate", [](unsigned int rate, int seconds) {
      setLuaNoSideEffect();
      return exceedQueryGen(rate, seconds, [](counts_t& counts, const Rings::Query& q) {
          counts[q.requestor]++;
	});
    });

  luaCtx.writeFunction("getRespRing", getRespRing);

  /* StatNode */
  luaCtx.registerFunction<unsigned int(StatNode::*)()const>("numChildren",
                                                            [](const StatNode& sn) -> unsigned int {
                                                              return sn.children.size();
                                                            } );
  luaCtx.registerMember("fullname", &StatNode::fullname);
  luaCtx.registerMember("labelsCount", &StatNode::labelsCount);
  luaCtx.registerMember("servfails", &StatNode::Stat::servfails);
  luaCtx.registerMember("nxdomains", &StatNode::Stat::nxdomains);
  luaCtx.registerMember("queries", &StatNode::Stat::queries);
  luaCtx.registerMember("noerrors", &StatNode::Stat::noerrors);
  luaCtx.registerMember("drops", &StatNode::Stat::drops);
  luaCtx.registerMember("bytes", &StatNode::Stat::bytes);
  luaCtx.registerMember("hits", &StatNode::Stat::hits);

  luaCtx.writeFunction("statNodeRespRing", [](statvisitor_t visitor, boost::optional<uint64_t> seconds) {
      statNodeRespRing(visitor, seconds ? *seconds : 0U);
    });
#endif /* DISABLE_DEPRECATED_DYNBLOCK */

  /* DynBlockRulesGroup */
  luaCtx.writeFunction("dynBlockRulesGroup", []() { return std::make_shared<DynBlockRulesGroup>(); });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>)>("setQueryRate", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate) {
      if (group) {
        group->setQueryRate(rate, warningRate ? *warningRate : 0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None);
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>)>("setResponseByteRate", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate) {
      if (group) {
        group->setResponseByteRate(rate, warningRate ? *warningRate : 0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None);
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, DynBlockRulesGroup::smtVisitor_t)>("setSuffixMatchRule", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, DynBlockRulesGroup::smtVisitor_t visitor) {
      if (group) {
        group->setSuffixMatchRule(seconds, reason, blockDuration, action ? *action : DNSAction::Action::None, visitor);
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, dnsdist_ffi_stat_node_visitor_t)>("setSuffixMatchRuleFFI", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, dnsdist_ffi_stat_node_visitor_t visitor) {
      if (group) {
        group->setSuffixMatchRuleFFI(seconds, reason, blockDuration, action ? *action : DNSAction::Action::None, visitor);
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(uint8_t, unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>)>("setRCodeRate", [](std::shared_ptr<DynBlockRulesGroup>& group, uint8_t rcode, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate) {
      if (group) {
        group->setRCodeRate(rcode, rate, warningRate ? *warningRate : 0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None);
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(uint8_t, double, unsigned int, const std::string&, unsigned int, size_t, boost::optional<DNSAction::Action>, boost::optional<double>)>("setRCodeRatio", [](std::shared_ptr<DynBlockRulesGroup>& group, uint8_t rcode, double ratio, unsigned int seconds, const std::string& reason, unsigned int blockDuration, size_t minimumNumberOfResponses, boost::optional<DNSAction::Action> action, boost::optional<double> warningRatio) {
      if (group) {
        group->setRCodeRatio(rcode, ratio, warningRatio ? *warningRatio : 0.0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None, minimumNumberOfResponses);
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(uint16_t, unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>)>("setQTypeRate", [](std::shared_ptr<DynBlockRulesGroup>& group, uint16_t qtype, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate) {
      if (group) {
        group->setQTypeRate(qtype, rate, warningRate ? *warningRate : 0, seconds, reason, blockDuration, action ? *action : DNSAction::Action::None);
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(uint8_t, uint8_t, uint8_t)>("setMasks", [](std::shared_ptr<DynBlockRulesGroup>& group, uint8_t v4, uint8_t v6, uint8_t port) {
      if (group) {
        if (v4 > 32) {
          throw std::runtime_error("Trying to set an invalid IPv4 mask (" + std::to_string(v4) + ") to a Dynamic Block object");
        }
        if (v6 > 128) {
          throw std::runtime_error("Trying to set an invalid IPv6 mask (" + std::to_string(v6) + ") to a Dynamic Block object");
        }
        if (port > 16) {
          throw std::runtime_error("Trying to set an invalid port mask (" + std::to_string(port) + ") to a Dynamic Block object");
        }
        if (port > 0 && v4 != 32) {
          throw std::runtime_error("Setting a non-zero port mask for Dynamic Blocks while only considering parts of IPv4 addresses does not make sense");
        }
        group->setMasks(v4, v6, port);
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(boost::variant<std::string, LuaArray<std::string>, NetmaskGroup>)>("excludeRange", [](std::shared_ptr<DynBlockRulesGroup>& group, boost::variant<std::string, LuaArray<std::string>, NetmaskGroup> ranges) {
      if (ranges.type() == typeid(LuaArray<std::string>)) {
        for (const auto& range : *boost::get<LuaArray<std::string>>(&ranges)) {
          group->excludeRange(Netmask(range.second));
        }
      }
      else if (ranges.type() == typeid(NetmaskGroup)) {
        group->excludeRange(*boost::get<NetmaskGroup>(&ranges));
      }
      else {
        group->excludeRange(Netmask(*boost::get<std::string>(&ranges)));
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(boost::variant<std::string, LuaArray<std::string>, NetmaskGroup>)>("includeRange", [](std::shared_ptr<DynBlockRulesGroup>& group, boost::variant<std::string, LuaArray<std::string>, NetmaskGroup> ranges) {
      if (ranges.type() == typeid(LuaArray<std::string>)) {
        for (const auto& range : *boost::get<LuaArray<std::string>>(&ranges)) {
          group->includeRange(Netmask(range.second));
        }
      }
      else if (ranges.type() == typeid(NetmaskGroup)) {
        group->includeRange(*boost::get<NetmaskGroup>(&ranges));
      }
      else {
        group->includeRange(Netmask(*boost::get<std::string>(&ranges)));
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)(LuaTypeOrArrayOf<std::string>)>("excludeDomains", [](std::shared_ptr<DynBlockRulesGroup>& group, LuaTypeOrArrayOf<std::string> domains) {
      if (domains.type() == typeid(LuaArray<std::string>)) {
        for (const auto& range : *boost::get<LuaArray<std::string>>(&domains)) {
          group->excludeDomain(DNSName(range.second));
        }
      }
      else {
        group->excludeDomain(DNSName(*boost::get<std::string>(&domains)));
      }
    });
  luaCtx.registerFunction<void(std::shared_ptr<DynBlockRulesGroup>::*)()>("apply", [](std::shared_ptr<DynBlockRulesGroup>& group) {
    group->apply();
  });
  luaCtx.registerFunction("setQuiet", &DynBlockRulesGroup::setQuiet);
  luaCtx.registerFunction("toString", &DynBlockRulesGroup::toString);
#endif /* DISABLE_DYNBLOCKS */
}
