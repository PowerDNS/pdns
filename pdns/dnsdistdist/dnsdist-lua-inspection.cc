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
#include <algorithm>
#include <fcntl.h>
#include <iterator>

#include "dnsdist.hh"
#include "dnsdist-console.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-frontend.hh"
#include "dnsdist-lua.hh"
#include "dnsdist-nghttp2.hh"
#include "dnsdist-rings.hh"
#include "dnsdist-tcp.hh"

#include "statnode.hh"

#ifndef DISABLE_TOP_N_BINDINGS
static LuaArray<std::vector<boost::variant<string, double>>> getGenResponses(uint64_t top, boost::optional<int> labels, const std::function<bool(const Rings::Response&)>& pred)
{
  setLuaNoSideEffect();
  map<DNSName, unsigned int> counts;
  unsigned int total = 0;
  {
    for (const auto& shard : g_rings.d_shards) {
      auto respRing = shard->respRing.lock();
      if (!labels) {
        for (const auto& entry : *respRing) {
          if (!pred(entry)) {
            continue;
          }
          counts[entry.name]++;
          total++;
        }
      }
      else {
        unsigned int lab = *labels;
        for (const auto& entry : *respRing) {
          if (!pred(entry)) {
            continue;
          }

          DNSName temp(entry.name);
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
  for (const auto& val : counts) {
    rcounts.emplace_back(val.second, val.first.makeLowerCase());
  }

  sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& lhs, const decltype(rcounts)::value_type& rhs) {
    return rhs.first < lhs.first;
  });

  LuaArray<vector<boost::variant<string, double>>> ret;
  ret.reserve(std::min(rcounts.size(), static_cast<size_t>(top + 1U)));
  int count = 1;
  unsigned int rest = 0;
  for (const auto& rcEntry : rcounts) {
    if (count == static_cast<int>(top + 1)) {
      rest += rcEntry.first;
    }
    else {
      ret.emplace_back(count++, std::vector<boost::variant<string, double>>{rcEntry.second.toString(), rcEntry.first, 100.0 * rcEntry.first / total});
    }
  }

  if (total > 0) {
    ret.push_back({count, {"Rest", rest, 100.0 * rest / total}});
  }
  else {
    ret.push_back({count, {"Rest", rest, 100.0}});
  }

  return ret;
}
#endif /* DISABLE_TOP_N_BINDINGS */

#ifndef DISABLE_DYNBLOCKS
#ifndef DISABLE_DEPRECATED_DYNBLOCK

using counts_t = std::unordered_map<ComboAddress, unsigned int, ComboAddress::addressOnlyHash, ComboAddress::addressOnlyEqual>;

static counts_t filterScore(const counts_t& counts,
                            double delta, unsigned int rate)
{
  counts_t ret;

  double lim = delta * rate;
  for (const auto& entry : counts) {
    if (entry.second > lim) {
      ret[entry.first] = entry.second;
    }
  }

  return ret;
}

using statvisitor_t = std::function<void(const StatNode&, const StatNode::Stat&, const StatNode::Stat&)>;

static void statNodeRespRing(statvisitor_t visitor, uint64_t seconds)
{
  timespec now{};
  gettime(&now);
  timespec cutoff{now};
  cutoff.tv_sec -= static_cast<time_t>(seconds);

  StatNode root;
  for (const auto& shard : g_rings.d_shards) {
    auto respRing = shard->respRing.lock();

    for (const auto& entry : *respRing) {
      if (now < entry.when) {
        continue;
      }

      if (seconds != 0 && entry.when < cutoff) {
        continue;
      }

      const bool hit = entry.isACacheHit();
      root.submit(entry.name, ((entry.dh.rcode == 0 && entry.usec == std::numeric_limits<unsigned int>::max()) ? -1 : entry.dh.rcode), entry.size, hit, std::nullopt);
    }
  }

  StatNode::Stat node;
  root.visit([visitor = std::move(visitor)](const StatNode* node_, const StatNode::Stat& self, const StatNode::Stat& children) { visitor(*node_, self, children); }, node);
}

static LuaArray<LuaAssociativeTable<std::string>> getRespRing(boost::optional<int> rcode)
{
  using entry_t = LuaAssociativeTable<std::string>;
  LuaArray<entry_t> ret;

  for (const auto& shard : g_rings.d_shards) {
    auto respRing = shard->respRing.lock();

    int count = 1;
    for (const auto& entry : *respRing) {
      if (rcode && (rcode.get() != entry.dh.rcode)) {
        continue;
      }
      entry_t newEntry;
      newEntry["qname"] = entry.name.toString();
      newEntry["rcode"] = std::to_string(entry.dh.rcode);
      ret.emplace_back(count, std::move(newEntry));
      count++;
    }
  }

  return ret;
}

static counts_t exceedRespGen(unsigned int rate, int seconds, const std::function<void(counts_t&, const Rings::Response&)>& visitor)
{
  counts_t counts;
  timespec now{};
  gettime(&now);
  timespec mintime{now};
  timespec cutoff{now};
  cutoff.tv_sec -= seconds;

  counts.reserve(g_rings.getNumberOfResponseEntries());

  for (const auto& shard : g_rings.d_shards) {
    auto respRing = shard->respRing.lock();
    for (const auto& entry : *respRing) {

      if (seconds != 0 && entry.when < cutoff) {
        continue;
      }
      if (now < entry.when) {
        continue;
      }

      visitor(counts, entry);
      if (entry.when < mintime) {
        mintime = entry.when;
      }
    }
  }

  double delta = seconds != 0 ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}

static counts_t exceedQueryGen(unsigned int rate, int seconds, const std::function<void(counts_t&, const Rings::Query&)>& visitor)
{
  counts_t counts;
  timespec now{};
  gettime(&now);
  timespec mintime{now};
  timespec cutoff{now};
  cutoff.tv_sec -= seconds;

  counts.reserve(g_rings.getNumberOfQueryEntries());

  for (const auto& shard : g_rings.d_shards) {
    auto respRing = shard->queryRing.lock();
    for (const auto& entry : *respRing) {
      if (seconds != 0 && entry.when < cutoff) {
        continue;
      }
      if (now < entry.when) {
        continue;
      }
      visitor(counts, entry);
      if (entry.when < mintime) {
        mintime = entry.when;
      }
    }
  }

  double delta = seconds != 0 ? seconds : DiffTime(now, mintime);
  return filterScore(counts, delta, rate);
}

static counts_t exceedRCode(unsigned int rate, int seconds, int rcode)
{
  return exceedRespGen(rate, seconds, [rcode](counts_t& counts, const Rings::Response& resp) {
    if (resp.dh.rcode == rcode) {
      counts[resp.requestor]++;
    }
  });
}

static counts_t exceedRespByterate(unsigned int rate, int seconds)
{
  return exceedRespGen(rate, seconds, [](counts_t& counts, const Rings::Response& resp) {
    counts[resp.requestor] += resp.size;
  });
}

#endif /* DISABLE_DEPRECATED_DYNBLOCK */
#endif /* DISABLE_DYNBLOCKS */

// NOLINTNEXTLINE(bugprone-exception-escape)
struct GrepQParams
{
  std::optional<Netmask> netmask;
  std::optional<DNSName> name;
  std::optional<unsigned int> msec;
  pdns::UniqueFilePtr outputFile{nullptr};
};

static std::optional<GrepQParams> parseGrepQParams(const LuaTypeOrArrayOf<std::string>& inp, boost::optional<LuaAssociativeTable<std::string>>& options)
{
  GrepQParams result{};

  if (options) {
    std::string outputFileName;
    if (getOptionalValue<std::string>(options, "outputFile", outputFileName) > 0) {
      int fileDesc = open(outputFileName.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
      if (fileDesc < 0) {
        g_outputBuffer = "Error opening dump file for writing: " + stringerror() + "\n";
        return std::nullopt;
      }
      result.outputFile = pdns::UniqueFilePtr(fdopen(fileDesc, "w"));
      if (result.outputFile == nullptr) {
        g_outputBuffer = "Error opening dump file for writing: " + stringerror() + "\n";
        close(fileDesc);
        return std::nullopt;
      }
    }
    checkAllParametersConsumed("grepq", options);
  }

  vector<string> filters;
  const auto* str = boost::get<string>(&inp);
  if (str != nullptr) {
    filters.push_back(*str);
  }
  else {
    auto values = boost::get<LuaArray<std::string>>(inp);
    for (const auto& filter : values) {
      filters.push_back(filter.second);
    }
  }

  for (const auto& filter : filters) {
    try {
      result.netmask = Netmask(filter);
      continue;
    }
    catch (...) {
      /* that's OK, let's try something else */
    }

    if (boost::ends_with(filter, "ms")) {
      /* skip the ms at the end */
      const auto msecStr = filter.substr(0, filter.size() - 2);
      try {
        result.msec = pdns::checked_stoi<unsigned int>(msecStr);
        continue;
      }
      catch (...) {
        /* that's OK, let's try to parse as a DNS name */
      }
    }

    try {
      result.name = DNSName(filter);
    }
    catch (...) {
      g_outputBuffer = "Could not parse '" + filter + "' as domain name or netmask";
      return std::nullopt;
    }
  }
  return result;
}

template <class C>
static bool ringEntryMatches(const GrepQParams& params, const C& entry)
{
  bool nmmatch = true;
  bool dnmatch = true;
  bool msecmatch = true;
  if (params.netmask) {
    nmmatch = params.netmask->match(entry.requestor);
  }
  if (params.name) {
    if (entry.name.empty()) {
      dnmatch = false;
    }
    else {
      dnmatch = entry.name.isPartOf(*params.name);
    }
  }

  constexpr bool response = std::is_same_v<C, Rings::Response>;
  if constexpr (response) {
    if (params.msec) {
      msecmatch = (entry.usec / 1000 > *params.msec);
    }
  }

  return nmmatch && dnmatch && msecmatch;
}

#ifndef DISABLE_DYNBLOCKS
using DynamicActionOptionalParameters = boost::optional<LuaAssociativeTable<std::string>>;

static void parseDynamicActionOptionalParameters(const std::string& directive, DynBlockRulesGroup::DynBlockRule& rule, const boost::optional<DNSAction::Action>& action, const DynamicActionOptionalParameters& optionalParameters)
{
  if (action && *action == DNSAction::Action::SetTag) {
    if (!optionalParameters) {
      throw std::runtime_error("SetTag action passed to " + directive + " without additional parameters");
    }
    const auto& paramNameIt = optionalParameters->find("tagName");
    if (paramNameIt == optionalParameters->end()) {
      throw std::runtime_error("SetTag action passed to " + directive + " without a tag name");
    }
    rule.d_tagSettings = std::make_shared<DynBlock::TagSettings>();
    rule.d_tagSettings->d_name = paramNameIt->second;
    const auto& paramValueIt = optionalParameters->find("tagValue");
    if (paramValueIt != optionalParameters->end()) {
      rule.d_tagSettings->d_value = paramValueIt->second;
    }
  }
}
#endif /* DISABLE_DYNBLOCKS */

// NOLINTNEXTLINE(readability-function-cognitive-complexity): this function declares Lua bindings, even with a good refactoring it will likely blow up the threshold
void setupLuaInspection(LuaContext& luaCtx)
{
#ifndef DISABLE_TOP_N_BINDINGS
  luaCtx.writeFunction("topClients", [](boost::optional<uint64_t> top_) {
    setLuaNoSideEffect();
    uint64_t top = top_ ? *top_ : 10U;
    map<ComboAddress, unsigned int, ComboAddress::addressOnlyLessThan> counts;
    unsigned int total = 0;
    {
      for (const auto& shard : g_rings.d_shards) {
        auto respRing = shard->queryRing.lock();
        for (const auto& entry : *respRing) {
          counts[entry.requestor]++;
          total++;
        }
      }
    }
    vector<pair<unsigned int, ComboAddress>> rcounts;
    rcounts.reserve(counts.size());
    for (const auto& entry : counts) {
      rcounts.emplace_back(entry.second, entry.first);
    }

    sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& lhs, const decltype(rcounts)::value_type& rhs) {
      return rhs.first < lhs.first;
    });
    unsigned int count = 1;
    unsigned int rest = 0;
    boost::format fmt("%4d  %-40s %4d %4.1f%%\n");
    for (const auto& entry : rcounts) {
      if (count == top + 1) {
        rest += entry.first;
      }
      else {
        g_outputBuffer += (fmt % (count++) % entry.second.toString() % entry.first % (100.0 * entry.first / total)).str();
      }
    }
    g_outputBuffer += (fmt % (count) % "Rest" % rest % (total > 0 ? 100.0 * rest / total : 100.0)).str();
  });

  luaCtx.writeFunction("getTopQueries", [](uint64_t top, boost::optional<int> labels) {
    setLuaNoSideEffect();
    map<DNSName, unsigned int> counts;
    unsigned int total = 0;
    if (!labels) {
      for (const auto& shard : g_rings.d_shards) {
        auto respRing = shard->queryRing.lock();
        for (const auto& entry : *respRing) {
          counts[entry.name]++;
          total++;
        }
      }
    }
    else {
      unsigned int lab = *labels;
      for (const auto& shard : g_rings.d_shards) {
        auto respRing = shard->queryRing.lock();
        for (const auto& entry : *respRing) {
          auto name = entry.name;
          name.trimToLabels(lab);
          counts[name]++;
          total++;
        }
      }
    }

    vector<pair<unsigned int, DNSName>> rcounts;
    rcounts.reserve(counts.size());
    for (const auto& entry : counts) {
      rcounts.emplace_back(entry.second, entry.first.makeLowerCase());
    }

    sort(rcounts.begin(), rcounts.end(), [](const decltype(rcounts)::value_type& lhs, const decltype(rcounts)::value_type& rhs) {
      return rhs.first < lhs.first;
    });

    std::unordered_map<unsigned int, vector<boost::variant<string, double>>> ret;
    unsigned int count = 1;
    unsigned int rest = 0;
    for (const auto& entry : rcounts) {
      if (count == top + 1) {
        rest += entry.first;
      }
      else {
        ret.insert({count++, {entry.second.toString(), entry.first, 100.0 * entry.first / total}});
      }
    }

    if (total > 0) {
      ret.insert({count, {"Rest", rest, 100.0 * rest / total}});
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
        auto respRing = shard->respRing.lock();
        rings.push_back(*respRing);
      }
      totalEntries += rings.back().size();
    }
    vector<std::unordered_map<string, boost::variant<unsigned int, string>>> ret;
    ret.reserve(totalEntries);
    for (const auto& ring : rings) {
      for (const auto& entry : ring) {
        decltype(ret)::value_type item;
        item["name"] = entry.name.toString();
        item["qtype"] = entry.qtype;
        item["rcode"] = entry.dh.rcode;
        item["usec"] = entry.usec;
        ret.push_back(std::move(item));
      }
    }
    return ret;
  });

  luaCtx.writeFunction("getTopResponses", [](uint64_t top, uint64_t kind, boost::optional<int> labels) {
    return getGenResponses(top, labels, [kind](const Rings::Response& resp) { return resp.dh.rcode == kind; });
  });

  luaCtx.executeCode(R"(function topResponses(top, kind, labels) top = top or 10; kind = kind or 0; for k,v in ipairs(getTopResponses(top, kind, labels)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");

  luaCtx.writeFunction("getSlowResponses", [](uint64_t top, uint64_t msec, boost::optional<int> labels, boost::optional<bool> timeouts) {
    return getGenResponses(top, labels, [msec, timeouts](const Rings::Response& resp) {
      if (timeouts && *timeouts) {
        return resp.usec == std::numeric_limits<unsigned int>::max();
      }
      return resp.usec > msec * 1000 && resp.usec != std::numeric_limits<unsigned int>::max();
    });
  });

  luaCtx.executeCode(R"(function topSlow(top, msec, labels) top = top or 10; msec = msec or 500; for k,v in ipairs(getSlowResponses(top, msec, labels, false)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");

  luaCtx.executeCode(R"(function topTimeouts(top, labels) top = top or 10; for k,v in ipairs(getSlowResponses(top, 0, labels, true)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");

  luaCtx.writeFunction("getTopBandwidth", [](uint64_t top) {
    setLuaNoSideEffect();
    return g_rings.getTopBandwidth(top);
  });

  luaCtx.executeCode(R"(function topBandwidth(top) top = top or 10; for k,v in ipairs(getTopBandwidth(top)) do show(string.format("%4d  %-40s %4d %4.1f%%",k,v[1],v[2],v[3])) end end)");
#endif /* DISABLE_TOP_N_BINDINGS */

  luaCtx.writeFunction("delta", []() {
    setLuaNoSideEffect();
    // we hold the lua lock already!
    for (const auto& entry : dnsdist::console::getConfigurationDelta()) {
      tm entryTime{};
      localtime_r(&entry.first.tv_sec, &entryTime);
      std::array<char, 80> date{};
      strftime(date.data(), date.size() - 1, "-- %a %b %d %Y %H:%M:%S %Z\n", &entryTime);
      g_outputBuffer += date.data();
      g_outputBuffer += entry.second + "\n";
    }
  });

  luaCtx.writeFunction("grepq", [](const LuaTypeOrArrayOf<std::string>& inp, boost::optional<unsigned int> limit, boost::optional<LuaAssociativeTable<std::string>> options) {
    setLuaNoSideEffect();

    auto paramsOrError = parseGrepQParams(inp, options);
    if (!paramsOrError) {
      return;
    }
    auto params = std::move(*paramsOrError);

    std::vector<Rings::Query> queries;
    std::vector<Rings::Response> responses;
    queries.reserve(g_rings.getNumberOfQueryEntries());
    responses.reserve(g_rings.getNumberOfResponseEntries());
    for (const auto& shard : g_rings.d_shards) {
      {
        auto respRing = shard->queryRing.lock();
        for (const auto& entry : *respRing) {
          queries.push_back(entry);
        }
      }
      {
        auto respRing = shard->respRing.lock();
        for (const auto& entry : *respRing) {
          responses.push_back(entry);
        }
      }
    }

    sort(queries.begin(), queries.end(), [](const decltype(queries)::value_type& lhs, const decltype(queries)::value_type& rhs) {
      return rhs.when < lhs.when;
    });

    sort(responses.begin(), responses.end(), [](const decltype(responses)::value_type& lhs, const decltype(responses)::value_type& rhs) {
      return rhs.when < lhs.when;
    });

    unsigned int num = 0;
    timespec now{};
    gettime(&now);

    std::multimap<struct timespec, string> out;

    boost::format fmt("%-7.1f %-47s %-12s %-12s %-5d %-25s %-5s %-6.1f %-2s %-2s %-2s %-s\n");
    const auto headLine = (fmt % "Time" % "Client" % "Protocol" % "Server" % "ID" % "Name" % "Type" % "Lat." % "TC" % "RD" % "AA" % "Rcode").str();
    if (!params.outputFile) {
      g_outputBuffer += headLine;
    }
    else {
      fprintf(params.outputFile.get(), "%s", headLine.c_str());
    }

    if (!params.msec) {
      for (const auto& entry : queries) {
        if (!ringEntryMatches(params, entry)) {
          continue;
        }
        QType qtype(entry.qtype);
        std::string extra;
        if (entry.dh.opcode != 0) {
          extra = " (" + Opcode::to_s(entry.dh.opcode) + ")";
        }
        out.emplace(entry.when, (fmt % DiffTime(now, entry.when) % entry.requestor.toStringWithPort() % dnsdist::Protocol(entry.protocol).toString() % "" % htons(entry.dh.id) % entry.name.toString() % qtype.toString() % "" % (entry.dh.tc != 0 ? "TC" : "") % (entry.dh.rd != 0 ? "RD" : "") % (entry.dh.aa != 0 ? "AA" : "") % ("Question" + extra)).str());

        if (limit && *limit == ++num) {
          break;
        }
      }
    }
    num = 0;

    string extra;
    for (const auto& entry : responses) {
      if (!ringEntryMatches(params, entry)) {
        continue;
      }
      QType qtype(entry.qtype);
      if (entry.dh.rcode == 0) {
        extra = ". " + std::to_string(htons(entry.dh.ancount)) + " answers";
      }
      else {
        extra.clear();
      }

      std::string server = entry.ds.toStringWithPort();
      std::string protocol = dnsdist::Protocol(entry.protocol).toString();
      if (server == "0.0.0.0:0") {
        server = "Cache";
        protocol = "-";
      }
      if (entry.usec != std::numeric_limits<decltype(entry.usec)>::max()) {
        out.emplace(entry.when, (fmt % DiffTime(now, entry.when) % entry.requestor.toStringWithPort() % protocol % server % htons(entry.dh.id) % entry.name.toString() % qtype.toString() % (entry.usec / 1000.0) % (entry.dh.tc != 0 ? "TC" : "") % (entry.dh.rd != 0 ? "RD" : "") % (entry.dh.aa != 0 ? "AA" : "") % (RCode::to_s(entry.dh.rcode) + extra)).str());
      }
      else {
        out.emplace(entry.when, (fmt % DiffTime(now, entry.when) % entry.requestor.toStringWithPort() % protocol % server % htons(entry.dh.id) % entry.name.toString() % qtype.toString() % "T.O" % (entry.dh.tc != 0 ? "TC" : "") % (entry.dh.rd != 0 ? "RD" : "") % (entry.dh.aa != 0 ? "AA" : "") % (RCode::to_s(entry.dh.rcode) + extra)).str());
      }

      if (limit && *limit == ++num) {
        break;
      }
    }

    for (const auto& entry : out) {
      if (!params.outputFile) {
        g_outputBuffer += entry.second;
      }
      else {
        fprintf(params.outputFile.get(), "%s", entry.second.c_str());
      }
    }
  });

  luaCtx.writeFunction("showResponseLatency", []() {
    setLuaNoSideEffect();
    map<double, unsigned int> histo;
    double bin = 100;
    for (int idx = 0; idx < 15; ++idx) {
      histo[bin];
      bin *= 2;
    }

    double totlat = 0;
    unsigned int size = 0;
    {
      for (const auto& shard : g_rings.d_shards) {
        auto respRing = shard->respRing.lock();
        for (const auto& entry : *respRing) {
          /* skip actively discovered timeouts */
          if (entry.usec == std::numeric_limits<unsigned int>::max()) {
            continue;
          }

          ++size;
          auto iter = histo.lower_bound(entry.usec);
          if (iter != histo.end()) {
            iter->second++;
          }
          else {
            histo.rbegin()++;
          }
          totlat += entry.usec;
        }
      }
    }

    if (size == 0) {
      g_outputBuffer = "No traffic yet.\n";
      return;
    }

    g_outputBuffer = (boost::format("Average response latency: %.02f ms\n") % (0.001 * totlat / size)).str();
    double highest = 0;

    for (const auto& entry : histo) {
      highest = std::max(highest, entry.second * 1.0);
    }
    boost::format fmt("%7.2f\t%s\n");
    g_outputBuffer += (fmt % "ms" % "").str();

    for (const auto& entry : histo) {
      int stars = static_cast<int>(70.0 * entry.second / highest);
      char value = '*';
      if (stars == 0 && entry.second != 0 && highest != 0.0) {
        stars = 1; // you get 1 . to show something is there..
        if (70.0 * entry.second / highest > 0.5) {
          value = ':';
        }
        else {
          value = '.';
        }
      }
      g_outputBuffer += (fmt % (entry.first / 1000.0) % string(stars, value)).str();
    }
  });

  luaCtx.writeFunction("showTCPStats", [] {
    setLuaNoSideEffect();
    const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
    ostringstream ret;
    boost::format fmt("%-12d %-12d %-12d %-12d");
    ret << (fmt % "Workers" % "Max Workers" % "Queued" % "Max Queued") << endl;
    ret << (fmt % g_tcpclientthreads->getThreadsCount() % immutableConfig.d_maxTCPClientThreads % g_tcpclientthreads->getQueuedCount() % immutableConfig.d_maxTCPQueuedConnections) << endl;
    ret << endl;

    ret << "Frontends:" << endl;
    fmt = boost::format("%-3d %-20.20s %-20d %-20d %-20d %-25d %-20d %-20d %-20d %-20f %-20f %-20d %-20d %-25d %-25d %-15d %-15d %-15d %-15d %-15d");
    ret << (fmt % "#" % "Address" % "Connections" % "Max concurrent conn" % "Died reading query" % "Died sending response" % "Gave up" % "Client timeouts" % "Downstream timeouts" % "Avg queries/conn" % "Avg duration" % "TLS new sessions" % "TLS Resumptions" % "TLS unknown ticket keys" % "TLS inactive ticket keys" % "TLS 1.0" % "TLS 1.1" % "TLS 1.2" % "TLS 1.3" % "TLS other") << endl;

    size_t counter = 0;
    for (const auto& frontend : dnsdist::getFrontends()) {
      ret << (fmt % counter % frontend->local.toStringWithPort() % frontend->tcpCurrentConnections % frontend->tcpMaxConcurrentConnections % frontend->tcpDiedReadingQuery % frontend->tcpDiedSendingResponse % frontend->tcpGaveUp % frontend->tcpClientTimeouts % frontend->tcpDownstreamTimeouts % frontend->tcpAvgQueriesPerConnection % frontend->tcpAvgConnectionDuration % frontend->tlsNewSessions % frontend->tlsResumptions % frontend->tlsUnknownTicketKey % frontend->tlsInactiveTicketKey % frontend->tls10queries % frontend->tls11queries % frontend->tls12queries % frontend->tls13queries % frontend->tlsUnknownqueries) << endl;
      ++counter;
    }
    ret << endl;

    ret << "Backends:" << endl;
    fmt = boost::format("%-3d %-20.20s %-20.20s %-20d %-20d %-25d %-25d %-20d %-20d %-20d %-20d %-20d %-20d %-20d %-20d %-20f %-20f");
    ret << (fmt % "#" % "Name" % "Address" % "Connections" % "Max concurrent conn" % "Died sending query" % "Died reading response" % "Gave up" % "Read timeouts" % "Write timeouts" % "Connect timeouts" % "Too many conn" % "Total connections" % "Reused connections" % "TLS resumptions" % "Avg queries/conn" % "Avg duration") << endl;

    counter = 0;
    for (const auto& backend : dnsdist::configuration::getCurrentRuntimeConfiguration().d_backends) {
      ret << (fmt % counter % backend->getName() % backend->d_config.remote.toStringWithPort() % backend->tcpCurrentConnections % backend->tcpMaxConcurrentConnections % backend->tcpDiedSendingQuery % backend->tcpDiedReadingResponse % backend->tcpGaveUp % backend->tcpReadTimeouts % backend->tcpWriteTimeouts % backend->tcpConnectTimeouts % backend->tcpTooManyConcurrentConnections % backend->tcpNewConnections % backend->tcpReusedConnections % backend->tlsResumptions % backend->tcpAvgQueriesPerConnection % backend->tcpAvgConnectionDuration) << endl;
      ++counter;
    }

    g_outputBuffer = ret.str();
  });

  luaCtx.writeFunction("showTLSErrorCounters", [] {
    setLuaNoSideEffect();
    ostringstream ret;
    boost::format fmt("%-3d %-20.20s %-23d %-23d %-23d %-23d %-23d %-23d %-23d %-23d");

    ret << (fmt % "#" % "Address" % "DH key too small" % "Inappropriate fallback" % "No shared cipher" % "Unknown cipher type" % "Unknown exchange type" % "Unknown protocol" % "Unsupported EC" % "Unsupported protocol") << endl;

    size_t counter = 0;
    for (const auto& frontend : dnsdist::getFrontends()) {
      if (!frontend->hasTLS()) {
        continue;
      }
      const TLSErrorCounters* errorCounters = nullptr;
      if (frontend->tlsFrontend != nullptr) {
        errorCounters = &frontend->tlsFrontend->d_tlsCounters;
      }
      else if (frontend->dohFrontend != nullptr) {
        errorCounters = &frontend->dohFrontend->d_tlsContext.d_tlsCounters;
      }
      if (errorCounters == nullptr) {
        continue;
      }

      ret << (fmt % counter % frontend->local.toStringWithPort() % errorCounters->d_dhKeyTooSmall % errorCounters->d_inappropriateFallBack % errorCounters->d_noSharedCipher % errorCounters->d_unknownCipherType % errorCounters->d_unknownKeyExchangeType % errorCounters->d_unknownProtocol % errorCounters->d_unsupportedEC % errorCounters->d_unsupportedProtocol) << endl;
      ++counter;
    }
    ret << endl;

    g_outputBuffer = ret.str();
  });

  luaCtx.writeFunction("requestTCPStatesDump", [] {
    setLuaNoSideEffect();
    extern std::atomic<uint64_t> g_tcpStatesDumpRequested;
    g_tcpStatesDumpRequested += g_tcpclientthreads->getThreadsCount();
  });

  luaCtx.writeFunction("requestDoHStatesDump", [] {
    setLuaNoSideEffect();
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
    g_dohStatesDumpRequested += g_dohClientThreads->getThreadsCount();
#endif
  });

  luaCtx.writeFunction("dumpStats", [] {
    setLuaNoSideEffect();
    vector<string> leftcolumn;
    vector<string> rightcolumn;

    boost::format fmt("%-35s\t%+11s");
    g_outputBuffer.clear();
    auto entries = *dnsdist::metrics::g_stats.entries.read_lock();

    // Filter entries to just the ones without label, for clearer output
    std::vector<std::reference_wrapper<decltype(entries)::value_type>> unlabeledEntries;
    std::copy_if(entries.begin(), entries.end(), std::back_inserter(unlabeledEntries), [](const decltype(entries)::value_type& triple) { return triple.d_labels.empty(); });

    sort(unlabeledEntries.begin(), unlabeledEntries.end(),
         [](const decltype(entries)::value_type& lhs, const decltype(entries)::value_type& rhs) {
           return lhs.d_name < rhs.d_name;
         });
    boost::format flt("    %9.1f");
    for (const auto& entryRef : unlabeledEntries) {
      const auto& entry = entryRef.get();
      string second;
      if (const auto& val = std::get_if<pdns::stat_t*>(&entry.d_value)) {
        second = std::to_string((*val)->load());
      }
      else if (const auto& adval = std::get_if<pdns::stat_double_t*>(&entry.d_value)) {
        second = (flt % (*adval)->load()).str();
      }
      else if (const auto& func = std::get_if<dnsdist::metrics::Stats::statfunction_t>(&entry.d_value)) {
        second = std::to_string((*func)(entry.d_name));
      }

      if (leftcolumn.size() < unlabeledEntries.size() / 2) {
        leftcolumn.push_back((fmt % entry.d_name % second).str());
      }
      else {
        rightcolumn.push_back((fmt % entry.d_name % second).str());
      }
    }

    auto leftiter = leftcolumn.begin();
    auto rightiter = rightcolumn.begin();
    boost::format clmn("%|0t|%1% %|51t|%2%\n");

    for (; leftiter != leftcolumn.end() || rightiter != rightcolumn.end();) {
      string lentry;
      string rentry;
      if (leftiter != leftcolumn.end()) {
        lentry = *leftiter;
        leftiter++;
      }
      if (rightiter != rightcolumn.end()) {
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
    return exceedQueryGen(rate, seconds, [type](counts_t& counts, const Rings::Query& query) {
      if (query.qtype == type) {
        counts[query.requestor]++;
      }
    });
  });

  luaCtx.writeFunction("exceedQRate", [](unsigned int rate, int seconds) {
    setLuaNoSideEffect();
    return exceedQueryGen(rate, seconds, [](counts_t& counts, const Rings::Query& query) {
      counts[query.requestor]++;
    });
  });

  luaCtx.writeFunction("getRespRing", getRespRing);

  /* StatNode */
  luaCtx.registerFunction<unsigned int (StatNode::*)() const>("numChildren",
                                                              [](const StatNode& node) -> unsigned int {
                                                                return node.children.size();
                                                              });
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
    statNodeRespRing(std::move(visitor), seconds ? *seconds : 0U);
  });
#endif /* DISABLE_DEPRECATED_DYNBLOCK */

  /* DynBlockRulesGroup */
  luaCtx.writeFunction("dynBlockRulesGroup", []() { return std::make_shared<DynBlockRulesGroup>(); });
  // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>, DynamicActionOptionalParameters)>("setQueryRate", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate, DynamicActionOptionalParameters optionalParameters) {
    if (group) {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, rate, warningRate ? *warningRate : 0, seconds, action ? *action : DNSAction::Action::None);
      parseDynamicActionOptionalParameters("setQueryRate", rule, action, optionalParameters);
      group->setQueryRate(std::move(rule));
    }
  });
  // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>, DynamicActionOptionalParameters)>("setResponseByteRate", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate, DynamicActionOptionalParameters optionalParameters) {
    if (group) {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, rate, warningRate ? *warningRate : 0, seconds, action ? *action : DNSAction::Action::None);
      parseDynamicActionOptionalParameters("setResponseByteRate", rule, action, optionalParameters);
      group->setResponseByteRate(std::move(rule));
    }
  });
  // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, DynBlockRulesGroup::smtVisitor_t, DynamicActionOptionalParameters)>("setSuffixMatchRule", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, DynBlockRulesGroup::smtVisitor_t visitor, DynamicActionOptionalParameters optionalParameters) {
    if (group) {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 0, 0, seconds, action ? *action : DNSAction::Action::None);
      parseDynamicActionOptionalParameters("setSuffixMatchRule", rule, action, optionalParameters);
      group->setSuffixMatchRule(std::move(rule), std::move(visitor));
    }
  });
  // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, dnsdist_ffi_stat_node_visitor_t, DynamicActionOptionalParameters)>("setSuffixMatchRuleFFI", [](std::shared_ptr<DynBlockRulesGroup>& group, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, dnsdist_ffi_stat_node_visitor_t visitor, DynamicActionOptionalParameters optionalParameters) {
    if (group) {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, 0, 0, seconds, action ? *action : DNSAction::Action::None);
      parseDynamicActionOptionalParameters("setSuffixMatchRuleFFI", rule, action, optionalParameters);
      group->setSuffixMatchRuleFFI(std::move(rule), std::move(visitor));
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(const dnsdist_ffi_dynamic_block_inserted_hook&)>("setNewBlockInsertedHook", [](std::shared_ptr<DynBlockRulesGroup>& group, const dnsdist_ffi_dynamic_block_inserted_hook& hook) {
    if (group) {
      group->setNewBlockHook(hook);
    }
  });
  // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(uint8_t, unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>, DynamicActionOptionalParameters)>("setRCodeRate", [](std::shared_ptr<DynBlockRulesGroup>& group, uint8_t rcode, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate, DynamicActionOptionalParameters optionalParameters) {
    if (group) {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, rate, warningRate ? *warningRate : 0, seconds, action ? *action : DNSAction::Action::None);
      parseDynamicActionOptionalParameters("setRCodeRate", rule, action, optionalParameters);
      group->setRCodeRate(rcode, std::move(rule));
    }
  });
  // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(uint8_t, double, unsigned int, const std::string&, unsigned int, size_t, boost::optional<DNSAction::Action>, boost::optional<double>, DynamicActionOptionalParameters)>("setRCodeRatio", [](std::shared_ptr<DynBlockRulesGroup>& group, uint8_t rcode, double ratio, unsigned int seconds, const std::string& reason, unsigned int blockDuration, size_t minimumNumberOfResponses, boost::optional<DNSAction::Action> action, boost::optional<double> warningRatio, DynamicActionOptionalParameters optionalParameters) {
    if (group) {
      DynBlockRulesGroup::DynBlockRatioRule rule(reason, blockDuration, ratio, warningRatio ? *warningRatio : 0.0, seconds, action ? *action : DNSAction::Action::None, minimumNumberOfResponses);
      parseDynamicActionOptionalParameters("setRCodeRatio", rule, action, optionalParameters);
      group->setRCodeRatio(rcode, std::move(rule));
    }
  });
  // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(uint16_t, unsigned int, unsigned int, const std::string&, unsigned int, boost::optional<DNSAction::Action>, boost::optional<unsigned int>, DynamicActionOptionalParameters)>("setQTypeRate", [](std::shared_ptr<DynBlockRulesGroup>& group, uint16_t qtype, unsigned int rate, unsigned int seconds, const std::string& reason, unsigned int blockDuration, boost::optional<DNSAction::Action> action, boost::optional<unsigned int> warningRate, DynamicActionOptionalParameters optionalParameters) {
    if (group) {
      DynBlockRulesGroup::DynBlockRule rule(reason, blockDuration, rate, warningRate ? *warningRate : 0, seconds, action ? *action : DNSAction::Action::None);
      parseDynamicActionOptionalParameters("setQTypeRate", rule, action, optionalParameters);
      group->setQTypeRate(qtype, std::move(rule));
    }
  });
  // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(double, unsigned int, const std::string&, unsigned int, size_t, double, boost::optional<DNSAction::Action>, boost::optional<double>, DynamicActionOptionalParameters)>("setCacheMissRatio", [](std::shared_ptr<DynBlockRulesGroup>& group, double ratio, unsigned int seconds, const std::string& reason, unsigned int blockDuration, size_t minimumNumberOfResponses, double minimumGlobalCacheHitRatio, boost::optional<DNSAction::Action> action, boost::optional<double> warningRatio, DynamicActionOptionalParameters optionalParameters) {
    if (group) {
      DynBlockRulesGroup::DynBlockCacheMissRatioRule rule(reason, blockDuration, ratio, warningRatio ? *warningRatio : 0.0, seconds, action ? *action : DNSAction::Action::None, minimumNumberOfResponses, minimumGlobalCacheHitRatio);
      parseDynamicActionOptionalParameters("setCacheMissRatio", rule, action, optionalParameters);
      group->setCacheMissRatio(std::move(rule));
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(uint8_t, uint8_t, uint8_t)>("setMasks", [](std::shared_ptr<DynBlockRulesGroup>& group, uint8_t v4addr, uint8_t v6addr, uint8_t port) {
    if (group) {
      if (v4addr > 32) {
        throw std::runtime_error("Trying to set an invalid IPv4 mask (" + std::to_string(v4addr) + ") to a Dynamic Block object");
      }
      if (v6addr > 128) {
        throw std::runtime_error("Trying to set an invalid IPv6 mask (" + std::to_string(v6addr) + ") to a Dynamic Block object");
      }
      if (port > 16) {
        throw std::runtime_error("Trying to set an invalid port mask (" + std::to_string(port) + ") to a Dynamic Block object");
      }
      if (port > 0 && v4addr != 32) {
        throw std::runtime_error("Setting a non-zero port mask for Dynamic Blocks while only considering parts of IPv4 addresses does not make sense");
      }
      group->setMasks(v4addr, v6addr, port);
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(boost::variant<std::string, LuaArray<std::string>, NetmaskGroup>)>("excludeRange", [](std::shared_ptr<DynBlockRulesGroup>& group, boost::variant<std::string, LuaArray<std::string>, NetmaskGroup> ranges) {
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
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(boost::variant<std::string, LuaArray<std::string>, NetmaskGroup>)>("includeRange", [](std::shared_ptr<DynBlockRulesGroup>& group, boost::variant<std::string, LuaArray<std::string>, NetmaskGroup> ranges) {
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
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(boost::variant<std::string, LuaArray<std::string>, NetmaskGroup>)>("removeRange", [](std::shared_ptr<DynBlockRulesGroup>& group, boost::variant<std::string, LuaArray<std::string>, NetmaskGroup> ranges) {
    if (ranges.type() == typeid(LuaArray<std::string>)) {
      for (const auto& range : *boost::get<LuaArray<std::string>>(&ranges)) {
        group->removeRange(Netmask(range.second));
      }
    }
    else if (ranges.type() == typeid(NetmaskGroup)) {
      group->removeRange(*boost::get<NetmaskGroup>(&ranges));
    }
    else {
      group->removeRange(Netmask(*boost::get<std::string>(&ranges)));
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)(LuaTypeOrArrayOf<std::string>)>("excludeDomains", [](std::shared_ptr<DynBlockRulesGroup>& group, LuaTypeOrArrayOf<std::string> domains) {
    if (domains.type() == typeid(LuaArray<std::string>)) {
      for (const auto& range : *boost::get<LuaArray<std::string>>(&domains)) {
        group->excludeDomain(DNSName(range.second));
      }
    }
    else {
      group->excludeDomain(DNSName(*boost::get<std::string>(&domains)));
    }
  });
  luaCtx.registerFunction<void (std::shared_ptr<DynBlockRulesGroup>::*)()>("apply", [](std::shared_ptr<DynBlockRulesGroup>& group) {
    group->apply();
  });
  luaCtx.registerFunction("setQuiet", &DynBlockRulesGroup::setQuiet);
  luaCtx.registerFunction("toString", &DynBlockRulesGroup::toString);

  /* DynBlock object accessors */
  luaCtx.registerMember("reason", &DynBlock::reason);
  luaCtx.registerMember("domain", &DynBlock::domain);
  luaCtx.registerMember<DynBlock, timespec>(
    "until", [](const DynBlock& block) {
      timespec nowMonotonic{};
      gettime(&nowMonotonic);
      timespec nowRealTime{};
      gettime(&nowRealTime, true);

      auto seconds = block.until.tv_sec - nowMonotonic.tv_sec;
      auto nseconds = block.until.tv_nsec - nowMonotonic.tv_nsec;
      if (nseconds < 0) {
        seconds -= 1;
        nseconds += 1000000000;
      }

      nowRealTime.tv_sec += seconds;
      nowRealTime.tv_nsec += nseconds;
      if (nowRealTime.tv_nsec > 1000000000) {
        nowRealTime.tv_sec += 1;
        nowRealTime.tv_nsec -= 1000000000;
      }

      return nowRealTime; }, []([[maybe_unused]] DynBlock& block, [[maybe_unused]] timespec until) {});
  luaCtx.registerMember<DynBlock, unsigned int>(
    "blocks", [](const DynBlock& block) { return block.blocks.load(); }, []([[maybe_unused]] DynBlock& block, [[maybe_unused]] unsigned int blocks) {});
  luaCtx.registerMember("action", &DynBlock::action);
  luaCtx.registerMember("warning", &DynBlock::warning);
  luaCtx.registerMember("bpf", &DynBlock::bpf);

  luaCtx.writeFunction("addDynBlockSMT",
                       // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
                       [](const LuaArray<std::string>& names, const std::string& msg, boost::optional<int> seconds, boost::optional<DNSAction::Action> action, DynamicActionOptionalParameters optionalParameters) {
                         if (names.empty()) {
                           return;
                         }
                         setLuaSideEffect();
                         timespec now{};
                         gettime(&now);
                         unsigned int actualSeconds = seconds ? *seconds : 10;
                         DynBlockRulesGroup::DynBlockRule rule;
                         parseDynamicActionOptionalParameters("addDynBlockSMT", rule, action, optionalParameters);

                         bool needUpdate = false;
                         auto smtBlocks = dnsdist::DynamicBlocks::getSuffixDynamicRulesCopy();
                         for (const auto& capair : names) {
                           DNSName domain(capair.second);
                           domain.makeUsLowerCase();
                           timespec until{now};
                           until.tv_sec += actualSeconds;
                           DynBlock dblock{msg, until, domain, action ? *action : DNSAction::Action::None};
                           dblock.tagSettings = rule.d_tagSettings;
                           if (dnsdist::DynamicBlocks::addOrRefreshBlockSMT(smtBlocks, now, std::move(dblock), false)) {
                             needUpdate = true;
                           }
                         }

                         if (needUpdate) {
                           dnsdist::DynamicBlocks::setSuffixDynamicRules(std::move(smtBlocks));
                         }
                       });

  luaCtx.writeFunction("addDynamicBlock",
                       // NOLINTNEXTLINE(performance-unnecessary-value-param): optional parameters cannot be passed by const reference
                       [](const boost::variant<ComboAddress, std::string>& clientIP, const std::string& msg, const boost::optional<DNSAction::Action> action, const boost::optional<int> seconds, boost::optional<uint8_t> clientIPMask, boost::optional<uint8_t> clientIPPortMask, DynamicActionOptionalParameters optionalParameters) {
                         setLuaSideEffect();

                         ComboAddress clientIPCA;
                         if (clientIP.type() == typeid(ComboAddress)) {
                           clientIPCA = boost::get<ComboAddress>(clientIP);
                         }
                         else {
                           const auto& clientIPStr = boost::get<std::string>(clientIP);
                           try {
                             clientIPCA = ComboAddress(clientIPStr);
                           }
                           catch (const std::exception& exp) {
                             errlog("addDynamicBlock: Unable to parse '%s': %s", clientIPStr, exp.what());
                             return;
                           }
                           catch (const PDNSException& exp) {
                             errlog("addDynamicBlock: Unable to parse '%s': %s", clientIPStr, exp.reason);
                             return;
                           }
                         }
                         AddressAndPortRange target(clientIPCA, clientIPMask ? *clientIPMask : (clientIPCA.isIPv4() ? 32 : 128), clientIPPortMask ? *clientIPPortMask : 0);
                         unsigned int actualSeconds = seconds ? *seconds : 10;
                         DynBlockRulesGroup::DynBlockRule rule;
                         parseDynamicActionOptionalParameters("addDynBlockSMT", rule, action, optionalParameters);

                         timespec now{};
                         gettime(&now);
                         timespec until{now};
                         until.tv_sec += actualSeconds;
                         DynBlock dblock{msg, until, DNSName(), action ? *action : DNSAction::Action::None};
                         dblock.tagSettings = rule.d_tagSettings;

                         auto dynamicRules = dnsdist::DynamicBlocks::getClientAddressDynamicRulesCopy();
                         if (dnsdist::DynamicBlocks::addOrRefreshBlock(dynamicRules, now, target, std::move(dblock), false)) {
                           dnsdist::DynamicBlocks::setClientAddressDynamicRules(std::move(dynamicRules));
                         }
                       });
#endif /* DISABLE_DYNBLOCKS */
}
