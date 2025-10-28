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

#include "config.h"

#include "utility.hh"
#include "rec_channel.hh"

#include <vector>
#ifdef MALLOC_TRACE
#include "malloctrace.hh"
#endif
#include "misc.hh"
#include "recursor_cache.hh"
#include "syncres.hh"
#include "negcache.hh"
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <iomanip>

#include "version.hh"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "logger.hh"
#include "dnsparser.hh"
#include "arguments.hh"
#include <sys/resource.h>
#include <sys/time.h>
#include "lock.hh"
#include "rec-lua-conf.hh"

#include "aggressive_nsec.hh"
#include "coverage.hh"
#include "validate-recursor.hh"
#include "filterpo.hh"

#include "secpoll-recursor.hh" // IWYU pragma: keep, needed by included generated file
#include "pubsuffix.hh"
#include "namespaces.hh"
#include "rec-taskqueue.hh"
#include "rec-tcpout.hh" // IWYU pragma: keep, needed by included generated file
#include "rec-main.hh"
#include "rec-system-resolve.hh"

#include "rec-rust-lib/cxxsettings.hh"

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#if __has_feature(address_sanitizer)
#define __SANITIZE_ADDRESS__ 1
#endif
#endif

#if defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE)
#include <sanitizer/lsan_interface.h>
#endif

std::pair<std::string, std::string> PrefixDashNumberCompare::prefixAndTrailingNum(const std::string& arg)
{
  auto length = arg.length();
  if (length == 0) {
    return {arg, ""};
  }
  --length;
  if (std::isdigit(arg[length]) == 0) {
    return {arg, ""};
  }
  while (length > 0) {
    if (std::isdigit(arg[length]) == 0) {
      break;
    }
    --length;
  }
  return {arg.substr(0, length + 1), arg.substr(length + 1, arg.size() - length - 1)};
}

bool PrefixDashNumberCompare::operator()(const std::string& lhs, const std::string& rhs) const
{
  auto [aprefix, anum] = prefixAndTrailingNum(lhs);
  auto [bprefix, bnum] = prefixAndTrailingNum(rhs);

  if (aprefix != bprefix || anum.length() == 0 || bnum.length() == 0) {
    return lhs < rhs;
  }
  return std::stoull(anum) < std::stoull(bnum);
}

static map<string, const pdns::stat_t*> d_getatomics;
static map<string, std::function<uint64_t()>> d_get64bitmembers;
static map<string, std::function<StatsMap()>> d_getmultimembers;

struct dynmetrics
{
  std::atomic<unsigned long>* d_ptr;
  std::string d_prometheusName;
};

static LockGuarded<map<string, dynmetrics>> d_dynmetrics;

static std::map<StatComponent, std::set<std::string>> s_disabledStats;

bool isStatDisabled(StatComponent component, const string& name)
{
  return s_disabledStats[component].count(name) != 0;
}

void disableStat(StatComponent component, const string& name)
{
  s_disabledStats[component].insert(name);
}

void disableStats(StatComponent component, const string& stats)
{
  std::vector<std::string> disabledStats;
  stringtok(disabledStats, stats, ", ");
  auto& map = s_disabledStats[component];
  for (const auto& stat : disabledStats) {
    map.insert(stat);
  }
}

static void addGetStat(const string& name, const pdns::stat_t* place)
{
  if (!d_getatomics.emplace(name, place).second) {
    cerr << "addGetStat: double def " << name << endl;
    _exit(1);
  }
}

static void addGetStat(const string& name, std::function<uint64_t()> func)
{
  if (!d_get64bitmembers.emplace(name, std::move(func)).second) {
    cerr << "addGetStat: double def " << name << endl;
    _exit(1);
  }
}

static void addGetStat(const string& name, std::function<StatsMap()> func)
{
  if (!d_getmultimembers.emplace(name, std::move(func)).second) {
    cerr << "addGetStat: double def " << name << endl;
    _exit(1);
  }
}

static std::string getPrometheusName(const std::string& arg)
{
  std::string name = arg;
  std::replace_if(
    name.begin(), name.end(), [](char letter) { return isalnum(static_cast<unsigned char>(letter)) == 0; }, '_');
  return "pdns_recursor_" + name;
}

std::atomic<unsigned long>* getDynMetric(const std::string& str, const std::string& prometheusName)
{
  auto locked = d_dynmetrics.lock();
  auto iter = locked->find(str);
  if (iter != locked->end()) {
    return iter->second.d_ptr;
  }

  std::string name(str);
  if (!prometheusName.empty()) {
    name = prometheusName;
  }
  else {
    name = getPrometheusName(name);
  }

  auto ret = dynmetrics{new std::atomic<unsigned long>(), std::move(name)};
  (*locked)[str] = ret;
  return ret.d_ptr;
}

static std::optional<uint64_t> get(const string& name)
{
  std::optional<uint64_t> ret;

  if (d_getatomics.count(name) != 0) {
    return d_getatomics.find(name)->second->load();
  }
  if (d_get64bitmembers.count(name) != 0) {
    return d_get64bitmembers.find(name)->second();
  }

  {
    auto lcoked = d_dynmetrics.lock();
    const auto* ptr = rplookup(*lcoked, name);
    if (ptr != nullptr) {
      return ptr->d_ptr->load();
    }
  }

  for (const auto& themultimember : d_getmultimembers) {
    const auto items = themultimember.second();
    const auto item = items.find(name);
    if (item != items.end()) {
      return std::stoull(item->second.d_value);
    }
  }

  return ret;
}

std::optional<uint64_t> getStatByName(const std::string& name)
{
  return get(name);
}

StatsMap getAllStatsMap(StatComponent component)
{
  StatsMap ret;
  const auto& disabledlistMap = s_disabledStats.at(component);

  for (const auto& atomic : d_getatomics) {
    if (disabledlistMap.count(atomic.first) == 0) {
      ret.emplace(atomic.first, StatsMapEntry{getPrometheusName(atomic.first), std::to_string(atomic.second->load())});
    }
  }

  for (const auto& the64bitmembers : d_get64bitmembers) {
    if (disabledlistMap.count(the64bitmembers.first) == 0) {
      ret.emplace(the64bitmembers.first, StatsMapEntry{getPrometheusName(the64bitmembers.first), std::to_string(the64bitmembers.second())});
    }
  }

  for (const auto& themultimember : d_getmultimembers) {
    if (disabledlistMap.count(themultimember.first) == 0) {
      ret.merge(themultimember.second());
    }
  }

  {
    for (const auto& value : *(d_dynmetrics.lock())) {
      if (disabledlistMap.count(value.first) == 0) {
        ret.emplace(value.first, StatsMapEntry{value.second.d_prometheusName, std::to_string(*value.second.d_ptr)});
      }
    }
  }

  return ret;
}

using ArgIterator = vector<string>::iterator;
using Answer = RecursorControlChannel::Answer;

static Answer getAllStats(ArgIterator /* begin */, ArgIterator /* end */)
{
  auto varmap = getAllStatsMap(StatComponent::RecControl);
  string ret;
  for (const auto& tup : varmap) {
    ret += tup.first + "\t" + tup.second.d_value + "\n";
  }
  return {0, std::move(ret)};
}

static Answer doGet(ArgIterator begin, ArgIterator end)
{
  string ret;

  for (auto i = begin; i != end; ++i) {
    std::optional<uint64_t> num = get(*i);
    if (num) {
      ret += std::to_string(*num) + "\n";
    }
    else {
      ret += "UNKNOWN\n";
    }
  }
  return {0, std::move(ret)};
}

static Answer doGetParameter(ArgIterator begin, ArgIterator end)
{
  if (!g_yamlSettings) {
    std::stringstream ret;

    for (auto i = begin; i != end; ++i) {
      if (::arg().parmIsset(*i)) {
        const auto& parm = arg()[*i];
        ret << *i << '=' << parm << endl;
      }
      else {
        ret << *i << " not known" << endl;
      }
    }
    return {0, ret.str()};
  }
  auto settings = g_yamlStruct.lock();
  rust::Vec<::rust::String> field;
  stringtok(field, *begin, ".");
  try {
    auto yaml = settings->get_value(field);
    return {0, std::string(yaml)};
  }
  catch (const std::exception& stdex) {
    return {1, std::string(stdex.what()) + '\n'};
  }
}

/* Read an (open) fd from the control channel */
static FDWrapper
getfd(int socket)
{
  int fileDesc = -1;
  struct msghdr msg{};
  struct cmsghdr* cmsg{};
  union
  {
    struct cmsghdr hdr;
    std::array<unsigned char, CMSG_SPACE(sizeof(int))> buf{};
  } cmsgbuf;
  std::array<struct iovec, 1> io_vector{};
  char character = 0;

  io_vector[0].iov_base = &character;
  io_vector[0].iov_len = 1;

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = cmsgbuf.buf.data();
  msg.msg_controllen = cmsgbuf.buf.size();
  msg.msg_iov = io_vector.data();
  msg.msg_iovlen = io_vector.size();

  if (recvmsg(socket, &msg, 0) == -1) {
    throw PDNSException("recvmsg");
  }
  if ((msg.msg_flags & MSG_TRUNC) != 0 || (msg.msg_flags & MSG_CTRUNC) != 0) {
    throw PDNSException("control message truncated");
  }
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
      fileDesc = *reinterpret_cast<int*>(CMSG_DATA(cmsg)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast)
      break;
    }
  }
  return fileDesc;
}

static uint64_t dumpAggressiveNSECCache(int fileDesc)
{
  if (!g_aggressiveNSECCache) {
    return 0;
  }

  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    return 0;
  }
  fprintf(filePtr.get(), "; aggressive NSEC cache dump follows\n;\n");

  struct timeval now{};
  Utility::gettimeofday(&now, nullptr);
  return g_aggressiveNSECCache->dumpToFile(filePtr, now);
}

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
static uint64_t* pleaseDumpCookiesMap(int fileDesc)
{
  return new uint64_t(dumpCookies(fileDesc));
}

static uint64_t* pleaseDumpEDNSMap(int fileDesc)
{
  return new uint64_t(SyncRes::doEDNSDump(fileDesc));
}

static uint64_t* pleaseDumpNSSpeeds(int fileDesc)
{
  return new uint64_t(SyncRes::doDumpNSSpeeds(fileDesc));
}

static uint64_t* pleaseDumpThrottleMap(int fileDesc)
{
  return new uint64_t(SyncRes::doDumpThrottleMap(fileDesc));
}

static uint64_t* pleaseDumpFailedServers(int fileDesc)
{
  return new uint64_t(SyncRes::doDumpFailedServers(fileDesc));
}

static uint64_t* pleaseDumpSavedParentNSSets(int fileDesc)
{
  return new uint64_t(SyncRes::doDumpSavedParentNSSets(fileDesc));
}

static uint64_t* pleaseDumpNonResolvingNS(int fileDesc)
{
  return new uint64_t(SyncRes::doDumpNonResolvingNS(fileDesc));
}

static uint64_t* pleaseDumpDoTProbeMap(int fileDesc)
{
  return new uint64_t(SyncRes::doDumpDoTProbeMap(fileDesc));
}
// NOLINTEND(cppcoreguidelines-owning-memory)

// Generic dump to file command
static RecursorControlChannel::Answer doDumpToFile(int socket, uint64_t* (*function)(int), const string& name, bool threads = true)
{
  auto fdw = getfd(socket);

  if (fdw < 0) {
    return {1, name + ": error opening dump file for writing: " + stringerror() + "\n"};
  }

  uint64_t total = 0;
  try {
    if (threads) {
      int fileDesc = fdw;
      total = broadcastAccFunction<uint64_t>([function, fileDesc] { return function(fileDesc); });
    }
    else {
      auto* ret = function(fdw);
      total = *ret;
      delete ret; // NOLINT(cppcoreguidelines-owning-memory)
    }
  }
  catch (std::exception& e) {
    return {1, name + ": error dumping data: " + string(e.what()) + "\n"};
  }
  catch (PDNSException& e) {
    return {1, name + ": error dumping data: " + e.reason + "\n"};
  }

  return {0, name + ": dumped " + std::to_string(total) + " records\n"};
}

// Does not follow the generic dump to file pattern, has a more complex lambda
static RecursorControlChannel::Answer doDumpCache(int socket, ArgIterator begin, ArgIterator end)
{
  auto fdw = getfd(socket);

  if (fdw < 0) {
    return {1, "Error opening dump file for writing: " + stringerror() + "\n"};
  }
  bool dumpRecordCache = true;
  bool dumpNegCache = true;
  bool dumpPacketCache = true;
  bool dumpAggrCache = true;
  if (begin != end) {
    dumpRecordCache = false;
    dumpNegCache = false;
    dumpPacketCache = false;
    dumpAggrCache = false;
    for (auto name = begin; name != end; ++name) {
      if (*name == "r") {
        dumpRecordCache = true;
      }
      else if (*name == "n") {
        dumpNegCache = true;
      }
      else if (*name == "p") {
        dumpPacketCache = true;
      }
      else if (*name == "a") {
        dumpAggrCache = true;
      }
    }
  }
  uint64_t total = 0;
  try {
    if (dumpRecordCache) {
      total += g_recCache->doDump(fdw, g_maxCacheEntries.load());
    }
    if (dumpNegCache) {
      total += g_negCache->doDump(fdw, g_maxCacheEntries.load() / 8);
    }
    if (dumpPacketCache) {
      total += g_packetCache ? g_packetCache->doDump(fdw) : 0;
    }
    if (dumpAggrCache) {
      total += dumpAggressiveNSECCache(fdw);
    }
  }
  catch (...) {
    ;
  }

  return {0, "dumped " + std::to_string(total) + " records\n"};
}

// Does not follow the generic dump to file pattern, has an argument
static RecursorControlChannel::Answer doDumpRPZ(int socket, ArgIterator begin, ArgIterator end)
{
  auto fdw = getfd(socket);

  if (fdw < 0) {
    return {1, "Error opening dump file for writing: " + stringerror() + "\n"};
  }

  auto iter = begin;

  if (iter == end) {
    return {1, "No zone name specified\n"};
  }
  const string& zoneName = *iter;

  auto luaconf = g_luaconfs.getLocal();
  const auto zone = luaconf->dfe.getZone(zoneName);
  if (!zone) {
    return {1, "No RPZ zone named " + zoneName + "\n"};
  }

  auto filePtr = pdns::UniqueFilePtr(fdopen(fdw, "w"));
  if (!filePtr) {
    int err = errno;
    return {1, "converting file descriptor: " + stringerror(err) + "\n"};
  }

  zone->dump(filePtr.get());

  return {0, "done\n"};
}

static Answer doWipeCache(ArgIterator begin, ArgIterator end, uint16_t qtype)
{
  vector<pair<DNSName, bool>> toWipe;
  for (auto i = begin; i != end; ++i) {
    DNSName canon;
    bool subtree = false;

    try {
      if (boost::ends_with(*i, "$")) {
        canon = DNSName(i->substr(0, i->size() - 1));
        subtree = true;
      }
      else {
        canon = DNSName(*i);
      }
    }
    catch (std::exception& e) {
      return {1, "Error: " + std::string(e.what()) + ", nothing wiped\n"};
    }
    toWipe.emplace_back(canon, subtree);
  }

  int count = 0;
  int pcount = 0;
  int countNeg = 0;
  for (const auto& wipe : toWipe) {
    try {
      auto res = wipeCaches(wipe.first, wipe.second, qtype);
      count += res.record_count;
      pcount += res.packet_count;
      countNeg += res.negative_record_count;
    }
    catch (const std::exception& e) {
      g_log << Logger::Warning << ", failed: " << e.what() << endl;
    }
  }

  return {0, "wiped " + std::to_string(count) + " records, " + std::to_string(countNeg) + " negative records, " + std::to_string(pcount) + " packets\n"};
}

static Answer doSetCarbonServer(ArgIterator begin, ArgIterator end)
{
  auto config = g_carbonConfig.getCopy();
  if (begin == end) {
    config.servers.clear();
    g_carbonConfig.setState(std::move(config));
    return {0, "cleared carbon-server setting\n"};
  }

  string ret;
  stringtok(config.servers, *begin, ", ");
  ret = "set carbon-server to '" + *begin + "'\n";

  ++begin;
  if (begin != end) {
    config.hostname = *begin;
    ret += "set carbon-ourname to '" + *begin + "'\n";
  }
  else {
    g_carbonConfig.setState(std::move(config));
    return {0, std::move(ret)};
  }

  ++begin;
  if (begin != end) {
    config.namespace_name = *begin;
    ret += "set carbon-namespace to '" + *begin + "'\n";
  }
  else {
    g_carbonConfig.setState(std::move(config));
    return {0, ret};
  }

  ++begin;
  if (begin != end) {
    config.instance_name = *begin;
    ret += "set carbon-instance to '" + *begin + "'\n";
  }

  g_carbonConfig.setState(std::move(config));
  return {0, std::move(ret)};
}

static Answer doSetDnssecLogBogus(ArgIterator begin, ArgIterator end)
{
  if (checkDNSSECDisabled()) {
    return {1, "DNSSEC is disabled in the configuration, not changing the Bogus logging setting\n"};
  }
  if (begin == end) {
    return {1, "No DNSSEC Bogus logging setting specified\n"};
  }
  if (pdns_iequals(*begin, "on") || pdns_iequals(*begin, "yes")) {
    if (!g_dnssecLogBogus) {
      g_log << Logger::Warning << "Enabling DNSSEC Bogus logging, requested via control channel" << endl;
      g_dnssecLogBogus = true;
      return {0, "DNSSEC Bogus logging enabled\n"};
    }
    return {0, "DNSSEC Bogus logging was already enabled\n"};
  }

  if (pdns_iequals(*begin, "off") || pdns_iequals(*begin, "no")) {
    if (g_dnssecLogBogus) {
      g_log << Logger::Warning << "Disabling DNSSEC Bogus logging, requested via control channel" << endl;
      g_dnssecLogBogus = false;
      return {0, "DNSSEC Bogus logging disabled\n"};
    }
    return {0, "DNSSEC Bogus logging was already disabled\n"};
  }

  return {1, "Unknown DNSSEC Bogus setting: '" + *begin + "'\n"};
}

static Answer doAddNTA(ArgIterator begin, ArgIterator end)
{
  if (checkDNSSECDisabled()) {
    return {1, "DNSSEC is disabled in the configuration, not adding a Negative Trust Anchor\n"};
  }
  if (begin == end) {
    return {1, "No NTA specified, doing nothing\n"};
  }
  DNSName who;
  try {
    who = DNSName(*begin);
  }
  catch (std::exception& e) {
    string ret("Can't add Negative Trust Anchor: ");
    ret += e.what();
    ret += "\n";
    return {1, std::move(ret)};
  }
  begin++;

  string why;
  while (begin != end) {
    why += *begin;
    begin++;
    if (begin != end) {
      why += " ";
    }
  }
  g_log << Logger::Warning << "Adding Negative Trust Anchor for " << who << " with reason '" << why << "', requested via control channel" << endl;
  g_luaconfs.modify([who, why](LuaConfigItems& lci) {
    lci.negAnchors[who] = why;
  });
  try {
    wipeCaches(who, true, 0xffff);
  }
  catch (std::exception& e) {
    g_log << Logger::Warning << ", failed: " << e.what() << endl;
    return {1, "Unable to clear caches while adding Negative Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n"};
  }
  return {0, "Added Negative Trust Anchor for " + who.toLogString() + " with reason '" + why + "'\n"};
}

static Answer doClearNTA(ArgIterator begin, ArgIterator end)
{
  if (checkDNSSECDisabled()) {
    return {1, "DNSSEC is disabled in the configuration, not removing a Negative Trust Anchor\n"};
  }
  if (begin == end) {
    return {1, "No Negative Trust Anchor specified, doing nothing.\n"};
  }
  if (begin + 1 == end && *begin == "*") {
    g_log << Logger::Warning << "Clearing all Negative Trust Anchors, requested via control channel" << endl;
    g_luaconfs.modify([](LuaConfigItems& lci) {
      lci.negAnchors.clear();
    });
    return {0, "Cleared all Negative Trust Anchors.\n"};
  }

  vector<DNSName> toRemove;
  DNSName who;
  while (begin != end) {
    if (*begin == "*") {
      return {1, "Don't mix all Negative Trust Anchor removal with multiple Negative Trust Anchor removal. Nothing removed\n"};
    }
    try {
      who = DNSName(*begin);
    }
    catch (std::exception& e) {
      string ret("Error: ");
      ret += e.what();
      ret += ". No Negative Anchors removed\n";
      return {1, std::move(ret)};
    }
    toRemove.push_back(who);
    begin++;
  }

  string removed;
  bool first(true);
  try {
    for (auto const& entry : toRemove) {
      g_log << Logger::Warning << "Clearing Negative Trust Anchor for " << entry << ", requested via control channel" << endl;
      g_luaconfs.modify([entry](LuaConfigItems& lci) {
        lci.negAnchors.erase(entry);
      });
      wipeCaches(entry, true, 0xffff);
      if (!first) {
        first = false;
        removed += ",";
      }
      removed += " " + entry.toStringRootDot();
    }
  }
  catch (std::exception& e) {
    g_log << Logger::Warning << ", failed: " << e.what() << endl;
    return {1, "Unable to clear caches while clearing Negative Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n"};
  }

  return {0, "Removed Negative Trust Anchors for " + removed + "\n"};
}

static Answer getNTAs(ArgIterator /* begin */, ArgIterator /* end */)
{
  if (checkDNSSECDisabled()) {
    return {1, "DNSSEC is disabled in the configuration\n"};
  }
  string ret("Configured Negative Trust Anchors:\n");
  auto luaconf = g_luaconfs.getLocal();
  for (const auto& negAnchor : luaconf->negAnchors) {
    ret += negAnchor.first.toLogString() + "\t" + negAnchor.second + "\n";
  }
  return {0, std::move(ret)};
}

static Answer doAddTA(ArgIterator begin, ArgIterator end)
{
  if (checkDNSSECDisabled()) {
    return {1, "DNSSEC is disabled in the configuration, not adding a Trust Anchor\n"};
  }
  if (begin == end) {
    return {1, "No TA specified, doing nothing\n"};
  }
  DNSName who;
  try {
    who = DNSName(*begin);
  }
  catch (std::exception& e) {
    string ret("Can't add Trust Anchor: ");
    ret += e.what();
    ret += "\n";
    return {1, std::move(ret)};
  }
  begin++;

  string what;
  while (begin != end) {
    what += *begin + " ";
    begin++;
  }

  try {
    g_log << Logger::Warning << "Adding Trust Anchor for " << who << " with data '" << what << "', requested via control channel";
    g_luaconfs.modify([who, what](LuaConfigItems& lci) {
      auto dsRecord = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(what));
      lci.dsAnchors[who].insert(*dsRecord);
    });
    wipeCaches(who, true, 0xffff);
    g_log << Logger::Warning << endl;
    return {0, "Added Trust Anchor for " + who.toStringRootDot() + " with data " + what + "\n"};
  }
  catch (std::exception& e) {
    g_log << Logger::Warning << ", failed: " << e.what() << endl;
    return {1, "Unable to add Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n"};
  }
}

static Answer doClearTA(ArgIterator begin, ArgIterator end)
{
  if (checkDNSSECDisabled()) {
    return {1, "DNSSEC is disabled in the configuration, not removing a Trust Anchor\n"};
  }
  if (begin == end) {
    return {1, "No Trust Anchor to clear\n"};
  }
  vector<DNSName> toRemove;
  DNSName who;
  while (begin != end) {
    try {
      who = DNSName(*begin);
    }
    catch (std::exception& e) {
      string ret("Error: ");
      ret += e.what();
      ret += ". No Anchors removed\n";
      return {1, std::move(ret)};
    }
    if (who.isRoot()) {
      return {1, "Refusing to remove root Trust Anchor, no Anchors removed\n"};
    }
    toRemove.push_back(who);
    begin++;
  }

  string removed;
  bool first = true;
  try {
    for (auto const& entry : toRemove) {
      g_log << Logger::Warning << "Removing Trust Anchor for " << entry << ", requested via control channel" << endl;
      g_luaconfs.modify([entry](LuaConfigItems& lci) {
        lci.dsAnchors.erase(entry);
      });
      wipeCaches(entry, true, 0xffff);
      if (!first) {
        first = false;
        removed += ",";
      }
      removed += " " + entry.toStringRootDot();
    }
  }
  catch (std::exception& e) {
    g_log << Logger::Warning << ", failed: " << e.what() << endl;
    return {1, "Unable to clear caches while clearing Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n"};
  }

  return {0, "Removed Trust Anchor(s) for" + removed + "\n"};
}

static Answer getTAs(ArgIterator /* begin */, ArgIterator /* end */)
{
  if (checkDNSSECDisabled()) {
    return {1, "DNSSEC is disabled in the configuration\n"};
  }
  string ret("Configured Trust Anchors:\n");
  auto luaconf = g_luaconfs.getLocal();
  for (const auto& anchor : luaconf->dsAnchors) {
    ret += anchor.first.toLogString() + "\n";
    for (const auto& entry : anchor.second) {
      ret += "\t\t" + entry.getZoneRepresentation() + "\n";
    }
  }

  return {0, std::move(ret)};
}

static Answer setMinimumTTL(ArgIterator begin, ArgIterator end)
{
  if (end - begin != 1) {
    return {1, "Need to supply new minimum TTL number\n"};
  }
  try {
    pdns::checked_stoi_into(SyncRes::s_minimumTTL, *begin);
    return {0, "New minimum TTL: " + std::to_string(SyncRes::s_minimumTTL) + "\n"};
  }
  catch (const std::exception& e) {
    return {1, "Error parsing the new minimum TTL number: " + std::string(e.what()) + "\n"};
  }
}

static Answer setMinimumECSTTL(ArgIterator begin, ArgIterator end)
{
  if (end - begin != 1) {
    return {1, "Need to supply new ECS minimum TTL number\n"};
  }
  try {
    pdns::checked_stoi_into(SyncRes::s_minimumECSTTL, *begin);
    return {0, "New minimum ECS TTL: " + std::to_string(SyncRes::s_minimumECSTTL) + "\n"};
  }
  catch (const std::exception& e) {
    return {1, "Error parsing the new ECS minimum TTL number: " + std::string(e.what()) + "\n"};
  }
}

static Answer setMaxCacheEntries(ArgIterator begin, ArgIterator end)
{
  if (end - begin != 1) {
    return {1, "Need to supply new cache size\n"};
  }
  try {
    g_maxCacheEntries = pdns::checked_stoi<uint32_t>(*begin);
    return {0, "New max cache entries: " + std::to_string(g_maxCacheEntries) + "\n"};
  }
  catch (const std::exception& e) {
    return {1, "Error parsing the new cache size: " + std::string(e.what()) + "\n"};
  }
}

static Answer setMaxPacketCacheEntries(ArgIterator begin, ArgIterator end)
{
  if (end - begin != 1) {
    return {0, "Need to supply new packet cache size\n"};
  }
  if (::arg().mustDo("disable-packetcache")) {
    return {1, "Packet cache is disabled\n"};
  }
  try {
    g_maxPacketCacheEntries = pdns::checked_stoi<uint32_t>(*begin);
    g_packetCache->setMaxSize(g_maxPacketCacheEntries);
    return {0, "New max packetcache entries: " + std::to_string(g_maxPacketCacheEntries) + "\n"};
  }
  catch (const std::exception& e) {
    return {1, "Error parsing the new packet cache size: " + std::string(e.what()) + "\n"};
  }
}

static RecursorControlChannel::Answer setAggrNSECCacheSize(ArgIterator begin, ArgIterator end)
{
  if (end - begin != 1) {
    return {1, "Need to supply new aggressive NSEC cache size\n"};
  }
  if (!g_aggressiveNSECCache) {
    return {1, "Aggressive NSEC cache is disabled by startup config\n"};
  }
  try {
    auto newmax = pdns::checked_stoi<uint64_t>(*begin);
    g_aggressiveNSECCache->setMaxEntries(newmax);
    return {0, "New aggressive NSEC cache size: " + std::to_string(newmax) + "\n"};
  }
  catch (const std::exception& e) {
    return {1, "Error parsing the new aggressive NSEC cache size: " + std::string(e.what()) + "\n"};
  }
}

static uint64_t getSysTimeMsec()
{
  struct rusage usage{};
  getrusage(RUSAGE_SELF, &usage);
  return (usage.ru_stime.tv_sec * 1000ULL) + (usage.ru_stime.tv_usec / 1000);
}

static uint64_t getUserTimeMsec()
{
  struct rusage usage{};
  getrusage(RUSAGE_SELF, &usage);
  return (usage.ru_utime.tv_sec * 1000ULL) + (usage.ru_utime.tv_usec / 1000);
}

/* This is a pretty weird set of functions. To get per-thread cpu usage numbers,
   we have to ask a thread over a pipe. We could do so surgically, so if you want to know about
   thread 3, we pick pipe 3, but we lack that infrastructure.

   We can however ask "execute this function on all threads and add up the results".
   This is what the first function does using a custom object ThreadTimes, which if you add
   to each other keeps filling the first one with CPU usage numbers
*/

static ThreadTimes* pleaseGetThreadCPUMsec()
{
  uint64_t ret = 0;
#ifdef RUSAGE_THREAD
  struct rusage ru;
  getrusage(RUSAGE_THREAD, &ru);
  ret = (ru.ru_utime.tv_sec * 1000ULL + ru.ru_utime.tv_usec / 1000);
  ret += (ru.ru_stime.tv_sec * 1000ULL + ru.ru_stime.tv_usec / 1000);
#endif
  return new ThreadTimes{ret, vector<uint64_t>()}; // NOLINT(cppcoreguidelines-owning-memory)
}

/* Next up, when you want msec data for a specific thread, we check
   if we recently executed pleaseGetThreadCPUMsec. If we didn't we do so
   now and consult all threads.

   We then answer you from the (re)fresh(ed) ThreadTimes.
*/
static uint64_t doGetThreadCPUMsec(unsigned int n)
{
  static std::mutex s_mut;
  static time_t last = 0;
  static ThreadTimes threadTimes;

  auto lock = std::scoped_lock(s_mut);
  if (last != time(nullptr)) {
    threadTimes = broadcastAccFunction<ThreadTimes>(pleaseGetThreadCPUMsec);
    last = time(nullptr);
  }

  return threadTimes.times.at(n);
}

static ProxyMappingStats_t* pleaseGetProxyMappingStats()
{
  auto* ret = new ProxyMappingStats_t; // NOLINT(cppcoreguidelines-owning-memory)
  if (t_proxyMapping) {
    for (const auto& [key, entry] : *t_proxyMapping) {
      ret->emplace(key, ProxyMappingCounts{entry.stats.netmaskMatches, entry.stats.suffixMatches});
    }
  }
  return ret;
}

static RemoteLoggerStats_t* pleaseGetRemoteLoggerStats()
{
  auto ret = make_unique<RemoteLoggerStats_t>(); // NOLINT(cppcoreguidelines-owning-memory)

  if (t_protobufServers.servers) {
    for (const auto& server : *t_protobufServers.servers) {
      ret->emplace(server->address(), server->getStats());
    }
  }
  return ret.release();
}

static Answer doGetProxyMappingStats(ArgIterator /* begin */, ArgIterator /* end */)
{
  ostringstream ret;
  ret << "subnet\t\t\tmatches\tsuffixmatches" << endl;
  auto proxyMappingStats = broadcastAccFunction<ProxyMappingStats_t>(pleaseGetProxyMappingStats);
  for (const auto& [key, entry] : proxyMappingStats) {
    ret << key.toString() << '\t' << entry.netmaskMatches << '\t' << entry.suffixMatches << endl;
  }
  return {0, ret.str()};
}

static RemoteLoggerStats_t* pleaseGetOutgoingRemoteLoggerStats()
{
  auto ret = make_unique<RemoteLoggerStats_t>();

  if (t_outgoingProtobufServers.servers) {
    for (const auto& server : *t_outgoingProtobufServers.servers) {
      ret->emplace(server->address(), server->getStats());
    }
  }
  return ret.release();
}

#ifdef HAVE_FSTRM
static RemoteLoggerStats_t* pleaseGetFramestreamLoggerStats()
{
  auto ret = make_unique<RemoteLoggerStats_t>();

  if (t_frameStreamServersInfo.servers) {
    for (const auto& server : *t_frameStreamServersInfo.servers) {
      ret->emplace(server->address(), server->getStats());
    }
  }
  return ret.release();
}

static RemoteLoggerStats_t* pleaseGetNODFramestreamLoggerStats()
{
  auto ret = make_unique<RemoteLoggerStats_t>();

  if (t_nodFrameStreamServersInfo.servers) {
    for (const auto& server : *t_nodFrameStreamServersInfo.servers) {
      ret->emplace(server->address(), server->getStats());
    }
  }
  return ret.release();
}
#endif

static void remoteLoggerStats(const string& type, const RemoteLoggerStats_t& stats, ostringstream& outpustStream)
{
  if (stats.empty()) {
    return;
  }
  for (const auto& [key, entry] : stats) {
    outpustStream << entry.d_queued << '\t' << entry.d_pipeFull << '\t' << entry.d_tooLarge << '\t' << entry.d_otherError << '\t' << key << '\t' << type << endl;
  }
}

static Answer getRemoteLoggerStats(ArgIterator /* begin */, ArgIterator /* end */)
{
  ostringstream outputStream;
  outputStream << "Queued\tPipe-\tToo-\tOther-\tAddress\tType" << endl;
  outputStream << "\tFull\tLarge\terror" << endl;
  auto stats = broadcastAccFunction<RemoteLoggerStats_t>(pleaseGetRemoteLoggerStats);
  remoteLoggerStats("protobuf", stats, outputStream);
  stats = broadcastAccFunction<RemoteLoggerStats_t>(pleaseGetOutgoingRemoteLoggerStats);
  remoteLoggerStats("outgoingProtobuf", stats, outputStream);
#ifdef HAVE_FSTRM
  stats = broadcastAccFunction<RemoteLoggerStats_t>(pleaseGetFramestreamLoggerStats);
  remoteLoggerStats("dnstapFrameStream", stats, outputStream);
  stats = broadcastAccFunction<RemoteLoggerStats_t>(pleaseGetNODFramestreamLoggerStats);
  remoteLoggerStats("dnstapNODFrameStream", stats, outputStream);
#endif
  return {0, outputStream.str()};
}

static string* pleaseGetCurrentQueries()
{
  ostringstream ostr;
  struct timeval now{};
  gettimeofday(&now, nullptr);

  ostr << getMT()->getWaiters().size() << " currently outstanding questions\n";

  boost::format fmt("%1% %|40t|%2% %|47t|%3% %|63t|%4% %|68t|%5% %|78t|%6%\n");

  ostr << (fmt % "qname" % "qtype" % "remote" % "tcp" % "chained" % "spent(ms)");
  unsigned int count = 0;
  for (const auto& mthread : getMT()->getWaiters()) {
    const std::shared_ptr<PacketID>& pident = mthread.key;
    const double spent = g_networkTimeoutMsec - (DiffTime(now, mthread.ttd) * 1000);
    ostr << (fmt
             % pident->domain.toLogString() /* ?? */ % DNSRecordContent::NumberToType(pident->type)
             % pident->remote.toString() % ((pident->tcpsock != 0) ? 'Y' : 'n')
             % (pident->fd == -1 ? 'Y' : 'n')
             % (spent > 0 ? spent : '0'));
    ++count;
    if (count >= 100) {
      break;
    }
  }
  ostr << " - done\n";
  return new string(ostr.str()); // NOLINT(cppcoreguidelines-owning-memory)
}

static Answer doCurrentQueries(ArgIterator /* begin */, ArgIterator /* end */)
{
  return {0, broadcastAccFunction<string>(pleaseGetCurrentQueries)};
}

static uint64_t getNegCacheSize()
{
  return g_negCache->size();
}

uint64_t* pleaseGetConcurrentQueries()
{
  return new uint64_t((getMT() != nullptr) ? getMT()->numProcesses() : 0); // NOLINT(cppcoreguidelines-owning-memory)
}

static uint64_t getConcurrentQueries()
{
  return broadcastAccFunction<uint64_t>(pleaseGetConcurrentQueries);
}

static uint64_t doGetCacheSize()
{
  return g_recCache->size();
}

static uint64_t doGetCacheBytes()
{
  return g_recCache->bytes();
}

static uint64_t doGetMallocated()
{
  // this turned out to be broken
  /*  struct mallinfo mi = mallinfo();
  return mi.uordblks; */
  return 0;
}

static StatsMap toStatsMap(const string& name, const pdns::Histogram& histogram)
{
  const auto& data = histogram.getCumulativeBuckets();
  const string pbasename = getPrometheusName(name);
  StatsMap entries;
  std::array<char, 32> buf{};

  for (const auto& bucket : data) {
    snprintf(buf.data(), buf.size(), "%g", static_cast<double>(bucket.d_boundary) / 1e6);
    std::string pname = pbasename + "seconds_bucket{" + "le=\"" + (bucket.d_boundary == std::numeric_limits<uint64_t>::max() ? "+Inf" : buf.data()) + "\"}";
    entries.emplace(bucket.d_name, StatsMapEntry{std::move(pname), std::to_string(bucket.d_count)});
  }

  snprintf(buf.data(), buf.size(), "%g", static_cast<double>(histogram.getSum()) / 1e6);
  entries.emplace(name + "sum", StatsMapEntry{pbasename + "seconds_sum", buf.data()});
  entries.emplace(name + "count", StatsMapEntry{pbasename + "seconds_count", std::to_string(data.back().d_count)});

  return entries;
}

static StatsMap toStatsMap(const string& name, const pdns::Histogram& histogram4, const pdns::Histogram& histogram6)
{
  const string pbasename = getPrometheusName(name);
  StatsMap entries;
  std::array<char, 32> buf{};
  std::string pname;

  const auto& data4 = histogram4.getCumulativeBuckets();
  for (const auto& bucket : data4) {
    snprintf(buf.data(), buf.size(), "%g", static_cast<double>(bucket.d_boundary) / 1e6);
    pname = pbasename + R"(seconds_bucket{ipversion="v4",le=")" + (bucket.d_boundary == std::numeric_limits<uint64_t>::max() ? "+Inf" : buf.data()) + "\"}";
    entries.emplace(bucket.d_name + "4", StatsMapEntry{pname, std::to_string(bucket.d_count)});
  }
  snprintf(buf.data(), buf.size(), "%g", static_cast<double>(histogram4.getSum()) / 1e6);
  entries.emplace(name + "sum4", StatsMapEntry{pbasename + "seconds_sum{ipversion=\"v4\"}", buf.data()});
  entries.emplace(name + "count4", StatsMapEntry{pbasename + "seconds_count{ipversion=\"v4\"}", std::to_string(data4.back().d_count)});

  const auto& data6 = histogram6.getCumulativeBuckets();
  for (const auto& bucket : data6) {
    snprintf(buf.data(), buf.size(), "%g", static_cast<double>(bucket.d_boundary) / 1e6);
    pname = pbasename + R"(seconds_bucket{ipversion="v6",le=")" + (bucket.d_boundary == std::numeric_limits<uint64_t>::max() ? "+Inf" : buf.data()) + "\"}";
    entries.emplace(bucket.d_name + "6", StatsMapEntry{pname, std::to_string(bucket.d_count)});
  }
  snprintf(buf.data(), buf.size(), "%g", static_cast<double>(histogram6.getSum()) / 1e6);
  entries.emplace(name + "sum6", StatsMapEntry{pbasename + "seconds_sum{ipversion=\"v6\"}", buf.data()});
  entries.emplace(name + "count6", StatsMapEntry{pbasename + "seconds_count{ipversion=\"v6\"}", std::to_string(data6.back().d_count)});

  return entries;
}

static StatsMap toAuthRCodeStatsMap(const string& name)
{
  const string pbasename = getPrometheusName(name);
  StatsMap entries;

  uint8_t count = 0;
  auto rcodes = g_Counters.sum(rec::RCode::auth).rcodeCounters;
  for (const auto& entry : rcodes) {
    const auto key = RCode::to_short_s(count);
    std::string pname = pbasename;
    pname += "{rcode=\"" + key + "\"}";
    entries.emplace("auth-" + key + "-answers", StatsMapEntry{std::move(pname), std::to_string(entry)});
    count++;
  }
  return entries;
}

static StatsMap toCPUStatsMap(const string& name)
{
  const string pbasename = getPrometheusName(name);
  StatsMap entries;

  // Handler is not reported
  for (unsigned int thread = 0; thread < RecThreadInfo::numRecursorThreads() - 1; ++thread) {
    uint64_t timeTaken = doGetThreadCPUMsec(thread);
    std::string pname = pbasename + "{thread=\"" + std::to_string(thread) + "\"}";
    entries.emplace(name + "-thread-" + std::to_string(thread), StatsMapEntry{std::move(pname), std::to_string(timeTaken)});
  }
  return entries;
}

static StatsMap toRPZStatsMap(const string& name, const std::unordered_map<std::string, uint64_t>& map)
{
  const string pbasename = getPrometheusName(name);
  StatsMap entries;

  uint64_t total = 0;
  for (const auto& entry : map) {
    const auto& key = entry.first;
    auto count = entry.second;
    std::string sname;
    std::string pname;
    if (key.empty()) {
      sname = name + "-filter";
      pname = pbasename + "{type=\"filter\"}";
    }
    else {
      sname = name;
      sname += "-rpz-" + key;
      pname = pbasename;
      pname += R"({type="rpz",policyname=")" + key + "\"}";
    }
    entries.emplace(sname, StatsMapEntry{std::move(pname), std::to_string(count)});
    total += count;
  }
  entries.emplace(name, StatsMapEntry{pbasename, std::to_string(total)});
  return entries;
}

static StatsMap toProxyMappingStatsMap(const string& name)
{
  const string pbasename = getPrometheusName(name);
  StatsMap entries;

  auto proxyMappingStats = broadcastAccFunction<ProxyMappingStats_t>(pleaseGetProxyMappingStats);
  size_t count = 0;
  for (const auto& [key, entry] : proxyMappingStats) {
    auto keyname = pbasename + "{netmask=\"" + key.toString() + "\",count=\"";
    auto sname1 = name + "-n-" + std::to_string(count);
    auto pname1 = keyname + "netmaskmatches\"}";
    entries.emplace(sname1, StatsMapEntry{std::move(pname1), std::to_string(entry.netmaskMatches)});
    auto sname2 = name + "-s-" + std::to_string(count);
    auto pname2 = keyname + "suffixmatches\"}";
    entries.emplace(sname2, StatsMapEntry{std::move(pname2), std::to_string(entry.suffixMatches)});
    count++;
  }
  return entries;
}

static StatsMap toRemoteLoggerStatsMap(const string& name)
{
  const auto pbasename = getPrometheusName(name);
  StatsMap entries;

  std::vector<std::pair<RemoteLoggerStats_t, std::string>> list;
  auto stats1 = broadcastAccFunction<RemoteLoggerStats_t>(pleaseGetRemoteLoggerStats);
  list.emplace_back(stats1, "protobuf");
  auto stats2 = broadcastAccFunction<RemoteLoggerStats_t>(pleaseGetOutgoingRemoteLoggerStats);
  list.emplace_back(stats2, "outgoingProtobuf");
#ifdef HAVE_FSTRM
  auto stats3 = broadcastAccFunction<RemoteLoggerStats_t>(pleaseGetFramestreamLoggerStats);
  list.emplace_back(stats3, "dnstapFrameStream");
  auto stats4 = broadcastAccFunction<RemoteLoggerStats_t>(pleaseGetNODFramestreamLoggerStats);
  list.emplace_back(stats4, "dnstapNODFrameStream");
#endif
  uint64_t count = 0;
  for (const auto& [stats, type] : list) {
    for (const auto& [key, entry] : stats) {
      auto keyname = pbasename;
      keyname += "{address=\"" + key + "\",type=\"";
      keyname += type + "\",count=\"";
      auto sname1 = name + "-q-" + std::to_string(count);
      auto pname1 = keyname + "queued\"}";
      entries.emplace(sname1, StatsMapEntry{std::move(pname1), std::to_string(entry.d_queued)});
      auto sname2 = name + "-p-" + std::to_string(count);
      auto pname2 = keyname + "pipeFull\"}";
      entries.emplace(sname2, StatsMapEntry{std::move(pname2), std::to_string(entry.d_pipeFull)});
      auto sname3 = name + "-t-" + std::to_string(count);
      auto pname3 = keyname + "tooLarge\"}";
      entries.emplace(sname3, StatsMapEntry{std::move(pname3), std::to_string(entry.d_tooLarge)});
      auto sname4 = name + "-o-" + std::to_string(count);
      auto pname4 = keyname + "otherError\"}";
      entries.emplace(sname4, StatsMapEntry{std::move(pname4), std::to_string(entry.d_otherError)});
      ++count;
    }
  }
  return entries;
}

static time_t s_startupTime = time(nullptr);

static void registerAllStats1()
{
#include "rec-metrics-gen.h"

  /* make sure that the ECS stats are properly initialized */
  SyncRes::clearECSStats();
  for (size_t idx = 0; idx < SyncRes::s_ecsResponsesBySubnetSize4.size(); idx++) {
    const std::string name = "ecs-v4-response-bits-" + std::to_string(idx + 1);
    addGetStat(name, &(SyncRes::s_ecsResponsesBySubnetSize4.at(idx)));
  }
  for (size_t idx = 0; idx < SyncRes::s_ecsResponsesBySubnetSize6.size(); idx++) {
    const std::string name = "ecs-v6-response-bits-" + std::to_string(idx + 1);
    addGetStat(name, &(SyncRes::s_ecsResponsesBySubnetSize6.at(idx)));
  }

  addGetStat("cumul-clientanswers", []() {
    return toStatsMap(t_Counters.at(rec::Histogram::cumulativeAnswers).getName(), g_Counters.sum(rec::Histogram::cumulativeAnswers));
  });
  addGetStat("cumul-authanswers", []() {
    return toStatsMap(t_Counters.at(rec::Histogram::cumulativeAuth4Answers).getName(), g_Counters.sum(rec::Histogram::cumulativeAuth4Answers), g_Counters.sum(rec::Histogram::cumulativeAuth6Answers));
  });
  addGetStat("policy-hits", []() {
    return toRPZStatsMap("policy-hits", g_Counters.sum(rec::PolicyNameHits::policyName).counts);
  });
  addGetStat("proxy-mapping-total", []() {
    return toProxyMappingStatsMap("proxy-mapping-total");
  });
  addGetStat("auth-rcode-answers", []() {
    return toAuthRCodeStatsMap("auth-rcode-answers");
  });
}

void registerAllStats()
{
  try {
    registerAllStats1();
  }
  catch (...) {
    g_log << Logger::Critical << "Could not add stat entries" << endl;
    exit(1); // NOLINT(concurrency-mt-unsafe)
  }
}

static auto clearLuaScript(ArgIterator /* begin */, ArgIterator /* end */)
{
  vector<string> empty;
  empty.emplace_back();
  return doQueueReloadLuaScript(empty.begin(), empty.end());
}

// This code SHOUD *NOT* BE CALLED BY SIGNAL HANDLERS anymore
static void doExitGeneric(bool nicely)
{
#if defined(__SANITIZE_THREAD__)
  _exit(0); // regression test check for exit 0
#endif
  g_slog->withName("runtime")->info(Logr::Notice, "Exiting on user request", "nicely", Logging::Loggable(nicely));

  if (!g_pidfname.empty()) {
    unlink(g_pidfname.c_str()); // we can at least try..
  }

  if (nicely) {
    RecursorControlChannel::stop = true;
    {
      std::unique_lock lock(g_doneRunning.mutex);
      g_doneRunning.condVar.wait(lock, [] { return g_doneRunning.done.load(); });
    }
    // g_rcc.~RecursorControlChannel() do not call, caller still needs it!
    // Caller will continue doing the orderly shutdown
  }
  else {
    // rec_control quit case. Is that still used by test code? bulktests and regression test use quit-nicely
    g_rcc.~RecursorControlChannel();
#if defined(__SANITIZE_ADDRESS__) && defined(HAVE_LEAK_SANITIZER_INTERFACE)
    clearLuaScript(ArgIterator{}, ArgIterator{});
    pdns::coverage::dumpCoverageData();
    __lsan_do_leak_check();
    _exit(0); // let the regression test distinguish between leaks and no leaks as __lsan_do_leak_check() exits 1 on leaks
#else
    pdns::coverage::dumpCoverageData();
    _exit(1); // for historic reasons we exit 1
#endif
  }
}

static void doExit()
{
  doExitGeneric(false);
}

void doExitNicely()
{
  doExitGeneric(true);
}

// NOLINTBEGIN(cppcoreguidelines-owning-memory)
vector<pair<DNSName, uint16_t>>* pleaseGetQueryRing()
{
  using query_t = pair<DNSName, uint16_t>;
  auto* ret = new vector<query_t>();
  if (!t_queryring) {
    return ret;
  }
  ret->reserve(t_queryring->size());

  for (const query_t& query : *t_queryring) {
    ret->emplace_back(query);
  }
  return ret;
}
vector<pair<DNSName, uint16_t>>* pleaseGetServfailQueryRing()
{
  using query_t = pair<DNSName, uint16_t>;
  auto* ret = new vector<query_t>();
  if (!t_servfailqueryring) {
    return ret;
  }
  ret->reserve(t_servfailqueryring->size());
  for (const query_t& query : *t_servfailqueryring) {
    ret->emplace_back(query);
  }
  return ret;
}
vector<pair<DNSName, uint16_t>>* pleaseGetBogusQueryRing()
{
  using query_t = pair<DNSName, uint16_t>;
  auto* ret = new vector<query_t>();
  if (!t_bogusqueryring) {
    return ret;
  }
  ret->reserve(t_bogusqueryring->size());
  for (const query_t& query : *t_bogusqueryring) {
    ret->emplace_back(query);
  }
  return ret;
}

using pleaseremotefunc_t = std::function<vector<ComboAddress>*()>;
using pleasequeryfunc_t = std::function<vector<pair<DNSName, uint16_t>>*()>;

vector<ComboAddress>* pleaseGetRemotes()
{
  auto* ret = new vector<ComboAddress>();
  if (!t_remotes) {
    return ret;
  }
  ret->reserve(t_remotes->size());
  for (const ComboAddress& address : *t_remotes) {
    ret->emplace_back(address);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetServfailRemotes()
{
  auto* ret = new vector<ComboAddress>();
  if (!t_servfailremotes) {
    return ret;
  }
  ret->reserve(t_servfailremotes->size());
  for (const ComboAddress& address : *t_servfailremotes) {
    ret->push_back(address);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetBogusRemotes()
{
  auto* ret = new vector<ComboAddress>();
  if (!t_bogusremotes) {
    return ret;
  }
  ret->reserve(t_bogusremotes->size());
  for (const ComboAddress& address : *t_bogusremotes) {
    ret->emplace_back(address);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetLargeAnswerRemotes()
{
  auto* ret = new vector<ComboAddress>();
  if (!t_largeanswerremotes) {
    return ret;
  }
  ret->reserve(t_largeanswerremotes->size());
  for (const ComboAddress& address : *t_largeanswerremotes) {
    ret->emplace_back(address);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetTimeouts()
{
  auto* ret = new vector<ComboAddress>();
  if (!t_timeouts) {
    return ret;
  }
  ret->reserve(t_timeouts->size());
  for (const ComboAddress& address : *t_timeouts) {
    ret->emplace_back(address);
  }
  return ret;
}
// NOLINTEND(cppcoreguidelines-owning-memory)

static Answer doGenericTopRemotes(const pleaseremotefunc_t& func)
{
  auto remotes = broadcastAccFunction<vector<ComboAddress>>(func);
  const unsigned int total = remotes.size();
  if (total == 0) {
    return {0, "No qualifying data available\n"};
  }

  std::map<ComboAddress, unsigned int, ComboAddress::addressOnlyLessThan> counts;
  for (const auto& address : remotes) {
    counts[address]++;
  }

  std::multimap<unsigned int, ComboAddress> rcounts;
  for (const auto& count : counts) {
    rcounts.emplace(count.second, count.first);
  }

  ostringstream ret;
  ret << "Over last " << total << " entries:\n";
  boost::format fmt("%.02f%%\t%s\n");
  unsigned int limit = 0;
  unsigned int accounted = 0;
  for (auto i = rcounts.rbegin(); i != rcounts.rend() && limit < 20; ++i, ++limit) {
    ret << fmt % (100.0 * i->first / total) % i->second.toString();
    accounted += i->first;
  }
  ret << '\n'
      << fmt % (100.0 * (total - accounted) / total) % "rest";
  return {0, ret.str()};
}

// XXX DNSName Pain - this function should benefit from native DNSName methods
DNSName getRegisteredName(const DNSName& dom)
{
  auto parts = dom.getRawLabels();
  if (parts.size() <= 2) {
    return dom;
  }
  reverse(parts.begin(), parts.end());
  for (string& str : parts) {
    str = toLower(str);
  };

  // uk co migweb
  string last;
  while (!parts.empty()) {
    if (parts.size() == 1 || binary_search(g_pubs.begin(), g_pubs.end(), parts)) {

      string ret = std::move(last);
      if (!ret.empty()) {
        ret += ".";
      }
      for (auto part = parts.crbegin(); part != parts.crend(); ++part) {
        ret += (*part) + ".";
      }
      return DNSName(ret);
    }

    last = parts[parts.size() - 1];
    parts.resize(parts.size() - 1);
  }
  return DNSName("??");
}

static DNSName nopFilter(const DNSName& name)
{
  return name;
}

static Answer doGenericTopQueries(const pleasequeryfunc_t& func, const std::function<DNSName(const DNSName&)>& filter = nopFilter)
{
  using query_t = pair<DNSName, uint16_t>;
  auto queries = broadcastAccFunction<vector<query_t>>(func);
  const unsigned int total = queries.size();
  if (total == 0) {
    return {0, "No qualifying data available\n"};
  }

  map<query_t, unsigned int> counts;
  for (const auto& query : queries) {
    counts[pair(filter(query.first), query.second)]++;
  }

  std::multimap<unsigned int, query_t> rcounts;
  for (const auto& count : counts) {
    rcounts.emplace(count.second, count.first);
  }

  ostringstream ret;
  ret << "Over last " << total << " entries:\n";
  boost::format fmt("%.02f%%\t%s\n");
  unsigned int limit = 0;
  unsigned int accounted = 0;
  for (auto i = rcounts.rbegin(); i != rcounts.rend() && limit < 20; ++i, ++limit) {
    ret << fmt % (100.0 * i->first / total) % (i->second.first.toLogString() + "|" + DNSRecordContent::NumberToType(i->second.second));
    accounted += i->first;
  }
  ret << '\n'
      << fmt % (100.0 * (total - accounted) / total) % "rest";

  return {0, ret.str()};
}

static string* nopFunction()
{
  return new string("pong " + RecThreadInfo::self().getName() + '\n'); // NOLINT(cppcoreguidelines-owning-memory)
}

static Answer getDontThrottleNames(ArgIterator /* begin */, ArgIterator /* end */)
{
  auto dtn = g_dontThrottleNames.getLocal();
  return {0, dtn->toString() + "\n"};
}

static Answer getDontThrottleNetmasks(ArgIterator /* begin */, ArgIterator /* end */)
{
  auto dtn = g_dontThrottleNetmasks.getLocal();
  return {0, dtn->toString() + "\n"};
}

static Answer addDontThrottleNames(ArgIterator begin, ArgIterator end)
{
  if (begin == end) {
    return {1, "No names specified, keeping existing list\n"};
  }
  vector<DNSName> toAdd;
  while (begin != end) {
    try {
      auto name = DNSName(*begin);
      toAdd.emplace_back(std::move(name));
    }
    catch (const std::exception& e) {
      return {1, "Problem parsing '" + *begin + "': " + e.what() + ", nothing added\n"};
    }
    begin++;
  }

  string ret = "Added";
  auto dnt = g_dontThrottleNames.getCopy();
  bool first = true;
  for (auto const& name : toAdd) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + name.toLogString();
    dnt.add(name);
  }

  g_dontThrottleNames.setState(std::move(dnt));

  ret += " to the list of nameservers that may not be throttled";
  g_log << Logger::Info << ret << ", requested via control channel" << endl;
  return {0, ret + "\n"};
}

static Answer addDontThrottleNetmasks(ArgIterator begin, ArgIterator end)
{
  if (begin == end) {
    return {1, "No netmasks specified, keeping existing list\n"};
  }
  vector<Netmask> toAdd;
  while (begin != end) {
    try {
      auto netmask = Netmask(*begin);
      toAdd.push_back(netmask);
    }
    catch (const std::exception& e) {
      return {1, "Problem parsing '" + *begin + "': " + e.what() + ", nothing added\n"};
    }
    catch (const PDNSException& e) {
      return {1, "Problem parsing '" + *begin + "': " + e.reason + ", nothing added\n"};
    }
    begin++;
  }

  string ret = "Added";
  auto dnt = g_dontThrottleNetmasks.getCopy();
  bool first = true;
  for (auto const& netmask : toAdd) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + netmask.toString();
    dnt.addMask(netmask);
  }

  g_dontThrottleNetmasks.setState(std::move(dnt));

  ret += " to the list of nameserver netmasks that may not be throttled";
  g_log << Logger::Info << ret << ", requested via control channel" << endl;
  return {0, ret + "\n"};
}

static Answer clearDontThrottleNames(ArgIterator begin, ArgIterator end)
{
  if (begin == end) {
    return {0, "No names specified, doing nothing.\n"};
  }
  if (begin + 1 == end && *begin == "*") {
    SuffixMatchNode smn;
    g_dontThrottleNames.setState(std::move(smn));
    string ret = "Cleared list of nameserver names that may not be throttled";
    g_log << Logger::Warning << ret << ", requested via control channel" << endl;
    return {0, ret + "\n"};
  }

  vector<DNSName> toRemove;
  while (begin != end) {
    try {
      if (*begin == "*") {
        return {1, "Please don't mix '*' with other names, nothing removed\n"};
      }
      toRemove.emplace_back(*begin);
    }
    catch (const std::exception& e) {
      return {1, "Problem parsing '" + *begin + "': " + e.what() + ", nothing removed\n"};
    }
    begin++;
  }

  string ret = "Removed";
  bool first = true;
  auto dnt = g_dontThrottleNames.getCopy();
  for (const auto& name : toRemove) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + name.toLogString();
    dnt.remove(name);
  }

  g_dontThrottleNames.setState(std::move(dnt));

  ret += " from the list of nameservers that may not be throttled";
  g_log << Logger::Info << ret << ", requested via control channel" << endl;
  return {0, ret + "\n"};
}

static Answer clearDontThrottleNetmasks(ArgIterator begin, ArgIterator end)
{
  if (begin == end) {
    return {1, "No netmasks specified, doing nothing.\n"};
  }
  if (begin + 1 == end && *begin == "*") {
    auto nmg = g_dontThrottleNetmasks.getCopy();
    nmg.clear();
    g_dontThrottleNetmasks.setState(std::move(nmg));

    string ret = "Cleared list of nameserver addresses that may not be throttled";
    g_log << Logger::Warning << ret << ", requested via control channel" << endl;
    return {0, ret + "\n"};
  }

  std::vector<Netmask> toRemove;
  while (begin != end) {
    try {
      if (*begin == "*") {
        return {1, "Please don't mix '*' with other netmasks, nothing removed\n"};
      }
      auto netmask = Netmask(*begin);
      toRemove.push_back(netmask);
    }
    catch (const std::exception& e) {
      return {1, "Problem parsing '" + *begin + "': " + e.what() + ", nothing added\n"};
    }
    catch (const PDNSException& e) {
      return {1, "Problem parsing '" + *begin + "': " + e.reason + ", nothing added\n"};
    }
    begin++;
  }

  string ret = "Removed";
  bool first = true;
  auto dnt = g_dontThrottleNetmasks.getCopy();
  for (const auto& mask : toRemove) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + mask.toString();
    dnt.deleteMask(mask);
  }

  g_dontThrottleNetmasks.setState(std::move(dnt));

  ret += " from the list of nameservers that may not be throttled";
  g_log << Logger::Info << ret << ", requested via control channel" << endl;
  return {0, ret + "\n"};
}

static Answer setEventTracing(ArgIterator begin, ArgIterator end)
{
  if (begin == end) {
    return {1, "No event trace enabled value specified\n"};
  }
  try {
    pdns::checked_stoi_into(SyncRes::s_event_trace_enabled, *begin);
    return {0, "New event trace enabled value: " + std::to_string(SyncRes::s_event_trace_enabled) + "\n"};
  }
  catch (const std::exception& e) {
    return {1, "Error parsing the new event trace enabled value: " + std::string(e.what()) + "\n"};
  }
}

static void* pleaseSupplantProxyMapping(const ProxyMapping& proxyMapping)
{
  if (proxyMapping.empty()) {
    t_proxyMapping = nullptr;
  }
  else {
    // Copy the existing stats values, for the new config items also present in the old
    auto newmapping = make_unique<ProxyMapping>();
    for (const auto& [nm, entry] : proxyMapping) {
      auto& newentry = newmapping->insert(nm);
      newentry.second = entry;
      if (t_proxyMapping) {
        if (const auto* existing = t_proxyMapping->lookup(nm); existing != nullptr) {
          newentry.second.stats = existing->second.stats;
        }
      }
    }
    t_proxyMapping = std::move(newmapping);
  }
  return nullptr;
}

static RecursorControlChannel::Answer help(ArgIterator /* begin */, ArgIterator /* end */)
{
  static const std::map<std::string, std::string> commands = {
    {"add-cookies-unsupported [IP...]", "Add non-expiring 'Unsupported' entry for IP to cookie table"},
    {"add-dont-throttle-names [N...]", "Add names that are not allowed to be throttled"},
    {"add-dont-throttle-netmasks [N...]", "Add netmasks that are not allowed to be throttled"},
    {"add-nta DOMAIN [REASON]", "Add a Negative Trust Anchor for DOMAIN with the comment REASON"},
    {"add-ta DOMAIN DSRECORD", "Add a Trust Anchor for DOMAIN with data DSRECORD"},
    {"current-queries", "Show currently active queries"},
    {"clear-cookies [IP...]", "Clear entries from cookie table, if IP is '*' remove all entries"},
    {"clear-dont-throttle-names [N...]", "Remove names that are not allowed to be throttled. If N is '*', remove all"},
    {"clear-dont-throttle-netmasks [N...]", "Remove netmasks that are not allowed to be throttled. If N is '*', remove all"},
    {"clear-nta [DOMAIN]...", "Clear the Negative Trust Anchor for DOMAINs, if no DOMAIN is specified, remove all"},
    {"clear-ta [DOMAIN]...", "Clear the Trust Anchor for DOMAINs"},
    {"dump-cache <filename> [type...]", "Dump cache contents to the named file, type is r, n, p or a"},
    {"dump-cookies <filename>", "Dump the contents of the cookie jar to the named file"},
    {"dump-dot-probe-map <filename>", "Dump the contents of the DoT probe map to the named file"},
    {"dump-edns [status] <filename>", "Dump EDNS status to the named file"},
    {"dump-failedservers <filename>", "Dump the failed servers to the named file"},
    {"dump-non-resolving <filename>", "Dump non-resolving nameservers addresses to the named file"},
    {"dump-nsspeeds <filename>", "Dump nsspeeds statistics to the named file"},
    {"dump-saved-parent-ns-sets <filename>", "Dump saved parent ns sets that were successfully used as fallback"},
    {"dump-rpz <zone name> <filename>", "Dump the content of a RPZ zone to the named file"},
    {"dump-throttlemap <filename>", "Dump the contents of the throttle map to the named file"},
    {"get [key1] [key2] ..", "Get specific statistics"},
    {"get-all", "Get all statistics"},
    {"get-dont-throttle-names", "Get the list of names that are not allowed to be throttled"},
    {"get-dont-throttle-netmasks", "Get the list of netmasks that are not allowed to be throttled"},
    {"get-ntas", "Get all configured Negative Trust Anchors"},
    {"get-tas", "Get all configured Trust Anchors"},
    {"get-parameter [key1] [key2] ..", "Get configuration parameters"},
    {"get-proxymapping-stats", "Get proxy mapping statistics"},
    {"get-qtypelist", "Get QType statistics. Note queries from cache aren't being counted yet"},
    {"get-remotelogger-stats", "Get remote logger statistics"},
    {"hash-password [work-factor]", "Ask for a password then return the hashed version"},
    {"help", "Get this list (from the running recursor)"},
    {"list-dnssec-algos", "List supported DNSSEC algorithms"},
    {"ping", "Check that all threads are alive"},
    {"quit", "Stop the recursor daemon"},
    {"quit-nicely or stop", "Stop the recursor daemon nicely"},
    {"reload-acls", "Reload ACLS"},
    {"reload-lua-script [filename]", "Reload Lua script"},
    {"reload-yaml", "Reload runtime settable parts of YAML settings"},
    {"reload-lua-config [filename]", "Reload Lua configuration file or equivalent YAML clauses"},
    {"reload-zones", "Reload all auth and forward zones"},
    {"set-ecs-minimum-ttl value", "Set ecs-minimum-ttl-override"},
    {"set-max-aggr-nsec-cache-size value", "Set new maximum aggressive NSEC cache size"},
    {"set-max-cache-entries value", "Set new maximum record cache size"},
    {"set-max-packetcache-entries value", "Set new maximum packet cache size"},
    {"set-minimum-ttl value", "Set minimum-ttl-override"},
    {"set-carbon-server", "Set a carbon server for telemetry"},
    {"set-dnssec-log-bogus SETTING", "Enable (yes) or disable (no) logging of DNSSEC validation failures"},
    {"set-event-trace-enabled SETTING", "Set logging of event traces, 0=disabled, 1=protobuf, 2=log file, 4=opentelemetry, combine by adding"},
    {"show-yaml [file]", "Show yaml config derived from old-style config"},
    {"trace-regex [regex file]", "Emit resolution trace for matching queries (no arguments clears tracing)"},
    {"top-largeanswer-remotes", "Show top remotes receiving large answers"},
    {"top-queries", "Show top queries"},
    {"top-pub-queries", "Show top queries grouped by public suffix list"},
    {"top-remotes", "Show top remotes"},
    {"top-timeouts", "Show top downstream timeouts"},
    {"top-servfail-queries", "Show top queries receiving servfail answers"},
    {"top-bogus-queries", "Show top queries validating as bogus"},
    {"top-pub-servfail-queries", "Show top queries receiving servfail answers grouped by public suffix list"},
    {"top-pub-bogus-queries", "Show top queries validating as bogus grouped by public suffix list"},
    {"top-servfail-remotes", "Show top remotes receiving servfail answers"},
    {"top-bogus-remotes", "Show top remotes receiving bogus answers"},
    {"unload-lua-script", "Unload Lua script"},
    {"version", "Return version number of running Recursor"},
    {"wipe-cache domain0 [domain1] ..", "Wipe domain data from cache"},
    {"wipe-cache-typed type domain0 [domain1] ..", "Wipe domain data with qtype from cache"},

  };
  ostringstream str;
  for (const auto& command : commands) {
    str << command.first << endl;
    str << std::setw(8) << ' ' << command.second << endl;
  }
  return {0, str.str()};
}

RecursorControlChannel::Answer luaconfig(bool broadcast)
{
  ProxyMapping proxyMapping;
  LuaConfigItems lci;
  lci.d_slog = g_slog;
  extern std::unique_ptr<ProxyMapping> g_proxyMapping;
  if (!g_luaSettingsInYAML) {
    try {
      if (::arg()["lua-config-file"].empty()) {
        return {0, "No Lua or corresponding YAML configuration active\n"};
      }
      loadRecursorLuaConfig(::arg()["lua-config-file"], proxyMapping, lci);
      activateLuaConfig(lci);
      lci = g_luaconfs.getCopy();
      if (broadcast) {
        startLuaConfigDelayedThreads(lci, lci.generation);
        broadcastFunction([pmap = std::move(proxyMapping)] { return pleaseSupplantProxyMapping(pmap); });
      }
      else {
        // Initial proxy mapping
        g_proxyMapping = proxyMapping.empty() ? nullptr : std::make_unique<ProxyMapping>(proxyMapping);
      }
      if (broadcast) {
        g_slog->withName("config")->info(Logr::Info, "Reloaded");
      }
      return {0, "Reloaded Lua configuration file '" + ::arg()["lua-config-file"] + "'\n"};
    }
    catch (std::exception& e) {
      return {1, "Unable to load Lua script from '" + ::arg()["lua-config-file"] + "': " + e.what() + "\n"};
    }
    catch (const PDNSException& e) {
      return {1, "Unable to load Lua script from '" + ::arg()["lua-config-file"] + "': " + e.reason + "\n"};
    }
  }
  try {
    string configname = ::arg()["config-dir"] + "/recursor";
    if (!::arg()["config-name"].empty()) {
      configname = ::arg()["config-dir"] + "/recursor-" + ::arg()["config-name"];
    }
    bool dummy1{};
    bool dummy2{};
    pdns::rust::settings::rec::Recursorsettings settings;
    auto yamlstat = pdns::settings::rec::tryReadYAML(configname + g_yamlSettingsSuffix, false, dummy1, dummy2, settings, g_slog, Logr::Error);
    if (yamlstat != pdns::settings::rec::YamlSettingsStatus::OK) {
      return {1, "Reloading dynamic part of YAML configuration failed\n"};
    }
    auto generation = g_luaconfs.getLocal()->generation;
    lci.generation = generation + 1;
    pdns::settings::rec::fromBridgeStructToLuaConfig(settings, lci, proxyMapping);
    activateLuaConfig(lci);
    lci = g_luaconfs.getCopy();
    if (broadcast) {
      startLuaConfigDelayedThreads(lci, lci.generation);
      broadcastFunction([pmap = std::move(proxyMapping)] { return pleaseSupplantProxyMapping(pmap); });
    }
    else {
      // Initial proxy mapping
      g_proxyMapping = proxyMapping.empty() ? nullptr : std::make_unique<ProxyMapping>(proxyMapping);
    }
    TCPOutConnectionManager::setupOutgoingTLSConfigTables(settings);

    return {0, "Reloaded dynamic part of YAML configuration\n"};
  }
  catch (std::exception& e) {
    return {1, "Unable to reload dynamic YAML changes: " + std::string(e.what()) + "\n"};
  }
  catch (const PDNSException& e) {
    return {1, "Unable to reload dynamic YAML changes: " + e.reason + "\n"};
  }
}

static RecursorControlChannel::Answer luaconfig1(ArgIterator begin, ArgIterator end)
{
  if (begin != end) {
    if (g_luaSettingsInYAML) {
      return {1, "Unable to reload Lua script from '" + *begin + "' as there is no active Lua configuration\n"};
    }
    ::arg().set("lua-config-file") = *begin;
  }
  return luaconfig(true);
}

static RecursorControlChannel::Answer reloadACLs(ArgIterator /* begin */, ArgIterator /* end */)
{
  if (!::arg()["chroot"].empty()) {
    g_log << Logger::Error << "Unable to reload ACL when chroot()'ed, requested via control channel" << endl;
    return {1, "Unable to reload ACL when chroot()'ed, please restart\n"};
  }

  try {
    parseACLs();
  }
  catch (std::exception& e) {
    g_log << Logger::Error << "Reloading ACLs failed (Exception: " << e.what() << ")" << endl;
    return {1, e.what() + string("\n")};
  }
  catch (PDNSException& ae) {
    g_log << Logger::Error << "Reloading ACLs failed (PDNSException: " << ae.reason << ")" << endl;
    return {1, ae.reason + string("\n")};
  }
  return {0, "ok\n"};
}

static std::string reloadZoneConfigurationWithSysResolveReset()
{
  auto& sysResolver = pdns::RecResolve::getInstance();
  sysResolver.stopRefresher();
  sysResolver.wipe();
  auto ret = reloadZoneConfiguration(g_yamlSettings);
  sysResolver.startRefresher();
  return ret;
}

RecursorControlChannel::Answer RecursorControlParser::getAnswer(int socket, const string& question, RecursorControlParser::func_t** command) // NOLINT(readability-function-cognitive-complexity)
{
  *command = nop;
  vector<string> words;
  stringtok(words, question);

  if (words.empty()) {
    return {1, "invalid command\n"};
  }

  string cmd = toLower(words.at(0));

  // The standard command function signature is (ArgIterator, ArgIterator) -> Answer
  // Answer is a pair of a status code and a message.
  // If you need to
  // specify a different signature, define a lambda, potentially capturing the socket and cmd by ref

  static const std::unordered_map<std::string, std::function<Answer(ArgIterator, ArgIterator)>> commands = {
    {"help", help},
    {"get-all", getAllStats},
    {"get", doGet},
    {"get-parameter", doGetParameter},
    {"quit", [&](ArgIterator, ArgIterator) -> Answer { *command = doExit; return {0, "bye\n"}; }},
    {"version", [&](ArgIterator, ArgIterator) -> Answer { return {0, getPDNSVersion() + "\n"}; }},
    {"quit-nicely", [&](ArgIterator, ArgIterator) -> Answer { *command = doExitNicely; return {0, "bye nicely\n"}; }},
    {"stop", [&](ArgIterator, ArgIterator) -> Answer { *command = doExitNicely; return {0, "bye nicely\n"}; }},
    {"dump-cache", [&](ArgIterator begin, ArgIterator end) {
       return doDumpCache(socket, begin, end);
     }},
    {"clear-cookies", [](ArgIterator begin, ArgIterator end) -> Answer {
       string errors;
       auto count = clearCookies(begin, end, errors);
       if (errors.empty()) {
         return {0, "Cleared " + std::to_string(count) + " entr" + addS(count, "y", "ies") + " from cookies table\n"};
       }
       return {1, "Cleared " + std::to_string(count) + " entr" + addS(count, "y", "ies") + " from cookies table, errors: " + errors + "\n"};
     }},
    {"add-cookies-unsupported", [](ArgIterator begin, ArgIterator end) -> Answer {
       string errors;
       auto count = addCookiesUnsupported(begin, end, errors);
       if (errors.empty()) {
         return {0, "Added " + std::to_string(count) + " entr" + addS(count, "y", "ies") + " to cookies table\n"};
       }
       return {1, "Added " + std::to_string(count) + " entr" + addS(count, "y", "ies") + " to cookies table, errors: " + errors + "\n"};
     }},
    {"dump-cookies", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpCookiesMap, cmd, false);
     }},
    {"dump-dot-probe-map", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpDoTProbeMap, cmd, false);
     }},
    {"dump-ednsstatus", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpEDNSMap, cmd, false);
     }},
    {"dump-edns", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpEDNSMap, cmd, false);
     }},
    {"dump-nsspeeds", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpNSSpeeds, cmd, false);
     }},
    {"dump-failedservers", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpFailedServers, cmd, false);
     }},
    {"dump-saved-parent-ns-sets", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpSavedParentNSSets, cmd, false);
     }},
    {"dump-rpz", [&](ArgIterator begin, ArgIterator end) -> Answer {
       return doDumpRPZ(socket, begin, end);
     }},
    {"dump-throttlemap", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpThrottleMap, cmd, false);
     }},
    {"dump-non-resolving", [&](ArgIterator, ArgIterator) -> Answer {
       return doDumpToFile(socket, pleaseDumpNonResolvingNS, cmd, false);
     }},
    {"wipe-cache", [](ArgIterator begin, ArgIterator end) -> Answer {
       return doWipeCache(begin, end, 0xffff);
     }},
    {"flushname", [](ArgIterator begin, ArgIterator end) -> Answer {
       return doWipeCache(begin, end, 0xffff);
     }},
    {"wipe-cache-typed", [](ArgIterator begin, ArgIterator end) -> Answer {
       if (begin == end) {
         return {1, "Need a qtype\n"};
       }
       uint16_t qtype = QType::chartocode(begin->c_str());
       if (qtype == 0) {
         return {1, "Unknown qtype " + *begin + "\n"};
       }
       ++begin;
       return doWipeCache(begin, end, qtype);
     }},
    {"reload-lua-script", doQueueReloadLuaScript},
    {"reload-lua-config", luaconfig1},
    {"reload-yaml", luaconfig1},
    {"set-carbon-server", doSetCarbonServer},
    {"trace-regex", [&](ArgIterator begin, ArgIterator end) -> Answer {
       return {0, doTraceRegex(begin == end ? FDWrapper(-1) : getfd(socket), begin, end)};
     }},
    {"unload-lua-script", clearLuaScript},
    {"reload-acls", reloadACLs},
    {"top-remotes", [](ArgIterator, ArgIterator) -> Answer {
       return doGenericTopRemotes(pleaseGetRemotes);
     }},
    {"top-queries", [](ArgIterator, ArgIterator) {
       return doGenericTopQueries(pleaseGetQueryRing);
     }},
    {"top-pub-queries", [](ArgIterator, ArgIterator) {
       return doGenericTopQueries(pleaseGetQueryRing, getRegisteredName);
     }},
    {"top-servfail-queries", [](ArgIterator, ArgIterator) {
       return doGenericTopQueries(pleaseGetServfailQueryRing);
     }},
    {"top-pub-servfail-queries", [](ArgIterator, ArgIterator) {
       return doGenericTopQueries(pleaseGetServfailQueryRing, getRegisteredName);
     }},
    {"top-bogus-queries", [](ArgIterator, ArgIterator) {
       return doGenericTopQueries(pleaseGetBogusQueryRing);
     }},
    {"top-pub-bogus-queries", [](ArgIterator, ArgIterator) {
       return doGenericTopQueries(pleaseGetBogusQueryRing, getRegisteredName);
     }},
    {"top-servfail-remotes", [](ArgIterator, ArgIterator) {
       return doGenericTopRemotes(pleaseGetServfailRemotes);
     }},
    {"top-bogus-remotes", [](ArgIterator, ArgIterator) {
       return doGenericTopRemotes(pleaseGetBogusRemotes);
     }},
    {"top-largeanswer-remotes", [](ArgIterator, ArgIterator) {
       return doGenericTopRemotes(pleaseGetLargeAnswerRemotes);
     }},
    {"top-timeouts", [](ArgIterator, ArgIterator) {
       return doGenericTopRemotes(pleaseGetTimeouts);
     }},
    {"current-queries", doCurrentQueries},
    {"ping", [](ArgIterator, ArgIterator) -> Answer {
       return {0, broadcastAccFunction<string>(nopFunction)};
     }},
    {"reload-zones", [](ArgIterator, ArgIterator) -> Answer {
       if (!::arg()["chroot"].empty()) {
         g_log << Logger::Error << "Unable to reload zones and forwards when chroot()'ed, requested via control channel" << endl;
         return {1, "Unable to reload zones and forwards when chroot()'ed, please restart\n"};
       }
       return {0, reloadZoneConfigurationWithSysResolveReset()};
     }},
    {"set-ecs-minimum-ttl", setMinimumECSTTL},
    {"set-max-cache-entries", setMaxCacheEntries},
    {"set-max-packetcache-entries", setMaxPacketCacheEntries},
    {"set-minimum-ttl", setMinimumTTL},
    {"get-qtypelist", [](ArgIterator, ArgIterator) -> Answer {
       return {0, g_Counters.sum(rec::ResponseStats::responseStats).getQTypeReport()};
     }},
    {"add-nta", doAddNTA},
    {"clear-nta", doClearNTA},
    {"get-ntas", getNTAs},
    {"add-ta", doAddTA},
    {"clear-ta", doClearTA},
    {"get-tas", getTAs},
    {"set-dnssec-log-bogus", doSetDnssecLogBogus},
    {"get-dont-throttle-names", getDontThrottleNames},
    {"get-dont-throttle-netmasks", getDontThrottleNetmasks},
    {"add-dont-throttle-names", addDontThrottleNames},
    {"add-dont-throttle-netmasks", addDontThrottleNetmasks},
    {"clear-dont-throttle-names", clearDontThrottleNames},
    {"clear-dont-throttle-netmasks", clearDontThrottleNetmasks},
    {"set-event-trace-enabled", setEventTracing},
    {"get-proxymapping-stats", doGetProxyMappingStats},
    {"get-remotelogger-stats", getRemoteLoggerStats},
    {"list-dnssec-algos", [](ArgIterator, ArgIterator) -> Answer {
       return {0, DNSCryptoKeyEngine::listSupportedAlgoNames()};
     }},
    {"set-aggr-nsec-cache-size", setAggrNSECCacheSize},
  };

  if (const auto entry = commands.find(cmd); entry != commands.end()) {
    auto begin = words.begin() + 1;
    auto end = words.end();
    return entry->second(begin, end);
  }

  return {1, "Unknown command '" + cmd + "', try 'help'\n"};
}
