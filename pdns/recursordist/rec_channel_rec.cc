#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
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

#include "settings/cxxsettings.hh"

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

std::pair<std::string, std::string> PrefixDashNumberCompare::prefixAndTrailingNum(const std::string& a)
{
  auto i = a.length();
  if (i == 0) {
    return {a, ""};
  }
  --i;
  if (!std::isdigit(a[i])) {
    return {a, ""};
  }
  while (i > 0) {
    if (!std::isdigit(a[i])) {
      break;
    }
    --i;
  }
  return {a.substr(0, i + 1), a.substr(i + 1, a.size() - i - 1)};
}

bool PrefixDashNumberCompare::operator()(const std::string& a, const std::string& b) const
{
  auto [aprefix, anum] = prefixAndTrailingNum(a);
  auto [bprefix, bnum] = prefixAndTrailingNum(b);

  if (aprefix != bprefix || anum.length() == 0 || bnum.length() == 0) {
    return a < b;
  }
  auto aa = std::stoull(anum);
  auto bb = std::stoull(bnum);
  return aa < bb;
}

static map<string, const uint32_t*> d_get32bitpointers;
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
  for (const auto& st : disabledStats) {
    map.insert(st);
  }
}

static void addGetStat(const string& name, const uint32_t* place)
{
  if (!d_get32bitpointers.emplace(name, place).second) {
    cerr << "addGetStat: double def " << name << endl;
    _exit(1);
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
    name.begin(), name.end(), [](char c) { return !isalnum(static_cast<unsigned char>(c)); }, '_');
  return "pdns_recursor_" + name;
}

std::atomic<unsigned long>* getDynMetric(const std::string& str, const std::string& prometheusName)
{
  auto dm = d_dynmetrics.lock();
  auto f = dm->find(str);
  if (f != dm->end()) {
    return f->second.d_ptr;
  }

  std::string name(str);
  if (!prometheusName.empty()) {
    name = prometheusName;
  }
  else {
    name = getPrometheusName(name);
  }

  auto ret = dynmetrics{new std::atomic<unsigned long>(), std::move(name)};
  (*dm)[str] = ret;
  return ret.d_ptr;
}

static std::optional<uint64_t> get(const string& name)
{
  std::optional<uint64_t> ret;

  if (d_get32bitpointers.count(name))
    return *d_get32bitpointers.find(name)->second;
  if (d_getatomics.count(name))
    return d_getatomics.find(name)->second->load();
  if (d_get64bitmembers.count(name))
    return d_get64bitmembers.find(name)->second();

  {
    auto dm = d_dynmetrics.lock();
    auto f = rplookup(*dm, name);
    if (f) {
      return f->d_ptr->load();
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

  for (const auto& the32bits : d_get32bitpointers) {
    if (disabledlistMap.count(the32bits.first) == 0) {
      ret.emplace(the32bits.first, StatsMapEntry{getPrometheusName(the32bits.first), std::to_string(*the32bits.second)});
    }
  }
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
    for (const auto& a : *(d_dynmetrics.lock())) {
      if (disabledlistMap.count(a.first) == 0) {
        ret.emplace(a.first, StatsMapEntry{a.second.d_prometheusName, std::to_string(*a.second.d_ptr)});
      }
    }
  }

  return ret;
}

static string getAllStats()
{
  auto varmap = getAllStatsMap(StatComponent::RecControl);
  string ret;
  for (const auto& tup : varmap) {
    ret += tup.first + "\t" + tup.second.d_value + "\n";
  }
  return ret;
}

template <typename T>
static string doGet(T begin, T end)
{
  string ret;

  for (T i = begin; i != end; ++i) {
    std::optional<uint64_t> num = get(*i);
    if (num)
      ret += std::to_string(*num) + "\n";
    else
      ret += "UNKNOWN\n";
  }
  return ret;
}

template <typename T>
string static doGetParameter(T begin, T end)
{
  string ret;
  string parm;
  using boost::replace_all;
  for (T i = begin; i != end; ++i) {
    if (::arg().parmIsset(*i)) {
      parm = ::arg()[*i];
      replace_all(parm, "\\", "\\\\");
      replace_all(parm, "\"", "\\\"");
      replace_all(parm, "\n", "\\n");
      ret += *i + "=\"" + parm + "\"\n";
    }
    else
      ret += *i + " not known\n";
  }
  return ret;
}

/* Read an (open) fd from the control channel */
static FDWrapper
getfd(int s)
{
  int fd = -1;
  struct msghdr msg;
  struct cmsghdr* cmsg;
  union
  {
    struct cmsghdr hdr;
    unsigned char buf[CMSG_SPACE(sizeof(int))];
  } cmsgbuf;
  struct iovec io_vector[1];
  char ch;

  io_vector[0].iov_base = &ch;
  io_vector[0].iov_len = 1;

  memset(&msg, 0, sizeof(msg));
  msg.msg_control = &cmsgbuf.buf;
  msg.msg_controllen = sizeof(cmsgbuf.buf);
  msg.msg_iov = io_vector;
  msg.msg_iovlen = 1;

  if (recvmsg(s, &msg, 0) == -1) {
    throw PDNSException("recvmsg");
  }
  if ((msg.msg_flags & MSG_TRUNC) || (msg.msg_flags & MSG_CTRUNC)) {
    throw PDNSException("control message truncated");
  }
  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
       cmsg = CMSG_NXTHDR(&msg, cmsg)) {
    if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
      fd = *(int*)CMSG_DATA(cmsg);
      break;
    }
  }
  return FDWrapper(fd);
}

static uint64_t dumpAggressiveNSECCache(int fd)
{
  if (!g_aggressiveNSECCache) {
    return 0;
  }

  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    return 0;
  }
  fprintf(filePtr.get(), "; aggressive NSEC cache dump follows\n;\n");

  struct timeval now;
  Utility::gettimeofday(&now, nullptr);
  return g_aggressiveNSECCache->dumpToFile(filePtr, now);
}

static uint64_t* pleaseDumpEDNSMap(int fd)
{
  return new uint64_t(SyncRes::doEDNSDump(fd));
}

static uint64_t* pleaseDumpNSSpeeds(int fd)
{
  return new uint64_t(SyncRes::doDumpNSSpeeds(fd));
}

static uint64_t* pleaseDumpThrottleMap(int fd)
{
  return new uint64_t(SyncRes::doDumpThrottleMap(fd));
}

static uint64_t* pleaseDumpFailedServers(int fd)
{
  return new uint64_t(SyncRes::doDumpFailedServers(fd));
}

static uint64_t* pleaseDumpSavedParentNSSets(int fd)
{
  return new uint64_t(SyncRes::doDumpSavedParentNSSets(fd));
}

static uint64_t* pleaseDumpNonResolvingNS(int fd)
{
  return new uint64_t(SyncRes::doDumpNonResolvingNS(fd));
}

static uint64_t* pleaseDumpDoTProbeMap(int fd)
{
  return new uint64_t(SyncRes::doDumpDoTProbeMap(fd));
}

// Generic dump to file command
static RecursorControlChannel::Answer doDumpToFile(int s, uint64_t* (*function)(int s), const string& name, bool threads = true)
{
  auto fdw = getfd(s);

  if (fdw < 0) {
    return {1, name + ": error opening dump file for writing: " + stringerror() + "\n"};
  }

  uint64_t total = 0;
  try {
    if (threads) {
      int fd = fdw;
      total = broadcastAccFunction<uint64_t>([function, fd] { return function(fd); });
    }
    else {
      auto ret = function(fdw);
      total = *ret;
      delete ret;
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
template <typename T>
static RecursorControlChannel::Answer doDumpCache(int socket, T begin, T end)
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
  }

  return {0, "dumped " + std::to_string(total) + " records\n"};
}

// Does not follow the generic dump to file pattern, has an argument
template <typename T>
static RecursorControlChannel::Answer doDumpRPZ(int s, T begin, T end)
{
  auto fdw = getfd(s);

  if (fdw < 0) {
    return {1, "Error opening dump file for writing: " + stringerror() + "\n"};
  }

  T i = begin;

  if (i == end) {
    return {1, "No zone name specified\n"};
  }
  string zoneName = *i;

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

template <typename T>
static string doWipeCache(T begin, T end, uint16_t qtype)
{
  vector<pair<DNSName, bool>> toWipe;
  for (T i = begin; i != end; ++i) {
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
      return "Error: " + std::string(e.what()) + ", nothing wiped\n";
    }
    toWipe.emplace_back(canon, subtree);
  }

  int count = 0, pcount = 0, countNeg = 0;
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

  return "wiped " + std::to_string(count) + " records, " + std::to_string(countNeg) + " negative records, " + std::to_string(pcount) + " packets\n";
}

template <typename T>
static string doSetCarbonServer(T begin, T end)
{
  auto config = g_carbonConfig.getCopy();
  if (begin == end) {
    config.servers.clear();
    g_carbonConfig.setState(std::move(config));
    return "cleared carbon-server setting\n";
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
    return ret;
  }

  ++begin;
  if (begin != end) {
    config.namespace_name = *begin;
    ret += "set carbon-namespace to '" + *begin + "'\n";
  }
  else {
    g_carbonConfig.setState(std::move(config));
    return ret;
  }

  ++begin;
  if (begin != end) {
    config.instance_name = *begin;
    ret += "set carbon-instance to '" + *begin + "'\n";
  }

  g_carbonConfig.setState(std::move(config));
  return ret;
}

template <typename T>
static string doSetDnssecLogBogus(T begin, T end)
{
  if (checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not changing the Bogus logging setting\n";

  if (begin == end)
    return "No DNSSEC Bogus logging setting specified\n";

  if (pdns_iequals(*begin, "on") || pdns_iequals(*begin, "yes")) {
    if (!g_dnssecLogBogus) {
      g_log << Logger::Warning << "Enabling DNSSEC Bogus logging, requested via control channel" << endl;
      g_dnssecLogBogus = true;
      return "DNSSEC Bogus logging enabled\n";
    }
    return "DNSSEC Bogus logging was already enabled\n";
  }

  if (pdns_iequals(*begin, "off") || pdns_iequals(*begin, "no")) {
    if (g_dnssecLogBogus) {
      g_log << Logger::Warning << "Disabling DNSSEC Bogus logging, requested via control channel" << endl;
      g_dnssecLogBogus = false;
      return "DNSSEC Bogus logging disabled\n";
    }
    return "DNSSEC Bogus logging was already disabled\n";
  }

  return "Unknown DNSSEC Bogus setting: '" + *begin + "'\n";
}

template <typename T>
static string doAddNTA(T begin, T end)
{
  if (checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not adding a Negative Trust Anchor\n";

  if (begin == end)
    return "No NTA specified, doing nothing\n";

  DNSName who;
  try {
    who = DNSName(*begin);
  }
  catch (std::exception& e) {
    string ret("Can't add Negative Trust Anchor: ");
    ret += e.what();
    ret += "\n";
    return ret;
  }
  begin++;

  string why("");
  while (begin != end) {
    why += *begin;
    begin++;
    if (begin != end)
      why += " ";
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
    return "Unable to clear caches while adding Negative Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n";
  }
  return "Added Negative Trust Anchor for " + who.toLogString() + " with reason '" + why + "'\n";
}

template <typename T>
static string doClearNTA(T begin, T end)
{
  if (checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not removing a Negative Trust Anchor\n";

  if (begin == end)
    return "No Negative Trust Anchor specified, doing nothing.\n";

  if (begin + 1 == end && *begin == "*") {
    g_log << Logger::Warning << "Clearing all Negative Trust Anchors, requested via control channel" << endl;
    g_luaconfs.modify([](LuaConfigItems& lci) {
      lci.negAnchors.clear();
    });
    return "Cleared all Negative Trust Anchors.\n";
  }

  vector<DNSName> toRemove;
  DNSName who;
  while (begin != end) {
    if (*begin == "*")
      return "Don't mix all Negative Trust Anchor removal with multiple Negative Trust Anchor removal. Nothing removed\n";
    try {
      who = DNSName(*begin);
    }
    catch (std::exception& e) {
      string ret("Error: ");
      ret += e.what();
      ret += ". No Negative Anchors removed\n";
      return ret;
    }
    toRemove.push_back(who);
    begin++;
  }

  string removed("");
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
    return "Unable to clear caches while clearing Negative Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n";
  }

  return "Removed Negative Trust Anchors for " + removed + "\n";
}

static string getNTAs()
{
  if (checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration\n";

  string ret("Configured Negative Trust Anchors:\n");
  auto luaconf = g_luaconfs.getLocal();
  for (const auto& negAnchor : luaconf->negAnchors)
    ret += negAnchor.first.toLogString() + "\t" + negAnchor.second + "\n";
  return ret;
}

template <typename T>
static string doAddTA(T begin, T end)
{
  if (checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not adding a Trust Anchor\n";

  if (begin == end)
    return "No TA specified, doing nothing\n";

  DNSName who;
  try {
    who = DNSName(*begin);
  }
  catch (std::exception& e) {
    string ret("Can't add Trust Anchor: ");
    ret += e.what();
    ret += "\n";
    return ret;
  }
  begin++;

  string what("");
  while (begin != end) {
    what += *begin + " ";
    begin++;
  }

  try {
    g_log << Logger::Warning << "Adding Trust Anchor for " << who << " with data '" << what << "', requested via control channel";
    g_luaconfs.modify([who, what](LuaConfigItems& lci) {
      auto ds = std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(what));
      lci.dsAnchors[who].insert(*ds);
    });
    wipeCaches(who, true, 0xffff);
    g_log << Logger::Warning << endl;
    return "Added Trust Anchor for " + who.toStringRootDot() + " with data " + what + "\n";
  }
  catch (std::exception& e) {
    g_log << Logger::Warning << ", failed: " << e.what() << endl;
    return "Unable to add Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n";
  }
}

template <typename T>
static string doClearTA(T begin, T end)
{
  if (checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not removing a Trust Anchor\n";

  if (begin == end)
    return "No Trust Anchor to clear\n";

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
      return ret;
    }
    if (who.isRoot())
      return "Refusing to remove root Trust Anchor, no Anchors removed\n";
    toRemove.push_back(who);
    begin++;
  }

  string removed("");
  bool first(true);
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
    return "Unable to clear caches while clearing Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n";
  }

  return "Removed Trust Anchor(s) for" + removed + "\n";
}

static string getTAs()
{
  if (checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration\n";

  string ret("Configured Trust Anchors:\n");
  auto luaconf = g_luaconfs.getLocal();
  for (const auto& anchor : luaconf->dsAnchors) {
    ret += anchor.first.toLogString() + "\n";
    for (const auto& e : anchor.second) {
      ret += "\t\t" + e.getZoneRepresentation() + "\n";
    }
  }

  return ret;
}

template <typename T>
static string setMinimumTTL(T begin, T end)
{
  if (end - begin != 1)
    return "Need to supply new minimum TTL number\n";
  try {
    pdns::checked_stoi_into(SyncRes::s_minimumTTL, *begin);
    return "New minimum TTL: " + std::to_string(SyncRes::s_minimumTTL) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new minimum TTL number: " + std::string(e.what()) + "\n";
  }
}

template <typename T>
static string setMinimumECSTTL(T begin, T end)
{
  if (end - begin != 1)
    return "Need to supply new ECS minimum TTL number\n";
  try {
    pdns::checked_stoi_into(SyncRes::s_minimumECSTTL, *begin);
    return "New minimum ECS TTL: " + std::to_string(SyncRes::s_minimumECSTTL) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new ECS minimum TTL number: " + std::string(e.what()) + "\n";
  }
}

template <typename T>
static string setMaxCacheEntries(T begin, T end)
{
  if (end - begin != 1)
    return "Need to supply new cache size\n";
  try {
    g_maxCacheEntries = pdns::checked_stoi<uint32_t>(*begin);
    return "New max cache entries: " + std::to_string(g_maxCacheEntries) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new cache size: " + std::string(e.what()) + "\n";
  }
}

template <typename T>
static string setMaxPacketCacheEntries(T begin, T end)
{
  if (end - begin != 1)
    return "Need to supply new packet cache size\n";
  if (::arg().mustDo("disable-packetcache")) {
    return "Packet cache is disabled\n";
  }
  try {
    g_maxPacketCacheEntries = pdns::checked_stoi<uint32_t>(*begin);
    g_packetCache->setMaxSize(g_maxPacketCacheEntries);
    return "New max packetcache entries: " + std::to_string(g_maxPacketCacheEntries) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new packet cache size: " + std::string(e.what()) + "\n";
  }
}

template <typename T>
static RecursorControlChannel::Answer setAggrNSECCacheSize(T begin, T end)
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
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  return (ru.ru_stime.tv_sec * 1000ULL + ru.ru_stime.tv_usec / 1000);
}

static uint64_t getUserTimeMsec()
{
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  return (ru.ru_utime.tv_sec * 1000ULL + ru.ru_utime.tv_usec / 1000);
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
  return new ThreadTimes{ret, vector<uint64_t>()};
}

/* Next up, when you want msec data for a specific thread, we check
   if we recently executed pleaseGetThreadCPUMsec. If we didn't we do so
   now and consult all threads.

   We then answer you from the (re)fresh(ed) ThreadTimes.
*/
static uint64_t doGetThreadCPUMsec(int n)
{
  static std::mutex s_mut;
  static time_t last = 0;
  static ThreadTimes tt;

  std::lock_guard<std::mutex> l(s_mut);
  if (last != time(nullptr)) {
    tt = broadcastAccFunction<ThreadTimes>(pleaseGetThreadCPUMsec);
    last = time(nullptr);
  }

  return tt.times.at(n);
}

static ProxyMappingStats_t* pleaseGetProxyMappingStats()
{
  auto ret = new ProxyMappingStats_t;
  if (t_proxyMapping) {
    for (const auto& [key, entry] : *t_proxyMapping) {
      ret->emplace(key, ProxyMappingCounts{entry.stats.netmaskMatches, entry.stats.suffixMatches});
    }
  }
  return ret;
}

static RemoteLoggerStats_t* pleaseGetRemoteLoggerStats()
{
  auto ret = make_unique<RemoteLoggerStats_t>();

  if (t_protobufServers.servers) {
    for (const auto& server : *t_protobufServers.servers) {
      ret->emplace(server->address(), server->getStats());
    }
  }
  return ret.release();
}

static string doGetProxyMappingStats()
{
  ostringstream ret;
  ret << "subnet\t\t\tmatches\tsuffixmatches" << endl;
  auto proxyMappingStats = broadcastAccFunction<ProxyMappingStats_t>(pleaseGetProxyMappingStats);
  for (const auto& [key, entry] : proxyMappingStats) {
    ret << key.toString() << '\t' << entry.netmaskMatches << '\t' << entry.suffixMatches << endl;
  }
  return ret.str();
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

static string getRemoteLoggerStats()
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
  return outputStream.str();
}

static string* pleaseGetCurrentQueries()
{
  ostringstream ostr;
  struct timeval now;
  gettimeofday(&now, 0);

  ostr << getMT()->getWaiters().size() << " currently outstanding questions\n";

  boost::format fmt("%1% %|40t|%2% %|47t|%3% %|63t|%4% %|68t|%5% %|78t|%6%\n");

  ostr << (fmt % "qname" % "qtype" % "remote" % "tcp" % "chained" % "spent(ms)");
  unsigned int n = 0;
  for (const auto& mthread : getMT()->getWaiters()) {
    const std::shared_ptr<PacketID>& pident = mthread.key;
    const double spent = g_networkTimeoutMsec - (DiffTime(now, mthread.ttd) * 1000);
    ostr << (fmt
             % pident->domain.toLogString() /* ?? */ % DNSRecordContent::NumberToType(pident->type)
             % pident->remote.toString() % (pident->tcpsock ? 'Y' : 'n')
             % (pident->fd == -1 ? 'Y' : 'n')
             % (spent > 0 ? spent : '0'));
    ++n;
    if (n >= 100)
      break;
  }
  ostr << " - done\n";
  return new string(ostr.str());
}

static string doCurrentQueries()
{
  return broadcastAccFunction<string>(pleaseGetCurrentQueries);
}

static uint64_t getNegCacheSize()
{
  return g_negCache->size();
}

uint64_t* pleaseGetConcurrentQueries()
{
  return new uint64_t(getMT() ? getMT()->numProcesses() : 0);
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
  char buf[32];

  for (const auto& bucket : data) {
    snprintf(buf, sizeof(buf), "%g", bucket.d_boundary / 1e6);
    std::string pname = pbasename + "seconds_bucket{" + "le=\"" + (bucket.d_boundary == std::numeric_limits<uint64_t>::max() ? "+Inf" : buf) + "\"}";
    entries.emplace(bucket.d_name, StatsMapEntry{std::move(pname), std::to_string(bucket.d_count)});
  }

  snprintf(buf, sizeof(buf), "%g", histogram.getSum() / 1e6);
  entries.emplace(name + "sum", StatsMapEntry{pbasename + "seconds_sum", buf});
  entries.emplace(name + "count", StatsMapEntry{pbasename + "seconds_count", std::to_string(data.back().d_count)});

  return entries;
}

static StatsMap toStatsMap(const string& name, const pdns::Histogram& histogram4, const pdns::Histogram& histogram6)
{
  const string pbasename = getPrometheusName(name);
  StatsMap entries;
  char buf[32];
  std::string pname;

  const auto& data4 = histogram4.getCumulativeBuckets();
  for (const auto& bucket : data4) {
    snprintf(buf, sizeof(buf), "%g", bucket.d_boundary / 1e6);
    pname = pbasename + "seconds_bucket{ipversion=\"v4\",le=\"" + (bucket.d_boundary == std::numeric_limits<uint64_t>::max() ? "+Inf" : buf) + "\"}";
    entries.emplace(bucket.d_name + "4", StatsMapEntry{pname, std::to_string(bucket.d_count)});
  }
  snprintf(buf, sizeof(buf), "%g", histogram4.getSum() / 1e6);
  entries.emplace(name + "sum4", StatsMapEntry{pbasename + "seconds_sum{ipversion=\"v4\"}", buf});
  entries.emplace(name + "count4", StatsMapEntry{pbasename + "seconds_count{ipversion=\"v4\"}", std::to_string(data4.back().d_count)});

  const auto& data6 = histogram6.getCumulativeBuckets();
  for (const auto& bucket : data6) {
    snprintf(buf, sizeof(buf), "%g", bucket.d_boundary / 1e6);
    pname = pbasename + "seconds_bucket{ipversion=\"v6\",le=\"" + (bucket.d_boundary == std::numeric_limits<uint64_t>::max() ? "+Inf" : buf) + "\"}";
    entries.emplace(bucket.d_name + "6", StatsMapEntry{pname, std::to_string(bucket.d_count)});
  }
  snprintf(buf, sizeof(buf), "%g", histogram6.getSum() / 1e6);
  entries.emplace(name + "sum6", StatsMapEntry{pbasename + "seconds_sum{ipversion=\"v6\"}", buf});
  entries.emplace(name + "count6", StatsMapEntry{pbasename + "seconds_count{ipversion=\"v6\"}", std::to_string(data6.back().d_count)});

  return entries;
}

static StatsMap toAuthRCodeStatsMap(const string& name)
{
  const string pbasename = getPrometheusName(name);
  StatsMap entries;

  uint8_t n = 0;
  auto rcodes = g_Counters.sum(rec::RCode::auth).rcodeCounters;
  for (const auto& entry : rcodes) {
    const auto key = RCode::to_short_s(n);
    std::string pname = pbasename + "{rcode=\"" + key + "\"}";
    entries.emplace("auth-" + key + "-answers", StatsMapEntry{std::move(pname), std::to_string(entry)});
    n++;
  }
  return entries;
}

static StatsMap toCPUStatsMap(const string& name)
{
  const string pbasename = getPrometheusName(name);
  StatsMap entries;

  // Handler is not reported
  for (unsigned int n = 0; n < RecThreadInfo::numRecursorThreads() - 1; ++n) {
    uint64_t tm = doGetThreadCPUMsec(n);
    std::string pname = pbasename + "{thread=\"" + std::to_string(n) + "\"}";
    entries.emplace(name + "-thread-" + std::to_string(n), StatsMapEntry{std::move(pname), std::to_string(tm)});
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
    std::string sname, pname;
    if (key.empty()) {
      sname = name + "-filter";
      pname = pbasename + "{type=\"filter\"}";
    }
    else {
      sname = name + "-rpz-" + key;
      pname = pbasename + "{type=\"rpz\",policyname=\"" + key + "\"}";
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
      auto keyname = pbasename + "{address=\"" + key + "\",type=\"" + type + "\",count=\"";
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
    exit(1);
  }
}

static auto clearLuaScript()
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
    clearLuaScript();
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

vector<pair<DNSName, uint16_t>>* pleaseGetQueryRing()
{
  typedef pair<DNSName, uint16_t> query_t;
  vector<query_t>* ret = new vector<query_t>();
  if (!t_queryring)
    return ret;
  ret->reserve(t_queryring->size());

  for (const query_t& q : *t_queryring) {
    ret->push_back(q);
  }
  return ret;
}
vector<pair<DNSName, uint16_t>>* pleaseGetServfailQueryRing()
{
  typedef pair<DNSName, uint16_t> query_t;
  vector<query_t>* ret = new vector<query_t>();
  if (!t_servfailqueryring)
    return ret;
  ret->reserve(t_servfailqueryring->size());
  for (const query_t& q : *t_servfailqueryring) {
    ret->push_back(q);
  }
  return ret;
}
vector<pair<DNSName, uint16_t>>* pleaseGetBogusQueryRing()
{
  typedef pair<DNSName, uint16_t> query_t;
  vector<query_t>* ret = new vector<query_t>();
  if (!t_bogusqueryring)
    return ret;
  ret->reserve(t_bogusqueryring->size());
  for (const query_t& q : *t_bogusqueryring) {
    ret->push_back(q);
  }
  return ret;
}

typedef std::function<vector<ComboAddress>*()> pleaseremotefunc_t;
typedef std::function<vector<pair<DNSName, uint16_t>>*()> pleasequeryfunc_t;

vector<ComboAddress>* pleaseGetRemotes()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if (!t_remotes)
    return ret;

  ret->reserve(t_remotes->size());
  for (const ComboAddress& ca : *t_remotes) {
    ret->push_back(ca);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetServfailRemotes()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if (!t_servfailremotes)
    return ret;
  ret->reserve(t_servfailremotes->size());
  for (const ComboAddress& ca : *t_servfailremotes) {
    ret->push_back(ca);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetBogusRemotes()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if (!t_bogusremotes)
    return ret;
  ret->reserve(t_bogusremotes->size());
  for (const ComboAddress& ca : *t_bogusremotes) {
    ret->push_back(ca);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetLargeAnswerRemotes()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if (!t_largeanswerremotes)
    return ret;
  ret->reserve(t_largeanswerremotes->size());
  for (const ComboAddress& ca : *t_largeanswerremotes) {
    ret->push_back(ca);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetTimeouts()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if (!t_timeouts)
    return ret;
  ret->reserve(t_timeouts->size());
  for (const ComboAddress& ca : *t_timeouts) {
    ret->push_back(ca);
  }
  return ret;
}

static string doGenericTopRemotes(const pleaseremotefunc_t& func)
{
  auto remotes = broadcastAccFunction<vector<ComboAddress>>(func);
  const unsigned int total = remotes.size();
  if (total == 0) {
    return "No qualifying data available\n";
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
  return ret.str();
}

// XXX DNSName Pain - this function should benefit from native DNSName methods
DNSName getRegisteredName(const DNSName& dom)
{
  auto parts = dom.getRawLabels();
  if (parts.size() <= 2)
    return dom;
  reverse(parts.begin(), parts.end());
  for (string& str : parts) {
    str = toLower(str);
  };

  // uk co migweb
  string last;
  while (!parts.empty()) {
    if (parts.size() == 1 || binary_search(g_pubs.begin(), g_pubs.end(), parts)) {

      string ret = std::move(last);
      if (!ret.empty())
        ret += ".";

      for (auto p = parts.crbegin(); p != parts.crend(); ++p) {
        ret += (*p) + ".";
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

static string doGenericTopQueries(const pleasequeryfunc_t& func, const std::function<DNSName(const DNSName&)>& filter = nopFilter)
{
  using query_t = pair<DNSName, uint16_t>;
  auto queries = broadcastAccFunction<vector<query_t>>(func);
  const unsigned int total = queries.size();
  if (total == 0) {
    return "No qualifying data available\n";
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

  return ret.str();
}

static string* nopFunction()
{
  return new string("pong " + RecThreadInfo::self().getName() + '\n');
}

static string getDontThrottleNames()
{
  auto dtn = g_dontThrottleNames.getLocal();
  return dtn->toString() + "\n";
}

static string getDontThrottleNetmasks()
{
  auto dtn = g_dontThrottleNetmasks.getLocal();
  return dtn->toString() + "\n";
}

template <typename T>
static string addDontThrottleNames(T begin, T end)
{
  if (begin == end) {
    return "No names specified, keeping existing list\n";
  }
  vector<DNSName> toAdd;
  while (begin != end) {
    try {
      auto d = DNSName(*begin);
      toAdd.push_back(std::move(d));
    }
    catch (const std::exception& e) {
      return "Problem parsing '" + *begin + "': " + e.what() + ", nothing added\n";
    }
    begin++;
  }

  string ret = "Added";
  auto dnt = g_dontThrottleNames.getCopy();
  bool first = true;
  for (auto const& d : toAdd) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + d.toLogString();
    dnt.add(d);
  }

  g_dontThrottleNames.setState(std::move(dnt));

  ret += " to the list of nameservers that may not be throttled";
  g_log << Logger::Info << ret << ", requested via control channel" << endl;
  return ret + "\n";
}

template <typename T>
static string addDontThrottleNetmasks(T begin, T end)
{
  if (begin == end) {
    return "No netmasks specified, keeping existing list\n";
  }
  vector<Netmask> toAdd;
  while (begin != end) {
    try {
      auto n = Netmask(*begin);
      toAdd.push_back(n);
    }
    catch (const std::exception& e) {
      return "Problem parsing '" + *begin + "': " + e.what() + ", nothing added\n";
    }
    catch (const PDNSException& e) {
      return "Problem parsing '" + *begin + "': " + e.reason + ", nothing added\n";
    }
    begin++;
  }

  string ret = "Added";
  auto dnt = g_dontThrottleNetmasks.getCopy();
  bool first = true;
  for (auto const& t : toAdd) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + t.toString();
    dnt.addMask(t);
  }

  g_dontThrottleNetmasks.setState(std::move(dnt));

  ret += " to the list of nameserver netmasks that may not be throttled";
  g_log << Logger::Info << ret << ", requested via control channel" << endl;
  return ret + "\n";
}

template <typename T>
static string clearDontThrottleNames(T begin, T end)
{
  if (begin == end)
    return "No names specified, doing nothing.\n";

  if (begin + 1 == end && *begin == "*") {
    SuffixMatchNode smn;
    g_dontThrottleNames.setState(std::move(smn));
    string ret = "Cleared list of nameserver names that may not be throttled";
    g_log << Logger::Warning << ret << ", requested via control channel" << endl;
    return ret + "\n";
  }

  vector<DNSName> toRemove;
  while (begin != end) {
    try {
      if (*begin == "*") {
        return "Please don't mix '*' with other names, nothing removed\n";
      }
      toRemove.push_back(DNSName(*begin));
    }
    catch (const std::exception& e) {
      return "Problem parsing '" + *begin + "': " + e.what() + ", nothing removed\n";
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
  return ret + "\n";
}

template <typename T>
static string clearDontThrottleNetmasks(T begin, T end)
{
  if (begin == end)
    return "No netmasks specified, doing nothing.\n";

  if (begin + 1 == end && *begin == "*") {
    auto nmg = g_dontThrottleNetmasks.getCopy();
    nmg.clear();
    g_dontThrottleNetmasks.setState(std::move(nmg));

    string ret = "Cleared list of nameserver addresses that may not be throttled";
    g_log << Logger::Warning << ret << ", requested via control channel" << endl;
    return ret + "\n";
  }

  std::vector<Netmask> toRemove;
  while (begin != end) {
    try {
      if (*begin == "*") {
        return "Please don't mix '*' with other netmasks, nothing removed\n";
      }
      auto n = Netmask(*begin);
      toRemove.push_back(n);
    }
    catch (const std::exception& e) {
      return "Problem parsing '" + *begin + "': " + e.what() + ", nothing added\n";
    }
    catch (const PDNSException& e) {
      return "Problem parsing '" + *begin + "': " + e.reason + ", nothing added\n";
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
  return ret + "\n";
}

template <typename T>
static string setEventTracing(T begin, T end)
{
  if (begin == end) {
    return "No event trace enabled value specified\n";
  }
  try {
    pdns::checked_stoi_into(SyncRes::s_event_trace_enabled, *begin);
    return "New event trace enabled value: " + std::to_string(SyncRes::s_event_trace_enabled) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new event trace enabled value: " + std::string(e.what()) + "\n";
  }
}

static void* pleaseSupplantProxyMapping(const ProxyMapping& pm)
{
  if (pm.empty()) {
    t_proxyMapping = nullptr;
  }
  else {
    // Copy the existing stats values, for the new config items also present in the old
    auto newmapping = make_unique<ProxyMapping>();
    for (const auto& [nm, entry] : pm) {
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

static RecursorControlChannel::Answer help()
{
  return {0,
          "add-dont-throttle-names [N...]   add names that are not allowed to be throttled\n"
          "add-dont-throttle-netmasks [N...]\n"
          "                                 add netmasks that are not allowed to be throttled\n"
          "add-nta DOMAIN [REASON]          add a Negative Trust Anchor for DOMAIN with the comment REASON\n"
          "add-ta DOMAIN DSRECORD           add a Trust Anchor for DOMAIN with data DSRECORD\n"
          "current-queries                  show currently active queries\n"
          "clear-dont-throttle-names [N...] remove names that are not allowed to be throttled. If N is '*', remove all\n"
          "clear-dont-throttle-netmasks [N...]\n"
          "                                 remove netmasks that are not allowed to be throttled. If N is '*', remove all\n"
          "clear-nta [DOMAIN]...            Clear the Negative Trust Anchor for DOMAINs, if no DOMAIN is specified, remove all\n"
          "clear-ta [DOMAIN]...             Clear the Trust Anchor for DOMAINs\n"
          "dump-cache <filename> [type...]  dump cache contents to the named file, type is r, n, p or a\n"
          "dump-dot-probe-map <filename>    dump the contents of the DoT probe map to the named file\n"
          "dump-edns [status] <filename>    dump EDNS status to the named file\n"
          "dump-failedservers <filename>    dump the failed servers to the named file\n"
          "dump-non-resolving <filename>    dump non-resolving nameservers addresses to the named file\n"
          "dump-nsspeeds <filename>         dump nsspeeds statistics to the named file\n"
          "dump-saved-parent-ns-sets <filename>\n"
          "                                 dump saved parent ns sets that were successfully used as fallback\n"
          "dump-rpz <zone name> <filename>  dump the content of a RPZ zone to the named file\n"
          "dump-throttlemap <filename>      dump the contents of the throttle map to the named file\n"
          "get [key1] [key2] ..             get specific statistics\n"
          "get-all                          get all statistics\n"
          "get-dont-throttle-names          get the list of names that are not allowed to be throttled\n"
          "get-dont-throttle-netmasks       get the list of netmasks that are not allowed to be throttled\n"
          "get-ntas                         get all configured Negative Trust Anchors\n"
          "get-tas                          get all configured Trust Anchors\n"
          "get-parameter [key1] [key2] ..   get configuration parameters\n"
          "get-proxymapping-stats           get proxy mapping statistics\n"
          "get-qtypelist                    get QType statistics\n"
          "                                 notice: queries from cache aren't being counted yet\n"
          "get-remotelogger-stats           get remote logger statistics\n"
          "hash-password [work-factor]      ask for a password then return the hashed version\n"
          "help                             get this list (from the running recursor)\n"
          "list-dnssec-algos                list supported DNSSEC algorithms\n"
          "ping                             check that all threads are alive\n"
          "quit                             stop the recursor daemon\n"
          "quit-nicely                      stop the recursor daemon nicely\n"
          "reload-acls                      reload ACLS\n"
          "reload-lua-script [filename]     (re)load Lua script\n"
          "reload-yaml                      Reload runtime settable parts of YAML settings\n"
          "reload-lua-config [filename]     (re)load Lua configuration file or equivalent YAML clauses\n"
          "reload-zones                     reload all auth and forward zones\n"
          "set-ecs-minimum-ttl value        set ecs-minimum-ttl-override\n"
          "set-max-aggr-nsec-cache-size value set new maximum aggressive NSEC cache size\n"
          "set-max-cache-entries value      set new maximum record cache size\n"
          "set-max-packetcache-entries val  set new maximum packet cache size\n"
          "set-minimum-ttl value            set minimum-ttl-override\n"
          "set-carbon-server                set a carbon server for telemetry\n"
          "set-dnssec-log-bogus SETTING     enable (SETTING=yes) or disable (SETTING=no) logging of DNSSEC validation failures\n"
          "set-event-trace-enabled SETTING  set logging of event trace messages, 0 = disabled, 1 = protobuf, 2 = log file, 3 = both\n"
          "show-yaml [file]                 show yaml config derived from old-style config\n"
          "trace-regex [regex file]         emit resolution trace for matching queries (no arguments clears tracing)\n"
          "top-largeanswer-remotes          show top remotes receiving large answers\n"
          "top-queries                      show top queries\n"
          "top-pub-queries                  show top queries grouped by public suffix list\n"
          "top-remotes                      show top remotes\n"
          "top-timeouts                     show top downstream timeouts\n"
          "top-servfail-queries             show top queries receiving servfail answers\n"
          "top-bogus-queries                show top queries validating as bogus\n"
          "top-pub-servfail-queries         show top queries receiving servfail answers grouped by public suffix list\n"
          "top-pub-bogus-queries            show top queries validating as bogus grouped by public suffix list\n"
          "top-servfail-remotes             show top remotes receiving servfail answers\n"
          "top-bogus-remotes                show top remotes receiving bogus answers\n"
          "unload-lua-script                unload Lua script\n"
          "version                          return version number of running Recursor\n"
          "wipe-cache domain0 [domain1] ..  wipe domain data from cache\n"
          "wipe-cache-typed type domain0 [domain1] ..  wipe domain data with qtype from cache\n"};
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
        SLOG(g_log << Logger::Notice << "Reloaded Lua configuration file '" << ::arg()["lua-config-file"] << "', requested via control channel" << endl,
             g_slog->withName("config")->info(Logr::Info, "Reloaded"));
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
    auto yamlstat = pdns::settings::rec::tryReadYAML(configname + g_yamlSettingsSuffix, false, dummy1, dummy2, settings, g_slog);
    if (yamlstat != pdns::settings::rec::YamlSettingsStatus::OK) {
      return {1, "Not reloading dynamic part of YAML configuration\n"};
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

    return {0, "Reloaded dynamic part of YAML configuration\n"};
  }
  catch (std::exception& e) {
    return {1, "Unable to reload dynamic YAML changes: " + std::string(e.what()) + "\n"};
  }
  catch (const PDNSException& e) {
    return {1, "Unable to reload dynamic YAML changes: " + e.reason + "\n"};
  }
}

template <typename T>
static RecursorControlChannel::Answer luaconfig(T begin, T end)
{
  if (begin != end) {
    if (g_luaSettingsInYAML) {
      return {1, "Unable to reload Lua script from '" + *begin + "' as there is no active Lua configuration\n"};
    }
    ::arg().set("lua-config-file") = *begin;
  }
  return luaconfig(true);
}

static RecursorControlChannel::Answer reloadACLs()
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

RecursorControlChannel::Answer RecursorControlParser::getAnswer(int socket, const string& question, RecursorControlParser::func_t** command)
{
  *command = nop;
  vector<string> words;
  stringtok(words, question);

  if (words.empty()) {
    return {1, "invalid command\n"};
  }

  string cmd = toLower(words[0]);
  auto begin = words.begin() + 1;
  auto end = words.end();

  // should probably have a smart dispatcher here, like auth has
  if (cmd == "help") {
    return help();
  }
  if (cmd == "get-all") {
    return {0, getAllStats()};
  }
  if (cmd == "get") {
    return {0, doGet(begin, end)};
  }
  if (cmd == "get-parameter") {
    return {0, doGetParameter(begin, end)};
  }
  if (cmd == "quit") {
    *command = &doExit;
    return {0, "bye\n"};
  }
  if (cmd == "version") {
    return {0, getPDNSVersion() + "\n"};
  }
  if (cmd == "quit-nicely") {
    *command = &doExitNicely;
    return {0, "bye nicely\n"};
  }
  if (cmd == "dump-cache") {
    return doDumpCache(socket, begin, end);
  }
  if (cmd == "dump-dot-probe-map") {
    return doDumpToFile(socket, pleaseDumpDoTProbeMap, cmd, false);
  }
  if (cmd == "dump-ednsstatus" || cmd == "dump-edns") {
    return doDumpToFile(socket, pleaseDumpEDNSMap, cmd, false);
  }
  if (cmd == "dump-nsspeeds") {
    return doDumpToFile(socket, pleaseDumpNSSpeeds, cmd, false);
  }
  if (cmd == "dump-failedservers") {
    return doDumpToFile(socket, pleaseDumpFailedServers, cmd, false);
  }
  if (cmd == "dump-saved-parent-ns-sets") {
    return doDumpToFile(socket, pleaseDumpSavedParentNSSets, cmd, false);
  }
  if (cmd == "dump-rpz") {
    return doDumpRPZ(socket, begin, end);
  }
  if (cmd == "dump-throttlemap") {
    return doDumpToFile(socket, pleaseDumpThrottleMap, cmd, false);
  }
  if (cmd == "dump-non-resolving") {
    return doDumpToFile(socket, pleaseDumpNonResolvingNS, cmd, false);
  }
  if (cmd == "wipe-cache" || cmd == "flushname") {
    return {0, doWipeCache(begin, end, 0xffff)};
  }
  if (cmd == "wipe-cache-typed") {
    if (begin == end) {
      return {1, "Need a qtype\n"};
    }
    uint16_t qtype = QType::chartocode(begin->c_str());
    if (qtype == 0) {
      return {1, "Unknown qtype " + *begin + "\n"};
    }
    ++begin;
    return {0, doWipeCache(begin, end, qtype)};
  }
  if (cmd == "reload-lua-script") {
    return doQueueReloadLuaScript(begin, end);
  }
  if (cmd == "reload-lua-config") {
    return luaconfig(begin, end);
  }
  if (cmd == "reload-yaml") {
    return luaconfig(begin, end);
  }
  if (cmd == "set-carbon-server") {
    return {0, doSetCarbonServer(begin, end)};
  }
  if (cmd == "trace-regex") {
    return {0, doTraceRegex(begin == end ? FDWrapper(-1) : getfd(socket), begin, end)};
  }
  if (cmd == "unload-lua-script") {
    return clearLuaScript();
  }
  if (cmd == "reload-acls") {
    return reloadACLs();
  }
  if (cmd == "top-remotes") {
    return {0, doGenericTopRemotes(pleaseGetRemotes)};
  }
  if (cmd == "top-queries") {
    return {0, doGenericTopQueries(pleaseGetQueryRing)};
  }
  if (cmd == "top-pub-queries") {
    return {0, doGenericTopQueries(pleaseGetQueryRing, getRegisteredName)};
  }
  if (cmd == "top-servfail-queries") {
    return {0, doGenericTopQueries(pleaseGetServfailQueryRing)};
  }
  if (cmd == "top-pub-servfail-queries") {
    return {0, doGenericTopQueries(pleaseGetServfailQueryRing, getRegisteredName)};
  }
  if (cmd == "top-bogus-queries") {
    return {0, doGenericTopQueries(pleaseGetBogusQueryRing)};
  }
  if (cmd == "top-pub-bogus-queries") {
    return {0, doGenericTopQueries(pleaseGetBogusQueryRing, getRegisteredName)};
  }
  if (cmd == "top-servfail-remotes") {
    return {0, doGenericTopRemotes(pleaseGetServfailRemotes)};
  }
  if (cmd == "top-bogus-remotes") {
    return {0, doGenericTopRemotes(pleaseGetBogusRemotes)};
  }
  if (cmd == "top-largeanswer-remotes") {
    return {0, doGenericTopRemotes(pleaseGetLargeAnswerRemotes)};
  }
  if (cmd == "top-timeouts") {
    return {0, doGenericTopRemotes(pleaseGetTimeouts)};
  }
  if (cmd == "current-queries") {
    return {0, doCurrentQueries()};
  }
  if (cmd == "ping") {
    return {0, broadcastAccFunction<string>(nopFunction)};
  }
  if (cmd == "reload-zones") {
    if (!::arg()["chroot"].empty()) {
      g_log << Logger::Error << "Unable to reload zones and forwards when chroot()'ed, requested via control channel" << endl;
      return {1, "Unable to reload zones and forwards when chroot()'ed, please restart\n"};
    }
    return {0, reloadZoneConfigurationWithSysResolveReset()};
  }
  if (cmd == "set-ecs-minimum-ttl") {
    return {0, setMinimumECSTTL(begin, end)};
  }
  if (cmd == "set-max-cache-entries") {
    return {0, setMaxCacheEntries(begin, end)};
  }
  if (cmd == "set-max-packetcache-entries") {
    return {0, setMaxPacketCacheEntries(begin, end)};
  }
  if (cmd == "set-minimum-ttl") {
    return {0, setMinimumTTL(begin, end)};
  }
  if (cmd == "get-qtypelist") {
    return {0, g_Counters.sum(rec::ResponseStats::responseStats).getQTypeReport()};
  }
  if (cmd == "add-nta") {
    return {0, doAddNTA(begin, end)};
  }
  if (cmd == "clear-nta") {
    return {0, doClearNTA(begin, end)};
  }
  if (cmd == "get-ntas") {
    return {0, getNTAs()};
  }
  if (cmd == "add-ta") {
    return {0, doAddTA(begin, end)};
  }
  if (cmd == "clear-ta") {
    return {0, doClearTA(begin, end)};
  }
  if (cmd == "get-tas") {
    return {0, getTAs()};
  }
  if (cmd == "set-dnssec-log-bogus") {
    return {0, doSetDnssecLogBogus(begin, end)};
  }
  if (cmd == "get-dont-throttle-names") {
    return {0, getDontThrottleNames()};
  }
  if (cmd == "get-dont-throttle-netmasks") {
    return {0, getDontThrottleNetmasks()};
  }
  if (cmd == "add-dont-throttle-names") {
    return {0, addDontThrottleNames(begin, end)};
  }
  if (cmd == "add-dont-throttle-netmasks") {
    return {0, addDontThrottleNetmasks(begin, end)};
  }
  if (cmd == "clear-dont-throttle-names") {
    return {0, clearDontThrottleNames(begin, end)};
  }
  if (cmd == "clear-dont-throttle-netmasks") {
    return {0, clearDontThrottleNetmasks(begin, end)};
  }
  if (cmd == "set-event-trace-enabled") {
    return {0, setEventTracing(begin, end)};
  }
  if (cmd == "get-proxymapping-stats") {
    return {0, doGetProxyMappingStats()};
  }
  if (cmd == "get-remotelogger-stats") {
    return {0, getRemoteLoggerStats()};
  }
  if (cmd == "list-dnssec-algos") {
    return {0, DNSCryptoKeyEngine::listSupportedAlgoNames()};
  }
  if (cmd == "set-aggr-nsec-cache-size") {
    return setAggrNSECCacheSize(begin, end);
  }

  return {1, "Unknown command '" + cmd + "', try 'help'\n"};
}
