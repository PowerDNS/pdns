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
#include <boost/function.hpp>
#include <boost/optional.hpp>
#include <boost/tuple/tuple.hpp>
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
#include "responsestats.hh"
#include "rec-lua-conf.hh"

#include "aggressive_nsec.hh"
#include "validate-recursor.hh"
#include "filterpo.hh"

#include "secpoll-recursor.hh"
#include "pubsuffix.hh"
#include "namespaces.hh"
#include "rec-taskqueue.hh"

std::pair<std::string, std::string> PrefixDashNumberCompare::prefixAndTrailingNum(const std::string& a)
{
  auto i = a.length();
  if (i == 0) {
    return make_pair(a, "");
  }
  --i;
  if (!std::isdigit(a[i])) {
    return make_pair(a, "");
  }
  while (i > 0) {
    if (!std::isdigit(a[i])) {
      break;
    }
    --i;
  }
  return make_pair(a.substr(0, i + 1), a.substr(i + 1, a.size() - i - 1));
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

std::mutex g_carbon_config_lock;

static map<string, const uint32_t*> d_get32bitpointers;
static map<string, const std::atomic<uint64_t>*> d_getatomics;
static map<string, std::function<uint64_t()>>  d_get64bitmembers;
static map<string, std::function<StatsMap()>> d_getmultimembers;

struct dynmetrics {
  std::atomic<unsigned long> *d_ptr;
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
  for (const auto &st : disabledStats) {
    map.insert(st);
  }
}

static void addGetStat(const string& name, const uint32_t* place)
{
  d_get32bitpointers[name] = place;
}

static void addGetStat(const string& name, const std::atomic<uint64_t>* place)
{
  d_getatomics[name] = place;
}

static void addGetStat(const string& name, std::function<uint64_t()> f)
{
  d_get64bitmembers[name] = f;
}

static void addGetStat(const string& name, std::function<StatsMap()> f)
{
  d_getmultimembers[name] = f;
}

static std::string getPrometheusName(const std::string& arg)
{
  std::string name = arg;
  std::replace_if(name.begin(), name.end(), [](char c){
    return !isalnum(static_cast<unsigned char>(c));}, '_');
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
  } else {
    name = getPrometheusName(name);
  }

  auto ret = dynmetrics{new std::atomic<unsigned long>(), name};
  (*dm)[str]= ret;
  return ret.d_ptr;
}

static boost::optional<uint64_t> get(const string& name)
{
  boost::optional<uint64_t> ret;

  if(d_get32bitpointers.count(name))
    return *d_get32bitpointers.find(name)->second;
  if(d_getatomics.count(name))
    return d_getatomics.find(name)->second->load();
  if(d_get64bitmembers.count(name))
    return d_get64bitmembers.find(name)->second();

  {
    auto dm = d_dynmetrics.lock();
    auto f = rplookup(*dm, name);
    if (f) {
      return f->d_ptr->load();
    }
  }

  for(const auto& themultimember : d_getmultimembers) {
    const auto items = themultimember.second();
    const auto item = items.find(name);
    if (item != items.end()) {
      return std::stoull(item->second.d_value);
    }
  }

  return ret;
}

boost::optional<uint64_t> getStatByName(const std::string& name)
{
  return get(name);
}

StatsMap getAllStatsMap(StatComponent component)
{
  StatsMap ret;
  const auto& disabledlistMap = s_disabledStats.at(component);

  for(const auto& the32bits :  d_get32bitpointers) {
    if (disabledlistMap.count(the32bits.first) == 0) {
      ret.insert(make_pair(the32bits.first, StatsMapEntry{getPrometheusName(the32bits.first), std::to_string(*the32bits.second)}));
    }
  }
  for(const auto& atomic :  d_getatomics) {
    if (disabledlistMap.count(atomic.first) == 0) {
      ret.insert(make_pair(atomic.first, StatsMapEntry{getPrometheusName(atomic.first), std::to_string(atomic.second->load())}));
    }
  }

  for(const auto& the64bitmembers :  d_get64bitmembers) {
    if (disabledlistMap.count(the64bitmembers.first) == 0) {
      ret.insert(make_pair(the64bitmembers.first, StatsMapEntry{getPrometheusName(the64bitmembers.first), std::to_string(the64bitmembers.second())}));
    }
  }

  for(const auto& themultimember : d_getmultimembers) {
    if (disabledlistMap.count(themultimember.first) == 0) {
      ret.merge(themultimember.second());
    }
  }

  {
    for(const auto& a : *(d_dynmetrics.lock())) {
      if (disabledlistMap.count(a.first) == 0) {
        ret.insert(make_pair(a.first, StatsMapEntry{a.second.d_prometheusName, std::to_string(*a.second.d_ptr)}));
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

template<typename T>
static string doGet(T begin, T end)
{
  string ret;

  for(T i=begin; i != end; ++i) {
    boost::optional<uint64_t> num=get(*i);
    if(num)
      ret+=std::to_string(*num)+"\n";
    else
      ret+="UNKNOWN\n";
  }
  return ret;
}

template<typename T>
string static doGetParameter(T begin, T end)
{
  string ret;
  string parm;
  using boost::replace_all;
  for(T i=begin; i != end; ++i) {
    if(::arg().parmIsset(*i)) {
      parm=::arg()[*i];
      replace_all(parm, "\\", "\\\\");
      replace_all(parm, "\"", "\\\"");
      replace_all(parm, "\n", "\\n");
      ret += *i +"=\""+ parm +"\"\n";
    }
    else
      ret += *i +" not known\n";
  }
  return ret;
}

struct FDWrapper : public boost::noncopyable
{
  FDWrapper(int descr) : fd(descr) {}
  ~FDWrapper()
  {
    if (fd != -1) {
      close(fd);
    }
    fd = -1;
  }
  FDWrapper(FDWrapper&& rhs) : fd(rhs.fd)
  {
    rhs.fd = -1;
  }
  operator int() const
  {
    return fd;
  }
private:
  int fd;
};

/* Read an (open) fd from the control channel */
static FDWrapper
getfd(int s)
{
  int fd = -1;
  struct msghdr    msg;
  struct cmsghdr  *cmsg;
  union {
    struct cmsghdr hdr;
    unsigned char    buf[CMSG_SPACE(sizeof(int))];
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
    if (cmsg->cmsg_len == CMSG_LEN(sizeof(int)) &&
        cmsg->cmsg_level == SOL_SOCKET &&
        cmsg->cmsg_type == SCM_RIGHTS) {
      fd = *(int *)CMSG_DATA(cmsg);
      break;
    }
  }
  return FDWrapper(fd);
}


static uint64_t dumpNegCache(int fd)
{
  int newfd = dup(fd);
  if (newfd == -1) {
    return 0;
  }
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    return 0;
  }
  fprintf(fp.get(), "; negcache dump follows\n;\n");

  struct timeval now;
  Utility::gettimeofday(&now, nullptr);
  return g_negCache->dumpToFile(fp.get(), now);
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
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(newfd, "w"), fclose);
  if (!fp) {
    return 0;
  }
  fprintf(fp.get(), "; aggressive NSEC cache dump follows\n;\n");

  struct timeval now;
  Utility::gettimeofday(&now, nullptr);
  return g_aggressiveNSECCache->dumpToFile(fp, now);
}

static uint64_t* pleaseDump(int fd)
{
  return new uint64_t(t_packetCache->doDump(fd));
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

static uint64_t* pleaseDumpNonResolvingNS(int fd)
{
  return new uint64_t(SyncRes::doDumpNonResolvingNS(fd));
}

// Generic dump to file command
static RecursorControlChannel::Answer doDumpToFile(int s, uint64_t* (*function)(int s), const string& name)
{
  auto fdw = getfd(s);

  if (fdw < 0) {
    return { 1, name + ": error opening dump file for writing: " + stringerror() + "\n" };
  }

  uint64_t total = 0;
  try {
    int fd = fdw;
    total = broadcastAccFunction<uint64_t>([function, fd]{ return function(fd); });
  }
  catch(std::exception& e)
  {
    return { 1, name + ": error dumping data: " + string(e.what()) + "\n" };
  }
  catch(PDNSException& e)
  {
    return { 1, name + ": error dumping data: " + e.reason + "\n" };
  }

  return { 0, name + ": dumped " + std::to_string(total) + " records\n" };
}

// Does not follow the generic dump to file pattern, has a more complex lambda
static RecursorControlChannel::Answer doDumpCache(int s)
{
  auto fdw = getfd(s);

  if (fdw < 0) {
    return { 1, "Error opening dump file for writing: " + stringerror() + "\n" };
  }
  uint64_t total = 0;
  try {
    int fd = fdw;
    total = g_recCache->doDump(fd) + dumpNegCache(fd) + broadcastAccFunction<uint64_t>([fd]{ return pleaseDump(fd); }) + dumpAggressiveNSECCache(fd);
  }
  catch(...){}

  return { 0, "dumped " + std::to_string(total) + " records\n" };
}

// Does not follow the generic dump to file pattern, has an argument
template<typename T>
static RecursorControlChannel::Answer doDumpRPZ(int s, T begin, T end)
{
  auto fdw = getfd(s);

  if (fdw < 0) {
    return { 1, "Error opening dump file for writing: " + stringerror() + "\n" };
  }

  T i = begin;

  if (i == end) {
    return { 1, "No zone name specified\n" };
  }
  string zoneName = *i;

  auto luaconf = g_luaconfs.getLocal();
  const auto zone = luaconf->dfe.getZone(zoneName);
  if (!zone) {
    return { 1, "No RPZ zone named " + zoneName + "\n" };
  }


  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(fdw, "w"), fclose);
  if (!fp) {
    int err = errno;
    return { 1, "converting file descriptor: " + stringerror(err) + "\n" };
  }

  zone->dump(fp.get());

  return {0, "done\n"};
}

uint64_t* pleaseWipePacketCache(const DNSName& canon, bool subtree, uint16_t qtype)
{
  return new uint64_t(t_packetCache->doWipePacketCache(canon, qtype, subtree));
}

template<typename T>
static string doWipeCache(T begin, T end, uint16_t qtype)
{
  vector<pair<DNSName, bool> > toWipe;
  for(T i=begin; i != end; ++i) {
    DNSName canon;
    bool subtree=false;

    try {
      if(boost::ends_with(*i, "$")) {
        canon=DNSName(i->substr(0, i->size()-1));
        subtree=true;
      } else {
        canon=DNSName(*i);
      }
    } catch (std::exception &e) {
      return "Error: " + std::string(e.what()) + ", nothing wiped\n";
    }
    toWipe.push_back({canon, subtree});
  }

  int count=0, pcount=0, countNeg=0;
  for (auto wipe : toWipe) {
    try {
      count += g_recCache->doWipeCache(wipe.first, wipe.second, qtype);
      pcount += broadcastAccFunction<uint64_t>([=]{ return pleaseWipePacketCache(wipe.first, wipe.second, qtype);});
      countNeg += g_negCache->wipe(wipe.first, wipe.second);
      if (g_aggressiveNSECCache) {
        g_aggressiveNSECCache->removeZoneInfo(wipe.first, wipe.second);
      }
    }
    catch (const std::exception& e) {
      g_log<<Logger::Warning<<", failed: "<<e.what()<<endl;
    }
  }

  return "wiped " + std::to_string(count)+" records, " + std::to_string(countNeg)+" negative records, " + std::to_string(pcount)+" packets\n";
}

template<typename T>
static string doSetCarbonServer(T begin, T end)
{
  std::lock_guard<std::mutex> l(g_carbon_config_lock);
  if(begin==end) {
    ::arg().set("carbon-server").clear();
    return "cleared carbon-server setting\n";
  }
  string ret;
  ::arg().set("carbon-server")=*begin;
  ret="set carbon-server to '"+::arg()["carbon-server"]+"'\n";
  ++begin;
  if(begin != end) {
    ::arg().set("carbon-ourname")=*begin;
    ret+="set carbon-ourname to '"+*begin+"'\n";
  } else {
    return ret;
  }
  ++begin;
  if(begin != end) {
    ::arg().set("carbon-namespace")=*begin;
    ret+="set carbon-namespace to '"+*begin+"'\n";
  } else {
    return ret;
  }
  ++begin;
  if(begin != end) {
    ::arg().set("carbon-instance")=*begin;
    ret+="set carbon-instance to '"+*begin+"'\n";
  }
  return ret;
}

template<typename T>
static string doSetDnssecLogBogus(T begin, T end)
{
  if(checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not changing the Bogus logging setting\n";

  if (begin == end)
    return "No DNSSEC Bogus logging setting specified\n";

  if (pdns_iequals(*begin, "on") || pdns_iequals(*begin, "yes")) {
    if (!g_dnssecLogBogus) {
      g_log<<Logger::Warning<<"Enabling DNSSEC Bogus logging, requested via control channel"<<endl;
      g_dnssecLogBogus = true;
      return "DNSSEC Bogus logging enabled\n";
    }
    return "DNSSEC Bogus logging was already enabled\n";
  }

  if (pdns_iequals(*begin, "off") || pdns_iequals(*begin, "no")) {
    if (g_dnssecLogBogus) {
      g_log<<Logger::Warning<<"Disabling DNSSEC Bogus logging, requested via control channel"<<endl;
      g_dnssecLogBogus = false;
      return "DNSSEC Bogus logging disabled\n";
    }
    return "DNSSEC Bogus logging was already disabled\n";
  }

  return "Unknown DNSSEC Bogus setting: '" + *begin +"'\n";
}

template<typename T>
static string doAddNTA(T begin, T end)
{
  if(checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not adding a Negative Trust Anchor\n";

  if(begin == end)
    return "No NTA specified, doing nothing\n";

  DNSName who;
  try {
    who = DNSName(*begin);
  }
  catch(std::exception &e) {
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
  g_log<<Logger::Warning<<"Adding Negative Trust Anchor for "<<who<<" with reason '"<<why<<"', requested via control channel"<<endl;
  g_luaconfs.modify([who, why](LuaConfigItems& lci) {
      lci.negAnchors[who] = why;
      });
  try {
    g_recCache->doWipeCache(who, true, 0xffff);
    broadcastAccFunction<uint64_t>([=]{return pleaseWipePacketCache(who, true, 0xffff);});
    g_negCache->wipe(who, true);
    if (g_aggressiveNSECCache) {
      g_aggressiveNSECCache->removeZoneInfo(who, true);
    }
  }
  catch (std::exception& e) {
    g_log<<Logger::Warning<<", failed: "<<e.what()<<endl;
    return "Unable to clear caches while adding Negative Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n";
  }
  return "Added Negative Trust Anchor for " + who.toLogString() + " with reason '" + why + "'\n";
}

template<typename T>
static string doClearNTA(T begin, T end)
{
  if(checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not removing a Negative Trust Anchor\n";

  if(begin == end)
    return "No Negative Trust Anchor specified, doing nothing.\n";

  if (begin + 1 == end && *begin == "*"){
    g_log<<Logger::Warning<<"Clearing all Negative Trust Anchors, requested via control channel"<<endl;
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
    catch(std::exception &e) {
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
    for (auto const &entry : toRemove) {
      g_log<<Logger::Warning<<"Clearing Negative Trust Anchor for "<<entry<<", requested via control channel"<<endl;
      g_luaconfs.modify([entry](LuaConfigItems& lci) {
                          lci.negAnchors.erase(entry);
                        });
      g_recCache->doWipeCache(entry, true, 0xffff);
      broadcastAccFunction<uint64_t>([=]{return pleaseWipePacketCache(entry, true, 0xffff);});
      g_negCache->wipe(entry, true);
      if (g_aggressiveNSECCache) {
        g_aggressiveNSECCache->removeZoneInfo(entry, true);
      }
      if (!first) {
        first = false;
        removed += ",";
      }
      removed += " " + entry.toStringRootDot();
    }
  }
  catch(std::exception &e) {
    g_log<<Logger::Warning<<", failed: "<<e.what()<<endl;
    return "Unable to clear caches while clearing Negative Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n";
  }

  return "Removed Negative Trust Anchors for " + removed + "\n";
}

static string getNTAs()
{
  if(checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration\n";

  string ret("Configured Negative Trust Anchors:\n");
  auto luaconf = g_luaconfs.getLocal();
  for (auto negAnchor : luaconf->negAnchors)
    ret += negAnchor.first.toLogString() + "\t" + negAnchor.second + "\n";
  return ret;
}

template<typename T>
static string doAddTA(T begin, T end)
{
  if(checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not adding a Trust Anchor\n";

  if(begin == end)
    return "No TA specified, doing nothing\n";

  DNSName who;
  try {
    who = DNSName(*begin);
  }
  catch(std::exception &e) {
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
    g_log<<Logger::Warning<<"Adding Trust Anchor for "<<who<<" with data '"<<what<<"', requested via control channel";
    g_luaconfs.modify([who, what](LuaConfigItems& lci) {
      auto ds=std::dynamic_pointer_cast<DSRecordContent>(DSRecordContent::make(what));
      lci.dsAnchors[who].insert(*ds);
      });
    g_recCache->doWipeCache(who, true, 0xffff);
    broadcastAccFunction<uint64_t>([=]{return pleaseWipePacketCache(who, true, 0xffff);});
    g_negCache->wipe(who, true);
    if (g_aggressiveNSECCache) {
      g_aggressiveNSECCache->removeZoneInfo(who, true);
    }
    g_log<<Logger::Warning<<endl;
    return "Added Trust Anchor for " + who.toStringRootDot() + " with data " + what + "\n";
  }
  catch(std::exception &e) {
    g_log<<Logger::Warning<<", failed: "<<e.what()<<endl;
    return "Unable to add Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n";
  }
}

template<typename T>
static string doClearTA(T begin, T end)
{
  if(checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration, not removing a Trust Anchor\n";

  if(begin == end)
    return "No Trust Anchor to clear\n";

  vector<DNSName> toRemove;
  DNSName who;
  while (begin != end) {
    try {
      who = DNSName(*begin);
    }
    catch(std::exception &e) {
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
    for (auto const &entry : toRemove) {
      g_log<<Logger::Warning<<"Removing Trust Anchor for "<<entry<<", requested via control channel"<<endl;
      g_luaconfs.modify([entry](LuaConfigItems& lci) {
                          lci.dsAnchors.erase(entry);
                        });
      g_recCache->doWipeCache(entry, true, 0xffff);
      broadcastAccFunction<uint64_t>([=]{return pleaseWipePacketCache(entry, true, 0xffff);});
      g_negCache->wipe(entry, true);
      if (g_aggressiveNSECCache) {
        g_aggressiveNSECCache->removeZoneInfo(entry, true);
      }
      if (!first) {
        first = false;
        removed += ",";
      }
      removed += " " + entry.toStringRootDot();
    }
  }
  catch (std::exception& e) {
    g_log<<Logger::Warning<<", failed: "<<e.what()<<endl;
    return "Unable to clear caches while clearing Trust Anchor for " + who.toStringRootDot() + ": " + e.what() + "\n";
  }

  return "Removed Trust Anchor(s) for" + removed + "\n";
}

static string getTAs()
{
  if(checkDNSSECDisabled())
    return "DNSSEC is disabled in the configuration\n";

  string ret("Configured Trust Anchors:\n");
  auto luaconf = g_luaconfs.getLocal();
  for (auto anchor : luaconf->dsAnchors) {
    ret += anchor.first.toLogString() + "\n";
    for (auto e : anchor.second) {
      ret+="\t\t"+e.getZoneRepresentation() + "\n";
    }
  }

  return ret;
}

template<typename T>
static string setMinimumTTL(T begin, T end)
{
  if(end-begin != 1)
    return "Need to supply new minimum TTL number\n";
  try {
    SyncRes::s_minimumTTL = pdns_stou(*begin);
    return "New minimum TTL: " + std::to_string(SyncRes::s_minimumTTL) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new minimum TTL number: " + std::string(e.what()) + "\n";
  }
}

template<typename T>
static string setMinimumECSTTL(T begin, T end)
{
  if(end-begin != 1)
    return "Need to supply new ECS minimum TTL number\n";
  try {
    SyncRes::s_minimumECSTTL = pdns_stou(*begin);
    return "New minimum ECS TTL: " + std::to_string(SyncRes::s_minimumECSTTL) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new ECS minimum TTL number: " + std::string(e.what()) + "\n";
  }
}

template<typename T>
static string setMaxCacheEntries(T begin, T end)
{
  if(end-begin != 1) 
    return "Need to supply new cache size\n";
  try {
    g_maxCacheEntries = pdns_stou(*begin);
    return "New max cache entries: " + std::to_string(g_maxCacheEntries) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new cache size: " + std::string(e.what()) + "\n";
  }
}

template<typename T>
static string setMaxPacketCacheEntries(T begin, T end)
{
  if(end-begin != 1) 
    return "Need to supply new packet cache size\n";
  try {
    g_maxPacketCacheEntries = pdns_stou(*begin);
    return "New max packetcache entries: " + std::to_string(g_maxPacketCacheEntries) + "\n";
  }
  catch (const std::exception& e) {
    return "Error parsing the new packet cache size: " + std::string(e.what()) + "\n";
  }
}


static uint64_t getSysTimeMsec()
{
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  return (ru.ru_stime.tv_sec*1000ULL + ru.ru_stime.tv_usec/1000);
}

static uint64_t getUserTimeMsec()
{
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
  return (ru.ru_utime.tv_sec*1000ULL + ru.ru_utime.tv_usec/1000);
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
  uint64_t ret=0;
#ifdef RUSAGE_THREAD
  struct rusage ru;
  getrusage(RUSAGE_THREAD, &ru);
  ret = (ru.ru_utime.tv_sec*1000ULL + ru.ru_utime.tv_usec/1000);
  ret += (ru.ru_stime.tv_sec*1000ULL + ru.ru_stime.tv_usec/1000);
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
  if(last != time(nullptr)) {
   tt = broadcastAccFunction<ThreadTimes>(pleaseGetThreadCPUMsec);
   last = time(nullptr);
  }

  return tt.times.at(n);
}

static uint64_t calculateUptime()
{
  return time(nullptr) - g_stats.startupTime;
}

static string* pleaseGetCurrentQueries()
{
  ostringstream ostr;
  struct timeval now;
  gettimeofday(&now, 0);

  ostr << getMT()->d_waiters.size() <<" currently outstanding questions\n";

  boost::format fmt("%1% %|40t|%2% %|47t|%3% %|63t|%4% %|68t|%5% %|78t|%6%\n");

  ostr << (fmt % "qname" % "qtype" % "remote" % "tcp" % "chained" % "spent(ms)");
  unsigned int n=0;
  for(const auto& mthread : getMT()->d_waiters) {
    const std::shared_ptr<PacketID>& pident = mthread.key;
    const double spent = g_networkTimeoutMsec - (DiffTime(now, mthread.ttd) * 1000);
    ostr << (fmt 
             % pident->domain.toLogString() /* ?? */ % DNSRecordContent::NumberToType(pident->type) 
             % pident->remote.toString() % (pident->tcpsock ? 'Y' : 'n')
             % (pident->fd == -1 ? 'Y' : 'n')
             % (spent > 0 ? spent : '0')
             );
    ++n;
    if (n >= 100)
      break;
  }
  ostr <<" - done\n";
  return new string(ostr.str());
}

static string doCurrentQueries()
{
  return broadcastAccFunction<string>(pleaseGetCurrentQueries);
}

uint64_t* pleaseGetThrottleSize()
{
  return new uint64_t(SyncRes::getThrottledServersSize());
}

static uint64_t getThrottleSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetThrottleSize);
}

static uint64_t getNegCacheSize()
{
  return g_negCache->size();
}

static uint64_t* pleaseGetFailedHostsSize()
{
  uint64_t tmp=(SyncRes::getThrottledServersSize());
  return new uint64_t(tmp);
}

static uint64_t getFailedHostsSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetFailedHostsSize);
}

uint64_t* pleaseGetNsSpeedsSize()
{
  return new uint64_t(SyncRes::getNSSpeedsSize());
}

static uint64_t getNsSpeedsSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetNsSpeedsSize);
}

uint64_t* pleaseGetFailedServersSize()
{
  return new uint64_t(SyncRes::getFailedServersSize());
}

uint64_t* pleaseGetEDNSStatusesSize()
{
  return new uint64_t(SyncRes::getEDNSStatusesSize());
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

static uint64_t doGetCacheHits()
{
  return g_recCache->cacheHits;
}

static uint64_t doGetCacheMisses()
{
  return g_recCache->cacheMisses;
}

uint64_t* pleaseGetPacketCacheSize()
{
  return new uint64_t(t_packetCache ? t_packetCache->size() : 0);
}

static uint64_t* pleaseGetPacketCacheBytes()
{
  return new uint64_t(t_packetCache ? t_packetCache->bytes() : 0);
}

static uint64_t doGetPacketCacheSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetPacketCacheSize);
}

static uint64_t doGetPacketCacheBytes()
{
  return broadcastAccFunction<uint64_t>(pleaseGetPacketCacheBytes);
}

uint64_t* pleaseGetPacketCacheHits()
{
  return new uint64_t(t_packetCache ? t_packetCache->d_hits : 0);
}

static uint64_t doGetPacketCacheHits()
{
  return broadcastAccFunction<uint64_t>(pleaseGetPacketCacheHits);
}

static uint64_t* pleaseGetPacketCacheMisses()
{
  return new uint64_t(t_packetCache ? t_packetCache->d_misses : 0);
}

static uint64_t doGetPacketCacheMisses()
{
  return broadcastAccFunction<uint64_t>(pleaseGetPacketCacheMisses);
}

static uint64_t doGetMallocated()
{
  // this turned out to be broken
/*  struct mallinfo mi = mallinfo();
  return mi.uordblks; */
  return 0;
}

static StatsMap toStatsMap(const string& name, const pdns::AtomicHistogram& histogram)
{
  const auto& data = histogram.getCumulativeBuckets();
  const string pbasename = getPrometheusName(name);
  StatsMap entries;
  char buf[32];

  for (const auto& bucket : data) {
    snprintf(buf, sizeof(buf), "%g", bucket.d_boundary / 1e6);
    std::string pname = pbasename + "seconds_bucket{" + "le=\"" +
      (bucket.d_boundary == std::numeric_limits<uint64_t>::max() ? "+Inf" : buf) + "\"}";
    entries.emplace(make_pair(bucket.d_name, StatsMapEntry{pname, std::to_string(bucket.d_count)}));
  }

  snprintf(buf, sizeof(buf), "%g", histogram.getSum() / 1e6);
  entries.emplace(make_pair(name + "sum", StatsMapEntry{pbasename + "seconds_sum", buf}));
  entries.emplace(make_pair(name + "count", StatsMapEntry{pbasename + "seconds_count", std::to_string(data.back().d_count)}));

  return entries;
}

extern ResponseStats g_rs;

static void registerAllStats1()
{
  addGetStat("questions", &g_stats.qcounter);
  addGetStat("ipv6-questions", &g_stats.ipv6qcounter);
  addGetStat("tcp-questions", &g_stats.tcpqcounter);

  addGetStat("cache-hits", doGetCacheHits);
  addGetStat("cache-misses", doGetCacheMisses); 
  addGetStat("cache-entries", doGetCacheSize);
  addGetStat("max-cache-entries", []() { return g_maxCacheEntries.load(); });
  addGetStat("max-packetcache-entries", []() { return g_maxPacketCacheEntries.load();}); 
  addGetStat("cache-bytes", doGetCacheBytes); 
  addGetStat("record-cache-contended", []() { return g_recCache->stats().first;});
  addGetStat("record-cache-acquired", []() { return g_recCache->stats().second;});
  
  addGetStat("packetcache-hits", doGetPacketCacheHits);
  addGetStat("packetcache-misses", doGetPacketCacheMisses); 
  addGetStat("packetcache-entries", doGetPacketCacheSize); 
  addGetStat("packetcache-bytes", doGetPacketCacheBytes); 

  addGetStat("aggressive-nsec-cache-entries", [](){ return g_aggressiveNSECCache ? g_aggressiveNSECCache->getEntriesCount() : 0; });
  addGetStat("aggressive-nsec-cache-nsec-hits", [](){ return g_aggressiveNSECCache ? g_aggressiveNSECCache->getNSECHits() : 0; });
  addGetStat("aggressive-nsec-cache-nsec3-hits", [](){ return g_aggressiveNSECCache ? g_aggressiveNSECCache->getNSEC3Hits() : 0; });
  addGetStat("aggressive-nsec-cache-nsec-wc-hits", [](){ return g_aggressiveNSECCache ? g_aggressiveNSECCache->getNSECWildcardHits() : 0; });
  addGetStat("aggressive-nsec-cache-nsec3-wc-hits", [](){ return g_aggressiveNSECCache ? g_aggressiveNSECCache->getNSEC3WildcardHits() : 0; });

  addGetStat("malloc-bytes", doGetMallocated);
  
  addGetStat("servfail-answers", &g_stats.servFails);
  addGetStat("nxdomain-answers", &g_stats.nxDomains);
  addGetStat("noerror-answers", &g_stats.noErrors);

  addGetStat("unauthorized-udp", &g_stats.unauthorizedUDP);
  addGetStat("unauthorized-tcp", &g_stats.unauthorizedTCP);
  addGetStat("tcp-client-overflow", &g_stats.tcpClientOverflow);

  addGetStat("client-parse-errors", &g_stats.clientParseError);
  addGetStat("server-parse-errors", &g_stats.serverParseError);
  addGetStat("too-old-drops", &g_stats.tooOldDrops);
  addGetStat("truncated-drops", &g_stats.truncatedDrops);
  addGetStat("query-pipe-full-drops", &g_stats.queryPipeFullDrops);

  addGetStat("answers0-1", []() { return g_stats.answers.getCount(0); });
  addGetStat("answers1-10", []() { return g_stats.answers.getCount(1); });
  addGetStat("answers10-100", []() { return g_stats.answers.getCount(2); });
  addGetStat("answers100-1000", []() { return g_stats.answers.getCount(3); });
  addGetStat("answers-slow", []() { return g_stats.answers.getCount(4); });

  addGetStat("x-ourtime0-1", []() { return g_stats.ourtime.getCount(0); });
  addGetStat("x-ourtime1-2", []() { return g_stats.ourtime.getCount(1); });
  addGetStat("x-ourtime2-4", []() { return g_stats.ourtime.getCount(2); });
  addGetStat("x-ourtime4-8", []() { return g_stats.ourtime.getCount(3); });
  addGetStat("x-ourtime8-16", []() { return g_stats.ourtime.getCount(4); });
  addGetStat("x-ourtime16-32", []() { return g_stats.ourtime.getCount(5); });
  addGetStat("x-ourtime-slow", []() { return g_stats.ourtime.getCount(6); });

  addGetStat("auth4-answers0-1", []() { return g_stats.auth4Answers.getCount(0); });
  addGetStat("auth4-answers1-10", []() { return g_stats.auth4Answers.getCount(1); });
  addGetStat("auth4-answers10-100", []() { return g_stats.auth4Answers.getCount(2); });
  addGetStat("auth4-answers100-1000", []() { return g_stats.auth4Answers.getCount(3); });
  addGetStat("auth4-answers-slow", []() { return g_stats.auth4Answers.getCount(4); });

  addGetStat("auth6-answers0-1", []() { return g_stats.auth6Answers.getCount(0); });
  addGetStat("auth6-answers1-10", []() { return g_stats.auth6Answers.getCount(1); });
  addGetStat("auth6-answers10-100", []() { return g_stats.auth6Answers.getCount(2); });
  addGetStat("auth6-answers100-1000", []() { return g_stats.auth6Answers.getCount(3); });
  addGetStat("auth6-answers-slow", []() { return g_stats.auth6Answers.getCount(4); });

  addGetStat("qa-latency", []() { return round(g_stats.avgLatencyUsec.load()); });
  addGetStat("x-our-latency", []() { return round(g_stats.avgLatencyOursUsec.load()); });
  addGetStat("unexpected-packets", &g_stats.unexpectedCount);
  addGetStat("case-mismatches", &g_stats.caseMismatchCount);
  addGetStat("spoof-prevents", &g_stats.spoofCount);

  addGetStat("nsset-invalidations", &g_stats.nsSetInvalidations);

  addGetStat("resource-limits", &g_stats.resourceLimits);
  addGetStat("over-capacity-drops", &g_stats.overCapacityDrops);
  addGetStat("policy-drops", &g_stats.policyDrops);
  addGetStat("no-packet-error", &g_stats.noPacketError);
  addGetStat("ignored-packets", &g_stats.ignoredCount);
  addGetStat("empty-queries", &g_stats.emptyQueriesCount);
  addGetStat("max-mthread-stack", &g_stats.maxMThreadStackUsage);

  addGetStat("negcache-entries", getNegCacheSize);
  addGetStat("throttle-entries", getThrottleSize);

  addGetStat("nsspeeds-entries", getNsSpeedsSize);
  addGetStat("failed-host-entries", getFailedHostsSize);

  addGetStat("concurrent-queries", getConcurrentQueries);
  addGetStat("security-status", &g_security_status);
  addGetStat("outgoing-timeouts", &SyncRes::s_outgoingtimeouts);
  addGetStat("outgoing4-timeouts", &SyncRes::s_outgoing4timeouts);
  addGetStat("outgoing6-timeouts", &SyncRes::s_outgoing6timeouts);
  addGetStat("auth-zone-queries", &SyncRes::s_authzonequeries);
  addGetStat("tcp-outqueries", &SyncRes::s_tcpoutqueries);
  addGetStat("dot-outqueries", &SyncRes::s_dotoutqueries);
  addGetStat("all-outqueries", &SyncRes::s_outqueries);
  addGetStat("ipv6-outqueries", &g_stats.ipv6queries);
  addGetStat("throttled-outqueries", &SyncRes::s_throttledqueries);
  addGetStat("dont-outqueries", &SyncRes::s_dontqueries);
  addGetStat("qname-min-fallback-success", &SyncRes::s_qnameminfallbacksuccess);
  addGetStat("throttled-out", &SyncRes::s_throttledqueries);
  addGetStat("unreachables", &SyncRes::s_unreachables);
  addGetStat("ecs-queries", &SyncRes::s_ecsqueries);
  addGetStat("ecs-responses", &SyncRes::s_ecsresponses);
  addGetStat("chain-resends", &g_stats.chainResends);
  addGetStat("tcp-clients", []{return TCPConnection::getCurrentConnections();});

#ifdef __linux__
  addGetStat("udp-recvbuf-errors", []{return udpErrorStats("udp-recvbuf-errors");});
  addGetStat("udp-sndbuf-errors", []{return udpErrorStats("udp-sndbuf-errors");});
  addGetStat("udp-noport-errors", []{return udpErrorStats("udp-noport-errors");});
  addGetStat("udp-in-errors", []{return udpErrorStats("udp-in-errors");});
#endif

  addGetStat("edns-ping-matches", &g_stats.ednsPingMatches);
  addGetStat("edns-ping-mismatches", &g_stats.ednsPingMismatches);
  addGetStat("dnssec-queries", &g_stats.dnssecQueries);

  addGetStat("dnssec-authentic-data-queries", &g_stats.dnssecAuthenticDataQueries);
  addGetStat("dnssec-check-disabled-queries", &g_stats.dnssecCheckDisabledQueries);

  addGetStat("variable-responses", &g_stats.variableResponses);

  addGetStat("noping-outqueries", &g_stats.noPingOutQueries);
  addGetStat("noedns-outqueries", &g_stats.noEdnsOutQueries);

  addGetStat("uptime", calculateUptime);
  addGetStat("real-memory-usage", []{ return getRealMemoryUsage(string()); });
  addGetStat("special-memory-usage", []{ return getSpecialMemoryUsage(string()); });
  addGetStat("fd-usage", []{ return getOpenFileDescriptors(string()); });

  //  addGetStat("query-rate", getQueryRate);
  addGetStat("user-msec", getUserTimeMsec);
  addGetStat("sys-msec", getSysTimeMsec);

#ifdef __linux__
  addGetStat("cpu-iowait", []{ return getCPUIOWait(string()); });
  addGetStat("cpu-steal", []{ return getCPUSteal(string()); });
#endif

  for (unsigned int n = 0; n < g_numThreads; ++n) {
    addGetStat("cpu-msec-thread-" + std::to_string(n), [n]{ return doGetThreadCPUMsec(n);});
  }

#ifdef MALLOC_TRACE
  addGetStat("memory-allocs", []{ return g_mtracer->getAllocs(string()); });
  addGetStat("memory-alloc-flux", []{ return g_mtracer->getAllocFlux(string()); });
  addGetStat("memory-allocated", []{ return g_mtracer->getTotAllocated(string()); });
#endif

  addGetStat("dnssec-validations", &g_stats.dnssecValidations);
  addGetStat("dnssec-result-insecure", &g_stats.dnssecResults[vState::Insecure]);
  addGetStat("dnssec-result-secure", &g_stats.dnssecResults[vState::Secure]);
  addGetStat("dnssec-result-bogus", []() {
    std::set<vState> const bogusStates = { vState::BogusNoValidDNSKEY, vState::BogusInvalidDenial, vState::BogusUnableToGetDSs, vState::BogusUnableToGetDNSKEYs, vState::BogusSelfSignedDS, vState::BogusNoRRSIG, vState::BogusNoValidRRSIG, vState::BogusMissingNegativeIndication, vState::BogusSignatureNotYetValid, vState::BogusSignatureExpired, vState::BogusUnsupportedDNSKEYAlgo, vState::BogusUnsupportedDSDigestType, vState::BogusNoZoneKeyBitSet, vState::BogusRevokedDNSKEY, vState::BogusInvalidDNSKEYProtocol };
    uint64_t total = 0;
    for (const auto& state : bogusStates) {
      total += g_stats.dnssecResults[state];
    }
    return total;
  });

  addGetStat("dnssec-result-bogus-no-valid-dnskey", &g_stats.dnssecResults[vState::BogusNoValidDNSKEY]);
  addGetStat("dnssec-result-bogus-invalid-denial", &g_stats.dnssecResults[vState::BogusInvalidDenial]);
  addGetStat("dnssec-result-bogus-unable-to-get-dss", &g_stats.dnssecResults[vState::BogusUnableToGetDSs]);
  addGetStat("dnssec-result-bogus-unable-to-get-dnskeys", &g_stats.dnssecResults[vState::BogusUnableToGetDNSKEYs]);
  addGetStat("dnssec-result-bogus-self-signed-ds", &g_stats.dnssecResults[vState::BogusSelfSignedDS]);
  addGetStat("dnssec-result-bogus-no-rrsig", &g_stats.dnssecResults[vState::BogusNoRRSIG]);
  addGetStat("dnssec-result-bogus-no-valid-rrsig", &g_stats.dnssecResults[vState::BogusNoValidRRSIG]);
  addGetStat("dnssec-result-bogus-missing-negative-indication", &g_stats.dnssecResults[vState::BogusMissingNegativeIndication]);
  addGetStat("dnssec-result-bogus-signature-not-yet-valid", &g_stats.dnssecResults[vState::BogusSignatureNotYetValid]);
  addGetStat("dnssec-result-bogus-signature-expired", &g_stats.dnssecResults[vState::BogusSignatureExpired]);
  addGetStat("dnssec-result-bogus-unsupported-dnskey-algo", &g_stats.dnssecResults[vState::BogusUnsupportedDNSKEYAlgo]);
  addGetStat("dnssec-result-bogus-unsupported-ds-digest-type", &g_stats.dnssecResults[vState::BogusUnsupportedDSDigestType]);
  addGetStat("dnssec-result-bogus-no-zone-key-bit-set", &g_stats.dnssecResults[vState::BogusNoZoneKeyBitSet]);
  addGetStat("dnssec-result-bogus-revoked-dnskey", &g_stats.dnssecResults[vState::BogusRevokedDNSKEY]);
  addGetStat("dnssec-result-bogus-invalid-dnskey-protocol", &g_stats.dnssecResults[vState::BogusInvalidDNSKEYProtocol]);
  addGetStat("dnssec-result-indeterminate", &g_stats.dnssecResults[vState::Indeterminate]);
  addGetStat("dnssec-result-nta", &g_stats.dnssecResults[vState::NTA]);

  if (::arg()["x-dnssec-names"].length() > 0) {
    addGetStat("x-dnssec-result-bogus", []() {
      std::set<vState> const bogusStates = { vState::BogusNoValidDNSKEY, vState::BogusInvalidDenial, vState::BogusUnableToGetDSs, vState::BogusUnableToGetDNSKEYs, vState::BogusSelfSignedDS, vState::BogusNoRRSIG, vState::BogusNoValidRRSIG, vState::BogusMissingNegativeIndication, vState::BogusSignatureNotYetValid, vState::BogusSignatureExpired, vState::BogusUnsupportedDNSKEYAlgo, vState::BogusUnsupportedDSDigestType, vState::BogusNoZoneKeyBitSet, vState::BogusRevokedDNSKEY, vState::BogusInvalidDNSKEYProtocol };
      uint64_t total = 0;
      for (const auto& state : bogusStates) {
        total += g_stats.xdnssecResults[state];
      }
      return total;
    });
    addGetStat("x-dnssec-result-bogus-no-valid-dnskey", &g_stats.xdnssecResults[vState::BogusNoValidDNSKEY]);
    addGetStat("x-dnssec-result-bogus-invalid-denial", &g_stats.xdnssecResults[vState::BogusInvalidDenial]);
    addGetStat("x-dnssec-result-bogus-unable-to-get-dss", &g_stats.xdnssecResults[vState::BogusUnableToGetDSs]);
    addGetStat("x-dnssec-result-bogus-unable-to-get-dnskeys", &g_stats.xdnssecResults[vState::BogusUnableToGetDNSKEYs]);
    addGetStat("x-dnssec-result-bogus-self-signed-ds", &g_stats.xdnssecResults[vState::BogusSelfSignedDS]);
    addGetStat("x-dnssec-result-bogus-no-rrsig", &g_stats.xdnssecResults[vState::BogusNoRRSIG]);
    addGetStat("x-dnssec-result-bogus-no-valid-rrsig", &g_stats.xdnssecResults[vState::BogusNoValidRRSIG]);
    addGetStat("x-dnssec-result-bogus-missing-negative-indication", &g_stats.xdnssecResults[vState::BogusMissingNegativeIndication]);
    addGetStat("x-dnssec-result-bogus-signature-not-yet-valid", &g_stats.xdnssecResults[vState::BogusSignatureNotYetValid]);
    addGetStat("x-dnssec-result-bogus-signature-expired", &g_stats.xdnssecResults[vState::BogusSignatureExpired]);
    addGetStat("x-dnssec-result-bogus-unsupported-dnskey-algo", &g_stats.xdnssecResults[vState::BogusUnsupportedDNSKEYAlgo]);
    addGetStat("x-dnssec-result-bogus-unsupported-ds-digest-type", &g_stats.xdnssecResults[vState::BogusUnsupportedDSDigestType]);
    addGetStat("x-dnssec-result-bogus-no-zone-key-bit-set", &g_stats.xdnssecResults[vState::BogusNoZoneKeyBitSet]);
    addGetStat("x-dnssec-result-bogus-revoked-dnskey", &g_stats.xdnssecResults[vState::BogusRevokedDNSKEY]);
    addGetStat("x-dnssec-result-bogus-invalid-dnskey-protocol", &g_stats.xdnssecResults[vState::BogusInvalidDNSKEYProtocol]);
    addGetStat("x-dnssec-result-indeterminate", &g_stats.xdnssecResults[vState::Indeterminate]);
    addGetStat("x-dnssec-result-nta", &g_stats.xdnssecResults[vState::NTA]);
    addGetStat("x-dnssec-result-insecure", &g_stats.xdnssecResults[vState::Insecure]);
    addGetStat("x-dnssec-result-secure", &g_stats.xdnssecResults[vState::Secure]);
  }

  addGetStat("policy-result-noaction", &g_stats.policyResults[DNSFilterEngine::PolicyKind::NoAction]);
  addGetStat("policy-result-drop", &g_stats.policyResults[DNSFilterEngine::PolicyKind::Drop]);
  addGetStat("policy-result-nxdomain", &g_stats.policyResults[DNSFilterEngine::PolicyKind::NXDOMAIN]);
  addGetStat("policy-result-nodata", &g_stats.policyResults[DNSFilterEngine::PolicyKind::NODATA]);
  addGetStat("policy-result-truncate", &g_stats.policyResults[DNSFilterEngine::PolicyKind::Truncate]);
  addGetStat("policy-result-custom", &g_stats.policyResults[DNSFilterEngine::PolicyKind::Custom]);

  addGetStat("rebalanced-queries", &g_stats.rebalancedQueries);

  addGetStat("proxy-protocol-invalid", &g_stats.proxyProtocolInvalidCount);

  addGetStat("nod-lookups-dropped-oversize", &g_stats.nodLookupsDroppedOversize);

  addGetStat("taskqueue-pushed",  []() { return getTaskPushes(); });
  addGetStat("taskqueue-expired",  []() { return getTaskExpired(); });
  addGetStat("taskqueue-size",  []() { return getTaskSize(); });

  addGetStat("dns64-prefix-answers",  &g_stats.dns64prefixanswers);

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

  addGetStat("cumul-answers", []() {
    return toStatsMap(g_stats.cumulativeAnswers.getName(), g_stats.cumulativeAnswers);
  });
  addGetStat("cumul-auth4answers", []() {
    return toStatsMap(g_stats.cumulativeAuth4Answers.getName(), g_stats.cumulativeAuth4Answers);
  });
  addGetStat("cumul-auth6answers", []() {
    return toStatsMap(g_stats.cumulativeAuth6Answers.getName(), g_stats.cumulativeAuth6Answers);
  });
}

void registerAllStats()
{
  static std::once_flag s_once;
  std::call_once(s_once, []() { try {
        registerAllStats1();
      }
      catch (...) {
        g_log << Logger::Critical << "Could not add stat entries" << endl;
        exit(1);
      }
  });
}

void doExitGeneric(bool nicely)
{
  g_log<<Logger::Error<<"Exiting on user request"<<endl;
  extern RecursorControlChannel s_rcc;
  s_rcc.~RecursorControlChannel();

  extern string s_pidfname;
  if(!s_pidfname.empty())
    unlink(s_pidfname.c_str()); // we can at least try..
  if(nicely) {
    RecursorControlChannel::stop = true;
  } else {
    _exit(1);
  }
}

void doExit()
{
  doExitGeneric(false);
}

void doExitNicely()
{
  doExitGeneric(true);
}

vector<pair<DNSName, uint16_t> >* pleaseGetQueryRing()
{
  typedef pair<DNSName,uint16_t> query_t;
  vector<query_t >* ret = new vector<query_t>();
  if(!t_queryring)
    return ret;
  ret->reserve(t_queryring->size());

  for(const query_t& q :  *t_queryring) {
    ret->push_back(q);
  }
  return ret;
}
vector<pair<DNSName,uint16_t> >* pleaseGetServfailQueryRing()
{
  typedef pair<DNSName,uint16_t> query_t;
  vector<query_t>* ret = new vector<query_t>();
  if(!t_servfailqueryring)
    return ret;
  ret->reserve(t_servfailqueryring->size());
  for(const query_t& q :  *t_servfailqueryring) {
    ret->push_back(q);
  }
  return ret;
}
vector<pair<DNSName,uint16_t> >* pleaseGetBogusQueryRing()
{
  typedef pair<DNSName,uint16_t> query_t;
  vector<query_t>* ret = new vector<query_t>();
  if(!t_bogusqueryring)
    return ret;
  ret->reserve(t_bogusqueryring->size());
  for(const query_t& q :  *t_bogusqueryring) {
    ret->push_back(q);
  }
  return ret;
}



typedef boost::function<vector<ComboAddress>*()> pleaseremotefunc_t;
typedef boost::function<vector<pair<DNSName,uint16_t> >*()> pleasequeryfunc_t;

vector<ComboAddress>* pleaseGetRemotes()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if(!t_remotes)
    return ret;

  ret->reserve(t_remotes->size());
  for(const ComboAddress& ca :  *t_remotes) {
    ret->push_back(ca);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetServfailRemotes()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if(!t_servfailremotes)
    return ret;
  ret->reserve(t_servfailremotes->size());
  for(const ComboAddress& ca :  *t_servfailremotes) {
    ret->push_back(ca);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetBogusRemotes()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if(!t_bogusremotes)
    return ret;
  ret->reserve(t_bogusremotes->size());
  for(const ComboAddress& ca :  *t_bogusremotes) {
    ret->push_back(ca);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetLargeAnswerRemotes()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if(!t_largeanswerremotes)
    return ret;
  ret->reserve(t_largeanswerremotes->size());
  for(const ComboAddress& ca :  *t_largeanswerremotes) {
    ret->push_back(ca);
  }
  return ret;
}

vector<ComboAddress>* pleaseGetTimeouts()
{
  vector<ComboAddress>* ret = new vector<ComboAddress>();
  if(!t_timeouts)
    return ret;
  ret->reserve(t_timeouts->size());
  for(const ComboAddress& ca :  *t_timeouts) {
    ret->push_back(ca);
  }
  return ret;
}

static string doGenericTopRemotes(pleaseremotefunc_t func)
{
  typedef map<ComboAddress, int, ComboAddress::addressOnlyLessThan> counts_t;
  counts_t counts;

  vector<ComboAddress> remotes=broadcastAccFunction<vector<ComboAddress> >(func);
    
  unsigned int total=0;
  for(const ComboAddress& ca :  remotes) {
    total++;
    counts[ca]++;
  }
  
  typedef std::multimap<int, ComboAddress> rcounts_t;
  rcounts_t rcounts;
  
  for(counts_t::const_iterator i=counts.begin(); i != counts.end(); ++i)
    rcounts.insert(make_pair(-i->second, i->first));

  ostringstream ret;
  ret<<"Over last "<<total<<" entries:\n";
  boost::format fmt("%.02f%%\t%s\n");
  int limit=0, accounted=0;
  if(total) {
    for(rcounts_t::const_iterator i=rcounts.begin(); i != rcounts.end() && limit < 20; ++i, ++limit) {
      ret<< fmt % (-100.0*i->first/total) % i->second.toString();
      accounted+= -i->first;
    }
    ret<< '\n' << fmt % (100.0*(total-accounted)/total) % "rest";
  }
  return ret.str();
}

// XXX DNSName Pain - this function should benefit from native DNSName methods
DNSName getRegisteredName(const DNSName& dom)
{
  auto parts=dom.getRawLabels();
  if(parts.size()<=2)
    return dom;
  reverse(parts.begin(), parts.end());
  for(string& str :  parts) { str=toLower(str); };

  // uk co migweb 
  string last;
  while(!parts.empty()) {
    if(parts.size()==1 || binary_search(g_pubs.begin(), g_pubs.end(), parts)) {
  
      string ret=last;
      if(!ret.empty())
	ret+=".";
      
      for(auto p = parts.crbegin(); p != parts.crend(); ++p) {
	ret+=(*p)+".";
      }
      return DNSName(ret);
    }

    last=parts[parts.size()-1];
    parts.resize(parts.size()-1);
  }
  return DNSName("??");
}

static DNSName nopFilter(const DNSName& name)
{
  return name;
}

static string doGenericTopQueries(pleasequeryfunc_t func, boost::function<DNSName(const DNSName&)> filter=nopFilter)
{
  typedef pair<DNSName,uint16_t> query_t;
  typedef map<query_t, int> counts_t;
  counts_t counts;
  vector<query_t> queries=broadcastAccFunction<vector<query_t> >(func);
    
  unsigned int total=0;
  for(const query_t& q :  queries) {
    total++;
    counts[make_pair(filter(q.first),q.second)]++;
  }

  typedef std::multimap<int, query_t> rcounts_t;
  rcounts_t rcounts;
  
  for(counts_t::const_iterator i=counts.begin(); i != counts.end(); ++i)
    rcounts.insert(make_pair(-i->second, i->first));

  ostringstream ret;
  ret<<"Over last "<<total<<" entries:\n";
  boost::format fmt("%.02f%%\t%s\n");
  int limit=0, accounted=0;
  if(total) {
    for(rcounts_t::const_iterator i=rcounts.begin(); i != rcounts.end() && limit < 20; ++i, ++limit) {
      ret<< fmt % (-100.0*i->first/total) % (i->second.first.toLogString()+"|"+DNSRecordContent::NumberToType(i->second.second));
      accounted+= -i->first;
    }
    ret<< '\n' << fmt % (100.0*(total-accounted)/total) % "rest";
  }

  
  return ret.str();
}

static string* nopFunction()
{
  return new string("pong\n");
}

static string getDontThrottleNames() {
  auto dtn = g_dontThrottleNames.getLocal();
  return dtn->toString() + "\n";
}

static string getDontThrottleNetmasks() {
  auto dtn = g_dontThrottleNetmasks.getLocal();
  return dtn->toString() + "\n";
}

template<typename T>
static string addDontThrottleNames(T begin, T end) {
  if (begin == end) {
    return "No names specified, keeping existing list\n";
  }
  vector<DNSName> toAdd;
  while (begin != end) {
    try {
      auto d = DNSName(*begin);
      toAdd.push_back(d);
    }
    catch(const std::exception &e) {
      return "Problem parsing '" + *begin + "': "+ e.what() + ", nothing added\n";
    }
    begin++;
  }

  string ret = "Added";
  auto dnt = g_dontThrottleNames.getCopy();
  bool first = true;
  for (auto const &d : toAdd) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + d.toLogString();
    dnt.add(d);
  }

  g_dontThrottleNames.setState(std::move(dnt));

  ret += " to the list of nameservers that may not be throttled";
  g_log<<Logger::Info<<ret<<", requested via control channel"<<endl;
  return ret + "\n";
}

template<typename T>
static string addDontThrottleNetmasks(T begin, T end) {
  if (begin == end) {
    return "No netmasks specified, keeping existing list\n";
  }
  vector<Netmask> toAdd;
  while (begin != end) {
    try {
      auto n = Netmask(*begin);
      toAdd.push_back(n);
    }
    catch(const std::exception &e) {
      return "Problem parsing '" + *begin + "': "+ e.what() + ", nothing added\n";
    }
    catch(const PDNSException &e) {
      return "Problem parsing '" + *begin + "': "+ e.reason + ", nothing added\n";
    }
    begin++;
  }

  string ret = "Added";
  auto dnt = g_dontThrottleNetmasks.getCopy();
  bool first = true;
  for (auto const &t : toAdd) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + t.toString();
    dnt.addMask(t);
  }

  g_dontThrottleNetmasks.setState(std::move(dnt));

  ret += " to the list of nameserver netmasks that may not be throttled";
  g_log<<Logger::Info<<ret<<", requested via control channel"<<endl;
  return ret + "\n";
}

template<typename T>
static string clearDontThrottleNames(T begin, T end) {
  if(begin == end)
    return "No names specified, doing nothing.\n";

  if (begin + 1 == end && *begin == "*"){
    SuffixMatchNode smn;
    g_dontThrottleNames.setState(std::move(smn));
    string ret = "Cleared list of nameserver names that may not be throttled";
    g_log<<Logger::Warning<<ret<<", requested via control channel"<<endl;
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
    catch (const std::exception &e) {
      return "Problem parsing '" + *begin + "': "+ e.what() + ", nothing removed\n";
    }
    begin++;
  }

  string ret = "Removed";
  bool first = true;
  auto dnt = g_dontThrottleNames.getCopy();
  for (const auto &name : toRemove) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + name.toLogString();
    dnt.remove(name);
  }

  g_dontThrottleNames.setState(std::move(dnt));

  ret += " from the list of nameservers that may not be throttled";
  g_log<<Logger::Info<<ret<<", requested via control channel"<<endl;
  return ret + "\n";
}

template<typename T>
static string clearDontThrottleNetmasks(T begin, T end) {
  if(begin == end)
    return "No netmasks specified, doing nothing.\n";

  if (begin + 1 == end && *begin == "*"){
    auto nmg = g_dontThrottleNetmasks.getCopy();
    nmg.clear();
    g_dontThrottleNetmasks.setState(std::move(nmg));

    string ret = "Cleared list of nameserver addresses that may not be throttled";
    g_log<<Logger::Warning<<ret<<", requested via control channel"<<endl;
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
    catch(const std::exception &e) {
      return "Problem parsing '" + *begin + "': "+ e.what() + ", nothing added\n";
    }
    catch(const PDNSException &e) {
      return "Problem parsing '" + *begin + "': "+ e.reason + ", nothing added\n";
    }
    begin++;
  }

  string ret = "Removed";
  bool first = true;
  auto dnt = g_dontThrottleNetmasks.getCopy();
  for (const auto &mask : toRemove) {
    if (!first) {
      ret += ",";
    }
    first = false;
    ret += " " + mask.toString();
    dnt.deleteMask(mask);
  }

  g_dontThrottleNetmasks.setState(std::move(dnt));

  ret += " from the list of nameservers that may not be throttled";
  g_log<<Logger::Info<<ret<<", requested via control channel"<<endl;
  return ret + "\n";
}


RecursorControlChannel::Answer RecursorControlParser::getAnswer(int s, const string& question, RecursorControlParser::func_t** command)
{
  *command=nop;
  vector<string> words;
  stringtok(words, question);

  if(words.empty())
    return {1, "invalid command\n"};

  string cmd=toLower(words[0]);
  vector<string>::const_iterator begin=words.begin()+1, end=words.end();

  // should probably have a smart dispatcher here, like auth has
  if(cmd=="help")
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
"dump-cache <filename>            dump cache contents to the named file\n"
"dump-edns [status] <filename>    dump EDNS status to the named file\n"
"dump-failedservers <filename>    dump the failed servers to the named file\n"
"dump-non-resolving <filename>    dump non-resolving nameservers addresses to the named file\n"
"dump-nsspeeds <filename>         dump nsspeeds statistics to the named file\n"
"dump-rpz <zone name> <filename>  dump the content of a RPZ zone to the named file\n"
"dump-throttlemap <filename>      dump the contents of the throttle map to the named file\n"
"get [key1] [key2] ..             get specific statistics\n"
"get-all                          get all statistics\n"
"get-dont-throttle-names          get the list of names that are not allowed to be throttled\n"
"get-dont-throttle-netmasks       get the list of netmasks that are not allowed to be throttled\n"
"get-ntas                         get all configured Negative Trust Anchors\n"
"get-tas                          get all configured Trust Anchors\n"
"get-parameter [key1] [key2] ..   get configuration parameters\n"
"get-qtypelist                    get QType statistics\n"
"                                 notice: queries from cache aren't being counted yet\n"
"help                             get this list\n"
"ping                             check that all threads are alive\n"
"quit                             stop the recursor daemon\n"
"quit-nicely                      stop the recursor daemon nicely\n"
"reload-acls                      reload ACLS\n"
"reload-lua-script [filename]     (re)load Lua script\n"
"reload-lua-config [filename]     (re)load Lua configuration file\n"
"reload-zones                     reload all auth and forward zones\n"
"set-ecs-minimum-ttl value        set ecs-minimum-ttl-override\n"
"set-max-cache-entries value      set new maximum cache size\n"
"set-max-packetcache-entries val  set new maximum packet cache size\n"      
"set-minimum-ttl value            set minimum-ttl-override\n"
"set-carbon-server                set a carbon server for telemetry\n"
"set-dnssec-log-bogus SETTING     enable (SETTING=yes) or disable (SETTING=no) logging of DNSSEC validation failures\n"
"trace-regex [regex]              emit resolution trace for matching queries (empty regex to clear trace)\n"
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
"version                          return Recursor version number\n"
"wipe-cache domain0 [domain1] ..  wipe domain data from cache\n"
"wipe-cache-typed type domain0 [domain1] ..  wipe domain data with qtype from cache\n"};

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
    *command=&doExit;
    return {0, "bye\n"};
  }
  if (cmd == "version") {
    return {0, getPDNSVersion()+"\n"};
  }
  if (cmd == "quit-nicely") {
    *command=&doExitNicely;
    return {0, "bye nicely\n"};
  }
  if (cmd == "dump-cache") {
    return doDumpCache(s);
  }
  if (cmd == "dump-ednsstatus" || cmd == "dump-edns") {
    return doDumpToFile(s, pleaseDumpEDNSMap, cmd);
  }
  if (cmd == "dump-nsspeeds") {
    return doDumpToFile(s, pleaseDumpNSSpeeds, cmd);
  }
  if (cmd == "dump-failedservers") {
    return doDumpToFile(s, pleaseDumpFailedServers, cmd);
  }
  if (cmd == "dump-rpz") {
    return doDumpRPZ(s, begin, end);
  }
  if (cmd == "dump-throttlemap") {
    return doDumpToFile(s, pleaseDumpThrottleMap, cmd);
  }
  if (cmd == "dump-non-resolving") {
    return doDumpToFile(s, pleaseDumpNonResolvingNS, cmd);
  }
  if (cmd == "wipe-cache" || cmd == "flushname") {
    return {0, doWipeCache(begin, end, 0xffff)};
  }
  if (cmd == "wipe-cache-typed") {
    uint16_t qtype = QType::chartocode(begin->c_str());
    ++begin;
    return {0, doWipeCache(begin, end, qtype)};
  }
  if (cmd == "reload-lua-script") {
    return doQueueReloadLuaScript(begin, end);
  }
  if (cmd == "reload-lua-config") {
    if (begin != end)
      ::arg().set("lua-config-file") = *begin;

    try {
      luaConfigDelayedThreads delayedLuaThreads;
      loadRecursorLuaConfig(::arg()["lua-config-file"], delayedLuaThreads);
      startLuaConfigDelayedThreads(delayedLuaThreads, g_luaconfs.getCopy().generation);
      g_log<<Logger::Warning<<"Reloaded Lua configuration file '"<<::arg()["lua-config-file"]<<"', requested via control channel"<<endl;
      return {0, "Reloaded Lua configuration file '"+::arg()["lua-config-file"]+"'\n"};
    }
    catch(std::exception& e) {
      return {1, "Unable to load Lua script from '"+::arg()["lua-config-file"]+"': "+e.what()+"\n"};
    }
    catch(const PDNSException& e) {
      return {1, "Unable to load Lua script from '"+::arg()["lua-config-file"]+"': "+e.reason+"\n"};
    }
  }
  if (cmd == "set-carbon-server") {
    return {0, doSetCarbonServer(begin, end)};
  }
  if (cmd == "trace-regex") {
    return {0, doTraceRegex(begin, end)};
  }
  if (cmd == "unload-lua-script") {
    vector<string> empty;
    empty.push_back(string());
    return doQueueReloadLuaScript(empty.begin(), empty.end());
  }
  if (cmd == "reload-acls") {
    if (!::arg()["chroot"].empty()) {
      g_log<<Logger::Error<<"Unable to reload ACL when chroot()'ed, requested via control channel"<<endl;
      return {1, "Unable to reload ACL when chroot()'ed, please restart\n"};
    }

    try {
      parseACLs();
    }
    catch(std::exception& e) {
      g_log<<Logger::Error<<"Reloading ACLs failed (Exception: "<<e.what()<<")"<<endl;
      return {1, e.what() + string("\n")};
    }
    catch(PDNSException& ae) {
      g_log<<Logger::Error<<"Reloading ACLs failed (PDNSException: "<<ae.reason<<")"<<endl;
      return {1, ae.reason + string("\n")};
    }
    return {0, "ok\n"};
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
      g_log<<Logger::Error<<"Unable to reload zones and forwards when chroot()'ed, requested via control channel"<<endl;
      return {1, "Unable to reload zones and forwards when chroot()'ed, please restart\n"};
    }
    return {0, reloadAuthAndForwards()};
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
    return {0, g_rs.getQTypeReport()};
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

  return {1, "Unknown command '"+cmd+"', try 'help'\n"};
}
