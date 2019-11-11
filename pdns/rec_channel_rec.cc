#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include "rec_channel.hh"
#include <boost/bind.hpp>
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

#include "validate-recursor.hh"
#include "filterpo.hh"

#include "secpoll-recursor.hh"
#include "pubsuffix.hh"
#include "namespaces.hh"
pthread_mutex_t g_carbon_config_lock=PTHREAD_MUTEX_INITIALIZER;

static map<string, const uint32_t*> d_get32bitpointers;
static map<string, const std::atomic<uint64_t>*> d_getatomics;
static map<string, function< uint64_t() > >  d_get64bitmembers;
static pthread_mutex_t d_dynmetricslock = PTHREAD_MUTEX_INITIALIZER;
static map<string, std::atomic<unsigned long>* > d_dynmetrics;

static std::map<StatComponent, std::set<std::string>> s_blacklistedStats;

bool isStatBlacklisted(StatComponent component, const string& name)
{
  return s_blacklistedStats[component].count(name) != 0;
}

void blacklistStat(StatComponent component, const string& name)
{
  s_blacklistedStats[component].insert(name);
}

void blacklistStats(StatComponent component, const string& stats)
{
  std::vector<std::string> blacklistedStats;
  stringtok(blacklistedStats, stats, ", ");
  auto& map = s_blacklistedStats[component];
  for (const auto &st : blacklistedStats) {
    map.insert(st);
  }
}

static void addGetStat(const string& name, const uint32_t* place)
{
  d_get32bitpointers[name]=place;
}

static void addGetStat(const string& name, const std::atomic<uint64_t>* place)
{
  d_getatomics[name]=place;
}

static void addGetStat(const string& name, function<uint64_t ()> f )
{
  d_get64bitmembers[name]=f;
}

std::atomic<unsigned long>* getDynMetric(const std::string& str)
{
  Lock l(&d_dynmetricslock);
  auto f = d_dynmetrics.find(str);
  if(f != d_dynmetrics.end())
    return f->second;

  auto ret = new std::atomic<unsigned long>();
  d_dynmetrics[str]= ret;
  return ret;
}

static optional<uint64_t> get(const string& name)
{
  optional<uint64_t> ret;

  if(d_get32bitpointers.count(name))
    return *d_get32bitpointers.find(name)->second;
  if(d_getatomics.count(name))
    return d_getatomics.find(name)->second->load();
  if(d_get64bitmembers.count(name))
    return d_get64bitmembers.find(name)->second();

  Lock l(&d_dynmetricslock);
  auto f =rplookup(d_dynmetrics, name);
  if(f)
    return (*f)->load();
  
  return ret;
}

optional<uint64_t> getStatByName(const std::string& name)
{
  return get(name);
}

map<string,string> getAllStatsMap(StatComponent component)
{
  map<string,string> ret;
  const auto& blacklistMap = s_blacklistedStats.at(component);

  for(const auto& the32bits :  d_get32bitpointers) {
    if (blacklistMap.count(the32bits.first) == 0) {
      ret.insert(make_pair(the32bits.first, std::to_string(*the32bits.second)));
    }
  }
  for(const auto& atomic :  d_getatomics) {
    if (blacklistMap.count(atomic.first) == 0) {
      ret.insert(make_pair(atomic.first, std::to_string(atomic.second->load())));
    }
  }

  for(const auto& the64bitmembers :  d_get64bitmembers) {
    if (blacklistMap.count(the64bitmembers.first) == 0) {
      ret.insert(make_pair(the64bitmembers.first, std::to_string(the64bitmembers.second())));
    }
  }

  {
    Lock l(&d_dynmetricslock);
    for(const auto& a : d_dynmetrics) {
      if (blacklistMap.count(a.first) == 0) {
        ret.insert({a.first, std::to_string(*a.second)});
      }
    }
  }

  return ret;
}

static string getAllStats()
{
  typedef map<string, string> varmap_t;
  varmap_t varmap = getAllStatsMap(StatComponent::RecControl);
  string ret;
  for(varmap_t::value_type& tup :  varmap) {
    ret += tup.first + "\t" + tup.second +"\n";
  }
  return ret;
}

template<typename T>
static string doGet(T begin, T end)
{
  string ret;

  for(T i=begin; i != end; ++i) {
    optional<uint64_t> num=get(*i);
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


static uint64_t dumpNegCache(NegCache& negcache, int fd)
{
  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(dup(fd), "w"), fclose);
  if(!fp) { // dup probably failed
    return 0;
  }
  uint64_t ret;
  fprintf(fp.get(), "; negcache dump from thread follows\n;\n");
  ret = negcache.dumpToFile(fp.get());
  return ret;
}

static uint64_t* pleaseDump(int fd)
{
  return new uint64_t(t_RC->doDump(fd) + dumpNegCache(SyncRes::t_sstorage.negcache, fd) + t_packetCache->doDump(fd));
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

template<typename T>
static string doDumpNSSpeeds(T begin, T end)
{
  T i=begin;
  string fname;

  if(i!=end)
    fname=*i;

  int fd=open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
  if(fd < 0)
    return "Error opening dump file for writing: "+stringerror()+"\n";
  uint64_t total = 0;
  try {
    total = broadcastAccFunction<uint64_t>(boost::bind(pleaseDumpNSSpeeds, fd));
  }
  catch(std::exception& e)
  {
    close(fd);
    return "error dumping NS speeds: "+string(e.what())+"\n";
  }
  catch(PDNSException& e)
  {
    close(fd);
    return "error dumping NS speeds: "+e.reason+"\n";
  }

  close(fd);
  return "dumped "+std::to_string(total)+" records\n";
}

template<typename T>
static string doDumpCache(T begin, T end)
{
  T i=begin;
  string fname;

  if(i!=end) 
    fname=*i;

  int fd=open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
  if(fd < 0) 
    return "Error opening dump file for writing: "+stringerror()+"\n";
  uint64_t total = 0;
  try {
    total = broadcastAccFunction<uint64_t>(boost::bind(pleaseDump, fd));
  }
  catch(...){}
  
  close(fd);
  return "dumped "+std::to_string(total)+" records\n";
}

template<typename T>
static string doDumpEDNSStatus(T begin, T end)
{
  T i=begin;
  string fname;

  if(i!=end) 
    fname=*i;

  int fd=open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
  if(fd < 0) 
    return "Error opening dump file for writing: "+stringerror()+"\n";
  uint64_t total = 0;
  try {
    total = broadcastAccFunction<uint64_t>(boost::bind(pleaseDumpEDNSMap, fd));
  }
  catch(...){}

  close(fd);
  return "dumped "+std::to_string(total)+" records\n";
}

template<typename T>
static string doDumpRPZ(T begin, T end)
{
  T i=begin;

  if (i == end) {
    return "No zone name specified\n";
  }
  string zoneName = *i;
  i++;

  if (i == end) {
    return "No file name specified\n";
  }
  string fname = *i;

  auto luaconf = g_luaconfs.getLocal();
  const auto zone = luaconf->dfe.getZone(zoneName);
  if (!zone) {
    return "No RPZ zone named "+zoneName+"\n";
  }

  int fd = open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);

  if(fd < 0) {
    return "Error opening dump file for writing: "+stringerror()+"\n";
  }

  auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fdopen(fd, "w"), fclose);
  if (!fp) {
    close(fd);
    return "Error converting file descriptor: "+stringerror()+"\n";
  }

  zone->dump(fp.get());

  return "done\n";
}

template<typename T>
static string doDumpThrottleMap(T begin, T end)
{
  T i=begin;
  string fname;

  if(i!=end)
    fname=*i;

  int fd=open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
  if(fd < 0)
    return "Error opening dump file for writing: "+stringerror()+"\n";
  uint64_t total = 0;
  try {
    total = broadcastAccFunction<uint64_t>(boost::bind(pleaseDumpThrottleMap, fd));
  }
  catch(...){}

  close(fd);
  return "dumped "+std::to_string(total)+" records\n";
}

uint64_t* pleaseWipeCache(const DNSName& canon, bool subtree)
{
  return new uint64_t(t_RC->doWipeCache(canon, subtree));
}

uint64_t* pleaseWipePacketCache(const DNSName& canon, bool subtree)
{
  return new uint64_t(t_packetCache->doWipePacketCache(canon,0xffff, subtree));
}


uint64_t* pleaseWipeAndCountNegCache(const DNSName& canon, bool subtree)
{
  uint64_t ret = SyncRes::wipeNegCache(canon, subtree);
  return new uint64_t(ret);
}


template<typename T>
static string doWipeCache(T begin, T end)
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
    count+= broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, wipe.first, wipe.second));
    pcount+= broadcastAccFunction<uint64_t>(boost::bind(pleaseWipePacketCache, wipe.first, wipe.second));
    countNeg+=broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, wipe.first, wipe.second));
  }

  return "wiped "+std::to_string(count)+" records, "+std::to_string(countNeg)+" negative records, "+std::to_string(pcount)+" packets\n";
}

template<typename T>
static string doSetCarbonServer(T begin, T end)
{
  Lock l(&g_carbon_config_lock);
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
  broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, who, true));
  broadcastAccFunction<uint64_t>(boost::bind(pleaseWipePacketCache, who, true));
  broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, who, true));
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
  for (auto const &entry : toRemove) {
    g_log<<Logger::Warning<<"Clearing Negative Trust Anchor for "<<entry<<", requested via control channel"<<endl;
    g_luaconfs.modify([entry](LuaConfigItems& lci) {
        lci.negAnchors.erase(entry);
      });
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, entry, true));
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipePacketCache, entry, true));
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, entry, true));
    if (!first) {
      first = false;
      removed += ",";
    }
    removed += " " + entry.toStringRootDot();
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
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, who, true));
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipePacketCache, who, true));
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, who, true));
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
  for (auto const &entry : toRemove) {
    g_log<<Logger::Warning<<"Removing Trust Anchor for "<<entry<<", requested via control channel"<<endl;
    g_luaconfs.modify([entry](LuaConfigItems& lci) {
        lci.dsAnchors.erase(entry);
      });
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, entry, true));
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipePacketCache, entry, true));
    broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, entry, true));
    if (!first) {
      first = false;
      removed += ",";
    }
    removed += " " + entry.toStringRootDot();
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
    const PacketID& pident = mthread.key;
    const double spent = g_networkTimeoutMsec - (DiffTime(now, mthread.ttd) * 1000);
    ostr << (fmt 
             % pident.domain.toLogString() /* ?? */ % DNSRecordContent::NumberToType(pident.type) 
             % pident.remote.toString() % (pident.sock ? 'Y' : 'n')
             % (pident.fd == -1 ? 'Y' : 'n')
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

uint64_t* pleaseGetNegCacheSize()
{
  uint64_t tmp=(SyncRes::getNegCacheSize());
  return new uint64_t(tmp);
}

static uint64_t getNegCacheSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetNegCacheSize);
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

uint64_t* pleaseGetConcurrentQueries()
{
  return new uint64_t(getMT() ? getMT()->numProcesses() : 0);
}

static uint64_t getConcurrentQueries()
{
  return broadcastAccFunction<uint64_t>(pleaseGetConcurrentQueries);
}

uint64_t* pleaseGetCacheSize()
{
  return new uint64_t(t_RC ? t_RC->size() : 0);
}

static uint64_t* pleaseGetCacheBytes()
{
  return new uint64_t(t_RC ? t_RC->bytes() : 0);
}

static uint64_t doGetCacheSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetCacheSize);
}

static uint64_t doGetAvgLatencyUsec()
{
  return (uint64_t) g_stats.avgLatencyUsec;
}

static uint64_t doGetCacheBytes()
{
  return broadcastAccFunction<uint64_t>(pleaseGetCacheBytes);
}

uint64_t* pleaseGetCacheHits()
{
  return new uint64_t(t_RC ? t_RC->cacheHits : 0);
}

static uint64_t doGetCacheHits()
{
  return broadcastAccFunction<uint64_t>(pleaseGetCacheHits);
}

uint64_t* pleaseGetCacheMisses()
{
  return new uint64_t(t_RC ? t_RC->cacheMisses : 0);
}

static uint64_t doGetCacheMisses()
{
  return broadcastAccFunction<uint64_t>(pleaseGetCacheMisses);
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

extern ResponseStats g_rs;

void registerAllStats()
{
  static std::atomic_flag s_init = ATOMIC_FLAG_INIT;
  if(s_init.test_and_set())
    return;

  addGetStat("questions", &g_stats.qcounter);
  addGetStat("ipv6-questions", &g_stats.ipv6qcounter);
  addGetStat("tcp-questions", &g_stats.tcpqcounter);

  addGetStat("cache-hits", doGetCacheHits);
  addGetStat("cache-misses", doGetCacheMisses); 
  addGetStat("cache-entries", doGetCacheSize);
  addGetStat("max-cache-entries", []() { return g_maxCacheEntries.load(); });
  addGetStat("max-packetcache-entries", []() { return g_maxPacketCacheEntries.load();}); 
  addGetStat("cache-bytes", doGetCacheBytes); 
  
  addGetStat("packetcache-hits", doGetPacketCacheHits);
  addGetStat("packetcache-misses", doGetPacketCacheMisses); 
  addGetStat("packetcache-entries", doGetPacketCacheSize); 
  addGetStat("packetcache-bytes", doGetPacketCacheBytes); 
  
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

  addGetStat("answers0-1", &g_stats.answers0_1);
  addGetStat("answers1-10", &g_stats.answers1_10);
  addGetStat("answers10-100", &g_stats.answers10_100);
  addGetStat("answers100-1000", &g_stats.answers100_1000);
  addGetStat("answers-slow", &g_stats.answersSlow);

  addGetStat("x-ourtime0-1", &g_stats.ourtime0_1);
  addGetStat("x-ourtime1-2", &g_stats.ourtime1_2);
  addGetStat("x-ourtime2-4", &g_stats.ourtime2_4);
  addGetStat("x-ourtime4-8", &g_stats.ourtime4_8);
  addGetStat("x-ourtime8-16", &g_stats.ourtime8_16);
  addGetStat("x-ourtime16-32", &g_stats.ourtime16_32);
  addGetStat("x-ourtime-slow", &g_stats.ourtimeSlow);

  addGetStat("auth4-answers0-1", &g_stats.auth4Answers0_1);
  addGetStat("auth4-answers1-10", &g_stats.auth4Answers1_10);
  addGetStat("auth4-answers10-100", &g_stats.auth4Answers10_100);
  addGetStat("auth4-answers100-1000", &g_stats.auth4Answers100_1000);
  addGetStat("auth4-answers-slow", &g_stats.auth4AnswersSlow);

  addGetStat("auth6-answers0-1", &g_stats.auth6Answers0_1);
  addGetStat("auth6-answers1-10", &g_stats.auth6Answers1_10);
  addGetStat("auth6-answers10-100", &g_stats.auth6Answers10_100);
  addGetStat("auth6-answers100-1000", &g_stats.auth6Answers100_1000);
  addGetStat("auth6-answers-slow", &g_stats.auth6AnswersSlow);


  addGetStat("qa-latency", doGetAvgLatencyUsec);
  addGetStat("x-our-latency", []() { return g_stats.avgLatencyOursUsec; });
  addGetStat("unexpected-packets", &g_stats.unexpectedCount);
  addGetStat("case-mismatches", &g_stats.caseMismatchCount);
  addGetStat("spoof-prevents", &g_stats.spoofCount);

  addGetStat("nsset-invalidations", &g_stats.nsSetInvalidations);

  addGetStat("resource-limits", &g_stats.resourceLimits);
  addGetStat("over-capacity-drops", &g_stats.overCapacityDrops);
  addGetStat("policy-drops", &g_stats.policyDrops);
  addGetStat("no-packet-error", &g_stats.noPacketError);
  addGetStat("dlg-only-drops", &SyncRes::s_nodelegated);
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
  addGetStat("all-outqueries", &SyncRes::s_outqueries);
  addGetStat("ipv6-outqueries", &g_stats.ipv6queries);
  addGetStat("throttled-outqueries", &SyncRes::s_throttledqueries);
  addGetStat("dont-outqueries", &SyncRes::s_dontqueries);
  addGetStat("throttled-out", &SyncRes::s_throttledqueries);
  addGetStat("unreachables", &SyncRes::s_unreachables);
  addGetStat("ecs-queries", &SyncRes::s_ecsqueries);
  addGetStat("ecs-responses", &SyncRes::s_ecsresponses);
  addGetStat("chain-resends", &g_stats.chainResends);
  addGetStat("tcp-clients", boost::bind(TCPConnection::getCurrentConnections));

#ifdef __linux__
  addGetStat("udp-recvbuf-errors", boost::bind(udpErrorStats, "udp-recvbuf-errors"));
  addGetStat("udp-sndbuf-errors", boost::bind(udpErrorStats, "udp-sndbuf-errors"));
  addGetStat("udp-noport-errors", boost::bind(udpErrorStats, "udp-noport-errors"));
  addGetStat("udp-in-errors", boost::bind(udpErrorStats, "udp-in-errors"));
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
  addGetStat("real-memory-usage", boost::bind(getRealMemoryUsage, string()));
  addGetStat("special-memory-usage", boost::bind(getSpecialMemoryUsage, string()));
  addGetStat("fd-usage", boost::bind(getOpenFileDescriptors, string()));

  //  addGetStat("query-rate", getQueryRate);
  addGetStat("user-msec", getUserTimeMsec);
  addGetStat("sys-msec", getSysTimeMsec);

  for(unsigned int n=0; n < g_numThreads; ++n)
    addGetStat("cpu-msec-thread-"+std::to_string(n), boost::bind(&doGetThreadCPUMsec, n));

#ifdef MALLOC_TRACE
  addGetStat("memory-allocs", boost::bind(&MallocTracer::getAllocs, g_mtracer, string()));
  addGetStat("memory-alloc-flux", boost::bind(&MallocTracer::getAllocFlux, g_mtracer, string()));
  addGetStat("memory-allocated", boost::bind(&MallocTracer::getTotAllocated, g_mtracer, string()));
#endif

  addGetStat("dnssec-validations", &g_stats.dnssecValidations);
  addGetStat("dnssec-result-insecure", &g_stats.dnssecResults[Insecure]);
  addGetStat("dnssec-result-secure", &g_stats.dnssecResults[Secure]);
  addGetStat("dnssec-result-bogus", &g_stats.dnssecResults[Bogus]);
  addGetStat("dnssec-result-indeterminate", &g_stats.dnssecResults[Indeterminate]);
  addGetStat("dnssec-result-nta", &g_stats.dnssecResults[NTA]);

  addGetStat("policy-result-noaction", &g_stats.policyResults[DNSFilterEngine::PolicyKind::NoAction]);
  addGetStat("policy-result-drop", &g_stats.policyResults[DNSFilterEngine::PolicyKind::Drop]);
  addGetStat("policy-result-nxdomain", &g_stats.policyResults[DNSFilterEngine::PolicyKind::NXDOMAIN]);
  addGetStat("policy-result-nodata", &g_stats.policyResults[DNSFilterEngine::PolicyKind::NODATA]);
  addGetStat("policy-result-truncate", &g_stats.policyResults[DNSFilterEngine::PolicyKind::Truncate]);
  addGetStat("policy-result-custom", &g_stats.policyResults[DNSFilterEngine::PolicyKind::Custom]);

  addGetStat("rebalanced-queries", &g_stats.rebalancedQueries);

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
}

void doExitGeneric(bool nicely)
{
  g_log<<Logger::Error<<"Exiting on user request"<<endl;
  extern RecursorControlChannel s_rcc;
  s_rcc.~RecursorControlChannel(); 

  extern string s_pidfname;
  if(!s_pidfname.empty()) 
    unlink(s_pidfname.c_str()); // we can at least try..
  if(nicely)
    exit(1);
  else
    _exit(1);
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

string doGenericTopRemotes(pleaseremotefunc_t func)
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
  format fmt("%.02f%%\t%s\n");
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

string doGenericTopQueries(pleasequeryfunc_t func, boost::function<DNSName(const DNSName&)> filter=nopFilter)
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
  format fmt("%.02f%%\t%s\n");
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

  g_dontThrottleNames.setState(dnt);

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

  g_dontThrottleNetmasks.setState(dnt);

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
    g_dontThrottleNames.setState(smn);
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

  g_dontThrottleNames.setState(dnt);

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
    g_dontThrottleNetmasks.setState(nmg);

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

  g_dontThrottleNetmasks.setState(dnt);

  ret += " from the list of nameservers that may not be throttled";
  g_log<<Logger::Info<<ret<<", requested via control channel"<<endl;
  return ret + "\n";
}


string RecursorControlParser::getAnswer(const string& question, RecursorControlParser::func_t** command)
{
  *command=nop;
  vector<string> words;
  stringtok(words, question);

  if(words.empty())
    return "invalid command\n";

  string cmd=toLower(words[0]);
  vector<string>::const_iterator begin=words.begin()+1, end=words.end();

  // should probably have a smart dispatcher here, like auth has
  if(cmd=="help")
    return
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
"dump-nsspeeds <filename>         dump nsspeeds statistics to the named file\n"
"dump-rpz <zone name> <filename>  dump the content of a RPZ zone to the named file\n"
"dump-throttlemap <filename>      dump the contents of the throttle to the named file\n"
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
"wipe-cache domain0 [domain1] ..  wipe domain data from cache\n";

  if(cmd=="get-all")
    return getAllStats();

  if(cmd=="get")
    return doGet(begin, end);

  if(cmd=="get-parameter")
    return doGetParameter(begin, end);

  if(cmd=="quit") {
    *command=&doExit;
    return "bye\n";
  }

  if(cmd=="version") {
    return getPDNSVersion()+"\n";
  }

  if(cmd=="quit-nicely") {
    *command=&doExitNicely;
    return "bye nicely\n";
  }

  if(cmd=="dump-cache")
    return doDumpCache(begin, end);

  if(cmd=="dump-ednsstatus" || cmd=="dump-edns")
    return doDumpEDNSStatus(begin, end);

  if(cmd=="dump-nsspeeds")
    return doDumpNSSpeeds(begin, end);

  if(cmd=="dump-rpz") {
    return doDumpRPZ(begin, end);
  }

  if(cmd=="dump-throttlemap")
   return doDumpThrottleMap(begin, end);

  if(cmd=="wipe-cache" || cmd=="flushname")
    return doWipeCache(begin, end);

  if(cmd=="reload-lua-script")
    return doQueueReloadLuaScript(begin, end);

  if(cmd=="reload-lua-config") {
    if(begin != end)
      ::arg().set("lua-config-file") = *begin;

    try {
      luaConfigDelayedThreads delayedLuaThreads;
      loadRecursorLuaConfig(::arg()["lua-config-file"], delayedLuaThreads);
      startLuaConfigDelayedThreads(delayedLuaThreads, g_luaconfs.getCopy().generation);
      g_log<<Logger::Warning<<"Reloaded Lua configuration file '"<<::arg()["lua-config-file"]<<"', requested via control channel"<<endl;
      return "Reloaded Lua configuration file '"+::arg()["lua-config-file"]+"'\n";
    }
    catch(std::exception& e) {
      return "Unable to load Lua script from '"+::arg()["lua-config-file"]+"': "+e.what()+"\n";
    }
    catch(const PDNSException& e) {
      return "Unable to load Lua script from '"+::arg()["lua-config-file"]+"': "+e.reason+"\n";
    }
  }

  if(cmd=="set-carbon-server")
    return doSetCarbonServer(begin, end);

  if(cmd=="trace-regex")
    return doTraceRegex(begin, end);

  if(cmd=="unload-lua-script") {
    vector<string> empty;
    empty.push_back(string());
    return doQueueReloadLuaScript(empty.begin(), empty.end());
  }

  if(cmd=="reload-acls") {
    if(!::arg()["chroot"].empty()) {
      g_log<<Logger::Error<<"Unable to reload ACL when chroot()'ed, requested via control channel"<<endl;
      return "Unable to reload ACL when chroot()'ed, please restart\n";
    }

    try {
      parseACLs();
    } 
    catch(std::exception& e) 
    {
      g_log<<Logger::Error<<"Reloading ACLs failed (Exception: "<<e.what()<<")"<<endl;
      return e.what() + string("\n");
    }
    catch(PDNSException& ae)
    {
      g_log<<Logger::Error<<"Reloading ACLs failed (PDNSException: "<<ae.reason<<")"<<endl;
      return ae.reason + string("\n");
    }
    return "ok\n";
  }


  if(cmd=="top-remotes")
    return doGenericTopRemotes(pleaseGetRemotes);

  if(cmd=="top-queries")
    return doGenericTopQueries(pleaseGetQueryRing);

  if(cmd=="top-pub-queries")
    return doGenericTopQueries(pleaseGetQueryRing, getRegisteredName);

  if(cmd=="top-servfail-queries")
    return doGenericTopQueries(pleaseGetServfailQueryRing);

  if(cmd=="top-pub-servfail-queries")
    return doGenericTopQueries(pleaseGetServfailQueryRing, getRegisteredName);

  if(cmd=="top-bogus-queries")
    return doGenericTopQueries(pleaseGetBogusQueryRing);

  if(cmd=="top-pub-bogus-queries")
    return doGenericTopQueries(pleaseGetBogusQueryRing, getRegisteredName);


  if(cmd=="top-servfail-remotes")
    return doGenericTopRemotes(pleaseGetServfailRemotes);

  if(cmd=="top-bogus-remotes")
    return doGenericTopRemotes(pleaseGetBogusRemotes);

  if(cmd=="top-largeanswer-remotes")
    return doGenericTopRemotes(pleaseGetLargeAnswerRemotes);

  if(cmd=="top-timeouts")
    return doGenericTopRemotes(pleaseGetTimeouts);


  if(cmd=="current-queries")
    return doCurrentQueries();
  
  if(cmd=="ping") {
    return broadcastAccFunction<string>(nopFunction);
  }

  if(cmd=="reload-zones") {
    if(!::arg()["chroot"].empty()) {
      g_log<<Logger::Error<<"Unable to reload zones and forwards when chroot()'ed, requested via control channel"<<endl;
      return "Unable to reload zones and forwards when chroot()'ed, please restart\n";
    }
    return reloadAuthAndForwards();
  }

  if(cmd=="set-ecs-minimum-ttl") {
    return setMinimumECSTTL(begin, end);
  }

  if(cmd=="set-max-cache-entries") {
    return setMaxCacheEntries(begin, end);
  }
  if(cmd=="set-max-packetcache-entries") {
    return setMaxPacketCacheEntries(begin, end);
  }
  
  if(cmd=="set-minimum-ttl") {
    return setMinimumTTL(begin, end);
  }
  
  if(cmd=="get-qtypelist") {
    return g_rs.getQTypeReport();
  }

  if(cmd=="add-nta") {
    return doAddNTA(begin, end);
  }

  if(cmd=="clear-nta") {
    return doClearNTA(begin, end);
  }

  if(cmd=="get-ntas") {
    return getNTAs();
  }

  if(cmd=="add-ta") {
    return doAddTA(begin, end);
  }

  if(cmd=="clear-ta") {
    return doClearTA(begin, end);
  }

  if(cmd=="get-tas") {
    return getTAs();
  }

  if (cmd=="set-dnssec-log-bogus")
    return doSetDnssecLogBogus(begin, end);

  if (cmd == "get-dont-throttle-names") {
    return getDontThrottleNames();
  }

  if (cmd == "get-dont-throttle-netmasks") {
    return getDontThrottleNetmasks();
  }

  if (cmd == "add-dont-throttle-names") {
    return addDontThrottleNames(begin, end);
  }

  if (cmd == "add-dont-throttle-netmasks") {
    return addDontThrottleNetmasks(begin, end);
  }

  if (cmd == "clear-dont-throttle-names") {
    return clearDontThrottleNames(begin, end);
  }

  if (cmd == "clear-dont-throttle-netmasks") {
    return clearDontThrottleNetmasks(begin, end);
  }

  return "Unknown command '"+cmd+"', try 'help'\n";
}
