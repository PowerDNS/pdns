#include "utility.hh"
#include "rec_channel.hh"
#include <boost/lexical_cast.hpp>
#include <boost/bind.hpp>
#include <vector>
#include "misc.hh"
#include "recursor_cache.hh"
#include "syncres.hh"
#include <boost/function.hpp>
#include <boost/optional.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/format.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/foreach.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "logger.hh"
#include "dnsparser.hh"
#include "arguments.hh"
#ifndef WIN32
#include <sys/resource.h>
#include <sys/time.h>
#endif

using namespace std;
#include "namespaces.hh"
map<string, const uint32_t*> d_get32bitpointers;
map<string, const uint64_t*> d_get64bitpointers;
map<string, function< uint32_t() > >  d_get32bitmembers;

void addGetStat(const string& name, const uint32_t* place)
{
  d_get32bitpointers[name]=place;
}
void addGetStat(const string& name, const uint64_t* place)
{
  d_get64bitpointers[name]=place;
}
void addGetStat(const string& name, function<uint32_t ()> f ) 
{
  d_get32bitmembers[name]=f;
}

optional<uint64_t> get(const string& name) 
{
  optional<uint64_t> ret;

  if(d_get32bitpointers.count(name))
    return *d_get32bitpointers.find(name)->second;
  if(d_get64bitpointers.count(name))
    return *d_get64bitpointers.find(name)->second;
  if(d_get32bitmembers.count(name))
    return d_get32bitmembers.find(name)->second();

  return ret;
}

string getAllStats()
{
  string ret;
  pair<string, const uint32_t*> the32bits;
  pair<string, const uint64_t*> the64bits;
  pair<string, function< uint32_t() > >  the32bitmembers;
  BOOST_FOREACH(the32bits, d_get32bitpointers) {
    ret += the32bits.first + "\t" + lexical_cast<string>(*the32bits.second) + "\n";
  }
  BOOST_FOREACH(the64bits, d_get64bitpointers) {
    ret += the64bits.first + "\t" + lexical_cast<string>(*the64bits.second) + "\n";
  }
  BOOST_FOREACH(the32bitmembers, d_get32bitmembers) {
    ret += the32bitmembers.first + "\t" + lexical_cast<string>(the32bitmembers.second()) + "\n";
  }
  return ret;
}

template<typename T>
string doGet(T begin, T end)
{
  string ret;

  for(T i=begin; i != end; ++i) {
    optional<uint64_t> num=get(*i);
    if(num)
      ret+=lexical_cast<string>(*num)+"\n";
    else
      ret+="UNKNOWN\n";
  }
  return ret;
}

template<typename T>
string doGetParameter(T begin, T end)
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


static uint64_t dumpNegCache(SyncRes::negcache_t& negcache, int fd)
{
  FILE* fp=fdopen(dup(fd), "w");
  if(!fp) { // dup probably failed
    return 0;
  }
  fprintf(fp, "; negcache dump from thread follows\n;\n");
  time_t now = time(0);
  
  typedef SyncRes::negcache_t::nth_index<1>::type sequence_t;
  sequence_t& sidx=negcache.get<1>();

  uint64_t count=0;
  BOOST_FOREACH(const NegCacheEntry& neg, sidx)
  {
    ++count;
    fprintf(fp, "%s IN %s %d VIA %s\n", neg.d_name.c_str(), neg.d_qtype.getName().c_str(), (unsigned int) (neg.d_ttd - now), neg.d_qname.c_str());
  }
  fclose(fp);
  return count;
}

static uint64_t* pleaseDump(int fd)
{
  return new uint64_t(t_RC->doDump(fd) + dumpNegCache(t_sstorage->negcache, fd));
}

template<typename T>
string doDumpCache(T begin, T end)
{
  T i=begin;
  string fname;

  if(i!=end) 
    fname=*i;

  int fd=open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
  if(fd < 0) 
    return "Error opening dump file for writing: "+string(strerror(errno))+"\n";
  uint64_t total = 0;
  try {
    total = broadcastAccFunction<uint64_t>(boost::bind(pleaseDump, fd));
  }
  catch(...){}
  
  close(fd);
  return "dumped "+lexical_cast<string>(total)+" records\n";
}

template<typename T>
string doDumpEDNSStatus(T begin, T end)
{
  T i=begin;
  string fname;

  if(i!=end) 
    fname=*i;

  int fd=open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0660);
  if(fd < 0) 
    return "Error opening dump file for writing: "+string(strerror(errno))+"\n";

  SyncRes::doEDNSDumpAndClose(fd);

  return "done\n";
}

uint64_t* pleaseWipeCache(const std::string& canon)
{
  return new uint64_t(t_RC->doWipeCache(canon));
}


static uint64_t* pleaseWipeAndCountNegCache(const std::string& canon)
{
  uint64_t res = t_sstorage->negcache.count(tie(canon));
  pair<SyncRes::negcache_t::iterator, SyncRes::negcache_t::iterator> range=t_sstorage->negcache.equal_range(tie(canon));
  t_sstorage->negcache.erase(range.first, range.second);
  return new uint64_t(res);
}

template<typename T>
string doWipeCache(T begin, T end)
{
  int count=0, countNeg=0;
  for(T i=begin; i != end; ++i) {
    string canon=toCanonic("", *i);
    count+= broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeCache, canon));
    countNeg+=broadcastAccFunction<uint64_t>(boost::bind(pleaseWipeAndCountNegCache, canon));
  }

  return "wiped "+lexical_cast<string>(count)+" records, "+lexical_cast<string>(countNeg)+" negative records\n";
}

#ifndef WIN32
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
#endif

static uint64_t calculateUptime()
{
  return time(0) - g_stats.startupTime;
}

static string* pleaseGetCurrentQueries()
{
  ostringstream ostr;

  ostr << MT->d_waiters.size() <<" currently outstanding questions\n";

  boost::format fmt("%1% %|40t|%2% %|47t|%3% %|63t|%4% %|68t|%5%\n");

  ostr << (fmt % "qname" % "qtype" % "remote" % "tcp" % "chained");
  int n=0;
  for(MT_t::waiters_t::iterator mthread=MT->d_waiters.begin(); mthread!=MT->d_waiters.end() && n < 100; ++mthread, ++n) {
    const PacketID& pident = mthread->key;
    ostr << (fmt 
             % pident.domain % DNSRecordContent::NumberToType(pident.type) 
             % pident.remote.toString() % (pident.sock ? 'Y' : 'n')
             % (pident.fd == -1 ? 'Y' : 'n')
             );
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
  return new uint64_t(t_sstorage->throttle.size());
}

static uint64_t getThrottleSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetThrottleSize);
}

uint64_t* pleaseGetNegCacheSize()
{
  uint64_t tmp=t_sstorage->negcache.size();
  return new uint64_t(tmp);
}

uint64_t getNegCacheSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetNegCacheSize);
}

uint64_t* pleaseGetNsSpeedsSize()
{
  return new uint64_t(t_sstorage->nsSpeeds.size());
}

uint64_t getNsSpeedsSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetNsSpeedsSize);
}

uint64_t* pleaseGetConcurrentQueries()
{
  return new uint64_t(MT->numProcesses()); 
}

static uint64_t getConcurrentQueries()
{
  return broadcastAccFunction<uint64_t>(pleaseGetConcurrentQueries);
}

uint64_t* pleaseGetCacheSize()
{
  return new uint64_t(t_RC->size());
}

uint64_t doGetCacheSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetCacheSize);
}

uint64_t* pleaseGetCacheHits()
{
  return new uint64_t(t_RC->cacheHits);
}

uint64_t doGetCacheHits()
{
  return broadcastAccFunction<uint64_t>(pleaseGetCacheHits);
}

uint64_t* pleaseGetCacheMisses()
{
  return new uint64_t(t_RC->cacheMisses);
}

uint64_t doGetCacheMisses()
{
  return broadcastAccFunction<uint64_t>(pleaseGetCacheMisses);
}




uint64_t* pleaseGetPacketCacheSize()
{
  return new uint64_t(t_packetCache->size());
}

uint64_t doGetPacketCacheSize()
{
  return broadcastAccFunction<uint64_t>(pleaseGetPacketCacheSize);
}

uint64_t* pleaseGetPacketCacheHits()
{
  return new uint64_t(t_packetCache->d_hits);
}

uint64_t doGetPacketCacheHits()
{
  return broadcastAccFunction<uint64_t>(pleaseGetPacketCacheHits);
}

uint64_t* pleaseGetPacketCacheMisses()
{
  return new uint64_t(t_packetCache->d_misses);
}

uint64_t doGetPacketCacheMisses()
{
  return broadcastAccFunction<uint64_t>(pleaseGetPacketCacheMisses);
}


RecursorControlParser::RecursorControlParser()
{
  addGetStat("questions", &g_stats.qcounter);
  addGetStat("tcp-questions", &g_stats.tcpqcounter);

  addGetStat("cache-hits", doGetCacheHits);
  addGetStat("cache-misses", doGetCacheMisses); 
  addGetStat("cache-entries", doGetCacheSize); 
  
  addGetStat("packetcache-hits", doGetPacketCacheHits);
  addGetStat("packetcache-misses", doGetPacketCacheMisses); 
  addGetStat("packetcache-entries", doGetPacketCacheSize); 
  
  
  
  addGetStat("servfail-answers", &g_stats.servFails);
  addGetStat("nxdomain-answers", &g_stats.nxDomains);
  addGetStat("noerror-answers", &g_stats.noErrors);

  addGetStat("unauthorized-udp", &g_stats.unauthorizedUDP);
  addGetStat("unauthorized-tcp", &g_stats.unauthorizedTCP);
  addGetStat("tcp-client-overflow", &g_stats.tcpClientOverflow);

  addGetStat("client-parse-errors", &g_stats.clientParseError);
  addGetStat("server-parse-errors", &g_stats.serverParseError);

  addGetStat("answers0-1", &g_stats.answers0_1);
  addGetStat("answers1-10", &g_stats.answers1_10);
  addGetStat("answers10-100", &g_stats.answers10_100);
  addGetStat("answers100-1000", &g_stats.answers100_1000);
  addGetStat("answers-slow", &g_stats.answersSlow);

  addGetStat("qa-latency", &g_stats.avgLatencyUsec);
  addGetStat("unexpected-packets", &g_stats.unexpectedCount);
  addGetStat("case-mismatches", &g_stats.caseMismatchCount);
  addGetStat("spoof-prevents", &g_stats.spoofCount);

  addGetStat("nsset-invalidations", &g_stats.nsSetInvalidations);

  addGetStat("resource-limits", &g_stats.resourceLimits);
  addGetStat("over-capacity-drops", &g_stats.overCapacityDrops);
  addGetStat("no-packet-error", &g_stats.noPacketError);
  addGetStat("dlg-only-drops", &SyncRes::s_nodelegated);
  
  addGetStat("negcache-entries", boost::bind(getNegCacheSize));
  addGetStat("throttle-entries", boost::bind(getThrottleSize)); 

  addGetStat("nsspeeds-entries", boost::bind(getNsSpeedsSize));

  addGetStat("concurrent-queries", boost::bind(getConcurrentQueries)); 
  addGetStat("outgoing-timeouts", &SyncRes::s_outgoingtimeouts);
  addGetStat("tcp-outqueries", &SyncRes::s_tcpoutqueries);
  addGetStat("all-outqueries", &SyncRes::s_outqueries);
  addGetStat("ipv6-outqueries", &g_stats.ipv6queries);
  addGetStat("throttled-outqueries", &SyncRes::s_throttledqueries);
  addGetStat("dont-outqueries", &SyncRes::s_dontqueries);
  addGetStat("throttled-out", &SyncRes::s_throttledqueries);
  addGetStat("unreachables", &SyncRes::s_unreachables);
  addGetStat("chain-resends", &g_stats.chainResends);
  addGetStat("tcp-clients", boost::bind(TCPConnection::getCurrentConnections));

  addGetStat("edns-ping-matches", &g_stats.ednsPingMatches);
  addGetStat("edns-ping-mismatches", &g_stats.ednsPingMismatches);

  addGetStat("noping-outqueries", &g_stats.noPingOutQueries);
  addGetStat("noedns-outqueries", &g_stats.noEdnsOutQueries);

  addGetStat("uptime", calculateUptime);

#ifndef WIN32
  //  addGetStat("query-rate", getQueryRate);
  addGetStat("user-msec", getUserTimeMsec);
  addGetStat("sys-msec", getSysTimeMsec);
#endif
}

static void doExitGeneric(bool nicely)
{
  L<<Logger::Error<<"Exiting on user request"<<endl;
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

static void doExit()
{
  doExitGeneric(false);
}

static void doExitNicely()
{
  doExitGeneric(true);
}

vector<ComboAddress>* pleaseGetRemotes()
{
  return new vector<ComboAddress>(t_remotes->remotes);
}

string doTopRemotes()
{
  typedef map<ComboAddress, int, ComboAddress::addressOnlyLessThan> counts_t;
  counts_t counts;

  vector<ComboAddress> remotes=broadcastAccFunction<vector<ComboAddress> >(pleaseGetRemotes);
    
  unsigned int total=0;
  for(RemoteKeeper::remotes_t::const_iterator i = remotes.begin(); i != remotes.end(); ++i)
    if(i->sin4.sin_family) {
      total++;
      counts[*i]++;
    }

  typedef multimap<int, ComboAddress> rcounts_t;
  rcounts_t rcounts;
  
  for(counts_t::const_iterator i=counts.begin(); i != counts.end(); ++i)
    rcounts.insert(make_pair(-i->second, i->first));

  ostringstream ret;
  ret<<"Over last "<<total<<" queries:\n";
  format fmt("%.02f%%\t%s\n");
  int limit=0;
  if(total)
    for(rcounts_t::const_iterator i=rcounts.begin(); i != rcounts.end() && limit < 20; ++i, ++limit)
      ret<< fmt % (-100.0*i->first/total) % i->second.toString();

  return ret.str();
}

static string* nopFunction()
{
  return new string("pong\n");
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
  
  if(cmd=="quit-nicely") {
    *command=&doExitNicely;
    return "bye nicely\n";
  }
  

  if(cmd=="dump-cache") 
    return doDumpCache(begin, end);

  if(cmd=="dump-ednsstatus" || cmd=="dump-edns") 
    return doDumpEDNSStatus(begin, end);


  if(cmd=="wipe-cache") 
    return doWipeCache(begin, end);

  if(cmd=="reload-lua-script") 
    return doQueueReloadLuaScript(begin, end);

  if(cmd=="unload-lua-script") {
    vector<string> empty;
    empty.push_back(string());
    return doQueueReloadLuaScript(empty.begin(), empty.end());
  }

  if(cmd=="reload-acls") {
    try {
      parseACLs();
    } 
    catch(exception& e) 
    {
      return e.what() + string("\n");
    }
    return "ok\n";
  }


  if(cmd=="top-remotes")
    return doTopRemotes();

  if(cmd=="current-queries")
    return doCurrentQueries();
  
  if(cmd=="ping") {
    return broadcastAccFunction<string>(nopFunction);
  }

  if(cmd=="reload-zones") {
    return reloadAuthAndForwards();
  }

  return "Unknown command '"+cmd+"'\n";
}
