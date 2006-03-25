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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

using namespace std;
using namespace boost;
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
string doDumpCache(T begin, T end)
{
  T i=begin;
  string fname;

  if(i!=end) 
    fname=*i;

  int fd=open(fname.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_LARGEFILE, 0660);
  if(fd < 0) 
    return "Error opening dump file for writing: "+string(strerror(errno))+"\n";

  RC.doDumpAndClose(fd); 

  return "done\n";
}

template<typename T>
string doWipeCache(T begin, T end)
{
  for(T i=begin; i != end; ++i)
    RC.doWipeCache(*i);

  return "done\n";
}


uint32_t getQueryRate()
{
  struct timeval now;
  gettimeofday(&now, 0);
  optional<float> delay=g_stats.queryrate.get(now, 10);
  if(delay)
    return 1000000/(*delay);
  else
    return 0;
}

RecursorControlParser::RecursorControlParser()
{
  extern uint64_t qcounter;
  addGetStat("questions", &qcounter);

  addGetStat("cache-hits", &RC.cacheHits);
  addGetStat("cache-misses", &RC.cacheMisses);

  addGetStat("cache-entries", bind(&MemRecursorCache::size, ref(RC)));
  addGetStat("servfail-answers", &g_stats.servFails);
  addGetStat("nxdomain-answers", &g_stats.nxDomains);
  addGetStat("noerror-answers", &g_stats.noErrors);

  addGetStat("answers0-1", &g_stats.answers0_1);
  addGetStat("answers1-10", &g_stats.answers1_10);
  addGetStat("answers10-100", &g_stats.answers10_100);
  addGetStat("answers100-1000", &g_stats.answers100_1000);
  addGetStat("answers-slow", &g_stats.answersSlow);

  addGetStat("qa-latency", &g_stats.avgLatencyUsec);

  addGetStat("all-questions", &qcounter);
  addGetStat("negcache-entries", bind(&SyncRes::negcache_t::size, ref(SyncRes::s_negcache)));
  addGetStat("throttle-entries", bind(&SyncRes::throttle_t::size, ref(SyncRes::s_throttle)));
  addGetStat("nsspeeds-entries", bind(&SyncRes::nsspeeds_t::size, ref(SyncRes::s_nsSpeeds)));

  addGetStat("concurrent-queries", bind(&MTasker<PacketID,string>::numProcesses, ref(MT)));
  addGetStat("outgoing-timeouts", &SyncRes::s_outgoingtimeouts);
  addGetStat("tcp-outqueries", &SyncRes::s_tcpoutqueries);
  addGetStat("all-outqueries", &SyncRes::s_outqueries);
  addGetStat("throttled-outqueries", &SyncRes::s_throttledqueries);
  addGetStat("throttled-out", &SyncRes::s_throttledqueries);

  addGetStat("query-rate", getQueryRate);
}

string RecursorControlParser::getAnswer(const string& question)
{
  vector<string> words;
  stringtok(words, question);

  if(words.empty())
    return "invalid command";

  string cmd=toLower(words[0]);
  vector<string>::const_iterator begin=words.begin()+1, end=words.end();

  if(words[0]=="get") 
    return doGet(begin, end);

  if(words[0]=="quit") 
    exit(1);

  if(words[0]=="dump-cache") 
    return doDumpCache(begin, end);

  if(words[0]=="wipe-cache") 
    return doWipeCache(begin, end);
  
  return "Unknown command '"+cmd+"'\n";

}
