#pragma once
#include "ext/luawrapper/include/LuaContext.hpp"
#include <time.h>
#include "misc.hh"
#include "iputils.hh"
#include "dnsname.hh"
#include <atomic>
#include <boost/circular_buffer.hpp>
#include <mutex>
#include <thread>
#include "sholder.hh"


struct StopWatch
{
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif
  struct timespec d_start{0,0};
  void start() {  
    if(clock_gettime(CLOCK_MONOTONIC_RAW, &d_start) < 0)
      unixDie("Getting timestamp");
    
  }
  
  double udiff() const {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC_RAW, &now) < 0)
      unixDie("Getting timestamp");
    
    return 1000000.0*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec)/1000.0;
  }

  double udiffAndSet() {
    struct timespec now;
    if(clock_gettime(CLOCK_MONOTONIC_RAW, &now) < 0)
      unixDie("Getting timestamp");
    
    auto ret= 1000000.0*(now.tv_sec - d_start.tv_sec) + (now.tv_nsec - d_start.tv_nsec)/1000.0;
    d_start = now;
    return ret;
  }

};

class QPSLimiter
{
public:
  QPSLimiter()
  {
  }

  QPSLimiter(unsigned int rate, unsigned int burst) : d_rate(rate), d_burst(burst), d_tokens(burst)
  {
    d_passthrough=false;
    d_prev.start();
  }

  unsigned int getRate() const
  {
    return d_passthrough? 0 : d_rate;
  }

  int getPassed() const
  {
    return d_passed;
  }
  int getBlocked() const
  {
    return d_blocked;
  }

  bool check() const // this is not quite fair
  {
    if(d_passthrough)
      return true;
    auto delta = d_prev.udiffAndSet();
  
    d_tokens += 1.0*d_rate * (delta/1000000.0);

    if(d_tokens > d_burst)
      d_tokens = d_burst;

    bool ret=false;
    if(d_tokens >= 1.0) { // we need this because burst=1 is weird otherwise
      ret=true;
      --d_tokens;
      d_passed++;
    }
    else
      d_blocked++;

    return ret; 
  }
private:
  bool d_passthrough{true};
  unsigned int d_rate;
  unsigned int d_burst;
  mutable double d_tokens;
  mutable StopWatch d_prev;
  mutable unsigned int d_passed{0};
  mutable unsigned int d_blocked{0};
};


struct IDState
{
  IDState() : origFD(-1) { origDest.sin4.sin_family = 0;}
  IDState(const IDState& orig)
  {
    origFD = orig.origFD;
    origID = orig.origID;
    origRemote = orig.origRemote;
    origDest = orig.origDest;
    age.store(orig.age.load());
  }

  int origFD;  // set to <0 to indicate this state is empty   // 4

  ComboAddress origRemote;                                    // 28
  ComboAddress origDest;                                      // 28
  StopWatch sentTime;                                         // 16
  DNSName qname;                                              // 80
  std::atomic<uint16_t> age;                                  // 4
  uint16_t qtype;                                             // 2
  uint16_t origID;                                            // 2
};

struct Rings {
  Rings()
  {
    clientRing.set_capacity(10000);
    queryRing.set_capacity(10000);
    respRing.set_capacity(10000);
  }
  boost::circular_buffer<ComboAddress> clientRing;
  boost::circular_buffer<DNSName> queryRing;
  struct Response
  {
    DNSName name;
    uint16_t qtype;
    uint8_t rcode;
    unsigned int usec;
  };
  boost::circular_buffer<Response> respRing;
  std::mutex respMutex;
};

extern Rings g_rings; // XXX locking for this is still substandard, queryRing and clientRing need RW lock

struct DownstreamState
{
  DownstreamState(const ComboAddress& remote_);

  int fd;            
  std::thread tid;
  ComboAddress remote;
  QPSLimiter qps;
  vector<IDState> idStates;
  std::atomic<uint64_t> idOffset{0};
  std::atomic<uint64_t> sendErrors{0};
  std::atomic<uint64_t> outstanding{0};
  std::atomic<uint64_t> reuseds{0};
  std::atomic<uint64_t> queries{0};
  struct {
    std::atomic<uint64_t> sendErrors{0};
    std::atomic<uint64_t> reuseds{0};
    std::atomic<uint64_t> queries{0};
  } prev;
  double queryLoad{0.0};
  double dropRate{0.0};
  double latencyUsec{0.0};
  int order{1};
  int weight{1};
  StopWatch sw;
  set<string> pools;
  enum class Availability { Up, Down, Auto} availability{Availability::Auto};
  bool upStatus{false};
  bool isUp() const
  {
    if(availability == Availability::Down)
      return false;
    if(availability == Availability::Up)
      return true;
    return upStatus;
  }
  void setUp() { availability = Availability::Up; }
  void setDown() { availability = Availability::Down; }
  void setAuto() { availability = Availability::Auto; }
};
using servers_t =vector<std::shared_ptr<DownstreamState>>;

template <class T> using NumberedVector = std::vector<std::pair<unsigned int, T> >;

void* responderThread(std::shared_ptr<DownstreamState> state);
extern std::mutex g_luamutex;
extern LuaContext g_lua;
extern std::string g_outputBuffer; // locking for this is ok, as locked by g_luamutex

class DNSRule
{
public:
  virtual bool matches(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len) const =0;
  virtual string toString() const = 0;
  mutable std::atomic<uint64_t> d_matches{0};
};

/* so what could you do: 
   drop, 
   fake up nxdomain, 
   provide actual answer, 
   allow & and stop processing, 
   continue processing, 
   modify header:    (servfail|refused|notimp), set TC=1,
   send to pool */

class DNSAction
{
public:
  enum class Action { Drop, Nxdomain, Spoof, Allow, HeaderModify, Pool, None};
  virtual Action operator()(const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh, int len, string* ruleresult) const =0;
  virtual string toString() const = 0;
};

using NumberedServerVector = NumberedVector<shared_ptr<DownstreamState>>;
typedef std::function<shared_ptr<DownstreamState>(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)> policy_t;

struct ServerPolicy
{
  string name;
  policy_t policy;
};

extern GlobalStateHolder<ServerPolicy> g_policy;
extern GlobalStateHolder<servers_t> g_dstates;
extern GlobalStateHolder<vector<pair<std::shared_ptr<DNSRule>, std::shared_ptr<DNSAction> > > > g_rulactions;
extern GlobalStateHolder<NetmaskGroup> g_ACL;

extern ComboAddress g_serverControl; // not changed during runtime

extern std::vector<ComboAddress> g_locals; // not changed at runtime
extern std::string g_key; // in theory needs locking

struct dnsheader;

void controlThread(int fd, ComboAddress local);
vector<std::function<void(void)>> setupLua(bool client, const std::string& config);
NumberedServerVector getDownstreamCandidates(const servers_t& servers, const std::string& pool);

std::shared_ptr<DownstreamState> firstAvailable(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh);

std::shared_ptr<DownstreamState> leastOutstanding(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh);
std::shared_ptr<DownstreamState> wrandom(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh);
std::shared_ptr<DownstreamState> roundrobin(const NumberedServerVector& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh);
int getEDNSZ(const char* packet, unsigned int len);
template<typename T, typename... Args>
std::unique_ptr<T> make_unique(Args&&... args)
{
    return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}
