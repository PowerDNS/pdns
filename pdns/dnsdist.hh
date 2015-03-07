#pragma once
#include "ext/luawrapper/include/LuaContext.hpp"
#include <time.h>
#include "misc.hh"
#include "iputils.hh"
#include "dnsname.hh"
#include <atomic>
#include <boost/circular_buffer.hpp>
#include <boost/program_options.hpp>
#include <mutex>
#include <thread>

template<typename T> class GlobalStateHolder;

template<typename T>
class LocalStateHolder
{
public:
  explicit LocalStateHolder(GlobalStateHolder<T>* source) : d_source(source)
  {}

  const T* operator->()
  {
    if(d_source->getGeneration() != d_generation) {
      d_source->getState(&d_state, & d_generation);
    }

    return d_state.get();
  }

  void reset()
  {
    d_generation=0;
    d_state.reset();
  }
private:
  std::shared_ptr<T> d_state;
  unsigned int d_generation;
  const GlobalStateHolder<T>* d_source;
};

template<typename T>
class GlobalStateHolder
{
public:
  GlobalStateHolder(){}
  LocalStateHolder<T> getLocal()
  {
    return LocalStateHolder<T>(this);
  }
  void setState(std::shared_ptr<T> state)
  {
    std::lock_guard<std::mutex> l(d_lock);
    d_state = state;
    d_generation++;
  }
  unsigned int getGeneration() const
  {
    return d_generation;
  }
  void getState(std::shared_ptr<T>* state, unsigned int* generation) const
  {
    std::lock_guard<std::mutex> l(d_lock);
    *state=d_state;
    *generation = d_generation;
  }
  std::shared_ptr<T> getCopy() const
  {
    std::lock_guard<std::mutex> l(d_lock);
    if(!d_state)
      return std::make_shared<T>();
    shared_ptr<T> ret = shared_ptr<T>(new T(*d_state));
    return d_state;
  }
private:
  mutable std::mutex d_lock;
  std::shared_ptr<T> d_state;
  std::atomic<unsigned int> d_generation{0};
};

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

  bool check()
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
  double d_tokens;
  StopWatch d_prev;
  unsigned int d_passed{0};
  unsigned int d_blocked{0};
};


struct IDState
{
  IDState() : origFD(-1) {}
  IDState(const IDState& orig)
  {
    origFD = orig.origFD;
    origID = orig.origID;
    origRemote = orig.origRemote;
    age.store(orig.age.load());
  }

  int origFD;  // set to <0 to indicate this state is empty   // 4

  ComboAddress origRemote;                                    // 28
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

extern Rings  g_rings;

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
typedef std::function<shared_ptr<DownstreamState>(const servers_t& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh)> policy_t;


struct ServerPolicy
{
  string name;
  policy_t policy;
};

void* responderThread(std::shared_ptr<DownstreamState> state);
extern std::mutex g_luamutex;
extern LuaContext g_lua;
extern ServerPolicy g_policy;
extern servers_t g_dstates;
extern std::string g_outputBuffer;
extern std::vector<ComboAddress> g_locals;
struct dnsheader;
std::shared_ptr<DownstreamState> firstAvailable(const servers_t& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh);
std::shared_ptr<DownstreamState> leastOutstanding(const servers_t& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh);
std::shared_ptr<DownstreamState> wrandom(const servers_t& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh);
std::shared_ptr<DownstreamState> roundrobin(const servers_t& servers, const ComboAddress& remote, const DNSName& qname, uint16_t qtype, dnsheader* dh);
extern vector<pair<boost::variant<SuffixMatchNode,NetmaskGroup>, QPSLimiter> > g_limiters;
extern vector<pair<boost::variant<SuffixMatchNode,NetmaskGroup>, std::string> > g_poolrules;
extern SuffixMatchNode g_suffixMatchNodeFilter;

extern ComboAddress g_serverControl;
void controlThread(int fd, ComboAddress local);
extern GlobalStateHolder<NetmaskGroup> g_ACL;

vector<std::function<void(void)>> setupLua(bool client);
extern std::string g_key;
namespace po = boost::program_options;
extern po::variables_map g_vm;
