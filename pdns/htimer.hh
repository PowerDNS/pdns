#ifndef PDNS_HTIMER_HH
#define PDNS_HTIMER_HH
#include <stdint.h>
#include <boost/shared_ptr.hpp>
#include <boost/utility.hpp>
#include <map>

class HTimerSentinel;
// typedef boost::shared_ptr<HTimerSentinelImp> HTimerSentinel;

class HTimer : public boost::noncopyable
{
public:
  HTimer(){};
  explicit HTimer(const std::string& name);
  ~HTimer();
  void start();
  void stop();
  uint64_t getAccumulated() const;
  uint64_t getAccumulatedReset();

  HTimerSentinel getSentinel();
  static void listAll();

private:
  typedef std::map<std::string, HTimer*> timers_t;
  static timers_t s_timers;
  uint64_t d_accumulated;
  uint64_t d_started;
};

class HTimerSentinel
{
public:
  explicit HTimerSentinel(class HTimer* parent) : d_parent(parent)
  {
    d_rc=1;
    d_parent->start();
  }

  HTimerSentinel(const HTimerSentinel& orig)
  {
    d_parent = orig.d_parent;
    orig.d_rc++;
  }

  ~HTimerSentinel()
  {
    if(!--d_rc)
      d_parent->stop();
  }

private:
  HTimerSentinel& operator=(const HTimerSentinel& rhs);
  HTimer* d_parent;

  mutable unsigned int d_rc;
};

class HTimerSentinelImp : public boost::noncopyable
{
public:
  explicit HTimerSentinelImp(class HTimer* parent) : d_parent(parent)
  {
    d_parent->start();
  }

  ~HTimerSentinelImp()
  {
    d_parent->stop();
  }

private:
  HTimer* d_parent;
};

#endif
