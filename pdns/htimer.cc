#include <stdexcept>
#include "htimer.hh"
#include <iostream>

HTimer::timers_t HTimer::s_timers;

using namespace std;
#include "namespaces.hh"


/* idea: nested timers, where the hierarchy of nesting is constructed at runtime. Each timer can have multiple
   positions in the hierarchy, and might conceivable nest within itself.

   Desired result:

   Processing incoming questions
      Rest
      Parsing question
        Rest
        MOADNSParser
      Searching cache
      Processing Server Answers
        Rest
	MOADNSParser
      Waiting for packets

   Parsing question
     Rest
     MOADDNSParser

   Processing Server Answers
     Rest
     MOADNSParser

   Waiting for packets
*/

  



#define RDTSC(qp) \
do { \
  unsigned long lowPart, highPart;					\
  __asm__ __volatile__("rdtsc" : "=a" (lowPart), "=d" (highPart)); \
    qp = (((unsigned long long) highPart) << 32) | lowPart; \
} while (0)

HTimer::HTimer(const std::string& name) : d_accumulated(0), d_started(0)
{
  s_timers[name]=this;
}

HTimer::~HTimer()
{
  for(timers_t::iterator iter = s_timers.begin(); iter != s_timers.end() ; ++iter) {
    if(iter->second == this) {
      s_timers.erase(iter);
      break;
    }
  }  
}

void HTimer::start()
{
  if(d_started)
    throw runtime_error("HTimer restarted!");
  RDTSC(d_started);
}

void HTimer::stop()
{
  if(!d_started)
    throw runtime_error("HTimer stopped that wasn't started!");
  uint64_t stopped;
  RDTSC(stopped);

  d_accumulated += stopped - d_started;
  d_started=0;
}

uint64_t HTimer::getAccumulated() const
{
  uint64_t accumulated = d_accumulated;
  if(d_started) {
    uint64_t midterm;
    RDTSC(midterm);

    accumulated += midterm - d_started;
  }
  return accumulated;
}

uint64_t HTimer::getAccumulatedReset() 
{
  uint64_t accumulated = d_accumulated;
  if(d_started) {
    uint64_t midterm;
    RDTSC(midterm);

    accumulated += midterm - d_started;
    d_started=midterm;
  }
  d_accumulated=0;
  return accumulated;
}


HTimerSentinel HTimer::getSentinel()
{
  return HTimerSentinel(this);
}

void HTimer::listAll()
{
  for(timers_t::iterator iter = s_timers.begin(); iter != s_timers.end() ; ++iter) {
    cerr << iter->first <<": " << iter->second->getAccumulatedReset()/3000.0 <<"usec\n";
  }
}

#if 0
int main()
{
  char *q = new char;
  delete q;

  HTimer htmain("main");
  htmain.start();

  HTimer htloop("loop");
  {
    HTimerSentinel hts=htloop.getSentinel();
    for(int i=0; i < 1000; ++i)
    {
      shared_ptr<char> p(shared_ptr<char>(new char));
    }
  }

  htloop.listAll();

  cerr<<"accumulated: "<< htmain.getAccumulated() <<endl;
  cerr<<"accumulated: "<< htloop.getAccumulated() <<endl;
}
#endif
