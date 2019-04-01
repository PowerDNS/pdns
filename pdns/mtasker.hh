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
#ifndef MTASKER_HH
#define MTASKER_HH
#include <stdint.h>
#include <queue>
#include <vector>
#include <map>
#include <time.h>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include "namespaces.hh"
#include "misc.hh"
#include "mtasker_context.hh"
#include <memory>
#include <boost/function.hpp>
using namespace ::boost::multi_index;

// #define MTASKERTIMING 1

struct KeyTag {};

//! The main MTasker class    
/** The main MTasker class. See the main page for more information.
    \tparam EventKey Type of the key with which events are to be identified. Defaults to int.
    \tparam EventVal Type of the content or value of an event. Defaults to int. Cannot be set to void.
    \note The EventKey needs to have an operator< defined because it is used as the key of an associative array
*/

template<class EventKey=int, class EventVal=int> class MTasker
{
private:
  pdns_ucontext_t d_kernel;
  std::queue<int> d_runQueue;
  std::queue<int> d_zombiesQueue;

  struct ThreadInfo
  {
	std::shared_ptr<pdns_ucontext_t> context;
	boost::function<void(void)> start;
	char* startOfStack;
	char* highestStackSeen;
#ifdef MTASKERTIMING
    	CPUTime dt;
	unsigned int totTime;
#endif
  };

  typedef std::map<int, ThreadInfo> mthreads_t;
  mthreads_t d_threads;
  size_t d_stacksize;
  size_t d_threadsCount;
  int d_tid;
  int d_maxtid;

  EventVal d_waitval;
  enum waitstatusenum {Error=-1,TimeOut=0,Answer} d_waitstatus;

public:
  struct Waiter
  {
    EventKey key;
    std::shared_ptr<pdns_ucontext_t> context;
    struct timeval ttd;
    int tid;    
  };

  typedef multi_index_container<
    Waiter,
    indexed_by <
                ordered_unique<member<Waiter,EventKey,&Waiter::key> >,
                ordered_non_unique<tag<KeyTag>, member<Waiter,struct timeval,&Waiter::ttd> >
               >
  > waiters_t;

  waiters_t d_waiters;

  void initMainStackBounds()
  {
#ifdef HAVE_FIBER_SANITIZER
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_getattr_np(pthread_self(), &attr);
    pthread_attr_getstack(&attr, &t_mainStack, &t_mainStackSize);
    pthread_attr_destroy(&attr);
#endif /* HAVE_FIBER_SANITIZER */
  }

  //! Constructor
  /** Constructor with a small default stacksize. If any of your threads exceeds this stack, your application will crash. 
      This limit applies solely to the stack, the heap is not limited in any way. If threads need to allocate a lot of data,
      the use of new/delete is suggested. 
   */
  MTasker(size_t stacksize=16*8192) : d_stacksize(stacksize), d_threadsCount(0), d_tid(0), d_maxtid(0), d_waitstatus(Error)
  {
    initMainStackBounds();

    // make sure our stack is 16-byte aligned to make all the architectures happy
    d_stacksize = d_stacksize >> 4 << 4;
  }

  typedef void tfunc_t(void *); //!< type of the pointer that starts a thread 
  int waitEvent(EventKey &key, EventVal *val=0, unsigned int timeoutMsec=0, struct timeval* now=0);
  void yield();
  int sendEvent(const EventKey& key, const EventVal* val=0);
  void getEvents(std::vector<EventKey>& events);
  void makeThread(tfunc_t *start, void* val);
  bool schedule(struct timeval* now=0);
  bool noProcesses() const;
  unsigned int numProcesses() const;
  int getTid() const;
  unsigned int getMaxStackUsage();
  unsigned int getUsec();

private:
  EventKey d_eventkey;   // for waitEvent, contains exact key it was awoken for
};
#include "mtasker.cc"

#endif // MTASKER_HH

