/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2009  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifndef MTASKER_HH
#define MTASKER_HH

#include <signal.h>
#include <ucontext.h>
#include <queue>
#include <vector>
#include <map>
#include <time.h>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include "namespaces.hh"
using namespace ::boost::multi_index;

struct KeyTag {};

//! The main MTasker class    
/** The main MTasker class. See the main page for more information.
    \param EventKey Type of the key with which events are to be identified. Defaults to int.
    \param EventVal Type of the content or value of an event. Defaults to int. Cannot be set to void.
    \note The EventKey needs to have an operator< defined because it is used as the key of an associative array
*/
template<class EventKey=int, class EventVal=int> class MTasker
{
private:
  ucontext_t d_kernel;     
  std::queue<int> d_runQueue;
  std::queue<int> d_zombiesQueue;

  struct ThreadInfo
  {
	ucontext_t* context;
	char* startOfStack;
	char* highestStackSeen;
  };

  typedef std::map<int, ThreadInfo> mthreads_t;
  mthreads_t d_threads;
  int d_tid;
  int d_maxtid;
  size_t d_stacksize;

  EventVal d_waitval;
  enum waitstatusenum {Error=-1,TimeOut=0,Answer} d_waitstatus;

public:
  struct Waiter
  {
    EventKey key;
    ucontext_t *context;
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

  //! Constructor
  /** Constructor with a small default stacksize. If any of your threads exceeds this stack, your application will crash. 
      This limit applies solely to the stack, the heap is not limited in any way. If threads need to allocate a lot of data,
      the use of new/delete is suggested. 
   */
  MTasker(size_t stacksize=8192) : d_stacksize(stacksize)
  {
    d_maxtid=0;
  }

  typedef void tfunc_t(void *); //!< type of the pointer that starts a thread 
  int waitEvent(EventKey &key, EventVal *val=0, unsigned int timeoutMsec=0, struct timeval* now=0);
  void yield();
  int sendEvent(const EventKey& key, const EventVal* val=0);
  void getEvents(std::vector<EventKey>& events);
  void makeThread(tfunc_t *start, void* val);
  bool schedule(struct timeval* now=0);
  bool noProcesses();
  unsigned int numProcesses();
  int getTid(); 
  unsigned int getMaxStackUsage();

private:
  static void threadWrapper(uint32_t self1, uint32_t self2, tfunc_t *tf, int tid, uint32_t val1, uint32_t val2);
  EventKey d_eventkey;   // for waitEvent, contains exact key it was awoken for
};
#include "mtasker.cc"

#endif // MTASKER_HH

