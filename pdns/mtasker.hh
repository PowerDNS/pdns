/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef MTASKER_HH
#define MTASKER_HH
#include <signal.h>
#include <ucontext.h>
#include <queue>
#include <vector> 
#include <map>
#include <time.h>

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

  struct Waiter
  {
    ucontext_t *context;
    time_t ttd;
    int tid;
  };

  typedef std::map<EventKey,Waiter> waiters_t;
  waiters_t d_waiters;
  std::map<int,ucontext_t*> d_threads;
  int d_tid;
  int d_maxtid;
  size_t d_stacksize;

  EventVal d_waitval;
  enum {Error=-1,TimeOut=0,Answer} d_waitstatus;

public:
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
  int waitEvent(const EventKey &key, EventVal *val=0, unsigned int timeout=0);
  void yield();
  int sendEvent(const EventKey& key, const EventVal* val=0);
  void getEvents(std::vector<EventKey>& events);
  void makeThread(tfunc_t *start, void* val);
  bool schedule();
  bool noProcesses();
  int getTid(); 
private:
  static void threadWrapper(MTasker *self, tfunc_t *tf, int tid, void* val);
};
#include "mtasker.cc"
#endif
