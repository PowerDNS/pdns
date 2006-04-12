/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

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
#ifndef WIN32_MTASKER_HH
#define WIN32_MTASKER_HH

#define WINDOWS_LEAN_AND_MEAN
#include <windows.h>

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
  LPVOID d_kernel;     
  std::queue<int> d_runQueue;
  std::queue<int> d_zombiesQueue;

  struct Waiter
  {
    LPVOID context;
    time_t ttd;
    int tid;
  };

  typedef std::map<EventKey,Waiter> waiters_t;
  waiters_t d_waiters;
  std::map<int,LPVOID> d_threads;
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
    d_kernel=ConvertThreadToFiber( NULL );
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
  //! This structure holds some fiber data that is passed to the threadWrapper.
  struct ThreadParam
  {
    tfunc_t *tf; 
    MTasker *self; 
    int tid; 
    LPVOID val; 
  };
 
  static void WINAPI threadWrapper( LPVOID lpFiberParameter );
};

#include "win32_mtasker.cc"

#endif // WIN32_MTASKER_HH

