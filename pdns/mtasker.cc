/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2006  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "mtasker.hh"
#include <stdio.h>
#include <iostream>

/** \page MTasker
    Simple system for implementing cooperative multitasking of functions, with 
    support for waiting on events which can return values.

    \section copyright Copyright and License
    MTasker is (c) 2002 - 2006 by bert hubert. It is licensed to you under the terms of the GPL version 2.

    \section overview High level overview
    MTasker is designed to support very simple cooperative multitasking to facilitate writing 
    code that would ordinarily require a statemachine, for which the author does not consider 
    himself smart enough.

    This class does not perform any magic it only makes calls to makecontext() and swapcontext(). 
    Getting the details right however is complicated and MTasker does that for you.

    If preemptive multitasking or more advanced concepts such as semaphores, locks or mutexes
    are required, the use of POSIX threads is advised.

    MTasker is designed to offer the performance of statemachines while maintaining simple thread semantics. It is not
    a replacement for a full threading system.

    \section compatability Compatability
    MTasker is only guaranteed to work on Linux with glibc 2.2.5 and higher. It does not work on FreeBSD and notably,
    not on Red Hat 6.0. It may work on Solaris, please test.

    \section concepts Concepts

    There are two important concepts, the 'kernel' and the 'thread'. Each thread starts out as a function,
    which is passed to MTasker::makeThread(), together with a possible argument.

    This function is now free to do whatever it wants, but realise that MTasker implements cooperative
    multitasking, which means that the coder has the responsiblilty of not taking the CPU overly long.
    Other threads can only get the CPU if MTasker::yield() is called or if a thread sleeps to wait for an event, 
    using the MTasker::waitEvent() method.

    \section kernel The Kernel
    The Kernel consists of functions that do housekeeping, but also of code that the client coder 
    can call to report events. A minimal kernel loop looks like this:
    \code
    for(;;) {
       MT.schedule();
       if(MT.noProcesses())  // exit if no processes are left
          break;
    }
    \endcode

    The kernel typically starts from the main() function of your program. New threads are also
    created from the kernel. This can also happen before entering the main loop. To start a thread,
    the method MTasker::makeThread is provided.

    \section events Events
    By default, Events are recognized by an int and their value is also an int.
    This can be overriden by specifying the EventKey and EventVal template parameters.
    
    An event can be a keypress, but also a UDP packet, or a bit of data from a TCP socket. The
    sample code provided works with keypresses, but that is just a not very useful example.

    A thread can also wait for an event only for a limited time, and receive a timeout of that 
    event did not occur within the specified timeframe.

    \section example A simple menu system
    \code
MTasker<> MT;

void menuHandler(void *p)
{
  int num=(int)p;
  cout<<"Key handler for key "<<num<<" launched"<<endl;
 
  MT.waitEvent(num);
  cout<<"Key "<<num<<" was pressed!"<<endl;
}


int main()
{
  char line[10];

  for(int i=0;i<10;++i) 
    MT.makeThread(menuHandler,(void *)i);
  
  for(;;) {
    while(MT.schedule()); // do everything we can do
    if(MT.noProcesses())  // exit if no processes are left
      break;

    if(!fgets(line,sizeof(line),stdin))
      break;
    
    MT.sendEvent(*line-'0');
  }
}
\endcode

\section example2 Canonical multitasking example
This implements the canonical multitasking example, alternately printing an 'A' and a 'B'. The Linux kernel
  started this way too.
\code
void printer(void *p)
{
  char c=(char)p;
  for(;;) {
    cout<<c<<endl;
    MT.yield();
  }

}

int main()
{
  MT.makeThread(printer,(void*)'a');
  MT.makeThread(printer,(void*)'b');

  for(;;) {
    while(MT.schedule()); // do everything we can do
    if(MT.noProcesses())  // exit if no processes are left
      break;
  }
}
\endcode

*/

//! puts a thread to sleep waiting until a specified event arrives
/** Threads can call waitEvent to register that they are waiting on an event with a certain key.
    If so desidered, the event can carry data which is returned in val in case that is non-zero.
    
    Furthermore, a timeout can be specified in seconds.
    
    Only one thread can be waiting on a key, results of trying to have more threads
    waiting on the same key are undefined.
    
    \param key Event key to wait for. Needs to match up to a key reported to sendEvent
    \param val If non-zero, the value of the event will be stored in *val
    \param timeout If non-zero, number of seconds to wait for an event.
    
    \return returns -1 in case of error, 0 in case of timeout, 1 in case of an answer 
*/

template<class EventKey, class EventVal>int MTasker<EventKey,EventVal>::waitEvent(EventKey &key, EventVal *val, unsigned int timeout, unsigned int now)
{
  if(d_waiters.count(key)) { // there was already an exact same waiter
    return -1;
  }

  Waiter w;
  w.context=new ucontext_t;
  w.ttd=0;
  if(timeout)
    w.ttd= timeout + (now ? now : time(0));

  w.tid=d_tid;
  
  w.key=key;

  d_waiters.insert(w);
  
  if(swapcontext(d_waiters.find(key)->context,&d_kernel)) { // 'A' will return here when 'key' has arrived, hands over control to kernel first
    perror("swapcontext");
    exit(EXIT_FAILURE); // no way we can deal with this 
  }
  if(val && d_waitstatus==Answer) 
    *val=d_waitval;
  d_tid=w.tid;
  key=d_eventkey;
  return d_waitstatus;
}

//! yields control to the kernel or other threads
/** Hands over control to the kernel, allowing other processes to run, or events to arrive */

template<class Key, class Val>void MTasker<Key,Val>::yield()
{
  d_runQueue.push(d_tid);
  if(swapcontext(d_threads[d_tid] ,&d_kernel) < 0) { // give control to the kernel
    perror("swapcontext in  yield");
    exit(EXIT_FAILURE);
  }
}

//! reports that an event took place for which threads may be waiting
/** From the kernel loop, sendEvent can be called to report that something occured for which there may be waiters.
    \param key Key of the event for which threads may be waiting
    \param val If non-zero, pointer to the content of the event
    \return Returns -1 in case of error, 0 if there were no waiters, 1 if a thread was woken up.

    WARNING: when passing val as zero, d_waitval is undefined, and hence waitEvent will return undefined!
*/
template<class EventKey, class EventVal>int MTasker<EventKey,EventVal>::sendEvent(const EventKey& key, const EventVal* val)
{
  typename waiters_t::iterator waiter=d_waiters.find(key);

  if(waiter == d_waiters.end()) {
    //    cout<<"Event sent nobody was waiting for!"<<endl;
    return 0;
  }
  
  d_waitstatus=Answer;
  if(val)
    d_waitval=*val;
  
  ucontext_t *userspace=waiter->context;
  d_tid=waiter->tid;         // set tid 
  d_eventkey=waiter->key;        // pass waitEvent the exact key it was woken for
  d_waiters.erase(waiter);             // removes the waitpoint 
  if(swapcontext(&d_kernel,userspace)) { // swaps back to the above point 'A'
    perror("swapcontext in sendEvent");
    exit(EXIT_FAILURE);
  }
  delete userspace;
  return 1;
}

//! launches a new thread
/** The kernel can call this to make a new thread, which starts at the function start and gets passed the val void pointer.
    \param start Pointer to the function which will form the start of the thread
    \param val A void pointer that can be used to pass data to the thread
*/
template<class Key, class Val>void MTasker<Key,Val>::makeThread(tfunc_t *start, void* val)
{
  ucontext_t *uc=new ucontext_t;
  getcontext(uc);
  
  uc->uc_link = &d_kernel; // come back to kernel after dying
  uc->uc_stack.ss_sp = new char[d_stacksize];
  
  uc->uc_stack.ss_size = d_stacksize;
#ifdef SOLARIS8
  uc->uc_stack.ss_sp = (void*)(((char*)uc->uc_stack.ss_sp)+d_stacksize);
  makecontext (uc,(void (*)(...))threadWrapper, 5, this, start, d_maxtid, val);
#else
  makecontext (uc, (void (*)(void))threadWrapper, 4, this, start, d_maxtid, val);
#endif
  d_threads[d_maxtid]=uc;
  d_runQueue.push(d_maxtid++); // will run at next schedule invocation
}


//! needs to be called periodically so threads can run and housekeeping can be performed
/** The kernel should call this function every once in a while. It makes sense
    to call this function if you:
    - reported an event
    - called makeThread
    - want to have threads running waitEvent() to get a timeout if enough time passed 
    
    \return Returns if there is more work scheduled and recalling schedule now would be useful
      
*/
template<class Key, class Val>bool MTasker<Key,Val>::schedule(unsigned int now)
{
  if(!d_runQueue.empty()) {
    d_tid=d_runQueue.front();
    if(swapcontext(&d_kernel, d_threads[d_tid])) {
      perror("swapcontext in schedule");
      exit(EXIT_FAILURE);
    }
      
    d_runQueue.pop();
    return true;
  }
  if(!d_zombiesQueue.empty()) {
#ifdef SOLARIS8
    delete[] (((char *)d_threads[d_zombiesQueue.front()]->uc_stack.ss_sp)-d_stacksize);
#else
    delete[] (char *)d_threads[d_zombiesQueue.front()]->uc_stack.ss_sp;
#endif
    delete d_threads[d_zombiesQueue.front()];
    d_threads.erase(d_zombiesQueue.front());
    d_zombiesQueue.pop();
    return true;
  }
  if(!d_waiters.empty()) {
    if(!now)
      now=time(0);

    typedef typename waiters_t::template index<KeyTag>::type waiters_by_ttd_index_t;
    //    waiters_by_ttd_index_t& ttdindex=d_waiters.template get<KeyTag>();
    waiters_by_ttd_index_t& ttdindex=boost::multi_index::get<KeyTag>(d_waiters);

    for(typename waiters_by_ttd_index_t::iterator i=ttdindex.begin(); i != ttdindex.end(); ) {
      if(i->ttd && (unsigned int)i->ttd < now) {
	d_waitstatus=TimeOut;
	if(swapcontext(&d_kernel,i->context)) { // swaps back to the above point 'A'
	  perror("swapcontext in schedule2");
	  exit(EXIT_FAILURE);
	}
	delete i->context;              
	ttdindex.erase(i++);                  // removes the waitpoint 
      }
      else if(i->ttd)
	break;
    }
  }
  return false;
}

//! returns true if there are no processes
/** Call this to check if no processes are running anymore
    \return true if no processes are left
 */
template<class Key, class Val>bool MTasker<Key,Val>::noProcesses()
{
  return d_threads.empty();
}

//! returns the number of processes running
/** Call this to perhaps limit activities if too many threads are running
    \return number of processes running
 */
template<class Key, class Val>unsigned int MTasker<Key,Val>::numProcesses()
{
  return d_threads.size();
}

//! gives access to the list of Events threads are waiting for
/** The kernel can call this to get a list of Events threads are waiting for. This is very useful
    to setup 'select' or 'poll' or 'aio' events needed to satisfy these requests.
    getEvents clears the events parameter before filling it.

    \param events Vector which is to be filled with keys threads are waiting for
*/
template<class Key, class Val>void MTasker<Key,Val>::getEvents(std::vector<Key>& events)
{
  events.clear();
  for(typename waiters_t::const_iterator i=d_waiters.begin();i!=d_waiters.end();++i) {
    events.push_back(i->first);
  }
}


template<class Key, class Val>void MTasker<Key,Val>::threadWrapper(MTasker *self, tfunc_t *tf, int tid, void* val)
{
  (*tf)(val);
  self->d_zombiesQueue.push(tid);
  
  // we now jump to &kernel, automatically
}

//! Returns the current Thread ID (tid)
/** Processes can call this to get a numerical representation of their current thread ID.
    This can be useful for logging purposes.
*/
template<class Key, class Val>int MTasker<Key,Val>::getTid()
{
  return d_tid;
}
