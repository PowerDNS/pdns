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
#pragma once
#include <cstdint>
#include <ctime>
#include <queue>
#include <memory>
#include <stack>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/key_extractors.hpp>

#include "misc.hh"
#include "mtasker_context.hh"

// #define MTASKERTIMING 1

//! The main MTasker class
/** The main MTasker class. See the main page for more information.
    \tparam EventKey Type of the key with which events are to be identified. Defaults to int.
    \tparam EventVal Type of the content or value of an event. Defaults to int. Cannot be set to void.
    \note The EventKey needs to have an operator< defined because it is used as the key of an associative array
*/

template <class EventKey = int, class EventVal = int, class Cmp = std::less<EventKey>>
class MTasker
{
public:
  struct Waiter
  {
    EventKey key;
    std::shared_ptr<pdns_ucontext_t> context;
    struct timeval ttd{};
    int tid{};
  };
  struct KeyTag
  {
  };

  using waiters_t = boost::multi_index::multi_index_container<
    Waiter,
    boost::multi_index::indexed_by<
      boost::multi_index::ordered_unique<boost::multi_index::member<Waiter, EventKey, &Waiter::key>, Cmp>,
      boost::multi_index::ordered_non_unique<boost::multi_index::tag<KeyTag>, boost::multi_index::member<Waiter, struct timeval, &Waiter::ttd>>>>;

  //! Constructor
  /** Constructor with a small default stacksize. If any of your threads exceeds this stack, your application will crash.
      This limit applies solely to the stack, the heap is not limited in any way. If threads need to allocate a lot of data,
      the use of new/delete is suggested.
   */
  MTasker(size_t stacksize = static_cast<size_t>(16 * 8192), size_t stackCacheSize = 0) :
    d_stacksize(stacksize), d_maxCachedStacks(stackCacheSize), d_waitstatus(Error)
  {
    initMainStackBounds();

    // make sure our stack is 16-byte aligned to make all the architectures happy
    d_stacksize = d_stacksize >> 4 << 4;
  }

  using tfunc_t = void(void*); //!< type of the pointer that starts a thread
  uint64_t nextWaiterDelayUsec(uint64_t defusecs);
  int waitEvent(EventKey& key, EventVal* val = nullptr, unsigned int timeoutMsec = 0, const struct timeval* now = nullptr);
  void yield();
  int sendEvent(const EventKey& key, const EventVal* val = nullptr);
  void makeThread(tfunc_t* start, void* val);
  bool schedule(const struct timeval& now);

  const waiters_t& getWaiters() const
  {
    return d_waiters;
  }

  //! gives access to the list of Events threads are waiting for
  /** The kernel can call this to get a list of Events threads are waiting for. This is very useful
      to setup 'select' or 'poll' or 'aio' events needed to satisfy these requests.
      getEvents clears the events parameter before filling it.

      \param events Vector which is to be filled with keys threads are waiting for
  */
  void getEvents(std::vector<EventKey>& events) const
  {
    events.clear();
    for (const auto& waiter : d_waiters) {
      events.emplace_back(waiter.key);
    }
  }

  //! returns true if there are no processes
  /** Call this to check if no processes are running anymore
      \return true if no processes are left
  */
  [[nodiscard]] bool noProcesses() const
  {
    return d_threadsCount == 0;
  }

  //! returns the number of processes running
  /** Call this to perhaps limit activities if too many threads are running
      \return number of processes running
  */
  [[nodiscard]] unsigned int numProcesses() const
  {
    return d_threadsCount;
  }

  //! Returns the current Thread ID (tid)
  /** Processes can call this to get a numerical representation of their current thread ID.
      This can be useful for logging purposes.
  */
  [[nodiscard]] int getTid() const
  {
    return d_tid;
  }

  //! Returns the maximum stack usage so far of this MThread
  [[nodiscard]] uint64_t getMaxStackUsage() const
  {
    return d_threads.at(d_tid).startOfStack - d_threads.at(d_tid).highestStackSeen;
  }

  //! Returns the maximum stack usage so far of this MThread
  [[nodiscard]] unsigned int getUsec() const
  {
#ifdef MTASKERTIMING
    return d_threads.at(d_tid).totTime + d_threads.at(d_tid).dt.ndiff() / 1000;
#else
    return 0;
#endif
  }

private:
  EventKey d_eventkey; // for waitEvent, contains exact key it was awoken for
  EventVal d_waitval;

  pdns_ucontext_t d_kernel;
  std::queue<int> d_runQueue;
  std::queue<int> d_zombiesQueue;

  struct ThreadInfo
  {
    std::shared_ptr<pdns_ucontext_t> context;
    std::function<void(void)> start;
    const char* startOfStack{};
    const char* highestStackSeen{};
#ifdef MTASKERTIMING
    CPUTime dt;
    unsigned int totTime;
#endif
  };

  using pdns_mtasker_stack_t = std::vector<char, lazy_allocator<char>>;
  using mthreads_t = std::map<int, ThreadInfo>;

  mthreads_t d_threads;
  std::stack<pdns_mtasker_stack_t> d_cachedStacks;
  waiters_t d_waiters;
  size_t d_stacksize;
  size_t d_threadsCount{0};
  size_t d_maxCachedStacks{0};
  int d_tid{0};
  int d_maxtid{0};
  bool d_used{true}; // was d_eventkey consumed?
  enum waitstatusenum : int8_t
  {
    Error = -1,
    TimeOut = 0,
    Answer = 1,
  } d_waitstatus;

  std::shared_ptr<pdns_ucontext_t> getUContext();

  void initMainStackBounds()
  {
#ifdef HAVE_FIBER_SANITIZER

#ifdef HAVE_PTHREAD_GETATTR_NP
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_getattr_np(pthread_self(), &attr);
    pthread_attr_getstack(&attr, &t_mainStack, &t_mainStackSize);
    pthread_attr_destroy(&attr);
#elif defined(HAVE_PTHREAD_GET_STACKSIZE_NP) && defined(HAVE_PTHREAD_GET_STACKADDR_NP)
    t_mainStack = pthread_get_stackaddr_np(pthread_self());
    t_mainStackSize = pthread_get_stacksize_np(pthread_self());
#else
#error Cannot determine stack size and base on this platform
#endif

#endif /* HAVE_FIBER_SANITIZER */
  }
};

#ifdef PDNS_USE_VALGRIND
#include <valgrind/valgrind.h>
#endif /* PDNS_USE_VALGRIND */

template <class EventKey, class EventVal, class Cmp>
uint64_t MTasker<EventKey, EventVal, Cmp>::nextWaiterDelayUsec(uint64_t defusecs)
{
  if (d_waiters.empty()) {
    // no waiters
    return defusecs;
  }
  auto& ttdindex = boost::multi_index::get<KeyTag>(d_waiters);
  auto iter = ttdindex.begin();
  timeval rnow{};
  gettimeofday(&rnow, nullptr);
  if (iter->ttd.tv_sec != 0) {
    // we have a waiter with a timeout specified
    if (rnow < iter->ttd) {
      // we should not wait longer than the default timeout
      return std::min(defusecs, uSec(iter->ttd - rnow));
    }
    // already expired
    return 0;
  }
  return defusecs;
}

//! puts a thread to sleep waiting until a specified event arrives
/** Threads can call waitEvent to register that they are waiting on an event with a certain key.
    If so desired, the event can carry data which is returned in val in case that is non-zero.

    Furthermore, a timeout can be specified in seconds.

    Only one thread can be waiting on a key, results of trying to have more threads
    waiting on the same key are undefined.

    \param key Event key to wait for. Needs to match up to a key reported to sendEvent
    \param val If non-zero, the value of the event will be stored in *val
    \param timeout If non-zero, number of seconds to wait for an event.

    \return returns -1 in case of error, 0 in case of timeout, 1 in case of an answer
*/
template <class EventKey, class EventVal, class Cmp>
int MTasker<EventKey, EventVal, Cmp>::waitEvent(EventKey& key, EventVal* val, unsigned int timeoutMsec, const struct timeval* now)
{
  if (d_waiters.count(key)) { // there was already an exact same waiter
    return -1;
  }

  Waiter waiter;
  waiter.context = std::make_shared<pdns_ucontext_t>();
  waiter.ttd.tv_sec = 0;
  waiter.ttd.tv_usec = 0;
  if (timeoutMsec != 0) {
    struct timeval increment{};
    increment.tv_sec = timeoutMsec / 1000;
    increment.tv_usec = static_cast<decltype(increment.tv_usec)>(1000 * (timeoutMsec % 1000));
    if (now != nullptr) {
      waiter.ttd = increment + *now;
    }
    else {
      struct timeval realnow{};
      gettimeofday(&realnow, nullptr);
      waiter.ttd = increment + realnow;
    }
  }

  waiter.tid = d_tid;
  waiter.key = key;

  d_waiters.insert(waiter);
#ifdef MTASKERTIMING
  unsigned int diff = d_threads[d_tid].dt.ndiff() / 1000;
  d_threads[d_tid].totTime += diff;
#endif
  notifyStackSwitchToKernel();
  pdns_swapcontext(*d_waiters.find(key)->context, d_kernel); // 'A' will return here when 'key' has arrived, hands over control to kernel first
  notifyStackSwitchDone();
#ifdef MTASKERTIMING
  d_threads[d_tid].dt.start();
#endif
  if (val && d_waitstatus == Answer) {
    *val = std::move(d_waitval);
  }
  d_tid = waiter.tid;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (auto* waiterAddress = reinterpret_cast<char*>(&waiter); waiterAddress < d_threads[d_tid].highestStackSeen) {
    d_threads[d_tid].highestStackSeen = waiterAddress;
  }
  assert(!d_used);
  key = std::move(d_eventkey);
  d_used = true;
  return d_waitstatus;
}

//! yields control to the kernel or other threads
/** Hands over control to the kernel, allowing other processes to run, or events to arrive */

template <class Key, class Val, class Cmp>
void MTasker<Key, Val, Cmp>::yield()
{
  d_runQueue.push(d_tid);
  notifyStackSwitchToKernel();
  pdns_swapcontext(*d_threads[d_tid].context, d_kernel); // give control to the kernel
  notifyStackSwitchDone();
}

//! reports that an event took place for which threads may be waiting
/** From the kernel loop, sendEvent can be called to report that something occurred for which there may be waiters.
    \param key Key of the event for which threads may be waiting
    \param val If non-zero, pointer to the content of the event
    \return Returns -1 in case of error, 0 if there were no waiters, 1 if a thread was woken up.

    WARNING: when passing val as zero, d_waitval is undefined, and hence waitEvent will return undefined!
*/
template <class EventKey, class EventVal, class Cmp>
int MTasker<EventKey, EventVal, Cmp>::sendEvent(const EventKey& key, const EventVal* val)
{
  auto waiter = d_waiters.find(key);

  if (waiter == d_waiters.end()) {
    return 0;
  }
  d_waitstatus = Answer;
  if (val) {
    d_waitval = *val;
  }
  d_tid = waiter->tid; // set tid
  d_eventkey = waiter->key; // pass waitEvent the exact key it was woken for
  d_used = false;
  auto userspace = std::move(waiter->context);
  d_waiters.erase(waiter); // removes the waitpoint
  notifyStackSwitch(d_threads[d_tid].startOfStack, d_stacksize);
  try {
    pdns_swapcontext(d_kernel, *userspace); // swaps back to the above point 'A'
  }
  catch (...) {
    notifyStackSwitchDone();
    throw;
  }
  notifyStackSwitchDone();
  return 1;
}

template <class Key, class Val, class Cmp>
std::shared_ptr<pdns_ucontext_t> MTasker<Key, Val, Cmp>::getUContext()
{
  auto ucontext = std::make_shared<pdns_ucontext_t>();
  if (d_cachedStacks.empty()) {
    ucontext->uc_stack.resize(d_stacksize + 1);
  }
  else {
    ucontext->uc_stack = std::move(d_cachedStacks.top());
    d_cachedStacks.pop();
  }

  ucontext->uc_link = &d_kernel; // come back to kernel after dying

#ifdef PDNS_USE_VALGRIND
  ucontext->valgrind_id = VALGRIND_STACK_REGISTER(&ucontext->uc_stack[0], &ucontext->uc_stack[ucontext->uc_stack.size() - 1]);
#endif /* PDNS_USE_VALGRIND */

  return ucontext;
}

//! launches a new thread
/** The kernel can call this to make a new thread, which starts at the function start and gets passed the val void pointer.
    \param start Pointer to the function which will form the start of the thread
    \param val A void pointer that can be used to pass data to the thread
*/
template <class Key, class Val, class Cmp>
void MTasker<Key, Val, Cmp>::makeThread(tfunc_t* start, void* val)
{
  auto ucontext = getUContext();

  ++d_threadsCount;
  auto& thread = d_threads[d_maxtid];
  // we will get a better approximation when the task is executed, but that prevents notifying a stack at nullptr
  // on the first invocation
  d_threads[d_maxtid].startOfStack = &ucontext->uc_stack[ucontext->uc_stack.size() - 1];
  thread.start = [start, val, this]() {
    char dummy{};
    d_threads[d_tid].startOfStack = d_threads[d_tid].highestStackSeen = &dummy;
    auto const tid = d_tid;
    start(val);
    d_zombiesQueue.push(tid);
  };
  pdns_makecontext(*ucontext, thread.start);

  thread.context = std::move(ucontext);
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
template <class Key, class Val, class Cmp>
bool MTasker<Key, Val, Cmp>::schedule(const struct timeval& now)
{
  if (!d_runQueue.empty()) {
    d_tid = d_runQueue.front();
#ifdef MTASKERTIMING
    d_threads[d_tid].dt.start();
#endif
    notifyStackSwitch(d_threads[d_tid].startOfStack, d_stacksize);
    try {
      pdns_swapcontext(d_kernel, *d_threads[d_tid].context);
    }
    catch (...) {
      notifyStackSwitchDone();
      // It is not clear if the d_runQueue.pop() should be done in this case
      throw;
    }
    notifyStackSwitchDone();

    d_runQueue.pop();
    return true;
  }
  if (!d_zombiesQueue.empty()) {
    auto zombi = d_zombiesQueue.front();
    if (d_cachedStacks.size() < d_maxCachedStacks) {
      auto thread = d_threads.find(zombi);
      if (thread != d_threads.end()) {
        d_cachedStacks.push(std::move(thread->second.context->uc_stack));
      }
      d_threads.erase(thread);
    }
    else {
      d_threads.erase(zombi);
    }
    --d_threadsCount;
    d_zombiesQueue.pop();
    return true;
  }
  if (!d_waiters.empty()) {
    auto& ttdindex = boost::multi_index::get<KeyTag>(d_waiters);

    for (auto i = ttdindex.begin(); i != ttdindex.end();) {
      if (i->ttd.tv_sec && i->ttd < now) {
        d_waitstatus = TimeOut;
        d_eventkey = i->key; // pass waitEvent the exact key it was woken for
        d_used = false;
        auto ucontext = i->context;
        d_tid = i->tid;
        ttdindex.erase(i++); // removes the waitpoint

        notifyStackSwitch(d_threads[d_tid].startOfStack, d_stacksize);
        try {
          pdns_swapcontext(d_kernel, *ucontext); // swaps back to the above point 'A'
        }
        catch (...) {
          notifyStackSwitchDone();
          throw;
        }
        notifyStackSwitchDone();
      }
      else if (i->ttd.tv_sec != 0) {
        break;
      }
      else {
        ++i;
      }
    }
  }
  return false;
}
