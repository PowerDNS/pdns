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
#include <memory>
#include <atomic>
#include <mutex>
/** This is sort of a light-weight RCU idea. 
    Suitable for when you frequently consult some "readonly" state, which infrequently
    gets changed. One way of dealing with this is fully locking access to the state, but 
    this is rather wasteful.

    Instead, in the code below, the frequent users of the state get a "readonly" copy of it, 
    which they can consult.  On access, we atomically compare if the local copy is still current 
    with the global one.  If it isn't we do the lock thing, and create a new local copy.

    Meanwhile, to upgrade the global state, methods are offered that do appropriate locking 
    and upgrade the 'generation' counter, signaling to the local copies that they need to be
    refreshed on the next access.

    Two ways to change the global copy are available:
        getCopy(), which delivers a deep copy of the current state, followed by setState()
	modify(), which accepts a (lambda)function that modifies the state

    NOTE: The actual destruction of the 'old' state happens when the last local state 
    relinquishes its access to the state.

    "read-only"
    Sometimes, a 'state' can contain parts that can safely be modified by multiple users, for 
    example, atomic counters. In such cases, it may be useful to explicitly declare such counters
    as mutable.  */

template<typename T> class GlobalStateHolder;

template<typename T>
class LocalStateHolder
{
public:
  explicit LocalStateHolder(GlobalStateHolder<T>* source) : d_source(source)
  {}

  const T* operator->()  // fast const-only access, but see "read-only" above
  {
    if(d_source->getGeneration() != d_generation) {
      d_source->getState(&d_state, & d_generation);
    }

    return d_state.get();
  }
  const T& operator*()  // fast const-only access, but see "read-only" above
  {
    return *operator->();
  }

  void reset()
  {
    d_generation=0;
    d_state.reset();
  }
private:
  std::shared_ptr<T> d_state;
  unsigned int d_generation{0};
  const GlobalStateHolder<T>* d_source;
};

template<typename T>
class GlobalStateHolder
{
public:
  GlobalStateHolder() : d_state(std::make_shared<T>())
  {}
  LocalStateHolder<T> getLocal()
  {
    return LocalStateHolder<T>(this);
  }

  void setState(T state) //!< Safely & slowly change the global state
  {
    std::shared_ptr<T> newState = std::make_shared<T>(state);
    {
      std::lock_guard<std::mutex> l(d_lock);
      d_state = newState;
      d_generation++;
    }
  }

  T getCopy() const  //!< Safely & slowly get a copy of the global state
  {
    std::lock_guard<std::mutex> l(d_lock);
    return *d_state;
  }
  
  //! Safely & slowly modify the global state
  template<typename F>
  void modify(F act) {
    std::lock_guard<std::mutex> l(d_lock); 
    auto state=*d_state; // and yes, these three steps are necessary, can't ever modify state in place, even when locked!
    act(state);
    d_state = std::make_shared<T>(state);
    ++d_generation;
  }


  typedef T value_type;
private:
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
  friend class LocalStateHolder<T>;
  mutable std::mutex d_lock;
  std::shared_ptr<T> d_state;
  std::atomic<unsigned int> d_generation{1};
};
