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
#ifndef LOCK_HH
#define LOCK_HH

#include <pthread.h>
#include <errno.h>
#include "misc.hh"
#include "pdnsexception.hh"

extern bool g_singleThreaded;

class Lock
{
  pthread_mutex_t *d_lock;
public:
  Lock(const Lock& rhs) = delete;
  Lock& operator=(const Lock& rhs) = delete;

  Lock(pthread_mutex_t *lock) : d_lock(lock)
  {
    if(g_singleThreaded)
      return;

    int err;
    if((err = pthread_mutex_lock(d_lock))) {
      errno = err;
      throw PDNSException("error acquiring lock: "+stringerror());
    }
  }
  ~Lock()
  {
    if(g_singleThreaded)
      return;

    pthread_mutex_unlock(d_lock);
  }
};

class WriteLock
{
  pthread_rwlock_t *d_lock;
public:

  WriteLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    if(g_singleThreaded)
      return;

    int err;
    if((err = pthread_rwlock_wrlock(d_lock))) {
      throw PDNSException("error acquiring rwlock wrlock: "+stringerror(err));
    }
  }
  ~WriteLock()
  {
    if(g_singleThreaded)
      return;
    if(d_lock) // might have been moved
      pthread_rwlock_unlock(d_lock);
  }

  WriteLock(WriteLock&& rhs)
  {
    d_lock = rhs.d_lock;
    rhs.d_lock=0;
  }
  WriteLock(const WriteLock& rhs) = delete;
  WriteLock& operator=(const WriteLock& rhs) = delete;


};

class TryWriteLock
{
  pthread_rwlock_t *d_lock;
  bool d_havelock;
public:
  TryWriteLock(const TryWriteLock& rhs) = delete;
  TryWriteLock& operator=(const TryWriteLock& rhs) = delete;

  TryWriteLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    if(g_singleThreaded) {
      d_havelock=true;
      return;
    }

    d_havelock=false;
    int err;
    if((err = pthread_rwlock_trywrlock(d_lock)) && err!=EBUSY) {
      throw PDNSException("error acquiring rwlock tryrwlock: "+stringerror(err));
    }
    d_havelock=(err==0);
  }

  TryWriteLock(TryWriteLock&& rhs)
  {
    d_lock = rhs.d_lock;
    rhs.d_lock = nullptr;
    d_havelock = rhs.d_havelock;
    rhs.d_havelock = false;
  }

  
  ~TryWriteLock()
  {
    if(g_singleThreaded)
      return;

    if(d_havelock && d_lock) // we might be moved
      pthread_rwlock_unlock(d_lock);
  }
  bool gotIt()
  {
    if(g_singleThreaded)
      return true;

    return d_havelock;
  }
};

class TryReadLock
{
  pthread_rwlock_t *d_lock;
  bool d_havelock;
public:
  TryReadLock(const TryReadLock& rhs) = delete;
  TryReadLock& operator=(const TryReadLock& rhs) = delete;

  TryReadLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    if(g_singleThreaded) {
      d_havelock=true;
      return;
    }

    int err;
    if((err = pthread_rwlock_tryrdlock(d_lock)) && err!=EBUSY) {
      throw PDNSException("error acquiring rwlock tryrdlock: "+stringerror(err));
    }
    d_havelock=(err==0);
  }
  TryReadLock(TryReadLock&& rhs)
  {
    d_lock = rhs.d_lock;
    rhs.d_lock = nullptr;
    d_havelock = rhs.d_havelock;
    rhs.d_havelock = false;
  }

  ~TryReadLock()
  {
    if(g_singleThreaded)
      return;

    if(d_havelock && d_lock)
      pthread_rwlock_unlock(d_lock);
  }
  bool gotIt()
  {
    if(g_singleThreaded)
      return true;

    return d_havelock;
  }
};


class ReadLock
{
  pthread_rwlock_t *d_lock;
public:

  ReadLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    if(g_singleThreaded)
      return;

    int err;
    if((err = pthread_rwlock_rdlock(d_lock))) {
      throw PDNSException("error acquiring rwlock readlock: "+stringerror(err));
    }
  }
  ~ReadLock()
  {
    if(g_singleThreaded)
      return;
    if(d_lock) // may have been moved
      pthread_rwlock_unlock(d_lock);
  }

  ReadLock(ReadLock&& rhs)
  {
    d_lock = rhs.d_lock;
    rhs.d_lock=0;
  }
  ReadLock(const ReadLock& rhs) = delete;
  ReadLock& operator=(const ReadLock& rhs) = delete;
};
#endif
