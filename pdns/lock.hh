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
#include <pthread.h>
#include <errno.h>
#include "misc.hh"
#include "pdnsexception.hh"

class ReadWriteLock
{
public:
  ReadWriteLock()
  {
    if (pthread_rwlock_init(&d_lock, nullptr) != 0) {
      throw std::runtime_error("Error creating a read-write lock: " + stringerror());
    }
  }

  ~ReadWriteLock() {
    /* might have been moved */
    pthread_rwlock_destroy(&d_lock);
  }

  ReadWriteLock(const ReadWriteLock& rhs) = delete;
  ReadWriteLock& operator=(const ReadWriteLock& rhs) = delete;

  pthread_rwlock_t* getLock()
  {
    return &d_lock;
  }

private:
  pthread_rwlock_t d_lock;
};

class ReadLock
{
public:
  ReadLock(ReadWriteLock& lock): ReadLock(lock.getLock())
  {
  }

  ReadLock(ReadWriteLock* lock): ReadLock(lock->getLock())
  {
  }

  ~ReadLock()
  {
    if(d_lock) // may have been moved
      pthread_rwlock_unlock(d_lock);
  }

  ReadLock(ReadLock&& rhs)
  {
    d_lock = rhs.d_lock;
    rhs.d_lock = nullptr;
  }
  ReadLock(const ReadLock& rhs) = delete;
  ReadLock& operator=(const ReadLock& rhs) = delete;

private:
  ReadLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    int err;
    if((err = pthread_rwlock_rdlock(d_lock))) {
      throw PDNSException("error acquiring rwlock readlock: "+stringerror(err));
    }
  }

 pthread_rwlock_t *d_lock;
};

class WriteLock
{
public:
  WriteLock(ReadWriteLock& lock): WriteLock(lock.getLock())
  {
  }

  WriteLock(ReadWriteLock* lock): WriteLock(lock->getLock())
  {
  }

  WriteLock(WriteLock&& rhs)
  {
    d_lock = rhs.d_lock;
    rhs.d_lock=0;
  }

  ~WriteLock()
  {
    if(d_lock) // might have been moved
      pthread_rwlock_unlock(d_lock);
  }

  WriteLock(const WriteLock& rhs) = delete;
  WriteLock& operator=(const WriteLock& rhs) = delete;

private:
  WriteLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    int err;
    if((err = pthread_rwlock_wrlock(d_lock))) {
      throw PDNSException("error acquiring rwlock wrlock: "+stringerror(err));
    }
  }

  pthread_rwlock_t *d_lock;
};

class TryReadLock
{
public:
  TryReadLock(ReadWriteLock& lock): TryReadLock(lock.getLock())
  {
  }

  TryReadLock(ReadWriteLock* lock): TryReadLock(lock->getLock())
  {
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
    if(d_havelock && d_lock)
      pthread_rwlock_unlock(d_lock);
  }

  TryReadLock(const TryReadLock& rhs) = delete;
  TryReadLock& operator=(const TryReadLock& rhs) = delete;

  bool gotIt()
  {
    return d_havelock;
  }

private:
  TryReadLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    int err;
    if((err = pthread_rwlock_tryrdlock(d_lock)) && err!=EBUSY) {
      throw PDNSException("error acquiring rwlock tryrdlock: "+stringerror(err));
    }
    d_havelock=(err==0);
  }

  pthread_rwlock_t *d_lock;
  bool d_havelock;
};

class TryWriteLock
{
public:
  TryWriteLock(ReadWriteLock& lock): TryWriteLock(lock.getLock())
  {
  }

  TryWriteLock(ReadWriteLock* lock): TryWriteLock(lock->getLock())
  {
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
    if(d_havelock && d_lock) // we might be moved
      pthread_rwlock_unlock(d_lock);
  }

  TryWriteLock(const TryWriteLock& rhs) = delete;
  TryWriteLock& operator=(const TryWriteLock& rhs) = delete;

  bool gotIt()
  {
    return d_havelock;
  }

private:
  TryWriteLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    d_havelock=false;
    int err;
    if((err = pthread_rwlock_trywrlock(d_lock)) && err!=EBUSY) {
      throw PDNSException("error acquiring rwlock tryrwlock: "+stringerror(err));
    }
    d_havelock=(err==0);
  }

  pthread_rwlock_t *d_lock;
  bool d_havelock;
};

