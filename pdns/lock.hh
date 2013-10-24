/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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

  Lock(pthread_mutex_t *lock) : d_lock(lock)
  {
    if(g_singleThreaded)
      return;
    if((errno=pthread_mutex_lock(d_lock)))
      throw PDNSException("error acquiring lock: "+stringerror());
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

    if((errno=pthread_rwlock_wrlock(d_lock))) {
      throw PDNSException("error acquiring rwlock wrlock: "+stringerror());
    }
  }
  ~WriteLock()
  {
    if(g_singleThreaded)
      return;

    pthread_rwlock_unlock(d_lock);
  }
};

class TryWriteLock
{
  pthread_rwlock_t *d_lock;
  bool d_havelock;
public:

  TryWriteLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    if(g_singleThreaded) {
      d_havelock=true;
      return;
    }

    d_havelock=false;
    if((errno=pthread_rwlock_trywrlock(d_lock)) && errno!=EBUSY)
      throw PDNSException("error acquiring rwlock tryrwlock: "+stringerror());
    d_havelock=(errno==0);
  }
  ~TryWriteLock()
  {
    if(g_singleThreaded)
      return;

    if(d_havelock)
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

  TryReadLock(pthread_rwlock_t *lock) : d_lock(lock)
  {
    if(g_singleThreaded) {
      d_havelock=true;
      return;
    }

    if((errno=pthread_rwlock_tryrdlock(d_lock)) && errno!=EBUSY)
      throw PDNSException("error acquiring rwlock tryrdlock: "+stringerror());
    d_havelock=(errno==0);
  }
  ~TryReadLock()
  {
    if(g_singleThreaded)
      return;

    if(d_havelock)
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

    if((errno=pthread_rwlock_rdlock(d_lock)))
      throw PDNSException("error acquiring rwlock tryrwlock: "+stringerror());
  }
  ~ReadLock()
  {
    if(g_singleThreaded)
      return;

    pthread_rwlock_unlock(d_lock);
  }
  
  void upgrade()
  {
    if(g_singleThreaded)
      return;

    pthread_rwlock_unlock(d_lock);
    pthread_rwlock_wrlock(d_lock);
  }
};
#endif
