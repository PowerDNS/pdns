/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h> 
#include "pdnsexception.hh"
#include "logger.hh"
#include "misc.hh"
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>


#if defined(_AIX) || defined(__APPLE__)

// Darwin 6.0 Compatible implementation, uses pthreads so it portable across more platforms.

#define SEM_VALUE_MAX 32767
#define SEM_MAGIC     ((uint32_t) 0x09fa4012)

Semaphore::Semaphore(unsigned int value)
{
  if (value > SEM_VALUE_MAX) {
    throw PDNSException("Cannot create semaphore: value too large");
  }

  // Initialize
  
  if (pthread_mutex_init(&m_lock, NULL) != 0) {
    throw PDNSException("Cannot create semaphore: cannot allocate mutex");
  }

  if (pthread_cond_init(&m_gtzero, NULL) != 0) {
    pthread_mutex_destroy(&m_lock);
    throw PDNSException("Cannot create semaphore: cannot allocate condition");
  }

  m_count = (uint32_t) value;
  m_nwaiters = 0;
  m_magic = SEM_MAGIC;
}

int Semaphore::post()
{
  pthread_mutex_lock(&m_lock);

  m_count++;
  if (m_nwaiters > 0) {
    pthread_cond_signal(&m_gtzero);
  }

  pthread_mutex_unlock(&m_lock);

  return 0;
}

int Semaphore::wait()
{
  pthread_mutex_lock(&m_lock);
  
  while (m_count == 0) {
    m_nwaiters++;
    pthread_cond_wait(&m_gtzero, &m_lock);
    m_nwaiters--;
  }
  
  m_count--;

  pthread_mutex_unlock(&m_lock);

  return 0;
}

int Semaphore::tryWait()
{
  int retval = 0;

  pthread_mutex_lock(&m_lock);

  if (m_count > 0) {
    m_count--;
  } else {
    errno = EAGAIN;
    retval = -1;
  }

  pthread_mutex_unlock(&m_lock);
 
  return retval;
}

int Semaphore::getValue(Semaphore::sem_value_t *sval)
{
  pthread_mutex_lock(&m_lock);
  *sval = m_count;
  pthread_mutex_unlock(&m_lock);

  return 0;
}

Semaphore::~Semaphore()
{
  // Make sure there are no waiters.
  
  pthread_mutex_lock(&m_lock);
  if (m_nwaiters > 0) {
    pthread_mutex_unlock(&m_lock);
    //errno = EBUSY;
    //return -1;
  }
  pthread_mutex_unlock(&m_lock);

  // Destroy it.

  pthread_mutex_destroy(&m_lock);
  pthread_cond_destroy(&m_gtzero);
  m_magic = 0;

  //return 0;
}

#else /* not DARWIN from here on */


Semaphore::Semaphore(unsigned int value)
{
  m_pSemaphore=new sem_t;
  if (sem_init(m_pSemaphore, 0, value) == -1) {
    theL() << Logger::Error << "Cannot create semaphore: " << stringerror() << endl;
    exit(1);
  }
}

int Semaphore::post()
{
  return sem_post(m_pSemaphore);
}

int Semaphore::wait()
{
  int ret;
  do
    ret = sem_wait(m_pSemaphore);
  while (ret == -1 && errno == EINTR);
  return ret;
}
int Semaphore::tryWait()
{
  return sem_trywait(m_pSemaphore);
}

int Semaphore::getValue(Semaphore::sem_value_t *sval)
{
  return sem_getvalue(m_pSemaphore, sval);
}

Semaphore::~Semaphore()
{
}

#endif
