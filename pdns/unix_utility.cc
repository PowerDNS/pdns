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
// Utility class win32 implementation.

#include "utility.hh"
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h> 
#include "ahuexception.hh"
#include "logger.hh"
#include "misc.hh"
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

using namespace std;

// Closes a socket.
int Utility::closesocket( Utility::sock_t socket )
{
  return ::close( socket );
}

bool Utility::setNonBlocking(sock_t sock)
{
  int flags=fcntl(sock,F_GETFL,0);    
  if(flags<0 || fcntl(sock, F_SETFL,flags|O_NONBLOCK) <0)
    return false;
  return true;
}

bool Utility::setBlocking(sock_t sock)
{
  int flags=fcntl(sock,F_GETFL,0);    
  if(flags<0 || fcntl(sock, F_SETFL,flags&(~O_NONBLOCK)) <0)
    return false;
  return true;
}

const char *Utility::inet_ntop(int af, const char *src, char *dst, size_t size)
{
  return const_cast<char *>(::inet_ntop(af,src,dst,size));
}

unsigned int Utility::sleep(unsigned int sec)
{
  return ::sleep(sec);
}

void Utility::usleep(unsigned long usec)
{
  ::usleep(usec);
}


// Drops the program's privileges.
void Utility::dropPrivs( int uid, int gid )
{
  if(gid) {
    if(setgid(gid)<0) {
      theL()<<Logger::Error<<"Unable to set effective group id to "<<gid<<": "<<stringerror()<<endl;
      exit(1);
    }
    else
      theL()<<Logger::Error<<"Set effective group id to "<<uid<<endl;

  }

  if(uid) {
    if(setuid(uid)<0) {
      theL()<<Logger::Error<<"Unable to set effective user id to "<<uid<<":  "<<stringerror()<<endl;
      exit(1);
    }
    else
      theL()<<Logger::Error<<"Set effective user id to "<<uid<<endl;
  }
}


// Returns the current process id.
Utility::pid_t Utility::getpid( void )
{
  return ::getpid();
}


// Returns the current time.
int Utility::gettimeofday( struct timeval *tv, void *tz )
{
  return ::gettimeofday(tv,0);
}


// Converts an address from dot and numbers format to binary data.
int Utility::inet_aton( const char *cp, struct in_addr *inp )
{
  return ::inet_aton(cp,inp);

}


// Converts an address from presentation format to network format.
int Utility::inet_pton( int af, const char *src, void *dst )
{
  return ::inet_pton(af, src, dst);
}


// Retrieves a gid using a groupname.
int Utility::makeGidNumeric(const string &group)
{
  int newgid;
  if(!(newgid=atoi(group.c_str()))) {
    struct group *gr=getgrnam(group.c_str());
    if(!gr) {
      theL()<<Logger::Error<<"Unable to look up gid of group '"<<group<<"': "<<strerror(errno)<<endl;
      exit(1);
    }
    newgid=gr->gr_gid;
  }
  return newgid;
}


// Retrieves an uid using a username.
int Utility::makeUidNumeric(const string &username)
{
  int newuid;
  if(!(newuid=atoi(username.c_str()))) {
    struct passwd *pw=getpwnam(username.c_str());
    if(!pw) {
      theL()<<Logger::Error<<"Unable to look up uid of user '"<<username<<"': "<<strerror(errno)<<endl;
      exit(1);
    }
    newuid=pw->pw_uid;
  }
  return newuid;
}


// Returns a random number.
long int Utility::random( void )
{
  return rand();
}

// Sets the random seed.
void Utility::srandom( unsigned int seed )
{
  ::srandom(seed);
}

// Compares two string, ignoring the case.
int Utility::strcasecmp( const char *s1, const char *s2 )
{
  return ::strcasecmp( s1, s2 );
}


// Writes a vector.
int Utility::writev(int socket, const struct iovec *vector, size_t count )
{
  return ::writev(socket,vector,count);
}

#ifdef DARWIN

// Darwin 6.0 Compatible implementation, uses pthreads so it portable across more platforms.

#define SEM_VALUE_MAX 32767
#define SEM_MAGIC     ((u_int32_t) 0x09fa4012)

Semaphore::Semaphore(unsigned int value)
{
  if (value > SEM_VALUE_MAX) {
    throw AhuException("Cannot create semaphore: value too large");
  }

  // Initialize
  
  if (pthread_mutex_init(&m_lock, NULL) != 0) {
    throw AhuException("Cannot create semaphore: cannot allocate mutex");
  }

  if (pthread_cond_init(&m_gtzero, NULL) != 0) {
    pthread_mutex_destroy(&m_lock);
    throw AhuException("Cannot create semaphore: cannot allocate condition");
  }

  m_count = (u_int32_t) value;
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
  return sem_wait(m_pSemaphore);
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
