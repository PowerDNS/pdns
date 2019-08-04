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
// Utility class specification.

#ifndef UTILITY_HH
#define UTILITY_HH

#ifdef NEED_POSIX_TYPEDEF
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <string>

#include "namespaces.hh"

//! A semaphore class.
class Semaphore
{
private:
  typedef int sem_value_t;

#if defined(_AIX) || defined(__APPLE__)
  uint32_t       m_magic;
  pthread_mutex_t m_lock;
  pthread_cond_t  m_gtzero;
  sem_value_t     m_count;
  uint32_t       m_nwaiters;
#else
  std::unique_ptr<sem_t> m_pSemaphore;
#endif

protected:
public:
  Semaphore(const Semaphore&) = delete;
  void operator=(const Semaphore&) = delete;
  //! Default constructor.
  Semaphore( unsigned int value = 0 );

  //! Destructor.
  ~Semaphore( void );

  //! Posts to a semaphore.
  int post( void );

  //! Waits for a semaphore.
  int wait( void );

  //! Tries to wait for a semaphore.
  int tryWait( void );

  //! Retrieves the semaphore value.
  int getValue( Semaphore::sem_value_t *sval );
};

//! This is a utility class used for platform independent abstraction.
class Utility
{
public:
  typedef ::iovec iovec;
  typedef ::pid_t pid_t;
  typedef int sock_t;
  typedef ::socklen_t socklen_t;

  //! Connect with timeout
  // Returns:
  //    > 0 on success
  //    -1 on error
  //    0 on timeout
  static int timed_connect(sock_t sock,
    const sockaddr *addr,
    socklen_t sockaddr_size,
    int timeout_sec,
    int timeout_usec);

  //! Returns the process id of the current process.
  static pid_t getpid( void );

  //! Gets the current time.
  static int gettimeofday( struct timeval *tv, void *tz = NULL );

  //! Converts an address from dot and numbers format to binary data.
  static int inet_aton( const char *cp, struct in_addr *inp );

  //! Converts an address from presentation format to network format.
  static int inet_pton( int af, const char *src, void *dst );

  //! The inet_ntop() function converts an address from network format (usually a struct in_addr or some other binary form, in network byte order) to presentation format.
  static const char *inet_ntop( int af, const char *src, char *dst, size_t size );

  //! Writes a vector.
  static int writev( Utility::sock_t socket, const iovec *vector, size_t count );

  //! Sets the random seed.
  static void srandom(void);

  //! Drops the program's group privileges.
  static void dropGroupPrivs( uid_t uid, gid_t gid );

  //! Drops the program's user privileges.
  static void dropUserPrivs( uid_t uid );
  
  //! Sets the socket into Bind-any mode
  static void setBindAny ( int af, Utility::sock_t socket );
  
  //! Sleeps for a number of seconds.
  static unsigned int sleep( unsigned int seconds );
  
  //! Sleeps for a number of microseconds.
  static void usleep( unsigned long usec );

  static time_t timegm(struct tm *tm);
  
};


#endif // UTILITY_HH
