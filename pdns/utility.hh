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
// Utility class specification.

#ifndef UTILITY_HH
#define UTILITY_HH

#ifndef WIN32
// # include "config.h"
#endif // WIN32

#ifdef _MSC_VER
# define NEED_POSIX_TYPEDEF
# pragma warning (disable:4996)
#endif // _MSC_VER

#ifdef NEED_POSIX_TYPEDEF
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#endif


#ifndef WIN32
# include <arpa/inet.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <sys/uio.h>
# include <signal.h>
# include <pthread.h>
# include <semaphore.h>
# include <signal.h>
# include <errno.h>
# include <unistd.h>
#else
typedef int socklen_t;
#define _WIN32_WINNT 0x0400
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
# define WINDOWS_LEAN_AND_MEAN
# include <windows.h>
# include <signal.h>
# include <map>

#ifndef ETIMEDOUT
# define ETIMEDOUT    WSAETIMEDOUT
#endif // ETIMEDOUT

# define EINPROGRESS  WSAEWOULDBLOCK

# define snprintf _snprintf
#endif // WIN32
#include <string>

#include "namespaces.hh"

//! A semaphore class.
class Semaphore
{
private:
  sem_t *m_pSemaphore;
#ifdef WIN32
  typedef int sem_value_t;

  //! The semaphore.



  //! Semaphore counter.
  long m_counter;

#else
  typedef int sem_value_t;

  uint32_t       m_magic;
  pthread_mutex_t m_lock;
  pthread_cond_t  m_gtzero;
  sem_value_t     m_count;
  uint32_t       m_nwaiters;
#endif

protected:
public:
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

//! This is a utility class used for platform independant abstraction.
class Utility
{
#ifdef WIN32
private:
  static int inet_pton4( const char *src, void *dst );
  static int inet_pton6( const char *src, void *dst );

  static const char *inet_ntop4( const char *src, char *dst, size_t size );
  static const char *inet_ntop6( const char *src, char *dst, size_t size );

#endif // WIN32

public:
#ifdef WIN32

  //! iovec structure for windows.
  typedef struct 
  {
    void  *iov_base;  //!< Base address.
    size_t iov_len;   //!< Number of bytes.
  } iovec;

  // A few type defines.
  typedef DWORD     pid_t;
  typedef SOCKET    sock_t;
  typedef int       socklen_t;
  
#else
  typedef ::iovec iovec;
  typedef ::pid_t     pid_t;
  typedef int       sock_t;
  typedef ::socklen_t        socklen_t;
  
#endif // WIN32

  //! Closes a socket.
  static int closesocket( sock_t socket );

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

  //! Retrieves a gid using a groupname.
  static int makeGidNumeric( const string & group );
  
  //! Retrieves an uid using an username.
  static int makeUidNumeric( const string & username );

  //! Writes a vector.
  static int writev( Utility::sock_t socket, const iovec *vector, size_t count );
  //! Returns a random number.
  static long int random( void );

  //! Sets the random seed.
  static void srandom( unsigned int seed );

  //! Drops the program's privileges.
  static void dropPrivs( int uid, int gid );
  
  //! Sets the socket into blocking mode.
  static bool setBlocking( Utility::sock_t socket );

  //! Sets the socket into non-blocking mode.
  static bool setNonBlocking( Utility::sock_t socket );
  
  //! Sleeps for a number of seconds.
  static unsigned int sleep( unsigned int seconds );
  
  //! Sleeps for a number of microseconds.
  static void usleep( unsigned long usec );

  static time_t timegm(struct tm *tm);
  
};


#endif // UTILITY_HH
