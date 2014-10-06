/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011 PowerDNS.COM BV

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
#include <sys/select.h>

#ifdef NEED_INET_NTOP_PROTO
extern "C" {
const char *inet_ntop(int af, const void *src, char *dst, size_t cnt);
}
#endif


#include "namespaces.hh"

// Closes a socket.
int Utility::closesocket( Utility::sock_t socket )
{
  int ret=::close(socket);
  if(ret < 0 && errno == ECONNRESET) // see ticket 192, odd BSD behaviour
    return 0;
  if(ret < 0) 
    throw PDNSException("Error closing socket: "+stringerror());
  return ret;
}

// Connects to socket with timeout
int Utility::timed_connect( Utility::sock_t sock,
    const sockaddr *addr,
    Utility::socklen_t sockaddr_size,
    int timeout_sec,
    int timeout_usec )
{
  fd_set set;
  struct timeval timeout;
  int ret;

  timeout.tv_sec = timeout_sec;
  timeout.tv_usec = timeout_usec;

  FD_ZERO(&set);
  FD_SET(sock, &set);

  setNonBlocking(sock);

  if ((ret = connect (sock, addr, sockaddr_size)) < 0) {
    if (errno != EINPROGRESS)
      return ret;
  }

  ret = select(sock + 1, NULL, &set, NULL, &timeout);
  setBlocking(sock);

  return ret;
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

bool Utility::setCloseOnExec(sock_t sock)
{
  int flags=fcntl(sock,F_GETFD,0);    
  if(flags<0 || fcntl(sock, F_SETFD,flags|FD_CLOEXEC) <0)
    return false;
  return true;
}

const char *Utility::inet_ntop(int af, const char *src, char *dst, size_t size)
{
  return ::inet_ntop(af,src,dst,size);
}

unsigned int Utility::sleep(unsigned int sec)
{
  return ::sleep(sec);
}

void Utility::usleep(unsigned long usec)
{
  struct timespec ts;
  ts.tv_sec = usec / 1000000;
  ts.tv_nsec = (usec % 1000000) * 1000;
  // POSIX.1 recommends using nanosleep instead of usleep
  ::nanosleep(&ts, NULL); 
}


// Drops the program's group privileges.
void Utility::dropGroupPrivs( int uid, int gid )
{
  if(gid) {
    if(setgid(gid)<0) {
      theL()<<Logger::Critical<<"Unable to set effective group id to "<<gid<<": "<<stringerror()<<endl;
      exit(1);
    }
    else
      theL()<<Logger::Info<<"Set effective group id to "<<gid<<endl;

    struct passwd *pw=getpwuid(uid);
    if(!pw) {
      theL()<<Logger::Warning<<"Unable to determine user name for uid "<<uid<<endl;
      if (setgroups(0, NULL)<0) {
        theL()<<Logger::Critical<<"Unable to drop supplementary gids: "<<stringerror()<<endl;
        exit(1);
      }
    } else {
      if (initgroups(pw->pw_name, gid)<0) {
        theL()<<Logger::Critical<<"Unable to set supplementary groups: "<<stringerror()<<endl;
        exit(1);
      }
    }
  }
}


// Drops the program's user privileges.
void Utility::dropUserPrivs( int uid )
{
  if(uid) {
    if(setuid(uid)<0) {
      theL()<<Logger::Critical<<"Unable to set effective user id to "<<uid<<":  "<<stringerror()<<endl;
      exit(1);
    }
    else
      theL()<<Logger::Info<<"Set effective user id to "<<uid<<endl;
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
    errno=0;
    struct group *gr=getgrnam(group.c_str());
    if(!gr) {
      theL()<<Logger::Critical<<"Unable to look up gid of group '"<<group<<"': "<< (errno ? strerror(errno) : "not found") <<endl;
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
      theL()<<Logger::Critical<<"Unable to look up uid of user '"<<username<<"': "<< (errno ? strerror(errno) : "not found") <<endl;
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


// Writes a vector.
int Utility::writev(int socket, const iovec *vector, size_t count )
{
  return ::writev(socket,vector,count);
}

/* this is cut and pasted from dietlibc, gratefully copied! */
static int isleap(int year) {
  /* every fourth year is a leap year except for century years that are
   * not divisible by 400. */
  return (!(year%4) && ((year%100) || !(year%400)));
}

time_t Utility::timegm(struct tm *const t) 
{
  const static short spm[13] = /* days per month -- nonleap! */
  { 0,
    (31),
    (31+28),
    (31+28+31),
    (31+28+31+30),
    (31+28+31+30+31),
    (31+28+31+30+31+30),
    (31+28+31+30+31+30+31),
    (31+28+31+30+31+30+31+31),
    (31+28+31+30+31+30+31+31+30),
    (31+28+31+30+31+30+31+31+30+31),
    (31+28+31+30+31+30+31+31+30+31+30),
    (31+28+31+30+31+30+31+31+30+31+30+31),
  };

  time_t  day;
  time_t  i;
  time_t years = t->tm_year - 70;

  if (t->tm_sec>60) { t->tm_min += t->tm_sec/60; t->tm_sec%=60; }
  if (t->tm_min>60) { t->tm_hour += t->tm_min/60; t->tm_min%=60; }
  if (t->tm_hour>60) { t->tm_mday += t->tm_hour/60; t->tm_hour%=60; }
  if (t->tm_mon>11) { t->tm_year += t->tm_mon/12; t->tm_mon%=12; }
 
  while (t->tm_mday>spm[1+t->tm_mon]) {
    if (t->tm_mon==1 && isleap(t->tm_year+1900)) {
      if (t->tm_mon==31+29) break;
      --t->tm_mday;
    }
    t->tm_mday-=spm[t->tm_mon];
    ++t->tm_mon;
    if (t->tm_mon>11) { t->tm_mon=0; ++t->tm_year; }
  }

  if (t->tm_year < 70)
    return (time_t) -1;
  /* Days since 1970 is 365 * number of years + number of leap years since 1970 */
  day  = years * 365 + (years + 1) / 4;

  /* After 2100 we have to subtract 3 leap years for every 400 years
     This is not intuitive. Most mktime implementations do not support
     dates after 2059, anyway, so we might leave this out for its
     bloat. */
  if ((years -= 131) >= 0) {
    years /= 100;
    day -= (years >> 2) * 3 + 1;
    if ((years &= 3) == 3) years--;
    day -= years;
  }

  day += t->tm_yday = spm [t->tm_mon] + t->tm_mday-1 + ( isleap (t->tm_year+1900)  &  (t->tm_mon > 1) );

  /* day is now the number of days since 'Jan 1 1970' */
  i = 7;
  t->tm_wday = (day + 4) % i;                        /* Sunday=0, Monday=1, ..., Saturday=6 */

  i = 24;
  day *= i;
  i = 60;
  return ((day + t->tm_hour) * i + t->tm_min) * i + t->tm_sec;
}

// we have our own gmtime_r because the one in GNU libc violates POSIX/SuS
// by supporting leap seconds when TZ=right/UTC
void Utility::gmtime_r(const time_t *timer, struct tm *tmbuf) {

  int monthdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  int days = *timer / 86400;
  int leapdays = (days + 671) / 1461;
  int leapydays = (days + 365) / 1461;

  tmbuf->tm_hour = *timer / 3600 % 24;
  tmbuf->tm_min = *timer / 60 % 60;
  tmbuf->tm_sec = *timer % 60;

  tmbuf->tm_year = (days - leapdays) / 365 + 70;
  tmbuf->tm_yday = days - leapydays - (tmbuf->tm_year - 70) * 365 + 1;

  tmbuf->tm_mon = 0;
  tmbuf->tm_mday = tmbuf->tm_yday;
  monthdays[1] += isleap(tmbuf->tm_year + 1900);
  while (monthdays[tmbuf->tm_mon] < tmbuf->tm_mday) {
    tmbuf->tm_mday -= monthdays[tmbuf->tm_mon];
    tmbuf->tm_mon++;
  }

  tmbuf->tm_wday = (days + 4) % 7; // Day 0 is magic thursday ;)
  tmbuf->tm_isdst = 0;
}
