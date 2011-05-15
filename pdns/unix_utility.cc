/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

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
#include "ahuexception.hh"
#include "logger.hh"
#include "misc.hh"
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>

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
    throw AhuException("Error closing socket: "+stringerror());
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
  ::usleep(usec);
}


// Drops the program's privileges.
void Utility::dropPrivs( int uid, int gid )
{
  if(gid) {
    if(setgid(gid)<0) {
      theL()<<Logger::Critical<<"Unable to set effective group id to "<<gid<<": "<<stringerror()<<endl;
      exit(1);
    }
    else
      theL()<<Logger::Info<<"Set effective group id to "<<gid<<endl;

  }

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
  if (t->tm_mon>12) { t->tm_year += t->tm_mon/12; t->tm_mon%=12; }
 
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

  /* After 2100 we have to substract 3 leap years for every 400 years
     This is not intuitive. Most mktime implementations do not support
     dates after 2059, anyway, so we might leave this out for it's
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

