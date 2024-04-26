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
#include "logging.hh"
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

  ret = select(sock + 1, nullptr, &set, nullptr, &timeout);
  setBlocking(sock);

  return ret;
}



void Utility::setBindAny([[maybe_unused]] int af, [[maybe_unused]] sock_t sock)
{
  const int one = 1;

  (void) one; // avoids 'unused var' warning on systems that have none of the defines checked below
#ifdef IP_FREEBIND
  if (setsockopt(sock, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one)) < 0) {
    int err = errno;
    SLOG(g_log<<Logger::Warning<<"Warning: IP_FREEBIND setsockopt failed: "<<stringerror(err)<<endl,
         g_slog->withName("runtime")->error(Logr::Warning, err, "Warning: IP_FREEBIND setsockopt failed"));
  }
#endif

#ifdef IP_BINDANY
  if (af == AF_INET)
    if (setsockopt(sock, IPPROTO_IP, IP_BINDANY, &one, sizeof(one)) < 0) {
      int err = errno;
      SLOG(g_log<<Logger::Warning<<"Warning: IP_BINDANY setsockopt failed: "<<stringerror(err)<<endl,
           g_slog->withName("runtime")->error(Logr::Warning, err, "Warning: IP_BINDANY setsockopt failed"));
    }
#endif
#ifdef IPV6_BINDANY
  if (af == AF_INET6) {
    if (setsockopt(sock, IPPROTO_IPV6, IPV6_BINDANY, &one, sizeof(one)) < 0) {
      int err = errno;
      SLOG(g_log<<Logger::Warning<<"Warning: IPV6_BINDANY setsockopt failed: "<<stringerror(err)<<endl,
           g_slog->withName("runtime")->error(Logr::Warning, err, "Warning: IPV6_BINDANY setsockopt failed"));
    }
  }
#endif
#ifdef SO_BINDANY
  if (setsockopt(sock, SOL_SOCKET, SO_BINDANY, &one, sizeof(one)) < 0) {
    int err = errno;
    SLOG(g_log<<Logger::Warning<<"Warning: SO_BINDANY setsockopt failed: "<<stringerror(err)<<endl,
         g_slog->withName("runtime")->error(Logr::Warning, err, "Warning: SO_BINDANY setsockopt failed"));
  }
#endif
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
  ::nanosleep(&ts, nullptr);
}


// Drops the program's group privileges.
void Utility::dropGroupPrivs( uid_t uid, gid_t gid )
{
  if(gid && gid != getegid()) {
    if(setgid(gid)<0) {
      int err = errno;
      SLOG(g_log<<Logger::Critical<<"Unable to set effective group id to "<<gid<<": "<<stringerror(err)<<endl,
           g_slog->withName("runtime")->error(Logr::Critical, err, "Unable to set effective group id", "gid", Logging::Loggable(gid)));
      exit(1);
    }
    else {
      SLOG(g_log<<Logger::Info<<"Set effective group id to "<<gid<<endl,
           g_slog->withName("runtime")->info(Logr::Info, "Set effective group id", "gid", Logging::Loggable(gid)));
    }
    struct passwd *pw=getpwuid(uid);
    if(!pw) {
      SLOG(g_log<<Logger::Warning<<"Unable to determine user name for uid "<<uid<<endl,
           g_slog->withName("runtime")->info(Logr::Warning, "Unable to determine user name", "uid", Logging::Loggable(uid)));
      if (setgroups(0, nullptr)<0) {
        int err = errno;
        SLOG(g_log<<Logger::Critical<<"Unable to drop supplementary gids: "<<stringerror(err)<<endl,
             g_slog->withName("runtime")->error(Logr::Critical, err, "Unable to drop supplementary gids"));
        exit(1);
      }
    } else {
      if (initgroups(pw->pw_name, gid)<0) {
        int err = errno;
        SLOG(g_log<<Logger::Critical<<"Unable to set supplementary groups: "<<stringerror(err)<<endl,
             g_slog->withName("runtime")->error(Logr::Critical, err, "Unable to set supplementary groups"));
        exit(1);
      }
    }
  }
}


// Drops the program's user privileges.
void Utility::dropUserPrivs( uid_t uid )
{
  if(uid && uid != geteuid()) {
    if(setuid(uid)<0) {
      int err = errno;
      SLOG(g_log<<Logger::Critical<<"Unable to set effective user id to "<<uid<<": "<<stringerror(err)<<endl,
           g_slog->withName("runtime")->error(Logr::Critical, err, "Unable to set effective user id", "uid", Logging::Loggable(uid)));
      exit(1);
    }
    else {
      SLOG(g_log<<Logger::Info<<"Set effective user id to "<<uid<<endl,
           g_slog->withName("runtime")->info(Logr::Info, "Set effective user", "uid", Logging::Loggable(uid)));
    }
  }
}


// Returns the current process id.
Utility::pid_t Utility::getpid( )
{
  return ::getpid();
}


// Returns the current time.
int Utility::gettimeofday( struct timeval *tv, void * /* tz */)
{
  return ::gettimeofday(tv, nullptr);
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
  // coverity[store_truncates_time_t]
  t->tm_wday = (day + 4) % i;                        /* Sunday=0, Monday=1, ..., Saturday=6 */

  i = 24;
  day *= i;
  i = 60;
  return ((day + t->tm_hour) * i + t->tm_min) * i + t->tm_sec;
}
