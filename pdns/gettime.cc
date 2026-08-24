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

#include "config.h"
#include "gettime.hh"

#ifdef HAVE_CLOCK_GETTIME
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

int gettime(struct timespec* timespec, bool needRealTime)
{
  return clock_gettime(needRealTime ? CLOCK_REALTIME : CLOCK_MONOTONIC, timespec);
}

#else
#include <sys/time.h>
#include <cstddef>

int gettime(struct timespec* timespec, bool /* needRealTime */)
{
  struct timeval timeval{};

  int ret = gettimeofday(&timeval, nullptr);
  if (ret < 0) {
    return ret;
  }
  timespec->tv_sec = timeval.tv_sec;
  timespec->tv_nsec = timeval.tv_usec * 1000L;
  return ret;
}

#endif
