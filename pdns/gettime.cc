#include "gettime.hh"
#include "config.h"

#ifdef HAVE_CLOCK_GETTIME
#include <time.h>

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

int gettime(struct timespec *tp, bool needRealTime)
{
	return clock_gettime(needRealTime ? CLOCK_REALTIME : CLOCK_MONOTONIC_RAW, tp);
}

#else
#include <sys/time.h>

int gettime(struct timespec *tp, bool needRealTime)
{
	struct timeval tv;

	int ret = gettimeofday(&tv, NULL);
	if(ret < 0) return ret;

	tp->tv_sec = tv.tv_sec;
	tp->tv_nsec = tv.tv_usec * 1000;
	return ret;
}

#endif