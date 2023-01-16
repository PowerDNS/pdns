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
#pragma once
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include "config.h"
#if !defined(RECURSOR)
#include <syslog.h>
#else
#include "logger.hh"
#endif // RECURSOR


/* This file is intended not to be metronome specific, and is simple example of C++2011
   variadic templates in action.

   The goal is rapid easy to use logging to console & syslog. 

   Usage: 
          string address="localhost";
          vinfolog("Got TCP connection from %s", remote);
          infolog("Bound to %s port %d", address, port);
          warnlog("Query took %d milliseconds", 1232.4); // yes, %d
          errlog("Unable to bind to %s: %s", ca.toStringWithPort(), strerr(errno));

   Will log to stdout. Will syslog in any case with LOG_INFO,
   LOG_WARNING, LOG_ERR respectively. If g_verbose=false, vinfolog is a noop.
   More generically, dolog(someiostream, "Hello %s", stream) will log to someiostream

   This will happily print a string to %d! Doesn't do further format processing.
*/

#if !defined(RECURSOR)
inline void dolog(std::ostream& os, const char*s)
{
  os<<s;
}

template<typename T, typename... Args>
void dolog(std::ostream& os, const char* s, T value, Args... args)
{
  while (*s) {
    if (*s == '%') {
      if (*(s + 1) == '%') {
	++s;
      }
      else {
	os << value;
	s += 2;
	dolog(os, s, args...);
	return;
      }
    }
    os << *s++;
  }
}

extern bool g_verbose;
extern bool g_syslog;
#ifdef DNSDIST
extern bool g_logtimestamps;
extern std::optional<std::ofstream> g_verboseStream;
#endif

inline void setSyslogFacility(int facility)
{
  /* we always call openlog() right away at startup */
  closelog();
  openlog("dnsdist", LOG_PID|LOG_NDELAY, facility);
}

template<typename... Args>
void genlog(std::ostream& stream, int level, bool doSyslog, const char* s, Args... args)
{
  std::ostringstream str;
  dolog(str, s, args...);

  auto output = str.str();

  if (doSyslog) {
    syslog(level, "%s", output.c_str());
  }

#ifdef DNSDIST
  if (g_logtimestamps) {
    char buffer[50] = "";
    struct tm tm;
    time_t t;
    time(&t);
    localtime_r(&t, &tm);
    if (strftime(buffer, sizeof(buffer), "%b %d %H:%M:%S ", &tm) == 0) {
      buffer[0] = '\0';
    }
    stream<<buffer;
  }
#endif

  stream<<output<<std::endl;
}

template<typename... Args>
void verboselog(const char* s, Args... args)
{
#ifdef DNSDIST
  if (g_verboseStream) {
    genlog(*g_verboseStream, LOG_DEBUG, false, s, args...);
  }
  else {
#endif /* DNSDIST */
    genlog(std::cout, LOG_DEBUG, g_syslog, s, args...);
#ifdef DNSDIST
  }
#endif /* DNSDIST */
}

#define vinfolog if (g_verbose) verboselog

template<typename... Args>
void infolog(const char* s, Args... args)
{
  genlog(std::cout, LOG_INFO, g_syslog, s, args...);
}

template<typename... Args>
void warnlog(const char* s, Args... args)
{
  genlog(std::cout, LOG_WARNING, g_syslog, s, args...);
}

template<typename... Args>
void errlog(const char* s, Args... args)
{
  genlog(std::cout, LOG_ERR, g_syslog, s, args...);
}

#else // RECURSOR

#define g_verbose 0

inline void dolog(Logger::Urgency u, const char* s)
{
  g_log << u << s << std::endl;
}

inline void dolog(const char* s)
{
  g_log << s << std::endl;
}

template<typename T, typename... Args>
void dolog(Logger::Urgency u, const char* s, T value, Args... args)
{
  g_log << u;
  while (*s) {
    if (*s == '%') {
      if (*(s + 1) == '%') {
	++s;
      }
      else {
	g_log << value;
	s += 2;
	dolog(s, args...);
	return;
      }
    }
    g_log << *s++;
  }
}

#define vinfolog if(g_verbose)infolog

template<typename... Args>
void infolog(const char* s, Args... args)
{
  dolog(Logger::Info, s, args...);
}

template<typename... Args>
void warnlog(const char* s, Args... args)
{
  dolog(Logger::Warning, s, args...);
}

template<typename... Args>
void errlog(const char* s, Args... args)
{
  dolog(Logger::Error, s, args...);
}

#endif
