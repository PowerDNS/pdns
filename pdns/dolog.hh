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
#include <array>
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
template<typename O>
inline void dolog(O& outputStream, const char* str)
{
  outputStream << str;
}

template<typename O, typename T, typename... Args>
void dolog(O& outputStream, const char* formatStr, T value, const Args&... args)
{
  while (*formatStr) {
    if (*formatStr == '%') {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
      if (*(formatStr + 1) == '%') {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
	++formatStr;
      }
      else {
	outputStream << value;
        // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
	formatStr += 2;
	dolog(outputStream, formatStr, args...);
	return;
      }
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    outputStream << *formatStr++;
  }
}

#if !defined(RECURSOR)
//NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
extern bool g_verbose;
//NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
extern bool g_syslog;
#ifdef DNSDIST
//NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
extern bool g_logtimestamps;
//NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
extern std::optional<std::ofstream> g_verboseStream;
#endif

inline void setSyslogFacility(int facility)
{
  /* we always call openlog() right away at startup */
  closelog();
  openlog("dnsdist", LOG_PID|LOG_NDELAY, facility);
}

template<typename... Args>
void genlog(std::ostream& stream, int level, bool doSyslog, const char* formatStr, const Args&... args)
{
  std::ostringstream str;
  dolog(str, formatStr, args...);

  auto output = str.str();

  if (doSyslog) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): syslog is what it is
    syslog(level, "%s", output.c_str());
  }

#ifdef DNSDIST
  if (g_logtimestamps) {
    std::array<char,50> buffer{""};
    time_t now{0};
    time(&now);
    struct tm localNow{};
    localtime_r(&now, &localNow);
    if (strftime(buffer.data(), buffer.size(), "%b %d %H:%M:%S ", &localNow) == 0) {
      buffer[0] = '\0';
    }
    stream << buffer.data();
  }
#endif

  stream << output << std::endl;
}

template<typename... Args>
void verboselog(const char* formatStr, const Args&... args)
{
#ifdef DNSDIST
  if (g_verboseStream) {
    genlog(*g_verboseStream, LOG_DEBUG, false, formatStr, args...);
  }
  else {
#endif /* DNSDIST */
    genlog(std::cout, LOG_DEBUG, g_syslog, formatStr, args...);
#ifdef DNSDIST
  }
#endif /* DNSDIST */
}

#define vinfolog if (g_verbose) verboselog

template<typename... Args>
void infolog(const char* formatStr, const Args&... args)
{
  genlog(std::cout, LOG_INFO, g_syslog, formatStr, args...);
}

template<typename... Args>
void warnlog(const char* formatStr, const Args&... args)
{
  genlog(std::cout, LOG_WARNING, g_syslog, formatStr, args...);
}

template<typename... Args>
void errlog(const char* formatStr, const Args&... args)
{
  genlog(std::cout, LOG_ERR, g_syslog, formatStr, args...);
}

#else // RECURSOR
#define g_verbose 0
#define vinfolog if(g_verbose)infolog

template<typename... Args>
void infolog(const char* formatStr, const Args&... args)
{
  g_log << Logger::Info;
  dolog(g_log, formatStr, args...);
}

template<typename... Args>
void warnlog(const char* formatStr, const Args&... args)
{
  g_log << Logger::Warning;
  dolog(g_log, formatStr, args...);
}

template<typename... Args>
void errlog(const char* formatStr, const Args&... args)
{
  g_log << Logger::Error;
  dolog(g_log, formatStr, args...);
}

#endif
