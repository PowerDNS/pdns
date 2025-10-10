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
#if defined(PDNS_AUTH)
#error This file should not be used by auth and related tools.
#endif
#include <array>
#include <fstream>
#include <iomanip>
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
   LOG_WARNING, LOG_ERR respectively. If verbose=false, vinfolog is a noop.
   More generically, dolog(someiostream, "Hello %s", stream) will log to someiostream

   This will happily print a string to %d! Doesn't do further format processing.
*/
template <typename O>
inline void dolog(O& outputStream, const char* str)
{
  outputStream << str;
}

template <typename O, typename T, typename... Args>
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
#ifdef DNSDIST
namespace dnsdist::logging
{
class LoggingConfiguration
{
public:
  enum class TimeFormat
  {
    Numeric,
    ISO8601
  };

  static void setSyslog(bool value = true)
  {
    s_syslog = value;
  }
  static void setStructuredLogging(bool value = true, std::string levelPrefix = "")
  {
    s_structuredLogging = value;
    if (value) {
      s_structuredLevelPrefix = levelPrefix.empty() ? "prio" : std::move(levelPrefix);
    }
  }
  static void setLogTimestamps(bool value = true)
  {
    s_logTimestamps = value;
  }
  static void setStructuredTimeFormat(TimeFormat format)
  {
    s_structuredTimeFormat = format;
  }
  static void setVerboseStream(std::ofstream&& stream)
  {
    s_verboseStream = std::move(stream);
  }
  static bool getSyslog()
  {
    return s_syslog;
  }
  static bool getLogTimestamps()
  {
    return s_logTimestamps;
  }
  static std::optional<std::ofstream>& getVerboseStream()
  {
    return s_verboseStream;
  }
  static bool getStructuredLogging()
  {
    return s_structuredLogging;
  }
  static const std::string& getStructuredLoggingLevelPrefix()
  {
    return s_structuredLevelPrefix;
  }

  static TimeFormat getStructuredLoggingTimeFormat()
  {
    return s_structuredTimeFormat;
  }

private:
  static std::optional<std::ofstream> s_verboseStream;
  static std::string s_structuredLevelPrefix;
  static TimeFormat s_structuredTimeFormat;
  static bool s_structuredLogging;
  static bool s_logTimestamps;
  static bool s_syslog;
};

extern void logTime(std::ostream& stream);
}
#endif

inline void setSyslogFacility(int facility)
{
  /* we always call openlog() right away at startup */
  closelog();
  openlog("dnsdist", LOG_PID | LOG_NDELAY, facility);
}

namespace
{
inline const char* syslogLevelToStr(int level)
{
  static constexpr std::array levelStrs{
    "Emergency",
    "Alert",
    "Critical",
    "Error",
    "Warning",
    "Notice",
    "Info",
    "Debug"};
  return levelStrs.at(level);
}
}

template <typename... Args>
void genlog(std::ostream& stream, [[maybe_unused]] int level, [[maybe_unused]] bool skipSyslog, const char* formatStr, const Args&... args)
{
  std::ostringstream str;
  dolog(str, formatStr, args...);

  auto output = str.str();

#ifdef DNSDIST
  if (!skipSyslog && dnsdist::logging::LoggingConfiguration::getSyslog()) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): syslog is what it is
    syslog(level, "%s", output.c_str());
  }

  if (dnsdist::logging::LoggingConfiguration::getLogTimestamps()) {
    dnsdist::logging::logTime(stream);
  }

  if (dnsdist::logging::LoggingConfiguration::getStructuredLogging()) {
    stream << dnsdist::logging::LoggingConfiguration::getStructuredLoggingLevelPrefix() << "=\"" << syslogLevelToStr(level) << "\" ";
    stream << "msg=" << std::quoted(output) << std::endl;
  }
  else {
    stream << output << std::endl;
  }
#else
  stream << output << std::endl;
#endif
}

template <typename... Args>
void verboselog(const char* formatStr, const Args&... args)
{
#ifdef DNSDIST
  if (auto& stream = dnsdist::logging::LoggingConfiguration::getVerboseStream()) {
    genlog(*stream, LOG_DEBUG, true, formatStr, args...);
  }
  else {
#endif /* DNSDIST */
    genlog(std::cout, LOG_DEBUG, false, formatStr, args...);
#ifdef DNSDIST
  }
#endif /* DNSDIST */
}

#ifdef DNSDIST
#include "dnsdist-configuration.hh"

#define vinfolog                                                          \
  if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose) \
  verboselog
#else
#define vinfolog \
  infolog
#endif

template <typename... Args>
void infolog(const char* formatStr, const Args&... args)
{
  genlog(std::cout, LOG_INFO, false, formatStr, args...);
}

template <typename... Args>
void warnlog(const char* formatStr, const Args&... args)
{
  genlog(std::cout, LOG_WARNING, false, formatStr, args...);
}

template <typename... Args>
void errlog(const char* formatStr, const Args&... args)
{
  genlog(std::cout, LOG_ERR, false, formatStr, args...);
}

#else // RECURSOR
#define vinfolog \
  if (false)     \
  infolog

template <typename... Args>
void infolog(const char* formatStr, const Args&... args)
{
  g_log << Logger::Info;
  dolog(g_log, formatStr, args...);
}

template <typename... Args>
void warnlog(const char* formatStr, const Args&... args)
{
  g_log << Logger::Warning;
  dolog(g_log, formatStr, args...);
}

template <typename... Args>
void errlog(const char* formatStr, const Args&... args)
{
  g_log << Logger::Error;
  dolog(g_log, formatStr, args...);
}

#endif
