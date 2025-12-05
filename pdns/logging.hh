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

#include "config.h"

#if defined(RECURSOR) || defined(DNSDIST)

#include <map>
#include <memory>
#include <string>
#include <sstream>

#include "logr.hh"
#include "dnsname.hh"
#include "iputils.hh"

namespace Logging
{

struct Entry
{
  std::optional<std::string> name; // name parts joined with '.'
  std::string message; // message as send to log call
  std::optional<std::string> error; // error if .Error() was called
  struct timeval d_timestamp; // time of entry generation
  std::map<std::string, std::string> values; // key-value pairs
  size_t level; // level at which this was logged
  Logr::Priority d_priority; // (syslog) priority)
};

// Warning: some meta-programming is going on.  We define helper
// templates that can be used to see if specific string output
// functions are available.  If so, we use those instead of << into an
// ostringstream. Note that this decision happens compile time.
// Some hints taken from https://www.cppstories.com/2019/07/detect-overload-from-chars/
// (I could not get function templates with enabled_if<> to work in this case)
//
// Default: std::string(T) is not available
template <typename T, typename = void>
struct is_to_string_available : std::false_type
{
};

// If std::string(T) is available this template is used
template <typename T>
struct is_to_string_available<T, std::void_t<decltype(std::to_string(std::declval<T>()))>> : std::true_type
{
};

// Same mechanism for t.toLogString() and t.toStructuredLogString()
template <typename T, typename = void>
struct is_toLogString_available : std::false_type
{
};

template <typename T>
struct is_toLogString_available<T, std::void_t<decltype(std::declval<T>().toLogString())>> : std::true_type
{
};

template <typename T, typename = void>
struct is_toStructuredLogString_available : std::false_type
{
};

template <typename T>
struct is_toStructuredLogString_available<T, std::void_t<decltype(std::declval<T>().toStructuredLogString())>> : std::true_type
{
};

template <typename T, typename = void>
struct is_toString_available : std::false_type
{
};

template <typename T>
struct is_toString_available<T, std::void_t<decltype(std::declval<T>().toString())>> : std::true_type
{
};

const char* toTimestampStringMilli(const struct timeval& tval, std::array<char, 64>& buf, const std::string& format = "%s");

template <typename T>
struct Loggable : public Logr::Loggable
{
  const T& _t;
  Loggable(const T& v) :
    _t(v)
  {
  }
  std::string to_string() const
  {
    if constexpr (std::is_same_v<T, std::string>) {
      return _t;
    }
    else if constexpr (is_toStructuredLogString_available<T>::value) {
      return _t.toStructuredLogString();
    }
    else if constexpr (is_toLogString_available<T>::value) {
      return _t.toLogString();
    }
    else if constexpr (is_toString_available<T>::value) {
      return _t.toString();
    }
    else if constexpr (is_to_string_available<T>::value) {
      return std::to_string(_t);
    }
    else {
      std::ostringstream oss;
      oss << _t;
      return oss.str();
    }
  }
};

template <typename T>
struct IterLoggable : public Logr::Loggable
{
  const T& _t1;
  const T& _t2;
  IterLoggable(const T& v1, const T& v2) :
    _t1(v1), _t2(v2)
  {
  }
  std::string to_string() const
  {
    std::ostringstream oss;
    bool first = true;
    for (auto i = _t1; i != _t2; i++) {
      if (!first) {
        oss << ' ';
      }
      else {
        first = false;
      }
      oss << *i;
    }
    return oss.str();
  }
};

using EntryLogger = void (*)(const Entry&);

class Logger : public Logr::Logger, public std::enable_shared_from_this<const Logger>
{
public:
  bool enabled(Logr::Priority) const override;

  void info(const std::string& msg) const override;
  void info(Logr::Priority, const std::string& msg) const override;
  void error(int err, const std::string& msg) const override;
  void error(const std::string& err, const std::string& msg) const override;
  void error(Logr::Priority, int err, const std::string& msg) const override;
  void error(Logr::Priority, const std::string& err, const std::string& msg) const override;

  std::shared_ptr<Logr::Logger> v(size_t level) const override;
  std::shared_ptr<Logr::Logger> withValues(const std::map<std::string, std::string>& values) const override;
  std::shared_ptr<Logr::Logger> withName(const std::string& name) const override;

  static std::shared_ptr<Logger> create(EntryLogger callback);
  static std::shared_ptr<Logger> create(EntryLogger callback, const std::string& name);

  Logger(EntryLogger callback);
  Logger(EntryLogger callback, std::optional<std::string> name);
  Logger(std::shared_ptr<const Logger> parent, std::optional<std::string> name, size_t verbosity, size_t lvl, EntryLogger callback);
  ~Logger() override;

  size_t getVerbosity() const;
  void setVerbosity(size_t verbosity);

private:
  void logMessage(const std::string& msg, const std::optional<std::string>& err) const;
  void logMessage(const std::string& msg, Logr::Priority prio, const std::optional<std::string>& err) const;
  std::shared_ptr<const Logger> getptr() const;

  std::shared_ptr<const Logger> _parent{nullptr};
  EntryLogger _callback;
  std::optional<std::string> _name;
  std::map<std::string, std::string> _values;
  // current Logger's level. the higher the more verbose.
  size_t _level{0};
  // verbosity settings. messages with level higher's than verbosity won't appear
  size_t _verbosity{0};
};
}

#if !defined(DNSDIST)
extern std::shared_ptr<Logging::Logger> g_slog;

// Prefer structured logging? Since Recursor 5.1.0, we always do. We keep a const, to allow for
// step-by-step removal of old style logging code (for recursor-only code). Note that code shared
// with auth still uses old-style, so the SLOG calls should remain for shared code.
constexpr bool g_slogStructured = true;

// A helper macro to switch between old-style logging and new-style (structured logging)
// A typical use:
//
// SLOG(g_log<<Logger::Warning<<"Unable to parse configuration file '"<<configname<<"'"<<endl,
//      startupLog->error("No such file", "Unable to parse configuration file", "config_file", Logging::Loggable(configname));
//
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SLOG(oldStyle, slogCall) \
  do {                           \
    slogCall;                    \
  } while (0)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERBOSESLOG(nonStructured, structured)

#else // DNSdist
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SLOG(nonStructured, structured)             \
  do {                                              \
    if (dnsdist::logging::doStructuredLogging()) {  \
      structured;                                   \
    }                                               \
    else {                                          \
      nonStructured;                                \
    }                                               \
  }                                                 \
  while (0)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERBOSESLOG(nonStructured, structured)  \
  do {                                          \
    if (dnsdist::logging::doVerboseLogging()) { \
      SLOG(nonStructured, structured);          \
    }                                           \
  }                                             \
  while (0)

#endif /* ! DNSDIST */

#else // !RECURSOR && !DNSDIST

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define SLOG(oldStyle, slogCall) \
  do {                           \
    oldStyle;                    \
  } while (0)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define VERBOSESLOG(nonStructured, structured)

#endif // !RECURSOR && !DNSDIST
