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
#include <string>
#include <memory>
#include <map>

// Minimal logging API based on https://github.com/go-logr/logr

namespace Logr
{
struct Loggable
{
  Loggable() = default;
  Loggable(const Loggable&) = delete;
  Loggable(Loggable&&) = delete;
  Loggable& operator=(const Loggable&) = delete;
  Loggable& operator=(Loggable&&) = delete;
  virtual ~Loggable() = default;
  [[nodiscard]] virtual std::string to_string() const = 0;
};

// In addition to level which specifies the amount of detail and is
// structured so that a derived logger always has a higher level
// than its parent we also have a priority/urgency field that maps
// to the same field of the old logger which in turns has a direct
// mapping to syslog priority. This is done to make it easier to
// move step by step to structured logging. We consider both level
// and priority to select which messages are logged, and a backend
// can further use priority to pass to syslog.

enum Priority : uint8_t
{
  Absent = 0,
  Alert = 1,
  Critical = 2,
  Error = 3,
  Warning = 4,
  Notice = 5,
  Info = 6,
  Debug = 7
};

class Logger
{
public:
  Logger() = default;
  Logger(const Logger&) = delete;
  Logger(Logger&&) = delete;
  Logger& operator=(const Logger&) = delete;
  Logger& operator=(Logger&&) = delete;
  virtual ~Logger() = default;

  // Enabled tests whether this Logger is enabled.  For example, commandline
  // flags might be used to set the logging verbosity and disable some info
  // logs.
  [[nodiscard]] virtual bool enabled(Priority) const = 0;

  static std::string toString(Priority arg)
  {
    const std::array<std::string, 8> names = {"Absent", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"};
    auto prio = static_cast<unsigned int>(arg);
    if (prio >= names.size()) {
      return "?";
    }
    return names.at(prio);
  }
  // Info logs a non-error message with the given key/value pairs as context.
  //
  // The msg argument should be used to add some constant description to
  // the log line.  The key/value pairs can then be used to add additional
  // variable information.  The key/value pairs should alternate string
  // keys and arbitrary values.
  virtual void info(const std::string& msg) const = 0;
  virtual void info(Logr::Priority, const std::string& msg) const = 0;

  template <typename... Args>
  void info(const std::string& msg, const std::string& key, const Loggable& value, const Args&... args) const
  {
    auto logger = this->withValues(key, value, args...);
    logger->info(msg);
  }

  template <typename... Args>
  void info(Priority prio, const std::string& msg, const std::string& key, const Loggable& value, const Args&... args) const
  {
    auto logger = this->withValues(key, value, args...);
    logger->info(prio, msg);
  }

  // Error logs an error, with the given message and key/value pairs as context.
  // It functions similarly to calling Info with the "error" named value, but may
  // have unique behavior, and should be preferred for logging errors (see the
  // package documentations for more information).
  //
  // The msg field should be used to add context to any underlying error,
  // while the err field should be used to attach the actual error that
  // triggered this log line, if present.
  virtual void error(const std::string& err, const std::string& msg) const = 0;
  virtual void error(int err, const std::string& msg) const = 0;
  virtual void error(Logr::Priority, const std::string& err, const std::string& msg) const = 0;
  virtual void error(Logr::Priority, int err, const std::string& msg) const = 0;

  template <typename... Args>
  void error(const std::string& err, const std::string& msg, const std::string& key, const Loggable& value, const Args&... args) const
  {
    auto logger = this->withValues(key, value, args...);
    logger->error(Logr::Absent, err, msg);
  }

  template <typename... Args>
  void error(int err, const std::string& msg, const std::string& key, const Loggable& value, const Args&... args) const
  {
    auto logger = this->withValues(key, value, args...);
    logger->error(Logr::Absent, err, msg);
  }

  template <typename... Args>
  void error(Priority prio, const std::string& err, const std::string& msg, const std::string& key, const Loggable& value, const Args&... args) const
  {
    auto logger = this->withValues(key, value, args...);
    logger->error(prio, err, msg);
  }

  template <typename... Args>
  void error(Priority prio, int err, const std::string& msg, const std::string& key, const Loggable& value, const Args&... args) const
  {
    auto logger = this->withValues(key, value, args...);
    logger->error(prio, err, msg);
  }

  // V returns an Logger value for a specific verbosity level, relative to
  // this Logger.  In other words, V values are additive.  V higher verbosity
  // level means a log message is less important.  It's illegal to pass a log
  // level less than zero.
  [[nodiscard]] virtual std::shared_ptr<Logger> v(size_t level) const = 0;

  template <typename... Args>
  std::shared_ptr<Logger> withValues(const std::string& key, const Loggable& value, const Args&... args) const
  {
    std::map<std::string, std::string> map = {};
    this->mapArguments(map, key, value, args...);
    return this->withValues(map);
  }

  // WithValues adds some key-value pairs of context to a logger.
  // See Info for documentation on how key/value pairs work.
  [[nodiscard]] virtual std::shared_ptr<Logger> withValues(const std::map<std::string, std::string>& values) const = 0;

  // WithName adds a new element to the logger's name.
  // Successive calls with WithName continue to append
  // suffixes to the logger's name.  It's strongly recommended
  // that name segments contain only letters, digits, and hyphens
  // (see the package documentation for more information).
  [[nodiscard]] virtual std::shared_ptr<Logger> withName(const std::string& name) const = 0;

private:
  template <typename... Args>
  void mapArguments(std::map<std::string, std::string>& map, const std::string& key, const Loggable& value, const Args&... args) const
  {
    map.emplace(key, value.to_string());
    mapArguments(map, args...);
  }

  void mapArguments(std::map<std::string, std::string>& /* map */) const {}
};

using log_t = const std::shared_ptr<Logger>&;
}
