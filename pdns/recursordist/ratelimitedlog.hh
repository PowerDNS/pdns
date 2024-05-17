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

#include "logger.hh"
#include "logging.hh"

namespace pdns
{
class RateLimitedLog
{
public:
  RateLimitedLog(time_t arg = 60) :
    d_period(arg) {}

  [[nodiscard]] uint32_t getCount() const
  {
    return d_count;
  }

  template <typename... Args>
  void log(Logr::log_t slog, const string& msg, const Args&... args)
  {
    uint32_t count{};
    if (doLog(count)) {
      SLOG(g_log << Logger::Error << msg << " created an exception" << endl,
           slog->info(Logr::Error, msg + " created an exception",
                      "ratelimitingSkipped", Logging::Loggable(count),
                      "exception", Logging::Loggable("other"), args...));
    };
  }
  template <typename... Args>
  void log(Logr::log_t slog, const string& msg, const std::exception& stdException, const Args&... args)
  {
    uint32_t count{};
    if (doLog(count)) {
      SLOG(g_log << Logger::Error << msg << " created an exception: " << except.what() << endl,
           slog->error(Logr::Error, stdException.what(), msg + " created an exception",
                       "ratelimitingSkipped", Logging::Loggable(count),
                       "exception", Logging::Loggable("std::exception"), args...));
    }
  }

  template <typename... Args>
  void log(Logr::log_t slog, const string& msg, const PDNSException& pdnsException, const Args&... args)
  {
    uint32_t count{};
    if (doLog(count)) {
      SLOG(g_log << Logger::Error << msg << " created an PDNSException: " << except.reason << endl,
           slog->error(Logr::Error, pdnsException.reason, msg + " created an exception",
                       "ratelimitingSkipped", Logging::Loggable(count),
                       "exception", Logging::Loggable("PDNSException"), args...));
    }
  }

private:
  [[nodiscard]] bool doLog(uint32_t& count)
  {
    std::lock_guard lock(d_mutex);
    time_t now = time(nullptr);
    if (d_last + d_period < now) {
      d_last = now;
      count = d_count;
      d_count = 0;
      return true;
    }
    count = d_count;
    d_count++;
    return false;
  }
  std::mutex d_mutex;
  time_t d_last{0};
  const time_t d_period;
  uint32_t d_count{0};
};
}
