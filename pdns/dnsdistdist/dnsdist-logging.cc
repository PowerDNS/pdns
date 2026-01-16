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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */

#include "dnsdist-logging.hh"

#include <iomanip>
#include <set>
#include <stdexcept>

#include "ext/json11/json11.hpp"

#include "config.h"
#if defined(HAVE_SYSTEMD)
#include <systemd/sd-journal.h>
#endif /* HAVE_SYSTEMD */

#include "dnsdist-configuration.hh"

namespace dnsdist::logging
{
static const char* convertTime(const timeval& tval, std::array<char, 64>& buffer)
{
  auto format = dnsdist::configuration::getImmutableConfiguration().d_structuredLoggingTimeFormat;
  if (format == dnsdist::configuration::TimeFormat::ISO8601) {
    time_t now{};
    time(&now);
    struct tm localNow{};
    localtime_r(&now, &localNow);

    {
      // strftime is not thread safe, it can access locale information
      static std::mutex mutex;
      auto lock = std::scoped_lock(mutex);

      if (strftime(buffer.data(), buffer.size(), "%FT%H:%M:%S%z", &localNow) == 0) {
        buffer[0] = '\0';
      }
    }

    return buffer.data();
  }
  return Logging::toTimestampStringMilli(tval, buffer);
}

#if defined(HAVE_SYSTEMD)
static void loggerSDBackend(const Logging::Entry& entry)
{
  static const std::set<std::string, CIStringComparePOSIX> special{
    "message",
    "message_id",
    "priority",
    "code_file",
    "code_line",
    "code_func",
    "errno",
    "invocation_id",
    "user_invocation_id",
    "syslog_facility",
    "syslog_identifier",
    "syslog_pid",
    "syslog_timestamp",
    "syslog_raw",
    "documentation",
    "tid",
    "unit",
    "user_unit",
    "object_pid"};

  // We need to keep the string in mem until sd_journal_sendv has been called
  std::vector<std::string> strings;
  auto appendKeyAndVal = [&strings](const string& key, const string& value) {
    strings.emplace_back(key + "=" + value);
  };
  appendKeyAndVal("MESSAGE", entry.message);
  if (entry.error) {
    appendKeyAndVal("ERROR", entry.error.value());
  }
  appendKeyAndVal("LEVEL", std::to_string(entry.level));
  appendKeyAndVal("PRIORITY", std::to_string(entry.d_priority));
  if (dnsdist::configuration::getImmutableConfiguration().d_structuredLoggingUseServerID) {
    appendKeyAndVal("INSTANCE", dnsdist::configuration::getCurrentRuntimeConfiguration().d_server_id);
  }
  if (entry.name) {
    appendKeyAndVal("SUBSYSTEM", entry.name.value());
  }
  std::array<char, 64> timebuf{};
  appendKeyAndVal("TIMESTAMP", convertTime(entry.d_timestamp, timebuf));
  for (const auto& value : entry.values) {
    if (value.first.at(0) == '_' || special.count(value.first) != 0) {
      string key{"PDNS"};
      key.append(value.first);
      appendKeyAndVal(toUpper(key), value.second);
    }
    else {
      appendKeyAndVal(toUpper(value.first), value.second);
    }
  }

  std::vector<iovec> iov;
  iov.reserve(strings.size());
  for (const auto& str : strings) {
    // iovec has no 2 arg constructor, so make it explicit
    iov.emplace_back(iovec{const_cast<void*>(reinterpret_cast<const void*>(str.data())), str.size()}); // NOLINT: it's the API
  }
  sd_journal_sendv(iov.data(), static_cast<int>(iov.size()));
}
#endif /* HAVE_SYSTEMD */

static void loggerJSONBackend(const Logging::Entry& entry)
{
  std::array<char, 64> timebuf{};
  json11::Json::object json = {
    {"msg", entry.message},
    {"level", std::to_string(entry.level)},
    {"ts", convertTime(entry.d_timestamp, timebuf)},
  };

  if (entry.error) {
    json.emplace("error", entry.error.value());
  }

  if (entry.name) {
    json.emplace("subsystem", entry.name.value());
  }

  if (entry.d_priority != 0) {
    json.emplace("priority", std::to_string(entry.d_priority));
  }

  if (dnsdist::configuration::getImmutableConfiguration().d_structuredLoggingUseServerID) {
    json.emplace("instance", dnsdist::configuration::getCurrentRuntimeConfiguration().d_server_id);
  }

  for (auto const& value : entry.values) {
    json.emplace(value.first, value.second);
  }

  static thread_local std::string out;
  out.clear();
  json11::Json doc(std::move(json));
  doc.dump(out);
  std::cerr << out << std::endl;
}

static void loggerBackend(const Logging::Entry& entry)
{
  static thread_local std::stringstream buf;

  buf.str("");
  buf << "msg=" << std::quoted(entry.message);
  if (entry.error) {
    buf << " error=" << std::quoted(entry.error.value());
  }

  if (entry.name) {
    buf << " subsystem=" << std::quoted(entry.name.value());
  }
  buf << " level=" << std::quoted(std::to_string(entry.level));
  if (entry.d_priority != 0) {
    buf << " prio=" << std::quoted(Logr::Logger::toString(entry.d_priority));
  }
  if (dnsdist::configuration::getImmutableConfiguration().d_structuredLoggingUseServerID) {
    buf << " instance=" << std::quoted(dnsdist::configuration::getCurrentRuntimeConfiguration().d_server_id);
  }

  std::array<char, 64> timebuf{};
  buf << " ts=" << std::quoted(convertTime(entry.d_timestamp, timebuf));
  for (auto const& value : entry.values) {
    buf << " ";
    buf << value.first << "=" << std::quoted(value.second);
  }

  std::cout << buf.str() << endl;
}

static std::shared_ptr<Logging::Logger> s_topLogger{nullptr};

void setup(const std::string& backend)
{
  std::shared_ptr<Logging::Logger> logger;
  if (backend == "systemd-journal") {
#if defined(HAVE_SYSTEMD)
    if (int fileDesc = sd_journal_stream_fd("dnsdist", LOG_DEBUG, 0); fileDesc >= 0) {
      logger = Logging::Logger::create(loggerSDBackend);
      close(fileDesc);
    }
#endif
    if (logger == nullptr) {
      cerr << "Requested structured logging to systemd-journal, but it is not available" << endl;
    }
  }
  else if (backend == "json") {
    logger = Logging::Logger::create(loggerJSONBackend);
    if (logger == nullptr) {
      cerr << "JSON logging requested but it is not available" << endl;
    }
  }

  if (logger == nullptr) {
    logger = Logging::Logger::create(loggerBackend);
  }

  if (logger) {
    std::atomic_store_explicit(&s_topLogger, logger, std::memory_order_release);
  }
}

std::shared_ptr<const Logr::Logger> getTopLogger(const std::string_view& subsystem)
{
  auto topLogger = std::atomic_load_explicit(&s_topLogger, std::memory_order_acquire);
  if (!topLogger) {
    throw std::runtime_error("Trying to access the top-level logger before logging has been setup");
  }

  return topLogger->withName(std::string(subsystem));
}

bool doVerboseLogging()
{
  return dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose;
}

bool doStructuredLogging()
{
  return dnsdist::configuration::getImmutableConfiguration().d_structuredLogging;
}

}
