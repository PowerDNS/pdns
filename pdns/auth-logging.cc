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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#ifdef HAVE_SYSTEMD
#include <systemd/sd-journal.h>
#endif

#include "ext/json11/json11.hpp"

#include "arguments.hh"
#include "auth-logging.hh"

bool g_slogStructured{false};
static Logger::Urgency s_logUrgency;

// Default backend
static void loggerBackend(const Logging::Entry& entry)
{
  static thread_local std::stringstream buf;

  // First map SL priority to syslog's Urgency
  Logger::Urgency urg = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (urg > s_logUrgency) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Not that lower Urgency means higher number.
    return;
  }
  buf.str("");
  buf << "msg=" << std::quoted(entry.message);
  if (entry.error) {
    buf << " error=" << std::quoted(entry.error.value());
  }

  if (entry.name) {
    buf << " subsystem=" << std::quoted(entry.name.value());
  }
  if (entry.d_priority != 0) {
    buf << " prio=" << std::quoted(Logr::Logger::toString(entry.d_priority));
  }

  std::array<char, 64> timebuf{};
  buf << " ts=" << std::quoted(Logging::toTimestampStringMilli(entry.d_timestamp, timebuf));
  for (auto const& value : entry.values) {
    buf << " ";
    buf << value.first << "=" << std::quoted(value.second);
  }

  g_log << urg << buf.str() << endl;
}

// journald backend
#ifdef HAVE_SYSTEMD
static void loggerSDBackend(const Logging::Entry& entry)
{
  static const std::set<std::string, CIStringComparePOSIX> special = {
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

  // First map SL priority to syslog's Urgency
  Logger::Urgency urgency = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (urgency > s_logUrgency) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Note that lower Urgency means higher number.
    return;
  }
  // We need to keep the string in mem until sd_journal_sendv has been called
  std::vector<std::string> strings;
  auto appendKeyAndVal = [&strings](const string& key, const string& value) {
    strings.emplace_back(key + "=" + value);
  };
  appendKeyAndVal("MESSAGE", entry.message);
  if (entry.error) {
    appendKeyAndVal("ERROR", entry.error.value());
  }
  appendKeyAndVal("PRIORITY", std::to_string(entry.d_priority));
  if (entry.name) {
    appendKeyAndVal("SUBSYSTEM", entry.name.value());
  }
  std::array<char, 64> timebuf{};
  appendKeyAndVal("TIMESTAMP", Logging::toTimestampStringMilli(entry.d_timestamp, timebuf));
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
#endif

// JSON backend
static void loggerJSONBackend(const Logging::Entry& entry)
{
  // First map SL priority to syslog's Urgency
  Logger::Urgency urg = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  if (urg > s_logUrgency) {
    // We do not log anything if the Urgency of the message is lower than the requested loglevel.
    // Note that lower Urgency means higher number.
    return;
  }

  std::array<char, 64> timebuf{};
  json11::Json::object json = {
    {"msg", entry.message},
    {"ts", Logging::toTimestampStringMilli(entry.d_timestamp, timebuf)},
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

  for (auto const& value : entry.values) {
    json.emplace(value.first, value.second);
  }

  static thread_local std::string out;
  out.clear();
  json11::Json doc(std::move(json));
  doc.dump(out);
  cerr << out << endl;
}

void setupLogging()
{
  s_logUrgency = (Logger::Urgency)(::arg().asNum("loglevel"));

  if (!::arg()["logging-facility"].empty()) {
    int val = logFacilityToLOG(::arg().asNum("logging-facility"));
    if (val >= 0) {
      g_log.setFacility(val);
    }
    else {
      g_log << Logger::Error << "Unknown logging facility " << ::arg().asNum("logging-facility") << endl;
    }
  }
  g_log.setLoglevel(s_logUrgency);
  g_log.toConsole(s_logUrgency);
  g_log.disableSyslog(::arg().mustDo("disable-syslog"));
  g_log.setTimestamps(::arg().mustDo("log-timestamp"));

  g_slogStructured = ::arg().mustDo("logging-structured");
  if (g_slogStructured) {
    const auto& loggingBackend = ::arg()["structured-logging-backend"];
    if (loggingBackend == "systemd-journal") {
#ifdef HAVE_SYSTEMD
      if (int fileDesc = sd_journal_stream_fd("pdns-authoritative", LOG_DEBUG, 0); fileDesc >= 0) {
        g_slog = Logging::Logger::create(loggerSDBackend);
        close(fileDesc);
      }
#endif
      if (g_slog == nullptr) {
        g_log << Logger::Error << "Requested structured logging to systemd-journal, but it is not available" << endl;
      }
    }
    else if (loggingBackend == "json") {
      g_slog = Logging::Logger::create(loggerJSONBackend);
      if (g_slog == nullptr) {
        g_log << Logger::Error << "JSON logging requested but it is not available" << endl;
      }
    }
    g_slog = Logging::Logger::create(loggerBackend);
  }
  else {
    g_log.setPrefixed(::arg().mustDo("loglevel-show"));
  }
}

void registerLoggingSettings(Logger::Urgency defaultLoglevel)
{
  ::arg().set("disable-syslog", "Disable logging to syslog, useful when running inside a supervisor that logs stderr") = "no";
  ::arg().set("log-timestamp", "Print timestamps in log lines") = "yes";
  ::arg().set("logging-facility", "Log under a specific facility") = "";
  ::arg().setSwitch("logging-structured", "Produce structured log messages") = "no";
  ::arg().set("loglevel", "Amount of logging. Higher is more. Do not set below 3") = std::to_string(defaultLoglevel);
  ::arg().setSwitch("loglevel-show", "Include log level indicator in log output") = "no";
  ::arg().set("structured-logging-backend", "Backend to use when structured logging is enabled") = "default";
}
