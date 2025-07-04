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

#include <mutex>
#include <sys/time.h>

#include "dolog.hh"

namespace dnsdist::logging
{
std::optional<std::ofstream> LoggingConfiguration::s_verboseStream{std::nullopt};
std::string LoggingConfiguration::s_structuredLevelPrefix{"prio"};
LoggingConfiguration::TimeFormat LoggingConfiguration::s_structuredTimeFormat{LoggingConfiguration::TimeFormat::Numeric};
bool LoggingConfiguration::s_structuredLogging{false};
bool LoggingConfiguration::s_logTimestamps{false};
bool LoggingConfiguration::s_syslog{true};

namespace
{
  const char* getTimeFormat()
  {
    if (!dnsdist::logging::LoggingConfiguration::getStructuredLogging()) {
      return "%b %d %H:%M:%S ";
    }

    auto format = dnsdist::logging::LoggingConfiguration::getStructuredLoggingTimeFormat();
    if (format == dnsdist::logging::LoggingConfiguration::TimeFormat::ISO8601) {
      return "%FT%H:%M:%S%z";
    }
    return nullptr;
  }
}

void logTime(std::ostream& stream)
{
  std::array<char, 50> buffer{""};

  if (LoggingConfiguration::getStructuredLogging() && LoggingConfiguration::getStructuredLoggingTimeFormat() == LoggingConfiguration::TimeFormat::Numeric) {
    struct timeval now{};
    gettimeofday(&now, nullptr);
    snprintf(buffer.data(), buffer.size(), "%lld.%03ld", static_cast<long long>(now.tv_sec), static_cast<long>(now.tv_usec / 1000));
  }
  else {
    const auto* timeFormat = getTimeFormat();
    if (timeFormat == nullptr) {
      return;
    }

    time_t now{0};
    time(&now);
    struct tm localNow{};
    localtime_r(&now, &localNow);

    {
      // strftime is not thread safe, it can access locale information
      static std::mutex mutex;
      auto lock = std::scoped_lock(mutex);

      if (strftime(buffer.data(), buffer.size(), timeFormat, &localNow) == 0) {
        buffer[0] = '\0';
      }
    }
  }

  if (dnsdist::logging::LoggingConfiguration::getStructuredLogging()) {
    stream << "ts=" << std::quoted(buffer.data()) << " ";
  }
  else {
    stream << buffer.data();
  }
}

}
