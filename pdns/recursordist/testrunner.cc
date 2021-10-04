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
#define BOOST_TEST_DYN_LINK

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include <iostream>
#include <dnsrecords.hh>
#include <iomanip>
#include "logger.hh"
#include "logging.hh"

static std::string s_timestampFormat = "%s";

static const char* toTimestampStringMilli(const struct timeval& tv, char* buf, size_t sz)

{
  struct tm tm;
  size_t len = strftime(buf, sz, s_timestampFormat.c_str(), localtime_r(&tv.tv_sec, &tm));
  if (len == 0) {
    len = snprintf(buf, sz, "%lld", static_cast<long long>(tv.tv_sec));
  }

  snprintf(buf + len, sz - len, ".%03ld", static_cast<long>(tv.tv_usec) / 1000);
  return buf;
}

static void loggerBackend(const Logging::Entry& entry)
{
  static thread_local std::stringstream buf;

  buf.str("");
  buf << "msg=" << std::quoted(entry.message);
  if (entry.error) {
    buf << " oserror=" << std::quoted(entry.error.get());
  }

  if (entry.name) {
    buf << " subsystem=" << std::quoted(entry.name.get());
  }
  buf << " level=" << entry.level;
  if (entry.d_priority) {
    buf << " prio=" << static_cast<int>(entry.d_priority);
  }
  char timebuf[64];
  buf << " ts=" << std::quoted(toTimestampStringMilli(entry.d_timestamp, timebuf, sizeof(timebuf)));
  for (auto const& v : entry.values) {
    buf << " ";
    buf << v.first << "=" << std::quoted(v.second);
  }
  Logger::Urgency u = entry.d_priority ? Logger::Urgency(entry.d_priority) : Logger::Info;
  g_log << u << buf.str() << endl;
}

static bool init_unit_test()
{
  g_slog = Logging::Logger::create(loggerBackend);
  reportAllTypes();
  return true;
}

// entry point:
int main(int argc, char* argv[])
{
  return boost::unit_test::unit_test_main(&init_unit_test, argc, argv);
}
