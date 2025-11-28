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
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>

#include <array>
#include <iostream>
#include <dnsrecords.hh>
#include <iomanip>
#include "logger.hh"
#include "logging.hh"
#include "arguments.hh"
#include "dns_random.hh"

static std::string s_timestampFormat = "%s";

static void loggerBackend(const Logging::Entry& entry)
{
  static thread_local std::stringstream buf;

  buf.str("");
  buf << "msg=" << std::quoted(entry.message);
  if (entry.error) {
    buf << " oserror=" << std::quoted(entry.error.value());
  }

  if (entry.name) {
    buf << " subsystem=" << std::quoted(entry.name.value());
  }
  buf << " level=" << entry.level;
  if (entry.d_priority != 0) {
    buf << " prio=" << static_cast<int>(entry.d_priority);
  }
  std::array<char, 64> timebuf{};
  buf << " ts=" << std::quoted(Logging::toTimestampStringMilli(entry.d_timestamp, timebuf));
  for (auto const& val : entry.values) {
    buf << " ";
    buf << val.first << "=" << std::quoted(val.second);
  }
  Logger::Urgency urgency = entry.d_priority != 0 ? Logger::Urgency(entry.d_priority) : Logger::Info;
  g_log << urgency << buf.str() << endl;
}

static bool init_unit_test()
{
  // Force init while we are still unthreaded
  dns_random_uint16();
  g_slog = Logging::Logger::create(loggerBackend);
  reportAllTypes();
  return true;
}

// entry point:
int main(int argc, char* argv[])
{
  setenv("BOOST_TEST_RANDOM", "1", 1); // NOLINT(concurrency-mt-unsafe)
  return boost::unit_test::unit_test_main(&init_unit_test, argc, argv);
}
