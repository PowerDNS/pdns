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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <mutex>

#include "logger.hh"
#include "misc.hh"
#ifndef RECURSOR
#include "statbag.hh"
extern StatBag S;
#endif
#include "namespaces.hh"

thread_local Logger::PerThread Logger::t_perThread;
const std::string Logger::s_defaultTimestampFormat = "%m-%dT%H:%M:%S";

Logger& getLogger()
{
  /* Since the Logger can be called very early, we need to make sure
     that the relevant parts are initialized no matter what, which is tricky
     because we can't easily control the initialization order, especially with
     built-in backends.
     t_perThread is thread_local, so it will be initialized when first accessed,
     but we need to make sure that the object itself is initialized, and making
     it a function-level static variable achieves that, because it will be
     initialized the first time we enter this function at the very last.
  */
  static Logger log("", LOG_DAEMON);
  return log;
}

void Logger::log(const string &msg, Urgency u) noexcept
{
  const static string empty;
#ifndef RECURSOR
  bool mustAccount(false);
#endif
  if(u<=consoleUrgency) {
    string prefix;
    if (d_prefixed) {
      switch(u) {
        case All:
          prefix = "[all] ";
          break;
        case Alert:
          prefix = "[ALERT] ";
          break;
        case Critical:
          prefix = "[CRITICAL] ";
          break;
        case Error:
          prefix = "[ERROR] ";
          break;
        case Warning:
          prefix = "[WARNING] ";
          break;
        case Notice:
          prefix = "[NOTICE] ";
          break;
        case Info:
          prefix = "[INFO] ";
          break;
        case Debug:
          prefix = "[DEBUG] ";
          break;
        case None:
          prefix = "[none] ";
          break;
      }
    }

    static std::mutex m;
    std::lock_guard<std::mutex> l(m); // the C++-2011 spec says we need this, and OSX actually does
    if (d_timestamps) {
      const std::string& ts = toTimestampStringMill();
      clog << ts << prefix << msg << endl;
    } else {
      clog << prefix << msg << endl;
    }
#ifndef RECURSOR
    mustAccount=true;
#endif
  }
  if( u <= d_loglevel && !d_disableSyslog ) {
    syslog(u,"%s",msg.c_str());
#ifndef RECURSOR
    mustAccount=true;
#endif
  }

#ifndef RECURSOR
  if(mustAccount) {
      try {
        S.ringAccount("logmessages",msg);
      }
      catch (const runtime_error& e) {
        cerr << e.what() << endl;
      }
  }
#endif
}

void Logger::open()
{
  if(opened)
    closelog();
  openlog(name.c_str(),flags,d_facility);
  opened=true;
}

void Logger::setName(const string &_name)
{
  name = _name;
  open();
}

Logger::Logger(const string &n, int facility) :
  name(n), flags(LOG_PID|LOG_NDELAY), d_facility(facility), d_loglevel(Logger::None),
  consoleUrgency(Error), opened(false), d_disableSyslog(false)
{
  open();
}

Logger& Logger::operator<<(ostream & (&)(ostream &))
{
  PerThread& pt = getPerThread();

  log(pt.d_output, pt.d_urgency);
  pt.d_output.clear();
  pt.d_urgency=Info;
  return *this;
}

const std::string& Logger::toTimestampString(time_t t)
{
  PerThread& pt = getPerThread();
  pt.d_timeBuffer.resize(64);  // must be >= 26 + 4 for ctime_r fallback and fractional seconds
  struct tm tm;
  if (strftime(&pt.d_timeBuffer.at(0), pt.d_timeBuffer.capacity(), d_timestampFormat.c_str(), localtime_r(&t, &tm)) != 0) {
    pt.d_timeBuffer.resize(strlen(pt.d_timeBuffer.c_str()));
    return pt.d_timeBuffer;
  }
  ctime_r(&t, &pt.d_timeBuffer.at(0));
  pt.d_timeBuffer.resize(strlen(pt.d_timeBuffer.c_str()));
  pt.d_timeBuffer.pop_back(); // zap newline
  return pt.d_timeBuffer;
}

const std::string& Logger::toTimestampStringMill()
{
  struct timespec tms;
  clock_gettime(CLOCK_REALTIME, &tms);
  toTimestampString(tms.tv_sec); // modifies pt.d_timeBuffer
  char buf[6];
  snprintf(buf, sizeof(buf), ".%03ld ", tms.tv_nsec / 1000000);
  PerThread& pt = getPerThread();
  pt.d_timeBuffer .append(buf);
  return pt.d_timeBuffer;
}
