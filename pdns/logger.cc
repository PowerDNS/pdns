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
#include <ostream>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iomanip>
#include <mutex>

#include "logger.hh"
#include "misc.hh"
#ifndef RECURSOR
#include "statbag.hh"
extern StatBag S;
#endif
#include "namespaces.hh"

thread_local Logger::PerThread Logger::t_perThread;

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

void Logger::log(const string& msg, Urgency u) noexcept
{
#ifndef RECURSOR
  bool mustAccount(false);
#endif
  if (u <= consoleUrgency) {
    std::array<char, 50> buffer{};
    buffer[0] = '\0';
    if (d_timestamps) {
      struct tm tm;
      time_t t;
      time(&t);
      localtime_r(&t, &tm);
      if (strftime(buffer.data(), buffer.size(), "%b %d %H:%M:%S ", &tm) == 0) {
        buffer[0] = '\0';
      }
    }

    string severity;
    if (d_prefixed) {
      switch (u) {
      case All:
        severity = "All";
        break;
      case Alert:
        severity = "Alert";
        break;
      case Critical:
        severity = "Critical";
        break;
      case Error:
        severity = "Error";
        break;
      case Warning:
        severity = "Warning";
        break;
      case Notice:
        severity = "Notice";
        break;
      case Info:
        severity = "Info";
        break;
      case Debug:
        severity = "Debug";
        break;
      case None:
        severity = "None";
        break;
      }
    }

    static std::mutex mutex;
    std::lock_guard<std::mutex> lock(mutex); // the C++-2011 spec says we need this, and OSX actually does

    // To avoid issuing multiple syscalls, we write the complete line to clog with a single << call.
    // For that we need a buffer allocated, we might want to use writev(2) one day to avoid that.
    ostringstream line;
    line << buffer.data();
    if (d_prefixed) {
      line << "msg=" << std::quoted(msg) << " prio=" << std::quoted(severity) << endl;
    }
    else {
      line << msg << endl;
    }
    clog << line.str() << std::flush;
#ifndef RECURSOR
    mustAccount = true;
#endif
  }
  if (u <= d_loglevel && !d_disableSyslog) {
    syslog(u, "%s", msg.c_str());
#ifndef RECURSOR
    mustAccount = true;
#endif
  }

#ifndef RECURSOR
  if (mustAccount) {
    try {
      S.ringAccount("logmessages", msg);
    }
    catch (const runtime_error& e) {
      cerr << e.what() << endl;
    }
  }
#endif
}

void Logger::setLoglevel(Urgency u)
{
  d_loglevel = u;
}

void Logger::toConsole(Urgency u)
{
  consoleUrgency = u;
}

void Logger::open()
{
  if (opened)
    closelog();
  openlog(name.c_str(), flags, d_facility);
  opened = true;
}

void Logger::setName(const string& _name)
{
  name = _name;
  open();
}

Logger::Logger(string n, int facility) :
  name(std::move(n)), flags(LOG_PID | LOG_NDELAY), d_facility(facility)
{
  open();
}

Logger& Logger::operator<<(Urgency u)
{
  getPerThread().d_urgency = u;
  return *this;
}

Logger::PerThread& Logger::getPerThread()
{
  return t_perThread;
}

Logger& Logger::operator<<(const string& s)
{
  PerThread& pt = getPerThread();
  pt.d_output.append(s);
  return *this;
}

Logger& Logger::operator<<(const char* s)
{
  *this << string(s);
  return *this;
}

Logger& Logger::operator<<(ostream& (&)(ostream&))
{
  PerThread& pt = getPerThread();

  log(pt.d_output, pt.d_urgency);
  pt.d_output.clear();
  pt.d_urgency = Info;
  return *this;
}

Logger& Logger::operator<<(const DNSName& d)
{
  *this << d.toLogString();

  return *this;
}

#if defined(PDNS_AUTH)
Logger& Logger::operator<<(const ZoneName& d)
{
  *this << d.toLogString();

  return *this;
}
#endif

Logger& Logger::operator<<(const ComboAddress& ca)
{
  *this << ca.toLogString();
  return *this;
}

Logger& Logger::operator<<(const SockaddrWrapper& sockaddr)
{
  *this << sockaddr.toString();
  return *this;
}

void addTraceTS(const timeval& start, ostringstream& str)
{
  const auto& content = str.str();
  if (content.empty() || content.back() == '\n') {
    timeval time{};
    gettimeofday(&time, nullptr);
    auto elapsed = time - start;
    auto diff = elapsed.tv_sec * 1000000 + static_cast<time_t>(elapsed.tv_usec);
    str << diff << ' ';
  }
}
