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
#include "logger.hh"
#include "misc.hh"
#ifndef RECURSOR
#include "statbag.hh"
extern StatBag S;
#endif
#include "lock.hh"
#include "namespaces.hh"

Logger g_log("", LOG_DAEMON);
thread_local Logger::PerThread Logger::t_perThread;

static Logger::Config& getLoggerConfig()
{
  /* Since the Logger can be called very early, we need to make sure
     that the relevant parts are initialized no matter what, which is tricky
     because we can't easily control the initialization order, especially with
     built-in backends.
     t_perThread is thread_local, so it will be initialized when first accessed,
     but we need to make sure that the rest of the config is too, and making
     it a function-level static variable achieves that, because it will be
     initialized the first time we enter this function at the very last.
  */
  static Logger::Config config;
  return config;
}

void Logger::log(const string &msg, Urgency u)
{
#ifndef RECURSOR
  bool mustAccount(false);
#endif
  const auto& config = getLoggerConfig();

  if(u <= config.consoleUrgency) {
    char buffer[50] = "";
    if (config.d_timestamps) {
      struct tm tm;
      time_t t;
      time(&t);
      tm=*localtime(&t);
      strftime(buffer,sizeof(buffer),"%b %d %H:%M:%S ", &tm);
    }

    string prefix;
    if (config.d_prefixed) {
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

    static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    Lock l(&m); // the C++-2011 spec says we need this, and OSX actually does
    clog << string(buffer) + prefix + msg <<endl;
#ifndef RECURSOR
    mustAccount=true;
#endif
  }
  if( u <= config.d_loglevel && !config.d_disableSyslog ) {
    syslog(u,"%s",msg.c_str());
#ifndef RECURSOR
    mustAccount=true;
#endif
  }

#ifndef RECURSOR
  if(mustAccount)
    S.ringAccount("logmessages",msg);
#endif
}

void Logger::setLoglevel( Urgency u )
{
  auto& config = getLoggerConfig();
  config.d_loglevel = u;
}
  
void Logger::setFacility(int f)
{
  auto& config = getLoggerConfig();

  config.d_facility = f;
  open();
}

void Logger::setFlag(int f)
{
  auto& config = getLoggerConfig();
  config. flags |= f;
  open();
}

void Logger::disableSyslog(bool d)
{
  auto& config = getLoggerConfig();

  config.d_disableSyslog = d;
}

void Logger::setTimestamps(bool t)
{
  auto& config = getLoggerConfig();
  config.d_timestamps = t;
}

void Logger::setPrefixed(bool p)
{
  auto& config = getLoggerConfig();
  config.d_prefixed = p;
}

void Logger::resetFlags()
{
  auto& config = getLoggerConfig();

  config.flags = 0;
  open();
}

void Logger::toConsole(Urgency u)
{
  auto& config = getLoggerConfig();
  config.consoleUrgency = u;
}

void Logger::open()
{
  auto& config = getLoggerConfig();
  if(config.opened) {
    closelog();
  }

  openlog(config.name.c_str(), config.flags, config.d_facility);
  config.opened = true;
}

void Logger::setName(const string &_name)
{
  auto& config = getLoggerConfig();
  config.name = _name;
  open();
}

Logger::Logger(const string &n, int facility)
{
  auto& config = getLoggerConfig();
  config.name = n;
  config.flags = LOG_PID|LOG_NDELAY;
  config.d_facility = facility;

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

Logger& Logger::operator<<(const string &s)
{
  PerThread& pt = getPerThread();
  pt.d_output.append(s);
  return *this;
}

Logger& Logger::operator<<(const char *s)
{
  *this<<string(s);
  return *this;
}

Logger& Logger::operator<<(int i)
{
  ostringstream tmp;
  tmp<<i;

  *this<<tmp.str();

  return *this;
}

Logger& Logger::operator<<(double i)
{
  ostringstream tmp;
  tmp<<i;
  *this<<tmp.str();
  return *this;
}

Logger& Logger::operator<<(unsigned int i)
{
  ostringstream tmp;
  tmp<<i;

  *this<<tmp.str();

  return *this;
}

Logger& Logger::operator<<(unsigned long i)
{
  ostringstream tmp;
  tmp<<i;

  *this<<tmp.str();

  return *this;
}

Logger& Logger::operator<<(unsigned long long i)
{
  ostringstream tmp;
  tmp<<i;

  *this<<tmp.str();

  return *this;
}

Logger& Logger::operator<<(long i)
{
  ostringstream tmp;
  tmp<<i;

  *this<<tmp.str();

  return *this;
}

Logger& Logger::operator<<(ostream & (&)(ostream &))
{
  PerThread& pt = getPerThread();

  log(pt.d_output, pt.d_urgency);
  pt.d_output.clear();
  pt.d_urgency=Info;
  return *this;
}

Logger& Logger::operator<<(const DNSName &d)
{
  *this<<d.toLogString();

  return *this;
}

Logger& Logger::operator<<(const ComboAddress &ca)
{
  *this<<ca.toLogString();
  return *this;
}

