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

void Logger::log(const string &msg, Urgency u)
{
#ifndef RECURSOR
  bool mustAccount(false);
#endif
  if(u<=consoleUrgency) {
    char buffer[50] = "";
    if (d_timestamps) {
      struct tm tm;
      time_t t;
      time(&t);
      localtime_r(&t, &tm);
      strftime(buffer,sizeof(buffer),"%b %d %H:%M:%S ", &tm);
    }

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

    static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    Lock l(&m); // the C++-2011 spec says we need this, and OSX actually does
    clog << string(buffer) + prefix + msg <<endl;
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
  if(mustAccount)
    S.ringAccount("logmessages",msg);
#endif
}

void Logger::setLoglevel( Urgency u )
{
  d_loglevel = u;
}
  

void Logger::toConsole(Urgency u)
{
  consoleUrgency=u;
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
  name=_name;
  open();
}

Logger::Logger(const string &n, int facility) :
  name(n), flags(LOG_PID|LOG_NDELAY), d_facility(facility), d_loglevel(Logger::None),
  consoleUrgency(Error), opened(false), d_disableSyslog(false)
{
  open();

}

Logger& Logger::operator<<(Urgency u)
{
  getPerThread().d_urgency=u;
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

