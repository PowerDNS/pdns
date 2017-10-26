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

pthread_once_t Logger::s_once;
pthread_key_t Logger::s_loggerKey;

Logger &theL(const string &pname)
{
  static Logger l("", LOG_DAEMON);
  if(!pname.empty())
    l.setName(pname);
  return l;
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
      tm=*localtime(&t);
      strftime(buffer,sizeof(buffer),"%b %d %H:%M:%S ", &tm);
    }

    static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    Lock l(&m); // the C++-2011 spec says we need this, and OSX actually does
    clog << string(buffer) + msg <<endl;
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

void Logger::initKey()
{
  if(pthread_key_create(&s_loggerKey, perThreadDestructor))
    unixDie("Creating thread key for logger");
}

Logger::Logger(const string &n, int facility)
{
  opened=false;
  flags=LOG_PID|LOG_NDELAY;
  d_facility=facility;
  d_loglevel=Logger::None;
  d_disableSyslog=false;
  consoleUrgency=Error;
  name=n;

  if(pthread_once(&s_once, initKey))
    unixDie("Creating thread key for logger");

  open();

}

Logger& Logger::operator<<(Urgency u)
{
  getPerThread()->d_urgency=u;
  return *this;
}

void Logger::perThreadDestructor(void* buf)
{
  PerThread* pt = (PerThread*) buf;
  delete pt;
}

Logger::PerThread* Logger::getPerThread()
{
  void *buf=pthread_getspecific(s_loggerKey);
  PerThread* ret;
  if(buf)
    ret = (PerThread*) buf;
  else {
    ret = new PerThread();
    pthread_setspecific(s_loggerKey, (void*)ret);
  }
  return ret;
}

Logger& Logger::operator<<(const string &s)
{
  PerThread* pt =getPerThread();
  pt->d_output.append(s);
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
  PerThread* pt =getPerThread();

  log(pt->d_output, pt->d_urgency);
  pt->d_output.clear();
  pt->d_urgency=Info;
  return *this;
}

Logger& Logger::operator<<(const DNSName &d)
{
  *this<<d.toLogString();

  return *this;
}

Logger& Logger::operator<<(const ComboAddress &ca)
{
  *this<<ca.toString();
  return *this;
}

