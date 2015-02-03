/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "logger.hh"
#include "config.h"
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
  struct tm tm;
  time_t t;
  time(&t);
  tm=*localtime(&t);

  if(u<=consoleUrgency) {
    char buffer[50];
    strftime(buffer,sizeof(buffer),"%b %d %H:%M:%S ", &tm);
    static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
    Lock l(&m); // the C++-2011 spec says we need this, and OSX actually does
    clog << string(buffer) + msg <<endl;
  }
  if( u <= d_loglevel ) {
#ifndef RECURSOR
    S.ringAccount("logmessages",msg);
#endif
    syslog(u,"%s",msg.c_str());
  }
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
