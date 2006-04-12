/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

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

#ifndef RECURSOR
#include "statbag.hh"
extern StatBag S;
#endif

using namespace std;

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

  if(u<=consoleUrgency) {// Sep 14 06:52:09
    char buffer[50];
    strftime(buffer,sizeof(buffer),"%b %d %H:%M:%S ", &tm);
    clog<<buffer;
    clog <<msg <<endl;
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

Logger::Logger(const string &n, int facility)
{
  opened=false;
  flags=LOG_PID|LOG_NDELAY;
  d_facility=facility;
  consoleUrgency=Error;
  name=n;
  pthread_mutex_init(&lock,0);
  open();

}

Logger& Logger::operator<<(Urgency u)
{
  pthread_mutex_lock(&lock);

  d_outputurgencies[pthread_self()]=u;

  pthread_mutex_unlock(&lock);
  return *this;
}

Logger& Logger::operator<<(const string &s)
{
  pthread_mutex_lock(&lock);

  if(!d_outputurgencies.count(pthread_self())) // default urgency
    d_outputurgencies[pthread_self()]=Info;

  //  if(d_outputurgencies[pthread_self()]<=(unsigned int)consoleUrgency) // prevent building strings we won't ever print
      d_strings[pthread_self()].append(s);

  pthread_mutex_unlock(&lock);
  return *this;
}

Logger& Logger::operator<<(int i)
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
  // *this<<" ("<<(int)d_outputurgencies[pthread_self()]<<", "<<(int)consoleUrgency<<")";
  pthread_mutex_lock(&lock);

  log(d_strings[pthread_self()], d_outputurgencies[pthread_self()]);
  d_strings.erase(pthread_self());  
  d_outputurgencies.erase(pthread_self());

  pthread_mutex_unlock(&lock);
  return *this;
}
