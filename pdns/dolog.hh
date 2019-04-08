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
#pragma once
#include <iostream>
#include <sstream>
#include <syslog.h>

/* This file is intended not to be metronome specific, and is simple example of C++2011
   variadic templates in action.

   The goal is rapid easy to use logging to console & syslog. 

   Usage: 
          string address="localhost";
          vinfolog("Got TCP connection from %s", remote);
          infolog("Bound to %s port %d", address, port);
          warnlog("Query took %d milliseconds", 1232.4); // yes, %d
          errlog("Unable to bind to %s: %s", ca.toStringWithPort(), strerr(errno));

   Will log to stdout. Will syslog in any case with LOG_INFO,
   LOG_WARNING, LOG_ERR respectively. If g_verbose=false, vinfolog is a noop.
   More generically, dolog(someiostream, "Hello %s", stream) will log to someiostream

   This will happily print a string to %d! Doesn't do further format processing.
*/

inline void dolog(std::ostream& os, const char*s)
{
  os<<s;
}

template<typename T, typename... Args>
void dolog(std::ostream& os, const char* s, T value, Args... args)
{
  while (*s) {
    if (*s == '%') {
      if (*(s + 1) == '%') {
	++s;
      }
      else {
	os << value;
	s += 2;
	dolog(os, s, args...); 
	return;
      }
    }
    os << *s++;
  }    
}

extern bool g_verbose;
extern bool g_syslog;

inline void setSyslogFacility(int facility)
{
  /* we always call openlog() right away at startup */
  closelog();
  openlog("dnsdist", LOG_PID|LOG_NDELAY, facility);
}

template<typename... Args>
void genlog(int level, const char* s, Args... args)
{
  std::ostringstream str;
  dolog(str, s, args...);
  if(g_syslog)
    syslog(level, "%s", str.str().c_str());
  std::cout<<str.str()<<std::endl;
}


#define vinfolog if(g_verbose)infolog

template<typename... Args>
void infolog(const char* s, Args... args)
{
  genlog(LOG_INFO, s, args...);
}

template<typename... Args>
void warnlog(const char* s, Args... args)
{
  genlog(LOG_WARNING, s, args...);
}

template<typename... Args>
void errlog(const char* s, Args... args)
{
  genlog(LOG_ERR, s, args...);
}

