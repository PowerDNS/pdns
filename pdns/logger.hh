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

#include <string>
#include <ctime>
#include <iostream>
#include <sstream>
#include <syslog.h>

#include "namespaces.hh"
#include "dnsname.hh"
#include "iputils.hh"

//! The Logger class can be used to log messages in various ways.
class Logger
{
public:
  Logger(const string &, int facility=LOG_DAEMON); //!< pass the identification you wish to appear in the log

  //! The urgency of a log message
  enum Urgency {All=32767,Alert=LOG_ALERT, Critical=LOG_CRIT, Error=LOG_ERR, Warning=LOG_WARNING,
                Notice=LOG_NOTICE,Info=LOG_INFO, Debug=LOG_DEBUG, None=-1};

  /** Log a message.
      \param msg Message you wish to log
      \param u Urgency of the message you wish to log
  */
  void log(const string &msg, Urgency u=Notice);

  void setFacility(int f){d_facility=f;open();} //!< Choose logging facility
  void setFlag(int f){flags|=f;open();} //!< set a syslog flag
  void setName(const string &);

  //! set lower limit of urgency needed for console display. Messages of this urgency, and higher, will be displayed
  void toConsole(Urgency);
  void setLoglevel( Urgency );

  void disableSyslog(bool d) {
    d_disableSyslog = d;
  }

  void setTimestamps(bool t) {
    d_timestamps = t;
  }

  void setPrefixed(bool p) {
    d_prefixed = p;
  }

  //! Log to a file.
  void toFile( const string & filename );
  
  void resetFlags(){flags=0;open();} //!< zero the flags
  /** Use this to stream to your log, like this:
      \code
      g_log<<"This is an informational message"<<endl; // logged at default loglevel (Info)
      g_log<<Logger::Warning<<"Out of diskspace"<<endl; // Logged as a warning 
      g_log<<"This is an informational message"<<endl; // logged AGAIN at default loglevel (Info)
      \endcode
  */
  Logger& operator<<(const char *s);
  Logger& operator<<(const string &s);   //!< log a string
  Logger& operator<<(const DNSName&); 
  Logger& operator<<(const ComboAddress&); //!< log an address
  Logger& operator<<(Urgency);    //!< set the urgency, << style

  // Using const & since otherwise SyncRes:: values induce (illegal) copies
  template<typename T> Logger & operator<<(const T & i) {
	ostringstream tmp;
	tmp<<i;
	*this<<tmp.str();
	return *this;
  }

  Logger& operator<<(std::ostream & (&)(std::ostream &)); //!< this is to recognise the endl, and to commit the log

private:
  struct PerThread
  {
    PerThread() : d_urgency(Info)
    {}
    string d_output;
    Urgency d_urgency;
  };
  PerThread& getPerThread();
  void open();

  static thread_local PerThread t_perThread;
  string name;
  int flags;
  int d_facility;
  Urgency d_loglevel;
  Urgency consoleUrgency;
  bool opened;
  bool d_disableSyslog;
  bool d_timestamps{true};
  bool d_prefixed{false};
};

Logger& getLogger();

#define g_log getLogger()

#ifdef VERBOSELOG
#define DLOG(x) x
#else
#define DLOG(x) ((void)0)
#endif
