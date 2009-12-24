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
#ifndef LOGGER_HH
#define LOGGER_HH
/* (C) 2002 POWERDNS.COM BV */

#include <string>
#include <map>
#include <ctime>
#include <iostream>
#include <sstream>
#include "config.h"
#ifndef WIN32
# include <syslog.h>
#include <pthread.h>

#else
# define WINDOWS_LEAN_AND_MEAN
# include <windows.h>
typedef int pthread_mutex_t;
typedef int pthread_t;
#endif // WIN32

using namespace std;

//! The Logger class can be used to log messages in various ways.
class Logger
{
public:
#ifndef WIN32
  Logger(const string &, int facility=LOG_DAEMON); //!< pass the identification you wish to appear in the log

  //! The urgency of a log message
  enum Urgency {All=99999,NTLog=12345,Alert=LOG_ALERT, Critical=LOG_CRIT, Error=LOG_ERR, Warning=LOG_WARNING,
        	Notice=LOG_NOTICE,Info=LOG_INFO, Debug=LOG_DEBUG, None=-1};

#else
  Logger( const string &, int facility = 0 ); //!< pass the identification you wish to appear in the log

  //! The urgency of a log message
  enum Urgency 
  {
    All     = 99999,
    NTLog   = 12345,
    Alert   = EVENTLOG_ERROR_TYPE, 
    Critical= EVENTLOG_ERROR_TYPE, 
    Error   = EVENTLOG_ERROR_TYPE, 
    Warning = EVENTLOG_WARNING_TYPE,
        	Notice  = EVENTLOG_INFORMATION_TYPE,
    Info    = EVENTLOG_INFORMATION_TYPE, 
    Debug   = EVENTLOG_INFORMATION_TYPE, 
    None    = -1
  };

  void toNTLog( void );

private:
  //! Handle used to communicate with the event log.
  HANDLE m_eventLogHandle;

  //! Log file handle.
  FILE *m_pLogFile;

  //! Log current message to the NT log?
  map< pthread_t, bool > m_toNTLog;

public:

#endif // WIN32

  /** Log a message. 
      \param msg Message you wish to log 
      \param Urgency Urgency of the message you wish to log
  */
  void log(const string &msg, Urgency u=Notice); 

  void setFacility(int f){d_facility=f;open();} //!< Choose logging facility
  void setFlag(int f){flags|=f;open();} //!< set a syslog flag
  void setName(const string &);

  //! set lower limit of urgency needed for console display. Messages of this urgency, and higher, will be displayed
  void toConsole(Urgency);
  void setLoglevel( Urgency );

  //! Log to a file.
  void toFile( const string & filename );
  
  void resetFlags(){flags=0;open();} //!< zero the flags
  /** Use this to stream to your log, like this:
      \code
      L<<"This is an informational message"<<endl; // logged at default loglevel (Info)
      L<<Logger::Warning<<"Out of diskspace"<<endl; // Logged as a warning 
      L<<"This is an informational message"<<endl; // logged AGAIN at default loglevel (Info)
      \endcode
  */
  Logger& operator<<(const string &s);   //!< log a string
  Logger& operator<<(int);   //!< log an int
  Logger& operator<<(unsigned int);   //!< log an unsigned int
  Logger& operator<<(long);   //!< log an unsigned int
  Logger& operator<<(unsigned long);   //!< log an unsigned int
  Logger& operator<<(unsigned long long);   //!< log an unsigned 64 bit int
  Logger& operator<<(Urgency);    //!< set the urgency, << style

#ifndef WIN32
  Logger& operator<<(ostream & (&)(ostream &)); //!< this is to recognise the endl, and to commit the log
#else
  // This is a hack to keep MSVC from generating a internal compiler error.
  Logger& operator<<(ostream & (hack)(ostream &)); //!< this is to recognise the endl, and to commit the log
#endif // WIN32

private:
  map<pthread_t,string>d_strings;
  map<pthread_t,Urgency> d_outputurgencies;
  void open();
  string name;
  int flags;
  int d_facility;
  bool opened;
  Urgency d_loglevel;
  Urgency consoleUrgency;
  pthread_mutex_t lock;
};

extern Logger &theL(const string &pname="");

#ifdef VERBOSELOG
#define DLOG(x) x
#else
#define DLOG(x) 
#endif


#endif
